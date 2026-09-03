"""条目管理器，负责密码条目的加密 CRUD 操作。

直接依赖 crypto_utils 的加解密原语（crypto_utils 同属 Business 层服务，非跨层依赖）；
分类/TOTP/密码历史/校验/变更通知/视图解密等职责拆至子服务与独立模块，本类聚焦条目
CRUD、读路径编排（epoch 守卫/锁外解密/搜索过滤）与变更通知，经 property 暴露分类/
TOTP/历史子服务。视图解密族（详情/导出/摘要的 raw→Entry 纯变换）下沉至
services/entry_view_decryption 的 EntryViewDecryptor（MAINT-021），公开解密 API
保持薄委托，调用方零改动。
"""

import json
import logging
import uuid
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from typing import TYPE_CHECKING, Any, NamedTuple

if TYPE_CHECKING:
    from .vault_manager import VaultManager

from ...crypto.password_generator import PasswordGenerator
from ...database.types import (
    ORDER_BY_FIELDS,
    EntryQuery,
    SearchRow,
    VaultDataStore,
    VerifyMode,
)
from ...exceptions import (
    DecryptionError,
    EntryIntegrityError,
    VaultKeyEpochMismatchError,
)
from ...models import (
    DEFAULT_RECENT_SUMMARIES_LIMIT,
    CustomField,
    Entry,
    RawEntry,
)
from ...utils.format import utc_now_iso
from ..services.crypto_utils import (
    SENSITIVE_ENCRYPTED_FIELDS,
    decrypt_field as _decrypt_field_impl,
    encrypt_field as _encrypt_field_impl,
    require_vault_key,
)
from ..services.entry_batch_writer import should_report_progress
from ..services.entry_search_match import matches_search_lower
from ..services.entry_sorting import SortKeySource, entry_sort_key
from ..services.entry_validation import validate_plain_entry
from ..services.entry_view_decryption import EntryViewDecryptor
from ..services.password_history_service import PasswordHistoryService
from ..services.password_service import PasswordService
from ..services.totp_service import TotpService
from .category_manager import CategoryManager
from .entry_cache import EntryCacheManager, ProjectionCacheKey, SearchMetadata
from .entry_change_bus import EntryChangeBus

logger = logging.getLogger(__name__)


class _SummaryRead(NamedTuple):
    """摘要读路径的锁内快照载荷（MAINT-092）：行集与密钥/世代同刻采集。

    两条行集互斥（内存路径仅 search_rows、SQL 下推路径仅 raw_entries），由
    :meth:`EntryManager.get_entry_summaries` 在 ``epoch_guarded_read`` 块内填充后
    传给锁外的摘要构建私有方法——行集与 key/data_epoch 的同刻性由构造点保证。
    """

    search_rows: list[SearchRow]
    raw_entries: list[RawEntry]
    key: bytes
    data_epoch: str | None


class EntryRead(NamedTuple):
    """详情读路径的锁内同刻快照载荷（SEC-063 b 层）：entry 与解密世代、TOTP 域版本。

    ``data_epoch`` 语义见 :meth:`EntryManager.get_entry_with_epoch`（SEC-054）；
    ``data_version`` 为 totp_secret 解密时点（读锁内与 raw/key/epoch 同刻快照）的
    TOTP 域失效版本，随 preloaded secret 沿预热链（detail_panel → TOTPWidget →
    TotpService.get_state → store_totp）透传——「解密 → 预热」窗口内发生过任何
    单条 TOTP 失效（pop_totp 不改 epoch，如导入覆盖 prepare 的 evict）时，旧
    secret 被 store 侧版本守卫拒收入缓存（SEC-063 b 层真实通道）。entry 为 None
    （条目不存在 / epoch 失配）时 epoch 与 version 均为 None，调用方先判 entry
    再消费。
    """

    entry: Entry | None
    data_epoch: str | None
    data_version: int | None


def _projection_cache_key(query: EntryQuery) -> ProjectionCacheKey:
    """从 EntryQuery 构造投影行集缓存键（ARCH-052，键构造单一事实源）。

    此前 ``get_entry_summaries`` 手工拼五元组、与 EntryQuery 的维度声明双源——
    未来加过滤维度漏改键则不同行集共享同键静默错数据，收敛为本函数显式提取。

    键维度 ↔ query 维度契约（键形态见 ``entry_cache.ProjectionCacheKey``）：

    - ``(deleted_only, category_id, favorite_only)`` ↔ 同名三维过滤条件；
    - ``(order_by, order_desc)`` ↔ 行集实际下推的排序规格；``order_by=None``
      （SQL 复合序）时规范化为 ``(None, True)``——复合序固定方向、方向参数无
      意义，避免同义键占多个缓存槽（PERF-086 键语义）。

    不参与键的维度及理由（入口校验升格为运行期拒绝，防「行集不同而键相同」）：

    - ``include_deleted``/``after_id``/``limit``：影响行集，但当前投影缓存的全部
      消费方（get_entry_summaries 内存路径、get_entry_dedup_index）恒传默认值
      （内存路径 limit 恒 None——截断由排序后/循环提前终止承担；after_id 无
      投影消费方）。传入非默认值须经新键维度（或显式论证）后再放行。
    - ``order_by`` 非 None 而 ``tie_break_order=False``：tie_break 只改行序不改
      行集，键的 order 段不区分两形态——当前消费方带显式排序时恒
      ``tie_break_order=True``（PERF-087 等价性诉求），混入 False 形态会使同键
      缓存两种并列序的行集，故拒绝。
    - ``verify``：投影查询本身无验签（``get_entries_search_projection``），
      对行集零影响，任意取值同键。

    Raises:
        ValueError: 上述「影响行集/行序但未入键」的维度被传入非默认形态。
    """
    if query.include_deleted or query.after_id is not None or query.limit is not None:
        raise ValueError(
            "投影缓存键不含 include_deleted/after_id/limit 维度，"
            "当前消费方须以默认值调用（见 _projection_cache_key 契约）"
        )
    if query.order_by is not None and not query.tie_break_order:
        raise ValueError("投影缓存键不区分并列裁决形态：order_by 非 None 时须 tie_break_order=True")
    order: tuple[str | None, bool] = (
        (None, True) if query.order_by is None else (query.order_by, query.order_desc)
    )
    return (
        query.deleted_only,
        query.category_id,
        query.favorite_only,
        order[0],
        order[1],
    )


class EntryManager:
    """管理密码条目的加密、解密和 CRUD 操作。"""

    def __init__(
        self,
        vault_manager: "VaultManager",
        cache: EntryCacheManager,
        change_bus: EntryChangeBus,
        category_mgr: CategoryManager,
    ):
        self._vault = vault_manager
        # 明文缓存（搜索摘要/分类名/TOTP/标签）与失效委托 EntryCacheManager。
        self._cache = cache
        # 条目变更通知管线：先失效缓存，再在锁外跑注册回调。
        self._change_bus = change_bus
        # 分类子服务经组合根/测试工厂显式注入（一等依赖，可替换/可测；MAINT-015 移除
        # 兜底内部构造——可选注入使遗漏装配在运行期才暴露且与组合根实例不一致）。
        # TOTP/密码历史为无状态子服务，保持内部构造。TotpService 的 vault 死依赖已
        # 删除（ARCH-039），单参构造仅注入缓存协议。
        self._category_mgr = category_mgr
        self._totp_svc = TotpService(cache)
        self._history_svc = PasswordHistoryService(vault_manager)
        # 视图解密子服务（MAINT-021 下沉）：详情/导出/摘要的 raw→Entry 纯变换。
        # 与 TOTP/密码历史同为无状态子服务，保持内部构造。
        self._view_decryptor = EntryViewDecryptor(vault_manager, cache)

    @property
    def categories(self) -> CategoryManager:
        """分类子服务（CRUD、查询、缓存失效）。"""
        return self._category_mgr

    @property
    def cache(self) -> EntryCacheManager:
        """明文缓存子服务（只读视图，QL-044）。

        消费方（测试、跨 manager 协作）经此公开入口取摘要/TOTP/标签缓存，不再穿透
        ``_category_mgr._cache`` 双层私有属性——分类 manager 与缓存无所有权关系，
        双层穿透在分类装配结构调整时会静默漂移。
        """
        return self._cache

    @property
    def totp(self) -> TotpService:
        """TOTP 子服务（生成、状态查询、缓存清理）。"""
        return self._totp_svc

    @property
    def password_history(self) -> PasswordHistoryService:
        """密码历史子服务（读取、计数、解密展示）。"""
        return self._history_svc

    def register_on_change(self, callback: Callable[[bool, bool, str | None], None]) -> None:
        """注册条目变更时自动调用的回调，用于缓存失效等。委托 change_bus。

        回调签名 ``(password_changed, metadata_changed, crypto_id)``，语义见
        :meth:`EntryChangeBus.notify`（crypto_id 为 None 表示全量语义，PERF-021）。
        """
        self._change_bus.register(callback)

    @property
    def db(self) -> VaultDataStore:
        """数据访问协议视图，委托 vault（收窄为 VaultDataStore，不含装配 setter）。"""
        return self._vault.db

    @property
    def key_epoch(self) -> str | None:
        """当前密钥版本，委托 vault。

        供 ImportExportManager 等跨管理器操作做 epoch 守卫，避免直接穿透 ``_vault``。
        """
        return self._vault.key_epoch

    @contextmanager
    def epoch_guarded_transaction(
        self,
        operation: str = "",
        pre_epoch: str | None = None,
    ) -> Iterator[None]:
        """epoch 守卫事务，委托 vault。

        供 ImportExportManager 等跨管理器操作做带 epoch 守卫的事务包裹，避免直接
        穿透 ``_vault``。语义与 ``VaultManager.epoch_guarded_transaction`` 一致
        （含事务成功提交后的 TOTP 缓存统一失效 seam，SEC-063 结构性根治）。
        pre_epoch 透传供导入路径锁外加密后传入（MAINT-004）。
        """
        with self._vault.epoch_guarded_transaction(
            operation=operation,
            pre_epoch=pre_epoch,
        ):
            yield

    @property
    def _key(self) -> bytes:
        return require_vault_key(self._vault)

    def build_encrypted_entry(
        self,
        entry: Entry,
        crypto_id: str,
        now: str,
        *,
        created_at: str | None = None,
        updated_at: str | None = None,
        password_override: str | None = None,
        entry_id: int | None = None,
    ) -> RawEntry:
        """构建加密 RawEntry，作为公开加密原语供单条 CRUD 与批量导入写入共用，避免加密字段遗漏。

        password_override: 若提供，视为已加密的密文直接赋值，不再重复加密。

        加密字段对 :data:`SENSITIVE_ENCRYPTED_FIELDS` 循环产出（QL-046）：custom_fields
        的 JSON 序列化与 password 的 override 密文特判，其余字符串字段统一经
        ``_encrypt_field``（AAD 构造与原手工枚举逐字段完全一致）。新增加密字段只需
        登记单一事实源，加密侧自动跟随——消除「解密/验签侧响亮失败、加密侧静默丢
        字段」的写读不对称（丢字段的密文入库会使编辑保存/导入覆盖后该字段永久为空，
        恢复往返断裂）。键集完备性由 tests/test_field_consistency.py 守护。
        """
        # update_entry 传密文走 override 分支；add_entry 传 None 走加密分支。
        encrypted_pwd = (
            password_override
            if password_override is not None
            else self._encrypt_field(entry.password, crypto_id, "password")
        )
        custom_fields_cipher = self._encrypt_custom_fields(entry.custom_fields, crypto_id)
        # 键来自运行期元组，静态检查器无法验证字段名↔构造参数匹配，value 类型标注
        # Any 使 ** 解包通过（守护交给 test_field_consistency 的键集断言）。
        encrypted: dict[str, Any] = {
            "password": encrypted_pwd,
            "custom_fields": custom_fields_cipher,
        }
        for field in SENSITIVE_ENCRYPTED_FIELDS:
            if field not in encrypted:
                encrypted[field] = self._encrypt_field(getattr(entry, field), crypto_id, field)
        return RawEntry(
            id=entry_id,
            crypto_id=crypto_id,
            category_id=entry.category_id,
            is_favorite=entry.is_favorite,
            password_strength=entry.password_strength,
            entry_type=entry.entry_type,
            created_at=created_at or now,
            updated_at=updated_at or now,
            password_changed_at=entry.password_changed_at or now,
            **encrypted,
        )

    def _encrypt_field(self, plaintext: str, crypto_id: str, field_name: str) -> str:
        """加密单个字段，委托给 crypto_utils.encrypt_field。"""
        return _encrypt_field_impl(plaintext, self._key, crypto_id, field_name)

    def _decrypt_field(
        self,
        encrypted: str,
        crypto_id: str,
        field_name: str,
        strict: bool = False,
        *,
        key: bytes | None = None,
    ) -> str:
        """解密单个字段，委托给 crypto_utils.decrypt_field。

        ``key`` 为 PERF-001 并发修补（M3）：调用方在 ``epoch_guarded_read`` with 块内
        快照的主密钥，锁外解密期间改密 activate 后用快照而非实时 ``self._key`` 解密
        本批旧密文，避免旧密文+新密钥 GCM 认证失败。默认 None 用实时 ``self._key``，
        保持写路径等非并发调用方零改动。
        """
        return _decrypt_field_impl(
            encrypted,
            key if key is not None else self._key,
            crypto_id,
            field_name,
            strict=strict,
        )

    def invalidate_caches(self) -> None:
        """外部调用：锁定或改密后显式清空明文缓存。委托 cache。"""
        self._cache.invalidate_all()

    def notify_batch_change(
        self, password_changed: bool = True, *, clear_summaries: bool = True
    ) -> None:
        """批量变更后的统一通知入口，供导入等批量操作在全部完成后触发一次。

        与单条 ``change_bus.notify`` 一致地失效缓存并通知回调，但作为公共 API
        暴露，避免跨管理器（如 ImportExportManager / entry_batch_writer）直接访问
        底层通知机制，使内部缓存失效机制不致成为跨模块契约的一部分。

        ``clear_summaries=False`` 供导入新增条目路径保留既有摘要缓存（新条目不改变
        既有条目摘要），避免无谓全量重解密。
        """
        self._change_bus.notify(password_changed, clear_summaries=clear_summaries)

    def invalidate_entry_summaries(self, crypto_ids: Iterable[str]) -> None:
        """按 crypto_id 批量失效搜索摘要缓存（导入覆盖路径专用，PERF-022）。

        供 ImportExportManager 在批量通知前精细 pop 被覆盖条目的摘要（同单条
        update_entry 的失效粒度），使 clear_summaries=False 的批量通知不残留
        被覆盖条目的旧摘要。不触发回调——统一通知仍由 notify_batch_change 发出。
        """
        self._cache.pop_search_metadata_batch(crypto_ids)

    def _encrypt_custom_fields(
        self,
        fields: list[CustomField] | str,
        crypto_id: str,
    ) -> str:
        """加密自定义字段列表。"""
        if not fields:
            return ""
        if not isinstance(fields, list) or not all(
            isinstance(field, CustomField) for field in fields
        ):
            raise ValueError("自定义字段必须是 CustomField 列表")
        data = json.dumps([f.to_dict() for f in fields], ensure_ascii=False)
        return self._encrypt_field(data, crypto_id, "custom_fields")

    def decrypt_entry(
        self,
        raw_entry: RawEntry,
        *,
        key: bytes | None = None,
        data_epoch: str | None = None,
    ) -> Entry:
        """解密条目的所有敏感字段，返回新的 Entry 对象（详情/编辑路径）。

        字段解密失败时容错：失败字段收集到 ``integrity_message``，password/totp
        包 :class:`Sensitive` 防明文意外进入日志/repr。

        ``key`` 语义见 :meth:`_decrypt_field`（PERF-001 并发修补）。

        ``data_epoch`` 语义见 ``EntryCacheManager._cached_search_metadata_no_check``
        （SEC-041/043 写入方世代）：调用方在 ``epoch_guarded_read`` 锁内与 raw/密钥
        同刻快照的世代，供摘要/分类名缓存回写守卫拒收跨世代解密结果。

        实现委托 :class:`EntryViewDecryptor.decrypt_entry`（MAINT-021 下沉）。
        """
        return self._view_decryptor.decrypt_entry(raw_entry, key=key, data_epoch=data_epoch)

    def decrypt_entry_for_export(
        self,
        raw_entry: RawEntry,
        include_secrets: bool = False,
        *,
        key: bytes | None = None,
        data_epoch: str | None = None,
    ) -> Entry:
        """仅解密导出所需字段，默认不让密码与 TOTP 进入内存结果。

        任何完整性/解密失败立即抛 :class:`DecryptionError`（拒绝导出损坏数据）；
        ``include_secrets=False`` 时跳过 password/totp_secret 解密。

        ``key`` 语义见 :meth:`_decrypt_field`（PERF-001 并发修补）。
        ``data_epoch`` 语义同 :meth:`decrypt_entry`（SEC-049 补齐 export 链）：
        分类名缓存回写守卫据此拒收跨世代解密结果。

        实现委托 :class:`EntryViewDecryptor.decrypt_entry_for_export`（MAINT-021 下沉）。
        """
        return self._view_decryptor.decrypt_entry_for_export(
            raw_entry, include_secrets=include_secrets, key=key, data_epoch=data_epoch
        )

    def add_entry(
        self,
        entry: Entry,
        *,
        notify: bool = True,
        skip_validation: bool = False,
    ) -> int:
        """添加新条目，自动加密并检测强度。

        Args:
            entry: 待添加的明文条目。
            notify: 是否触发条目变更通知。
            skip_validation: 导入路径已由 Entry.from_dict 校验，传 True 跳过重复长度校验。
        """
        if not skip_validation:
            validate_plain_entry(entry)
        strength = PasswordGenerator.check_strength(entry.password)
        entry = replace(entry, password_strength=strength.score)
        crypto_id = entry.crypto_id or uuid.uuid4().hex

        now = utc_now_iso()
        enc_entry = self.build_encrypted_entry(
            entry,
            crypto_id,
            now,
            created_at=entry.created_at or now,
            updated_at=entry.updated_at or now,
        )
        # 差分世代快照在写库前捕获（QL-065）：新增提交后的 +1 差分不得应用于
        # 「并发失效+基于新库重建」后的缓存（重建已含新条目，再加即双扣）。
        expected_version = self._cache.invalidate_version
        result = self._vault.db.add_entry(
            enc_entry,
            preserve_metadata=bool(entry.created_at or entry.updated_at),
        )
        if notify:
            # 新增走单条增量通知（PERF-079，扩展 PERF-021 框架至增删路径）：携带
            # crypto_id 使 SecurityAnalyzer 仅重读/重分类该条并按「缓存成员资格」
            # 上调 total，替代原先 crypto_id=None 触发的整库失效 + 状态栏 worker
            # 全量重算（O(n) 解密+指纹+摘要）。标签计数同步差分 +1（PERF-079），
            # 不再整表失效 _tags_cache。新条目自身摘要尚未缓存，apply_change 的
            # 单条 pop 为 no-op，既有摘要天然保留（对齐原 clear_summaries=False）。
            # 分类计数缓存经显式失效（PERF-064 同款模式）：bus 的 crypto_id 单条
            # 通道无法表达「分类×有效条目分布」这一结构性维度。
            self._notify_entry_structure_changed(
                crypto_id,
                "",
                entry.tags,
                expected_version=expected_version,
            )
        return result

    def update_entry(
        self,
        entry: Entry,
        *,
        preserve_password_changed_at: bool = False,
        notify: bool = True,
    ) -> None:
        """更新条目，自动加密并记录密码历史。

        线程安全：采用事务外 read-modify-write + 事务内复查 key_epoch——相比
        toggle_favorite（事务内 read），事务外 read 缩短 db_lock 持有时间，避免
        加解密期间阻塞改密；epoch 复查保证若 read 到 commit 期间发生改密重加密，
        本写入中止而非把旧密钥密文落到已重写的历史表。单用户桌面应用同一时刻仅
        一个 UI 操作修改同一条目，竞态窗口极小。
        """
        validate_plain_entry(entry)
        if entry.integrity_error:
            raise EntryIntegrityError(
                f"条目存在无法解密的字段（{entry.integrity_message}），为避免数据丢失已禁止保存"
            )
        if entry.id is None:
            return
        # read 前快照 key_epoch，事务内复查，防止 read-modify-write 期间改密
        # 导致 add_password_history 写入旧密钥密文到已被重写的历史表。
        pre_epoch = self.key_epoch
        # 条目更新可能修改 totp_secret，失效该条目的 TOTP secret 缓存，
        # 下次 TotpService.get_state / generate_cached 重新解密。须在写库**前**
        # 执行（QL-070）：「写库 → pop」窗口内 TOTP 定时器会命中缓存的旧 secret
        # 生成过期验证码；pop 只推进 TOTP 域失效版本（QL-070 分域，见 entry_cache），
        # 不影响紧随其后的差分世代快照（expected_version 读主域版本）。事务提交后
        # 由统一失效 seam 再 clear_totp 一轮（SEC-063 结构性根治，见
        # VaultManager.epoch_guarded_transaction），前置 pop 覆盖「写库 → 提交」间
        # 窗口，语义互补。时序由 TestTotpInvalidateOrdering 以调用顺序 spy 守护。
        self._cache.pop_totp(entry.id)
        # 差分世代快照同刻捕获（QL-065）：提交后的标签差分不得应用于「并发失效+
        # 重建」后的缓存（重建已含编辑后的 tags，再减旧加新即双扣）。
        expected_version = self._cache.invalidate_version
        raw = self.db.get_entry(entry.id)
        if raw is None:
            return

        new_pwd_enc, password_changed = self.prepare_password_update(entry, raw)
        password_changed_at = self.resolve_password_changed_at(
            entry,
            raw,
            password_changed,
            preserve_password_changed_at,
        )

        strength = PasswordGenerator.check_strength(entry.password)
        entry = replace(entry, password_strength=strength.score)

        now = utc_now_iso()
        enc_entry = self.build_encrypted_entry(
            entry,
            raw.crypto_id,
            now,
            created_at=raw.created_at,
            updated_at=now,
            password_override=new_pwd_enc,
            entry_id=entry.id,
        )
        enc_entry = replace(enc_entry, password_changed_at=password_changed_at)
        # epoch 守卫事务（MAINT-089）：原手写「开事务→复查 epoch→写入」样板与
        # ``epoch_guarded_transaction`` 语义逐行等价（pre_epoch 为锁外 read 前的
        # 自行快照，同 MAINT-004 导入路径的透传形态），收敛至单一实现。
        with self.epoch_guarded_transaction(operation="更新条目", pre_epoch=pre_epoch):
            if raw.password and password_changed and entry.id is not None:
                # 用与条目一致的 password_changed_at 作为历史 changed_at，
                # 避免两次独立 utc_now_iso() 产生的微秒级时序倒置
                self.db.add_password_history(
                    entry.id,
                    raw.password,
                    changed_at=password_changed_at,
                )
            self.db.update_entry(enc_entry)
        if notify:
            self._notify_entry_updated(
                raw, entry, password_changed, expected_version=expected_version
            )

    def prepare_password_update(
        self,
        entry: Entry,
        raw: RawEntry,
        preloaded_old_password: str | None = None,
    ) -> tuple[str, bool]:
        """检测密码变更并加密新密码，返回 (新密码密文, 是否变更)。

        必须解密旧密码与明文比较——AES-GCM 用随机 nonce，密文比较不可行；HMAC 指纹
        方案需 schema 变更，当前解密比较是无需迁移的合理选择。常量时间比较
        （:meth:`PasswordService.passwords_match`，经 utf-8 编码的
        ``hmac.compare_digest`）避免时序侧信道。``preloaded_old_password`` 供
        :func:`entry_batch_writer.prepare_overwrite_updates` 批量路径注入（其
        BatchUpdateItem.old_password 现恒 None 走默认解密分支，PERF-006）；单条
        :meth:`update_entry` 路径不使用（MAINT-090 已随 preloaded_raw 一并删除
        update_entry 侧的对应参数）。
        """
        old_pwd_enc = raw.password
        if preloaded_old_password is not None:
            old_password = preloaded_old_password
        else:
            # 容错解密（PERF-006）：批量覆盖路径 old_password 留 None 经此分支解密，损坏
            # 回退 ''（与原 decrypt_password 语义一致）——'' 与新密码比较通常判定变更并
            # 归档旧密文历史。单条路径因 update_entry 已据 integrity_error 拦截损坏条目，
            # 不会经此分支遇损坏。
            try:
                old_password = (
                    self._decrypt_field(
                        old_pwd_enc,
                        raw.crypto_id,
                        "password",
                        strict=True,
                    )
                    if old_pwd_enc
                    else ""
                )
            except DecryptionError:
                old_password = ""
        new_pwd_enc = self._encrypt_field(entry.password, raw.crypto_id, "password")
        # 常量时间比较新旧密码（QL-044 收敛至 PasswordService.passwords_match 单一
        # 事实源）：内部经 encode('utf-8') 的 hmac.compare_digest——条目密码可含
        # Unicode（中文/重音/emoji），str 版仅接受 ASCII，非 ASCII 直接比较会抛
        # TypeError 使该条目永远无法编辑、覆盖导入整体中止（QL-019 语义保持）。
        password_changed = not PasswordService.passwords_match(old_password, entry.password)
        del old_password  # 尽快释放明文引用
        return new_pwd_enc, password_changed

    def resolve_password_changed_at(
        self,
        entry: Entry,
        raw: RawEntry,
        password_changed: bool,
        preserve: bool,
    ) -> str:
        """决定 update_entry 写入的 password_changed_at。

        - preserve（导入覆盖同步）：保留原值，避免批量导入把「久未修改」条目重置为
          「刚修改」从而绕过过期检测。
        - password_changed：密码实际变更，记当前时间。
        - 否则：保留原值。
        """
        if preserve:
            return entry.password_changed_at or raw.password_changed_at
        if password_changed:
            return utc_now_iso()
        return raw.password_changed_at

    def _notify_entry_structure_changed(
        self,
        crypto_id: str | None,
        old_tags: str | None,
        new_tags: str = "",
        *,
        password_changed: bool = True,
        invalidate_category_counts: bool = True,
        clear_summaries: bool = False,
        expected_version: int | None = None,
    ) -> None:
        """增删/恢复/编辑路径统一的「标签差分 + 分类计数失效 + 通知」组合（MAINT-100）。

        PERF-079 扩展至 add/update/delete/restore/permanent_delete 五处时各自手写
        本组合，参数各异（本次审查的删除路径静默 no-op 与编辑路径两段锁撕裂均属
        各自漂移）——收敛为单一 helper，行为语义仍由 PERF-079 框架声明。

        - ``old_tags`` 为 None 表示旧 tags 密文解密失败（LENIENT 读路径服务的清理
          场景）：差分不可依赖损坏旧值，跳过差分并保守 ``tags_changed=True`` 整表
          失效（QL-066，对齐编辑路径的既有保守口径，修复删除/恢复路径静默 no-op
          致 ``_tags_cache`` 陈旧）；空串为合法端点（该条目无标签，差分 no-op）。
        - ``invalidate_category_counts``：结构性增删/恢复恒 True；编辑仅在分类归属
          变化时失效（PERF-064，bus 的单条通道无法表达该维度）。
        - ``expected_version``：写事务前快照的失效版本（:attr:`EntryCacheManager.
          invalidate_version`），差分写回前复查，堵「读 raw → 提交 → 差分」窗口内
          并发失效+重建后的双扣（QL-065）。
        """
        if invalidate_category_counts:
            self._category_mgr.invalidate_entry_counts_cache()
        if old_tags is not None:
            # 差分被世代守卫放弃（或缓存未填充）时保守整表失效（QL-070）：
            # apply_tag_delta 返回是否应用——False 时 tags_changed 必须为 True，
            # 否则既未差分也未失效，_tags_cache 残留窗口前的旧计数。旧行为恒
            # tags_changed=False，正确性依赖随后 apply_change（默认
            # tags_changed=True 经 notify 路径时）恰好整表失效的未声明不变量
            # 巧合收敛；缓存未填充（None）场景下该「巧合」不成立（置 None 是
            # no-op，但此时本就无陈旧数据，保守分支亦无损）。
            applied = self._cache.apply_tag_delta(
                old_tags, new_tags, expected_version=expected_version
            )
            tags_changed = not applied
        else:
            tags_changed = True
        self._change_bus.notify(
            password_changed,
            crypto_id=crypto_id,
            clear_summaries=clear_summaries,
            tags_changed=tags_changed,
        )

    def _notify_entry_updated(
        self,
        raw: RawEntry,
        entry: Entry,
        password_changed: bool,
        *,
        expected_version: int | None = None,
    ) -> None:
        """update_entry 后的变更通知：检测 tags 是否变更以决定标签缓存失效粒度。

        摘要缓存按 crypto_id 单条精细失效（避免标题/URL 编辑触发全量重解密）；
        raw.tags 解密失败时保守视为 tags 已变（仍整表失效标签缓存）。tags 实际
        变更且旧值可解时走差分（PERF-079）：一次锁内先减旧计数再加新计数，
        替代整表失效的全量重解密重算。

        分类归属变化（单条编辑可改 category_id）影响分类条目计数缓存（PERF-064）：
        bus 的 crypto_id 单条通道无法表达该维度，此处显式失效——纯字段编辑
        （归属未变）不失效，保住侧边栏刷新的计数缓存命中。
        """
        self._notify_entry_structure_changed(
            raw.crypto_id,
            # None=解密失败 → 保守整表失效（QL-066）；'' 为合法空标签端点。
            self._decrypt_tags_for_delta(raw),
            entry.tags,
            password_changed=password_changed,
            invalidate_category_counts=entry.category_id != raw.category_id,
            expected_version=expected_version,
        )

    def _decrypt_tags_for_delta(self, raw: RawEntry) -> str | None:
        """增删/恢复/编辑差分所需的单条 tags 明文（PERF-079），失败返回 None。

        委托 :meth:`EntryCacheManager.decrypt_tags_for_delta`（QL-066 单一事实源）：
        优先复用搜索摘要缓存的暖 tags；解密失败返回 None 哨兵供调用方保守整表
        失效，与合法空串（''，差分 no-op）显式区分。
        """
        return self._cache.decrypt_tags_for_delta(raw.crypto_id, raw.tags)

    def _read_raw_for_delta(self, entry_id: int) -> RawEntry | None:
        """增删差分前置读取的单条 raw（PERF-079），LENIENT 容错语义。

        经 ``get_entries_by_ids``（LENIENT 验签）而非 ``get_entry``（STRICT）：
        元数据 HMAC 被篡改的条目仅标记 ``integrity_error`` 不抛异常——差分前置
        读取不得使「删除损坏条目」这一清理路径本身失败；损坏行的 tags 解密由
        :meth:`_decrypt_tags_for_delta` 失败返回 None（调用方保守整表失效，
        QL-066），分析器侧重读见 is_deleted 仍走移除差分。
        """
        rows = self._vault.db.get_entries_by_ids([entry_id])
        return rows[0] if rows else None

    def delete_entry(self, entry_id: int) -> bool:
        """软删除条目，移入回收站。返回是否实际执行（条目存在）。"""
        # 差分前置读取（PERF-079）：删除前取 crypto_id 与 tags 明文，供分析器
        # 「重读见 is_deleted → 仅移除」差分与标签计数 -1 差分。
        raw = self._read_raw_for_delta(entry_id)
        if raw is None:
            return False
        tags = self._decrypt_tags_for_delta(raw)
        # TOTP 缓存失效先于写库（QL-070 时序，理由见 update_entry）：「写库 → pop」
        # 窗口内定时器命中旧 secret；pop 只推进 TOTP 域版本，不影响主域差分快照。
        self._cache.pop_totp(entry_id)
        # 差分世代快照在软删除前捕获（QL-065）：提交后的 -1 差分不得应用于
        # 「并发失效+基于新库重建」后的缓存（重建已不含被删条目标签，再扣即双扣）。
        expected_version = self._cache.invalidate_version
        if not self._vault.db.soft_delete_entry(entry_id):
            return False
        # 单条增量通知（PERF-079）：分析器重读该条见 is_deleted=1 构造移除差分
        # （按缓存成员资格下调 total 并移出弱/重复/过期名单），其余 N-1 条的解密
        # 与指纹结果复用；标签计数 -1 差分与分类计数显式失效（结构性维度经
        # PERF-064 模式显式失效，bus 单条通道无法表达）。tags 解密失败时保守
        # 整表失效（old_tags=None → tags_changed=True，QL-066）。
        self._notify_entry_structure_changed(
            raw.crypto_id,
            tags,
            expected_version=expected_version,
        )
        return True

    def restore_entry(self, entry_id: int) -> bool:
        """恢复条目。返回是否实际执行（条目存在）。"""
        # 差分前置读取（PERF-079）：恢复前取 crypto_id 与 tags 明文（恢复不改变
        # tags 密文），恢复后作为单条重分类插入与标签计数 +1 差分的输入。
        raw = self._read_raw_for_delta(entry_id)
        if raw is None:
            return False
        tags = self._decrypt_tags_for_delta(raw)
        # 差分世代快照在恢复前捕获（QL-065，语义同 delete_entry）。
        expected_version = self._cache.invalidate_version
        if not self._vault.db.restore_entry(entry_id):
            return False
        # 恢复与新增同构（PERF-079）：分析器重读该条（is_deleted=0）重分类插入并
        # 按缓存成员资格上调 total；软删除时已移出的标签计数加回。tags 解密失败
        # 时以不可解端点触发保守整表失效（old 端传 None → tags_changed=True，
        # QL-066）；成功时 old=''（软删除端点已减）+ new=tags（加回）。
        self._notify_entry_structure_changed(
            raw.crypto_id,
            None if tags is None else "",
            tags or "",
            expected_version=expected_version,
        )
        return True

    def permanent_delete_entry(self, entry_id: int) -> None:
        """永久删除条目。"""
        raw = self._read_raw_for_delta(entry_id)
        # TOTP 缓存失效先于写库（QL-070 时序，理由见 update_entry）：pop 只推进
        # TOTP 域版本，不影响主域差分快照（条目不存在时 pop 为幂等 no-op，仅多
        # 一次 TOTP 域版本推进，无正确性影响）。时序由 TestTotpInvalidateOrdering
        # 以调用顺序 spy 守护。
        self._cache.pop_totp(entry_id)
        # 差分世代快照在物理删除前捕获（QL-065，语义同 delete_entry）。
        expected_version = self._cache.invalidate_version
        tags = self._decrypt_tags_for_delta(raw) if raw is not None else ""
        was_active = raw is not None and not raw.is_deleted
        self._vault.db.permanent_delete_entry(entry_id)
        # 回收站路径的永久删除作用于已软删除条目（was_active=False）：分析/标签/
        # 计数缓存在软删除时已差分移除，此处增量通知对已移除条目是幂等 no-op。
        # 直接物理删除活跃条目的调用形态（was_active=True）则补齐差分（PERF-079）。
        if raw is None:
            # 条目本不存在：保持全量语义通知（crypto_id=None，差分无从谈起）。
            self._notify_entry_structure_changed(
                None,
                None,
                invalidate_category_counts=False,
                clear_summaries=True,
            )
        else:
            self._notify_entry_structure_changed(
                raw.crypto_id,
                tags if was_active else "",
                invalidate_category_counts=was_active,
                expected_version=expected_version,
            )

    def empty_trash(self) -> None:
        """清空回收站。

        批量删除后统一 secure_checkpoint：收缩 WAL（清除已删除条目旧密文扇区残留）
        并刷新 -wal/-shm 文件权限，避免每条 DELETE 各自 checkpoint 的 O(n) 次
        TRUNCATE+fsync。
        """
        # TOTP 缓存清空先于物理删除（QL-075，pop-before-write 纪律对齐 update_entry/
        # delete_entry 的 QL-070 时序）：原「db.empty_trash() 在前、clear_totp() 在后」
        # 在 db 抛异常时已物理删除条目的 TOTP secret 残留缓存（条目已不存在而明文
        # secret 仍在内存缓存，违反自家失效纪律）。clear_totp 幂等（清空已空缓存无
        # 副作用，仅推进 TOTP 域失效版本），先行清空不改变成功路径行为。本路径不经
        # epoch_guarded_transaction（db.empty_trash 各自隐式提交），SEC-063 统一失效
        # seam 不覆盖，前置清空是唯一失效点。
        self._cache.clear_totp()
        self._vault.db.empty_trash()
        # 通知降级为纯旁路语义（PERF-088）：回收站条目不在活跃分析集合——软删除时
        # 已按 PERF-079 增量差分移出 SecurityAnalyzer 缓存与标签计数，物理清空不
        # 改变活跃集合，故 password_changed/metadata_changed=False：
        # - SecurityAnalyzer.invalidate_cache 对双 False 直接返回，跳过整库 O(n)
        #   重解密重算（原零参 notify 默认双 True 触发状态栏 worker 全量重算）；
        # - category_mgr 的计数订阅同样跳过（get_category_entry_counts 过滤
        #   is_deleted=0，回收站条目本就不计入分类计数）。
        # 其余失效面不受降级影响：apply_change 仍整体执行（tags_changed/
        #   clear_summaries 默认 True + 推进 version），摘要/标签缓存与投影行集
        # 缓存（PERF-086）照常失效，回收站（deleted_only）视图的行集正确性保持。
        self._change_bus.notify(password_changed=False, metadata_changed=False)
        # 数据已提交，WAL 截断失败非致命（仅旧密文残留收缩失败）；与改密/恢复/解锁路径
        # 对称地降级为告警，避免截断异常冒泡使 UI 显示模糊错误（secure_checkpoint 失败
        # 上抛 DatabaseError，见 SEC-010）。
        try:
            self._vault.db.secure_checkpoint()
        except Exception:
            logger.warning("清空回收站后 WAL 安全截断失败（非致命）", exc_info=True)

    def get_entry(self, entry_id: int) -> Entry | None:
        """获取并解密单个条目。

        读路径经 :meth:`epoch_guarded_read` 守卫（ARCH-005）：with 块内仅读 raw、解密移
        锁外（与摘要路径 PERF-001 一致）；epoch 不一致时返回 None，调用方据此跳过。

        实现（SEC-054 闭合）委托 :meth:`get_entry_with_epoch` 后丢弃世代与版本。
        """
        return self.get_entry_with_epoch(entry_id).entry

    def get_entry_with_epoch(self, entry_id: int) -> EntryRead:
        """获取并解密单个条目，随行携带解密世代与 TOTP 域版本（:class:`EntryRead`）。

        与 :meth:`get_entry` 同一读路径（epoch 守卫 + 锁内快照 key/世代 + 锁外解密），
        区别仅在于把锁内快照的 ``data_epoch``（SEC-054 残余窗口闭合）与
        ``data_version``（SEC-063 b 层：TOTP 域失效版本的解密时点快照）一并返回：
        消费方（detail_panel 的 TOTP 预热）需要「entry 敏感字段解密时所处世代/版本」
        ——世代与版本从锁内带出后，「解密后→预热前」窗口内发生恢复轮换（改 epoch）
        或单条 TOTP 失效（pop_totp 不改 epoch、仅推进 TOTP 域版本）时，旧 secret
        分别被 store_totp 的世代/版本守卫拒收；在 show_entry 调用点另行快照会把
        该窗口误判为零间隙。其余不消费世代/版本的调用方继续用 :meth:`get_entry`。
        """
        try:
            with self._vault.epoch_guarded_read():
                raw = self._vault.db.get_entry(entry_id)
                # PERF-001 并发修补（M3）：锁内快照主密钥，锁外解密用快照（语义见 _decrypt_field）。
                key = self._key
                # SEC-043 写入方世代：详情路径同样快照世代传入缓存回写（语义见
                # get_entry_summaries 处注释）——此前仅搜索分支接入，详情的摘要/
                # 分类名缓存回写退回缓存侧采样，跨世代后旧明文可植入新 epoch 缓存。
                data_epoch = self._vault.key_epoch
                # SEC-063 b 层：TOTP 域版本与 raw/key/epoch 同刻快照——store_totp 的
                # 版本守卫据此拒收「解密 → 预热」窗口内被 pop_totp 失效的旧 secret
                # （pop 不改 epoch，SEC-054 的世代守卫对该失效盲）。
                data_version = self._cache.totp_invalidate_version
        except VaultKeyEpochMismatchError:
            return EntryRead(None, None, None)
        if raw is None:
            return EntryRead(None, None, None)
        entry = self.decrypt_entry(raw, key=key, data_epoch=data_epoch)
        return EntryRead(entry, data_epoch, data_version)

    def get_entry_summaries(
        self,
        deleted_only: bool = False,
        category_id: int | None = None,
        favorite_only: bool = False,
        search: str = "",
        limit: int | None = None,
        cancel_check: Callable[[], bool] | None = None,
        *,
        order_by: str | None = None,
        order_desc: bool = True,
    ) -> list[Entry]:
        """获取不含密码等敏感明文的列表摘要。

        Note:
            ``limit`` 的生效方式（PERF-078 后统一）：
            - 无搜索且排序为 SQL 白名单字段/默认复合序：``limit`` 经
              ``ORDER BY ... LIMIT`` 下推 SQL（PERF-073）。字段序为纯单列序，
              不附加并列裁决键（PERF-090）：该路径无内存对等路径，裁决键只会在
              updated_at 序上破坏 idx_entries_active_updated 的索引下推
              （退化为 TEMP B-TREE filesort）而无等价性收益。
            - 搜索非空或不可 SQL 下推的排序（内存路径）：匹配/收集必须全量（加密字段
              不可先截断后过滤），排序在内存按 meta/窄行键完成后取前 ``limit``——
              仅这前 N 条回查宽行与构建摘要，语义与 SQL「ORDER BY ... LIMIT`` 同构；
              排序可 SQL 下推且 ``limit`` 非 None 时走排序下推分支（PERF-087，投影
              查询带 ORDER BY、匹配循环凑满即止，跳过内存排序）。下推的 SQL 序带
              并列裁决键（排序列 + is_favorite DESC, updated_at DESC），与内存稳定
              排序继承的复合序一致——并列 + limit 截断边界上两路径选出同一集合与
              同一序。
            - ``limit`` 为 None 返回全部（内存全量回查，既有调用方语义不变）；
              ``limit=0`` 两路径一致返回空集（QL-072 统一：此前内存路径的
              ``if limit`` 视 0 为 falsy 跳过截断返回全部，与 SQL 路径 LIMIT 0
              返回空集语义分叉）。

        ``order_by``/``order_desc``（PERF-073/078）：``database.types.ORDER_BY_FIELDS``
        白名单字段 + 无搜索 → SQL 下推；白名单外的排序（如 ``"title"``，密文列不可
        SQL 排序）或搜索非空 → 内存排序（title 键为缓存的 meta.title_lower，其余键
        为窄投影明文列），截断集合=排序序前 N。``None``（默认）走复合序（内存路径
        下即窄投影的 SQL 序，不重排）。

        读路径经 :meth:`epoch_guarded_read` 守卫（ARCH-005）：改密窗口内 epoch 不一致时
        返回空列表，触发 UI 经变更回调刷新。锁定期 :class:`VaultLockedError` 仍正常传播。

        实现（MAINT-092 拆分，对齐 MAINT-021 模式）：本方法保持薄编排——锁内
        （``epoch_guarded_read`` 块）完成行集读取与 key/世代快照、组装
        :class:`_SummaryRead` 载荷，锁外按路径分派到
        :meth:`_summaries_via_search_projection` / :meth:`_summaries_from_raw_rows`
        构建摘要，逐块自原 190 行单体方法搬运，语义零变化。
        """
        # 路径分流（PERF-078；ARCH-051 白名单驱动）：搜索路径与不可 SQL 下推的排序
        # （ORDER_BY_FIELDS 之外的密文字段，如 title）走「窄投影全量 → 内存 meta
        # 排序 → 仅前 limit 回查宽行」；其余（无搜索 + SQL 白名单字段/默认复合序）
        # 维持 PERF-073 的 SQL ``ORDER BY ... LIMIT`` 下推宽行路径。此前硬编码
        # ``order_by == "title"`` 与 ORDER_BY_FIELDS 构成双源——白名单新增字段时
        # 本判定不自动跟随（新增可下推字段会被误判为 SQL 路径之外的第三态）；
        # 改为白名单否定式后，「不可下推」集合自动继承单一事实源。
        in_memory_path = bool(search) or (order_by is not None and order_by not in ORDER_BY_FIELDS)
        sql_pushdown = not in_memory_path
        # 内存路径的排序下推（PERF-087）：order_by 属 SQL 白名单且 limit 非 None 时，
        # 投影查询下推 ORDER BY，行集即目标序——匹配循环按序扫描凑满 limit 即 break，
        # 跳过 O(n log n) 的全量收集+内存排序（50k 库内存排序 ~100ms）。语义同构
        # 论证：「近期更新」等带 limit 的视图用户意图即「最新匹配的前 N」，与
        # 「全量收集 → 内存排序 → 取前 N」选出同一集合与同一序。等价性含并列裁决
        # （PERF-087）：SQL 序带固定 tie-breaker（ORDER BY <列> <方向>, is_favorite
        # DESC, updated_at DESC，见 entry_repository._entry_query_clauses），与内存
        # 稳定排序继承的复合序逐层一致——排序键同值并列时（强度刻度 0-4 并列常见、
        # 批量导入 created_at 同刻），截断边界上的入选集合与「全量收集→稳定排序→
        # 截断」完全相同；不带裁决键的引擎内序会在并列+limit 处选出分叉的集合。
        order_pushdown = (
            in_memory_path
            and limit is not None
            and order_by is not None
            and order_by in ORDER_BY_FIELDS
        )
        # SQL 路径的 limit 直接下推；内存路径的 limit 在排序后截断（匹配必须全量，
        # 截断在排序后语义等价于 SQL「ORDER BY ... LIMIT」的前 N；排序下推分支的
        # 截断由匹配循环的提前终止承担）。
        sql_limit = limit if sql_pushdown else None
        # 列表（无搜索词）传 LENIENT：逐行 HMAC 验签并标记篡改条目（不抛异常），使列表
        # 能检测非加密元数据篡改（is_favorite/category_id/password_strength/deleted_at）。
        # _view_decryptor.decrypt_summary 将 raw.integrity_error 透传到 summary，列表
        # delegate 据此显示完整性警示。
        # 进读块前先固定本批缓存 epoch（PERF-086 前移，原在锁外解密前）：首次调用
        # 的重臂（清空+推进 version）若发生在投影拉取**之后**，会把本次刚回填的投影
        # 行集一并清掉，首次调用自废缓存；前移后拉取的版本快照已含重臂推进，回填
        # 可存活。逐条目不再重复校验（同批 epoch 不可能变化）的既有语义不变。
        self._cache.invalidate_if_epoch_changed()
        try:
            with self._vault.epoch_guarded_read():
                query = EntryQuery(
                    deleted_only=deleted_only,
                    category_id=category_id,
                    favorite_only=favorite_only,
                    limit=sql_limit,
                    # 字段序下推（PERF-073/087）：SQL 路径与内存路径的排序下推分支
                    # 都把白名单字段序传入查询（后者的截断由循环提前终止承担）；
                    # 其余内存路径恒传 None——SQL 层保持复合序作为内存排序的稳定基数
                    # （同键条目的相对序继承复合序，与 SQL 字段序的稳定语义一致）。
                    order_by=order_by if (sql_pushdown or order_pushdown) else None,
                    order_desc=order_desc,
                    # 并列裁决键仅搜索的排序下推分支需要（PERF-090）：该分支依赖
                    # 「行集序 == 内存稳定排序序」的等价性（PERF-087）；SQL 直连
                    # 路径（sql_pushdown，与 order_pushdown 互斥）无内存对等路径，
                    # 追加裁决键只会在 updated_at 序上破坏索引下推、纯付 filesort
                    # 成本。
                    tie_break_order=order_pushdown,
                    verify=VerifyMode.LENIENT,
                )
                if in_memory_path:
                    # 窄投影拉取（PERF-074/078）：宽行（e.* + 24 字段 RawEntry 构造）是
                    # 温态主导成本（50k 库实测 656ms，同条件窄投影仅 102ms）；搜索只需
                    # 4 个摘要密文字段做小写匹配，标题序只需 meta.title_lower + 行明文
                    # 排序键。投影无验签（不含签名载荷列），回查完整行时经
                    # get_entries_by_ids 的 LENIENT 验签补偿；未命中/未截断行不验签的
                    # 取舍与 PERF-019 声明一致（篡改检测由无搜索词的全量列表刷新覆盖）。
                    # 行集经投影缓存复用（PERF-086）：行集仅取决于过滤三元组与排序
                    # 规格、与搜索词无关，暖态重复搜索免重拉。键构造收敛至
                    # _projection_cache_key（ARCH-052）单一函数：从本 query 显式提取
                    # 影响行集/行序的维度（未下推排序已在 query 构造点规范化为
                    # order_by=None 的复合序），有序行集与无序行集因消费方对行序敏感
                    # （排序下推分支依赖行序提前终止）不可混存同一键。
                    search_rows = self._cache.search_projection_rows(
                        _projection_cache_key(query),
                        lambda: self.db.get_entries_search_projection(query),
                    )
                    raw_entries = []
                else:
                    search_rows = []
                    raw_entries = self.db.get_entries(query)
                # PERF-001 并发修补（M3）：锁内快照主密钥，锁外解密用快照（语义见 _decrypt_field）。
                key = self._key
                # SEC-041/043 写入方世代：与 raw/key 同刻快照 epoch，供摘要/分类名缓存
                # 回写守卫——后台 worker 在恢复提交（invalidate_all → 新读路径重臂新
                # epoch）后未被取消时，其旧 raw+旧密钥的解密结果不得写入新世代缓存
                # （跨世代 grafting 会把恢复前明文持久污染进新缓存）。该快照覆盖本方法
                # 全部分支（含搜索分支的 decrypt_summary meta 路径——分类名解密经
                # data_epoch 守卫，PERF-074 重写时曾掉落、PERF-078 复核补齐）。
                data_epoch = self._vault.key_epoch
            # 解密移出 db_lock（PERF-001）：with 块内仅读 raw（持锁快速），锁外逐条解密，
            # 释放 db_lock 供 TOTP 定时器读与写入。epoch 已在读块前固定（见方法头
            # PERF-086 前移注释），循环内走无校验路径避免每条目重复加锁取 epoch。
            read = _SummaryRead(
                search_rows=search_rows,
                raw_entries=raw_entries,
                key=key,
                data_epoch=data_epoch,
            )
            if in_memory_path:
                summaries = self._summaries_via_search_projection(
                    read,
                    search=search,
                    order_by=order_by,
                    order_desc=order_desc,
                    limit=limit,
                    cancel_check=cancel_check,
                    pre_sorted=order_pushdown,
                )
            else:
                summaries = self._summaries_from_raw_rows(read, cancel_check)
        except VaultKeyEpochMismatchError:
            return []
        # 内存路径的 limit 已在排序后截断（回查与构建仅前 limit 条），无出口二次截断。
        return summaries

    def _summaries_via_search_projection(
        self,
        read: "_SummaryRead",
        *,
        search: str,
        order_by: str | None,
        order_desc: bool,
        limit: int | None,
        cancel_check: Callable[[], bool] | None,
        pre_sorted: bool = False,
    ) -> list[Entry]:
        """内存路径（搜索/不可下推排序）的摘要构建（MAINT-092 自 get_entry_summaries 拆出）。

        「窄投影全量 → 匹配 → 内存 meta 排序 → 前 limit 回查宽行 → 构建」逐块
        搬运自原单体方法；各块的 PERF/SEC 决策注释随块迁移。``pre_sorted=True``
        （PERF-087 排序下推分支）时行集已按 SQL 白名单序排好，匹配循环凑满
        ``limit`` 即提前终止，跳过内存排序与截断。
        """
        key = read.key
        data_epoch = read.data_epoch
        selected: list[tuple[SearchRow, SearchMetadata]] = []
        # 批量摘要会话（PERF-086）：一次持锁快照命中集、循环内零锁取 meta、退出
        # 一次回写，替代逐行 cached_search_metadata_full 的 N 次 RLock 往返。
        # data_epoch 语义不变（SEC-041）：会话进入时作为整批回写的世代守卫。
        with self._cache.search_metadata_batch(key=key, data_epoch=data_epoch) as batch:
            for row in read.search_rows:
                if cancel_check and cancel_check():
                    break
                # 提前终止（PERF-087）：行集已按目标序排好（pre_sorted）时，凑满
                # limit 个命中即停——limit=0 时首次循环即跳出（与 SQL 路径 LIMIT 0
                # 返回空集的语义对齐，QL-072）。
                if pre_sorted and limit is not None and len(selected) >= limit:
                    break
                # 一次取完整 SearchMetadata，匹配与排序键共用，省第二次缓存查询
                # （PERF-016）。
                meta = batch.get(row)
                if search:
                    # 匹配检查前移到回查/摘要构建之前（PERF-018）：仅命中条目进入
                    # 排序与回查（meta 已含匹配所需小写形式）。
                    if not matches_search_lower(
                        (
                            meta.title_lower,
                            meta.username_lower,
                            meta.url_lower,
                            meta.tags_lower,
                        ),
                        search,
                    ):
                        continue
                selected.append((row, meta))
        # 内存排序（PERF-078）：title 序的键在 meta.title_lower（缓存已有，
        # UI 的 (e.title or "").lower() 与其同源），其余键来自窄投影的明文列
        # ——排序无需宽行 Entry。原「标题序需重构 UI 排序数据流、暂受 1.76s」
        # 的声明被推翻：排序键全在窄行+meta，5k 库实测标题序全量宽行
        # 165.9ms → meta 排序+前 1000 回查 53.8ms（3.1×，50k 等比外推
        # ~1.7s → ~0.5s）。order_by 为 None（搜索调用方未指定排序）时不重排
        # ——窄投影的 SQL 复合序（is_favorite DESC, updated_at DESC）即默认
        # 视图序，稳定排序继承之。排序下推分支（pre_sorted）行集已按目标序
        # 排好，跳过重排。
        if order_by is not None and not pre_sorted:
            # 键函数单一事实源（MAINT-091，模块归属 MAINT-104 迁 services/entry_sorting）：
            # 窄投影行+meta 经 SortKeySource 适配为 Entry 同名属性形态，经
            # entry_sort_key 取键——此前 4 键逻辑在本方法与 UI 各一份（UI 重排入口
            # 已随 QL-074 删除死代码，本路径为键函数唯一生产消费方；title 键直接取
            # meta.title_lower 已小写，经 entry_sort_key 再 .lower() 幂等，语义等价）。
            key_of = entry_sort_key(order_by)

            def sort_key(item: tuple[SearchRow, SearchMetadata]) -> str | int:
                row_i, meta_i = item
                return key_of(
                    SortKeySource(
                        meta_i.title_lower,
                        row_i.password_strength,
                        row_i.created_at,
                        row_i.updated_at,
                    )
                )

            selected.sort(key=sort_key, reverse=order_desc)
        # 截断在排序后（PERF-078 收口）：匹配/收集必须全量，排序后取前 limit
        # 才与「ORDER BY ... LIMIT」语义同构——原实现收集全部命中后**全量回查**
        # 才在出口截断，宽搜索词（单字符命中 20k）时 836ms 反超旧宽行直拉且
        # 双份驻留；现仅回查/构建前 limit 条（5k 全命中实测 187.7ms →
        # 50.6ms，3.7×）。判定统一为 ``is not None``（QL-072）：limit=0 截断为
        # 空集（此前 ``if limit`` 视 0 为 falsy 跳过截断返回全部，与 SQL 路径
        # LIMIT 0 语义分叉）；pre_sorted 分支的截断已由循环提前终止承担。
        if limit is not None and not pre_sorted:
            selected = selected[:limit]
        # 回查完整行（PERF-074）：LENIENT 验签在 db 层 _row_to_entry 完成
        # （替代原 PERF-067 的就地验签——窄投影后宽行不再物化，回查是摘要
        # 构建的必要步骤而非重复读库），损坏行带 integrity_error 标记不抛
        # 异常。无命中/截断后为空时跳过回查（守护「未命中行不回查」的测试
        # 以哨兵 spy 断言零调用）。
        hit_ids = [row.id for row, _meta in selected if row.id is not None]
        full_by_id: dict[int | None, RawEntry] = {}
        if hit_ids:
            for hit_raw in self.db.get_entries_by_ids(hit_ids):
                full_by_id[hit_raw.id] = hit_raw
        summaries = []
        for row, meta in selected:
            # 回查段同样可取消（PERF-078）：原第二段（回查+构建）无探针，宽
            # 搜索词取消后 worker 空转数秒——与第一段 break 语义一致，返回
            # 已构建部分。
            if cancel_check and cancel_check():
                break
            full = full_by_id.get(row.id) if row.id is not None else None
            # 回查缺失（窄投影后行被并发删除）：跳过而非中断——尽力视图，
            # 与列表路径对并发删除的容忍语义一致。
            if full is None:
                continue
            summaries.append(
                self._view_decryptor.decrypt_summary(
                    full,
                    skip_epoch_check=True,
                    key=key,
                    meta=meta,
                    # data_epoch 透传（PERF-078 修复 PERF-074 的回归）：meta 路径
                    # 的 title 等四字段取自 meta 无回写，但分类名解密回写需要
                    # 世代守卫——漏传使搜索 worker 在飞+恢复重臂新世代时旧
                    # 分类名植入新缓存（SEC-043 的搜索分支漏点）。
                    data_epoch=data_epoch,
                )
            )
        return summaries

    def _summaries_from_raw_rows(
        self,
        read: "_SummaryRead",
        cancel_check: Callable[[], bool] | None,
    ) -> list[Entry]:
        """SQL 下推路径（无搜索+白名单字段序）的摘要构建（MAINT-092 自 get_entry_summaries 拆出）。"""
        summaries = []
        for raw in read.raw_entries:
            if cancel_check and cancel_check():
                break
            # 非搜索分支同样透传锁内快照世代（SEC-043）：此前 meta=None 走
            # 缓存侧采样，跨世代后旧明文可植入新 epoch 缓存（与搜索分支
            # 的差异是 SEC-041 的遗留漏点，本处补齐）。
            summaries.append(
                self._view_decryptor.decrypt_summary(
                    raw,
                    skip_epoch_check=True,
                    key=read.key,
                    data_epoch=read.data_epoch,
                )
            )
        return summaries

    def get_recent_summaries(self, limit: int = DEFAULT_RECENT_SUMMARIES_LIMIT) -> list[Entry]:
        """获取最近更新的条目摘要，供「近期更新」视图。

        相较 ``get_entry_summaries``（按 is_favorite DESC, updated_at DESC 排序），
        本方法仅按 updated_at DESC 排序并下推 LIMIT 到 SQL，避免拉全量内存排序
        再截断，消除大库下「近期更新」切换的全量解密与内存驻留开销。

        Args:
            limit: 返回条目数上限。

        读路径经 :meth:`epoch_guarded_read` 守卫（ARCH-005）：改密窗口内 epoch 不一致时
        返回空列表，触发 UI 经变更回调刷新。
        """
        if limit <= 0:
            return []
        # 进读块前先固定本批缓存 epoch（ARCH-056 对齐 get_entry_summaries 的位置
        # 模式，原在锁外解密前）：本路径虽不消费投影行集缓存，但摘要构建的
        # decrypt_summary 回写（分类名缓存等）与其它读路径共用同一 epoch 臂，
        # 「读块后 invalidate」的模式分裂会误导后来者在新读路径复制旧位置——
        # 前移统一后，任何读路径首次调用的重臂（清空+推进 version）都发生在其
        # 拉取/解密之前，不废自己刚回填的缓存（PERF-086 的前移论证同源）。
        self._cache.invalidate_if_epoch_changed()
        try:
            with self._vault.epoch_guarded_read():
                raw_entries = self.db.get_entries(
                    # 字段序下推（PERF-073）：updated_at DESC 明文表达，替代原
                    # sort_by_updated 布尔单字段特例。纯单列序不附加并列裁决键
                    # （PERF-090）：本路径无内存对等路径，裁决键只会把
                    # idx_entries_active_updated 的索引序下推退化为 filesort。
                    EntryQuery(
                        order_by="updated_at",
                        limit=limit,
                        verify=VerifyMode.LENIENT,
                    ),
                )
                # PERF-001 并发修补（M3）：锁内快照主密钥，锁外解密用快照（语义见 _decrypt_field）。
                key = self._key
                # SEC-043 写入方世代：近期更新视图同样快照世代传入缓存回写（语义见
                # get_entry_summaries 处注释），补齐 SEC-041 仅接搜索分支的遗留漏点。
                data_epoch = self._vault.key_epoch
            # 解密移出 db_lock（PERF-001），与 get_entry_summaries 一致；用锁内快照 key
            # 解密。epoch 已在读块前固定（见上方 ARCH-056 注释），此处不再重复校验。
            return [
                self._view_decryptor.decrypt_summary(
                    entry,
                    skip_epoch_check=True,
                    key=key,
                    data_epoch=data_epoch,
                )
                for entry in raw_entries
            ]
        except VaultKeyEpochMismatchError:
            return []

    def get_entry_dedup_index(self) -> list[tuple[str, str, int]]:
        """导入去重对照所需的 ``(title, username, id)`` 明文索引（PERF-075）。

        去重只需 ``(title, username)`` casefold 对照与覆盖目标的 id，原路径经
        ``get_entry_summaries()`` 拉全量摘要——多解密 url/tags 之外的完整 summary
        构建（50k 冷缓存实测 1834ms，导入 worker 后台）。现改搜索同款窄投影 +
        摘要缓存解密：四摘要字段一次解密入会话缓存（去重只消费 title/username，
        但导入后紧随的列表/搜索刷新命中同一缓存，摊销后整体更优），不物化宽行
        与 summary Entry。title 解密失败的条目摘要为空串，被调用方的
        ``if entry.title`` 前置过滤天然排除（与原摘要路径语义一致）。

        行集拉取接投影行集缓存（ARCH-055）：键为「未删除全量 + 复合序」
        （``(False, None, False, None, True)``，经 :func:`_projection_cache_key`
        构造），与搜索路径的无排序投影同键复用——原直连
        ``get_entries_search_projection`` 与 PERF-086 缓存路径并行，50k ~160ms
        全量拉取每次重复支付、导入去重与前后脚的列表/搜索刷新无法互相摊销。
        去重对照取「未删除」条目（与原实现一致）：回收站条目不参与覆盖判定，
        导入同名条目仍走新增而非覆盖已删条目。invalidate_if_epoch_changed
        前移至读块前（对齐 get_entry_summaries 的 PERF-086 前移论证：首次调用
        的 epoch 重臂若发生在投影拉取之后，会把本次刚回填的投影行集一并清掉）。

        读路径经 :meth:`epoch_guarded_read` 守卫，语义与 :meth:`get_entry_summaries`
        一致（改密窗口内 epoch 不一致时返回空列表）。
        """
        # 进读块前先固定本批缓存 epoch（PERF-086 前移，语义见 docstring）。
        self._cache.invalidate_if_epoch_changed()
        try:
            with self._vault.epoch_guarded_read():
                query = EntryQuery(include_deleted=False)
                rows = self._cache.search_projection_rows(
                    _projection_cache_key(query),
                    lambda: self.db.get_entries_search_projection(query),
                )
                key = self._key
                data_epoch = self._vault.key_epoch
            result: list[tuple[str, str, int]] = []
            for row in rows:
                if row.id is None:
                    continue
                meta = self._cache.cached_search_metadata_full(row, key=key, data_epoch=data_epoch)
                result.append((meta.title, meta.username, row.id))
            return result
        except VaultKeyEpochMismatchError:
            return []

    def get_entries_for_export(
        self,
        include_secrets: bool = False,
        cancel_check: Callable[[], bool] | None = None,
        progress: Callable[[int, int], None] | None = None,
    ) -> list[Entry]:
        """获取用于导出的全部条目（不含回收站），默认不解密密码/TOTP。

        走 :meth:`decrypt_entry_for_export` 的 export 模式：任何字段完整性/解密
        失败立即抛 :class:`DecryptionError`（拒绝导出损坏数据；测试断言用的一次性
        全量解密助手见 tests/helpers.decrypt_all_entries，生产 API 面不保留该入口，
        MAINT-098）。``include_secrets=False`` 时跳过 password/totp_secret 解密。

        Args:
            include_secrets: 是否解密 password 与 totp_secret 入结果。
            cancel_check: 可选取消探针，返回真值时中止遍历。
            progress: 可选 ``(done, total)`` 进度回调（PERF-070）：按已解密条目数
                上报，每 ``PROGRESS_REPORT_EVERY`` 条节流、终值恒上报——50k 库解密
                实测 5.1s，此前导出全程不确定旋转。百分比映射由 UI 调用方完成。

        读路径经 :meth:`epoch_guarded_read` 守卫（ARCH-005）：改密窗口内 epoch 不一致时
        抛 :class:`VaultKeyEpochMismatchError` 让导出 worker 据此报错（导出为用户主动
        操作，空结果会误导用户认为成功导出 0 条，故向上传播而非返回空）。
        """
        with self._vault.epoch_guarded_read():
            raw_entries = self.db.get_entries(EntryQuery(include_deleted=False))
            # PERF-001 并发修补（M3）：锁内快照主密钥，锁外解密用快照（语义见 _decrypt_field）。
            key = self._key
            # 锁内快照世代（SEC-049）：分类名缓存回写守卫据此拒收「导出 worker 在飞 +
            # 恢复提交重臂新世代」交错下的跨世代解密结果（与 get_entry/摘要路径对齐）。
            data_epoch = self._vault.key_epoch
        # 解密移出 db_lock（PERF-001）；epoch 不一致已在 with 块内抛 VaultKeyEpochMismatchError
        # 向上传播（导出为用户主动操作，空结果会误导用户）。用锁内快照 key 解密。
        entries = []
        total = len(raw_entries)
        done = 0
        for raw_entry in raw_entries:
            if cancel_check and cancel_check():
                break
            entries.append(
                self.decrypt_entry_for_export(
                    raw_entry, include_secrets, key=key, data_epoch=data_epoch
                )
            )
            done += 1
            if progress is not None and should_report_progress(done, total):
                progress(done, total)
        if progress is not None and total == 0:
            progress(0, 0)  # 空库也上报终值（UI 侧映射为 100，进度不留悬挂）
        return entries

    def toggle_favorite(self, entry_id: int) -> bool | None:
        """切换收藏状态，返回新的收藏状态；条目不存在时返回 None。

        在单个事务内完成读-改-写，避免 TOCTOU 竞态。
        ``db.update_entry`` 写入时由 ``MetadataSigner`` 自动重签 metadata_mac，
        保证元数据完整性。
        """
        with self._vault.epoch_guarded_transaction(operation="切换收藏"):
            raw = self._vault.db.get_entry(entry_id)
            if raw is None:
                return None
            raw = replace(raw, is_favorite=not raw.is_favorite)
            self._vault.db.update_entry(raw)
            result = raw.is_favorite
        # 收藏切换是纯旁路变更：is_favorite 不进入安全报告（weak/duplicate/old）的
        # 判定或展示，也不在摘要/标签/分类名缓存中。password_changed=metadata_changed=
        # False 使 SecurityAnalyzer 跳过无谓的整库重解密，其余三者缓存亦无需失效；
        # 列表排序变化由回调触发 SQL 重查，复用摘要缓存避免重解密。
        self._change_bus.notify(
            password_changed=False,
            clear_summaries=False,
            tags_changed=False,
            metadata_changed=False,
        )
        return result

    def get_entry_count(self, include_deleted: bool = False) -> int:
        """获取条目总数。委托 vault。"""
        return self._vault.db.get_entry_count(include_deleted)

    def get_all_tags(self) -> list[tuple[str, int]]:
        """获取所有标签及其使用频率。委托 cache。"""
        return self._cache.get_all_tags()

    @property
    def tags_cache_valid(self) -> bool:
        """标签缓存是否有效，委托 cache。供 UI 决定标签下拉同步/异步刷新。"""
        return self._cache.tags_cache_valid
