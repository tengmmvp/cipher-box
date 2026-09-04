"""条目管理器，负责密码条目的加密 CRUD 操作。

直接依赖 crypto_utils 的加解密原语（crypto_utils 同属 Business 层服务，非跨层依赖）；
分类/TOTP/密码历史/校验/变更通知/视图解密/查询读等职责拆至子服务与独立模块，本类
聚焦条目 CRUD 的写路径（加密、epoch 守卫事务、变更通知与缓存失效差分），经 property
暴露分类/TOTP/历史子服务。视图解密族（详情/导出/摘要的 raw→Entry 纯变换）下沉至
services/entry_view_decryption 的 EntryViewDecryptor（MAINT-021）；查询读族
（列表摘要/详情/近期更新/导入去重/导出读取的锁内外编排）下沉 services/entry_queries
的 EntryQueryService（MAINT-116）——公开查询方法保持薄委托，调用方零改动。
"""

import json
import logging
import uuid
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .vault_manager import VaultManager

from ...crypto.password_generator import PasswordGenerator
from ...database.types import VaultDataStore
from ...exceptions import (
    DecryptionError,
    EntryIntegrityError,
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
from ..services.db_checkpoint import safe_checkpoint
from ..services.entry_queries import EntryQueryService, EntryRead
from ..services.entry_validation import validate_plain_entry
from ..services.entry_view_decryption import EntryViewDecryptor
from ..services.password_history_service import PasswordHistoryService
from ..services.password_service import PasswordService
from ..services.totp_service import TotpService
from .category_manager import CategoryManager
from .entry_cache import EntryCacheManager
from .entry_change_bus import EntryChangeBus

logger = logging.getLogger(__name__)


class EntryManager:
    """管理密码条目的加密、解密和 CRUD 操作。

    现存 6 个「收窄转发」薄委托（MAINT-122）：MAINT-021 的 ``decrypt_entry`` 与
    MAINT-116 的查询读族五方法（export 委托已随 MAINT-118 删除），为下沉时调用方
    零改动的过渡保留；退役路径是经 property 或 BusinessContext 公开
    ``EntryQueryService``、消费方迁移后删除对应委托，新增查询直接落在查询服务。
    """

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
        # 查询读子服务（MAINT-116 下沉）：列表摘要/详情/近期更新/导入去重/导出
        # 读取的锁内外读路径编排。同为无状态子服务，内部构造并共用同一 cache
        # 与 view_decryptor 实例（ARCH-033），公开查询方法保持薄委托。
        self._query_svc = EntryQueryService(vault_manager, cache, self._view_decryptor)

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

    # ---- 单条写路径纪律（集中声明；bulk 写路径同款约束见 entry_batch_writer）----
    # 「写路径遗漏 per-site 失效」目前无结构强制（SEC-063 seam 只覆盖事务写），
    # 新增/修改写方法时对照本 checklist 逐项核对：
    # 1. pop-before-write：触及 totp_secret 或条目生死的写在写库**前** pop_totp /
    #    clear_totp（QL-070/075——「写库 → 失效」窗口内 TOTP 定时器命中旧 secret
    #    生成过期验证码）；
    # 2. 写后闭环：非事务删除写（soft_delete / permanent_delete / empty_trash
    #    不经 epoch_guarded_transaction）在写后补一轮失效（SEC-072），使条目/
    #    整体水位越过一切提交前快照；事务写的提交由 SEC-063 seam 自动 clear_totp
    #    兜底（旁路写如 toggle_favorite 也触发，代价一次重解密）；
    # 3. epoch 守卫：写包进 epoch_guarded_transaction(pre_epoch=)（SEC-069），
    #    「加密后 → 写入前」窗口内改密时中止回滚；非事务写须显式论证（db 层
    #    enforce_key_epoch 仍在写入瞬间把关）；
    # 4. 差分世代快照（expected_version）在写事务前捕获（QL-065），提交后差分
    #    经守卫复查，堵「读 raw → 提交 → 差分」窗口内并发失效+重建的双扣。
    # TOTP secret 的解密与缓存回写必须留在 GUI 线程（ARCH-054 线程模型约束，
    # 理由与违反后果见 entry_cache 模块 docstring）——上述 1/2 的窗口推演均以
    # 该约束为纵深前提。
    def add_entry(
        self,
        entry: Entry,
        *,
        notify: bool = True,
        skip_validation: bool = False,
    ) -> int:
        """添加新条目，自动加密并检测强度。

        线程安全（SEC-069）：加密前快照 key_epoch、写入包进 epoch 守卫事务——
        「加密后 → 写入前」窗口内改密（commit+activate 完成）时写入中止回滚，
        旧密钥密文不落入已轮换为新 epoch 的库（与 update_entry/导入/恢复同款
        防御层）；加密保持在事务外，不占 db_lock。

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

        # epoch 守卫事务接入（SEC-069）：对齐 update_entry/toggle_favorite/导入/恢复
        # 的写路径防御层——此前 add_entry 是「锁外加密（实时 self._key）→ 直接
        # db.add_entry」，仅靠写入瞬间 enforce_key_epoch；「加密后 → 写入前」窗口
        # 内改密完成 commit+activate 时，旧密钥密文会落入已轮换为新 epoch 的库并
        # 永久不可解密（此前不可达仅靠 GUI 线程模态串行的巧合，正是 SEC-063 注释
        # 点名要消除的形态）。pre_epoch 在加密前快照（同 MAINT-004 导入路径的
        # 透传形态）；加密保持在事务外（CPU 密集段不占 db_lock）。
        pre_epoch = self.key_epoch
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
        # 事务提交 seam 只推进 TOTP 域（clear_totp）不动主域，不影响本快照。
        expected_version = self._cache.invalidate_version
        with self.epoch_guarded_transaction(operation="新增条目", pre_epoch=pre_epoch):
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
        # 写后 TOTP 再清（SEC-072，与前置 pop 互补）：软删除是非事务写
        # （db.soft_delete_entry 隐式提交，不经 epoch_guarded_transaction，SEC-063
        # seam 不覆盖），前置 pop 记录的条目水位为 pop 完成时刻的版本 N——「恰在
        # pop 后快照」的读者（data_version=N）读到尚未删除的活跃行，删除提交后
        # 其 store 复查 N > N 为 False 仍被放行，软删条目的明文 secret 重入缓存。
        # 写后再 pop 把水位推过 N：任何早于提交的快照自此恒被拒收。写路径自身的
        # 失效闭环不依赖其后的通知链（notify 的 apply_change 亦推进全局水位，但
        # 依赖其时序属巧合约束）；「提交 → 再 pop」间在 GUI 线程串行下不可插入
        # （ARCH-054 线程模型），跨线程交错需违反该模型的后台 store 方可命中。
        self._cache.pop_totp(entry_id)
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
        """恢复条目。返回是否实际执行（条目存在）。

        TOTP 语义（跨方法耦合，SEC-072 pin）：恢复不自带 TOTP 失效也不回填——
        restore 不改 totp_secret，「软删条目的 secret 不在缓存」依赖 delete_entry
        已 pop（含写后再清）。若未来删除路径的失效被移除，本路径将成为旧 secret
        驻留的唯一缺口；该依赖由 TestRestoreEntryTotpCoupling 行为锚定。
        """
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
        # 写后 TOTP 再清（SEC-072，语义同 delete_entry）：物理删除同为非事务写
        # （seam 不覆盖），写后再 pop 使条目水位越过一切提交前快照——「恰在
        # pop 后快照」的读者在删除提交后 store 不再把已物理删除条目的明文
        # secret 重入缓存。
        self._cache.pop_totp(entry_id)
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
        # seam 不覆盖，前置清空覆盖「清空 → 写库」窗口。
        self._cache.clear_totp()
        self._vault.db.empty_trash()
        # 写后 TOTP 再清（SEC-072，语义同 delete_entry 的写后再 pop）：非事务写的
        # 失效闭环——「恰在前置 clear 后快照」的读者在物理删除提交后 store 不再把
        # 已删除条目的明文 secret 重入缓存（整体失效水位越过一切提交前快照）。
        self._cache.clear_totp()
        # 通知降级为纯旁路语义（PERF-088）：回收站条目不在活跃分析集合——软删除时
        # 已按 PERF-079 增量差分移出 SecurityAnalyzer 缓存与标签计数，物理清空不
        # 改变活跃集合，故 password_changed/metadata_changed=False：
        # - SecurityAnalyzer.invalidate_caches 对双 False 直接返回，跳过整库 O(n)
        #   重解密重算（原零参 notify 默认双 True 触发状态栏 worker 全量重算）；
        # - category_mgr 的计数订阅同样跳过（get_category_entry_counts 过滤
        #   is_deleted=0，回收站条目本就不计入分类计数）。
        # 其余失效面不受降级影响：apply_change 仍整体执行（tags_changed/
        #   clear_summaries 默认 True + 推进 version），摘要/标签缓存与投影行集
        # 缓存（PERF-086）照常失效，回收站（deleted_only）视图的行集正确性保持。
        self._change_bus.notify(password_changed=False, metadata_changed=False)
        # 数据已提交，截断失败非致命；与改密/恢复/解锁路径共用 safe_checkpoint 降级
        # （QL-079 收窄元组的单一事实源，此处曾漏写 OSError 致 ACL 失败在物理删除
        # 成功后仍报硬错误）。
        safe_checkpoint(self._vault.db, "清空回收站后 WAL 安全截断失败（非致命）")

    def get_entry(self, entry_id: int) -> Entry | None:
        """获取并解密单个条目。

        读路径经 :meth:`epoch_guarded_read` 守卫（ARCH-005）：with 块内仅读 raw、解密移
        锁外（与摘要路径 PERF-001 一致）；epoch 不一致时返回 None，调用方据此跳过。

        实现（SEC-054 闭合）委托 :meth:`get_entry_with_epoch` 后丢弃世代与版本。
        """
        return self.get_entry_with_epoch(entry_id).entry

    def get_entry_with_epoch(self, entry_id: int) -> EntryRead:
        """获取并解密单个条目，随行携带解密世代与 TOTP 域版本（:class:`EntryRead`）。

        实现（MAINT-116 下沉）委托 :meth:`EntryQueryService.get_entry_with_epoch`；
        世代/版本锁内同刻快照的语义（SEC-054 / SEC-063 b 层）与预热链消费方见
        :class:`EntryRead`。
        """
        return self._query_svc.get_entry_with_epoch(entry_id)

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
        """获取不含密码等敏感明文的列表摘要（薄委托，MAINT-116 下沉）。

        ``limit``/``order_by``/``order_desc`` 的 SQL 下推与截断契约
        （PERF-073/078/087/090，含 limit=0 返回空集的 QL-072 统一）、epoch 守卫
        语义（ARCH-005，改密窗口返回空列表、锁定期 VaultLockedError 传播）与
        内存/SQL 路径分派的实现见
        :meth:`EntryQueryService.get_entry_summaries`。
        """
        return self._query_svc.get_entry_summaries(
            deleted_only,
            category_id,
            favorite_only,
            search,
            limit,
            cancel_check,
            order_by=order_by,
            order_desc=order_desc,
        )

    def get_recent_summaries(self, limit: int = DEFAULT_RECENT_SUMMARIES_LIMIT) -> list[Entry]:
        """获取最近更新的条目摘要，供「近期更新」视图（薄委托，MAINT-116 下沉）。

        仅按 updated_at DESC 排序并下推 LIMIT 到 SQL（PERF-073，无内存对等路径
        故不附加并列裁决键，PERF-090）；epoch 守卫语义（ARCH-005/056）与实现见
        :meth:`EntryQueryService.get_recent_summaries`。
        """
        return self._query_svc.get_recent_summaries(limit)

    def get_entry_dedup_index(self) -> list[tuple[str, str, int]]:
        """导入去重对照所需的 ``(title, username, id)`` 明文索引（薄委托，MAINT-116 下沉）。

        窄投影 + 摘要缓存解密（PERF-075）与投影行集缓存同键复用（ARCH-055）的
        实现见 :meth:`EntryQueryService.get_entry_dedup_index`。
        """
        return self._query_svc.get_entry_dedup_index()

    def get_entries_for_export(
        self,
        include_secrets: bool = False,
        cancel_check: Callable[[], bool] | None = None,
        progress: Callable[[int, int], None] | None = None,
    ) -> list[Entry]:
        """获取用于导出的全部条目（不含回收站），默认不解密密码/TOTP（薄委托，MAINT-116 下沉）。

        严格解密语义（任一字段损坏即抛 :class:`DecryptionError` 拒绝导出）、
        进度节流（PERF-070）与 epoch 守卫（ARCH-005，失配向上传播而非返回空）
        的实现见 :meth:`EntryQueryService.get_entries_for_export`。
        """
        return self._query_svc.get_entries_for_export(include_secrets, cancel_check, progress)

    def toggle_favorite(self, entry_id: int) -> bool | None:
        """切换收藏状态，返回新的收藏状态；条目不存在时返回 None。

        在单个事务内完成读-改-写，避免 TOCTOU 竞态。
        ``db.update_entry`` 写入时由 ``MetadataSigner`` 自动重签 metadata_mac，
        保证元数据完整性。

        not-found 前置读检查在事务外（SEC-063 演进，空事务不触发 seam）：原先
        早退在 with 块内，条目不存在也会空提交——统一失效 seam 在提交后无条件
        触发，清空全部 TOTP 缓存并推进全局水位（展示中条目下一 tick 重解密一次，
        churn-only）。前置检查本身无需事务：``entry_exists`` 是 ``@_db_operation``
        持锁纯读；toggle 的读-改-写原子性仍由事务内复读承担，前置检查与事务
        开闸间条目被并发删除的罕见竞态由事务内 ``raw is None`` 分支兜底（该
        竞态路径的空提交如实触发 seam——并发删除本就应失效 TOTP 缓存）。

        前置检查走轻量 EXISTS 探测（PERF-099，原为 ``get_entry``）：存在性判定
        无需宽行读取与 STRICT 验签，读-改-写仍由事务内复读承担；错误语义不变。
        """
        if not self._vault.db.entry_exists(entry_id):
            return None
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
