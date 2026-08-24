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
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .vault_manager import VaultManager

from ...crypto.password_generator import PasswordGenerator
from ...database.types import EntryQuery, VaultDataStore, VerifyMode
from ...exceptions import (
    DecryptionError,
    EntryIntegrityError,
    VaultKeyEpochMismatchError,
)
from ...models import (
    CustomField,
    Entry,
    RawEntry,
)
from ...utils.format import utc_now_iso
from ...utils.memory import secure_zero_buffer
from ..services.crypto_utils import (
    SENSITIVE_ENCRYPTED_FIELDS,
    decrypt_field as _decrypt_field_impl,
    encrypt_field as _encrypt_field_impl,
    matches_search_lower,
    require_vault_key,
)
from ..services.entry_batch_writer import PROGRESS_REPORT_EVERY
from ..services.entry_validation import validate_plain_entry
from ..services.entry_view_decryption import EntryViewDecryptor
from ..services.metadata_signer import MetadataSigner, verify_raw
from ..services.password_history_service import PasswordHistoryService
from ..services.password_service import PasswordService
from ..services.totp_service import TotpService
from .category_manager import CategoryManager
from .entry_cache import EntryCacheManager, SearchMetadata
from .entry_change_bus import EntryChangeBus

logger = logging.getLogger(__name__)

# 「近期更新」视图默认拉取的条目数，供 get_recent_summaries 默认 limit。
DEFAULT_RECENT_SUMMARIES_LIMIT = 20


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
        # TOTP/密码历史为无状态子服务，保持内部构造。
        self._category_mgr = category_mgr
        self._totp_svc = TotpService(vault_manager, cache)
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
        穿透 ``_vault``。语义与 ``VaultManager.epoch_guarded_transaction`` 一致。
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
    ) -> Entry:
        """仅解密导出所需字段，默认不让密码与 TOTP 进入内存结果。

        任何完整性/解密失败立即抛 :class:`DecryptionError`（拒绝导出损坏数据）；
        ``include_secrets=False`` 时跳过 password/totp_secret 解密。

        ``key`` 语义见 :meth:`_decrypt_field`（PERF-001 并发修补）。

        实现委托 :class:`EntryViewDecryptor.decrypt_entry_for_export`（MAINT-021 下沉）。
        """
        return self._view_decryptor.decrypt_entry_for_export(
            raw_entry, include_secrets=include_secrets, key=key
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
        result = self._vault.db.add_entry(
            enc_entry,
            preserve_metadata=bool(entry.created_at or entry.updated_at),
        )
        if notify:
            # 新增不改变既有摘要，clear_summaries=False 保留缓存避免全量重解密；
            # tags 分布与 total/重复分组变化仍由默认 tags_changed/password_changed 失效。
            self._change_bus.notify(clear_summaries=False)
        return result

    def update_entry(
        self,
        entry: Entry,
        *,
        preserve_password_changed_at: bool = False,
        notify: bool = True,
        preloaded_raw: RawEntry | None = None,
        preloaded_old_password: str | None = None,
    ) -> None:
        """更新条目，自动加密并记录密码历史。

        preloaded_raw / preloaded_old_password：可选的复用注入——调用方已持有该条目
        的密文 raw / 已解密旧密码时传入，跳过 ``get_entry`` 重读与旧密码解密。当前
        生产路径均不使用（导入覆盖已改走 ``entry_batch_writer.prepare_overwrite_updates``
        → ``update_overwrite_batch`` 单事务批量写入，其 old_password 恒传 None 走
        :meth:`prepare_password_update` 的默认解密分支）；参数保留是为签名兼容与
        潜在外部调用（如未来的单条覆盖路径复用此入口），语义仍是「复用已读数据」。

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
        # preloaded_raw 非空时复用调用方已读的密文 raw（见 docstring：当前无生产调用方）。
        raw = preloaded_raw if preloaded_raw is not None else self.db.get_entry(entry.id)
        if raw is None:
            return

        # 条目更新可能修改 totp_secret，失效该条目的 TOTP secret 缓存，
        # 下次 TotpService.get_state / generate_cached 重新解密。
        self._cache.pop_totp(entry.id)

        new_pwd_enc, password_changed = self.prepare_password_update(
            entry,
            raw,
            preloaded_old_password,
        )
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
        with self.db.transaction():
            # epoch 复查：enforce_key_epoch 事务内跳过，单条写路径须自行复查，
            # 防止 read（事务外）到 commit（事务内）期间改密导致写入旧密钥密文。
            if self.key_epoch != pre_epoch:
                raise VaultKeyEpochMismatchError(
                    "更新期间检测到密钥变更（改密/锁定），已中止以防写入旧密钥密文"
                )
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
            self._notify_entry_updated(raw, entry, password_changed)

    def prepare_password_update(
        self,
        entry: Entry,
        raw: RawEntry,
        preloaded_old_password: str | None,
    ) -> tuple[str, bool]:
        """检测密码变更并加密新密码，返回 (新密码密文, 是否变更)。

        必须解密旧密码与明文比较——AES-GCM 用随机 nonce，密文比较不可行；HMAC 指纹
        方案需 schema 变更，当前解密比较是无需迁移的合理选择。常量时间比较
        （:meth:`PasswordService.passwords_match`，经 utf-8 编码的
        ``hmac.compare_digest`）避免时序侧信道。preloaded_old_password 为调用方已
        解密的旧密码复用（当前无生产调用方——导入批量路径传 None 走下方默认解密
        分支，见 :meth:`update_entry` 的参数说明）。
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

    def _notify_entry_updated(
        self,
        raw: RawEntry,
        entry: Entry,
        password_changed: bool,
    ) -> None:
        """update_entry 后的变更通知：检测 tags 是否变更以决定标签缓存失效粒度。

        摘要缓存按 crypto_id 单条精细失效（避免标题/URL 编辑触发全量重解密）；
        raw.tags 解密失败时保守视为 tags 已变（仍失效标签缓存）。

        分类归属变化（单条编辑可改 category_id）影响分类条目计数缓存（PERF-064）：
        bus 的 crypto_id 单条通道无法表达该维度，此处显式失效——纯字段编辑
        （归属未变）不失效，保住侧边栏刷新的计数缓存命中。
        """
        if entry.category_id != raw.category_id:
            self._category_mgr.invalidate_entry_counts_cache()
        try:
            old_tags = (
                self._decrypt_field(raw.tags, raw.crypto_id, "tags", strict=True)
                if raw.tags
                else ""
            )
            tags_decrypt_failed = False
        except DecryptionError:
            old_tags = ""
            tags_decrypt_failed = True
        self._change_bus.notify(
            password_changed,
            crypto_id=raw.crypto_id,
            # 解密失败时保守视为 tags 已变以失效标签缓存。
            tags_changed=tags_decrypt_failed or (old_tags != entry.tags),
        )

    def delete_entry(self, entry_id: int) -> bool:
        """软删除条目，移入回收站。返回是否实际执行（条目存在）。"""
        if not self._vault.db.soft_delete_entry(entry_id):
            return False
        self._cache.pop_totp(entry_id)
        # 软删除仅切换 is_deleted，不改变摘要内容，保留摘要缓存避免全量重解密；
        # tags 分布与 total/重复分组变化由默认 tags_changed/password_changed 失效。
        self._change_bus.notify(clear_summaries=False)
        return True

    def restore_entry(self, entry_id: int) -> bool:
        """恢复条目。返回是否实际执行（条目存在）。"""
        if not self._vault.db.restore_entry(entry_id):
            return False
        # 恢复仅切换 is_deleted，不改变摘要内容，保留摘要缓存（同 delete_entry 理由）。
        self._change_bus.notify(clear_summaries=False)
        return True

    def permanent_delete_entry(self, entry_id: int) -> None:
        """永久删除条目。"""
        self._vault.db.permanent_delete_entry(entry_id)
        self._cache.pop_totp(entry_id)
        self._change_bus.notify()

    def empty_trash(self) -> None:
        """清空回收站。

        批量删除后统一 secure_checkpoint：收缩 WAL（清除已删除条目旧密文扇区残留）
        并刷新 -wal/-shm 文件权限，避免每条 DELETE 各自 checkpoint 的 O(n) 次
        TRUNCATE+fsync。
        """
        self._vault.db.empty_trash()
        self._cache.clear_totp()
        self._change_bus.notify()
        # 数据已提交，WAL 截断失败非致命（仅旧密文残留收缩失败）；与改密/恢复/解锁路径
        # 对称地降级为告警，避免截断异常冒泡使 UI 显示模糊错误（secure_checkpoint 失败
        # 上抛 DatabaseError，见 SEC-010）。
        try:
            self._vault.db.secure_checkpoint()
        except Exception:
            logger.warning("清空回收站后 WAL 安全截断失败（非致命）", exc_info=True)

    def get_entries(
        self,
        deleted_only: bool = False,
        include_deleted: bool = False,
        category_id: int | None = None,
        favorite_only: bool = False,
    ) -> list[Entry]:
        """获取并解密全部条目（含 password/totp_secret 等敏感字段）。

        生产代码无调用方——列表用 :meth:`get_entry_summaries`、详情用 :meth:`get_entry`、
        导出用 :meth:`get_entries_for_export`；本方法解密全部密码的入口主要供测试断言与
        「一次性获取全部明文」场景（QL-001）。

        读路径经 :meth:`epoch_guarded_read` 守卫（ARCH-005）：with 块内仅读 raw，解密移
        锁外（PERF-001）；改密窗口内 epoch 不一致时返回空列表触发 UI 刷新；锁定期
        :class:`VaultLockedError` 正常传播。
        """
        try:
            with self._vault.epoch_guarded_read():
                raw_entries = self._vault.db.get_entries(
                    EntryQuery(
                        deleted_only=deleted_only,
                        include_deleted=include_deleted,
                        category_id=category_id,
                        favorite_only=favorite_only,
                    )
                )
                # PERF-001 并发修补（M3）：密钥快照须在 epoch 校验通过后、锁内取——
                # 锁外解密期间发生改密 activate 后，实时 self._key 已轮换为新密钥，
                # 与本批旧密文不匹配会致 GCM 认证失败、错误摘要以新 epoch 写入缓存
                # 持续污染。锁内快照保证 raw 与 key 同 epoch，锁外用快照解密旧密文。
                key = self._key
                # SEC-043 写入方世代：与 raw/key 同刻快照 epoch，供缓存回写守卫
                # 拒收跨世代解密结果（语义见 get_entry_summaries 处注释）。
                data_epoch = self._vault.key_epoch
            # 解密移出 db_lock（PERF-001），与摘要路径一致；用锁内快照 key 解密。
            decrypted = [self.decrypt_entry(e, key=key, data_epoch=data_epoch) for e in raw_entries]
        except VaultKeyEpochMismatchError:
            return []
        for dec_entry in decrypted:
            if dec_entry.integrity_error:
                logger.warning("条目 %d 解密存在异常", dec_entry.id)
        return decrypted

    def get_entry(self, entry_id: int) -> Entry | None:
        """获取并解密单个条目。

        读路径经 :meth:`epoch_guarded_read` 守卫（ARCH-005）：with 块内仅读 raw、解密移
        锁外（与摘要路径 PERF-001 一致）；epoch 不一致时返回 None，调用方据此跳过。
        """
        try:
            with self._vault.epoch_guarded_read():
                raw = self._vault.db.get_entry(entry_id)
                # PERF-001 并发修补（M3）：锁内快照主密钥，锁外解密用快照（见 get_entries）。
                key = self._key
                # SEC-043 写入方世代：详情路径同样快照世代传入缓存回写（语义见
                # get_entry_summaries 处注释）——此前仅搜索分支接入，详情的摘要/
                # 分类名缓存回写退回缓存侧采样，跨世代后旧明文可植入新 epoch 缓存。
                data_epoch = self._vault.key_epoch
        except VaultKeyEpochMismatchError:
            return None
        if raw is None:
            return None
        return self.decrypt_entry(raw, key=key, data_epoch=data_epoch)

    def get_entry_summaries(
        self,
        deleted_only: bool = False,
        category_id: int | None = None,
        favorite_only: bool = False,
        search: str = "",
        limit: int | None = None,
        cancel_check: Callable[[], bool] | None = None,
    ) -> list[Entry]:
        """获取不含密码等敏感明文的列表摘要。

        Note:
            ``limit`` 的生效方式取决于 ``search``：
            - ``search`` 为空时，``limit`` 在 SQL 层生效（LIMIT 子句），高效截断。
            - ``search`` 非空时，因摘要字段已加密，必须先全量解密搜索摘要再过滤。
              此时 ``limit`` 不下推到 SQL（否则会先
              截断再过滤，导致搜索命中远少于实际），由调用方在内存过滤后自行截断。
              即当 search 非空时本方法忽略 limit，返回全部命中结果。

        读路径经 :meth:`epoch_guarded_read` 守卫（ARCH-005）：改密窗口内 epoch 不一致时
        返回空列表，触发 UI 经变更回调刷新。锁定期 :class:`VaultLockedError` 仍正常传播。
        """
        # search 非空时不向 SQL 下推 limit，避免「先截断后过滤」导致命中失真。
        sql_limit = limit if not search else None
        # 列表（无搜索词）传 LENIENT：逐行 HMAC 验签并标记篡改条目（不抛异常），使列表
        # 能检测非加密元数据篡改（is_favorite/category_id/password_strength/deleted_at）。
        # _view_decryptor.decrypt_summary 将 raw.integrity_error 透传到 summary，列表
        # delegate 据此显示完整性警示。
        try:
            with self._vault.epoch_guarded_read():
                raw_entries = self.db.get_entries(
                    EntryQuery(
                        deleted_only=deleted_only,
                        category_id=category_id,
                        favorite_only=favorite_only,
                        limit=sql_limit,
                        # 搜索路径先 SKIP 拉取（PERF-019）：温缓存下搜索的耗时主导是
                        # 全部行的逐行 HMAC 验签 + e.* 全列物化（摘要解密≈0 时反转为主
                        # 导成本，实测 2000 条目 94-213ms/次）；改 SKIP 拉取后仅对匹配
                        # 命中的行补验签（见 _reverify_search_matches）。
                        # 安全取舍：未命中的行不验签，其篡改检测由无搜索词的全量
                        # 列表刷新（LENIENT）覆盖——搜索只是列表的过滤视图，篡改行
                        # 在回到全量视图时仍会被标记。
                        verify=VerifyMode.SKIP if search else VerifyMode.LENIENT,
                    )
                )
                # PERF-001 并发修补（M3）：锁内快照主密钥，锁外解密用快照（见 get_entries）。
                key = self._key
                # SEC-041/043 写入方世代：与 raw/key 同刻快照 epoch，供摘要缓存回写守卫——
                # 后台 worker 在恢复提交（invalidate_all → 新读路径重臂新 epoch）后
                # 未被取消时，其旧 raw+旧密钥的解密结果不得写入新世代缓存（跨世代
                # grafting 会把恢复前明文持久污染进新缓存）。SEC-043 将该快照从仅
                # 搜索分支扩展到非搜索列表分支（本方法）与 get_recent_summaries/
                # get_entry/SecurityAnalyzer 全部读路径。
                data_epoch = self._vault.key_epoch
            # 解密移出 db_lock（PERF-001）：with 块内仅读 raw（持锁快速），锁外逐条解密，
            # 释放 db_lock 供 TOTP 定时器读与写入。循环外一次性 invalidate_if_epoch_changed
            # 固定本批缓存 epoch，循环内走无校验路径避免每条目重复加锁取 epoch。
            self._cache.invalidate_if_epoch_changed()
            # search 与非 search 共用同一循环：search 时在 append 前做 matches_search 过滤。
            # 摘要字段首次搜索后进入会话缓存，后续搜索无重复解密成本。
            summaries = []
            if search:
                matched: list[tuple[RawEntry, SearchMetadata]] = []
                for raw in raw_entries:
                    if cancel_check and cancel_check():
                        break
                    # 搜索：一次取完整 SearchMetadata，摘要与小写匹配共用，省第二次缓存查询（PERF-016）。
                    # data_epoch 传锁内快照世代，回写守卫据此拒收跨世代解密结果（SEC-041）。
                    meta = self._cache.cached_search_metadata_full(
                        raw, key=key, data_epoch=data_epoch
                    )
                    # 匹配检查前移到摘要构建之前（PERF-018）：仅命中条目才走完整
                    # decrypt_summary，省去未命中条目的 Entry 构造 + 分类名/failed_fields
                    # 缓存查询（meta 已含匹配所需小写形式）。
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
                    matched.append((raw, meta))
                # 命中行就地 LENIENT 验签（PERF-019/067）：损坏→integrity_error 标记不抛异常。
                verified_by_id = self._reverify_search_matches(matched, key=key)
                for raw, meta in matched:
                    verified = verified_by_id.get(raw.id) if raw.id is not None else None
                    summaries.append(
                        self._view_decryptor.decrypt_summary(
                            verified if verified is not None else raw,
                            skip_epoch_check=True,
                            key=key,
                            meta=meta,
                        )
                    )
            else:
                for raw in raw_entries:
                    if cancel_check and cancel_check():
                        break
                    # 非搜索分支同样透传锁内快照世代（SEC-043）：此前 meta=None 走
                    # 缓存侧采样，跨世代后旧明文可植入新 epoch 缓存（与搜索分支
                    # 的差异是 SEC-041 的遗留漏点，本处补齐）。
                    summaries.append(
                        self._view_decryptor.decrypt_summary(
                            raw,
                            skip_epoch_check=True,
                            key=key,
                            data_epoch=data_epoch,
                        )
                    )
        except VaultKeyEpochMismatchError:
            return []
        # search 时 limit 未下推 SQL（避免先截断后过滤致命中失真），此处截断兑现契约
        if search and limit:
            summaries = summaries[:limit]
        return summaries

    def _reverify_search_matches(
        self,
        matched: list[tuple[RawEntry, SearchMetadata]],
        *,
        key: bytes,
    ) -> dict[int, RawEntry]:
        """对全部搜索命中的行就地 LENIENT 补验签（PERF-019/032/067），返回 ``{id: raw}``。

        搜索路径的拉取改用 VerifyMode.SKIP（见 get_entry_summaries 处注释），完整性
        标记由此处补偿。PERF-067 前的实现经 ``get_entries_by_ids``（LENIENT）对命中
        行二次读库验签——命中行的 RawEntry 本已物化在内存，二次 SQL 读纯属重复：
        实测 5000 ids 234.6ms、50k 1.3-2s（约为 PERF-019 注释所估 15.6µs/行的 3 倍，
        SQL 读+行物化而非纯 HMAC），且第二份宽行物化使 50k 库多驻留 ~208MB。现经
        :func:`metadata_signer.verify_raw` 对已物化的行就地 HMAC 验签：域密钥由与
        解密同源的锁内快照主密钥派生（raw/密钥/域密钥同 epoch），比对语义与 db 层
        ``_row_to_entry`` 的 verifier 钩子一致。就地验签不再持 db_lock（原二次读库
        须进读守卫），跨世代污染由调用方已就位的 data_epoch 缓存守卫兜底。

        损坏行经 ``dataclasses.replace`` 置 integrity_error 标志而非抛异常（保持列表
        路径的 LENIENT 语义，文案与 _row_to_entry 的 LENIENT 分支归一一致）。

        PERF-032（修订 PERF-019 的 1000 行验签上界）：UI 按排序字段重排 + 标签过滤
        后才截断渲染，验签集合须覆盖全部命中行（SQL 序 1000 名之外仍可能落入渲染
        窗口）。就地验签消除 SQL 读后，全量验签仅剩纯 HMAC 计算，亦无
        ``get_entries_by_ids`` 的主机变量分批需求。
        """
        verified: dict[int, RawEntry] = {}
        if not matched:
            return verified
        # 域密钥派生自锁内快照主密钥（一次性 HMAC），用毕原地清零（与
        # compute_vault_meta_mac 的域密钥清零纪律一致）。
        domain_key = MetadataSigner.compute_domain_key(key)
        try:
            for raw, _meta in matched:
                if raw.id is None:
                    continue
                verified[raw.id] = (
                    raw
                    if verify_raw(raw, domain_key)
                    else replace(
                        raw,
                        integrity_error=True,
                        integrity_message="元数据完整性校验失败",
                    )
                )
        finally:
            secure_zero_buffer(domain_key)
        return verified

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
        try:
            with self._vault.epoch_guarded_read():
                raw_entries = self.db.get_entries(
                    EntryQuery(sort_by_updated=True, limit=limit, verify=VerifyMode.LENIENT),
                )
                # PERF-001 并发修补（M3）：锁内快照主密钥，锁外解密用快照（见 get_entries）。
                key = self._key
                # SEC-043 写入方世代：近期更新视图同样快照世代传入缓存回写（语义见
                # get_entry_summaries 处注释），补齐 SEC-041 仅接搜索分支的遗留漏点。
                data_epoch = self._vault.key_epoch
            # 解密移出 db_lock（PERF-001），与 get_entry_summaries 一致；用锁内快照 key 解密。
            self._cache.invalidate_if_epoch_changed()
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

    def get_entries_for_export(
        self,
        include_secrets: bool = False,
        cancel_check: Callable[[], bool] | None = None,
        progress: Callable[[int, int], None] | None = None,
    ) -> list[Entry]:
        """获取用于导出的全部条目（不含回收站），默认不解密密码/TOTP。

        走 :meth:`decrypt_entry_for_export` 的 export 模式：任何字段完整性/解密
        失败立即抛 :class:`DecryptionError`（拒绝导出损坏数据），区别于
        :meth:`get_entries` 的容错汇总。``include_secrets=False`` 时跳过
        password/totp_secret 解密。

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
            # PERF-001 并发修补（M3）：锁内快照主密钥，锁外解密用快照（见 get_entries）。
            key = self._key
        # 解密移出 db_lock（PERF-001）；epoch 不一致已在 with 块内抛 VaultKeyEpochMismatchError
        # 向上传播（导出为用户主动操作，空结果会误导用户）。用锁内快照 key 解密。
        entries = []
        total = len(raw_entries)
        done = 0
        for raw_entry in raw_entries:
            if cancel_check and cancel_check():
                break
            entries.append(self.decrypt_entry_for_export(raw_entry, include_secrets, key=key))
            done += 1
            if progress is not None and (done % PROGRESS_REPORT_EVERY == 0 or done == total):
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
