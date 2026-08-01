"""条目管理器，负责密码条目的加密 CRUD 操作。

直接依赖 crypto_utils 的加解密原语（crypto_utils 同属 Business 层服务，非跨层依赖）；分类/TOTP/
密码历史/校验/变更通知等职责拆至子服务与独立模块，本类聚焦条目 CRUD、视图
解密与搜索匹配，经 property 暴露分类/TOTP/历史子服务。
"""

import hmac
import json
import logging
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from .vault_manager import VaultManager

from ...crypto.password_generator import PasswordGenerator
from ...database.types import EntryQuery, VaultDataStore, VerifyMode
from ...exceptions import (
    DecryptionError,
    EntryError,
    EntryIntegrityError,
    VaultKeyEpochMismatchError,
)
from ...models import (
    CustomField,
    Entry,
    RawEntry,
    Sensitive,
)
from ...utils.format import utc_now_iso
from ..services.crypto_utils import (
    build_entry_summary,
    copy_entry_fields,
    decrypt_field as _decrypt_field_impl,
    encrypt_field as _encrypt_field_impl,
    matches_search_lower,
    require_vault_key,
)
from ..services.entry_validation import validate_plain_entry
from ..services.password_history_service import PasswordHistoryService
from ..services.totp_service import TotpService
from .category_manager import CategoryManager
from .entry_cache import EntryCacheManager
from .entry_change_bus import EntryChangeBus

logger = logging.getLogger(__name__)

# 完整性失败字段→中文标签映射，构造 integrity_message 用。模块级常量避免重建。
_INTEGRITY_FIELD_LABELS: dict[str, str] = {
    "title": "标题",
    "username": "账号",
    "url": "URL",
    "tags": "标签",
    "category": "分类",
}

# 「近期更新」视图默认拉取的条目数，供 get_recent_summaries 默认 limit。
DEFAULT_RECENT_SUMMARIES_LIMIT = 20


class BatchUpdateItem(NamedTuple):
    """批量覆盖更新项（导入覆盖路径）：合并后条目、待覆盖条目密文 raw。

    old_password 为 None 表示未预解密，由 :meth:`prepare_overwrite_updates` 在
    prepared 阶段逐条解密（PF-005：不在 _prepare_overwrite_batch 批量预解密致全部旧密码同刻
    驻留）；解密后经 _prepare_password_update 比对即 del，收敛明文驻留面。
    """

    entry: Entry
    raw: RawEntry
    old_password: str | None


class PreparedUpdate(NamedTuple):
    """覆盖项加密预处理结果（MAINT-004）：写阶段所需的最小密文载荷。

    由 :meth:`EntryManager.prepare_overwrite_updates` 在锁外加密构建，供
    :meth:`EntryManager.write_overwrite_updates` 在事务内逐条写入。raw 保留以取
    ``raw.password`` 记录密码历史（旧密文，非明文）。
    """

    enc_entry: RawEntry
    raw: RawEntry
    password_changed: bool
    password_changed_at: str


class EntryManager:
    """管理密码条目的加密、解密和 CRUD 操作。"""

    def __init__(
        self,
        vault_manager: "VaultManager",
        cache: EntryCacheManager,
        change_bus: EntryChangeBus,
    ):
        self._vault = vault_manager
        # 明文缓存（搜索摘要/分类名/TOTP/标签）与失效委托 EntryCacheManager。
        self._cache = cache
        # 条目变更通知管线：先失效缓存，再在锁外跑注册回调。
        self._change_bus = change_bus
        # 子服务：分类 / TOTP / 密码历史（经 property 暴露）
        self._category_mgr = CategoryManager(vault_manager, cache, change_bus)
        self._totp_svc = TotpService(vault_manager, cache)
        self._history_svc = PasswordHistoryService(vault_manager)

    @property
    def categories(self) -> CategoryManager:
        """分类子服务（CRUD、查询、缓存失效）。"""
        return self._category_mgr

    @property
    def totp(self) -> TotpService:
        """TOTP 子服务（生成、状态查询、缓存清理）。"""
        return self._totp_svc

    @property
    def password_history(self) -> PasswordHistoryService:
        """密码历史子服务（读取、计数、解密展示）。"""
        return self._history_svc

    def register_on_change(self, callback: Callable[[bool], None]) -> None:
        """注册条目变更时自动调用的回调，用于缓存失效等。委托 change_bus。"""
        self._change_bus.register(callback)

    @property
    def db(self) -> VaultDataStore:
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

    def _build_encrypted_entry(
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
        """构建加密 RawEntry，add_entry 与 update_entry 共用，避免加密字段遗漏。

        password_override: 若提供，视为已加密的密文直接赋值，不再重复加密。
        """
        # update_entry 传密文走 override 分支；add_entry 传 None 走加密分支。
        encrypted_pwd = (
            password_override
            if password_override is not None
            else self._encrypt_field(entry.password, crypto_id, "password")
        )
        custom_fields_cipher = self._encrypt_custom_fields(entry.custom_fields, crypto_id)
        return RawEntry(
            id=entry_id,
            crypto_id=crypto_id,
            title=self._encrypt_field(entry.title, crypto_id, "title"),
            username=self._encrypt_field(entry.username, crypto_id, "username"),
            password=encrypted_pwd,
            url=self._encrypt_field(entry.url, crypto_id, "url"),
            category_id=entry.category_id,
            tags=self._encrypt_field(entry.tags, crypto_id, "tags"),
            notes=self._encrypt_field(entry.notes, crypto_id, "notes"),
            custom_fields=custom_fields_cipher,
            is_favorite=entry.is_favorite,
            password_strength=entry.password_strength,
            entry_type=entry.entry_type,
            totp_secret=self._encrypt_field(entry.totp_secret, crypto_id, "totp_secret"),
            created_at=created_at or now,
            updated_at=updated_at or now,
            password_changed_at=entry.password_changed_at or now,
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
    ) -> str:
        """解密单个字段，委托给 crypto_utils.decrypt_field。"""
        return _decrypt_field_impl(
            encrypted,
            self._key,
            crypto_id,
            field_name,
            strict=strict,
        )

    def invalidate_caches(self) -> None:
        """外部调用：锁定或改密后显式清空明文缓存。委托 cache。"""
        self._cache.invalidate_all()

    def notify_batch_change(self, password_changed: bool = True) -> None:
        """批量变更后的统一通知入口，供导入等批量操作在全部完成后触发一次。

        与单条 ``change_bus.notify`` 一致地失效缓存并通知回调，但作为公共 API
        暴露，避免跨管理器（如 ImportExportManager）直接访问底层通知机制，
        使内部缓存失效机制不致成为跨模块契约的一部分。
        """
        self._change_bus.notify(password_changed)

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

    def _decrypt_custom_fields(self, encrypted: str, crypto_id: str) -> list[CustomField]:
        """解密自定义字段列表。

        密文通过 GCM 认证后内容仍可能损坏：``json.loads`` 失败或结构不符时抛
        :class:`EntryIntegrityError`（而非裸 ``ValueError``），可与 :class:`DecryptionError`
        一并精确捕获，避免外层 ``except ValueError`` 兜底吞掉无关 ValueError
        （DecryptionError 亦是 ValueError 子类）。
        """
        if not encrypted:
            return []
        data = self._decrypt_field(encrypted, crypto_id, "custom_fields", strict=True)
        try:
            items = json.loads(data)
        except ValueError as exc:
            # JSONDecodeError 是 ValueError 子类；归一为领域异常避免裸 ValueError 逃逸
            raise EntryIntegrityError("自定义字段内容损坏（非有效 JSON）") from exc
        if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
            raise EntryIntegrityError("自定义字段结构无效")
        return [CustomField.from_dict(item) for item in items]

    def decrypt_entry(self, raw_entry: RawEntry) -> Entry:
        """解密条目的所有敏感字段，返回新的 Entry 对象（详情/编辑路径）。

        字段解密失败时容错：失败字段收集到 ``integrity_message``，password/totp
        包 :class:`Sensitive` 防明文意外进入日志/repr。
        """
        return self._decrypt_for_detail(raw_entry)

    def decrypt_entry_for_export(
        self,
        raw_entry: RawEntry,
        include_secrets: bool = False,
    ) -> Entry:
        """仅解密导出所需字段，默认不让密码与 TOTP 进入内存结果。

        任何完整性/解密失败立即抛 :class:`DecryptionError`（拒绝导出损坏数据）；
        ``include_secrets=False`` 时跳过 password/totp_secret 解密。
        """
        return self._decrypt_for_export(raw_entry, include_secrets=include_secrets)

    def _decrypt_field_lenient(
        self,
        encrypted: str,
        crypto_id: str,
        name: str,
        errors: list[str],
    ) -> str:
        """详情路径字段级容错解密：失败记入 errors 返回空串。

        始终用 strict=True 解密以触发 GCM 认证，失败处置为本方法的容错语义。
        """
        try:
            return self._decrypt_field(encrypted, crypto_id, name, strict=True)
        except DecryptionError:
            errors.append(name)
            return ""

    def _decrypt_field_strict(
        self,
        encrypted: str,
        crypto_id: str,
        name: str,
        entry_id: int | None,
    ) -> str:
        """导出路径字段级解密：失败立即抛 DecryptionError，拒绝导出损坏数据。"""
        try:
            return self._decrypt_field(encrypted, crypto_id, name, strict=True)
        except DecryptionError:
            raise DecryptionError(f"条目 {entry_id} 导出失败，数据可能已损坏") from None

    def _decrypt_for_detail(self, raw_entry: RawEntry) -> Entry:
        """解密条目字段（详情/编辑路径）。

        失败字段容错汇总到 ``integrity_message``；password/totp 包 :class:`Sensitive`
        防明文进入日志/repr。title/username/url/tags 复用列表摘要缓存避免重复解密。
        """
        integrity_errors: list[str] = []
        if raw_entry.integrity_error:
            integrity_errors.append(raw_entry.integrity_message or "元数据")

        try:
            custom_fields = self._decrypt_custom_fields(
                raw_entry.custom_fields_db_value,
                raw_entry.crypto_id,
            )
        except (DecryptionError, EntryIntegrityError) as exc:
            # 精确捕获两类损坏（不吞其他异常），区分故障层记日志：DecryptionError=
            # 密文层损坏（GCM 认证失败/密钥问题）；EntryIntegrityError=结构层损坏
            # （已解密但内容损坏——非合法 JSON 或结构不符）。
            layer = "密文" if isinstance(exc, DecryptionError) else "结构"
            logger.warning(
                "条目 %s 自定义字段%s层损坏",
                raw_entry.crypto_id,
                layer,
            )
            integrity_errors.append("自定义字段")
            custom_fields = []

        cid = raw_entry.crypto_id
        password = Sensitive(
            self._decrypt_field_lenient(
                raw_entry.password,
                cid,
                "password",
                integrity_errors,
            )
        )
        totp_secret = Sensitive(
            self._decrypt_field_lenient(
                raw_entry.totp_secret,
                cid,
                "totp_secret",
                integrity_errors,
            )
        )

        # 分类名密文损坏时回退空串并记入完整性错误，与摘要路径 (_decrypt_summary)
        # 对齐——避免详情面板因分类名解密失败而崩溃（上游 get_entry 未捕获 DecryptionError）。
        try:
            category_name = self._cache.decrypt_category_name(
                raw_entry.category_id,
                raw_entry.category_name,
            )
        except DecryptionError:
            category_name = ""
            integrity_errors.append("分类名")

        # detail 路径复用列表摘要缓存（title/username/url/tags 已解密），避免详情面板
        # 选中时重复解密这 4 字段；仅 notes/password/totp/custom_fields 需解密。摘要解密
        # 失败的字段经 get_failed_fields 取，按原容错语义（英文字段名）计入 integrity_errors。
        title, username, url, tags = self._cache.cached_search_metadata(raw_entry)
        failed = self._cache.get_failed_fields(cid)
        integrity_errors.extend(
            name for name in ("title", "username", "url", "tags") if name in failed
        )
        return copy_entry_fields(
            raw_entry,
            title=title,
            username=username,
            password=password,
            url=url,
            category_name=category_name,
            tags=tags,
            notes=self._decrypt_field_lenient(
                raw_entry.notes,
                cid,
                "notes",
                integrity_errors,
            ),
            custom_fields=custom_fields,
            totp_secret=totp_secret,
            integrity_error=bool(integrity_errors),
            integrity_message="、".join(dict.fromkeys(integrity_errors)),
        )

    def _decrypt_for_export(
        self,
        raw_entry: RawEntry,
        include_secrets: bool = True,
    ) -> Entry:
        """解密条目字段（导出路径）。

        任一完整性/解密失败立即抛 :class:`DecryptionError`（拒绝导出损坏数据）；
        password/totp 返回明文（普通 str）供备份序列化。``include_secrets=False``
        时跳过 password/totp_secret 解密。
        """
        if raw_entry.integrity_error:
            raise DecryptionError(f"条目 {raw_entry.id} 元数据完整性校验失败，已拒绝导出")

        try:
            custom_fields = self._decrypt_custom_fields(
                raw_entry.custom_fields_db_value,
                raw_entry.crypto_id,
            )
        except (DecryptionError, EntryIntegrityError) as exc:
            layer = "密文" if isinstance(exc, DecryptionError) else "结构"
            logger.warning(
                "条目 %s 自定义字段%s层损坏",
                raw_entry.crypto_id,
                layer,
            )
            raise DecryptionError(f"条目 {raw_entry.id} 导出失败，数据可能已损坏") from None

        cid = raw_entry.crypto_id
        password = (
            self._decrypt_field_strict(
                raw_entry.password,
                cid,
                "password",
                raw_entry.id,
            )
            if include_secrets
            else ""
        )
        totp_secret = (
            self._decrypt_field_strict(
                raw_entry.totp_secret,
                cid,
                "totp_secret",
                raw_entry.id,
            )
            if include_secrets
            else ""
        )

        try:
            category_name = self._cache.decrypt_category_name(
                raw_entry.category_id,
                raw_entry.category_name,
            )
        except DecryptionError:
            raise DecryptionError(f"条目 {raw_entry.id} 导出失败，数据可能已损坏") from None

        return copy_entry_fields(
            raw_entry,
            title=self._decrypt_field_strict(
                raw_entry.title,
                cid,
                "title",
                raw_entry.id,
            ),
            username=self._decrypt_field_strict(
                raw_entry.username,
                cid,
                "username",
                raw_entry.id,
            ),
            password=password,
            url=self._decrypt_field_strict(
                raw_entry.url,
                cid,
                "url",
                raw_entry.id,
            ),
            category_name=category_name,
            tags=self._decrypt_field_strict(
                raw_entry.tags,
                cid,
                "tags",
                raw_entry.id,
            ),
            notes=self._decrypt_field_strict(
                raw_entry.notes,
                cid,
                "notes",
                raw_entry.id,
            ),
            custom_fields=custom_fields,
            totp_secret=totp_secret,
            integrity_error=False,
            integrity_message="",
        )

    def _decrypt_summary(
        self,
        raw_entry: RawEntry,
        *,
        skip_epoch_check: bool = False,
    ) -> Entry:
        """仅解密列表展示所需字段，不让密码等明文进入列表模型。

        title/username/url/tags 经统一摘要缓存复用，避免列表与搜索重复解密。
        摘要不包含 password/totp_secret/notes/custom_fields 等高敏字段；
        epoch 变化、锁定或条目更新时缓存立即失效。

        skip_epoch_check=True 跳过单条 epoch 校验，供批量循环路径复用——调用方
        须在循环外已调用缓存失效，避免每条目重复加锁。
        """
        title, username, url, tags = (
            self._cache.search_metadata_for_analysis(raw_entry)
            if skip_epoch_check
            else self._cache.cached_search_metadata(raw_entry)
        )
        # 失败字段集经 cache 锁内采样，避免与并发失效的 .clear() 竞态。
        failed = self._cache.get_failed_fields(raw_entry.crypto_id)
        summary = build_entry_summary(raw_entry, username)
        category_name = summary.category_name
        try:
            category_name = self._cache.decrypt_category_name(
                raw_entry.category_id,
                raw_entry.category_name,
            )
        except DecryptionError:
            failed = set(failed)
            failed.add("category")
        integrity_error = raw_entry.integrity_error or bool(failed)
        messages = []
        if raw_entry.integrity_error:
            messages.append(raw_entry.integrity_message or "元数据")
        messages.extend(_INTEGRITY_FIELD_LABELS[name] for name in failed)
        integrity_message = "、".join(dict.fromkeys(messages))
        return replace(
            summary,
            title=title,
            url=url,
            tags=tags,
            category_name=category_name,
            integrity_error=integrity_error,
            integrity_message=integrity_message,
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
        enc_entry = self._build_encrypted_entry(
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

    def encrypt_new_entries(self, entries: list[Entry]) -> tuple[list[RawEntry], bool]:
        """锁外加密构建新条目密文（MAINT-004），返回 ``(enc_entries, preserve_metadata)``。

        CPU 密集的加密循环移出 db_lock：调用方先取 ``pre_epoch`` 快照，调本方法加密，
        再于 ``epoch_guarded_transaction(pre_epoch=...)`` 内调 :meth:`write_new_entries`
        裸写入。加密仅依赖 vault key（不触 db_lock），故可锁外；
        pre_epoch 守卫保证「加密后→写入前」若改密则复查失败回滚，旧密钥密文不落库。
        ``entries`` 须已由 ``Entry.from_dict`` 校验（与单条 add_entry(skip_validation=True)
        对齐）。
        """
        now = utc_now_iso()
        enc_entries: list[RawEntry] = []
        for entry in entries:
            entry = replace(
                entry,
                password_strength=PasswordGenerator.check_strength(entry.password).score,
            )
            crypto_id = entry.crypto_id or uuid.uuid4().hex
            enc_entries.append(
                self._build_encrypted_entry(
                    entry,
                    crypto_id,
                    now,
                    created_at=entry.created_at or now,
                    updated_at=entry.updated_at or now,
                )
            )
        preserve = any(e.created_at or e.updated_at for e in entries)
        return enc_entries, preserve

    def write_new_entries(
        self,
        enc_entries: list[RawEntry],
        *,
        preserve: bool,
        notify: bool = True,
    ) -> None:
        """事务内裸写入已加密条目（MAINT-004），executemany 一次性 INSERT。

        写入须受 epoch 守卫保护：导入路径在 ``epoch_guarded_transaction`` 内调用
        （写入前 epoch 已复查）；便捷封装 :meth:`add_entries` 则经 ``@_db_write`` 的
        ``enforce_key_epoch`` 写守卫保护。不含加密，仅 db 写，把 db_lock 持有收敛到
        executemany 时长。
        """
        if not enc_entries:
            if notify:
                self._change_bus.notify(clear_summaries=False)
            return
        self._vault.db.add_entries_batch(enc_entries, preserve_metadata=preserve)
        if notify:
            # 与 add_entry 一致：新条目不改变既有摘要，clear_summaries=False 保留缓存。
            self._change_bus.notify(clear_summaries=False)

    def add_entries(self, entries: list[Entry], *, notify: bool = True) -> None:
        """批量添加条目：加密 + 写入一体（便捷封装）。

        单次 ``add_entries_batch`` 将 N 次 INSERT 合并为 1 次 executemany。导入路径为
        缩短 db_lock 持有改用 :meth:`encrypt_new_entries` + :meth:`write_new_entries`
        分离调用（MAINT-004）；本方法保留供需一体调用的场景（含空列表 notify 语义）。
        """
        if not entries:
            if notify:
                self._change_bus.notify(clear_summaries=False)
            return
        enc_entries, preserve = self.encrypt_new_entries(entries)
        self.write_new_entries(enc_entries, preserve=preserve, notify=notify)

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

        preloaded_raw / preloaded_old_password：导入覆盖路径已由
        ``_prepare_overwrite_map`` 批量预读 raw 与解密旧密码，传入以跳过重复
        ``get_entry`` 与旧密码解密（消除覆盖路径的双重读取与解密）。其他调用方
        留空，走默认 read-modify-write。

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
        # preloaded_raw：导入覆盖路径已批量预读，跳过重复 get_entry。
        raw = preloaded_raw if preloaded_raw is not None else self.db.get_entry(entry.id)
        if raw is None:
            return

        # 条目更新可能修改 totp_secret，失效该条目的 TOTP secret 缓存，
        # 下次 TotpService.get_state / generate_cached 重新解密。
        self._cache.pop_totp(entry.id)

        new_pwd_enc, password_changed = self._prepare_password_update(
            entry,
            raw,
            preloaded_old_password,
        )
        password_changed_at = self._resolve_password_changed_at(
            entry,
            raw,
            password_changed,
            preserve_password_changed_at,
        )

        strength = PasswordGenerator.check_strength(entry.password)
        entry = replace(entry, password_strength=strength.score)

        now = utc_now_iso()
        enc_entry = self._build_encrypted_entry(
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

    def prepare_overwrite_updates(
        self,
        items: list[BatchUpdateItem],
        *,
        preserve_password_changed_at: bool = True,
    ) -> tuple[list[PreparedUpdate], list[tuple[int, Exception]]]:
        """锁外验证+加密覆盖项（MAINT-004），返回 ``(prepared, failures)``。

        验证/解密/加密预处理移出 db_lock：调用方先取 ``pre_epoch`` 快照，调本方法
        预处理，再于 ``epoch_guarded_transaction(pre_epoch=...)`` 内调
        :meth:`write_overwrite_updates`。

        failures 仅收集验证/解密阶段的 EntryError / EntryIntegrityError /
        DecryptionError（数据问题，逐条跳过）；写阶段错误由 :meth:`write_overwrite_updates`
        向上传播中止。pop_totp 在此阶段（加密前）失效缓存。
        """
        failures: list[tuple[int, Exception]] = []
        # 预处理：验证 + 解密旧密码 + 加密，单条失败仅收集到 failures，写阶段错误向上传播。
        now = utc_now_iso()
        prepared: list[PreparedUpdate] = []
        for idx, item in enumerate(items):
            entry, raw, old_password = item.entry, item.raw, item.old_password
            try:
                validate_plain_entry(entry)
                if entry.integrity_error:
                    raise EntryIntegrityError(
                        f"条目存在无法解密的字段（{entry.integrity_message}），"
                        f"为避免数据丢失已禁止保存"
                    )
                if entry.id is None:
                    raise EntryError("覆盖条目缺少 id")
                # 失效该条目的 TOTP secret 缓存，下次 TotpService 重新解密。
                self._cache.pop_totp(entry.id)
                new_pwd_enc, password_changed = self._prepare_password_update(
                    entry,
                    raw,
                    old_password,
                )
                password_changed_at = self._resolve_password_changed_at(
                    entry,
                    raw,
                    password_changed,
                    preserve_password_changed_at,
                )
                entry = replace(
                    entry,
                    password_strength=PasswordGenerator.check_strength(
                        entry.password,
                    ).score,
                )
                enc_entry = self._build_encrypted_entry(
                    entry,
                    raw.crypto_id,
                    now,
                    created_at=raw.created_at,
                    updated_at=now,
                    password_override=new_pwd_enc,
                    entry_id=entry.id,
                )
                enc_entry = replace(enc_entry, password_changed_at=password_changed_at)
                prepared.append(
                    PreparedUpdate(
                        enc_entry,
                        raw,
                        password_changed,
                        password_changed_at,
                    )
                )
            except (EntryError, EntryIntegrityError, DecryptionError) as exc:
                failures.append((idx, exc))
        return prepared, failures

    def write_overwrite_updates(
        self,
        prepared: list[PreparedUpdate],
        pre_epoch: str | None,
    ) -> int:
        """锁内逐条 SAVEPOINT 写入已加密覆盖项（MAINT-004），复查 ``pre_epoch``。

        须在 ``epoch_guarded_transaction(pre_epoch=...)`` 内调用。``pre_epoch`` 由调用方
        在锁外加密前快照并传入，与本方法逐条复查共用同一快照——纵深防御「写入期间改密」，
        不匹配或写失败照原语义向上传播中止导入（不由 failures 收集）。
        """
        count = 0
        for item in prepared:
            with self.db.transaction():
                if self.key_epoch != pre_epoch:
                    raise VaultKeyEpochMismatchError(
                        "更新期间检测到密钥变更（改密/锁定），已中止以防写入旧密钥密文"
                    )
                if item.raw.password and item.password_changed and item.enc_entry.id is not None:
                    # 用与条目一致的 password_changed_at 作为历史 changed_at，
                    # 避免两次独立 utc_now_iso() 产生的微秒级时序倒置。
                    self.db.add_password_history(
                        item.enc_entry.id,
                        item.raw.password,
                        changed_at=item.password_changed_at,
                    )
                self.db.update_entry(item.enc_entry, preserve_updated_at=True)
            count += 1
        return count

    def update_entries_batch_with_history(
        self,
        items: list[BatchUpdateItem],
        *,
        preserve_password_changed_at: bool = True,
    ) -> tuple[int, list[tuple[int, Exception]]]:
        """批量更新条目（导入覆盖路径），返回 ``(成功条数, 失败项)``。便捷封装。

        拆分为 :meth:`prepare_overwrite_updates`（锁外加密）+ :meth:`write_overwrite_updates`
        （锁内写入）。导入路径为缩短 db_lock 持有改用分离调用并自行快照 pre_epoch
        （MAINT-004）；本方法保留供需一体调用的场景，``pre_epoch`` 在 prepare 后、write 前
        快照（与原逐条复查时机一致）。导入整体已由外层 :meth:`_import_entries` 包裹
        单事务，本方法的 SAVEPOINT 在该外层事务内嵌套（不会触发额外 fsync）。
        """
        if not items:
            return 0, []
        prepared, failures = self.prepare_overwrite_updates(
            items,
            preserve_password_changed_at=preserve_password_changed_at,
        )
        pre_epoch = self.key_epoch
        count = self.write_overwrite_updates(prepared, pre_epoch)
        return count, failures

    def _prepare_password_update(
        self,
        entry: Entry,
        raw: RawEntry,
        preloaded_old_password: str | None,
    ) -> tuple[str, bool]:
        """检测密码变更并加密新密码，返回 (新密码密文, 是否变更)。

        必须解密旧密码与明文比较——AES-GCM 用随机 nonce，密文比较不可行；HMAC 指纹
        方案需 schema 变更，当前解密比较是无需迁移的合理选择。常量时间比较
        （hmac.compare_digest）避免时序侧信道。preloaded_old_password 用于导入覆盖
        路径已解密的旧密码，跳过重复解密。
        """
        old_pwd_enc = raw.password
        if preloaded_old_password is not None:
            old_password = preloaded_old_password
        else:
            # 容错解密（PF-005）：批量覆盖路径 old_password 留 None 经此分支解密，损坏
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
        password_changed = not hmac.compare_digest(old_password, entry.password)
        del old_password  # 尽快释放明文引用
        return new_pwd_enc, password_changed

    def _resolve_password_changed_at(
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
        """
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
        锁外（PF-001）；改密窗口内 epoch 不一致时返回空列表触发 UI 刷新；锁定期
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
            # 解密移出 db_lock（PF-001），与摘要路径一致。
            decrypted = [self.decrypt_entry(e) for e in raw_entries]
        except VaultKeyEpochMismatchError:
            return []
        for dec_entry in decrypted:
            if dec_entry.integrity_error:
                logger.warning("条目 %d 解密存在异常", dec_entry.id)
        return decrypted

    def get_entry(self, entry_id: int) -> Entry | None:
        """获取并解密单个条目。

        读路径经 :meth:`epoch_guarded_read` 守卫（ARCH-005）：with 块内仅读 raw、解密移
        锁外（与摘要路径 PF-001 一致）；epoch 不一致时返回 None，调用方据此跳过。
        """
        try:
            with self._vault.epoch_guarded_read():
                raw = self._vault.db.get_entry(entry_id)
        except VaultKeyEpochMismatchError:
            return None
        if raw is None:
            return None
        return self.decrypt_entry(raw)

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
        # 列表/搜索传 LENIENT：逐行 HMAC 验签并标记篡改条目（不抛异常），使列表
        # 能检测非加密元数据篡改（is_favorite/category_id/password_strength/deleted_at）。
        # _decrypt_summary 将 raw.integrity_error 透传到 summary，列表 delegate 据此
        # 显示完整性警示。HMAC 开销远小于摘要解密，性能影响可忽略。
        try:
            with self._vault.epoch_guarded_read():
                raw_entries = self.db.get_entries(
                    EntryQuery(
                        deleted_only=deleted_only,
                        category_id=category_id,
                        favorite_only=favorite_only,
                        limit=sql_limit,
                        verify=VerifyMode.LENIENT,
                    )
                )
            # 解密移出 db_lock（PF-001）：with 块内仅读 raw（持锁快速），锁外逐条解密，
            # 释放 db_lock 供 TOTP 定时器读与写入。循环外一次性 invalidate_if_epoch_changed
            # 固定本批缓存 epoch，循环内走无校验路径避免每条目重复加锁取 epoch。
            self._cache.invalidate_if_epoch_changed()
            # search 与非 search 共用同一循环：search 时在 append 前做 matches_search 过滤。
            # 摘要字段首次搜索后进入会话缓存，后续搜索无重复解密成本。
            summaries = []
            for raw in raw_entries:
                if cancel_check and cancel_check():
                    break
                summary = self._decrypt_summary(raw, skip_epoch_check=True)
                if search and not matches_search_lower(
                    self._cache.search_lower_no_check(raw),
                    search,
                ):
                    continue
                summaries.append(summary)
        except VaultKeyEpochMismatchError:
            return []
        # search 时 limit 未下推 SQL（避免先截断后过滤致命中失真），此处截断兑现契约
        if search and limit:
            summaries = summaries[:limit]
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
        try:
            with self._vault.epoch_guarded_read():
                raw_entries = self.db.get_entries(
                    EntryQuery(sort_by_updated=True, limit=limit, verify=VerifyMode.LENIENT),
                )
            # 解密移出 db_lock（PF-001），与 get_entry_summaries 一致。
            self._cache.invalidate_if_epoch_changed()
            return [self._decrypt_summary(entry, skip_epoch_check=True) for entry in raw_entries]
        except VaultKeyEpochMismatchError:
            return []

    def get_entries_for_export(
        self,
        include_secrets: bool = False,
        cancel_check: Callable[[], bool] | None = None,
    ) -> list[Entry]:
        """获取用于导出的全部条目（不含回收站），默认不解密密码/TOTP。

        走 :meth:`decrypt_entry_for_export` 的 export 模式：任何字段完整性/解密
        失败立即抛 :class:`DecryptionError`（拒绝导出损坏数据），区别于
        :meth:`get_entries` 的容错汇总。``include_secrets=False`` 时跳过
        password/totp_secret 解密。

        Args:
            include_secrets: 是否解密 password 与 totp_secret 入结果。
            cancel_check: 可选取消探针，返回真值时中止遍历。

        读路径经 :meth:`epoch_guarded_read` 守卫（ARCH-005）：改密窗口内 epoch 不一致时
        抛 :class:`VaultKeyEpochMismatchError` 让导出 worker 据此报错（导出为用户主动
        操作，空结果会误导用户认为成功导出 0 条，故向上传播而非返回空）。
        """
        with self._vault.epoch_guarded_read():
            raw_entries = self.db.get_entries(EntryQuery(include_deleted=False))
        # 解密移出 db_lock（PF-001）；epoch 不一致已在 with 块内抛 VaultKeyEpochMismatchError
        # 向上传播（导出为用户主动操作，空结果会误导用户）。
        entries = []
        for raw_entry in raw_entries:
            if cancel_check and cancel_check():
                break
            entries.append(self.decrypt_entry_for_export(raw_entry, include_secrets))
        return entries

    def toggle_favorite(self, entry_id: int) -> bool | None:
        """切换收藏状态，返回新的收藏状态；条目不存在时返回 None。

        在单个事务内完成读-改-写，避免 TOCTOU 竞态。
        update_entry 会自动重签 metadata_mac，保证元数据完整性。
        """
        with self._vault.epoch_guarded_transaction(operation="切换收藏"):
            raw = self._vault.db.get_entry(entry_id)
            if raw is None:
                return None
            raw = replace(raw, is_favorite=not raw.is_favorite)
            self._vault.db.update_entry(raw)
            result = raw.is_favorite
        # 收藏切换不影响密码相关分析维度，传 False 避免 SecurityAnalyzer 缓存
        # 无谓失效触发整库重算。is_favorite 不在摘要/标签/分类名缓存中，三者
        # 均无需失效；列表排序变化由回调触发 SQL 重查，复用摘要缓存避免重解密。
        self._change_bus.notify(
            password_changed=False,
            clear_summaries=False,
            tags_changed=False,
        )
        return result

    def get_entry_count(self, include_deleted: bool = False) -> int:
        return self._vault.db.get_entry_count(include_deleted)

    def get_all_tags(self) -> list[tuple[str, int]]:
        """获取所有标签及其使用频率。委托 cache。"""
        return self._cache.get_all_tags()

    @property
    def tags_cache_valid(self) -> bool:
        """标签缓存是否有效，委托 cache。供 UI 决定标签下拉同步/异步刷新。"""
        return self._cache.tags_cache_valid
