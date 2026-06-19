"""条目管理器，负责密码条目的加密 CRUD 操作。

架构说明：EntryManager 直接依赖 crypto_utils 的 encrypt_field 与 decrypt_field，
这属于 Business → Crypto 的同层依赖，符合架构约束。UI 层通过 EntryManager
间接访问这些加密原语，不直接导入 crypto 模块。

职责拆分（阶段D SRP 重构）：
- 分类 CRUD → ``CategoryManager``（含两阶段加密事务）
- TOTP 生成/状态 → ``TotpService``
- 密码历史读取/解密 → ``PasswordHistoryService``
- 明文条目校验 → ``entry_validation.validate_plain_entry``
- 条目变更通知管线 → ``EntryChangeBus``（缓存失效 + 回调）
本类保留条目 CRUD、视图解密、加解密编排原语与搜索匹配等条目核心关注点，
通过 property 暴露分类/TOTP/历史子服务供 UI 属性访问。
"""

import json
import logging
import uuid
from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ...database.db_manager import DatabaseManager
    from .vault_manager import VaultManager

from ...crypto.password_generator import PasswordGenerator
from ...database.types import VerifyMode
from ...exceptions import DecryptionError, EntryIntegrityError, VaultKeyEpochMismatchError
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
    matches_search,
    matches_tag as _matches_tag_impl,
    require_vault_key,
)
from ..services.entry_validation import validate_plain_entry
from ..services.password_history_service import PasswordHistoryService
from ..services.totp_service import TotpService
from .category_manager import CategoryManager
from .entry_cache import EntryCacheManager
from .entry_change_bus import EntryChangeBus

logger = logging.getLogger(__name__)


class EntryManager:
    """管理密码条目的加密、解密和 CRUD 操作。"""

    def __init__(
        self,
        vault_manager: 'VaultManager',
        cache: EntryCacheManager,
        change_bus: EntryChangeBus,
    ):
        self._vault = vault_manager
        # 明文缓存矩阵（搜索摘要/分类名/TOTP/标签）委托 EntryCacheManager，
        # 集中缓存与失效逻辑（独立模块 entry_cache.py，含填充与失效）。
        self._cache = cache
        # 条目变更通知管线：先失效缓存，再在锁外跑注册回调。
        self._change_bus = change_bus
        # 子服务：分类 / TOTP / 密码历史（SRP 拆分后由 property 暴露）
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
    def db(self) -> 'DatabaseManager':
        return self._vault.db

    @property
    def key_epoch(self) -> str | None:
        """当前密钥版本，委托 vault。

        供 ImportExportManager 等跨管理器操作做 epoch 守卫，避免直接穿透
        ``_vault`` 私有属性。EntryManager 内部（``_invalidate_if_epoch_changed``）
        本就经此路径访问 key_epoch。
        """
        return self._vault.key_epoch

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
        """构建加密 RawEntry 对象，统一处理字段加密逻辑。

        add_entry 和 update_entry 共用此方法，避免加密字段遗漏。返回密文态
        RawEntry（custom_fields 为密文 str），供 EntryRepository 写入数据库。
        password_override: 若提供，视为已加密的密文，直接赋值，不再重复加密。
        """
        # password_override 已是密文，即 update_entry 场景，直接赋值；
        # 否则加密明文密码，即 add_entry 场景。
        encrypted_pwd = (
            password_override
            if password_override is not None
            else self._encrypt_field(entry.password, crypto_id, 'password')
        )
        custom_fields_cipher = self._encrypt_custom_fields(entry.custom_fields, crypto_id)
        return RawEntry(
            id=entry_id,
            crypto_id=crypto_id,
            title=self._encrypt_field(entry.title, crypto_id, 'title'),
            username=self._encrypt_field(entry.username, crypto_id, 'username'),
            password=encrypted_pwd,
            url=self._encrypt_field(entry.url, crypto_id, 'url'),
            category_id=entry.category_id,
            tags=self._encrypt_field(entry.tags, crypto_id, 'tags'),
            notes=self._encrypt_field(entry.notes, crypto_id, 'notes'),
            custom_fields=custom_fields_cipher,
            is_favorite=entry.is_favorite,
            password_strength=entry.password_strength,
            entry_type=entry.entry_type,
            totp_secret=self._encrypt_field(entry.totp_secret, crypto_id, 'totp_secret'),
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
            encrypted, self._key, crypto_id, field_name, strict=strict,
        )

    def _cached_search_metadata(
        self, raw_entry: RawEntry,
    ) -> tuple[str, str, str, str]:
        """解密并缓存列表/搜索所需的 title、username、url、tags。委托 cache。"""
        return self._cache.cached_search_metadata(raw_entry)

    def _cached_search_metadata_no_check(
        self, raw_entry: RawEntry,
    ) -> tuple[str, str, str, str]:
        """无 epoch 校验的摘要解密，供批量循环复用（循环外须已 invalidate）。"""
        return self._cache._cached_search_metadata_no_check(raw_entry)

    def _decrypt_category_name(self, category_id: int | None, value: str) -> str:
        """解密分类名并缓存。委托 cache。"""
        return self._cache.decrypt_category_name(category_id, value)

    def _invalidate_if_epoch_changed(self) -> None:
        """检测 vault.key_epoch 变化，变化则清空所有明文缓存。委托 cache。"""
        self._cache.invalidate_if_epoch_changed()

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
            return ''
        if not isinstance(fields, list) or not all(
            isinstance(field, CustomField) for field in fields
        ):
            raise ValueError('自定义字段必须是 CustomField 列表')
        data = json.dumps([f.to_dict() for f in fields], ensure_ascii=False)
        return self._encrypt_field(data, crypto_id, 'custom_fields')

    def _decrypt_custom_fields(self, encrypted: str, crypto_id: str) -> list[CustomField]:
        """解密自定义字段列表。"""
        if not encrypted:
            return []
        data = self._decrypt_field(
            encrypted, crypto_id, 'custom_fields', strict=True
        )
        items = json.loads(data)
        if not isinstance(items, list) or not all(
            isinstance(item, dict) for item in items
        ):
            raise ValueError('自定义字段结构无效')
        return [CustomField.from_dict(item) for item in items]

    def decrypt_entry(self, raw_entry: RawEntry) -> Entry:
        """解密条目的所有敏感字段，返回新的 Entry 对象。"""
        integrity_errors = []
        if raw_entry.integrity_error:
            integrity_errors.append(raw_entry.integrity_message or '元数据')

        def decrypt(name: str, value: str) -> str:
            try:
                return self._decrypt_field(
                    value, raw_entry.crypto_id, name, strict=True
                )
            except ValueError:
                integrity_errors.append(name)
                return ''

        try:
            custom_fields = self._decrypt_custom_fields(
                raw_entry.custom_fields_db_value,
                raw_entry.crypto_id,
            )
        except ValueError:
            integrity_errors.append('自定义字段')
            custom_fields = []

        return copy_entry_fields(
            raw_entry,
            title=decrypt('title', raw_entry.title),
            username=decrypt('username', raw_entry.username),
            password=Sensitive(decrypt('password', raw_entry.password)),
            url=decrypt('url', raw_entry.url),
            category_name=self._decrypt_category_name(
                raw_entry.category_id, raw_entry.category_name,
            ),
            tags=decrypt('tags', raw_entry.tags),
            notes=decrypt('notes', raw_entry.notes),
            custom_fields=custom_fields,
            totp_secret=Sensitive(decrypt('totp_secret', raw_entry.totp_secret)),
            integrity_error=bool(integrity_errors),
            integrity_message='、'.join(dict.fromkeys(integrity_errors)),
        )

    def decrypt_entry_for_export(
        self,
        raw_entry: RawEntry,
        include_secrets: bool = False,
    ) -> Entry:
        """仅解密导出所需字段，默认不让密码与 TOTP 进入内存结果。"""
        if raw_entry.integrity_error:
            raise DecryptionError(
                f'条目 {raw_entry.id} 元数据完整性校验失败，已拒绝导出'
            )
        try:
            custom_fields = self._decrypt_custom_fields(
                raw_entry.custom_fields_db_value,
                raw_entry.crypto_id,
            )
            return copy_entry_fields(
                raw_entry,
                title=self._decrypt_field(
                    raw_entry.title, raw_entry.crypto_id, 'title', strict=True
                ),
                username=self._decrypt_field(
                    raw_entry.username, raw_entry.crypto_id, 'username', strict=True
                ),
                password=(
                    self._decrypt_field(
                        raw_entry.password, raw_entry.crypto_id, 'password', strict=True
                    ) if include_secrets else ''
                ),
                url=self._decrypt_field(
                    raw_entry.url, raw_entry.crypto_id, 'url', strict=True
                ),
                category_name=self._decrypt_category_name(
                    raw_entry.category_id, raw_entry.category_name,
                ),
                tags=self._decrypt_field(
                    raw_entry.tags, raw_entry.crypto_id, 'tags', strict=True
                ),
                notes=self._decrypt_field(
                    raw_entry.notes, raw_entry.crypto_id, 'notes', strict=True
                ),
                custom_fields=custom_fields,
                totp_secret=(
                    self._decrypt_field(
                        raw_entry.totp_secret, raw_entry.crypto_id, 'totp_secret', strict=True
                    ) if include_secrets else ''
                ),
            )
        except ValueError as exc:
            raise DecryptionError(
                f'条目 {raw_entry.id} 导出失败，数据可能已损坏'
            ) from exc

    def _decrypt_summary(
        self, raw_entry: RawEntry, *, skip_epoch_check: bool = False,
    ) -> Entry:
        """仅解密列表展示所需字段，不让密码等明文进入列表模型。

        title/username/url/tags 经统一摘要缓存复用，避免列表与搜索重复解密。
        摘要不包含 password/totp_secret/notes/custom_fields 等高敏字段；
        epoch 变化、锁定或条目更新时缓存立即失效。

        skip_epoch_check=True 跳过单条 epoch 校验，供批量循环路径复用——调用方
        须在循环外已调用 ``_invalidate_if_epoch_changed``，避免每条目重复加锁。
        """
        title, username, url, tags = (
            self._cached_search_metadata_no_check(raw_entry)
            if skip_epoch_check
            else self._cached_search_metadata(raw_entry)
        )
        # 失败字段集经 cache 锁内采样，避免与并发失效的 .clear() 竞态。
        failed = self._cache.get_failed_fields(raw_entry.crypto_id)
        summary = build_entry_summary(raw_entry, username)
        summary.title = title
        summary.url = url
        summary.tags = tags
        try:
            summary.category_name = self._decrypt_category_name(
                raw_entry.category_id, raw_entry.category_name,
            )
        except ValueError:
            failed = set(failed)
            failed.add('category')
        summary.integrity_error = raw_entry.integrity_error or bool(failed)
        messages = []
        if raw_entry.integrity_error:
            messages.append(raw_entry.integrity_message or '元数据')
        label_map = {
            'title': '标题', 'username': '账号', 'url': 'URL',
            'tags': '标签', 'category': '分类',
        }
        messages.extend(label_map[name] for name in failed)
        summary.integrity_message = '、'.join(dict.fromkeys(messages))
        return summary

    def add_entry(
        self, entry: Entry, *, notify: bool = True, skip_validation: bool = False,
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
        entry.password_strength = strength.score
        crypto_id = entry.crypto_id or uuid.uuid4().hex

        now = utc_now_iso()
        enc_entry = self._build_encrypted_entry(
            entry, crypto_id, now,
            created_at=entry.created_at or now,
            updated_at=entry.updated_at or now,
        )
        result = self._vault.db.add_entry(
            enc_entry,
            preserve_metadata=bool(entry.created_at or entry.updated_at),
        )
        if notify:
            self._change_bus.notify()
        return result

    def update_entry(
        self,
        entry: Entry,
        *,
        preserve_password_changed_at: bool = False,
        notify: bool = True,
    ) -> None:
        """更新条目，自动加密并记录密码历史。

        线程安全说明：此方法采用 read-modify-write 模式，先在事务外读取旧条目
        与旧密码、完成加解密与 enc_entry 构建，仅在最后写入时进入事务并复查
        ``key_epoch``（事务内 ``_enforce_key_epoch`` 会跳过，故单条写路径须自行
        复查）。这是有意为之：相比 ``toggle_favorite``（单字段、用事务内 read）
        采用事务外 read 以缩短 ``db_lock`` 持有时间，避免加解密期间长时间阻塞
        改密等长事务；epoch 复查保证若 read 到 commit 期间发生改密重加密，本
        写入会中止而非把旧密钥密文落到已重写的历史表。单用户桌面应用中同一时
        刻仅一个 UI 操作修改同一条目，竞态窗口极小；未来若引入并发写入，需在
        调用方加锁串行化。
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
        raw = self.db.get_entry(entry.id)
        if raw is None:
            return

        # 条目更新可能修改 totp_secret，失效该条目的 TOTP secret 缓存，
        # 下次 TotpService.get_state / generate_cached 重新解密。
        self._cache.pop_totp(entry.id)

        # 检测密码变更，归档旧密码
        old_pwd_enc = raw.password
        # 安全-性能权衡：此处必须解密旧密码与明文比较来检测变更。
        # AES-256-GCM 每次加密使用随机 nonce，相同明文产生不同密文，
        # 因此密文比较不可行。HMAC 指纹方案需要在数据库中额外存储指纹
        # 字段，这会要求 schema 变更，当前解密比较是无需迁移的合理选择。
        old_password = self._decrypt_field(
            old_pwd_enc, raw.crypto_id, 'password', strict=True
        ) if old_pwd_enc else ''
        new_pwd_enc = self._encrypt_field(entry.password, raw.crypto_id, 'password')
        password_changed = (old_password != entry.password)
        del old_password  # 尽快释放明文引用
        if preserve_password_changed_at:
            # 导入覆盖等同步场景：保留原 password_changed_at，避免批量导入
            # 把"久未修改"条目重置为"刚修改"从而绕过过期检测
            password_changed_at = entry.password_changed_at or raw.password_changed_at
        elif password_changed:
            password_changed_at = utc_now_iso()
        else:
            password_changed_at = raw.password_changed_at

        strength = PasswordGenerator.check_strength(entry.password)
        entry.password_strength = strength.score

        now = utc_now_iso()
        enc_entry = self._build_encrypted_entry(
            entry, raw.crypto_id, now,
            created_at=raw.created_at,
            updated_at=now,
            password_override=new_pwd_enc,
            entry_id=entry.id,
        )
        enc_entry.password_changed_at = password_changed_at
        with self.db.transaction():
            # epoch 复查：_enforce_key_epoch 事务内跳过，单条写路径须自行复查，
            # 防止 read（事务外）到 commit（事务内）期间改密导致写入旧密钥密文。
            if self.key_epoch != pre_epoch:
                raise VaultKeyEpochMismatchError(
                    '更新期间检测到密钥变更（改密/锁定），已中止以防写入旧密钥密文'
                )
            if old_pwd_enc and password_changed and entry.id is not None:
                # 用与条目一致的 password_changed_at 作为历史 changed_at，
                # 避免两次独立 utc_now_iso() 产生的微秒级时序倒置
                self.db.add_password_history(
                    entry.id, old_pwd_enc, changed_at=password_changed_at,
                )
            self.db.update_entry(enc_entry)
        if notify:
            # 检测 tags 是否变更以决定是否失效标签缓存；摘要缓存按 crypto_id 单条
            # 精细失效，避免标题/URL 编辑触发全量重解密。raw.tags 解密失败时保守
            # 视为 tags 已变（None != 任意字符串），仍失效标签缓存。
            try:
                old_tags = self._decrypt_field(
                    raw.tags, raw.crypto_id, 'tags', strict=True,
                ) if raw.tags else ''
            except ValueError:
                old_tags = None
            self._change_bus.notify(
                password_changed,
                crypto_id=raw.crypto_id,
                tags_changed=(old_tags != entry.tags),
            )

    def delete_entry(self, entry_id: int) -> bool:
        """软删除条目，移入回收站。返回是否实际执行（条目存在）。"""
        if not self._vault.db.soft_delete_entry(entry_id):
            return False
        self._cache.pop_totp(entry_id)
        self._change_bus.notify()
        return True

    def restore_entry(self, entry_id: int) -> bool:
        """恢复条目。返回是否实际执行（条目存在）。"""
        if not self._vault.db.restore_entry(entry_id):
            return False
        self._change_bus.notify()
        return True

    def permanent_delete_entry(self, entry_id: int) -> None:
        """永久删除条目。"""
        self._vault.db.permanent_delete_entry(entry_id)
        self._cache.pop_totp(entry_id)
        self._change_bus.notify()

    def empty_trash(self) -> None:
        """清空回收站。

        批量删除后统一 secure_checkpoint：收缩 WAL（清除已删除条目的旧密文扇区
        残留）并刷新 -wal/-shm 文件权限，替代原先每条 DELETE 各自 checkpoint
        的 O(n) 次 TRUNCATE+fsync。
        """
        self._vault.db.empty_trash()
        self._cache.clear_totp()
        self._change_bus.notify()
        self._vault.db.secure_checkpoint()

    def get_entries(
        self,
        deleted_only: bool = False,
        include_deleted: bool = False,
        category_id: int | None = None,
        favorite_only: bool = False,
    ) -> list[Entry]:
        """获取并解密全部条目（含 password/totp_secret 等敏感字段）。

        列表展示等不需要密码的场景应使用 :meth:`get_entry_summaries`；
        按关键词过滤使用 ``get_entry_summaries(search=...)``。
        """
        raw_entries = self._vault.db.get_entries(
            deleted_only=deleted_only,
            include_deleted=include_deleted,
            category_id=category_id,
            favorite_only=favorite_only,
        )

        decrypted = [self.decrypt_entry(e) for e in raw_entries]

        # 检查解密失败的条目并记录警告
        for dec_entry in decrypted:
            if dec_entry.integrity_error:
                logger.warning("条目 %d 解密存在异常", dec_entry.id)

        return decrypted

    def get_entry(self, entry_id: int) -> Entry | None:
        """获取并解密单个条目。"""
        raw = self._vault.db.get_entry(entry_id)
        if raw is None:
            return None
        return self.decrypt_entry(raw)

    def get_entry_summaries(
        self,
        deleted_only: bool = False,
        category_id: int | None = None,
        favorite_only: bool = False,
        search: str = '',
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
        """
        # search 非空时不向 SQL 下推 limit，避免「先截断后过滤」导致命中失真。
        sql_limit = limit if not search else None
        # 列表/搜索传 LENIENT：逐行 HMAC 验签并标记篡改条目（不抛异常），使列表
        # 能检测非加密元数据篡改（is_favorite/category_id/password_strength/deleted_at）。
        # _decrypt_summary 将 raw.integrity_error 透传到 summary，列表 delegate 据此
        # 显示完整性警示。HMAC 开销远小于摘要解密，性能影响可忽略。
        raw_entries = self.db.get_entries(
            deleted_only=deleted_only,
            category_id=category_id,
            favorite_only=favorite_only,
            limit=sql_limit,
            verify=VerifyMode.LENIENT,
        )
        # 循环外一次性 epoch 校验：本批 raw 在单次调用内 epoch 不可能变化
        # （调用方事务内已固定），循环内走无校验路径避免每条目重复加锁取 epoch。
        self._invalidate_if_epoch_changed()
        if search:
            # 摘要字段首次搜索后进入会话缓存，后续搜索无重复解密成本。
            summaries = []
            for raw in raw_entries:
                if cancel_check and cancel_check():
                    break
                summary = self._decrypt_summary(raw, skip_epoch_check=True)
                if matches_search(summary, search):
                    summaries.append(summary)
            # search 时 limit 未下推 SQL，此处截断以兑现 limit 契约
            if limit:
                summaries = summaries[:limit]
        else:
            summaries = []
            for raw in raw_entries:
                if cancel_check and cancel_check():
                    break
                summaries.append(self._decrypt_summary(raw, skip_epoch_check=True))
        return summaries

    def get_recent_summaries(self, limit: int = 20) -> list[Entry]:
        """获取最近更新的条目摘要，供「近期更新」视图。

        相较 ``get_entry_summaries``（按 is_favorite DESC, updated_at DESC 排序），
        本方法仅按 updated_at DESC 排序并下推 LIMIT 到 SQL，避免拉全量内存排序
        再截断，消除大库下「近期更新」切换的全量解密与内存驻留开销。

        Args:
            limit: 返回条目数上限。
        """
        if limit <= 0:
            return []
        raw_entries = self.db.get_entries(
            sort_by_updated=True, limit=limit, verify=VerifyMode.LENIENT,
        )
        self._invalidate_if_epoch_changed()
        return [self._decrypt_summary(entry, skip_epoch_check=True) for entry in raw_entries]

    def get_entries_for_export(
        self,
        include_secrets: bool = False,
        cancel_check: Callable[[], bool] | None = None,
    ) -> list[Entry]:
        raw_entries = self.db.get_entries(include_deleted=False)
        entries = []
        for raw_entry in raw_entries:
            if cancel_check and cancel_check():
                break
            entries.append(
                self.decrypt_entry_for_export(raw_entry, include_secrets)
            )
        return entries

    def toggle_favorite(self, entry_id: int) -> bool | None:
        """切换收藏状态，返回新的收藏状态；条目不存在时返回 None。

        在单个事务内完成读-改-写，避免 TOCTOU 竞态。
        update_entry 会自动重签 metadata_mac，保证元数据完整性。
        """
        with self._vault.epoch_guarded_transaction(operation='切换收藏'):
            raw = self._vault.db.get_entry(entry_id)
            if raw is None:
                return None
            raw.is_favorite = not raw.is_favorite
            self._vault.db.update_entry(raw)
            result = raw.is_favorite
        # 收藏切换不影响密码相关分析维度，传 False 避免 SecurityAnalyzer 缓存
        # 无谓失效触发整库重算。is_favorite 不在摘要/标签/分类名缓存中，三者
        # 均无需失效；列表排序变化由回调触发 SQL 重查，复用摘要缓存避免重解密。
        self._change_bus.notify(
            password_changed=False, clear_summaries=False, tags_changed=False,
        )
        return result

    def get_entry_count(self, include_deleted: bool = False) -> int:
        return self._vault.db.get_entry_count(include_deleted)

    def get_all_tags(self) -> list[tuple[str, int]]:
        """获取所有标签及其使用频率。委托 cache。"""
        return self._cache.get_all_tags()

    @staticmethod
    def matches_search(entry: Entry, query: str) -> bool:
        """检查条目是否匹配搜索关键词，大小写不敏感，匹配 title、username、url、tags。

        EntryManager 的公共 API，委托给 ``crypto_utils.matches_search``。UI 层应通过
        此方法调用，避免直接依赖 ``business.crypto_utils`` 模块。
        """
        return matches_search(entry, query)

    @staticmethod
    def matches_tag(entry: Entry, tag: str) -> bool:
        """检查条目是否包含指定标签。

        标签匹配为大小写不敏感的精确匹配：条目 tags 字段以逗号分隔后，
        逐个与目标 tag 比对。即 ``tag="work"`` 匹配 ``"Work,Personal"``
        但不匹配 ``"network"``。

        此方法作为 EntryManager 的公共 API 委托给 ``crypto_utils.matches_tag``，
        供 UI 层使用，避免 UI 直接依赖 ``crypto_utils`` 模块。
        """
        return _matches_tag_impl(entry, tag)
