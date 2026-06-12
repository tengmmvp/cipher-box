"""条目管理器，负责密码条目的加密 CRUD 操作。

架构说明：EntryManager 直接依赖 crypto_utils 的 encrypt_field 与 decrypt_field，
这属于 Business → Crypto 的同层依赖，符合架构约束。UI 层通过 EntryManager
间接访问这些加密原语，不直接导入 crypto 模块。
"""

import json
import logging
import uuid
from typing import TYPE_CHECKING, Optional

from ...utils.format import utc_now_iso

if TYPE_CHECKING:
    from .vault_manager import VaultManager

logger = logging.getLogger(__name__)

from ...crypto.password_generator import PasswordGenerator
from ...crypto.totp import TOTPGenerator
from ...exceptions import DecryptionError, EntryIntegrityError
from ...models import (
    ENTRY_TYPES,
    MAX_FIELD_NOTES,
    MAX_FIELD_PASSWORD,
    MAX_FIELD_TAGS,
    MAX_FIELD_TITLE,
    MAX_FIELD_TOTP_SECRET,
    MAX_FIELD_URL,
    MAX_FIELD_USERNAME,
    Category,
    CustomField,
    Entry,
    PasswordHistory,
    RawEntry,
    Sensitive,
)
from ...utils.format import format_datetime
from ..services.crypto_utils import (
    build_entry_summary,
    copy_entry_fields,
    matches_search,
    require_vault_key,
)
from ..services.crypto_utils import (
    decrypt_field as _decrypt_field_impl,
)
from ..services.crypto_utils import (
    encrypt_field as _encrypt_field_impl,
)
from ..services.crypto_utils import matches_tag as _matches_tag_impl


class EntryManager:
    """管理密码条目的加密、解密和 CRUD 操作"""

    def __init__(self, vault_manager: 'VaultManager'):
        self._vault = vault_manager
        # username 明文缓存，crypto_id → 解密 username，减少重复搜索解密。
        # 生命周期：会话内有效，key_epoch 变化即改密或锁定时自动失效。
        # username 非密码，缓存风险可控；详见 _cached_username。
        self._username_cache: dict[str, str] = {}
        self._username_decrypt_failed: set[str] = set()
        self._cache_epoch: str | None = None
        # TOTP secret 明文缓存，entry_id → 解密 totp_secret。
        # 仅供 generate_totp_cached 复用，避免定时器每秒查 DB + AESGCM 解密。
        # 生命周期与 username 缓存一致：key_epoch 因改密或锁定而变化时即清空，
        # 条目更新修改 totp_secret 时按 entry_id 失效，详见 update_entry。
        # TOTP secret 用于生成验证码，属敏感凭据，但与 username 同属会话内
        # 必需明文，缓存窗口与 username 缓存等价。
        self._totp_secret_cache: dict[int, str] = {}
        # 标签计数缓存，避免侧边栏每次刷新都全表扫描 tags 列并内存聚合。
        # tags 为明文字段、非加密，缓存仅含 tag 计数，无敏感数据。
        # 失效条件：条目增删改经 _notify_entry_change 触发，锁定或改密使 epoch 变化。
        self._tags_cache: list[tuple[str, int]] | None = None
        # 条目变更回调列表，用于事件驱动的缓存失效，如 SecurityAnalyzer。
        self._on_entry_change_callbacks: list = []

    def register_on_change(self, callback):
        """注册条目变更时自动调用的回调，用于缓存失效等。"""
        self._on_entry_change_callbacks.append(callback)

    @property
    def db(self):
        return self._vault.db

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
    ) -> Entry:
        """构建加密 Entry 对象，统一处理字段加密逻辑。

        add_entry 和 update_entry 共用此方法，避免加密字段遗漏。
        password_override: 若提供，视为已加密的密文，直接赋值，不再重复加密。
        """
        # password_override 已是密文，即 update_entry 场景，直接赋值；
        # 否则加密明文密码，即 add_entry 场景。
        encrypted_pwd = (
            password_override
            if password_override is not None
            else self._encrypt_field(entry.password, crypto_id, 'password')
        )
        return Entry(
            id=entry_id,
            crypto_id=crypto_id,
            title=entry.title,
            username=self._encrypt_field(entry.username, crypto_id, 'username'),
            password=encrypted_pwd,
            url=entry.url,
            category_id=entry.category_id,
            tags=entry.tags,
            notes=self._encrypt_field(entry.notes, crypto_id, 'notes'),
            custom_fields=self._encrypt_custom_fields(entry.custom_fields, crypto_id),
            is_favorite=entry.is_favorite,
            password_strength=entry.password_strength,
            entry_type=entry.entry_type,
            totp_secret=self._encrypt_field(entry.totp_secret, crypto_id, 'totp_secret'),
            created_at=created_at or now,
            updated_at=updated_at or now,
            password_changed_at=entry.password_changed_at or now,
        )

    def _encrypt_field(self, plaintext: str, crypto_id: str, field_name: str) -> str:
        """加密单个字段，委托给 crypto_utils.encrypt_field"""
        return _encrypt_field_impl(plaintext, self._key, crypto_id, field_name)

    def _decrypt_field(
        self,
        encrypted: str,
        crypto_id: str,
        field_name: str,
        strict: bool = False,
    ) -> str:
        """解密单个字段，委托给 crypto_utils.decrypt_field"""
        return _decrypt_field_impl(
            encrypted, self._key, crypto_id, field_name, strict=strict,
        )

    def _cached_username(self, raw_entry: RawEntry) -> str:
        """返回解密后的 username，带会话内缓存，key_epoch 变化时失效。

        加密 username 使 SQL 无法下推搜索匹配，每次搜索需解密全部 username。
        本缓存避免重复解密：首次解密后按 crypto_id 缓存，后续命中直接返回。

        生命周期与安全：
        - key_epoch 变化即改密或锁定时，下次访问检测到并清空缓存。
        - 锁定后 key_epoch 为 None，触发清空；MainWindow.prepare_for_lock 亦会
          显式调用 invalidate_caches 以立即释放明文，避免锁定到进程退出的残留窗口。
        - 缓存的是 username 明文，属 PII 而非密码，风险可控。
        - 解密失败的 crypto_id 记入 _username_decrypt_failed，供 _decrypt_summary
          标记 integrity_error。
        """
        self._invalidate_if_epoch_changed()
        cid = raw_entry.crypto_id
        if cid in self._username_cache:
            return self._username_cache[cid]
        try:
            username = self._decrypt_field(
                raw_entry.username, cid, 'username', strict=True
            )
        except ValueError:
            logger.warning(
                "username 解密失败 (crypto_id=%s)，缓存为空串", cid,
            )
            username = ''
            self._username_decrypt_failed.add(cid)
        self._username_cache[cid] = username
        return username

    def _invalidate_if_epoch_changed(self):
        """检测 vault.key_epoch 变化，变化则清空所有明文缓存。

        当 key_epoch 变为 None 时，即保险库已锁定或 epoch 不匹配强制清除，
        无论 _cache_epoch 是否也为 None，都应清空缓存。
        """
        current = self._vault.key_epoch
        if current is None or current != self._cache_epoch:
            self._username_cache.clear()
            self._username_decrypt_failed.clear()
            self._totp_secret_cache.clear()
            self._tags_cache = None
            self._cache_epoch = current

    def invalidate_caches(self):
        """外部调用：锁定或改密后显式清空明文缓存。"""
        self._username_cache.clear()
        self._username_decrypt_failed.clear()
        self._totp_secret_cache.clear()
        self._tags_cache = None
        self._cache_epoch = None

    def _notify_entry_change(self, password_changed: bool = True):
        """通知所有注册的条目变更回调，事件驱动缓存失效。

        password_changed 为 False，如仅修改标题或 URL 时，不涉及密码的分析维度，
        即弱密码、重复、过期结果不变，订阅方可据此跳过昂贵的缓存重算。
        增删条目等结构性变更保持默认 True，因其改变 total 与重复分组。
        """
        # 条目增删改可能改变 tags 分布，失效标签计数缓存，下次 get_all_tags 重算。
        self._tags_cache = None
        for cb in self._on_entry_change_callbacks:
            try:
                cb(password_changed)
            except Exception:
                logger.debug("条目变更回调执行失败", exc_info=True)

    def _encrypt_custom_fields(
        self,
        fields: list[CustomField] | str,
        crypto_id: str,
    ) -> str:
        """加密自定义字段列表"""
        if not fields:
            return ''
        if not isinstance(fields, list) or not all(
            isinstance(field, CustomField) for field in fields
        ):
            raise ValueError('自定义字段必须是 CustomField 列表')
        data = json.dumps([f.to_dict() for f in fields], ensure_ascii=False)
        return self._encrypt_field(data, crypto_id, 'custom_fields')

    def _decrypt_custom_fields(self, encrypted: str, crypto_id: str) -> list[CustomField]:
        """解密自定义字段列表"""
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
        """解密条目的所有敏感字段，返回新的 Entry 对象"""
        integrity_errors = []

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
            username=decrypt('username', raw_entry.username),
            password=Sensitive(decrypt('password', raw_entry.password)),
            notes=decrypt('notes', raw_entry.notes),
            custom_fields=custom_fields,
            totp_secret=Sensitive(decrypt('totp_secret', raw_entry.totp_secret)),
            integrity_error=bool(integrity_errors),
            integrity_message='、'.join(integrity_errors),
        )

    def decrypt_entry_for_export(
        self,
        raw_entry: RawEntry,
        include_secrets: bool = False,
    ) -> Entry:
        """仅解密导出所需字段，默认不让密码与 TOTP 进入内存结果。"""
        try:
            custom_fields = self._decrypt_custom_fields(
                raw_entry.custom_fields_db_value,
                raw_entry.crypto_id,
            )
            return copy_entry_fields(
                raw_entry,
                username=self._decrypt_field(
                    raw_entry.username, raw_entry.crypto_id, 'username', strict=True
                ),
                password=(
                    self._decrypt_field(
                        raw_entry.password, raw_entry.crypto_id, 'password', strict=True
                    ) if include_secrets else ''
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

    def _decrypt_summary(self, raw_entry: RawEntry) -> Entry:
        """仅解密列表展示所需字段，不让密码等明文进入列表模型。

        username 经 _cached_username 复用会话内缓存，避免列表/搜索路径
        重复解密。解密失败由 _username_decrypt_failed 记录并据此标记完整性。
        """
        username = self._cached_username(raw_entry)
        integrity_error = raw_entry.crypto_id in self._username_decrypt_failed
        summary = build_entry_summary(raw_entry, username)
        summary.integrity_error = integrity_error
        summary.integrity_message = '账号' if integrity_error else ''
        return summary

    def add_entry(self, entry: Entry) -> int:
        """添加新条目，自动加密并检测强度。"""
        self._validate_plain_entry(entry)
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
        self._notify_entry_change()
        return result

    def update_entry(self, entry: Entry):
        """更新条目，自动加密并记录密码历史。

        线程安全说明：此方法采用 read-modify-write 模式，先读取旧密码，
        比较后再写入，未使用锁保护。在单用户桌面应用中，同一时刻只有
        一个 UI 操作会修改同一条目，竞态窗口极小，可接受。若未来引入
        并发写入场景，需在此方法外加锁。
        """
        self._validate_plain_entry(entry)
        if entry.integrity_error:
            raise EntryIntegrityError(
                f"条目存在无法解密的字段（{entry.integrity_message}），为避免数据丢失已禁止保存"
            )
        if entry.id is None:
            return
        raw = self.db.get_entry(entry.id)
        if raw is None:
            return

        # 条目更新可能修改 totp_secret，失效该条目的 TOTP secret 缓存，
        # 下次 get_totp_state / generate_totp_cached 重新解密。
        self._totp_secret_cache.pop(entry.id, None)

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
        password_changed_at = (
            utc_now_iso()
            if password_changed
            else raw.password_changed_at
        )

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
            if old_pwd_enc and password_changed and entry.id is not None:
                self.db.add_password_history(entry.id, old_pwd_enc)
            self.db.update_entry(enc_entry)
        self._notify_entry_change(password_changed)

    def delete_entry(self, entry_id: int):
        """软删除条目，移入回收站。"""
        self._vault.db.soft_delete_entry(entry_id)
        self._totp_secret_cache.pop(entry_id, None)
        self._notify_entry_change()

    def restore_entry(self, entry_id: int):
        """恢复条目"""
        self._vault.db.restore_entry(entry_id)
        self._notify_entry_change()

    def permanent_delete_entry(self, entry_id: int):
        """永久删除条目"""
        self._vault.db.permanent_delete_entry(entry_id)
        self._totp_secret_cache.pop(entry_id, None)
        self._notify_entry_change()

    def empty_trash(self):
        """清空回收站"""
        self._vault.db.empty_trash()
        self._totp_secret_cache.clear()
        self._notify_entry_change()

    def get_entries(
        self,
        deleted_only: bool = False,
        include_deleted: bool = False,
        category_id: Optional[int] = None,
        favorite_only: bool = False,
        search: str = '',
    ) -> list[Entry]:
        """获取并解密条目列表。

        WARNING: 搜索场景下仅解密 username 用于匹配，命中条目再完整解密，
        减少未命中条目的 password、totp_secret 等敏感数据暴露在内存中。
        对于列表展示等不需要密码的场景，优先使用 get_entry_summaries。

        NOTE: search 参数不传递到 SQL 层，因为 username 是加密字段，
        SQL LIKE 无法过滤。所有搜索匹配在 Python 层完成。

        PERF: 生产代码中列表展示统一走轻量的 get_entry_summaries（仅解密
        username），本方法的 search 分支「命中后完整解密」仅在测试中使用，
        不构成生产路径的性能热点。导出等需要全字段的场景走
        get_entries_for_export。如未来需要列表展示调用此方法，应改用
        get_entry_summaries 以避免过度解密。
        """
        raw_entries = self._vault.db.get_entries(
            deleted_only=deleted_only,
            include_deleted=include_deleted,
            category_id=category_id,
            favorite_only=favorite_only,
        )

        if search:
            # 搜索路径：仅解密 username 用于匹配，复用会话内缓存避免重复解密。
            # 通过 username_override 将缓存值注入 matches_search，避免内联搜索逻辑。
            matched = []
            for raw in raw_entries:
                username = self._cached_username(raw)
                if matches_search(raw, search, username_override=username):
                    matched.append(self.decrypt_entry(raw))
            decrypted = matched
        else:
            decrypted = [self.decrypt_entry(e) for e in raw_entries]

        # 检查解密失败的条目并记录警告
        for dec_entry in decrypted:
            if dec_entry.integrity_error:
                logger.warning("条目 %d (%s) 解密存在异常", dec_entry.id, dec_entry.title)

        return decrypted

    def get_entry(self, entry_id: int) -> Optional[Entry]:
        """获取并解密单个条目"""
        raw = self._vault.db.get_entry(entry_id)
        if raw is None:
            return None
        return self.decrypt_entry(raw)

    def get_entry_summaries(
        self,
        deleted_only: bool = False,
        category_id: Optional[int] = None,
        favorite_only: bool = False,
        search: str = '',
        limit: int | None = None,
    ) -> list[Entry]:
        """获取不含密码等敏感明文的列表摘要。

        Note:
            ``limit`` 的生效方式取决于 ``search``：
            - ``search`` 为空时，``limit`` 在 SQL 层生效（LIMIT 子句），高效截断。
            - ``search`` 非空时，因加密字段无法在数据库层面搜索，必须先全量
              解密 username 再在内存中过滤。此时 ``limit`` 不下推到 SQL（否则会先
              截断再过滤，导致搜索命中远少于实际），由调用方在内存过滤后自行截断。
              即当 search 非空时本方法忽略 limit，返回全部命中结果。
        """
        # search 非空时不向 SQL 下推 limit，避免「先截断后过滤」导致命中失真。
        sql_limit = limit if not search else None
        raw_entries = self.db.get_entries(
            deleted_only=deleted_only,
            category_id=category_id,
            favorite_only=favorite_only,
            limit=sql_limit,
        )
        summaries = [self._decrypt_summary(entry) for entry in raw_entries]
        if search:
            summaries = [e for e in summaries if matches_search(e, search)]
            # search 时 limit 未下推 SQL，此处截断以兑现 limit 契约
            if limit:
                summaries = summaries[:limit]
        return summaries

    def get_entries_for_export(self, include_secrets: bool = False) -> list[Entry]:
        raw_entries = self.db.get_entries(include_deleted=False)
        return [
            self.decrypt_entry_for_export(entry, include_secrets)
            for entry in raw_entries
        ]

    # ==================== 委托方法 ====================
    # 以下方法直接委托给 DatabaseManager，无额外业务逻辑。
    # 委托层存在的理由：为 UI 层提供单一入口点，允许未来在此层添加
    # 验证或日志逻辑，防止 UI 直接依赖 DatabaseManager。
    # DELEGATE: see DatabaseManager.get_categories
    def get_categories(self) -> list[Category]:
        return self._vault.db.get_categories()

    # DELEGATE: see DatabaseManager.get_category
    def get_category(self, category_id: int) -> Category | None:
        return self._vault.db.get_category(category_id)

    # DELEGATE: see DatabaseManager.get_category_entry_count
    def get_category_entry_count(self, category_id: int) -> int:
        return self._vault.db.get_category_entry_count(category_id)

    # DELEGATE: see DatabaseManager.get_category_entry_counts
    def get_category_entry_counts(self) -> dict[int, int]:
        return self._vault.db.get_category_entry_counts()

    # DELEGATE: see DatabaseManager.add_category
    def add_category(self, category: Category) -> int:
        result = self._vault.db.add_category(category)
        # 分类变更不改变条目密码相关维度，仅失效 _tags_cache 等结构缓存。
        self._notify_entry_change(password_changed=False)
        return result

    # DELEGATE: see DatabaseManager.update_category
    def update_category(self, category: Category) -> None:
        self._vault.db.update_category(category)
        # 分类变更不改变条目密码相关维度，仅失效 _tags_cache 等结构缓存。
        self._notify_entry_change(password_changed=False)

    # DELEGATE: see DatabaseManager.delete_category
    def delete_category(self, category_id: int) -> None:
        self._vault.db.delete_category(category_id)
        # 分类变更不改变条目密码相关维度，仅失效 _tags_cache 等结构缓存。
        self._notify_entry_change(password_changed=False)

    def toggle_favorite(self, entry_id: int) -> bool | None:
        """切换收藏状态，返回新的收藏状态；条目不存在时返回 None。

        在单个事务内完成读-改-写，避免 TOCTOU 竞态。
        update_entry 会自动重签 metadata_mac，保证元数据完整性。
        """
        with self._vault.db.transaction():
            raw = self._vault.db.get_entry(entry_id)
            if raw is None:
                return None
            raw.is_favorite = not raw.is_favorite
            self._vault.db.update_entry(raw)
            result = raw.is_favorite
        self._notify_entry_change()
        return result

    # DELEGATE: see DatabaseManager.get_entry_count
    def get_entry_count(self, include_deleted: bool = False) -> int:
        return self._vault.db.get_entry_count(include_deleted)

    # DELEGATE: see DatabaseManager.get_password_history
    def get_password_history(self, entry_id: int) -> list[PasswordHistory]:
        return self._vault.db.get_password_history(entry_id)

    # DELEGATE: see DatabaseManager.get_password_history_count
    def get_password_history_count(self, entry_id: int) -> int:
        return self.db.get_password_history_count(entry_id)

    def decrypt_password_history(self, history: list[PasswordHistory]) -> list[dict]:
        """解密密码历史，返回字典列表，每个字典含变更时间 changed_at 与密码 password。"""
        result = []
        for h in history:
            pwd = self._decrypt_field(
                h.old_password_enc, h.entry_crypto_id, 'password'
            )
            if pwd:
                result.append({
                    'changed_at': format_datetime(h.changed_at),
                    'password': pwd,
                })
        return result

    # ==================== TOTP 生成 ====================
    # UI→Business 迁移，调用方不接触明文 TOTP secret

    def generate_totp(self, entry_id: int) -> str | None:
        """生成指定条目的 TOTP 验证码。

        仅解密 totp_secret 字段，避免触发 password/notes/custom_fields
        等其他敏感字段的不必要解密。

        解密逻辑复用 generate_totp_cached 的单一解密路径，避免两份独立的
        解密与空值判断逻辑漂移。与 generate_totp_cached 的区别：本方法
        不写入会话内 totp_secret 缓存（调用方按需自行预热）。

        Returns:
            6 位验证码字符串，条目不存在或无 TOTP 密钥时返回 None。
        """
        secret = self._resolve_totp_secret(entry_id)
        if not secret:
            return None
        return TOTPGenerator.generate(secret)

    def generate_totp_cached(self, entry_id: int) -> str | None:
        """生成指定条目的 TOTP 验证码，复用会话内缓存的 totp_secret。

        与 generate_totp 的区别：缓存命中时跳过 DB 查询与 AESGCM 解密，
        仅做纯 HOTP 计算，供 TOTP 定时器每秒刷新调用。缓存以 entry_id 为键，
        由以下途径失效：
        - key_epoch 变化（改密/锁定）：整体清空（_invalidate_if_epoch_changed）。
        - 条目更新修改 totp_secret：按 entry_id 失效（update_entry）。
        - 条目删除：按 entry_id 失效（delete_entry / permanent_delete_entry）。
        get_totp_state 在条目首次展示时预热缓存，此后定时器全程命中缓存。

        解密逻辑复用 _resolve_totp_secret 的单一解密路径，避免与 generate_totp
        两份独立的解密与空值判断逻辑漂移。

        Returns:
            6 位验证码字符串，条目不存在或无 TOTP 密钥时返回 None。
        """
        self._invalidate_if_epoch_changed()
        secret = self._resolve_totp_secret(entry_id, use_cache=True)
        if not secret:
            return None
        return TOTPGenerator.generate(secret)

    def _resolve_totp_secret(
        self, entry_id: int, *, use_cache: bool = False,
    ) -> str | None:
        """解析条目的 totp_secret 明文，单一解密路径供 TOTP 方法复用。

        Args:
            entry_id: 条目 ID。
            use_cache: 是否读写会话内 totp_secret 缓存。generate_totp_cached
                传 True 复用缓存；generate_totp 传 False 仅解密不落缓存，
                保持其「不写缓存」语义。
        """
        if use_cache:
            secret = self._totp_secret_cache.get(entry_id)
            if secret is not None:
                return secret
        raw = self.db.get_entry(entry_id)
        if raw is None or not raw.totp_secret:
            return None
        secret = self._decrypt_field(
            raw.totp_secret, raw.crypto_id, 'totp_secret',
        )
        if not secret:
            return None
        if use_cache:
            self._totp_secret_cache[entry_id] = secret
        return secret

    def get_totp_state(self, entry_id: int) -> dict | None:
        """获取指定条目的 TOTP 完整状态，含验证码、倒计时和周期。

        仅解密 totp_secret 字段，供 detail_panel 的 TOTP 显示和刷新定时器使用。
        首次调用时将解密后的 secret 写入 _totp_secret_cache，使后续
        generate_totp_cached 命中缓存，避免定时器每秒重复解密。

        Returns:
            包含验证码 code、剩余秒数 remaining、周期 period 三个键的字典；
            条目不存在或无 TOTP 密钥时返回 None。
        """
        self._invalidate_if_epoch_changed()
        raw = self.db.get_entry(entry_id)
        if raw is None or not raw.totp_secret:
            return None
        secret = self._decrypt_field(raw.totp_secret, raw.crypto_id, 'totp_secret')
        if not secret:
            return None
        # 预热缓存，供 generate_totp_cached 复用。
        self._totp_secret_cache[entry_id] = secret
        return {
            'code': TOTPGenerator.generate(secret),
            'remaining': TOTPGenerator.get_remaining_seconds(secret=secret),
            'period': TOTPGenerator.get_period(secret),
        }

    def get_all_tags(self) -> list[tuple[str, int]]:
        """获取所有标签及其使用频率。

        结果在会话内缓存，避免侧边栏每次刷新（含搜索防抖）都全表扫描 tags
        列并内存聚合。缓存于条目增删改（_notify_entry_change）与锁定/改密
        （key_epoch 变化）时失效。tags 为明文字段，缓存无敏感数据。
        """
        self._invalidate_if_epoch_changed()
        if self._tags_cache is not None:
            return self._tags_cache
        tag_rows = self.db.get_all_tags()
        tag_count: dict[str, int] = {}
        for tags_str in tag_rows:
            for tag in (t.strip() for t in tags_str.split(',') if t.strip()):
                tag_count[tag] = tag_count.get(tag, 0) + 1
        self._tags_cache = sorted(tag_count.items(), key=lambda x: -x[1])
        return self._tags_cache

    @staticmethod
    def _validate_plain_entry(entry: Entry):
        if entry.entry_type not in ENTRY_TYPES:
            raise ValueError('条目类型无效')
        for field_name in (
            'title', 'username', 'password', 'url', 'tags', 'notes', 'totp_secret'
        ):
            if not isinstance(getattr(entry, field_name), str):
                raise ValueError(f'条目字段 {field_name} 类型无效')
        field_limits = {
            'title': MAX_FIELD_TITLE, 'username': MAX_FIELD_USERNAME,
            'password': MAX_FIELD_PASSWORD, 'url': MAX_FIELD_URL,
            'tags': MAX_FIELD_TAGS, 'notes': MAX_FIELD_NOTES,
            'totp_secret': MAX_FIELD_TOTP_SECRET,
        }
        for field_name, max_len in field_limits.items():
            if len(getattr(entry, field_name)) > max_len:
                raise ValueError(f'条目字段 {field_name} 过长（最多 {max_len} 字符）')
        # 此方法仅用于 add_entry/update_entry 路径的明文条目校验。
        # custom_fields 必须为已解密的 list[CustomField]。
        # DB 原始条目的 custom_fields 为 str 类型的密文，不经过此校验。
        entry.assert_decrypted()
        if not isinstance(entry.custom_fields, list) or not all(
            isinstance(field, CustomField) for field in entry.custom_fields
        ):
            raise ValueError('自定义字段结构无效')

    @staticmethod
    def matches_search(entry, query: str) -> bool:
        """检查条目是否匹配搜索关键词，大小写不敏感，匹配 title、username、url、tags。

        此方法作为 EntryManager 的公共 API 委托给 ``crypto_utils.matches_search``，
        供 UI 层使用，避免 UI 直接依赖 ``business.crypto_utils`` 模块，
        同时消除两份相同实现必须手动同步的维护负担。

        Note:
            内部实现委托给 ``crypto_utils.matches_search``。UI 层应通过
            此公共方法调用，避免直接依赖 ``crypto_utils`` 模块。
        """
        return matches_search(entry, query)

    @staticmethod
    def matches_tag(entry, tag: str) -> bool:
        """检查条目是否包含指定标签。

        标签匹配为大小写不敏感的精确匹配：条目 tags 字段以逗号分隔后，
        逐个与目标 tag 比对。即 ``tag="work"`` 匹配 ``"Work,Personal"``
        但不匹配 ``"network"``。

        此方法作为 EntryManager 的公共 API 委托给 ``crypto_utils.matches_tag``，
        供 UI 层使用，避免 UI 直接依赖 ``crypto_utils`` 模块。
        """
        return _matches_tag_impl(entry, tag)
