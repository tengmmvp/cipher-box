"""条目管理器 - 密码条目的加密 CRUD 操作。

架构说明：EntryManager 直接依赖 crypto_utils 的 encrypt_field / decrypt_field，
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
from ...database.models import (
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
)
from ...utils.format import format_datetime
from ..exceptions import DecryptionError, EntryIntegrityError, VaultLockedError
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

_MAX_TITLE_LEN = MAX_FIELD_TITLE
_MAX_USERNAME_LEN = MAX_FIELD_USERNAME
_MAX_URL_LEN = MAX_FIELD_URL
_MAX_PASSWORD_LEN = MAX_FIELD_PASSWORD
_MAX_NOTES_LEN = MAX_FIELD_NOTES
_MAX_TAGS_LEN = MAX_FIELD_TAGS
_MAX_TOTP_SECRET_LEN = MAX_FIELD_TOTP_SECRET


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

    def get_cached_username(self, raw_entry: Entry) -> str:
        """获取条目的缓存用户名（优先使用缓存，避免重复解密）。"""
        return self._cached_username(raw_entry)

    def _cached_username(self, raw_entry: Entry) -> str:
        """返回解密后的 username，带会话内缓存（key_epoch 失效）。

        加密 username 使 SQL 无法下推搜索匹配，每次搜索需解密全部 username。
        本缓存避免重复解密：首次解密后按 crypto_id 缓存，后续命中直接返回。

        生命周期与安全：
        - key_epoch 变化即改密或锁定时，下次访问检测到并清空缓存。
        - 锁定后 key_epoch 为 None，触发清空；MainWindow.prepare_for_lock 亦会
          显式调用 invalidate_caches() 以立即释放明文，避免锁定到进程退出的残留窗口。
        - 缓存的是 username 明文（PII，非密码），风险可控。
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

        当 key_epoch 变为 None（保险库已锁定或 epoch 不匹配强制清除）时，
        无论 _cache_epoch 是否也为 None，都应清空缓存。
        """
        current = self._vault.key_epoch
        if current is None or current != self._cache_epoch:
            self._username_cache.clear()
            self._username_decrypt_failed.clear()
            self._cache_epoch = current

    def invalidate_caches(self):
        """外部调用：锁定或改密后显式清空明文缓存。"""
        self._username_cache.clear()
        self._username_decrypt_failed.clear()
        self._cache_epoch = None

    def _notify_entry_change(self):
        """通知所有注册的条目变更回调，事件驱动缓存失效。"""
        for cb in self._on_entry_change_callbacks:
            try:
                cb()
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

    def decrypt_entry(self, raw_entry: Entry) -> Entry:
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
            password=decrypt('password', raw_entry.password),
            notes=decrypt('notes', raw_entry.notes),
            custom_fields=custom_fields,
            totp_secret=decrypt('totp_secret', raw_entry.totp_secret),
            integrity_error=bool(integrity_errors),
            integrity_message='、'.join(integrity_errors),
        )

    def decrypt_entry_to_dict(
        self, raw_entry: Entry, include_secrets: bool = True,
    ) -> dict | None:
        """将原始 Entry 解密为明文字典（容错版本）。

        单条目解密失败时返回 None 而非抛出异常，供备份、导出等需要
        跳过损坏条目继续处理的场景使用。

        Args:
            raw_entry: 数据库层原始 Entry（custom_fields 为密文字符串）
            include_secrets: 是否包含密码和 TOTP 密钥等敏感字段
        """
        try:
            custom_json = self._decrypt_field(
                raw_entry.custom_fields_db_value,
                raw_entry.crypto_id, 'custom_fields',
            )
            try:
                custom_fields = json.loads(custom_json) if custom_json else []
            except json.JSONDecodeError:
                return None
            return {
                'id': raw_entry.id,
                'crypto_id': raw_entry.crypto_id,
                'title': raw_entry.title,
                'username': self._decrypt_field(
                    raw_entry.username, raw_entry.crypto_id, 'username',
                ),
                'password': (
                    self._decrypt_field(
                        raw_entry.password, raw_entry.crypto_id, 'password',
                    ) if include_secrets else ''
                ),
                'url': raw_entry.url,
                'category_id': raw_entry.category_id,
                'tags': raw_entry.tags,
                'notes': self._decrypt_field(
                    raw_entry.notes, raw_entry.crypto_id, 'notes',
                ),
                'custom_fields': custom_fields,
                'totp_secret': (
                    self._decrypt_field(
                        raw_entry.totp_secret, raw_entry.crypto_id, 'totp_secret',
                    ) if include_secrets else ''
                ),
                'password_strength': raw_entry.password_strength,
                'entry_type': raw_entry.entry_type,
                'is_favorite': raw_entry.is_favorite,
                'is_deleted': raw_entry.is_deleted,
                'created_at': raw_entry.created_at,
                'updated_at': raw_entry.updated_at,
                'deleted_at': raw_entry.deleted_at,
                'password_changed_at': raw_entry.password_changed_at,
            }
        except (ValueError, DecryptionError):
            logger.warning(
                "decrypt_entry_to_dict 跳过损坏条目 crypto_id=%s",
                raw_entry.crypto_id, exc_info=True,
            )
            return None

    def decrypt_entry_for_export(
        self,
        raw_entry: Entry,
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

    def _decrypt_summary(self, raw_entry: Entry) -> Entry:
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
        """添加新条目（自动加密并检测强度）"""
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
        """更新条目（自动加密、记录密码历史）

        线程安全说明：此方法采用 read-modify-write 模式（先读取旧密码、
        比较后再写入），未使用锁保护。在单用户桌面应用中，同一时刻只有
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

        # 检测密码变更，归档旧密码
        old_pwd_enc = raw.password
        # 安全-性能权衡：此处必须解密旧密码与明文比较来检测变更。
        # AES-256-GCM 每次加密使用随机 nonce，相同明文产生不同密文，
        # 因此密文比较不可行。HMAC 指纹方案需要在数据库中额外存储指纹
        # 字段（需 schema 变更），当前解密比较是无需迁移的合理选择。
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
        self._notify_entry_change()

    def delete_entry(self, entry_id: int):
        """软删除条目（移入回收站）"""
        self._vault.db.soft_delete_entry(entry_id)
        self._notify_entry_change()

    def restore_entry(self, entry_id: int):
        """恢复条目"""
        self._vault.db.restore_entry(entry_id)
        self._notify_entry_change()

    def permanent_delete_entry(self, entry_id: int):
        """永久删除条目"""
        self._vault.db.permanent_delete_entry(entry_id)
        self._notify_entry_change()

    def empty_trash(self):
        """清空回收站"""
        self._vault.db.empty_trash()
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
        减少未命中条目的 password/totp_secret 等敏感数据暴露在内存中。
        对于列表展示等不需要密码的场景，优先使用 get_entry_summaries()。

        NOTE: search 参数不传递到 SQL 层，因为 username 是加密字段，
        SQL LIKE 无法过滤。所有搜索匹配在 Python 层完成。
        """
        raw_entries = self._vault.db.get_entries(
            deleted_only=deleted_only,
            include_deleted=include_deleted,
            category_id=category_id,
            favorite_only=favorite_only,
        )

        if search:
            # 搜索路径：仅解密 username 用于匹配，复用会话内缓存避免重复解密。
            # 解密失败的条目由 _cached_username 记录并缓存空串。
            # 注意：此处的搜索逻辑与 crypto_utils.matches_search 逻辑一致
            # title/username/url/tags 四字段大小写不敏感匹配，但不能直接调用
            # matches_search，因为 raw 条目的 username 仍为密文，需要先通过
            # _cached_username 解密。matches_search 仅适用于已解密的 Entry 对象。
            kw = search.lower()
            matched = []
            for raw in raw_entries:
                username = self._cached_username(raw)
                if (kw in (raw.title or '').lower()
                        or kw in username.lower()
                        or kw in (raw.url or '').lower()
                        or kw in (raw.tags or '').lower()):
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
            当 ``limit`` 非空且 ``search`` 为空时，``limit`` 在 SQL 层生效，即 LIMIT 子句。
            但当 ``search`` 非空时，因加密字段无法在数据库层面搜索，
            必须先全量解密 username 再在内存中过滤，此时 SQL LIMIT 无法正确下推，
            可能返回少于 ``limit`` 条结果。这是加密数据库的根本限制。
        """
        raw_entries = self.db.get_entries(
            deleted_only=deleted_only,
            category_id=category_id,
            favorite_only=favorite_only,
            limit=limit,
        )
        summaries = [self._decrypt_summary(entry) for entry in raw_entries]
        if search:
            summaries = [e for e in summaries if matches_search(e, search)]
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
        return self._vault.db.add_category(category)

    # DELEGATE: see DatabaseManager.update_category
    def update_category(self, category: Category) -> None:
        self._vault.db.update_category(category)

    # DELEGATE: see DatabaseManager.delete_category
    def delete_category(self, category_id: int) -> None:
        self._vault.db.delete_category(category_id)

    def toggle_favorite(self, entry_id: int) -> bool | None:
        """切换收藏状态，返回新的收藏状态或 None（条目不存在）

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
        """解密密码历史，返回 [{changed_at, password}]"""
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

        Returns:
            6 位验证码字符串，条目不存在或无 TOTP 密钥时返回 None。
        """
        raw = self.db.get_entry(entry_id)
        if raw is None or not raw.totp_secret:
            return None
        secret = self._decrypt_field(raw.totp_secret, raw.crypto_id, 'totp_secret')
        if not secret:
            return None
        return TOTPGenerator.generate(secret)

    def get_totp_state(self, entry_id: int) -> dict | None:
        """获取指定条目的 TOTP 完整状态，含验证码、倒计时和周期。

        仅解密 totp_secret 字段，供 detail_panel 的 TOTP 显示和刷新定时器使用。

        Returns:
            ``{'code': str, 'remaining': int, 'period': int}``，
            条目不存在或无 TOTP 密钥时返回 None。
        """
        raw = self.db.get_entry(entry_id)
        if raw is None or not raw.totp_secret:
            return None
        secret = self._decrypt_field(raw.totp_secret, raw.crypto_id, 'totp_secret')
        if not secret:
            return None
        return {
            'code': TOTPGenerator.generate(secret),
            'remaining': TOTPGenerator.get_remaining_seconds(secret=secret),
            'period': TOTPGenerator.get_period(secret),
        }

    def get_all_tags(self) -> list[tuple[str, int]]:
        """获取所有标签及其使用频率"""
        tag_rows = self.db.get_all_tags()
        tag_count: dict[str, int] = {}
        for tags_str in tag_rows:
            for tag in (t.strip() for t in tags_str.split(',') if t.strip()):
                tag_count[tag] = tag_count.get(tag, 0) + 1
        return sorted(tag_count.items(), key=lambda x: -x[1])

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
            'title': _MAX_TITLE_LEN, 'username': _MAX_USERNAME_LEN,
            'password': _MAX_PASSWORD_LEN, 'url': _MAX_URL_LEN,
            'tags': _MAX_TAGS_LEN, 'notes': _MAX_NOTES_LEN,
            'totp_secret': _MAX_TOTP_SECRET_LEN,
        }
        for field_name, max_len in field_limits.items():
            if len(getattr(entry, field_name)) > max_len:
                raise ValueError(f'条目字段 {field_name} 过长（最多 {max_len} 字符）')
        # 此方法仅用于 add_entry/update_entry 路径的明文条目校验。
        # custom_fields 必须为 list[CustomField]（已解密）。
        # DB 原始条目的 custom_fields 为 str 类型（密文），不经过此校验。
        if not isinstance(entry.custom_fields, list) or not all(
            isinstance(field, CustomField) for field in entry.custom_fields
        ):
            raise ValueError('自定义字段结构无效')

    @staticmethod
    def matches_search(entry, query: str) -> bool:
        """检查条目是否匹配搜索关键词（大小写不敏感，搜索 title/username/url/tags）。

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
