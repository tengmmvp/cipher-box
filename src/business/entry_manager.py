"""条目管理器 - 密码条目的加密 CRUD 操作"""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .vault_manager import VaultManager

logger = logging.getLogger(__name__)

from ..crypto.password_generator import PasswordGenerator


def _format_datetime(iso_str: str) -> str:
    """将 ISO 8601 日期字符串格式化为 'YYYY-MM-DD HH:MM:SS'。

    优先使用 datetime.fromisoformat 进行严格解析，
    解析失败时回退到截断前 19 字符并替换 'T' 的兼容方式。
    """
    if not iso_str:
        return ''
    try:
        dt = datetime.fromisoformat(iso_str)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError):
        return iso_str[:19].replace('T', ' ')


from ..crypto.totp import TOTPGenerator
from ..database.models import (
    ENTRY_TYPES, Category, CustomField, Entry, PasswordHistory,
    MAX_FIELD_TITLE, MAX_FIELD_USERNAME, MAX_FIELD_URL,
    MAX_FIELD_PASSWORD, MAX_FIELD_NOTES, MAX_FIELD_TAGS,
    MAX_FIELD_TOTP_SECRET,
)
from .exceptions import DecryptionError, EntryIntegrityError, VaultLockedError
from .crypto_utils import (
    build_entry_summary,
    copy_entry_fields,
    decrypt_field as _decrypt_field_impl,
    encrypt_field as _encrypt_field_impl,
    matches_search,
    require_vault_key,
)

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
        # M-P1：username 明文缓存（crypto_id → 解密 username），减少重复搜索解密。
        # 生命周期：会话内有效，key_epoch 变化（改密/锁定）时自动失效。
        # username 非密码，缓存风险可控；详见 _cached_username。
        self._username_cache: dict[str, str] = {}
        self._username_decrypt_failed: set[str] = set()
        self._cache_epoch: str | None = None
        # A-06：条目变更回调列表，用于事件驱动的缓存失效（如 SecurityAnalyzer）。
        self._on_entry_change_callbacks: list = []

    def register_on_change(self, callback):
        """注册条目变更时自动调用的回调（用于缓存失效等）。"""
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
        password_override: 若提供，视为已加密的密文，直接赋值（不再加密）。
        """
        # password_override 已是密文（update_entry 场景），直接赋值；
        # 否则加密明文密码（add_entry 场景）。
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
        """加密单个字段（委托给 crypto_utils.encrypt_field）"""
        return _encrypt_field_impl(plaintext, self._key, crypto_id, field_name)

    def _decrypt_field(
        self,
        encrypted: str,
        crypto_id: str,
        field_name: str,
        strict: bool = False,
    ) -> str:
        """解密单个字段（委托给 crypto_utils.decrypt_field）"""
        return _decrypt_field_impl(
            encrypted, self._key, crypto_id, field_name, strict=strict,
        )

    def get_cached_username(self, raw_entry: Entry) -> str:
        """获取条目的缓存用户名（优先使用缓存，避免重复解密）。"""
        return self._cached_username(raw_entry)

    def _cached_username(self, raw_entry: Entry) -> str:
        """返回解密后的 username，带会话内缓存（key_epoch 失效）。

        M-P1：加密 username 使 SQL 无法下推搜索匹配，每次搜索需解密全部 username。
        本缓存避免重复解密：首次解密后按 crypto_id 缓存，后续命中直接返回。

        生命周期与安全：
        - key_epoch 变化（改密/锁定）时，下次访问检测到并清空缓存。
        - 锁定后 key_epoch 为 None，触发清空；MainWindow.prepare_for_lock 亦会
          显式调用 invalidate_caches() 以立即释放明文（避免锁定到进程退出的残留窗口）。
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
        """检测 vault.key_epoch 变化，变化则清空所有明文缓存。"""
        current = self._vault.key_epoch
        if current != self._cache_epoch:
            self._username_cache.clear()
            self._username_decrypt_failed.clear()
            self._cache_epoch = current

    def invalidate_caches(self):
        """外部调用：锁定或改密后显式清空明文缓存。"""
        self._username_cache.clear()
        self._username_decrypt_failed.clear()
        self._cache_epoch = None

    def _notify_entry_change(self):
        """A-06：通知所有注册的条目变更回调（事件驱动缓存失效）。"""
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

        M-P1：username 经 _cached_username 复用会话内缓存，避免列表/搜索路径
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

        now = datetime.now(timezone.utc).isoformat()
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
            datetime.now(timezone.utc).isoformat()
            if password_changed
            else raw.password_changed_at
        )

        strength = PasswordGenerator.check_strength(entry.password)
        entry.password_strength = strength.score

        now = datetime.now(timezone.utc).isoformat()
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
            # 搜索路径：仅解密 username 用于匹配（M-P1：复用会话内缓存避免重复解密，
            # 解密失败的条目由 _cached_username 记录并缓存空串）。
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
        """获取不含密码等敏感明文的列表摘要。"""
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
    # 委托层存在是为了：(1) 为 UI 层提供单一入口点，(2) 允许未来在此层添加
    # 验证/日志/A/B 测试逻辑，(3) 防止 UI 直接依赖 DatabaseManager。
    # DELEGATE: see DatabaseManager.get_categories
    def get_categories(self) -> list[Category]:
        """获取所有分类"""
        return self._vault.db.get_categories()

    # DELEGATE: see DatabaseManager.get_category
    def get_category(self, category_id: int) -> Category | None:
        """获取单个分类"""
        return self._vault.db.get_category(category_id)

    # DELEGATE: see DatabaseManager.get_category_entry_count
    def get_category_entry_count(self, category_id: int) -> int:
        """获取指定分类的条目数"""
        return self._vault.db.get_category_entry_count(category_id)

    # DELEGATE: see DatabaseManager.get_category_entry_counts
    def get_category_entry_counts(self) -> dict[int, int]:
        """获取所有分类的条目计数"""
        return self._vault.db.get_category_entry_counts()

    # DELEGATE: see DatabaseManager.add_category
    def add_category(self, category: Category) -> int:
        """添加分类"""
        return self._vault.db.add_category(category)

    # DELEGATE: see DatabaseManager.update_category
    def update_category(self, category: Category) -> None:
        """更新分类"""
        self._vault.db.update_category(category)

    # DELEGATE: see DatabaseManager.delete_category
    def delete_category(self, category_id: int) -> None:
        """删除分类"""
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
        """获取条目数量"""
        return self._vault.db.get_entry_count(include_deleted)

    # DELEGATE: see DatabaseManager.get_password_history
    def get_password_history(self, entry_id: int) -> list[PasswordHistory]:
        """获取密码历史（返回加密记录）"""
        return self._vault.db.get_password_history(entry_id)

    # DELEGATE: see DatabaseManager.get_password_history_count
    def get_password_history_count(self, entry_id: int) -> int:
        """获取密码历史记录数（轻量 COUNT 查询，避免加载全部记录）。"""
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
                    'changed_at': _format_datetime(h.changed_at),
                    'password': pwd,
                })
        return result

    # ------------------------------------------------------------------
    # TOTP（4A：UI→Business 迁移，调用方不接触明文 secret）
    # ------------------------------------------------------------------

    def generate_totp(self, entry_id: int) -> str | None:
        """生成指定条目的 TOTP 验证码。

        4A 架构迁移：封装 get_entry→解密→TOTPGenerator.generate 流程，
        使 main_window 等调用方不直接接触明文 TOTP secret。

        Returns
        -------
        str | None
            6 位验证码字符串，条目不存在或无 TOTP 密钥时返回 None。
        """
        entry = self.get_entry(entry_id)
        if entry and entry.totp_secret:
            return TOTPGenerator.generate(entry.totp_secret)
        return None

    def get_totp_state(self, entry_id: int) -> dict | None:
        """获取指定条目的 TOTP 完整状态（验证码 + 倒计时 + 周期）。

        4A 架构迁移：供 detail_panel 的 TOTP 显示和刷新定时器使用，
        避免在 UI 层直接调用 crypto 模块。

        Returns
        -------
        dict | None
            ``{'code': str, 'remaining': int, 'period': int}``，
            条目不存在或无 TOTP 密钥时返回 None。
        """
        entry = self.get_entry(entry_id)
        if entry and entry.totp_secret:
            secret = entry.totp_secret
            return {
                'code': TOTPGenerator.generate(secret),
                'remaining': TOTPGenerator.get_remaining_seconds(secret=secret),
                'period': TOTPGenerator.get_period(secret),
            }
        return None

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

        .. note::
            内部实现委托给 ``crypto_utils.matches_search``。UI 层应通过
            此公共方法调用，避免直接依赖 ``crypto_utils`` 模块。
        """
        return matches_search(entry, query)
