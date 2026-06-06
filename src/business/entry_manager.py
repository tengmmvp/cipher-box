"""条目管理器 - 密码条目的加密 CRUD 操作"""

import json
import logging
import uuid
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

from ..crypto.encryption import EncryptionEngine
from ..crypto.password_generator import PasswordGenerator
from ..database.models import Category, CustomField, Entry, PasswordHistory


class EntryManager:
    """管理密码条目的加密、解密和 CRUD 操作"""

    def __init__(self, vault_manager):
        self._vault = vault_manager

    @property
    def db(self):
        return self._vault.db

    @property
    def _key(self) -> bytes:
        key = self._vault.key
        if key is None:
            raise RuntimeError("保险库未解锁")
        return key

    @staticmethod
    def _aad(crypto_id: str, field_name: str) -> str:
        return f'entry:{crypto_id}:{field_name}'

    def _encrypt_field(self, plaintext: str, crypto_id: str, field_name: str) -> str:
        """加密单个字段"""
        if not plaintext:
            return ''
        return EncryptionEngine.encrypt(
            plaintext, self._key, self._aad(crypto_id, field_name)
        )

    def _decrypt_field(
        self,
        encrypted: str,
        crypto_id: str,
        field_name: str,
        strict: bool = False,
    ) -> str:
        """解密单个字段"""
        if not encrypted:
            return ''
        try:
            return EncryptionEngine.decrypt(
                encrypted, self._key, self._aad(crypto_id, field_name)
            )
        except ValueError:
            logger.warning("敏感字段解密失败", exc_info=True)
            if strict:
                raise
            return ''

    def _encrypt_custom_fields(self, fields: list[CustomField], crypto_id: str) -> str:
        """加密自定义字段列表"""
        if not fields:
            return ''
        data = json.dumps([f.to_dict() for f in fields], ensure_ascii=False)
        return self._encrypt_field(data, crypto_id, 'custom_fields')

    def _decrypt_custom_fields(self, encrypted: str, crypto_id: str) -> list[CustomField]:
        """解密自定义字段列表"""
        if not encrypted:
            return []
        try:
            data = self._decrypt_field(
                encrypted, crypto_id, 'custom_fields', strict=True
            )
            items = json.loads(data)
            return [CustomField.from_dict(item) for item in items]
        except json.JSONDecodeError:
            return []

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
                raw_entry.custom_fields if isinstance(raw_entry.custom_fields, str) else '',
                raw_entry.crypto_id,
            )
        except ValueError:
            integrity_errors.append('自定义字段')
            custom_fields = []

        return Entry(
            id=raw_entry.id,
            crypto_id=raw_entry.crypto_id,
            title=raw_entry.title,
            username=decrypt('username', raw_entry.username),
            password=decrypt('password', raw_entry.password),
            url=raw_entry.url,
            category_id=raw_entry.category_id,
            category_name=raw_entry.category_name,
            tags=raw_entry.tags,
            notes=decrypt('notes', raw_entry.notes),
            custom_fields=custom_fields,
            is_favorite=raw_entry.is_favorite,
            is_deleted=raw_entry.is_deleted,
            password_strength=raw_entry.password_strength,
            entry_type=raw_entry.entry_type,
            totp_secret=decrypt('totp_secret', raw_entry.totp_secret),
            created_at=raw_entry.created_at,
            updated_at=raw_entry.updated_at,
            deleted_at=raw_entry.deleted_at,
            password_changed_at=raw_entry.password_changed_at,
            integrity_error=bool(integrity_errors),
            integrity_message='、'.join(integrity_errors),
            password_present=bool(raw_entry.password),
            totp_present=bool(raw_entry.totp_secret),
        )

    def _decrypt_summary(self, raw_entry: Entry) -> Entry:
        """仅解密列表展示所需字段，不让密码等明文进入列表模型。"""
        integrity_error = False
        try:
            username = self._decrypt_field(
                raw_entry.username, raw_entry.crypto_id, 'username', strict=True
            )
        except ValueError:
            username = ''
            integrity_error = True
        return Entry(
            id=raw_entry.id,
            crypto_id=raw_entry.crypto_id,
            title=raw_entry.title,
            username=username,
            url=raw_entry.url,
            category_id=raw_entry.category_id,
            category_name=raw_entry.category_name,
            tags=raw_entry.tags,
            is_favorite=raw_entry.is_favorite,
            is_deleted=raw_entry.is_deleted,
            password_strength=raw_entry.password_strength,
            entry_type=raw_entry.entry_type,
            created_at=raw_entry.created_at,
            updated_at=raw_entry.updated_at,
            deleted_at=raw_entry.deleted_at,
            password_changed_at=raw_entry.password_changed_at,
            integrity_error=integrity_error,
            integrity_message='账号' if integrity_error else '',
            password_present=bool(raw_entry.password),
            totp_present=bool(raw_entry.totp_secret),
        )

    def add_entry(self, entry: Entry) -> int:
        """添加新条目（自动加密并检测强度）"""
        strength = PasswordGenerator.check_strength(entry.password)
        entry.password_strength = strength.score
        crypto_id = entry.crypto_id or uuid.uuid4().hex

        now = datetime.now().isoformat()
        enc_entry = Entry(
            crypto_id=crypto_id,
            title=entry.title,
            username=self._encrypt_field(entry.username, crypto_id, 'username'),
            password=self._encrypt_field(entry.password, crypto_id, 'password'),
            url=entry.url,
            category_id=entry.category_id,
            tags=entry.tags,
            notes=self._encrypt_field(entry.notes, crypto_id, 'notes'),
            custom_fields=self._encrypt_custom_fields(entry.custom_fields, crypto_id),
            is_favorite=entry.is_favorite,
            password_strength=entry.password_strength,
            entry_type=entry.entry_type,
            totp_secret=self._encrypt_field(entry.totp_secret, crypto_id, 'totp_secret'),
            created_at=entry.created_at or now,
            updated_at=entry.updated_at or now,
            password_changed_at=entry.password_changed_at or now,
        )
        return self._vault.db.add_entry(
            enc_entry,
            preserve_metadata=bool(entry.created_at or entry.updated_at),
        )

    def update_entry(self, entry: Entry):
        """更新条目（自动加密、记录密码历史）"""
        if entry.integrity_error:
            raise RuntimeError(
                f"条目存在无法解密的字段（{entry.integrity_message}），为避免数据丢失已禁止保存"
            )
        raw = self.db.get_entry(entry.id)
        if raw is None:
            return

        # 检测密码变更，归档旧密码
        old_pwd_enc = raw.password
        old_password = self._decrypt_field(
            old_pwd_enc, raw.crypto_id, 'password', strict=True
        ) if old_pwd_enc else ''
        new_pwd_enc = self._encrypt_field(entry.password, raw.crypto_id, 'password')
        password_changed_at = (
            datetime.now().isoformat()
            if old_password != entry.password
            else raw.password_changed_at
        )

        strength = PasswordGenerator.check_strength(entry.password)
        entry.password_strength = strength.score

        enc_entry = Entry(
            id=entry.id,
            crypto_id=raw.crypto_id,
            title=entry.title,
            username=self._encrypt_field(entry.username, raw.crypto_id, 'username'),
            password=new_pwd_enc,
            url=entry.url,
            category_id=entry.category_id,
            tags=entry.tags,
            notes=self._encrypt_field(entry.notes, raw.crypto_id, 'notes'),
            custom_fields=self._encrypt_custom_fields(entry.custom_fields, raw.crypto_id),
            is_favorite=entry.is_favorite,
            password_strength=entry.password_strength,
            entry_type=entry.entry_type,
            totp_secret=self._encrypt_field(entry.totp_secret, raw.crypto_id, 'totp_secret'),
            created_at=raw.created_at,
            password_changed_at=password_changed_at,
        )
        with self.db.transaction():
            if old_pwd_enc and old_password != entry.password:
                self.db.add_password_history(entry.id, old_pwd_enc)
            self.db.update_entry(enc_entry)

    def delete_entry(self, entry_id: int):
        """软删除条目（移入回收站）"""
        self._vault.db.soft_delete_entry(entry_id)

    def restore_entry(self, entry_id: int):
        """恢复条目"""
        self._vault.db.restore_entry(entry_id)

    def permanent_delete_entry(self, entry_id: int):
        """永久删除条目"""
        self._vault.db.permanent_delete_entry(entry_id)

    def empty_trash(self):
        """清空回收站"""
        self._vault.db.empty_trash()

    def get_entries(
        self,
        deleted_only: bool = False,
        include_deleted: bool = False,
        category_id: Optional[int] = None,
        favorite_only: bool = False,
        search: str = '',
    ) -> list[Entry]:
        """获取并解密条目列表"""
        # 搜索时不做 DB 层文本过滤（因为 username 是加密的），
        # 改为全量取回后统一在内存中做 OR 模糊匹配
        raw_entries = self._vault.db.get_entries(
            deleted_only=deleted_only,
            include_deleted=include_deleted,
            category_id=category_id,
            favorite_only=favorite_only,
            search='' if search else '',  # 不传 search 给 DB
        )
        decrypted = [self.decrypt_entry(e) for e in raw_entries]

        # 检查解密失败的条目并记录警告
        for raw_entry, dec_entry in zip(raw_entries, decrypted):
            if raw_entry.password and not dec_entry.password:
                logger.warning("条目 %d (%s) 密码解密失败", raw_entry.id, raw_entry.title)

        # 内存中 OR 过滤：title / url / tags / username 任一匹配即保留
        if search:
            search_lower = search.lower()
            decrypted = [
                e for e in decrypted
                if (search_lower in e.title.lower()
                    or search_lower in e.url.lower()
                    or search_lower in e.tags.lower()
                    or search_lower in e.username.lower())
            ]

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
    ) -> list[Entry]:
        """获取不含密码等敏感明文的列表摘要。"""
        raw_entries = self.db.get_entries(
            deleted_only=deleted_only,
            category_id=category_id,
            favorite_only=favorite_only,
        )
        summaries = [self._decrypt_summary(entry) for entry in raw_entries]
        if search:
            keyword = search.lower()
            summaries = [
                entry for entry in summaries
                if keyword in entry.title.lower()
                or keyword in entry.username.lower()
                or keyword in entry.url.lower()
                or keyword in entry.tags.lower()
            ]
        return summaries

    def get_categories(self) -> list[Category]:
        """获取所有分类"""
        return self._vault.db.get_categories()

    def toggle_favorite(self, entry_id: int):
        """切换收藏状态"""
        raw = self._vault.db.get_entry(entry_id)
        if raw:
            raw.is_favorite = not raw.is_favorite
            self._vault.db.update_entry(raw)

    def get_entry_count(self, include_deleted: bool = False) -> int:
        """获取条目数量"""
        return self._vault.db.get_entry_count(include_deleted)

    def get_password_history(self, entry_id: int) -> list[PasswordHistory]:
        """获取密码历史（返回加密记录）"""
        return self._vault.db.get_password_history(entry_id)

    def decrypt_password_history(self, history: list[PasswordHistory]) -> list[dict]:
        """解密密码历史，返回 [{changed_at, password}]"""
        result = []
        for h in history:
            pwd = self._decrypt_field(
                h.old_password_enc, h.entry_crypto_id, 'password'
            )
            if pwd:
                result.append({
                    'changed_at': h.changed_at[:19].replace('T', ' ') if h.changed_at else '',
                    'password': pwd,
                })
        return result

    def get_all_tags(self) -> list[tuple[str, int]]:
        """获取所有标签及其使用频率"""
        entries = self._vault.db.get_entries(include_deleted=False)
        tag_count: dict[str, int] = {}
        for e in entries:
            for tag in e.get_tag_list():
                tag_count[tag] = tag_count.get(tag, 0) + 1
        return sorted(tag_count.items(), key=lambda x: -x[1])
