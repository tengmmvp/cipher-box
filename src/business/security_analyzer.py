"""安全分析器 - 弱密码检测、重复密码检测、过期提醒"""

import json

from ..crypto.encryption import EncryptionEngine
from ..crypto.password_generator import PasswordGenerator
from ..database.models import Entry, CustomField


class SecurityAnalyzer:
    """密码安全分析"""

    def __init__(self, vault_manager):
        self._vault = vault_manager

    @property
    def _key(self) -> bytes:
        key = self._vault.key
        if key is None:
            raise RuntimeError("保险库未解锁")
        return key

    def _make_decrypted_copy(self, raw: Entry, password: str) -> Entry:
        """创建解密后的 Entry 副本（不修改原始对象）"""
        # 解密 custom_fields
        custom_fields = []
        if raw.custom_fields:
            try:
                cf_json = EncryptionEngine.decrypt(raw.custom_fields, self._key) if isinstance(raw.custom_fields, str) else ''
                if cf_json:
                    items = json.loads(cf_json)
                    custom_fields = [CustomField.from_dict(item) for item in items]
            except (json.JSONDecodeError, ValueError):
                pass

        return Entry(
            id=raw.id,
            title=raw.title,
            username=EncryptionEngine.decrypt(raw.username, self._key) if raw.username else '',
            password=password,
            url=raw.url,
            category_id=raw.category_id,
            category_name=raw.category_name,
            tags=raw.tags,
            notes=EncryptionEngine.decrypt(raw.notes, self._key) if raw.notes else '',
            custom_fields=custom_fields,
            is_favorite=raw.is_favorite,
            is_deleted=raw.is_deleted,
            password_strength=raw.password_strength,
            entry_type=raw.entry_type,
            totp_secret=EncryptionEngine.decrypt(raw.totp_secret, self._key) if raw.totp_secret else '',
            created_at=raw.created_at,
            updated_at=raw.updated_at,
            deleted_at=raw.deleted_at,
            password_changed_at=raw.password_changed_at,
        )

    def find_weak_passwords(self) -> list[Entry]:
        """查找弱密码条目（强度评分 <= 1）"""
        entries = self._vault.db.get_entries(include_deleted=False)
        weak = []
        for raw in entries:
            try:
                password = EncryptionEngine.decrypt(raw.password, self._key) if raw.password else ''
                if password:
                    strength = PasswordGenerator.check_strength(password)
                    if strength.score <= 1:
                        weak.append(self._make_decrypted_copy(raw, password))
            except ValueError:
                continue
        return weak

    def find_duplicate_passwords(self) -> list[list[Entry]]:
        """查找重复密码（返回分组列表，每组包含使用相同密码的条目）"""
        entries = self._vault.db.get_entries(include_deleted=False)
        password_map: dict[str, list[Entry]] = {}

        for raw in entries:
            try:
                password = EncryptionEngine.decrypt(raw.password, self._key) if raw.password else ''
                if password:
                    copy = self._make_decrypted_copy(raw, password)
                    if password not in password_map:
                        password_map[password] = []
                    password_map[password].append(copy)
            except ValueError:
                continue

        return [group for group in password_map.values() if len(group) > 1]

    def find_old_passwords(self, days: int = 90) -> list[Entry]:
        """查找超过指定天数未修改的条目"""
        raw_entries = self._vault.db.get_old_entries(days)
        result = []
        for raw in raw_entries:
            try:
                password = EncryptionEngine.decrypt(raw.password, self._key) if raw.password else ''
                result.append(self._make_decrypted_copy(raw, password))
            except ValueError:
                continue
        return result

    def full_analysis(self, days: int = 90) -> dict:
        """一次性完成所有安全分析，避免重复解密"""
        entries = self._vault.db.get_entries(include_deleted=False)
        total = len(entries)
        weak_entries = []
        password_map: dict[str, list[Entry]] = {}

        for raw in entries:
            try:
                password = EncryptionEngine.decrypt(raw.password, self._key) if raw.password else ''
                if not password:
                    continue

                strength = PasswordGenerator.check_strength(password)
                if strength.score <= 1:
                    weak_entries.append(self._make_decrypted_copy(raw, password))

                copy = self._make_decrypted_copy(raw, password)
                if password not in password_map:
                    password_map[password] = []
                password_map[password].append(copy)
            except ValueError:
                continue

        duplicate_groups = [g for g in password_map.values() if len(g) > 1]
        duplicate_count = sum(len(g) - 1 for g in duplicate_groups)

        # 旧密码单独查（这个查询量小，可以保留 DB 层过滤）
        old_entries = self.find_old_passwords(days)

        return {
            'total': total,
            'weak': len(weak_entries),
            'weak_entries': weak_entries,
            'duplicate_groups': duplicate_groups,
            'duplicate_count': duplicate_count,
            'old_entries': old_entries,
            'old': len(old_entries),
        }
