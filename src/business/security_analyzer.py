"""安全分析器 - 弱密码检测、重复密码检测、过期提醒"""

import hmac

from ..crypto.encryption import EncryptionEngine
from ..crypto.password_generator import PasswordGenerator
from ..database.models import Entry


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

    def _decrypt(self, raw: Entry, field_name: str, value: str) -> str:
        if not value:
            return ''
        return EncryptionEngine.decrypt(
            value, self._key, f'entry:{raw.crypto_id}:{field_name}'
        )

    def _make_summary(self, raw: Entry) -> Entry:
        """只返回分析界面所需字段，避免缓存敏感明文。"""
        return Entry(
            id=raw.id,
            crypto_id=raw.crypto_id,
            title=raw.title,
            username=self._decrypt(raw, 'username', raw.username),
            url=raw.url,
            category_id=raw.category_id,
            category_name=raw.category_name,
            tags=raw.tags,
            is_favorite=raw.is_favorite,
            is_deleted=raw.is_deleted,
            password_strength=raw.password_strength,
            entry_type=raw.entry_type,
            created_at=raw.created_at,
            updated_at=raw.updated_at,
            deleted_at=raw.deleted_at,
            password_changed_at=raw.password_changed_at,
            password_present=bool(raw.password),
            totp_present=bool(raw.totp_secret),
        )

    def _password_fingerprint(self, password: str) -> bytes:
        return hmac.digest(self._key, password.encode('utf-8'), 'sha256')

    def find_weak_passwords(self) -> list[Entry]:
        """查找弱密码条目（强度评分 <= 1）"""
        entries = self._vault.db.get_entries(include_deleted=False)
        weak = []
        for raw in entries:
            try:
                password = self._decrypt(raw, 'password', raw.password)
                if password:
                    strength = PasswordGenerator.check_strength(password)
                    if strength.score <= 1:
                        weak.append(self._make_summary(raw))
            except ValueError:
                continue
        return weak

    def find_duplicate_passwords(self) -> list[list[Entry]]:
        """查找重复密码（返回分组列表，每组包含使用相同密码的条目）"""
        entries = self._vault.db.get_entries(include_deleted=False)
        password_map: dict[bytes, list[Entry]] = {}

        for raw in entries:
            try:
                password = self._decrypt(raw, 'password', raw.password)
                if password:
                    fingerprint = self._password_fingerprint(password)
                    password_map.setdefault(fingerprint, []).append(
                        self._make_summary(raw)
                    )
            except ValueError:
                continue

        return [group for group in password_map.values() if len(group) > 1]

    def find_old_passwords(self, days: int = 90) -> list[Entry]:
        """查找超过指定天数未修改的条目"""
        raw_entries = self._vault.db.get_old_entries(days)
        result = []
        for raw in raw_entries:
            try:
                result.append(self._make_summary(raw))
            except ValueError:
                continue
        return result

    def full_analysis(self, days: int = 90) -> dict:
        """一次性完成所有安全分析，避免重复解密"""
        entries = self._vault.db.get_entries(include_deleted=False)
        total = len(entries)
        weak_entries = []
        password_map: dict[bytes, list[Entry]] = {}

        for raw in entries:
            try:
                password = self._decrypt(raw, 'password', raw.password)
                if not password:
                    continue

                strength = PasswordGenerator.check_strength(password)
                summary = self._make_summary(raw)
                if strength.score <= 1:
                    weak_entries.append(summary)

                fingerprint = self._password_fingerprint(password)
                password_map.setdefault(fingerprint, []).append(summary)
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
