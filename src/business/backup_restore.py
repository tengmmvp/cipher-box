"""加密备份与恢复。

V3 备份把明文领域数据放入独立加密容器，恢复时再使用当前保险库密钥加密。
因此备份不再绑定创建时的主密钥，并继续兼容读取 V1/V2 文件。
"""

import json
import logging
import os
import struct
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ..crypto.encryption import EncryptionEngine
from ..database.models import Category, Entry

logger = logging.getLogger(__name__)

BACKUP_MAGIC = b'CBOX'
BACKUP_VERSION = 3
BACKUP_SALT_SIZE = 32
BACKUP_KDF_ITERATIONS = 600_000
_FLAG_PASSWORD = 1


class BackupRestoreManager:
    """创建可移植的加密备份并以事务方式恢复。"""

    def __init__(self, vault_manager):
        self._vault = vault_manager

    @property
    def _key(self) -> bytes:
        key = self._vault.key
        if key is None:
            raise RuntimeError("保险库未解锁")
        return key

    @staticmethod
    def _derive_backup_key(password: str, salt: bytes, iterations: int) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        return kdf.derive(password.encode('utf-8'))

    @staticmethod
    def _decrypt_text(value: str, key: bytes, label: str) -> str:
        if not value:
            return ''
        try:
            return EncryptionEngine.decrypt(value, key)
        except ValueError as exc:
            raise RuntimeError(f"{label}解密失败，保险库数据可能已损坏") from exc

    def _collect_portable_data(self) -> dict:
        db = self._vault.db
        key = self._key
        categories = [category.to_dict() for category in db.get_categories()]
        entries = []
        for raw in db.get_entries(include_deleted=True):
            custom_json = self._decrypt_text(raw.custom_fields, key, f"条目 {raw.id} 自定义字段")
            try:
                custom_fields = json.loads(custom_json) if custom_json else []
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"条目 {raw.id} 自定义字段格式损坏") from exc
            entries.append({
                'id': raw.id,
                'title': raw.title,
                'username': self._decrypt_text(raw.username, key, f"条目 {raw.id} 账号"),
                'password': self._decrypt_text(raw.password, key, f"条目 {raw.id} 密码"),
                'url': raw.url,
                'category_id': raw.category_id,
                'tags': raw.tags,
                'notes': self._decrypt_text(raw.notes, key, f"条目 {raw.id} 备注"),
                'custom_fields': custom_fields,
                'is_favorite': raw.is_favorite,
                'is_deleted': raw.is_deleted,
                'password_strength': raw.password_strength,
                'entry_type': raw.entry_type,
                'totp_secret': self._decrypt_text(raw.totp_secret, key, f"条目 {raw.id} TOTP"),
                'created_at': raw.created_at,
                'updated_at': raw.updated_at,
                'deleted_at': raw.deleted_at,
                'password_changed_at': raw.password_changed_at,
            })

        history = []
        for item in db.get_all_password_history():
            history.append({
                'entry_id': item.entry_id,
                'password': self._decrypt_text(
                    item.old_password_enc, key, f"密码历史 {item.id}"
                ),
                'changed_at': item.changed_at,
            })

        return {
            'format': 'CipherBox portable backup',
            'version': BACKUP_VERSION,
            'created_at': datetime.now().isoformat(),
            'categories': categories,
            'entries': entries,
            'password_history': history,
        }

    def create_backup(
        self,
        filepath: str,
        backup_password: str | None = None,
    ) -> tuple[bool, str]:
        """创建 V3 备份。

        传入备份密码时文件可跨主密码、跨安装恢复。未传入时为兼容旧调用，
        容器使用当前保险库密钥，只适合同一主密钥下恢复。
        """
        try:
            data = self._collect_portable_data()
            salt = os.urandom(BACKUP_SALT_SIZE)
            if backup_password:
                flags = _FLAG_PASSWORD
                iterations = BACKUP_KDF_ITERATIONS
                backup_key = self._derive_backup_key(backup_password, salt, iterations)
            else:
                flags = 0
                iterations = 0
                backup_key = self._key

            payload = json.dumps(data, ensure_ascii=False).encode('utf-8')
            encrypted = EncryptionEngine.encrypt_bytes(payload, backup_key)
            target = Path(filepath)
            target.parent.mkdir(parents=True, exist_ok=True)
            temp_path = target.with_name(target.name + '.tmp')
            with open(temp_path, 'wb') as file:
                file.write(BACKUP_MAGIC)
                file.write(struct.pack('<I', BACKUP_VERSION))
                file.write(struct.pack('<B', flags))
                file.write(salt)
                file.write(struct.pack('<I', iterations))
                file.write(encrypted)
                file.flush()
                os.fsync(file.fileno())
            os.replace(temp_path, target)
            return True, ''
        except Exception as exc:
            logger.error("备份失败", exc_info=True)
            return False, str(exc)

    @staticmethod
    def inspect_backup(filepath: str) -> dict:
        """读取备份头，不解密内容。"""
        with open(filepath, 'rb') as file:
            if file.read(4) != BACKUP_MAGIC:
                raise ValueError('无效的备份文件格式')
            raw_version = file.read(4)
            if len(raw_version) != 4:
                raise ValueError('备份文件已损坏')
            version = struct.unpack('<I', raw_version)[0]
            password_required = False
            if version == BACKUP_VERSION:
                flags = file.read(1)
                if len(flags) != 1:
                    raise ValueError('备份文件头已损坏')
                password_required = bool(struct.unpack('<B', flags)[0] & _FLAG_PASSWORD)
            return {'version': version, 'password_required': password_required}

    def restore_backup(
        self,
        filepath: str,
        backup_password: str | None = None,
    ) -> tuple[bool, str]:
        """恢复备份；任何步骤失败都会回滚当前数据库。"""
        try:
            with open(filepath, 'rb') as file:
                if file.read(4) != BACKUP_MAGIC:
                    return False, '无效的备份文件格式'
                version_bytes = file.read(4)
                if len(version_bytes) != 4:
                    return False, '备份文件已损坏'
                version = struct.unpack('<I', version_bytes)[0]
                if version == BACKUP_VERSION:
                    return self._restore_v3(file, backup_password)
                if version in (1, 2):
                    return self._restore_legacy(file, version)
                return False, f'不支持的备份版本：{version}'
        except Exception as exc:
            logger.error("恢复失败", exc_info=True)
            return False, str(exc)

    def _restore_v3(self, file, backup_password: str | None) -> tuple[bool, str]:
        flags_raw = file.read(1)
        salt = file.read(BACKUP_SALT_SIZE)
        iterations_raw = file.read(4)
        if len(flags_raw) != 1 or len(salt) != BACKUP_SALT_SIZE or len(iterations_raw) != 4:
            return False, '备份文件头已损坏'
        flags = struct.unpack('<B', flags_raw)[0]
        iterations = struct.unpack('<I', iterations_raw)[0]
        if flags & _FLAG_PASSWORD:
            if not backup_password:
                return False, '请输入创建备份时设置的备份密码'
            backup_key = self._derive_backup_key(backup_password, salt, iterations)
        else:
            backup_key = self._key

        try:
            plaintext = EncryptionEngine.decrypt_bytes(file.read(), backup_key)
            data = json.loads(plaintext.decode('utf-8'))
        except Exception:
            return False, '备份密码错误或文件已损坏'
        if not isinstance(data, dict) or not isinstance(data.get('entries'), list):
            return False, '备份数据结构无效'
        self._restore_data(data, portable=True)
        return True, ''

    def _restore_legacy(self, file, version: int) -> tuple[bool, str]:
        try:
            plaintext = EncryptionEngine.decrypt_bytes(file.read(), self._key)
            data = json.loads(plaintext.decode('utf-8'))
        except Exception:
            return False, '旧版备份与当前主密码不匹配或文件已损坏'
        self._restore_data(data, portable=False, legacy_version=version)
        return True, ''

    def _restore_data(
        self,
        data: dict,
        portable: bool,
        legacy_version: int = 0,
    ):
        db = self._vault.db
        key = self._key
        db.begin_transaction()
        try:
            connection = db._conn
            if connection is None:
                raise RuntimeError("数据库未连接")
            connection.execute("DELETE FROM password_history")
            connection.execute("DELETE FROM entries")
            connection.execute("DELETE FROM categories")

            category_map = {}
            for item in data.get('categories', []):
                category = Category(
                    name=item.get('name', '').strip(),
                    icon_char=item.get('icon_char', '📁'),
                    color=item.get('color', '#666666'),
                    sort_order=item.get('sort_order', 0),
                    created_at=item.get('created_at', ''),
                )
                if not category.name:
                    continue
                new_id = db.add_category(category)
                if item.get('id') is not None:
                    category_map[item['id']] = new_id

            entry_map = {}
            for item in data.get('entries', []):
                old_category = item.get('category_id')
                if portable:
                    custom_fields = item.get('custom_fields', [])
                    custom_json = json.dumps(custom_fields, ensure_ascii=False) if custom_fields else ''
                    username = EncryptionEngine.encrypt(item.get('username', ''), key)
                    password = EncryptionEngine.encrypt(item.get('password', ''), key)
                    notes = EncryptionEngine.encrypt(item.get('notes', ''), key)
                    custom = EncryptionEngine.encrypt(custom_json, key)
                    totp = EncryptionEngine.encrypt(item.get('totp_secret', ''), key)
                else:
                    username = item.get('username_enc', '')
                    password = item.get('password_enc', '')
                    notes = item.get('notes_enc', '')
                    custom = item.get('custom_fields_enc', '')
                    totp = item.get('totp_secret_enc', '')
                entry = Entry(
                    title=item.get('title', ''),
                    username=username,
                    password=password,
                    url=item.get('url', ''),
                    category_id=category_map.get(old_category),
                    tags=item.get('tags', ''),
                    notes=notes,
                    custom_fields=custom,
                    is_favorite=bool(item.get('is_favorite', False)),
                    is_deleted=bool(item.get('is_deleted', False)),
                    password_strength=int(item.get('password_strength', 0)),
                    entry_type=item.get('entry_type', 'login'),
                    totp_secret=totp,
                    created_at=item.get('created_at', ''),
                    updated_at=item.get('updated_at', ''),
                    deleted_at=item.get('deleted_at', '') or '',
                    password_changed_at=item.get('password_changed_at', ''),
                )
                new_id = db.add_entry(entry, preserve_metadata=True)
                if item.get('id') is not None:
                    entry_map[item['id']] = new_id

            if portable or legacy_version >= 2:
                for item in data.get('password_history', []):
                    new_entry_id = entry_map.get(item.get('entry_id'))
                    if not new_entry_id:
                        continue
                    if portable:
                        ciphertext = EncryptionEngine.encrypt(item.get('password', ''), key)
                    else:
                        ciphertext = item.get('old_password_enc', '')
                    if ciphertext:
                        db.add_password_history(
                            new_entry_id,
                            ciphertext,
                            item.get('changed_at', ''),
                        )
            db.commit_transaction()
        except Exception:
            db.rollback_transaction()
            raise
