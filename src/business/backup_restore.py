"""CipherBox 固定格式的加密备份与恢复。"""

import json
import logging
import os
import struct
import uuid
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ..crypto.encryption import EncryptionEngine
from ..database.models import ENTRY_TYPES, Category, Entry
from ..utils.file_security import secure_directory, secure_file

logger = logging.getLogger(__name__)

BACKUP_MAGIC = b'CipherBoxBackup\x00'
BACKUP_FORMAT = 'CipherBoxBackup'
BACKUP_AAD = b'CipherBox:backup'
BACKUP_SALT_SIZE = 32
BACKUP_KDF_ITERATIONS = 600_000
BACKUP_MIN_KDF_ITERATIONS = 100_000
BACKUP_MAX_KDF_ITERATIONS = 2_000_000
MAX_BACKUP_FILE_SIZE = 64 * 1024 * 1024
MAX_BACKUP_PAYLOAD_SIZE = 32 * 1024 * 1024
MAX_BACKUP_ENTRIES = 50_000
MAX_RESTORE_POINTS = 10
MAX_ENTRY_JSON_SIZE = 2 * 1024 * 1024
MAX_TEXT_FIELD_SIZE = 1024 * 1024
_FLAG_PASSWORD = 1
_FLAG_SNAPSHOT = 2


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
        if not BACKUP_MIN_KDF_ITERATIONS <= iterations <= BACKUP_MAX_KDF_ITERATIONS:
            raise ValueError('备份 KDF 参数无效')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        return kdf.derive(password.encode('utf-8'))

    @staticmethod
    def _decrypt_text(value: str, key: bytes, label: str, aad: str) -> str:
        if not value:
            return ''
        try:
            return EncryptionEngine.decrypt(value, key, aad)
        except ValueError as exc:
            raise RuntimeError(f"{label}解密失败，保险库数据可能已损坏") from exc

    def _collect_portable_data(self) -> dict:
        db = self._vault.db
        key = self._key
        categories = [category.to_dict() for category in db.get_categories()]
        entries = []
        raw_entries = db.get_entries(include_deleted=True)
        if len(raw_entries) > MAX_BACKUP_ENTRIES:
            raise ValueError('备份条目数量超出限制')
        estimated_size = len(json.dumps(categories, ensure_ascii=False).encode('utf-8'))
        for raw in raw_entries:
            aad = lambda field: f'entry:{raw.crypto_id}:{field}'
            custom_json = self._decrypt_text(
                raw.custom_fields, key, f"条目 {raw.id} 自定义字段", aad('custom_fields')
            )
            try:
                custom_fields = json.loads(custom_json) if custom_json else []
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"条目 {raw.id} 自定义字段格式损坏") from exc
            item = {
                'id': raw.id,
                'crypto_id': raw.crypto_id,
                'title': raw.title,
                'username': self._decrypt_text(raw.username, key, f"条目 {raw.id} 账号", aad('username')),
                'password': self._decrypt_text(raw.password, key, f"条目 {raw.id} 密码", aad('password')),
                'url': raw.url,
                'category_id': raw.category_id,
                'tags': raw.tags,
                'notes': self._decrypt_text(raw.notes, key, f"条目 {raw.id} 备注", aad('notes')),
                'custom_fields': custom_fields,
                'is_favorite': raw.is_favorite,
                'is_deleted': raw.is_deleted,
                'password_strength': raw.password_strength,
                'entry_type': raw.entry_type,
                'totp_secret': self._decrypt_text(raw.totp_secret, key, f"条目 {raw.id} TOTP", aad('totp_secret')),
                'created_at': raw.created_at,
                'updated_at': raw.updated_at,
                'deleted_at': raw.deleted_at,
                'password_changed_at': raw.password_changed_at,
            }
            estimated_size += len(json.dumps(item, ensure_ascii=False).encode('utf-8'))
            if estimated_size > MAX_BACKUP_PAYLOAD_SIZE:
                raise ValueError('备份数据过大')
            entries.append(item)

        history = []
        history_rows = db.get_all_password_history()
        if len(history_rows) > MAX_BACKUP_ENTRIES * 10:
            raise ValueError('密码历史数量超出限制')
        for item in history_rows:
            history_item = {
                'entry_id': item.entry_id,
                'password': self._decrypt_text(
                    item.old_password_enc,
                    key,
                    f"密码历史 {item.id}",
                    f'entry:{item.entry_crypto_id}:password',
                ),
                'changed_at': item.changed_at,
            }
            estimated_size += len(
                json.dumps(history_item, ensure_ascii=False).encode('utf-8')
            )
            if estimated_size > MAX_BACKUP_PAYLOAD_SIZE:
                raise ValueError('备份数据过大')
            history.append(history_item)

        return {
            'format': BACKUP_FORMAT,
            'created_at': datetime.now().isoformat(),
            'categories': categories,
            'entries': entries,
            'password_history': history,
        }

    def create_backup(
        self,
        filepath: str,
        backup_password: str | None = None,
        use_snapshot_key: bool = False,
    ) -> tuple[bool, str]:
        """创建加密备份；密码备份可跨安装恢复，快照使用稳定快照密钥。"""
        try:
            data = self._collect_portable_data()
            salt = os.urandom(BACKUP_SALT_SIZE)
            if backup_password:
                flags = _FLAG_PASSWORD
                iterations = BACKUP_KDF_ITERATIONS
                backup_key = self._derive_backup_key(backup_password, salt, iterations)
            elif use_snapshot_key:
                flags = _FLAG_SNAPSHOT
                iterations = 0
                backup_key = self._vault.snapshot_key
            else:
                flags = 0
                iterations = 0
                backup_key = self._key

            payload = json.dumps(data, ensure_ascii=False).encode('utf-8')
            if len(payload) > MAX_BACKUP_PAYLOAD_SIZE:
                raise ValueError('备份数据过大')
            encrypted = EncryptionEngine.encrypt_bytes(
                payload, backup_key, BACKUP_AAD
            )
            target = Path(filepath)
            target.parent.mkdir(parents=True, exist_ok=True)
            temp_path = target.with_name(target.name + '.tmp')
            with open(temp_path, 'wb') as file:
                file.write(BACKUP_MAGIC)
                file.write(struct.pack('<B', flags))
                file.write(salt)
                file.write(struct.pack('<I', iterations))
                file.write(encrypted)
                file.flush()
                os.fsync(file.fileno())
            secure_file(temp_path)
            os.replace(temp_path, target)
            secure_file(target)
            return True, ''
        except Exception as exc:
            logger.error("备份失败", exc_info=True)
            return False, str(exc)

    @staticmethod
    def inspect_backup(filepath: str) -> dict:
        """读取备份头，不解密内容。"""
        if Path(filepath).stat().st_size > MAX_BACKUP_FILE_SIZE:
            raise ValueError('备份文件过大')
        with open(filepath, 'rb') as file:
            if file.read(len(BACKUP_MAGIC)) != BACKUP_MAGIC:
                raise ValueError('无效的备份文件格式')
            flags = file.read(1)
            if len(flags) != 1:
                raise ValueError('备份文件头已损坏')
            flag_value = struct.unpack('<B', flags)[0]
            if flag_value & ~(_FLAG_PASSWORD | _FLAG_SNAPSHOT):
                raise ValueError('备份文件包含未知标志')
            if flag_value == (_FLAG_PASSWORD | _FLAG_SNAPSHOT):
                raise ValueError('备份文件标志冲突')
            return {
                'format': BACKUP_FORMAT,
                'password_required': bool(flag_value & _FLAG_PASSWORD),
                'snapshot_required': bool(flag_value & _FLAG_SNAPSHOT),
            }

    def restore_backup(
        self,
        filepath: str,
        backup_password: str | None = None,
    ) -> tuple[bool, str]:
        """恢复备份；任何步骤失败都会回滚当前数据库。"""
        try:
            if Path(filepath).stat().st_size > MAX_BACKUP_FILE_SIZE:
                return False, '备份文件过大'
            with open(filepath, 'rb') as file:
                if file.read(len(BACKUP_MAGIC)) != BACKUP_MAGIC:
                    return False, '无效的备份文件格式'
                return self._restore_current(file, backup_password)
        except Exception as exc:
            logger.error("恢复失败", exc_info=True)
            return False, str(exc)

    def _restore_current(self, file, backup_password: str | None) -> tuple[bool, str]:
        flags_raw = file.read(1)
        salt = file.read(BACKUP_SALT_SIZE)
        iterations_raw = file.read(4)
        if len(flags_raw) != 1 or len(salt) != BACKUP_SALT_SIZE or len(iterations_raw) != 4:
            return False, '备份文件头已损坏'
        flags = struct.unpack('<B', flags_raw)[0]
        if flags & ~(_FLAG_PASSWORD | _FLAG_SNAPSHOT):
            return False, '备份文件包含未知标志'
        if flags == (_FLAG_PASSWORD | _FLAG_SNAPSHOT):
            return False, '备份文件标志冲突'
        iterations = struct.unpack('<I', iterations_raw)[0]
        if flags & _FLAG_PASSWORD:
            if not backup_password:
                return False, '请输入创建备份时设置的备份密码'
            backup_key = self._derive_backup_key(backup_password, salt, iterations)
        elif flags & _FLAG_SNAPSHOT:
            backup_key = self._vault.snapshot_key
        else:
            backup_key = self._key

        try:
            encrypted = file.read(MAX_BACKUP_FILE_SIZE + 1)
            if len(encrypted) > MAX_BACKUP_FILE_SIZE:
                return False, '备份文件过大'
            plaintext = EncryptionEngine.decrypt_bytes(
                encrypted, backup_key, BACKUP_AAD
            )
            if len(plaintext) > MAX_BACKUP_PAYLOAD_SIZE:
                return False, '备份解密数据过大'
            data = json.loads(plaintext.decode('utf-8'))
        except Exception:
            return False, '备份密码错误或文件已损坏'
        if not isinstance(data, dict) or not isinstance(data.get('entries'), list):
            return False, '备份数据结构无效'
        self._validate_restore_data(data)
        self._create_restore_point()
        self._restore_data(data)
        return True, ''

    @staticmethod
    def _validate_restore_data(data: dict):
        if data.get('format') != BACKUP_FORMAT:
            raise ValueError('备份格式标识无效')
        entries = data.get('entries', [])
        categories = data.get('categories', [])
        history = data.get('password_history', [])
        if not all(isinstance(items, list) for items in (entries, categories, history)):
            raise ValueError('备份数据结构无效')
        if len(entries) > MAX_BACKUP_ENTRIES or len(history) > MAX_BACKUP_ENTRIES * 10:
            raise ValueError('备份条目数量超出限制')
        if len(categories) > 10_000:
            raise ValueError('备份分类数量超出限制')

        category_ids: set[int] = set()
        for item in categories:
            if not isinstance(item, dict):
                raise ValueError('备份分类格式无效')
            BackupRestoreManager._require_keys(
                item,
                {'id', 'name', 'icon_char', 'color', 'sort_order', 'created_at'},
                '备份分类',
            )
            category_id = item['id']
            if not isinstance(category_id, int) or isinstance(category_id, bool):
                raise ValueError('备份分类 ID 无效')
            if category_id in category_ids:
                raise ValueError('备份分类 ID 重复')
            category_ids.add(category_id)
            BackupRestoreManager._require_text(item['name'], '分类名称', 256, allow_empty=False)
            BackupRestoreManager._require_text(item['icon_char'], '分类图标', 32)
            BackupRestoreManager._require_text(item['color'], '分类颜色', 32)
            BackupRestoreManager._require_text(item['created_at'], '分类创建时间', 64)
            if not isinstance(item['sort_order'], int) or isinstance(item['sort_order'], bool):
                raise ValueError('分类排序值无效')

        entry_ids: set[int] = set()
        crypto_ids: set[str] = set()
        required_entry_keys = {
            'id', 'crypto_id', 'title', 'username', 'password', 'url',
            'category_id', 'tags', 'notes', 'custom_fields', 'is_favorite',
            'is_deleted', 'password_strength', 'entry_type', 'totp_secret',
            'created_at', 'updated_at', 'deleted_at', 'password_changed_at',
        }
        for item in entries:
            if not isinstance(item, dict):
                raise ValueError('备份条目格式无效')
            if len(json.dumps(item, ensure_ascii=False).encode('utf-8')) > MAX_ENTRY_JSON_SIZE:
                raise ValueError('备份条目格式或大小无效')
            BackupRestoreManager._require_keys(item, required_entry_keys, '备份条目')
            entry_id = item['id']
            if not isinstance(entry_id, int) or isinstance(entry_id, bool) or entry_id <= 0:
                raise ValueError('备份条目 ID 无效')
            if entry_id in entry_ids:
                raise ValueError('备份条目 ID 重复')
            entry_ids.add(entry_id)
            crypto_id = item['crypto_id']
            if (
                not isinstance(crypto_id, str)
                or len(crypto_id) != 32
                or any(char not in '0123456789abcdef' for char in crypto_id)
            ):
                raise ValueError('备份条目加密标识无效')
            if crypto_id in crypto_ids:
                raise ValueError('备份条目加密标识重复')
            crypto_ids.add(crypto_id)

            for field in (
                'title', 'username', 'password', 'url', 'tags', 'notes',
                'totp_secret', 'created_at', 'updated_at', 'deleted_at',
                'password_changed_at',
            ):
                limit = 64 if field.endswith('_at') else MAX_TEXT_FIELD_SIZE
                BackupRestoreManager._require_text(item[field], f'条目字段 {field}', limit)
            category_id = item['category_id']
            if category_id is not None and category_id not in category_ids:
                raise ValueError('备份条目引用了不存在的分类')
            if type(item['is_favorite']) is not bool or type(item['is_deleted']) is not bool:
                raise ValueError('备份条目布尔字段无效')
            strength = item['password_strength']
            if not isinstance(strength, int) or isinstance(strength, bool) or not 0 <= strength <= 4:
                raise ValueError('备份条目密码强度无效')
            if item['entry_type'] not in ENTRY_TYPES:
                raise ValueError('备份条目类型无效')
            custom_fields = item['custom_fields']
            if not isinstance(custom_fields, list) or len(custom_fields) > 1000:
                raise ValueError('备份自定义字段结构无效')
            for field in custom_fields:
                if not isinstance(field, dict):
                    raise ValueError('备份自定义字段格式无效')
                BackupRestoreManager._require_keys(
                    field, {'name', 'value', 'field_type'}, '备份自定义字段'
                )
                BackupRestoreManager._require_text(field['name'], '自定义字段名称', 1024)
                BackupRestoreManager._require_text(
                    field['value'], '自定义字段值', MAX_TEXT_FIELD_SIZE
                )
                if field['field_type'] not in {'text', 'password', 'url', 'email'}:
                    raise ValueError('备份自定义字段类型无效')

        for item in history:
            if not isinstance(item, dict):
                raise ValueError('备份密码历史格式无效')
            BackupRestoreManager._require_keys(
                item, {'entry_id', 'password', 'changed_at'}, '备份密码历史'
            )
            if item['entry_id'] not in entry_ids:
                raise ValueError('备份密码历史引用了不存在的条目')
            BackupRestoreManager._require_text(
                item['password'], '密码历史密码', MAX_TEXT_FIELD_SIZE
            )
            BackupRestoreManager._require_text(item['changed_at'], '密码历史时间', 64)

    @staticmethod
    def _require_keys(item: dict, expected: set[str], label: str):
        if set(item) != expected:
            raise ValueError(f'{label}字段不完整或包含未知字段')

    @staticmethod
    def _require_text(value, label: str, max_bytes: int, allow_empty: bool = True):
        if not isinstance(value, str):
            raise ValueError(f'{label}类型无效')
        if not allow_empty and not value.strip():
            raise ValueError(f'{label}不能为空')
        if len(value.encode('utf-8')) > max_bytes:
            raise ValueError(f'{label}过大')

    def _create_restore_point(self):
        directory = self._vault.data_dir / 'backups'
        secure_directory(directory)
        filename = f'pre_restore_{datetime.now():%Y%m%d_%H%M%S_%f}.cbox'
        success, error = self.create_backup(
            str(directory / filename),
            use_snapshot_key=True,
        )
        if not success:
            raise RuntimeError(f'无法创建恢复前安全快照：{error}')
        restore_points = sorted(
            directory.glob('pre_restore_*.cbox'),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        for expired in restore_points[MAX_RESTORE_POINTS:]:
            try:
                expired.unlink()
            except OSError:
                logger.warning('清理过期恢复点失败：%s', expired, exc_info=True)

    def _restore_data(self, data: dict):
        db = self._vault.db
        key = self._key
        with db.transaction():
            db.clear_vault_data()

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
                crypto_id = item.get('crypto_id') or uuid.uuid4().hex
                aad = lambda field: f'entry:{crypto_id}:{field}'
                custom_fields = item.get('custom_fields', [])
                custom_json = json.dumps(custom_fields, ensure_ascii=False) if custom_fields else ''
                username = EncryptionEngine.encrypt(item.get('username', ''), key, aad('username'))
                password = EncryptionEngine.encrypt(item.get('password', ''), key, aad('password'))
                notes = EncryptionEngine.encrypt(item.get('notes', ''), key, aad('notes'))
                custom = EncryptionEngine.encrypt(custom_json, key, aad('custom_fields'))
                totp = EncryptionEngine.encrypt(item.get('totp_secret', ''), key, aad('totp_secret'))
                entry = Entry(
                    crypto_id=crypto_id,
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

            for item in data.get('password_history', []):
                new_entry_id = entry_map.get(item.get('entry_id'))
                if not new_entry_id:
                    continue
                raw_entry = db.get_entry(new_entry_id)
                ciphertext = EncryptionEngine.encrypt(
                    item.get('password', ''),
                    key,
                    f'entry:{raw_entry.crypto_id}:password',
                )
                if ciphertext:
                    db.add_password_history(
                        new_entry_id,
                        ciphertext,
                        item.get('changed_at', ''),
                    )
