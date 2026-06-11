"""CipherBox 固定格式的加密备份与恢复。"""

import enum
import errno
import hashlib
import hmac
import json
import logging
import os
import struct
import time
import uuid
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .vault_manager import VaultManager

from ..crypto.encryption import EncryptionEngine
from ..crypto.master_key import MasterKeyManager
from ..database.models import ENTRY_TYPES, MAX_CUSTOM_FIELDS_PER_ENTRY, Category, Entry
from ..models import MAX_PASSWORD_HISTORY
from ..utils.file_security import secure_directory, secure_file, validate_file_path
from ..utils.format import utc_now_iso
from .crypto_utils import decrypt_field, encrypt_field, require_vault_key
from .exceptions import BackupError, DecryptionError, EntryIntegrityError

logger = logging.getLogger(__name__)


def _user_friendly_error(exc: Exception) -> str:
    """将异常映射为用户友好的错误消息。

    按异常类型精确匹配映射，不依赖英文错误文本，避免子串误匹配。
    未识别的异常类型返回包含 ``type(exc).__name__`` 的通用提示。
    """
    if isinstance(exc, FileNotFoundError):
        return '找不到指定的文件'
    if isinstance(exc, PermissionError):
        return '没有文件访问权限'
    if isinstance(exc, IsADirectoryError):
        return '所选路径是目录，请选择文件'
    if isinstance(exc, OSError):
        # ENOSPC 表示磁盘满，其余 OSError 统一提示读写失败
        if exc.errno == errno.ENOSPC:
            return '磁盘空间不足'
        return '文件读写失败，请检查路径和磁盘'
    if isinstance(exc, json.JSONDecodeError):
        return '备份文件格式无效或已损坏'
    return f'操作失败（{type(exc).__name__}），请检查文件和磁盘空间'

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
MAX_HISTORY_PER_ENTRY = MAX_PASSWORD_HISTORY * 2  # 每条目历史上限，2 倍余量


class BackupFlag(enum.IntEnum):
    """备份类型标志，用于二进制头部标识加密方式。

    使用 IntEnum 而非 IntFlag，因为 IntFlag 的 ~ 运算仅翻转已定义位，
    无法检测未知标志位。IntEnum 的 ~ 返回标准 int 按位取反，可正确检测非法组合。
    """
    NONE = 0
    PASSWORD = 1     # 使用独立备份密码加密
    SNAPSHOT = 2     # 使用快照密钥加密


class BackupRestoreManager:
    """创建可移植的加密备份并以事务方式恢复。"""

    def __init__(self, vault_manager: 'VaultManager'):
        self._vault = vault_manager

    @property
    def _key(self) -> bytes:
        return require_vault_key(self._vault)

    @staticmethod
    def _derive_backup_key(password: str, salt: bytes, iterations: int) -> bytes:
        return MasterKeyManager.derive_backup_key(password, salt, iterations)

    @staticmethod
    def _decrypt_text(value: str, key: bytes, label: str, aad: str) -> str:
        if not value:
            return ''
        try:
            return EncryptionEngine.decrypt(value, key, aad)
        except ValueError as exc:
            raise DecryptionError(f"{label}解密失败，保险库数据可能已损坏") from exc

    def _collect_portable_data(self) -> dict:
        """收集备份数据：手动解密所有字段为明文，构建可移植字典。

        注意：此方法直接操作原始 DB 条目并手动解密，未复用
        EntryManager.decrypt_entry_to_dict()，原因是备份需要同时收集
        密码历史并在循环内做增量大小估算，这两者超出了
        decrypt_entry_to_dict 的设计范围（该方法仅处理单条目解密）。
        """
        db = self._vault.db
        key = self._key
        categories = [category.to_dict() for category in db.get_categories()]
        entries = []
        raw_entries = db.get_entries(include_deleted=True)
        if len(raw_entries) > MAX_BACKUP_ENTRIES:
            raise ValueError('备份条目数量超出限制')
        # 基于字段原始字节长度的粗略估算，避免逐条 json.dumps 双重序列化开销
        estimated_size = sum(
            len(c.get('name', '').encode('utf-8')) + 128
            for c in categories
        )
        for raw in raw_entries:
            # 单条目解密失败时记录警告并跳过——既不固化被篡改/损坏的明文列，
            # 也不让单条损坏中断整个备份，_decrypt_text 失败会抛出 DecryptionError。
            try:
                custom_json = decrypt_field(
                    raw.custom_fields_db_value, key, raw.crypto_id, 'custom_fields',
                )
                try:
                    custom_fields = json.loads(custom_json) if custom_json else []
                except json.JSONDecodeError as exc:
                    raise DecryptionError("自定义字段格式损坏") from exc
                item = {
                    'id': raw.id,
                    'crypto_id': raw.crypto_id,
                    'title': raw.title,
                    'username': decrypt_field(raw.username, key, raw.crypto_id, 'username'),
                    'password': decrypt_field(raw.password, key, raw.crypto_id, 'password'),
                    'url': raw.url,
                    'category_id': raw.category_id,
                    'tags': raw.tags,
                    'notes': decrypt_field(raw.notes, key, raw.crypto_id, 'notes'),
                    'custom_fields': custom_fields,
                    'is_favorite': raw.is_favorite,
                    'is_deleted': raw.is_deleted,
                    'password_strength': raw.password_strength,
                    'entry_type': raw.entry_type,
                    'totp_secret': decrypt_field(raw.totp_secret, key, raw.crypto_id, 'totp_secret'),
                    'created_at': raw.created_at,
                    'updated_at': raw.updated_at,
                    'deleted_at': raw.deleted_at,
                    'password_changed_at': raw.password_changed_at,
                }
            except (DecryptionError, EntryIntegrityError):
                logger.warning(
                    "备份跳过损坏条目 crypto_id=%s，数据可能已损坏",
                    raw.crypto_id, exc_info=True,
                )
                continue
            # 基于字段原始长度的粗略估算，每条目约 512 字节固定开销
            estimated_size += (
                len(raw.title.encode('utf-8'))
                + len((raw.url or '').encode('utf-8'))
                + len((raw.tags or '').encode('utf-8'))
                + 512
            )
            if estimated_size > MAX_BACKUP_PAYLOAD_SIZE:
                raise ValueError('备份数据过大')
            entries.append(item)

        history = []
        history_rows = db.get_all_password_history()
        if len(history_rows) > len(raw_entries) * MAX_HISTORY_PER_ENTRY:
            raise ValueError('密码历史数量超出限制')
        for item in history_rows:
            history_item = {
                'entry_id': item.entry_id,
                'password': decrypt_field(
                    item.old_password_enc, key,
                    item.entry_crypto_id, 'password',
                ),
                'changed_at': item.changed_at,
            }
            estimated_size += (
                len(item.changed_at.encode('utf-8'))
                + len((item.old_password_enc or '').encode('utf-8'))
                + 64
            )
            if estimated_size > MAX_BACKUP_PAYLOAD_SIZE:
                raise ValueError('备份数据过大')
            history.append(history_item)

        return {
            'format': BACKUP_FORMAT,
            'version': 1,
            'created_at': utc_now_iso(),
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
            t0 = time.monotonic()
            validate_file_path(filepath)
            data = self._collect_portable_data()
            salt = os.urandom(BACKUP_SALT_SIZE)
            if backup_password:
                flags = BackupFlag.PASSWORD
                iterations = BACKUP_KDF_ITERATIONS
                backup_key = self._derive_backup_key(backup_password, salt, iterations)
            elif use_snapshot_key:
                flags = BackupFlag.SNAPSHOT
                iterations = 0
                backup_key = self._vault.snapshot_key
            else:
                # flags=0 即旧版主密钥派生已无生产创建路径，UI 强制备份密码、
                # 自动备份/恢复点用快照密钥。仅恢复路径保留 flags=0 兼容旧备份。
                raise ValueError('必须指定备份密码或使用快照密钥')

            payload = json.dumps(data, ensure_ascii=False).encode('utf-8')
            del data  # 序列化后立即释放明文引用
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
            logger.info("备份创建完成 (%.1fms)", (time.monotonic() - t0) * 1000)
            return True, ''
        except Exception as exc:
            logger.error("备份失败: %s", exc)
            return False, _user_friendly_error(exc)

    @staticmethod
    def inspect_backup(filepath: str) -> dict:
        """读取备份头，不解密内容。"""
        validate_file_path(filepath)
        if Path(filepath).stat().st_size > MAX_BACKUP_FILE_SIZE:
            raise ValueError('备份文件过大')
        with open(filepath, 'rb') as file:
            if file.read(len(BACKUP_MAGIC)) != BACKUP_MAGIC:
                raise ValueError('无效的备份文件格式')
            flags = file.read(1)
            if len(flags) != 1:
                raise ValueError('备份文件头已损坏')
            flag_value = struct.unpack('<B', flags)[0]
            if flag_value & ~(BackupFlag.PASSWORD | BackupFlag.SNAPSHOT):
                raise ValueError('备份文件格式无效或已损坏')
            if flag_value == (BackupFlag.PASSWORD | BackupFlag.SNAPSHOT):
                raise ValueError('备份文件格式无效或已损坏')
            return {
                'format': BACKUP_FORMAT,
                'password_required': bool(flag_value & BackupFlag.PASSWORD),
                'snapshot_required': bool(flag_value & BackupFlag.SNAPSHOT),
                # flags=0 的旧备份用创建时的主密钥派生密钥，非密码也非快照，
                # 一旦改密即无法恢复。UI 据此字段向用户提示风险。
                'master_key_bound': flag_value == 0,
            }

    def restore_backup(
        self,
        filepath: str,
        backup_password: str | None = None,
    ) -> tuple[bool, str]:
        """恢复备份；任何步骤失败都会回滚当前数据库。"""
        try:
            t0 = time.monotonic()
            validate_file_path(filepath)
            if Path(filepath).stat().st_size > MAX_BACKUP_FILE_SIZE:
                return False, '备份文件过大'
            with open(filepath, 'rb') as file:
                if file.read(len(BACKUP_MAGIC)) != BACKUP_MAGIC:
                    return False, '无效的备份文件格式'
                result = self._restore_current(file, backup_password)
                if result[0]:
                    logger.info("备份恢复完成 (%.1fms)", (time.monotonic() - t0) * 1000)
                return result
        except ValueError as exc:
            # _restore_current 中精心编写的错误消息直接传递给用户
            logger.error("恢复失败: %s", exc)
            return False, str(exc)
        except Exception as exc:
            logger.error("恢复失败: %s", exc)
            return False, _user_friendly_error(exc)

    def _restore_current(self, file, backup_password: str | None) -> tuple[bool, str]:
        flags_raw = file.read(1)
        salt = file.read(BACKUP_SALT_SIZE)
        iterations_raw = file.read(4)
        if len(flags_raw) != 1 or len(salt) != BACKUP_SALT_SIZE or len(iterations_raw) != 4:
            return False, '备份文件头已损坏'
        flags = struct.unpack('<B', flags_raw)[0]
        if flags & ~(BackupFlag.PASSWORD | BackupFlag.SNAPSHOT):
            return False, '备份文件格式无效或已损坏'
        if flags == (BackupFlag.PASSWORD | BackupFlag.SNAPSHOT):
            return False, '备份文件格式无效或已损坏'
        iterations = struct.unpack('<I', iterations_raw)[0]
        if flags & BackupFlag.PASSWORD:
            if not backup_password:
                return False, '请输入创建备份时设置的备份密码'
            if not BACKUP_MIN_KDF_ITERATIONS <= iterations <= BACKUP_MAX_KDF_ITERATIONS:
                return False, '备份密钥派生参数无效'
            backup_key = self._derive_backup_key(backup_password, salt, iterations)
        elif flags & BackupFlag.SNAPSHOT:
            backup_key = self._vault.snapshot_key
        else:
            backup_key = hmac.new(self._key, b'cipherbox:backup-key-v1' + salt, hashlib.sha256).digest()

        try:
            # 内存特征：峰值约 3 倍载荷大小
            # (encrypted ≤ 64MB + plaintext ≤ 32MB + JSON parse tree)
            # 桌面应用可接受；GCM 认证加密要求完整密文可用，无法流式解密。
            encrypted = file.read(MAX_BACKUP_FILE_SIZE + 1)
            if len(encrypted) > MAX_BACKUP_FILE_SIZE:
                return False, '备份文件过大'
            try:
                plaintext = EncryptionEngine.decrypt_bytes(
                    encrypted, backup_key, BACKUP_AAD
                )
            except ValueError:
                # 向后兼容：尝试旧版密钥派生（无域前缀）。
                # 旧版密钥派生将在未来版本移除，建议用户重新创建备份。
                if backup_password:
                    logger.warning(
                        "旧版密钥派生兼容模式（将在未来版本移除），"
                        "建议使用当前版本重新创建备份"
                    )
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore', DeprecationWarning)
                        legacy_key = MasterKeyManager.derive_backup_key_legacy(
                            backup_password, salt, iterations
                        )
                    plaintext = EncryptionEngine.decrypt_bytes(
                        encrypted, legacy_key, BACKUP_AAD
                    )
                else:
                    raise
            if len(plaintext) > MAX_BACKUP_PAYLOAD_SIZE:
                return False, '备份解密数据过大'
            data = json.loads(plaintext.decode('utf-8'))
        except Exception:
            logger.debug("备份读取或解密失败", exc_info=True)
            return False, '备份密码错误或文件已损坏'
        if not isinstance(data, dict) or not isinstance(data.get('entries'), list):
            return False, '备份数据结构无效'
        self._validate_restore_data(data)
        restore_path = self._create_restore_point()
        try:
            new_epoch = self._restore_data(data)
        except Exception:
            # 恢复失败时清理刚创建的恢复点，避免反复尝试时占用磁盘空间。
            if restore_path is not None:
                try:
                    restore_path.unlink(missing_ok=True)
                except OSError:
                    logger.debug("清理恢复点失败", exc_info=True)
            raise
        finally:
            if 'plaintext' in locals():
                del plaintext
            if 'data' in locals():
                del data
        # 同步内存中的 key_epoch，使当前会话的写入守卫识别新 epoch
        if new_epoch:
            self._vault.update_key_epoch(new_epoch)
        return True, ''

    @staticmethod
    def _validate_restore_data(data: dict):
        if data.get('format') != BACKUP_FORMAT:
            raise ValueError('备份格式标识无效')
        # 版本检查：version=0 视为旧版（向后兼容），version>1 为未来格式（暂不支持）。
        # 安全考量：v0 旧备份不含 version 字段，但其数据结构已通过后续校验
        # （format 标识、entries/categories 类型检查、_validate_entries 结构验证），
        # 因此放行是安全的。仅拒绝未知的新版本格式以防止数据误读。
        version = data.get('version', 0)
        if version > 1:
            raise ValueError(f'不支持的备份格式版本：{version}（当前支持 v0/v1）')
        entries = data.get('entries', [])
        categories = data.get('categories', [])
        history = data.get('password_history', [])
        if not all(isinstance(items, list) for items in (entries, categories, history)):
            raise ValueError('备份数据结构无效')
        if len(entries) > MAX_BACKUP_ENTRIES:
            raise ValueError('备份条目数量超出限制')
        if len(history) > len(entries) * MAX_HISTORY_PER_ENTRY:
            raise ValueError('密码历史数量超出限制')
        if len(categories) > 10_000:
            raise ValueError('备份分类数量超出限制')

        category_ids = BackupRestoreManager._validate_categories(categories)
        entry_ids = BackupRestoreManager._validate_entries(entries, category_ids)
        BackupRestoreManager._validate_history(history, entry_ids)

    @staticmethod
    def _validate_categories(categories: list) -> set[int]:
        """验证备份分类数据，返回有效的分类 ID 集合。"""
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
        return category_ids

    @staticmethod
    def _validate_entry_fields(item: dict, category_ids: set[int]):
        """验证单条备份条目的必填键、字段类型和文本长度。"""
        required_entry_keys = {
            'id', 'crypto_id', 'title', 'username', 'password', 'url',
            'category_id', 'tags', 'notes', 'custom_fields', 'is_favorite',
            'is_deleted', 'password_strength', 'entry_type', 'totp_secret',
            'created_at', 'updated_at', 'deleted_at', 'password_changed_at',
        }
        if sum(len(str(v).encode('utf-8')) for v in item.values()) > MAX_ENTRY_JSON_SIZE:
            raise ValueError('备份条目格式或大小无效')
        BackupRestoreManager._require_keys(item, required_entry_keys, '备份条目')

        for field in (
            'title', 'username', 'password', 'url', 'tags', 'notes',
            'totp_secret', 'created_at', 'updated_at', 'deleted_at',
            'password_changed_at',
        ):
            limit = 64 if field.endswith('_at') else MAX_TEXT_FIELD_SIZE
            BackupRestoreManager._require_text(item[field], f'条目字段 {field}', limit)
        # 基本 ISO 8601 格式校验
        for key in ('created_at', 'updated_at', 'deleted_at', 'password_changed_at'):
            val = item.get(key, '')
            if val and isinstance(val, str):
                try:
                    datetime.fromisoformat(val)
                except (ValueError, TypeError):
                    logger.warning(
                        "条目 %s 字段 %s 日期格式无效: %s",
                        item.get('id', '?'), key, val[:32],
                    )

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

    @staticmethod
    def _validate_entry_custom_fields(fields: list):
        """验证自定义字段列表结构（数量、键完整性、类型）。

        数量上限与 ``Entry.from_dict`` 保持一致（100），确保恢复后
        条目能通过 ``from_dict`` 的校验。
        """
        if not isinstance(fields, list) or len(fields) > MAX_CUSTOM_FIELDS_PER_ENTRY:
            raise ValueError('备份自定义字段结构无效')
        for field in fields:
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

    @staticmethod
    def _validate_entries(entries: list, category_ids: set[int]) -> set[int]:
        """验证备份条目数据，返回有效的 entry_ids 集合。"""
        entry_ids: set[int] = set()
        crypto_ids: set[str] = set()
        for item in entries:
            if not isinstance(item, dict):
                raise ValueError('备份条目格式无效')
            BackupRestoreManager._validate_entry_fields(item, category_ids)

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

            BackupRestoreManager._validate_entry_custom_fields(item['custom_fields'])
        return entry_ids

    @staticmethod
    def _validate_history(history: list, entry_ids: set[int]):
        """验证备份密码历史数据。"""
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
        """验证 item 是否包含所有必需键。使用 issubset 而非严格相等，
        允许备份格式前向兼容（新增字段不会导致校验失败）。"""
        if not expected.issubset(set(item)):
            raise ValueError(f'{label}字段不完整')

    @staticmethod
    def _require_text(value, label: str, max_bytes: int, allow_empty: bool = True):
        if not isinstance(value, str):
            raise ValueError(f'{label}类型无效')
        if not allow_empty and not value.strip():
            raise ValueError(f'{label}不能为空')
        if len(value.encode('utf-8')) > max_bytes:
            raise ValueError(f'{label}过大')

    def _create_restore_point(self) -> Path | None:
        """创建恢复前安全快照，返回快照文件路径用于失败时清理，创建失败返回 None。"""
        directory = self._vault.data_dir / 'backups'
        secure_directory(directory)
        filename = f'pre_restore_{datetime.now(timezone.utc):%Y%m%d_%H%M%S_%f}.cbox'
        target_path = directory / filename
        success, error = self.create_backup(
            str(target_path),
            use_snapshot_key=True,
        )
        if not success:
            raise BackupError(f'无法创建恢复前安全快照：{error}')
        # 按文件名排序比 st_mtime 更精确，避免秒级精度问题
        restore_points = sorted(
            directory.glob('pre_restore_*.cbox'),
            key=lambda p: p.name,
            reverse=True,
        )
        for expired in restore_points[MAX_RESTORE_POINTS:]:
            try:
                expired.unlink()
            except OSError:
                logger.warning('清理过期恢复点失败：%s', expired, exc_info=True)
        return target_path

    def _restore_data(self, data: dict):
        db = self._vault.db
        key = self._key
        with db.transaction():
            db.clear_vault_data()

            category_map = {}
            for item in data.get('categories', []):
                category = Category.from_dict(item)
                if not category.name:
                    continue
                new_id = db.add_category(category)
                if item.get('id') is not None:
                    category_map[item['id']] = new_id

            entry_map = {}
            crypto_id_map = {}  # old_id -> crypto_id
            for item in data.get('entries', []):
                old_category = item.get('category_id')
                crypto_id = item['crypto_id']  # validated by _validate_entries
                custom_fields = item.get('custom_fields', [])
                custom_json = json.dumps(custom_fields, ensure_ascii=False) if custom_fields else ''
                username = encrypt_field(item.get('username', ''), key, crypto_id, 'username')
                password = encrypt_field(item.get('password', ''), key, crypto_id, 'password')
                notes = encrypt_field(item.get('notes', ''), key, crypto_id, 'notes')
                custom = encrypt_field(custom_json, key, crypto_id, 'custom_fields')
                totp = encrypt_field(item.get('totp_secret', ''), key, crypto_id, 'totp_secret')
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
                    created_at=item.get('created_at', '') or '',
                    updated_at=item.get('updated_at', '') or '',
                    deleted_at=item.get('deleted_at', '') or '',
                    password_changed_at=item.get('password_changed_at', '') or '',
                )
                new_id = db.add_entry(entry, preserve_metadata=True)
                if item.get('id') is not None:
                    entry_map[item['id']] = new_id
                    crypto_id_map[item['id']] = crypto_id

            # 密码历史按 entry_id 分组，批量写入并统一截断，
            # 替代逐条 add_password_history 触发的 N 次截断 DELETE。
            history_by_entry: dict[int, list[tuple[str, str]]] = {}
            for item in data.get('password_history', []):
                new_entry_id = entry_map.get(item.get('entry_id'))
                if not new_entry_id:
                    continue
                crypto_id = crypto_id_map.get(item['entry_id'], '')
                ciphertext = encrypt_field(
                    item.get('password', ''),
                    key,
                    crypto_id,
                    'password',
                )
                if ciphertext:
                    history_by_entry.setdefault(new_entry_id, []).append(
                        (ciphertext, item.get('changed_at', ''))
                    )
            for entry_id, items in history_by_entry.items():
                db.add_password_history_batch(entry_id, items)

            # 轮换 key_epoch 防止旧会话写入恢复后的数据
            new_epoch = uuid.uuid4().hex
            db.set_meta('key_epoch', new_epoch)

        return new_epoch

    def maybe_auto_backup(
        self,
        config,
        force: bool = False,
    ) -> tuple[bool, str]:
        """按配置创建当前保险库的本地快速快照。

        Args:
            config: ConfigManager 实例，用于读取备份设置。
            force: 是否强制创建（忽略时间间隔检查）。

        Returns:
            (success, error_message) — 成功时 error_message 为空字符串。
        """
        if not config.get('auto_backup_enabled', False):
            return True, ''

        interval = config.get('auto_backup_interval_hours', 24)
        last_text = config.get('last_auto_backup_at', '')
        if not force and last_text:
            try:
                elapsed = datetime.now(timezone.utc) - datetime.fromisoformat(last_text)
                if elapsed < timedelta(hours=interval):
                    return True, ''
            except ValueError:
                pass

        backup_dir = config.get('backup_directory', '')
        if backup_dir:
            try:
                backup_dir = str(validate_file_path(backup_dir))
            except ValueError:
                return False, f'备份目录路径无效: {backup_dir}'

        directory = Path(backup_dir) if backup_dir else config.data_dir / 'backups'
        directory.mkdir(parents=True, exist_ok=True)
        filename = f'cipherbox_snapshot_{datetime.now(timezone.utc):%Y%m%d_%H%M%S}.cbox'
        success, error = self.create_backup(
            str(directory / filename), use_snapshot_key=True
        )
        if not success:
            return False, error

        config.set('last_auto_backup_at', utc_now_iso())
        config.save()

        retention = config.get('auto_backup_retention', 10)
        snapshots = sorted(directory.glob('cipherbox_snapshot_*.cbox'), reverse=True)
        for old_file in snapshots[retention:]:
            try:
                old_file.unlink()
            except OSError:
                pass

        return True, ''
