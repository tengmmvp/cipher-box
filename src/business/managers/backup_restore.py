"""CipherBox 固定格式的加密备份与恢复。"""

import enum
import errno
import json
import logging
import os
import struct
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .vault_manager import VaultManager

from ...crypto.encryption import EncryptionEngine
from ...crypto.master_key import MasterKeyManager
from ...exceptions import BackupError, VaultKeyEpochMismatchError
from ...models import (
    ENTRY_TYPES,
    MAX_CUSTOM_FIELDS_PER_ENTRY,
    MAX_PASSWORD_HISTORY,
    Category,
    Entry,
)
from ...utils.file_security import secure_directory, secure_file, validate_file_path
from ...utils.format import utc_now_iso
from ...utils.memory import secure_zero_buffer
from ..services.crypto_utils import (
    build_encrypted_entry_fields,
    decrypt_entry_to_portable_dict,
    decrypt_field,
    encrypt_field,
    require_vault_key,
)

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
    if isinstance(exc, VaultKeyEpochMismatchError):
        return '操作期间检测到主密码已被修改，已中止并回滚，请重试'
    if isinstance(exc, OSError):
        # ENOSPC 表示磁盘满，其余 OSError 统一提示读写失败
        if exc.errno == errno.ENOSPC:
            return '磁盘空间不足'
        return '文件读写失败，请检查路径和磁盘'
    if isinstance(exc, json.JSONDecodeError):
        return '备份文件格式无效或已损坏'
    if isinstance(exc, ValueError) and '过大' in str(exc):
        # _collect_portable_data 预估算或 payload 精确检查抛出，保留具体提示
        return str(exc)
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
    def _derive_backup_key(password: str, salt: bytes, iterations: int) -> bytearray:
        return MasterKeyManager.derive_backup_key(password, salt, iterations)

    def _collect_portable_data(self) -> dict:
        """收集备份数据：解密所有字段为明文，构建可移植字典。

        使用 crypto_utils.decrypt_entry_to_portable_dict 共享解密逻辑，
        本方法保留备份特有的增量大小估算和密码历史收集。
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
            item = decrypt_entry_to_portable_dict(raw, key, include_secrets=True)
            if item is None:
                logger.warning(
                    "备份跳过损坏条目 crypto_id=%s，数据可能已损坏",
                    raw.crypto_id,
                )
                continue
            # 基于字段原始长度的粗略估算，每条目约 512 字节固定开销。
            # 估算覆盖全部将进入 JSON payload 的字段，以密文长度作上界，
            # 因 base64 密文大于等于明文，避免大 notes 或 custom_fields 场景下
            # 粗估漏判、直至序列化才产生内存峰值。
            estimated_size += (
                len(raw.title.encode('utf-8'))
                + len((raw.username or '').encode('utf-8'))
                + len((raw.url or '').encode('utf-8'))
                + len((raw.tags or '').encode('utf-8'))
                + len((raw.notes or '').encode('utf-8'))
                + len(raw.custom_fields_db_value.encode('utf-8'))
                + len((raw.totp_secret or '').encode('utf-8'))
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
            try:
                pwd = decrypt_field(
                    item.old_password_enc, key,
                    item.entry_crypto_id, 'password', strict=True,
                )
            except ValueError:
                logger.warning("备份跳过损坏的密码历史 entry_id=%s", item.entry_id)
                continue
            history_item = {
                'entry_id': item.entry_id,
                'password': pwd,
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
            filepath = str(validate_file_path(filepath))
            salt = os.urandom(BACKUP_SALT_SIZE)
            # 持 vault 锁与改密重加密串行：避免后台备份读全量明文期间密钥被
            # 轮换，导致解密失败被静默跳过而产出残缺备份。
            # 备份密钥也在锁内解析：snapshot_key 从 KeyManager 读取后立即复制
            # 为 bytes，避免释放锁后、加密前主线程 lock() 清零 snapshot_key
            # 的竞态窗口（锁定与自动备份后台线程竞态）。
            with self._vault._lock:
                data = self._collect_portable_data()
                if backup_password:
                    flags = BackupFlag.PASSWORD
                    iterations = BACKUP_KDF_ITERATIONS
                    backup_key = self._derive_backup_key(backup_password, salt, iterations)
                elif use_snapshot_key:
                    flags = BackupFlag.SNAPSHOT
                    iterations = 0
                    backup_key = bytes(self._vault.snapshot_key)
                else:
                    raise ValueError('必须指定备份密码或使用快照密钥')

            try:
                payload = json.dumps(data, ensure_ascii=False).encode('utf-8')
                del data  # 序列化后立即释放明文引用
                if len(payload) > MAX_BACKUP_PAYLOAD_SIZE:
                    raise ValueError('备份数据过大')
                encrypted = EncryptionEngine.encrypt_bytes(
                    payload, backup_key, BACKUP_AAD
                )
            finally:
                # 仅清零本次派生的密码备份密钥；SNAPSHOT 路径的 backup_key 借用 snapshot_key，
                # 其生命周期由 KeyManager 管理，清零它会破坏同会话的后续快照。
                # finally 确保即使 payload 超限 raise 也清零。
                if flags == BackupFlag.PASSWORD:
                    secure_zero_buffer(backup_key)
            target = Path(filepath)
            # 创建并收紧目录权限，避免快照全量明文以继承的宽松 ACL 落盘
            secure_directory(target.parent)
            temp_path = target.with_name(target.name + '.tmp')
            try:
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
            except Exception:
                temp_path.unlink(missing_ok=True)
                raise
            logger.info("备份创建完成 (%.1fms)", (time.monotonic() - t0) * 1000)
            return True, ''
        except Exception as exc:
            logger.error("备份失败: %s", exc, exc_info=True)
            return False, _user_friendly_error(exc)

    @staticmethod
    def inspect_backup(filepath: str) -> dict:
        """读取备份头，不解密内容。"""
        filepath = str(validate_file_path(filepath))
        if Path(filepath).stat().st_size > MAX_BACKUP_FILE_SIZE:
            raise ValueError('备份文件过大')
        with open(filepath, 'rb') as file:
            if file.read(len(BACKUP_MAGIC)) != BACKUP_MAGIC:
                raise ValueError('无效的备份文件格式')
            flags = file.read(1)
            if len(flags) != 1:
                raise ValueError('备份文件头已损坏')
            flag_value = struct.unpack('<B', flags)[0]
            if flag_value not in (BackupFlag.PASSWORD, BackupFlag.SNAPSHOT):
                raise ValueError('备份文件格式无效或已损坏')
            return {
                'format': BACKUP_FORMAT,
                'password_required': flag_value == BackupFlag.PASSWORD,
                'snapshot_required': flag_value == BackupFlag.SNAPSHOT,
            }

    def restore_backup(
        self,
        filepath: str,
        backup_password: str | None = None,
    ) -> tuple[bool, str]:
        """恢复备份；任何步骤失败都会回滚当前数据库。"""
        try:
            t0 = time.monotonic()
            filepath = str(validate_file_path(filepath))
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
            logger.error("恢复失败: %s", exc, exc_info=True)
            return False, str(exc)
        except Exception as exc:
            logger.error("恢复失败: %s", exc, exc_info=True)
            return False, _user_friendly_error(exc)

    def _restore_current(self, file, backup_password: str | None) -> tuple[bool, str]:
        flags_raw = file.read(1)
        salt = file.read(BACKUP_SALT_SIZE)
        iterations_raw = file.read(4)
        if len(flags_raw) != 1 or len(salt) != BACKUP_SALT_SIZE or len(iterations_raw) != 4:
            return False, '备份文件头已损坏'
        flags = struct.unpack('<B', flags_raw)[0]
        if flags not in (BackupFlag.PASSWORD, BackupFlag.SNAPSHOT):
            return False, '备份文件格式无效或已损坏'
        iterations = struct.unpack('<I', iterations_raw)[0]
        if flags == BackupFlag.PASSWORD:
            if not backup_password:
                return False, '请输入创建备份时设置的备份密码'
            if not BACKUP_MIN_KDF_ITERATIONS <= iterations <= BACKUP_MAX_KDF_ITERATIONS:
                return False, '备份密钥派生参数无效'
            backup_key = self._derive_backup_key(backup_password, salt, iterations)
        else:
            if not self._vault.is_unlocked:
                return False, '恢复快照备份需要先解锁保险库'
            # 与 create_backup 一致：复制为独立 bytes，避免借用 KeyManager 内部对象，
            # 防止后续若在锁外使用时与主线程清零 snapshot_key 产生竞态
            backup_key = bytes(self._vault.snapshot_key)

        try:
            # 持 vault 锁串行化恢复与改密/备份：从解密全量明文到写库全程持锁，
            # 与 create_backup 的「持锁才接触全量明文」契约统一。
            with self._vault._lock:
                try:
                    # 内存特征：峰值约 3 倍载荷大小。
                    # encrypted 不超过 64MB，plaintext 不超过 32MB，外加 JSON 解析树，
                    # 桌面应用可接受。GCM 认证加密要求完整密文可用，无法流式解密。
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
                    logger.debug("备份读取或解密失败", exc_info=True)
                    return False, '备份密码错误或文件已损坏'
                if not isinstance(data, dict) or not isinstance(data.get('entries'), list):
                    return False, '备份数据结构无效'
                self._validate_restore_data(data)
                restore_path = self._create_restore_point()
                try:
                    new_epoch, new_snapshot_key = self._restore_data(data)
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
            # 事务已提交，key_epoch 与 snapshot_key_enc 均已在同一事务内原子写入。
            # 此处仅同步内存状态（不写库），消除原事务外 set_snapshot_key 的崩溃窗口。
            if new_epoch:
                self._vault.update_key_epoch(new_epoch)
            self._vault.apply_snapshot_key(new_snapshot_key)
            # 轮换后清理旧 snapshot_key 加密的快照与恢复点以收缩泄漏面。
            failed_purges = self._vault.purge_snapshot_backups()
            if failed_purges:
                return True, (
                    f'恢复完成，但 {len(failed_purges)} 个旧快照未能删除'
                    '（可能被占用），建议在备份对话框手动清理以收缩泄漏面。'
                )
            return True, ''
        finally:
            # 确保 PASSWORD 派生的 backup_key 在所有退出路径（含文件过大、解密异常）都清零；
            # SNAPSHOT 路径借用 snapshot_key 不清零。
            if flags == BackupFlag.PASSWORD:
                secure_zero_buffer(backup_key)

    @staticmethod
    def _validate_restore_data(data: dict):
        if data.get('format') != BACKUP_FORMAT:
            raise ValueError('备份格式标识无效')
        # 版本检查：仅支持 v1 格式。
        version = data.get('version')
        if version != 1:
            raise ValueError(f'不支持的备份格式版本：{version}（当前支持 v1）')
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
        """验证自定义字段列表结构，包含数量、键完整性与类型。

        数量上限与 ``Entry.from_dict`` 保持一致，为 100，确保恢复后
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
        """验证 item 是否恰好包含所需的键集合，拒绝多余或缺失的键。"""
        if set(item) != expected:
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

    def clear_restore_points(self) -> int:
        """删除所有恢复前安全快照 pre_restore_*.cbox，返回删除数量。

        供 UI 手动清理；改密时由 VaultManager 自动清理。恢复点含恢复前全部
        条目明文，定期清理可收缩泄漏面。
        """
        directory = self._vault.data_dir / 'backups'
        if not directory.is_dir():
            return 0
        count = 0
        for f in directory.glob('pre_restore_*.cbox'):
            try:
                f.unlink()
                count += 1
            except OSError:
                logger.warning('清理恢复点失败：%s', f, exc_info=True)
        return count

    def count_restore_points(self) -> int:
        """统计恢复前安全快照数量，供 UI 决定清理按钮的可用性。"""
        directory = self._vault.data_dir / 'backups'
        if not directory.is_dir():
            return 0
        return sum(1 for _ in directory.glob('pre_restore_*.cbox'))

    def _restore_data(self, data: dict) -> tuple[str, bytes]:
        db = self._vault.db
        key = self._key
        pre_epoch = self._vault.key_epoch
        # snapshot_key 与 key_epoch 在同一事务内轮换：恢复整体替换数据后，旧 snapshot_key
        # 加密的快照含恢复前明文，轮换使其失效以收缩泄漏面，与改密路径语义一致。
        # 同事务写入消除原事务外 set_snapshot_key 在崩溃时 epoch 已提交而
        # snapshot_key_enc 未写入的不一致窗口。
        new_snapshot_key = os.urandom(32)
        with db.transaction():
            # 事务边界二次校验 epoch，防止恢复期间并发改密导致密钥不一致，
            # 兑现 _enforce_key_epoch 的事务化写路径契约
            if self._vault.key_epoch != pre_epoch:
                raise VaultKeyEpochMismatchError('恢复期间检测到密钥变更，已中止恢复')
            db.clear_vault_data()
            category_map = self._restore_categories(db, data)
            entry_map, crypto_id_map = self._restore_entries(db, data, key, category_map)
            self._restore_history(db, data, key, entry_map, crypto_id_map)
            # 轮换 key_epoch 防止旧会话写入恢复后的数据
            new_epoch = uuid.uuid4().hex
            db.set_meta('key_epoch', new_epoch)
            db.set_meta('snapshot_key_enc', self._vault.encrypt_snapshot_key(new_snapshot_key))
        return new_epoch, new_snapshot_key

    @staticmethod
    def _restore_categories(db, data: dict) -> dict:
        """重建分类，返回旧 ID 到新 ID 的映射。"""
        category_map = {}
        for item in data.get('categories', []):
            category = Category.from_dict(item)
            if not category.name:
                continue
            new_id = db.add_category(category)
            if item.get('id') is not None:
                category_map[item['id']] = new_id
        return category_map

    @staticmethod
    def _restore_entries(db, data: dict, key: bytes, category_map: dict):
        """重建条目，加密敏感字段，返回 (entry_map, crypto_id_map)。"""
        entry_map = {}
        crypto_id_map = {}  # 旧 entry_id 到 crypto_id 的映射
        for item in data.get('entries', []):
            old_category = item.get('category_id')
            crypto_id = item['crypto_id']  # 已由 _validate_entries 校验
            enc = build_encrypted_entry_fields(item, key, crypto_id)
            entry = Entry(
                crypto_id=crypto_id,
                title=item.get('title', ''),
                username=enc['username'],
                password=enc['password'],
                url=item.get('url', ''),
                category_id=category_map.get(old_category),
                tags=item.get('tags', ''),
                notes=enc['notes'],
                custom_fields=enc['custom_fields'],
                is_favorite=bool(item.get('is_favorite', False)),
                is_deleted=bool(item.get('is_deleted', False)),
                password_strength=int(item.get('password_strength', 0)),
                entry_type=item.get('entry_type', 'login'),
                totp_secret=enc['totp_secret'],
                created_at=item.get('created_at', '') or '',
                updated_at=item.get('updated_at', '') or '',
                deleted_at=item.get('deleted_at', '') or '',
                password_changed_at=item.get('password_changed_at', '') or '',
            )
            new_id = db.add_entry(entry, preserve_metadata=True)
            if item.get('id') is not None:
                entry_map[item['id']] = new_id
                crypto_id_map[item['id']] = crypto_id
        return entry_map, crypto_id_map

    @staticmethod
    def _restore_history(db, data: dict, key: bytes, entry_map: dict, crypto_id_map: dict) -> None:
        """重建密码历史，按 entry_id 分组批量写入并统一截断。"""
        history_by_entry: dict[int, list[tuple[str, str]]] = {}
        for item in data.get('password_history', []):
            new_entry_id = entry_map.get(item.get('entry_id'))
            if not new_entry_id:
                continue
            crypto_id = crypto_id_map.get(item['entry_id'], '')
            ciphertext = encrypt_field(
                item.get('password', ''), key, crypto_id, 'password',
            )
            if ciphertext:
                history_by_entry.setdefault(new_entry_id, []).append(
                    (ciphertext, item.get('changed_at', ''))
                )
        for entry_id, items in history_by_entry.items():
            db.add_password_history_batch(entry_id, items)

    def maybe_auto_backup(
        self,
        config,
        force: bool = False,
    ) -> tuple[bool, str]:
        """按配置创建当前保险库的本地快速快照。

        Args:
            config: ConfigManager 实例，用于读取备份设置。
            force: 是否强制创建，忽略时间间隔检查。

        Returns:
            由是否成功与错误信息组成的二元组，成功时错误信息为空字符串。
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
        # 创建并收紧权限，含用户自定义目录，避免快照全量明文以宽松 ACL 落盘
        secure_directory(directory)
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
