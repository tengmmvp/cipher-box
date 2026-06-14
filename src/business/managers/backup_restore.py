"""CipherBox 固定格式的加密备份与恢复。"""

import enum
import errno
import json
import logging
import os
import struct
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .vault_manager import VaultManager

from ...crypto.encryption import EncryptionEngine
from ...crypto.master_key import DEFAULT_KDF_PARAMS, KdfParams, MasterKeyManager
from ...exceptions import BackupError, VaultKeyEpochMismatchError
from ...models import (
    ENTRY_TYPES,
    MAX_CUSTOM_FIELDS_PER_ENTRY,
    MAX_PASSWORD_HISTORY,
    Category,
    RawEntry,
)
from ...utils.file_security import (
    secure_delete_file,
    secure_directory,
    secure_file,
    validate_file_path,
)
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
    if isinstance(exc, BackupError):
        return str(exc)
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
# 固定头：flags、Argon2 time/memory/parallelism，随后为 32 字节 salt。
BACKUP_HEADER_STRUCT = struct.Struct('<BIII')
BACKUP_HEADER_SIZE = len(BACKUP_MAGIC) + BACKUP_HEADER_STRUCT.size + BACKUP_SALT_SIZE
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
    def _derive_backup_key(password: str, salt: bytes) -> bytearray:
        return MasterKeyManager.derive_backup_key(password, salt, DEFAULT_KDF_PARAMS)

    @staticmethod
    def _write_backup_header(file, flags: BackupFlag, salt: bytes, params: KdfParams) -> None:
        """写入备份头，持久化实际 KDF 参数。"""
        MasterKeyManager.validate_params(params)
        if len(salt) != BACKUP_SALT_SIZE:
            raise ValueError('备份盐长度无效')
        file.write(BACKUP_MAGIC)
        file.write(BACKUP_HEADER_STRUCT.pack(
            int(flags),
            params.time_cost,
            params.memory_cost,
            params.parallelism,
        ))
        file.write(salt)

    @staticmethod
    def _read_backup_header(file) -> tuple[BackupFlag, bytes, KdfParams]:
        """读取备份头，解析标志位与持久化的 KDF 参数。"""
        file.seek(0)
        if file.read(len(BACKUP_MAGIC)) != BACKUP_MAGIC:
            raise ValueError('无效的备份文件格式')
        raw = file.read(BACKUP_HEADER_STRUCT.size)
        salt = file.read(BACKUP_SALT_SIZE)
        if len(raw) != BACKUP_HEADER_STRUCT.size or len(salt) != BACKUP_SALT_SIZE:
            raise ValueError('备份文件头已损坏')
        flag_value, time_cost, memory_cost, parallelism = (
            BACKUP_HEADER_STRUCT.unpack(raw)
        )
        if flag_value not in (BackupFlag.PASSWORD, BackupFlag.SNAPSHOT):
            raise ValueError('备份文件格式无效或已损坏')
        params = KdfParams(time_cost, memory_cost, parallelism)
        MasterKeyManager.validate_params(params)
        return BackupFlag(flag_value), salt, params

    def _collect_portable_data(
        self, cancel_check: Callable[[], bool] | None = None,
    ) -> dict | None:
        """收集备份数据：解密所有字段为明文，构建可移植字典。

        使用 crypto_utils.decrypt_entry_to_portable_dict 共享解密逻辑，
        本方法保留备份特有的增量大小估算和密码历史收集。

        若提供 ``cancel_check`` 且在解密循环中返回真值，立即返回 None
        表示备份已被取消，调用方据此中止而不产出残缺备份。
        """
        db = self._vault.db
        key = self._key
        from .entry_manager import EntryManager
        categories = [
            category.to_dict()
            for category in EntryManager(self._vault).get_categories()
        ]
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
            if cancel_check and cancel_check():
                return None
            portable_item = decrypt_entry_to_portable_dict(
                raw, key, include_secrets=True,
            )
            if portable_item is None:
                raise BackupError(
                    f'条目 {raw.id} 完整性校验或解密失败，备份已中止'
                )
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
            entries.append(portable_item)

        history = []
        history_rows = db.get_all_password_history()
        if len(history_rows) > len(raw_entries) * MAX_HISTORY_PER_ENTRY:
            raise ValueError('密码历史数量超出限制')
        for history_row in history_rows:
            if cancel_check and cancel_check():
                return None
            try:
                pwd = decrypt_field(
                    history_row.old_password_enc, key,
                    history_row.entry_crypto_id, 'password', strict=True,
                )
            except ValueError:
                raise BackupError(
                    f'条目 {history_row.entry_id} 的密码历史解密失败，备份已中止'
                ) from None
            history_item = {
                'entry_id': history_row.entry_id,
                'password': pwd,
                'changed_at': history_row.changed_at,
            }
            estimated_size += (
                len(history_row.changed_at.encode('utf-8'))
                + len((history_row.old_password_enc or '').encode('utf-8'))
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
        cancel_check: Callable[[], bool] | None = None,
    ) -> tuple[bool, str]:
        """创建加密备份；密码备份可跨安装恢复，快照使用稳定快照密钥。

        ``cancel_check`` 可选取消探针，在全量解密循环中周期性调用，返回真值
        时中止备份并返回 (False, '备份已取消')，避免后台备份在隐藏/锁定后
        继续持有密钥解密。
        """
        try:
            t0 = time.monotonic()
            filepath = str(validate_file_path(filepath))
            salt = os.urandom(BACKUP_SALT_SIZE)
            # 持 vault 锁与改密重加密串行：避免后台备份读全量明文期间密钥被
            # 轮换，导致解密失败被静默跳过而产出残缺备份。
            # 备份密钥也在锁内解析：snapshot_key 在锁内读取（KeyManager.snapshot_key
            # property 已返回独立 bytes 副本），避免释放锁后、加密前主线程 lock()
            # 清零 snapshot_key 的竞态窗口（锁定与自动备份后台线程竞态）。
            with self._vault.vault_write_lock():
                data = self._collect_portable_data(cancel_check=cancel_check)
                if data is None:
                    return False, '备份已取消'
                backup_key: bytes | bytearray
                if backup_password:
                    flags = BackupFlag.PASSWORD
                    backup_key = MasterKeyManager.derive_backup_key(
                        backup_password, salt, DEFAULT_KDF_PARAMS,
                    )
                elif use_snapshot_key:
                    flags = BackupFlag.SNAPSHOT
                    backup_key = self._vault.snapshot_key
                else:
                    raise ValueError('必须指定备份密码或使用快照密钥')
                try:
                    payload = json.dumps(data, ensure_ascii=False).encode('utf-8')
                    del data
                    if len(payload) > MAX_BACKUP_PAYLOAD_SIZE:
                        raise ValueError('备份数据过大')
                    encrypted = EncryptionEngine.encrypt_bytes(
                        payload, backup_key, BACKUP_AAD
                    )
                    del payload
                    target = Path(filepath)
                    temp_path = target.with_name(target.name + '.tmp')
                    try:
                        with open(temp_path, 'wb') as file:
                            self._write_backup_header(
                                file, flags, salt, DEFAULT_KDF_PARAMS,
                            )
                            file.write(encrypted)
                            file.flush()
                            os.fsync(file.fileno())
                        secure_file(temp_path, strict=True)
                        os.replace(temp_path, target)
                        secure_file(target, strict=True)
                    except Exception:
                        temp_path.unlink(missing_ok=True)
                        raise
                finally:
                    self._zero_backup_key_if_owned(flags, backup_key)
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
            flags, _salt, params = BackupRestoreManager._read_backup_header(file)
            return {
                'format': BACKUP_FORMAT,
                'password_required': flags == BackupFlag.PASSWORD,
                'snapshot_required': flags == BackupFlag.SNAPSHOT,
                'kdf': {
                    'name': 'argon2id',
                    'time_cost': params.time_cost,
                    'memory_cost': params.memory_cost,
                    'parallelism': params.parallelism,
                },
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
        flags, salt, kdf_params = self._read_backup_header(file)
        # 预声明 backup_key：PASSWORD 派生失败或 SNAPSHOT 路径前的提前 return 会使
        # backup_key 未在 with 块内赋值，方法级 finally 仍需引用它。预声明 None 避免
        # locals().get 反射（字段重命名时静态检查无法发现）。
        backup_key: bytearray | bytes | None = None
        try:
            # 持 vault 写锁串行化恢复与改密/备份：从解密全量明文到写库全程持锁，
            # 与 create_backup 的「持锁才接触全量明文」契约统一。经公共
            # vault_write_lock 访问，不直接触碰受保护的 _lock。备份密钥（PASSWORD
            # 派生 / SNAPSHOT 读取）也在锁内解析，与 create_backup 完全对称，消除
            # SNAPSHOT 路径 is_unlocked 检查与读取之间主线程 lock() 清零 snapshot_key
            # 的竞态窗口。
            with self._vault.vault_write_lock():
                if flags == BackupFlag.PASSWORD:
                    if not backup_password:
                        return False, '请输入创建备份时设置的备份密码'
                    backup_key = MasterKeyManager.derive_backup_key(
                        backup_password, salt, kdf_params,
                    )
                else:
                    if not self._vault.is_unlocked:
                        return False, '恢复快照备份需要先解锁保险库'
                    backup_key = self._vault.snapshot_key
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
                            secure_delete_file(restore_path)
                        except OSError:
                            logger.debug("清理恢复点失败", exc_info=True)
                    raise
                finally:
                    # plaintext/data 在内层 try 成功后必然已赋值（内层 try 异常走
                    # except return，不会到达此处），直接释放明文引用，无需 locals 反射。
                    del plaintext
                    del data
                # 事务已提交，key_epoch 与 snapshot_key_enc 均已在同一事务内原子写入。
                # 在释放 vault 锁前同步内存状态（不写库），既消除事务外写库的崩溃窗口，
                # 也消除旧 snapshot_key 仍可被并发读取（snapshot_key property）的窗口。
                if new_epoch:
                    self._vault.update_key_epoch(new_epoch)
                self._vault.apply_snapshot_key(new_snapshot_key)
            # 锁外清理旧 snapshot_key 加密的快照与恢复点：仅 unlink 文件，不读取
            # snapshot_key property，故无需持锁，减少锁持有时间。
            failed_purges = self._vault.purge_snapshot_backups()
            if failed_purges:
                return True, (
                    f'恢复完成，但 {len(failed_purges)} 个旧快照未能删除'
                    '（可能被占用），建议在备份对话框手动清理以收缩泄漏面。'
                )
            return True, ''
        finally:
            # 确保 PASSWORD 派生的 backup_key 在所有退出路径（含密钥派生失败、文件
            # 过大、解密异常）都清零；SNAPSHOT 路径借用 snapshot_key 不清零。
            # backup_key 已在方法级预声明，派生异常时为 None，_zero_backup_key_if_owned 对 None 跳过。
            self._zero_backup_key_if_owned(flags, backup_key)

    @staticmethod
    def _zero_backup_key_if_owned(flags, key) -> None:
        """清零 PASSWORD 路径派生的 backup_key；SNAPSHOT 路径借用 snapshot_key 不清零。

        集中「是否应清零」判定，使 create_backup 与 _restore_current 的清零逻辑共用
        单一来源，避免未来新增备份加密 flag 时漏改其中一处。key 为 None 时跳过
        （派生阶段异常致 backup_key 未定义的兜底）。
        """
        if flags == BackupFlag.PASSWORD and key is not None:
            secure_zero_buffer(key)

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
        if not isinstance(item['is_favorite'], bool) or not isinstance(item['is_deleted'], bool):
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
            entry_id = item['entry_id']
            # 与 _validate_entries 的 ID 校验对齐：拒绝 bool/float 等伪装成 int 的类型
            if not isinstance(entry_id, int) or isinstance(entry_id, bool):
                raise ValueError('备份密码历史 entry_id 必须为整数')
            if entry_id not in entry_ids:
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
        filename = f'pre_restore_{datetime.now(timezone.utc):%Y%m%d_%H%M%S_%f}_{uuid.uuid4().hex[:8]}.cbox'
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
                secure_delete_file(expired)
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
                secure_delete_file(f)
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
        # 同事务写入消除事务外写库在崩溃时 epoch 已提交而
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
        # 事务提交后截断 WAL：clear_vault_data 删除的旧主密码密文残留在 WAL，
        # 事务内 secure_checkpoint 会跳过，须在事务外显式截断以收缩泄漏面。
        db.secure_checkpoint()
        return new_epoch, new_snapshot_key

    def _restore_categories(self, db, data: dict) -> dict:
        """重建分类，返回旧 ID 到新 ID 的映射。"""
        from .entry_manager import EntryManager
        entry_manager = EntryManager(self._vault)
        category_map = {}
        for item in data.get('categories', []):
            category = Category.from_dict(item)
            if not category.name:
                continue
            new_id = entry_manager.add_category(category, notify=False)
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
            entry = RawEntry(
                crypto_id=crypto_id,
                title=enc['title'],
                username=enc['username'],
                password=enc['password'],
                url=enc['url'],
                category_id=category_map.get(old_category),
                tags=enc['tags'],
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
                password_changed_at=(
                    item.get('password_changed_at', '')
                    or item.get('updated_at', '')
                    or item.get('created_at', '')
                    or utc_now_iso()
                ),
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
            # entry_map 命中则 crypto_id_map 必同步存在（_restore_entries 同填充），
            # 直接取而非 get 默认 ''，避免空 crypto_id 产生 AAD 不一致的密文。
            crypto_id = crypto_id_map[item['entry_id']]
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
        cancel_check: Callable[[], bool] | None = None,
    ) -> tuple[bool, str]:
        """按配置创建当前保险库的本地快速快照。

        Args:
            config: ConfigManager 实例，用于读取备份设置。
            force: 是否强制创建，忽略时间间隔检查。
            cancel_check: 可选取消探针，透传给 create_backup，使后台快照
                在隐藏到托盘或锁定时能尽快退出。

        Returns:
            由是否成功与错误信息组成的二元组，成功时错误信息为空字符串。
        """
        if not force and not config.get('auto_backup_enabled', False):
            return True, ''

        interval = config.get('auto_backup_interval_hours', 24)
        last_text = config.get('last_auto_backup_at', '')
        if not force and last_text:
            try:
                elapsed = datetime.now(timezone.utc) - datetime.fromisoformat(last_text)
                if elapsed < timedelta(hours=interval):
                    return True, ''
            except ValueError:
                # last_auto_backup_at 解析失败（损坏的时间戳）会让间隔检查每次都
                # 重新备份；记录以便运维发现配置损坏，而非静默持续冗余备份。
                logger.warning('last_auto_backup_at 解析失败，跳过间隔检查：%s', last_text)

        backup_dir = config.get('backup_directory', '')
        if backup_dir:
            try:
                backup_dir = str(validate_file_path(backup_dir))
            except ValueError:
                return False, f'备份目录路径无效: {backup_dir}'

        directory = Path(backup_dir) if backup_dir else config.data_dir / 'backups'
        # 创建并收紧权限，含用户自定义目录，避免快照全量明文以宽松 ACL 落盘
        secure_directory(directory)
        filename = f'cipherbox_snapshot_{datetime.now(timezone.utc):%Y%m%d_%H%M%S_%f}_{uuid.uuid4().hex[:8]}.cbox'
        success, error = self.create_backup(
            str(directory / filename), use_snapshot_key=True,
            cancel_check=cancel_check,
        )
        if not success:
            return False, error

        config.set('last_auto_backup_at', utc_now_iso())
        config.save()

        retention = config.get('auto_backup_retention', 10)
        snapshots = sorted(directory.glob('cipherbox_snapshot_*.cbox'), reverse=True)
        for old_file in snapshots[retention:]:
            try:
                secure_delete_file(old_file)
            except OSError:
                # 过期自动快照含全量明文，清理失败会扩大泄漏面；记录以便人工处理。
                logger.warning('清理过期自动快照失败：%s', old_file, exc_info=True)

        return True, ''
