"""CipherBox 固定格式的加密备份与恢复。

模块拆分后仅承载备份创建/恢复的核心编排逻辑：
- 头部编解码、检视、密钥派生 → :mod:`..services.backup_header_codec`
- 恢复前数据校验 → :mod:`..services.backup_validator`
- 命名常量 → :mod:`..services.backup_paths`
- 恢复点统计/清理 → :class:`.restore_point_manager.RestorePointManager`
"""

import errno
import json
import logging
import os
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any, TypedDict, cast

if TYPE_CHECKING:
    from ...config import ConfigManager
    from ...database.types import VaultDataStore
    from .entry_manager import EntryManager
    from .vault_manager import VaultManager

from ...crypto.encryption import EncryptionEngine
from ...crypto.master_key import DEFAULT_KDF_PARAMS, KEY_SIZE, MasterKeyManager
from ...exceptions import (
    BackupError,
    DecryptionError,
    PayloadTooLargeError,
    VaultKeyEpochMismatchError,
)
from ...models import (
    Category,
    RawEntry,
)
from ...utils.file_security import (
    atomic_write,
    secure_delete_file,
    secure_directory,
    validate_file_path,
)
from ...utils.format import utc_now_iso
from ...utils.memory import secure_zero_buffer
from ...utils.purge_files import secure_purge
from ..services.backup_header_codec import (
    BACKUP_FORMAT,
    BACKUP_SALT_SIZE,
    MAX_BACKUP_FILE_SIZE,
    MAX_BACKUP_PAYLOAD_SIZE,
    BackupFlag,
    enforce_kdf_floor,
    header_aad,
    read_backup_header,
    write_backup_header,
    zero_backup_key_if_owned,
)
from ..services.backup_paths import (
    BACKUPS_DIR_NAME,
    PRE_RESTORE_GLOB,
    PRE_RESTORE_PREFIX,
    SNAPSHOT_GLOB,
    SNAPSHOT_PREFIX,
    build_backup_filename,
)
from ..services.backup_validator import (
    MAX_BACKUP_ENTRIES,
    MAX_HISTORY_PER_ENTRY,
    REQUIRED_CATEGORY_KEYS,
    REQUIRED_ENTRY_KEYS,
    REQUIRED_HISTORY_KEYS,
    validate_restore_data,
)
from ..services.crypto_utils import (
    build_encrypted_entry_fields,
    decrypt_entry_to_portable_dict,
    decrypt_field,
    encrypt_field,
    require_vault_key,
)
from ..services.metadata_signer import VAULT_META_SIGNED_KEYS, MetadataSigner
from ..services.password_service import PasswordService
from .restore_point_manager import MAX_RESTORE_POINTS, RestorePointManager

logger = logging.getLogger(__name__)


class PortableCategory(TypedDict):
    """备份载荷中的分类项（与 Category.to_dict 对称，不含 metadata_mac：恢复时重签）。"""

    id: int
    name: str
    icon_char: str
    color: str
    sort_order: int
    created_at: str


class PortableEntry(TypedDict):
    """备份载荷中的条目项（与 decrypt_entry_to_portable_dict 输出对称）。

    键集与 backup_validator.validate_entry_fields 的 require_keys 精确匹配，
    故恢复消费端可安全直接索引（无 .get 默认值死分支）。
    """

    id: int
    crypto_id: str
    title: str
    username: str
    password: str
    url: str
    category_id: int | None
    tags: str
    notes: str
    custom_fields: list[dict[str, Any]]
    is_favorite: bool
    is_deleted: bool
    password_strength: int
    entry_type: str
    totp_secret: str
    created_at: str
    updated_at: str
    deleted_at: str
    password_changed_at: str


class PortableHistoryItem(TypedDict):
    """备份载荷中的密码历史项。"""

    entry_id: int
    password: str
    changed_at: str


class PortableBackup(TypedDict):
    """已校验的备份载荷结构（validate_restore_data 通过后 cast 使用）。"""

    format: str
    version: int
    created_at: str
    categories: list[PortableCategory]
    entries: list[PortableEntry]
    password_history: list[PortableHistoryItem]


# 启动期一致性断言：Portable* TypedDict 字段集须与 backup_validator.REQUIRED_*_KEYS
# 完全一致。新增字段时若只改 TypedDict 而漏改校验键集（或反之），模块加载即失败，
# 而非让恢复路径静默放行残缺载荷。用显式 raise 而非 assert：python -O 会剔除 assert。
_PORTABLE_KEY_ASSERTS = (
    (set(PortableCategory.__annotations__), REQUIRED_CATEGORY_KEYS, 'PortableCategory'),
    (set(PortableEntry.__annotations__), REQUIRED_ENTRY_KEYS, 'PortableEntry'),
    (set(PortableHistoryItem.__annotations__), REQUIRED_HISTORY_KEYS, 'PortableHistoryItem'),
)
for _actual, _expected, _name in _PORTABLE_KEY_ASSERTS:
    if _actual != _expected:
        raise RuntimeError(
            f'{_name} 字段集与 backup_validator 校验键集不一致：'
            f'{sorted(_actual)} != {sorted(_expected)}'
        )


def _user_friendly_error(exc: Exception) -> str:
    """将异常映射为用户友好的错误消息。

    按异常类型精确匹配映射，不依赖英文错误文本，避免子串误匹配。
    未识别的异常类型返回通用提示，不向用户暴露内部异常类名（类名经调用方日志记录）。
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
    if isinstance(exc, ValueError):
        # validate_file_path 等抛出的 ValueError 已携带面向用户的中文消息，直接展示；
        # 其余 ValueError 退回通用提示，不向用户暴露内部异常细节。
        return str(exc) or '输入数据无效'
    # PayloadTooLargeError(BackupError 子类)已由上方 BackupError 分支捕获并返回 str
    return '操作失败，请检查文件和磁盘'


class _BackupCancelled(Exception):
    """内部哨兵异常：cancel_check 触发时中止备份采集，编排层捕获后返回 None。

    用异常而非返回值传递「取消」，使采集子方法保持单一返回类型（tuple），
    编排层 ``_collect_portable_data`` 统一在 try/except 中归一为 None。
    """


# payload 字节估算的固定开销常量（JSON 键名 + 结构开销的粗略上界），供
# _collect_portable_* 增量估算复用，单一来源避免三处魔术数漂移。
_CATEGORY_OVERHEAD_BYTES = 128
_ENTRY_OVERHEAD_BYTES = 512
_HISTORY_OVERHEAD_BYTES = 64


class BackupRestoreManager:
    """创建可移植的加密备份并以事务方式恢复。"""

    def __init__(
        self,
        vault_manager: 'VaultManager',
        entry_manager: 'EntryManager',
    ) -> None:
        self._vault = vault_manager
        # 复用调用方（MainWindow）持有的 EntryManager 单例，共享分类名缓存，
        # 避免备份/恢复时新建临时实例导致分类名重复解密与缓存双份明文驻留。
        self._entry_mgr = entry_manager
        self._restore_points = RestorePointManager(vault_manager)

    @property
    def _key(self) -> bytes:
        return require_vault_key(self._vault)

    @property
    def restore_points(self) -> RestorePointManager:
        """恢复点统计/清理管理器，供 UI 与清理路径访问。"""
        return self._restore_points

    @staticmethod
    def _check_payload_limit(estimated_size: int) -> None:
        """估算的 payload 字节数超限时抛 PayloadTooLargeError，供采集路径复用。"""
        if estimated_size > MAX_BACKUP_PAYLOAD_SIZE:
            raise PayloadTooLargeError('备份数据过大')

    def _collect_portable_data(
        self, cancel_check: Callable[[], bool] | None = None,
    ) -> dict[str, Any] | None:
        """收集备份数据：解密所有字段为明文，构建可移植字典。

        编排条目与密码历史的采集：二者各自增量估算 payload 大小，超限抛
        :class:`PayloadTooLargeError`；``cancel_check`` 触发时经
        :class:`_BackupCancelled` 中止并整体返回 None（调用方据此不产出残缺备份）。

        返回结构的嵌套 entries/categories/password_history 项值类型混合，故标注
        ``dict[str, Any]``（结构由 :func:`validate_restore_data` 校验）。
        """
        key = self._key
        categories = [
            category.to_dict()
            for category in self._entry_mgr.categories.get_categories()
        ]
        # 基于字段原始字节长度的粗略估算，避免逐条 json.dumps 双重序列化开销
        estimated_size = sum(
            len(c.get('name', '').encode('utf-8')) + _CATEGORY_OVERHEAD_BYTES
            for c in categories
        )
        try:
            entries, entry_count, estimated_size = self._collect_portable_entries(
                key, cancel_check, estimated_size,
            )
            history, _ = self._collect_portable_history(
                key, cancel_check, entry_count, estimated_size,
            )
        except _BackupCancelled:
            return None
        return {
            'format': BACKUP_FORMAT,
            'version': 1,
            'created_at': utc_now_iso(),
            'categories': categories,
            'entries': entries,
            'password_history': history,
        }

    def _collect_portable_entries(
        self,
        key: bytes,
        cancel_check: Callable[[], bool] | None,
        estimated_size: int,
    ) -> tuple[list[dict[str, Any]], int, int]:
        """采集并解密全部条目为可移植字典，增量估算 payload 大小。

        返回 ``(entries, entry_count, estimated_size)``。``cancel_check`` 触发时抛
        :class:`_BackupCancelled`（编排层捕获）；完整性失败抛 :class:`BackupError`；
        估算超限抛 :class:`PayloadTooLargeError`。
        """
        raw_entries = self._vault.db.get_entries(include_deleted=True)
        if len(raw_entries) > MAX_BACKUP_ENTRIES:
            raise PayloadTooLargeError('备份条目数量超出限制')
        entries: list[dict[str, Any]] = []
        for raw in raw_entries:
            if cancel_check and cancel_check():
                raise _BackupCancelled
            portable_item = decrypt_entry_to_portable_dict(raw, key, include_secrets=True)
            if portable_item is None:
                raise BackupError(f'条目 {raw.id} 完整性校验或解密失败，备份已中止')
            # 基于字段原始长度的粗略估算，每条目约 512 字节固定开销。估算覆盖全部
            # 将进入 JSON payload 的字段，以密文长度作上界（base64 密文 ≥ 明文），
            # 避免大 notes 或 custom_fields 场景下粗估漏判、直至序列化才产生内存峰值。
            estimated_size += (
                len(raw.title.encode('utf-8'))
                + len((raw.username or '').encode('utf-8'))
                + len((raw.url or '').encode('utf-8'))
                + len((raw.tags or '').encode('utf-8'))
                + len((raw.notes or '').encode('utf-8'))
                + len(raw.custom_fields_db_value.encode('utf-8'))
                + len((raw.totp_secret or '').encode('utf-8'))
                + _ENTRY_OVERHEAD_BYTES
            )
            self._check_payload_limit(estimated_size)
            entries.append(portable_item)
        return entries, len(raw_entries), estimated_size

    def _collect_portable_history(
        self,
        key: bytes,
        cancel_check: Callable[[], bool] | None,
        entry_count: int,
        estimated_size: int,
    ) -> tuple[list[dict[str, Any]], int]:
        """采集并解密密码历史，增量估算 payload 大小。

        返回 ``(history, estimated_size)``。``entry_count`` 用于历史条数上限校验
       （每条目平均历史数不超过 :data:`MAX_HISTORY_PER_ENTRY`）。
        """
        history_rows = self._vault.db.get_all_password_history()
        if len(history_rows) > entry_count * MAX_HISTORY_PER_ENTRY:
            raise PayloadTooLargeError('密码历史数量超出限制')
        history: list[dict[str, Any]] = []
        for history_row in history_rows:
            if cancel_check and cancel_check():
                raise _BackupCancelled
            try:
                pwd = decrypt_field(
                    history_row.old_password_enc, key,
                    history_row.entry_crypto_id, 'password', strict=True,
                )
            except DecryptionError:
                raise BackupError(
                    f'条目 {history_row.entry_id} 的密码历史解密失败，备份已中止'
                ) from None
            history.append({
                'entry_id': history_row.entry_id,
                'password': pwd,
                'changed_at': history_row.changed_at,
            })
            estimated_size += (
                len(history_row.changed_at.encode('utf-8'))
                + len((history_row.old_password_enc or '').encode('utf-8'))
                + _HISTORY_OVERHEAD_BYTES
            )
            self._check_payload_limit(estimated_size)
        return history, estimated_size

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

        锁获取与核心逻辑分离：核心逻辑抽取到 :meth:`_create_backup_locked`，供
        :meth:`_create_restore_point` 在已持锁上下文复用，避免经本方法再次获取
        RLock 的嵌套重入（虽 RLock 可重入，但契约脆弱）。
        """
        try:
            filepath = str(validate_file_path(filepath))
            # 备份密码是离线攻击（窃取 .cbox 后暴力破解）的唯一屏障，须与主密码
            # 同等强度。UI 已校验，业务层兜底防止绕过 UI（如未来 CLI/自动化入口）
            # 直接调用 create_backup 设置极弱备份密码。
            if backup_password:
                valid, error = PasswordService.validate_master_password(
                    backup_password, label='备份密码',
                )
                if not valid:
                    return False, error
            # 持 vault 锁与改密重加密串行：避免后台备份读全量明文期间密钥被轮换，
            # 导致解密失败被静默跳过而产出残缺备份。备份密钥也在锁内解析，避免
            # snapshot_key 在释放锁后、加密前被主线程 lock() 清零的竞态。
            with self._vault.vault_write_lock():
                return self._create_backup_locked(
                    filepath, backup_password, use_snapshot_key, cancel_check,
                )
        except Exception as exc:
            logger.error("备份失败: %s", exc, exc_info=True)
            return False, _user_friendly_error(exc)

    def _create_backup_locked(
        self,
        filepath: str,
        backup_password: str | None,
        use_snapshot_key: bool,
        cancel_check: Callable[[], bool] | None,
    ) -> tuple[bool, str]:
        """备份核心逻辑；调用方须已持有 ``vault_write_lock``。

        持锁契约：snapshot_key 在锁内读取，备份密钥全程在锁内解析与清零，与
        :meth:`_restore_current` 的「持锁才接触全量明文」契约统一。
        """
        t0 = time.monotonic()
        salt = os.urandom(BACKUP_SALT_SIZE)
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
            raise BackupError('必须指定备份密码或使用快照密钥')
        try:
            payload = json.dumps(data, ensure_ascii=False).encode('utf-8')
            del data
            if len(payload) > MAX_BACKUP_PAYLOAD_SIZE:
                raise PayloadTooLargeError('备份数据过大')
            encrypted = EncryptionEngine.encrypt_bytes(
                payload, backup_key, header_aad(flags, salt, DEFAULT_KDF_PARAMS)
            )
            del payload
            def _write_backup_file(file: IO[bytes]) -> bool:
                write_backup_header(file, flags, salt, DEFAULT_KDF_PARAMS)
                file.write(encrypted)
                return True

            atomic_write(Path(filepath), _write_backup_file)
        finally:
            zero_backup_key_if_owned(flags, backup_key)
        logger.info("备份创建完成 (%.1fms)", (time.monotonic() - t0) * 1000)
        return True, ''

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
        except Exception as exc:
            # 所有异常（validate_file_path 的 ValueError、BackupError、OSError 等）统一
            # 经 _user_friendly_error 翻译为用户友好消息。原先独立的 except ValueError
            # 分支注释声称透传 _restore_current 的消息，但 _restore_current 只 return 不
            # raise，实际仅捕获 validate_file_path 的 ValueError——该职责已由
            # _user_friendly_error 的 ValueError 分支承接，消除「未来 _restore_current
            # 误抛 ValueError 会绕过翻译直暴露内部消息」的风险。
            logger.error("恢复失败: %s", exc, exc_info=True)
            return False, _user_friendly_error(exc)

    def _restore_current(self, file: IO[bytes], backup_password: str | None) -> tuple[bool, str]:
        flags, salt, kdf_params = read_backup_header(file)
        # 防 KDF 参数降级：在派生密钥前拒绝被篡改为更弱参数的备份头
        enforce_kdf_floor(kdf_params)
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
                        encrypted, backup_key, header_aad(flags, salt, kdf_params)
                    )
                    if len(plaintext) > MAX_BACKUP_PAYLOAD_SIZE:
                        return False, '备份解密数据过大'
                    data = json.loads(plaintext.decode('utf-8'))
                except Exception:
                    logger.debug("备份读取或解密失败", exc_info=True)
                    return False, '备份密码错误或文件已损坏'
                if not isinstance(data, dict) or not isinstance(data.get('entries'), list):
                    return False, '备份数据结构无效'
                validate_restore_data(data)
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
                # apply_snapshot_key 总复制到 KeyManager，此后局部 new_snapshot_key
                # 不再需要，立即清零（含 update_key_epoch 异常路径）收缩崩溃 dump 窗口。
                try:
                    if new_epoch:
                        self._vault.update_key_epoch(new_epoch)
                    self._vault.apply_snapshot_key(new_snapshot_key)
                finally:
                    secure_zero_buffer(new_snapshot_key)
            # 锁外清理旧 snapshot_key 加密的快照与恢复点：仅 unlink 文件，不读取
            # snapshot_key property，故无需持锁，减少锁持有时间。
            failed_purges = self._vault.purge_snapshot_backups()
            if failed_purges:
                # 区分明文恢复点（pre_restore_*，含恢复前全部条目明文）与普通快照：
                # 恢复点未能删除是更严重的明文泄漏面，需显著警告并指引重启清理，
                # 而非笼统归并到「旧快照」让用户在「恢复完成」措辞下忽视风险。
                restore_point_failed = any(
                    p.name.startswith('pre_restore_') for p in failed_purges
                )
                if restore_point_failed:
                    return True, (
                        f'恢复完成，但 {len(failed_purges)} 个含恢复前明文的快照'
                        '未能删除（可能被占用）。为避免明文泄漏，请关闭可能占用'
                        '该文件的程序后重启应用以自动清理。'
                    )
                return True, (
                    f'恢复完成，但 {len(failed_purges)} 个旧快照未能删除'
                    '（可能被占用），建议在备份对话框手动清理以收缩泄漏面。'
                )
            return True, ''
        finally:
            # 确保 PASSWORD 派生的 backup_key 在所有退出路径（含密钥派生失败、文件
            # 过大、解密异常）都清零；SNAPSHOT 路径借用 snapshot_key 不清零。
            # backup_key 已在方法级预声明，派生异常时为 None，zero_backup_key_if_owned 对 None 跳过。
            zero_backup_key_if_owned(flags, backup_key)

    def _create_restore_point(self) -> Path | None:
        """创建恢复前安全快照，返回快照文件路径用于失败时清理，创建失败返回 None。"""
        directory = self._vault.data_dir / BACKUPS_DIR_NAME
        # 恢复点是恢复失败回滚的安全网，优先于权限严格性：data_dir 已由 config
        # 以 strict 创建，backups 子目录继承收紧后的父权限；宁可保留安全网也
        # 不因 ACL 失败放弃恢复点（短期明文，恢复后即清理）。
        secure_directory(directory)
        filename = build_backup_filename(PRE_RESTORE_PREFIX)
        target_path = directory / filename
        # 已在 _restore_current 的 vault_write_lock 内，直接调用持锁版本，避免经
        # create_backup 再次获取 RLock 的嵌套重入。
        try:
            success, error = self._create_backup_locked(
                str(target_path), None, True, None,
            )
        except Exception:
            # _create_backup_locked 的 atomic_write 在 os.replace 成功后若
            # secure_file 失败会抛异常；此时 target_path 可能已写出含恢复前全部
            # 明文的文件（atomic_write 仅清理 .tmp，不清理已 replace 到位的目标）。
            # 立即安全删除避免明文泄漏面扩大，再向上抛出原异常。
            self._safe_delete_restore_point(target_path)
            raise
        if not success:
            raise BackupError(f'无法创建恢复前安全快照：{error}')
        # 按文件名降序保留最新 MAX_RESTORE_POINTS 个恢复点，删除过期项；删除失败
        # 仅告警（恢复点含全量明文，残留由调用方据创建结果决定是否重试清理）。
        secure_purge(
            [directory], [PRE_RESTORE_GLOB],
            keep=MAX_RESTORE_POINTS, collect_failures=False,
        )
        return target_path

    @staticmethod
    def _safe_delete_restore_point(path: Path) -> None:
        """异常路径清理恢复点：删除失败仅告警，绝不掩盖向上抛出的原异常。

        恢复点含恢复前全部条目明文，删除失败意味着泄漏面未收缩，需可见日志；
        但调用方（如 _create_restore_point）的原异常更需向上传递，故此处吞掉
        删除异常仅记录。
        """
        try:
            secure_delete_file(path)
        except OSError:
            logger.warning('异常路径清理恢复点失败：%s', path, exc_info=True)

    def _restore_data(self, data: dict[str, Any]) -> tuple[str, bytearray]:
        db = self._vault.db
        key = self._key
        # validate_restore_data 已校验载荷结构，cast 为 PortableBackup 使后续 _restore_*
        # 经 TypedDict 直接索引（键集由 require_keys 精确匹配保证），消除 dict[str, Any]
        # 下 .get(default) 的死分支与字段拼写静默。
        backup = cast(PortableBackup, data)
        # snapshot_key 与 key_epoch 在同一事务内轮换：恢复整体替换数据后，旧 snapshot_key
        # 加密的快照含恢复前明文，轮换使其失效以收缩泄漏面，与改密路径语义一致。
        # 同事务写入消除事务外写库在崩溃时 epoch 已提交而
        # snapshot_key_enc 未写入的不一致窗口。
        # bytearray 持有以便原地清零：成功路径 return 交调用方，apply_snapshot_key
        # 总复制到 KeyManager 后由调用方清零自己的引用；失败路径在 finally 清零。
        new_snapshot_key = bytearray(os.urandom(KEY_SIZE))
        new_epoch = ''
        success = False
        try:
            with self._vault.epoch_guarded_transaction(operation='恢复'):
                db.clear_vault_data()
                category_map = self._restore_categories(backup)
                entry_map, crypto_id_map = self._restore_entries(db, backup, key, category_map)
                self._restore_history(db, backup, key, entry_map, crypto_id_map)
                # 轮换 key_epoch 防止旧会话写入恢复后的数据
                new_epoch = uuid.uuid4().hex
                db.set_meta('key_epoch', new_epoch)
                db.set_meta('snapshot_key_enc', self._vault.encrypt_snapshot_key(new_snapshot_key))
                # key_epoch 轮换后重算 vault_meta_mac（签名含 key_epoch），保持 unlock
                # 校验一致；恢复不改凭据字段（salt/verify/KDF），故读回当前值重算即可。
                meta_snapshot = db.get_meta_batch(list(VAULT_META_SIGNED_KEYS))
                db.set_meta(
                    'vault_meta_mac',
                    MetadataSigner.compute_vault_meta_mac(meta_snapshot, key),
                )
            # 事务提交后截断 WAL：clear_vault_data 删除的旧主密码密文残留在 WAL，
            # 事务内 secure_checkpoint 会跳过，须在事务外显式截断以收缩泄漏面。
            # 截断失败非致命（数据已提交完整，WAL 残留仅为泄漏面问题），单独捕获
            # 避免 finally 因 success 未置 True 而清零 new_snapshot_key——否则调用方
            # 拿不到已落库 snapshot_key_enc 对应的密钥，当前会话 snapshot 状态与已
            # 提交的库不一致。与改密路径（vault_manager._re_encrypt_all）secure_checkpoint
            # 的非致命处理对称。
            try:
                db.secure_checkpoint()
            except Exception:
                logger.warning('恢复后 WAL 安全截断失败（非致命）', exc_info=True)
            success = True
            return new_epoch, new_snapshot_key
        finally:
            # 事务失败（success 未置 True）时局部 snapshot_key 未被 apply_snapshot_key
            # 接管，原地清零收缩崩溃 dump 窗口；成功路径由调用方在 apply 后清零自己的引用。
            # 用 try/finally + 标志位替代原先 except Exception + raise，避免过宽捕获掩盖
            # 本应快速失败的编程错误（如 KeyError/TypeError）。
            if not success:
                secure_zero_buffer(new_snapshot_key)

    def _restore_categories(self, backup: PortableBackup) -> dict[int, int]:
        """重建分类，返回旧 ID 到新 ID 的映射。"""
        entry_manager = self._entry_mgr
        category_map: dict[int, int] = {}
        for item in backup['categories']:
            # PortableCategory(TypedDict)经 cast 桥接到 from_dict 的 dict 参数：
            # pyright 严格模式不允许 TypedDict 隐式赋给 dict（结构化类型限制），
            # validator 已保证键集，cast 安全。
            category = Category.from_dict(cast(dict[str, Any], item))
            if not category.name:
                continue
            new_id = entry_manager.categories.add_category(category, notify=False)
            # item['id'] 由 validator 校验为 int（非 None），直接索引建立映射。
            category_map[item['id']] = new_id
        return category_map

    @staticmethod
    def _restore_entries(
        db: 'VaultDataStore',
        backup: PortableBackup,
        key: bytes,
        category_map: dict[int, int],
    ) -> tuple[dict[int, int], dict[int, str]]:
        """重建条目，加密敏感字段，返回 (entry_map, crypto_id_map)。

        全部条目先在内存构建为 RawEntry，再经 ``add_entries_batch`` 一次性
        executemany 写入，避免逐条 INSERT+commit 的 N 次 fsync 拖长恢复期间
        ``vault_write_lock`` 的持锁时间（UI 冻结窗口）。

        item 经 validator 校验类型/长度，直接索引 PortableEntry 字段，消除原先
        .get(default) 的死分支（键集由 require_keys 精确匹配保证存在）。
        """
        items = backup['entries']
        entries: list[RawEntry] = []
        for item in items:
            # PortableEntry(TypedDict)经 cast 桥接到 build_encrypted_entry_fields 的
            # dict 参数（同 from_dict，TypedDict 不隐式兼容 dict）。
            enc = build_encrypted_entry_fields(cast(dict[str, Any], item), key, item['crypto_id'])
            entries.append(RawEntry(
                crypto_id=item['crypto_id'],
                title=enc['title'],
                username=enc['username'],
                password=enc['password'],
                url=enc['url'],
                category_id=(
                    category_map.get(item['category_id'])
                    if item['category_id'] is not None
                    else None
                ),
                tags=enc['tags'],
                notes=enc['notes'],
                custom_fields=enc['custom_fields'],
                is_favorite=item['is_favorite'],
                is_deleted=item['is_deleted'],
                password_strength=item['password_strength'],
                entry_type=item['entry_type'],
                totp_secret=enc['totp_secret'],
                created_at=item['created_at'],
                updated_at=item['updated_at'],
                deleted_at=item['deleted_at'],
                password_changed_at=(
                    item['password_changed_at']
                    or item['updated_at']
                    or item['created_at']
                    or utc_now_iso()
                ),
            ))
        crypto_id_to_new_id = db.add_entries_batch(entries, preserve_metadata=True)
        entry_map: dict[int, int] = {}
        crypto_id_map: dict[int, str] = {}  # 旧 entry_id 到 crypto_id 的映射
        for item, entry in zip(items, entries, strict=True):
            if item.get('id') is not None:
                entry_map[item['id']] = crypto_id_to_new_id[entry.crypto_id]
                crypto_id_map[item['id']] = entry.crypto_id
        return entry_map, crypto_id_map

    @staticmethod
    def _restore_history(
        db: 'VaultDataStore',
        backup: PortableBackup,
        key: bytes,
        entry_map: dict[int, int],
        crypto_id_map: dict[int, str],
    ) -> None:
        """重建密码历史，按 entry_id 分组批量写入并统一截断。"""
        history_by_entry: dict[int, list[tuple[str, str]]] = {}
        for item in backup['password_history']:
            new_entry_id = entry_map.get(item['entry_id'])
            if not new_entry_id:
                continue
            # entry_map 命中则 crypto_id_map 必同步存在（_restore_entries 同填充），
            # 直接取而非 get 默认 ''，避免空 crypto_id 产生 AAD 不一致的密文。
            crypto_id = crypto_id_map[item['entry_id']]
            ciphertext = encrypt_field(item['password'], key, crypto_id, 'password')
            if ciphertext:
                history_by_entry.setdefault(new_entry_id, []).append(
                    (ciphertext, item['changed_at'])
                )
        for entry_id, items in history_by_entry.items():
            db.add_password_history_batch(entry_id, items)

    def maybe_auto_backup(
        self,
        config: 'ConfigManager',
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

        directory = Path(backup_dir) if backup_dir else config.data_dir / BACKUPS_DIR_NAME
        # 创建并收紧权限（strict）：自动快照含全量明文，ACL 失败时宁可中止备份
        # 也不以宽松权限落盘，让用户经返回的错误感知权限问题。
        try:
            secure_directory(directory, strict=True)
        except OSError as exc:
            return False, f'无法收紧备份目录权限：{exc}'
        filename = build_backup_filename(SNAPSHOT_PREFIX)
        success, error = self.create_backup(
            str(directory / filename), use_snapshot_key=True,
            cancel_check=cancel_check,
        )
        if not success:
            return False, error

        config.set('last_auto_backup_at', utc_now_iso())
        config.save()

        retention = config.get('auto_backup_retention', 10)
        # 按文件名降序保留最新 retention 个自动快照；过期快照含全量明文，删除失败
        # 会扩大泄漏面，secure_purge 收集失败仅告警以便人工处理。
        secure_purge([directory], [SNAPSHOT_GLOB], keep=retention, collect_failures=False)

        return True, ''
