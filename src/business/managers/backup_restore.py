"""CipherBox 固定格式的加密备份与恢复。

模块拆分后仅承载备份创建/恢复的核心编排逻辑：
- 头部编解码、检视、密钥派生 → :mod:`..services.backup_header_codec`
- 恢复前数据校验 → :mod:`..services.backup_validator`
- 命名常量 → :mod:`..services.backup_paths`
- 恢复点统计/清理 → :class:`.restore_point_manager.RestorePointManager`
"""

import json
import logging
import os
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from ...config import ConfigManager
    from .entry_manager import EntryManager
    from .vault_manager import VaultManager

from ...config import DEFAULT_CONFIG
from ...crypto.encryption import EncryptionEngine
from ...crypto.master_key import DEFAULT_KDF_PARAMS, KEY_SIZE, MasterKeyManager
from ...database.types import EntryQuery
from ...exceptions import (
    BackupError,
    DecryptionError,
    PayloadTooLargeError,
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
from ..services.auto_backup_policy import (
    is_auto_backup_due,
    purge_expired_auto_backups,
)
from ..services.backup_collector import collect_portable_data
from ..services.backup_header_codec import (
    BACKUP_SALT_SIZE,
    MAX_BACKUP_FILE_SIZE,
    MAX_BACKUP_PAYLOAD_SIZE,
    BackupFlag,
    derive_backup_key,
    enforce_kdf_ceiling,
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
    SNAPSHOT_PREFIX,
    build_backup_filename,
)
from ..services.backup_payload import PortableBackup, PreparedBackup
from ..services.backup_rebuilder import (
    restore_categories,
    restore_entries,
    restore_history,
)
from ..services.backup_validator import (
    MAX_BACKUP_ENTRIES,
    validate_restore_data,
)
from ..services.crypto_utils import require_vault_key
from ..services.error_messages import to_user_message
from ..services.metadata_signer import VAULT_META_SIGNED_KEYS, MetadataSigner
from ..services.password_service import PasswordService
from .restore_point_manager import MAX_RESTORE_POINTS, RestorePointManager

logger = logging.getLogger(__name__)


class BackupRestoreManager:
    """创建可移植的加密备份并以事务方式恢复。"""

    def __init__(
        self,
        vault_manager: 'VaultManager',
        entry_manager: 'EntryManager',
    ) -> None:
        self._vault = vault_manager
        # 复用调用方持有的 EntryManager 单例，共享分类名缓存，避免重复解密与双份明文驻留。
        self._entry_mgr = entry_manager
        self._restore_points = RestorePointManager(vault_manager)

    @property
    def _key(self) -> bytes:
        return require_vault_key(self._vault)

    @property
    def restore_points(self) -> RestorePointManager:
        """恢复点统计/清理管理器，供 UI 与清理路径访问。"""
        return self._restore_points

    def create_backup(
        self,
        filepath: str,
        backup_password: str | None = None,
        use_snapshot_key: bool = False,
        cancel_check: Callable[[], bool] | None = None,
    ) -> tuple[bool, str]:
        """创建加密备份；密码备份可跨安装恢复，快照使用稳定快照密钥。

        ``cancel_check`` 在全量解密循环中周期调用，返回真值时中止备份。

        A4（备份锁外解密）：``vault_write_lock`` 仅持有快速 prepare 阶段（DB 读 +
        snapshot_key 副本采集 + 数量校验），全量解密与 PASSWORD 密钥派生（Argon2id）
        推迟到锁外 :meth:`_finalize_backup`。主线程 ``lock()`` 经 ``_shutdown_workers``
        → ``cancel_check`` 中止备份后才取锁清零密钥（worker 全程 join 后方清零），
        故 finalize 锁外解密期间主密钥不会被并发清零；snapshot_key 取 bytes 副本
        （property 返回拷贝），锁外使用不受 KeyManager 内部 bytearray 清零影响。

        ``_create_backup_locked`` 保留为持锁全流程入口，供 :meth:`_create_restore_point`
        在已持锁上下文复用（恢复点快照体积小，无需 A4 优化）。
        """
        try:
            filepath = str(validate_file_path(filepath))
            # 备份密码是离线攻击（窃取 .cbox 后暴力破解）的唯一屏障，须与主密码
            # 同等强度。UI 已校验，业务层兜底防止绕过 UI（如未来 CLI/自动化入口）
            # 直接调用 create_backup 设置极弱备份密码。强度校验在锁前完成。
            if backup_password:
                valid, error = PasswordService.validate_master_password(
                    backup_password, label='备份密码',
                )
                if not valid:
                    return False, error
            # 锁内仅做快速 prepare（DB 读 + snapshot_key 副本采集），全量解密与密钥
            # 派生推迟到锁外 finalize，缩短 vault_write_lock 持有时间，使主线程 lock()
            # 经 cancel_check 及时中止备份而非等待全量解密。
            with self._vault.vault_write_lock():
                prepared = self._prepare_backup_locked(
                    filepath, backup_password, use_snapshot_key,
                )
            return self._finalize_backup(prepared, cancel_check)
        except Exception as exc:
            logger.error("备份失败: %s", exc, exc_info=True)
            return False, to_user_message(exc, default='操作失败，请检查文件和磁盘。')

    def _create_backup_locked(
        self,
        filepath: str,
        backup_password: str | None,
        use_snapshot_key: bool,
        cancel_check: Callable[[], bool] | None,
    ) -> tuple[bool, str]:
        """备份全流程；调用方须已持有 ``vault_write_lock``。

        持锁顺序执行 prepare + finalize，供 :meth:`_create_restore_point` 在已持锁
        上下文复用。亦为测试 monkeypatch 拦截恢复点创建的桩点
        （见 test_restore_point_cleaned_on_creation_exception）。
        """
        prepared = self._prepare_backup_locked(filepath, backup_password, use_snapshot_key)
        return self._finalize_backup(prepared, cancel_check)

    def _prepare_backup_locked(
        self,
        filepath: str,
        backup_password: str | None,
        use_snapshot_key: bool,
    ) -> PreparedBackup:
        """锁内快速采集 finalize 所需全部输入；调用方须已持有 ``vault_write_lock``。

        仅完成需持锁串行的快速操作——生成 salt、读 raw_entries/history_rows/
        categories、数量上限校验、确定 flags、SNAPSHOT 路径取 snapshot_key 副本。
        PASSWORD 密钥派生（Argon2id）与全量解密推迟到锁外 :meth:`_finalize_backup`，
        缩短 ``lock()`` 经 cancel_check 中止前的阻塞窗口。

        snapshot_key 经 property 取 bytes 副本，锁外 finalize 持此副本加密，
        不受 KeyManager 内部 bytearray 清零影响。
        """
        salt = os.urandom(BACKUP_SALT_SIZE)
        raw_entries = self._vault.db.get_entries(EntryQuery(include_deleted=True))
        # 数量上限在锁内预判（快速失败，避免锁外 finalize 才抛错白白多持锁时间）；
        # _collect_portable_entries 收到预读 raw 时仍保留同名校验作防御性冗余。
        if len(raw_entries) > MAX_BACKUP_ENTRIES:
            raise PayloadTooLargeError('备份条目数量超出限制')
        history_rows = self._vault.db.get_all_password_history()
        categories = [
            category.to_dict()
            for category in self._entry_mgr.categories.get_categories()
        ]
        snapshot_key: bytes | None
        if backup_password:
            flags = BackupFlag.PASSWORD
            snapshot_key = None
        elif use_snapshot_key:
            flags = BackupFlag.SNAPSHOT
            snapshot_key = self._vault.snapshot_key
        else:
            raise BackupError('必须指定备份密码或使用快照密钥')
        return PreparedBackup(
            filepath=filepath,
            salt=salt,
            flags=flags,
            backup_password=backup_password,
            snapshot_key=snapshot_key,
            raw_entries=raw_entries,
            history_rows=history_rows,
            categories=categories,
        )

    def _finalize_backup(
        self,
        prepared: PreparedBackup,
        cancel_check: Callable[[], bool] | None,
    ) -> tuple[bool, str]:
        """锁外完成密钥派生、全量解密、加密与落盘（A4：缩短 vault_write_lock 持有）。

        PASSWORD 路径在此派生 backup_key；SNAPSHOT 路径用 prepared 锁内取的 snapshot_key
        副本。``cancel_check`` 在解密循环中及时中止。AAD、header 写入、payload/数量上限
        与原持锁实现完全一致，备份格式不变。backup_key 的清零在 finally 完成，PASSWORD
        路径派生密钥在所有退出路径均被清零；SNAPSHOT 路径借用 snapshot_key 不清零。
        """
        t0 = time.monotonic()
        backup_key: bytes | bytearray
        if prepared.flags == BackupFlag.PASSWORD:
            password = prepared.backup_password
            # prepare 已保证 PASSWORD 路径 backup_password 非 None；此处显式检查替代
            # assert（python -O 下 assert 跳过），满足类型 narrow 与意外状态防御。
            if password is None:
                raise BackupError('备份密码不可用')
            backup_key = derive_backup_key(password, prepared.salt)
        else:
            snapshot_key = prepared.snapshot_key
            if snapshot_key is None:
                raise BackupError('快照密钥不可用')
            backup_key = snapshot_key
        try:
            data = collect_portable_data(
                self._key,
                self._vault.db,
                self._entry_mgr,
                cancel_check=cancel_check,
                raw_entries=prepared.raw_entries,
                history_rows=prepared.history_rows,
                categories=prepared.categories,
            )
            if data is None:
                return False, '备份已取消'
            payload = json.dumps(data, ensure_ascii=False).encode('utf-8')
            del data
            if len(payload) > MAX_BACKUP_PAYLOAD_SIZE:
                raise PayloadTooLargeError('备份数据过大')
            encrypted = EncryptionEngine.encrypt_bytes(
                payload, backup_key,
                header_aad(prepared.flags, prepared.salt, DEFAULT_KDF_PARAMS),
            )
            del payload
            def _write_backup_file(file: IO[bytes]) -> bool:
                write_backup_header(
                    file, prepared.flags, prepared.salt, DEFAULT_KDF_PARAMS,
                )
                file.write(encrypted)
                return True

            atomic_write(Path(prepared.filepath), _write_backup_file)
        finally:
            zero_backup_key_if_owned(prepared.flags, backup_key)
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
            # 经 to_user_message 翻译为用户友好消息，避免内部消息直接暴露。
            logger.error("恢复失败: %s", exc, exc_info=True)
            return False, to_user_message(exc, default='操作失败，请检查文件和磁盘。')

    def _restore_current(self, file: IO[bytes], backup_password: str | None) -> tuple[bool, str]:
        flags, salt, kdf_params = read_backup_header(file)
        # 防 KDF 参数降级/飙升：在派生密钥前拒绝被篡改的参数。floor 拒绝弱化降级；
        # ceiling 拒绝社会工程下构造的内存耗尽参数（合法备份恒用 DEFAULT_KDF_PARAMS），
        # 避免在持锁派生时 UI 长冻结或 OOM。
        enforce_kdf_floor(kdf_params)
        enforce_kdf_ceiling(kdf_params)
        # 预声明 backup_key：PASSWORD 派生失败或 SNAPSHOT 路径前的提前 return 会使
        # backup_key 未赋值，方法级 finally 仍需引用它。预声明 None 避免 locals 反射。
        backup_key: bytearray | bytes | None = None
        checkpoint_ok = True
        try:
            # PASSWORD 派生在锁外完成：Argon2id（64MB）耗时，移出 vault_write_lock
            # 缩短持锁与 UI 冻结窗口。backup_key 为本地派生，不涉及 snapshot_key 竞态。
            if flags == BackupFlag.PASSWORD:
                if not backup_password:
                    return False, '请输入创建备份时设置的备份密码'
                backup_key = MasterKeyManager.derive_backup_key(
                    backup_password, salt, kdf_params,
                )
            # 持 vault 写锁串行化恢复与改密/备份：从解密全量明文到写库全程持锁。
            # SNAPSHOT 路径借用 snapshot_key，须在锁内读取（消除 is_unlocked 检查与
            # 读取间主线程 lock() 清零 snapshot_key 的竞态），故仍在锁内解析。
            with self._vault.vault_write_lock():
                if flags != BackupFlag.PASSWORD:
                    if not self._vault.is_unlocked:
                        return False, '恢复快照备份需要先解锁保险库'
                    backup_key = self._vault.snapshot_key
                # backup_key 必非 None：PASSWORD 在锁外已派生，SNAPSHOT 在上方分支已读取。
                # 显式检查替代 assert（python -O 下 assert 跳过），同时满足类型 narrow 需求。
                if backup_key is None:
                    raise RuntimeError('备份密钥未初始化')
                try:
                    # S8 TOCTOU 防护：header 锁外读取后，锁内读 payload 前重读 header
                    # 比对——检测文件在「锁外读 header → 锁内读 payload」窗口内被替换。
                    # GCM-AAD 只绑定单次 header+payload，整个合法备份替换需此额外校验拦截。
                    file.seek(0)
                    if read_backup_header(file) != (flags, salt, kdf_params):
                        return False, '备份文件在读取期间已变更，请重试'
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
                except (OSError, DecryptionError, json.JSONDecodeError):
                    # 缩窄为预期的「读文件 / GCM 解密 / JSON 解析」失败，统一提示密码错误
                    # 或损坏；编程错误（KeyError/TypeError/AttributeError 等）不在此列，
                    # 冒泡由上层 restore_backup 的 except 经 to_user_message 兜底，避免
                    # 把真实 bug 静默归为「备份损坏」而掩盖根因。
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
                    # 内层 try 成功后 plaintext/data 必然已赋值，直接释放明文引用。
                    del plaintext
                    del data
                # 事务已提交，key_epoch 与 snapshot_key_enc 均已在同一事务内原子写入。
                # 在释放 vault 锁前同步内存状态（不写库），既消除事务外写库的崩溃窗口，
                # 也消除旧 snapshot_key 仍可被并发读取（snapshot_key property）的窗口。
                try:
                    if new_epoch:
                        self._vault.update_key_epoch(new_epoch)
                    self._vault.apply_snapshot_key(new_snapshot_key)
                finally:
                    secure_zero_buffer(new_snapshot_key)
                # 事务提交后截断 WAL：clear_vault_data 删除的是被恢复数据替换的旧条目/
                # 分类/历史密文，由**当前主密钥**加密（恢复不轮换主密钥，与改密路径残留
                # 旧密钥不同），持当前主密钥与 WAL 文件者可恢复这些旧明文。须在事务外
                # 显式截断（事务内 secure_checkpoint 会跳过）；失败非致命（数据已提交完整），
                # 但纳入返回警告让降级可见，建议重启重试 TRUNCATE。
                try:
                    self._vault.db.secure_checkpoint()
                except Exception:
                    logger.warning('恢复后 WAL 安全截断失败', exc_info=True)
                    checkpoint_ok = False
            # 锁外清理旧 snapshot_key 加密的快照与恢复点：仅 unlink 文件，不读取
            # snapshot_key property，故无需持锁，减少锁持有时间。
            failed_purges = self._vault.purge_snapshot_backups()
            warnings: list[str] = []
            if not checkpoint_ok:
                warnings.append(
                    '恢复完成，但 WAL 安全截断失败，被替换的旧数据（当前主密钥加密）'
                    '可能残留于 WAL；建议重启应用以完成清理。'
                )
            if failed_purges:
                warnings.append(self._format_purge_warning(failed_purges))
            if warnings:
                return True, ' '.join(warnings)
            return True, ''
        finally:
            # 确保 PASSWORD 派生的 backup_key 在所有退出路径（含密钥派生失败、文件
            # 过大、解密异常）都清零；SNAPSHOT 路径借用 snapshot_key 不清零。
            zero_backup_key_if_owned(flags, backup_key)

    def _format_purge_warning(self, failed_purges: list[Path]) -> str:
        """格式化 purge 失败警告：区分含明文的恢复点（严重泄漏面）与普通旧快照。

        恢复点（``pre_restore_*``，含恢复前全部条目明文）未能删除是更严重的明文
        泄漏面，需显著警告并指引重启清理；普通旧快照笼统提示手动清理即可。
        """
        restore_point_failed = any(
            p.name.startswith('pre_restore_') for p in failed_purges
        )
        if restore_point_failed:
            return (
                f'恢复完成，但 {len(failed_purges)} 个含恢复前明文的快照'
                '未能删除（可能被占用）。为避免明文泄漏，请关闭可能占用'
                '该文件的程序后重启应用以自动清理。'
            )
        return (
            f'恢复完成，但 {len(failed_purges)} 个旧快照未能删除'
            '（可能被占用），建议在备份对话框手动清理以收缩泄漏面。'
        )

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
        """在 epoch 守卫事务内用当前主密钥重建全部数据并轮换 key_epoch 与 snapshot_key。

        恢复不改主密码，故用 ``self._key`` 重新加密备份载荷。事务内清空库后重建
        分类/条目/密码历史，同事务写入新的 key_epoch 与 snapshot_key_enc（消除事务外
        崩溃的不一致窗口），并据新 epoch 重算 vault_meta_mac。

        返回 ``(new_epoch, new_snapshot_key)``：调用方在事务提交后、释放锁前经
        :meth:`update_key_epoch` 与 :meth:`apply_snapshot_key` 同步内存状态。
        ``new_snapshot_key`` 为 bytearray 便于失败时原地清零。
        """
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
                category_map = restore_categories(self._entry_mgr, backup)
                entry_map, crypto_id_map = restore_entries(db, backup, key, category_map)
                restore_history(db, backup, key, entry_map, crypto_id_map)
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
            # WAL 截断已移至调用方 _restore_current（事务提交后显式 secure_checkpoint）。
            # 此处不再截断避免重复；success 在 return 前置 True，保证 finally 不误清零
            # 已落库的 snapshot_key（调用方 apply_snapshot_key 复制后才清零自身引用）。
            success = True
            return new_epoch, new_snapshot_key
        finally:
            # 事务失败（success 未置 True）时局部 snapshot_key 未被 apply_snapshot_key
            # 接管，原地清零收缩崩溃 dump 窗口；成功路径由调用方在 apply 后清零自己的引用。
            if not success:
                secure_zero_buffer(new_snapshot_key)

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

        # 间隔判定下沉 auto_backup_policy.is_auto_backup_due（纯函数，可独立测试）；
        # 未到间隔时静默返回成功（与禁用跳过一致：非错误，只是无需备份）。
        if not is_auto_backup_due(config, force=force):
            return True, ''

        backup_dir = config.get('backup_directory', '')
        if backup_dir:
            try:
                # backup_directory 是用户自定义的高敏感路径——自动快照含全量明文，
                # 若攻击者把其某祖先目录替换为符号链接，可把写入重定向到攻击者位置。
                # 默认 validate_file_path 的 Unix 分支仅检测叶子（避开 macOS 系统
                # 符号链接误伤），此处追加 check_ancestors 逐级检测祖先符号链接
                # （系统规范链接放行），收缩该重定向威胁。
                backup_dir = str(validate_file_path(backup_dir, check_ancestors=True))
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
        try:
            config.save()
        except OSError:
            # save 失败：备份已成功创建，未持久化的时间戳仅会让下次间隔检查失效而
            # 冗余备份，非致命；风格与 settings_dialog 的 config.save() 一致。
            logger.warning('无法写入配置文件，请检查磁盘空间和文件权限。', exc_info=True)

        retention = config.get('auto_backup_retention', DEFAULT_CONFIG['auto_backup_retention'])
        # 过期快照清理下沉 auto_backup_policy.purge_expired_auto_backups（纯策略函数）。
        purge_expired_auto_backups(directory, retention)

        return True, ''
