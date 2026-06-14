"""保险库管理器，负责保险库的高层操作。"""

import base64
import gc
import logging
import os
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

logger = logging.getLogger(__name__)

from ...config import ConfigManager
from ...crypto.encryption import EncryptionEngine
from ...crypto.master_key import DEFAULT_KDF_PARAMS, KDF_NAME, KdfParams, MasterKeyManager
from ...crypto.password_generator import PasswordGenerator
from ...database.db_manager import DatabaseManager
from ...exceptions import (
    CipherBoxError,
    DatabaseError,
    VaultAlreadyInitializedError,
    VaultIntegrityError,
    VaultKeyEpochMismatchError,
    VaultLockedError,
)
from ...utils.file_security import secure_delete_file
from ...utils.memory import secure_zero_buffer
from ..services.key_manager import KeyManager
from ..services.key_rotation import KeyRotationService
from ..services.metadata_signer import MetadataSigner

_SNAPSHOT_KEY_AAD = 'vault:snapshot-key'

# 改密时旧主密码验证失败的错误消息。供 change_master_dialog 判定是否计入速率
# 限制——以常量而非硬编码字面量比较，使文案变更不需同步改 dialog（单一真相源）。
AUTH_FAILED_MESSAGE = '当前主密码错误'


# TODO: 初始化/解锁/锁定/改密流程可进一步提取为独立的 VaultLifecycle。
# 密钥持有与清零职责已拆出至 src/business/services/key_manager.py。

class VaultManager:
    """管理保险库的创建、解锁、锁定等操作。"""

    def __init__(self, config: ConfigManager):
        self._config = config
        self._db = DatabaseManager(config.db_path)
        self._db.set_write_guard(self._enforce_key_epoch)

        # 元数据签名器
        self._signer = MetadataSigner()
        self._db.set_entry_integrity_handlers(
            self._signer.sign,
            self._signer.verify,
        )

        # 密钥轮换服务，仅负责纯加解密计算，事务仍由 VaultManager 管理
        self._rotator = KeyRotationService(self._db, self._signer)

        self._is_unlocked = False
        self._key_mgr = KeyManager()
        self._lock = threading.RLock()  # 保护改密和重加密等关键写操作串行化
        self._db_initialized = False  # 缓存标志，避免 is_initialized 重复打开数据库
        self._on_lock_callbacks: list = []
        self._cancel_event = threading.Event()  # close() 时设置，通知长时间操作提前终止

    # 密钥材料由 KeyManager 持有，此处通过 property 代理，保持 VaultManager
    # 内部 self._key / self._snapshot_key / self._key_epoch 访问接口不变。
    @property
    def _key(self):
        return self._key_mgr.key

    @_key.setter
    def _key(self, value):
        self._key_mgr.update_key(value)

    @property
    def _snapshot_key(self):
        return self._key_mgr.snapshot_key

    @_snapshot_key.setter
    def _snapshot_key(self, value):
        self._key_mgr.update_snapshot_key(value)

    @property
    def _key_epoch(self):
        return self._key_mgr.key_epoch

    @_key_epoch.setter
    def _key_epoch(self, value):
        self._key_mgr.update_epoch(value)

    def register_on_lock(self, callback):
        """注册锁定时自动调用的回调，用于清除缓存等。"""
        self._on_lock_callbacks.append(callback)

    @property
    def db(self) -> DatabaseManager:
        return self._db

    @property
    def data_dir(self) -> Path:
        return self._config.data_dir

    @property
    def is_initialized(self) -> bool:
        """保险库是否已初始化，即是否设置了主密码。"""
        if not self._config.db_path.exists():
            return False
        try:
            self._ensure_db_open()
            salt_b64 = self._db.get_meta('master_salt')
            return salt_b64 is not None
        except Exception:
            logger.error("检查保险库状态失败", exc_info=True)
            return False

    def _ensure_db_open(self):
        """确保数据库已打开且表已初始化。幂等方法，已打开则跳过。"""
        if self._db_initialized:
            return
        if not self._db.is_open and not self._db.open():
            raise DatabaseError('数据库无法打开')
        self._db.init_tables()
        self._db_initialized = True

    @property
    def is_unlocked(self) -> bool:
        return self._is_unlocked and self._key is not None

    @property
    def key(self) -> bytes | None:
        return self._key

    @property
    def snapshot_key(self) -> bytes:
        if not self.is_unlocked or self._snapshot_key is None:
            raise VaultLockedError('自动快照密钥不可用')
        return self._snapshot_key

    @property
    def key_epoch(self) -> str | None:
        """当前主密钥版本，改密时自动轮换，用于缓存失效判定。"""
        return self._key_epoch

    def update_key_epoch(self, new_epoch: str):
        """更新 key_epoch，用于备份恢复后同步状态。

        恢复会整体替换数据，触发缓存失效回调清除恢复前的明文缓存。例如
        username 缓存按 crypto_id 索引，而恢复保留 crypto_id，若不清除会
        命中旧明文而与新数据不一致。复用 on_lock 回调列表，其当前仅注册缓存清除。
        """
        self._key_epoch = new_epoch
        for cb in self._on_lock_callbacks:
            try:
                cb()
            except Exception:
                logger.debug("恢复后缓存失效回调失败", exc_info=True)

    def _enforce_key_epoch(self):
        """拒绝锁定状态或主密钥已轮换的旧会话写入数据库。

        每次写入都比对 key_epoch，不做时间缓存，避免改密后旧会话在窗口内
        用旧密钥写入导致数据按旧密钥落盘、新会话解密失败的损坏窗口。
        检测到 epoch 不匹配时调用 _clear_vault_state 而非 lock，
        避免在持有数据库锁时触发回调导致死锁。
        """
        if self._key_epoch is None:
            return
        if self._db.in_transaction:
            # 事务进行中跳过：写路径已在事务边界校验过 epoch，事务内重复比对
            # 无意义（get_meta 经 @_db_operation 重入 RLock 不会死锁，但属冗余）。
            # 代价是整个事务期间的写入不受此守卫保护，故每个事务化写路径
            # 必须在事务开始时自行比对 epoch（见 _transactional_import 二次校验）。
            return
        if not self.is_unlocked:
            raise VaultLockedError("保险库已锁定，不能写入数据")
        current_epoch = self._db.get_meta('key_epoch')
        if current_epoch and current_epoch != self._key_epoch:
            self._clear_vault_state()
            raise VaultKeyEpochMismatchError("保险库密钥已变更，请重新启动并解锁")

    def initialize(self, master_password: str) -> tuple[bool, str]:
        """首次初始化保险库，设置主密码

        Args:
            master_password: 主密码

        Returns:
            由是否成功与错误信息组成的二元组，成功时错误信息为空字符串。
        """
        try:
            valid, error = PasswordGenerator.validate_master_password(master_password)
            if not valid:
                raise ValueError(error)
            self._ensure_db_open()
            if self._db.get_meta('master_salt') or self._db.get_meta('master_verify'):
                raise VaultAlreadyInitializedError('保险库已经初始化，不能重复设置主密码')
            salt, verify_token, derived_key = MasterKeyManager.create(
                master_password, DEFAULT_KDF_PARAMS
            )
            snapshot_key = os.urandom(32)
            key_epoch = uuid.uuid4().hex
            with self._db.transaction():
                self._write_vault_metadata(
                    salt=salt, verify_token=verify_token, snapshot_key=snapshot_key,
                    key=derived_key, key_epoch=key_epoch,
                )
            self._key_mgr.activate(derived_key, snapshot_key, key_epoch)
            self._signer.set_domain_key(MetadataSigner.compute_domain_key(derived_key))
            self._is_unlocked = True
            return True, ''
        except VaultAlreadyInitializedError as exc:
            return False, str(exc)
        except CipherBoxError:
            raise
        except Exception as exc:
            msg = str(exc) or '保险库初始化失败'
            logger.warning("保险库初始化失败", exc_info=True)
            return False, msg

    @staticmethod
    def _read_kdf_params(meta: dict) -> KdfParams:
        """从 vault_meta 解析 Argon2id 参数，缺失或非法时抛 VaultLockedError。"""
        try:
            return KdfParams(
                int(meta['master_kdf_time_cost']),
                int(meta['master_kdf_memory_cost']),
                int(meta['master_kdf_parallelism']),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise VaultLockedError('保险库缺少密钥派生参数') from exc

    def unlock(self, master_password: str) -> tuple[bool, str]:
        """使用主密码解锁保险库

        Args:
            master_password: 主密码

        Returns:
            由是否成功与错误信息组成的二元组，成功时错误信息为空字符串。
        """
        # 预声明 key：verify 未执行（如凭据校验前异常）时，except 仍需引用它做清零
        # 判断。预声明 None 避免 locals().get 反射（字段重命名时静态检查无法发现）。
        key: bytearray | None = None
        try:
            t0 = time.monotonic()
            self._ensure_db_open()

            # 单次查询获取全部元数据，避免 7 次独立 DB 锁获取
            meta = self._db.get_meta_batch([
                'master_salt', 'master_verify', 'master_kdf_time_cost',
                'master_kdf_memory_cost', 'master_kdf_parallelism',
                'master_kdf', 'ciphertext_format', 'key_epoch',
                'snapshot_key_enc',
            ])

            salt_b64 = meta['master_salt']
            verify_token = meta['master_verify']

            if not salt_b64 or not verify_token:
                return False, '保险库凭据不完整'

            salt = base64.b64decode(salt_b64)
            params = self._read_kdf_params(meta)
            key = MasterKeyManager.verify(
                master_password, salt, verify_token, params
            )

            if key is None:
                return False, '主密码错误'

            # 先完成全部元数据格式校验，再持有密钥，遵循最小暴露原则：
            # 格式校验失败时 key 仅作局部变量，不写入 KeyManager 也不触发加密缓存。
            if meta['master_kdf'] != KDF_NAME:
                raise VaultLockedError('不支持的主密钥派生格式')
            if meta['ciphertext_format'] != EncryptionEngine.FORMAT_ID:
                raise VaultLockedError('不支持的密文格式')
            key_epoch = meta['key_epoch']
            if not key_epoch:
                raise VaultLockedError('保险库缺少当前格式的密钥版本')
            # snapshot_key_enc 用主密钥加密，_load_snapshot_key 须在主密钥设置后调用，
            # 故无法进一步前置；其失败由下方 except 经 lock() 清零兜底（此时 key 已写入
            # KeyManager，但 lock 会一并清零，状态最终一致）。
            self._key = key
            self._key_epoch = key_epoch
            self._signer.set_domain_key(MetadataSigner.compute_domain_key(key))
            self._load_snapshot_key(meta.get('snapshot_key_enc'))
            # 全部密钥材料（主密钥、epoch、domain_key、snapshot_key）就位后再标记解锁，
            # 缩小「主密钥已写入但 snapshot_key 尚未加载」的部分就位窗口：此窗口内
            # is_unlocked 为 False，并发读取者不会得到「已解锁但 snapshot_key 缺失」的
            # 中间态。_load_snapshot_key 仅依赖 self._key（已设置），不依赖 is_unlocked。
            self._is_unlocked = True
            logger.info("解锁完成 (%.1fms)", (time.monotonic() - t0) * 1000)
            return True, ''
        except CipherBoxError:
            # key 可能已写入 KeyManager（_load_snapshot_key 在 _key 赋值后调用，
            # snapshot_key 损坏时 key 已就位）。secure_zero_buffer 清零该 bytearray
            # （KeyManager 持同一对象），随后的 lock() 统一清零全部密钥材料。
            # key 已在 try 前预声明，verify 未执行时为 None，跳过清零。
            if key is not None:
                secure_zero_buffer(key)
            self.lock()
            raise
        except Exception as exc:
            self.lock()
            msg = str(exc) or '保险库无法解锁'
            logger.warning("解锁失败", exc_info=True)
            return False, msg

    def _clear_vault_state(self):
        """清除密钥材料和加密缓存，不触发回调，也不执行 gc。

        用于 _enforce_key_epoch 中需要安全清除状态但不能触发回调的场景，
        避免在持有数据库锁时回调中再获取数据库锁导致死锁。
        """
        # 密钥材料由 KeyManager 集中清零，含主密钥、快照密钥与 epoch
        self._key_mgr.clear()
        # 清零 MetadataSigner 中的域密钥
        dk = self._signer.domain_key
        if dk is not None:
            secure_zero_buffer(dk)
        self._signer.domain_key = None
        self._is_unlocked = False
        # 重置初始化标志：下次 _ensure_db_open 将重新验证 schema。
        # 注意：不关闭数据库连接，_conn 仍可能被后续操作使用，
        # 但 _db_initialized=False 确保 init_tables 在下次访问时重新运行。
        self._db_initialized = False
        EncryptionEngine.clear_cache()

    def lock(self):
        """锁定保险库，清除内存中的密钥材料。

        安全注意事项：
        Python bytes 对象不可变，无法可靠地原地清零密钥数据。
        本方法通过 secure_zero_buffer 尽力清零密钥材料的可变副本，
        以缩短密钥数据在内存中的生命周期。但原始 bytes 对象仍依赖 GC 回收，
        在 GC 回收前可能仍驻留在进程内存中。这是 CPython 的固有局限。
        """
        # 主动通知任何进行中的改密/重加密取消，缩短 lock 获取 self._lock 的阻塞窗口：
        # 改密循环检测 cancel_event 后抛异常回滚，尽快释放 self._lock，避免 UI 长时间冻结。
        self._cancel_event.set()
        try:
            # 持 vault 锁串行化与 create_backup：确保清零密钥前，进行中的备份已完成，
            # 避免备份用密钥副本在 lock 后继续解密。回调在锁外执行，避免回调获取锁导致死锁。
            with self._lock:
                self._clear_vault_state()
                gc.collect()
        finally:
            # 复位取消事件，避免残留影响后续改密
            self._cancel_event.clear()
        # gc.collect() 缩短密钥材料驻留时间；lock 属低频操作，GC 暂停可接受。
        # 随后通知依赖方清除缓存，不依赖调用方纪律。
        for cb in self._on_lock_callbacks:
            try:
                cb()
            except Exception:
                logger.debug("锁定回调执行失败", exc_info=True)

    @contextmanager
    def vault_write_lock(self):
        """获取保险库写锁，串行化接触全量明文的长操作（改密/重加密/备份/恢复）。

        外部协作者（如 BackupRestoreManager）须通过此公共上下文访问锁，而非直接
        访问受保护的 ``_lock``，使「持锁才能接触全量明文」契约显式化，避免重构
        锁结构时静默破坏串行化保护。持锁期间可安全读取/重写全部条目明文，与
        ``_change_master_password_locked`` 等内部长事务互斥，避免半完成状态
        （部分新密钥/部分旧密钥）被并发读取。
        """
        with self._lock:
            yield

    def change_master_password(
        self, old_password: str, new_password: str
    ) -> tuple[bool, str]:
        """修改主密码

        Args:
            old_password: 旧主密码
            new_password: 新主密码

        Returns:
            由是否成功与错误信息组成的二元组，成功时错误信息为空字符串。

        方法获取可重入锁，与 _re_encrypt_all 的写操作串行化。
        """
        with self._lock:
            return self._change_master_password_locked(old_password, new_password)

    def _change_master_password_locked(
        self, old_password: str, new_password: str
    ) -> tuple[bool, str]:
        try:
            valid, error = PasswordGenerator.validate_master_password(new_password)
            if not valid:
                return False, error
            if old_password == new_password:
                return False, '新密码不能与当前主密码相同'
            meta = self._db.get_meta_batch([
                'master_salt', 'master_verify', 'master_kdf_time_cost',
                'master_kdf_memory_cost', 'master_kdf_parallelism',
            ])
            salt_b64 = meta['master_salt']
            verify_token = meta['master_verify']
            if not salt_b64 or not verify_token:
                return False, '保险库凭据不完整'

            old_salt = base64.b64decode(salt_b64)
            old_params = self._read_kdf_params(meta)
            result = MasterKeyManager.change_password(
                old_password,
                new_password,
                old_salt,
                verify_token,
                old_params,
                DEFAULT_KDF_PARAMS,
            )
            if result is None:
                return False, AUTH_FAILED_MESSAGE

            new_salt, new_verify_token, new_key = result

            # 复用 MasterKeyManager.create 已派生的 new_key，省一次 Argon2id 派生
            failed_purges = self._re_encrypt_all(
                new_key, new_salt, new_verify_token, new_params=DEFAULT_KDF_PARAMS,
            )
            if failed_purges:
                # 改密成功但旧明文快照未能清理：明确反馈用户，避免误以为泄漏面已收缩
                return True, (
                    f'主密码已修改，但 {len(failed_purges)} 个历史明文快照未能删除'
                    '（可能被占用），建议在备份对话框手动清理以收缩泄漏面。'
                )
            return True, ''
        except CipherBoxError:
            raise  # 所有 CipherBox 自定义异常向上传播
        except Exception as exc:
            logger.warning("修改主密码失败", exc_info=True)
            return False, str(exc) or '修改主密码失败'

    def _re_encrypt_all(self, new_key: bytes, new_salt: bytes, new_verify_token: str,
                        new_params: KdfParams = DEFAULT_KDF_PARAMS):
        """使用新密钥重新加密所有条目，含已删除条目，受事务保护。

        调用方须已持有 self._lock，当前唯一调用方 _change_master_password_locked
        已在 with self._lock 内调用此方法。

        Args:
            new_key: 由 MasterKeyManager.create 派生的新密钥，复用以避免重复 KDF。
            new_salt: 新盐值，用于回写 vault_meta。
            new_verify_token: 新验证令牌，用于回写 vault_meta。
        """
        if self._key is None:
            raise VaultLockedError('保险库未解锁，无法执行重加密')

        # 重置取消事件，避免上一次 reject/close 的残留导致本次改密被误取消
        self._cancel_event.clear()
        old_key = self._key
        new_epoch = uuid.uuid4().hex
        # snapshot_key 随主密钥一同轮换：旧 snapshot_key 加密的快照与恢复点随后清理，
        # 彻底收缩历史明文泄漏面，使主密码一旦被攻破也无法解密历史快照。
        new_snapshot_key = os.urandom(32)

        try:
            t0 = time.monotonic()
            # 通过 transaction() 上下文持有 db_lock 并包裹真实事务：
            # 数据读取在事务内完成，防止 TOCTOU 竞态；db_lock 持有期间阻止
            # 其他线程在此连接上插队写入导致跨线程部分回滚。异常时由
            # transaction() 自动回滚所有数据库变更。
            with self._db.transaction():
                self._rotator.re_encrypt_entries(old_key, new_key, cancel_event=self._cancel_event)
                self._rotator.re_encrypt_history(old_key, new_key, cancel_event=self._cancel_event)
                self._update_vault_metadata(
                    new_key, new_salt, new_verify_token, new_epoch,
                    snapshot_key=new_snapshot_key, params=new_params,
                )

            # 事务已提交。密钥赋值放在 commit 之后，避免后台线程在 commit 前
            # 读到新密钥、解密尚未提交的旧数据，造成解密窗口问题。
            # 若提交失败 transaction() 已回滚，下方 except 会清除密钥保证一致性。
            self._key_mgr.activate(new_key, new_snapshot_key, new_epoch)
            self._signer.set_domain_key(MetadataSigner.compute_domain_key(new_key))
            EncryptionEngine.clear_cache()  # 旧密钥 cipher 已失效，确保后续用新密钥
            logger.info("重加密完成 (%.1fms)", (time.monotonic() - t0) * 1000)
            # 清理旧 snapshot_key 加密的全部快照与恢复点，收缩泄漏面。
            # purge 失败不使改密失败，但必须明确记录，避免用户误以为泄漏面
            # 已收缩而旧明文快照实际仍因文件占用或只读目录残留磁盘。
            failed_purges = self._purge_snapshot_backups()
            if failed_purges:
                logger.warning(
                    "改密后未能删除 %d 个旧快照/恢复点（可能被占用或目录只读），"
                    "建议手动清理以收缩历史明文泄漏面：%s",
                    len(failed_purges),
                    ', '.join(str(p) for p in failed_purges),
                )
            # WAL 截断在事务提交之后执行；此时数据已落盘，截断失败非致命，
            # 单独捕获避免其异常冒泡导致 UI 显示模糊错误，而事务其实已成功。
            try:
                self._db.secure_checkpoint()
            except Exception:
                logger.warning("改密后 WAL 安全截断失败（非致命）", exc_info=True)

            return failed_purges

        except Exception:
            # transaction() 上下文已回滚所有数据库变更。
            # 即使 lock() 异常也必须确保密钥被清除，防止内存状态不一致。
            try:
                self.lock()
            except Exception:
                logger.error("改密后锁定失败，强制清除状态", exc_info=True)
                self._clear_vault_state()
            logger.error("重加密失败: 回滚所有变更", exc_info=True)
            raise
        finally:
            # 清理取消事件，避免残留影响后续改密
            self._cancel_event.clear()
            # 旧主密钥副本（self._key 返回的 bytes，不可原地清零）在新密钥生效后立即
            # 释放引用，缩短旧密钥在内存/swap 的驻留，收敛改密的「撤销泄漏」语义。
            # CPython 下 bytes 不可变，del 后仍依赖 GC 回收，此为固有限制下的尽力而为。
            del old_key

    def _purge_snapshot_backups(self) -> list:
        """删除所有 snapshot_key 加密的快照与恢复前安全快照，返回未能删除的文件。

        改密时 snapshot_key 随主密钥轮换，旧 snapshot_key 加密的文件无法用新密钥
        解密，且含历史明文，清理以收缩泄漏面。同时覆盖默认目录与用户自定义目录。
        返回因占用或权限等原因未能删除的文件清单，供调用方明确上报而非静默丢失。
        """
        directories = [self.data_dir / 'backups']
        backup_dir = self._config.get('backup_directory', '')
        if backup_dir:
            directories.append(Path(backup_dir))
        failed = []
        for directory in directories:
            if not directory.is_dir():
                continue
            for pattern in ('pre_restore_*.cbox', 'cipherbox_snapshot_*.cbox'):
                for f in directory.glob(pattern):
                    try:
                        secure_delete_file(f)
                    except OSError:
                        failed.append(f)
        return failed

    def encrypt_snapshot_key(self, snapshot_key: bytes) -> str:
        """加密 snapshot_key 以写入 vault_meta，供恢复流程在事务内复用。

        恢复流程不改主密钥，故用当前 self._key 加密（与 initialize/改密路径传入
        特定 key 不同）。将加密与 set_meta 解耦，使 snapshot_key_enc 能与 key_epoch
        在同一数据库事务内写入，消除事务外崩溃导致 epoch 已提交而 snapshot_key_enc
        未写入的不一致窗口。
        """
        if self._key is None:
            raise VaultLockedError('保险库未解锁')
        return EncryptionEngine.encrypt(
            base64.b64encode(snapshot_key).decode('ascii'),
            self._key,
            _SNAPSHOT_KEY_AAD,
        )

    def apply_snapshot_key(self, snapshot_key: bytes) -> None:
        """仅同步内存中的 snapshot_key，不写库。

        供恢复流程在事务提交后同步内存状态——库内 snapshot_key_enc 已在事务内
        由调用方经 encrypt_snapshot_key + set_meta 写入，此处只更新 KeyManager。
        """
        self._key_mgr.update_snapshot_key(snapshot_key)

    def purge_snapshot_backups(self) -> list:
        """删除所有 snapshot_key 加密的快照与恢复前安全快照，返回未能删除的文件。

        供改密/恢复流程在轮换 snapshot_key 后清理旧明文快照以收缩泄漏面。
        """
        return self._purge_snapshot_backups()

    def _write_vault_metadata(
        self, *, salt: bytes, verify_token: str,
        snapshot_key: bytes, key: bytes, key_epoch: str,
        params: KdfParams = DEFAULT_KDF_PARAMS,
    ):
        """将保险库元数据写入 vault_meta，包含盐、验证令牌、KDF 参数、快照密钥和 epoch。

        initialize 与改密共用此序列，避免两处逐字重复。params 为实际派生所用的
        Argon2id 参数，写入数据库而非硬编码常量，为未来调整参数保留正确性。
        """
        self._db.set_meta('master_salt', base64.b64encode(salt).decode('ascii'))
        self._db.set_meta('master_verify', verify_token)
        self._db.set_meta('master_kdf', KDF_NAME)
        self._db.set_meta('master_kdf_time_cost', str(params.time_cost))
        self._db.set_meta('master_kdf_memory_cost', str(params.memory_cost))
        self._db.set_meta('master_kdf_parallelism', str(params.parallelism))
        self._db.set_meta('ciphertext_format', EncryptionEngine.FORMAT_ID)
        self._db.set_meta(
            'snapshot_key_enc',
            EncryptionEngine.encrypt(
                base64.b64encode(snapshot_key).decode('ascii'),
                key,
                _SNAPSHOT_KEY_AAD,
            ),
        )
        self._db.set_meta('key_epoch', key_epoch)

    def _update_vault_metadata(
        self, new_key: bytes, new_salt: bytes, new_verify_token: str,
        new_epoch: str, *, snapshot_key: bytes | None,
        params: KdfParams = DEFAULT_KDF_PARAMS,
    ):
        """更新 vault_meta 表中的验证信息和密钥元数据。

        snapshot_key 由调用方传入，改密时轮换为全新值，不再复用旧值。
        params 透传给 _write_vault_metadata，写入实际派生所用的 Argon2id 参数。
        """
        if snapshot_key is None:
            raise VaultIntegrityError('snapshot_key 未加载，无法更新保险库元数据')
        self._write_vault_metadata(
            salt=new_salt, verify_token=new_verify_token,
            snapshot_key=snapshot_key, key=new_key, key_epoch=new_epoch,
            params=params,
        )

    def _load_snapshot_key(self, encrypted: str | None = None):
        key = self._key
        if key is None:
            raise VaultLockedError('保险库未解锁')
        if encrypted is None:
            encrypted = self._db.get_meta('snapshot_key_enc')
        if not encrypted:
            raise VaultLockedError('保险库缺少自动快照密钥')
        encoded = EncryptionEngine.decrypt(
            encrypted, key, _SNAPSHOT_KEY_AAD
        )
        self._snapshot_key = base64.b64decode(encoded)
        if len(self._snapshot_key) != 32:
            raise VaultIntegrityError('自动快照密钥损坏')

    def request_cancel(self):
        """请求中止进行中的重加密（改密取消或关闭应用时调用）。

        设置取消事件，重加密循环检测后抛出异常并回滚事务，避免提交
        半成品。_re_encrypt_all 在开始与结束时清理该事件，使取消请求
        不残留影响后续改密。
        """
        self._cancel_event.set()

    def close(self):
        """关闭保险库。

        设置取消事件通知正在进行的密钥轮换等长时间操作提前终止，
        然后锁定保险库并关闭数据库连接。
        """
        self._cancel_event.set()
        self.lock()
        self._db.close()
        self._cancel_event.clear()
