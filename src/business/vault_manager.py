"""保险库管理器 - 高层保险库操作"""

import base64
import gc
import hashlib
import hmac
import json
import logging
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

from ..config import ConfigManager
from ..crypto.encryption import EncryptionEngine
from ..crypto.master_key import PBKDF2_ITERATIONS, MasterKeyManager
from ..crypto.password_generator import PasswordGenerator
from ..database.db_manager import DatabaseManager
from .exceptions import (
    CipherBoxError,
    DatabaseError,
    DecryptionError,
    VaultAlreadyInitializedError,
    VaultError,
    VaultIntegrityError,
    VaultKeyEpochMismatchError,
    VaultLockedError,
)
from .crypto_utils import decrypt_field as _decrypt_field_impl
from .crypto_utils import encrypt_field as _encrypt_field_impl

_SNAPSHOT_KEY_AAD = 'vault:snapshot-key'
_RE_ENCRYPT_BATCH_SIZE = 200
_ENCRYPTED_ENTRY_FIELDS = ('username', 'password', 'notes', 'totp_secret', 'custom_fields')


# TODO: God Object 分解计划
# VaultManager 当前承担了密钥管理、数据库生命周期、元数据签名、重加密等职责。
# 建议分解为：
# - KeyManager: 密钥派生、存储、零化
# - MetadataSigner: 条目元数据签名/验证
# - VaultLifecycle: 初始化、解锁、锁定、改密

class VaultManager:
    """管理保险库的创建、解锁、锁定等操作"""

    def __init__(self, config: ConfigManager):
        self._config = config
        self._db = DatabaseManager(config.db_path)
        self._db.set_write_guard(self._enforce_key_epoch)
        self._db.set_entry_integrity_handlers(
            self._sign_entry_metadata,
            self._verify_entry_metadata,
        )
        self._key: Optional[bytes] = None
        self._is_unlocked = False
        self._key_epoch: str | None = None
        self._snapshot_key: bytes | None = None
        self._last_error = ''
        self._epoch_cache_time: float = 0.0
        self._metadata_domain_key: bytes | None = None
        self._lock = threading.RLock()  # M-A3：保护改密/重加密等关键写操作串行化
        self._db_initialized = False  # 缓存标志，避免 is_initialized 重复打开数据库
        self._on_lock_callbacks: list = []

    def register_on_lock(self, callback):
        """注册锁定时自动调用的回调（用于清除缓存等）。"""
        self._on_lock_callbacks.append(callback)

    @property
    def db(self) -> DatabaseManager:
        return self._db

    @property
    def data_dir(self) -> Path:
        return self._config.data_dir

    @property
    def last_error(self) -> str:
        return self._last_error

    @property
    def is_initialized(self) -> bool:
        """保险库是否已初始化（是否设置了主密码）"""
        if not self._config.db_path.exists():
            return False
        try:
            self._last_error = ''
            self._ensure_db_open()
            salt_b64 = self._db.get_meta('master_salt')
            return salt_b64 is not None
        except Exception as exc:
            self._last_error = str(exc) or '保险库格式无效'
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

    @staticmethod
    def _compute_domain_key(key: bytes) -> bytes:
        """从主密钥派生 metadata 签名域密钥"""
        return hmac.new(key, b'cipherbox:entry-metadata-key', hashlib.sha256).digest()

    @property
    def is_unlocked(self) -> bool:
        return self._is_unlocked and self._key is not None

    @property
    def key(self) -> Optional[bytes]:
        return self._key

    @property
    def snapshot_key(self) -> bytes:
        if not self.is_unlocked or self._snapshot_key is None:
            raise VaultLockedError('自动快照密钥不可用')
        return self._snapshot_key

    @property
    def key_epoch(self) -> str | None:
        """当前主密钥版本（改密时轮换），用于缓存失效判定（M-S4）。"""
        return self._key_epoch

    def update_key_epoch(self, new_epoch: str):
        """更新 key_epoch 并重置缓存（用于备份恢复后同步状态）。"""
        self._key_epoch = new_epoch
        self._epoch_cache_time = 0.0  # 强制下次写入时重新校验

    def _enforce_key_epoch(self):
        """拒绝锁定状态或主密钥已轮换的旧会话写入数据库。

        使用时间戳缓存避免每次写入都查询数据库，2 秒内只检查一次 epoch。
        检测到 epoch 不匹配时使用 _clear_vault_state() 而非 lock()，
        避免在持有数据库锁时触发回调导致死锁。
        """
        if self._key_epoch is None:
            return
        if self._db.in_transaction:
            return
        if not self.is_unlocked:
            raise VaultLockedError("保险库已锁定，不能写入数据")
        now = time.monotonic()
        if now - self._epoch_cache_time < 2.0:
            return
        current_epoch = self._db.get_meta('key_epoch')
        if current_epoch and current_epoch != self._key_epoch:
            self._clear_vault_state()
            raise VaultKeyEpochMismatchError("保险库密钥已被其他进程更新，请重新启动并解锁")
        self._epoch_cache_time = now

    def initialize(self, master_password: str) -> bool:
        """首次初始化保险库，设置主密码

        Args:
            master_password: 主密码

        Returns:
            是否成功
        """
        try:
            self._last_error = ''
            valid, error = PasswordGenerator.validate_master_password(master_password)
            if not valid:
                raise ValueError(error)
            self._ensure_db_open()
            if self._db.get_meta('master_salt') or self._db.get_meta('master_verify'):
                raise VaultAlreadyInitializedError('保险库已经初始化，不能重复设置主密码')
            salt, verify_token, derived_key = MasterKeyManager.create(
                master_password, PBKDF2_ITERATIONS
            )
            snapshot_key = os.urandom(32)
            self._db.begin_transaction()
            try:
                self._db.set_meta('master_salt', base64.b64encode(salt).decode('ascii'))
                self._db.set_meta('master_verify', verify_token)
                self._db.set_meta('master_kdf', 'pbkdf2-sha256')
                self._db.set_meta('master_kdf_iterations', str(PBKDF2_ITERATIONS))
                self._db.set_meta('ciphertext_format', EncryptionEngine.FORMAT_ID)
                self._db.set_meta(
                    'snapshot_key_enc',
                    EncryptionEngine.encrypt(
                        base64.b64encode(snapshot_key).decode('ascii'),
                        derived_key,
                        _SNAPSHOT_KEY_AAD,
                    ),
                )
                key_epoch = uuid.uuid4().hex
                self._db.set_meta('key_epoch', key_epoch)
                self._db.commit_transaction()
            except Exception:
                self._db.rollback_transaction()
                raise
            self._key = derived_key
            self._snapshot_key = snapshot_key
            self._key_epoch = key_epoch
            self._metadata_domain_key = self._compute_domain_key(derived_key)
            self._is_unlocked = True
            return True
        except Exception as exc:
            self._last_error = str(exc) or '保险库初始化失败'
            logger.warning("保险库初始化失败", exc_info=True)
            return False

    def unlock(self, master_password: str) -> bool:
        """使用主密码解锁保险库

        Args:
            master_password: 主密码

        Returns:
            是否成功
        """
        try:
            t0 = time.monotonic()
            self._last_error = ''
            self._ensure_db_open()

            salt_b64 = self._db.get_meta('master_salt')
            verify_token = self._db.get_meta('master_verify')

            if not salt_b64 or not verify_token:
                self._last_error = '保险库凭据不完整'
                return False

            salt = base64.b64decode(salt_b64)
            iterations_text = self._db.get_meta('master_kdf_iterations')
            if not iterations_text:
                raise VaultLockedError('保险库缺少密钥派生参数')
            iterations = int(iterations_text)
            key = MasterKeyManager.verify(
                master_password, salt, verify_token, iterations
            )

            if key is None:
                self._last_error = '主密码错误'
                return False

            self._key = key
            if self._db.get_meta('master_kdf') != 'pbkdf2-sha256':
                raise VaultLockedError('不支持的主密钥派生格式')
            if self._db.get_meta('ciphertext_format') != EncryptionEngine.FORMAT_ID:
                raise VaultLockedError('不支持的密文格式')
            self._key_epoch = self._db.get_meta('key_epoch')
            if not self._key_epoch:
                raise VaultLockedError('保险库缺少当前格式的密钥版本')
            self._is_unlocked = True
            self._metadata_domain_key = self._compute_domain_key(key)
            self._load_snapshot_key()
            logger.info("解锁完成 (%.1fms)", (time.monotonic() - t0) * 1000)
            return True
        except Exception as exc:
            self.lock()
            self._last_error = str(exc) or '保险库无法解锁'
            logger.warning("解锁失败", exc_info=True)
            return False

    def _clear_vault_state(self):
        """清除密钥材料和加密缓存（不触发回调，不执行 gc）。

        用于 _enforce_key_epoch 中需要安全清除状态但不能触发回调的场景，
        避免在持有数据库锁时回调中再获取数据库锁导致死锁。
        """
        # 尽力清零密钥内存
        try:
            import ctypes
            for attr in ('_key', '_snapshot_key', '_metadata_domain_key'):
                secret = getattr(self, attr, None)
                if secret is not None:
                    try:
                        mutable = bytearray(secret)
                        ctypes.memset(
                            (ctypes.c_char * len(mutable)).from_buffer(mutable),
                            0, len(mutable),
                        )
                        del mutable
                    except Exception:
                        logger.warning("密钥内存清零失败", exc_info=True)
        except Exception:
            logger.warning("密钥清零初始化失败", exc_info=True)
        self._key = None
        self._snapshot_key = None
        self._is_unlocked = False
        self._key_epoch = None
        self._metadata_domain_key = None
        self._epoch_cache_time = 0.0
        self._db_initialized = False
        EncryptionEngine.clear_cache()

    def lock(self):
        """锁定保险库，清除内存中的密钥材料。

        安全注意事项：
        Python bytes 对象不可变，无法可靠地原地清零密钥数据。
        本方法将每个密钥转为 bytearray 可变副本并通过 ctypes.memset 清零该副本，
        以缩短密钥数据在内存中的生命周期。但原始 bytes 对象仍依赖 GC 回收，
        在 GC 回收前可能仍驻留在进程内存中。这是 CPython 的固有局限。
        """
        self._clear_vault_state()
        gc.collect()
        # SEC-02: 恢复 gc.collect() 以缩短密钥材料在内存中的驻留时间。
        # lock() 属于低频操作（用户手动锁定或自动超时），10-50ms 的 GC 暂停
        # 完全可接受，换来的是更短的生命周期，减少密钥残留风险。
        # SEC-08：自动通知依赖方清除缓存，不依赖调用方纪律
        for cb in self._on_lock_callbacks:
            try:
                cb()
            except Exception:
                logger.debug("锁定回调执行失败", exc_info=True)

    def change_master_password(
        self, old_password: str, new_password: str
    ) -> bool:
        """修改主密码

        Args:
            old_password: 旧主密码
            new_password: 新主密码

        Returns:
            是否成功

        M-A3：获取可重入锁，与 _re_encrypt_all 的写操作串行化。
        """
        with self._lock:
            return self._change_master_password_locked(old_password, new_password)

    def _change_master_password_locked(
        self, old_password: str, new_password: str
    ) -> bool:
        try:
            self._last_error = ''
            valid, error = PasswordGenerator.validate_master_password(new_password)
            if not valid:
                self._last_error = error
                return False
            if old_password == new_password:
                self._last_error = '新密码不能与当前主密码相同'
                return False
            salt_b64 = self._db.get_meta('master_salt')
            verify_token = self._db.get_meta('master_verify')
            if not salt_b64 or not verify_token:
                return False

            old_salt = base64.b64decode(salt_b64)
            iterations_text = self._db.get_meta('master_kdf_iterations')
            if not iterations_text:
                raise VaultLockedError('保险库缺少密钥派生参数')
            old_iterations = int(iterations_text)
            result = MasterKeyManager.change_password(
                old_password,
                new_password,
                old_salt,
                verify_token,
                old_iterations,
                PBKDF2_ITERATIONS,
            )
            if result is None:
                self._last_error = '当前主密码错误'
                return False

            new_salt, new_verify_token, new_key = result

            # 用新密钥重新加密所有条目的敏感字段
            # （复用 MasterKeyManager.create 已派生的 new_key，省一次 PBKDF2 派生）
            self._re_encrypt_all(new_key, new_salt, new_verify_token)

            return True
        except CipherBoxError:
            raise  # 所有 CipherBox 自定义异常向上传播
        except Exception as exc:
            self._last_error = str(exc) or '修改主密码失败'
            return False

    def _re_encrypt_all(self, new_key: bytes, new_salt: bytes, new_verify_token: str):
        """使用新密钥重新加密所有条目（含已删除），事务保护。

        调用方须已持有 self._lock（当前唯一调用方 _change_master_password_locked
        已在 with self._lock 内调用此方法）。

        Args:
            new_key: 由 MasterKeyManager.create 派生的新密钥（复用，避免重复 KDF）。
            new_salt: 新盐值（用于回写 vault_meta）。
            new_verify_token: 新验证令牌（用于回写 vault_meta）。
        """
        if self._key is None:
            raise VaultLockedError('保险库未解锁，无法执行重加密')

        old_key = self._key
        new_epoch = uuid.uuid4().hex

        # 使用真实事务：begin_transaction 抑制内部 commit
        # 数据读取在事务内完成，防止 TOCTOU 竞态
        self._db.begin_transaction()

        try:
            t0 = time.monotonic()
            self._re_encrypt_entries(old_key, new_key)
            self._re_encrypt_history(old_key, new_key)
            self._update_vault_metadata(new_key, new_salt, new_verify_token, new_epoch)

            # 全部成功 → 先更新内存密钥，再提交事务。
            # 若提交失败回滚，lock() 会清除 self._key 保证一致性。
            self._key = new_key
            self._key_epoch = new_epoch
            self._metadata_domain_key = self._compute_domain_key(new_key)
            EncryptionEngine.clear_cache()  # 旧密钥 cipher 已失效，确保后续用新密钥
            self._db.commit_transaction()
            entry_count = self._db.get_entry_count()
            logger.info("重加密完成 (%.1fms, %d 条)", (time.monotonic() - t0) * 1000, entry_count)
            # WAL 截断在事务提交之后执行；此时数据已落盘，截断失败非致命，
            # 单独捕获避免其异常冒泡导致 UI 显示模糊错误（事务其实已成功）。
            try:
                self._db.secure_checkpoint()
            except Exception:
                logger.warning("改密后 WAL 安全截断失败（非致命）", exc_info=True)

        except Exception:
            # 回滚所有变更，保护数据一致性
            rollback_ok = False
            try:
                self._db.rollback_transaction()
                rollback_ok = True
            except Exception:
                logger.error("改密回滚失败，数据库可能不一致", exc_info=True)
            if rollback_ok:
                self.lock()
            logger.error("重加密失败: 回滚所有变更", exc_info=True)
            raise

    def _re_encrypt_entries(self, old_key: bytes, new_key: bytes):
        """分批重新加密所有条目的敏感字段。

        逐字段解密→加密，减少同时驻留内存的明文数量。
        不变量：raw_entry 来自 get_entries，_row_to_entry 将 custom_fields
        设为与 custom_fields_enc 相同的密文字符串（str 类型），因此 getattr
        读取的是密文字符串，setattr 写入的也是密文字符串。
        若 _row_to_entry 的行为改变（如改为解密后设为 list），此处会静默损坏。

        P-03：每批收集所有更新行，通过 executemany 一次性写入，减少 N 次单独
        UPDATE 为 N/200 次 executemany 调用。
        """
        last_id = 0
        while True:
            batch = self._db.get_entries(
                include_deleted=True, limit=_RE_ENCRYPT_BATCH_SIZE,
                after_id=last_id,
            )
            if not batch:
                break
            last_id = batch[-1].id
            rows = []
            for raw_entry in batch:
                try:
                    for field in _ENCRYPTED_ENTRY_FIELDS:
                        value = getattr(raw_entry, field)
                        if value:
                            plain = _decrypt_field_impl(
                                value, old_key, raw_entry.crypto_id, field,
                            )
                            setattr(raw_entry, field,
                                    _encrypt_field_impl(plain, new_key, raw_entry.crypto_id, field))
                            del plain
                except ValueError:
                    logger.error("重加密中止：条目 id=%s 解密失败", raw_entry.id)
                    raise DecryptionError(
                        "某条目解密失败，数据可能已损坏。中止改密以保护数据完整性。"
                    )

                mac = self._sign_entry_metadata(raw_entry, new_key)
                # 列顺序须与 _RE_ENCRYPT_BATCH_UPDATE_SQL 匹配
                rows.append((
                    raw_entry.crypto_id, raw_entry.title,
                    raw_entry.username, raw_entry.password, raw_entry.url,
                    raw_entry.category_id, raw_entry.tags,
                    raw_entry.notes, raw_entry.custom_fields_db_value,
                    1 if raw_entry.is_favorite else 0,
                    raw_entry.password_strength, raw_entry.entry_type,
                    raw_entry.totp_secret, raw_entry.updated_at,
                    raw_entry.password_changed_at, mac,
                    raw_entry.id,
                ))
            self._db.update_entries_batch(rows)
            del batch, rows

    def _re_encrypt_history(self, old_key: bytes, new_key: bytes):
        """分批重新加密密码历史记录。

        M-P2：密码历史分批拉取，使用游标分页与条目批处理对齐，
        控制改密重加密时的内存峰值（复用 _RE_ENCRYPT_BATCH_SIZE）。

        M-15：每批收集所有更新行，通过 update_password_history_batch 一次性写入，
        将 N 次单独 UPDATE 合并为 N/200 次 executemany 调用。
        """
        last_history_id = 0
        while True:
            history_batch = self._db.get_all_password_history_batch(
                last_history_id, _RE_ENCRYPT_BATCH_SIZE
            )
            if not history_batch:
                break
            last_history_id = history_batch[-1].id or 0
            rows: list[tuple] = []
            for history in history_batch:
                if history.id is None:
                    continue  # 跳过无 ID 的历史记录（不应出现，防御性编程）
                try:
                    plaintext = _decrypt_field_impl(
                        history.old_password_enc, old_key,
                        history.entry_crypto_id, 'password',
                    )
                except ValueError as exc:
                    logger.error("重加密中止：密码历史 id=%s 解密失败", history.id)
                    raise DecryptionError(
                        "某密码历史记录解密失败，数据可能已损坏。"
                    ) from exc
                ciphertext = _encrypt_field_impl(
                    plaintext, new_key,
                    history.entry_crypto_id, 'password',
                )
                rows.append((ciphertext, history.id))
            if rows:
                self._db.update_password_history_batch(rows)
            del history_batch, rows

    def _update_vault_metadata(
        self, new_key: bytes, new_salt: bytes, new_verify_token: str, new_epoch: str,
    ):
        """更新 vault_meta 表中的验证信息和密钥元数据。"""
        if self._snapshot_key is None:
            raise RuntimeError('snapshot_key 未加载，无法更新保险库元数据')
        self._db.set_meta('master_salt', base64.b64encode(new_salt).decode('ascii'))
        self._db.set_meta('master_verify', new_verify_token)
        self._db.set_meta('master_kdf', 'pbkdf2-sha256')
        self._db.set_meta('master_kdf_iterations', str(PBKDF2_ITERATIONS))
        self._db.set_meta('ciphertext_format', EncryptionEngine.FORMAT_ID)
        self._db.set_meta(
            'snapshot_key_enc',
            EncryptionEngine.encrypt(
                base64.b64encode(self._snapshot_key).decode('ascii'),
                new_key,
                _SNAPSHOT_KEY_AAD,
            ),
        )
        self._db.set_meta('key_epoch', new_epoch)

    def _load_snapshot_key(self):
        key = self._key
        if key is None:
            raise VaultLockedError('保险库未解锁')
        encrypted = self._db.get_meta('snapshot_key_enc')
        if not encrypted:
            raise VaultLockedError('保险库缺少自动快照密钥')
        encoded = EncryptionEngine.decrypt(
            encrypted, key, _SNAPSHOT_KEY_AAD
        )
        self._snapshot_key = base64.b64decode(encoded)
        if len(self._snapshot_key) != 32:
            raise VaultIntegrityError('自动快照密钥损坏')

    @staticmethod
    def _entry_metadata_payload(entry, *, include_enc_hash: bool = True) -> bytes:
        data = {
            'crypto_id': entry.crypto_id,
            'title': entry.title,
            'url': entry.url,
            'category_id': entry.category_id,
            'tags': entry.tags,
            'is_favorite': bool(entry.is_favorite),
            'is_deleted': bool(entry.is_deleted),
            'password_strength': entry.password_strength,
            'entry_type': entry.entry_type,
            'created_at': entry.created_at,
            'updated_at': entry.updated_at,
            'deleted_at': entry.deleted_at,
            'password_changed_at': entry.password_changed_at,
        }
        if include_enc_hash:
            # SEC-05: 绑定加密字段密文到签名，防止密文置换/回滚攻击
            enc_concat = '|'.join([
                entry.username, entry.password, entry.notes,
                entry.totp_secret, entry.custom_fields_db_value,
            ])
            data['_enc_hash'] = hashlib.sha256(enc_concat.encode('utf-8')).hexdigest()
        return json.dumps(
            data,
            ensure_ascii=False,
            sort_keys=True,
            separators=(',', ':'),
        ).encode('utf-8')

    def _sign_entry_metadata(self, entry, key: bytes | None = None) -> str:
        signing_key = key or self._key
        if signing_key is None:
            raise VaultLockedError('保险库未解锁，无法签名条目元数据')
        # 使用预计算的域密钥（L1 优化），仅在 _re_encrypt_all 传入显式 key 时
        # 临时计算。
        if key is None and self._metadata_domain_key is not None:
            domain_key = self._metadata_domain_key
        else:
            domain_key = self._compute_domain_key(signing_key)
        return hmac.new(
            domain_key,
            self._entry_metadata_payload(entry),
            hashlib.sha256,
        ).hexdigest()

    def _verify_entry_metadata(self, entry):
        if not entry.metadata_mac:
            raise VaultIntegrityError(f'条目 {entry.id} 缺少元数据完整性签名')
        # SEC-05: 先尝试新格式（含加密字段哈希），失败后回退旧格式（自迁移策略）
        expected_new = self._sign_entry_metadata(entry)
        if hmac.compare_digest(entry.metadata_mac, expected_new):
            return
        # 回退旧格式（不含 _enc_hash）——兼容已有条目
        domain_key = self._metadata_domain_key
        if domain_key is None:
            if self._key is None:
                raise VaultLockedError('保险库未解锁')
            domain_key = self._compute_domain_key(self._key)
        expected_old = hmac.new(
            domain_key,
            self._entry_metadata_payload(entry, include_enc_hash=False),
            hashlib.sha256,
        ).hexdigest()
        if hmac.compare_digest(entry.metadata_mac, expected_old):
            logger.debug("条目 %s 签名使用旧格式，下次写入时自动升级", entry.id)
            return
        raise VaultIntegrityError(f'条目 {entry.id} 元数据完整性校验失败')

    def close(self):
        """关闭保险库"""
        self.lock()
        self._db.close()
