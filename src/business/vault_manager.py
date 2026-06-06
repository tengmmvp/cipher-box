"""保险库管理器 - 高层保险库操作"""

import base64
import logging
import os
import uuid
from typing import Optional

logger = logging.getLogger(__name__)

from ..config import ConfigManager
from ..crypto.master_key import MasterKeyManager, PBKDF2_ITERATIONS
from ..crypto.encryption import EncryptionEngine
from ..database.db_manager import DatabaseManager


class VaultManager:
    """管理保险库的创建、解锁、锁定等操作"""

    def __init__(self, config: ConfigManager):
        self._config = config
        self._db = DatabaseManager(config.db_path)
        self._db.set_write_guard(self.assert_current_key)
        self._key: Optional[bytes] = None
        self._is_unlocked = False
        self._key_epoch: str | None = None
        self._snapshot_key: bytes | None = None
        self._last_error = ''

    @property
    def db(self) -> DatabaseManager:
        return self._db

    @property
    def data_dir(self):
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
            if not self._db.is_open and not self._db.open():
                self._last_error = '数据库无法打开'
                return True
            self._db.init_tables()
            salt_b64 = self._db.get_meta('master_salt')
            return salt_b64 is not None
        except Exception as exc:
            self._last_error = str(exc) or '保险库格式无效'
            logger.error("检查保险库状态失败", exc_info=True)
            return self._config.db_path.stat().st_size > 0

    @property
    def is_unlocked(self) -> bool:
        return self._is_unlocked and self._key is not None

    @property
    def key(self) -> Optional[bytes]:
        return self._key

    @property
    def snapshot_key(self) -> bytes:
        if not self.is_unlocked or self._snapshot_key is None:
            raise RuntimeError('自动快照密钥不可用')
        return self._snapshot_key

    def assert_current_key(self):
        """拒绝锁定状态或主密钥已轮换的旧会话写入数据库。"""
        if self._key_epoch is None:
            return
        if not self.is_unlocked:
            raise RuntimeError("保险库已锁定，不能写入数据")
        current_epoch = self._db.get_meta('key_epoch')
        if current_epoch and current_epoch != self._key_epoch:
            self.lock()
            raise RuntimeError("保险库密钥已被其他进程更新，请重新启动并解锁")

    def initialize(self, master_password: str) -> bool:
        """首次初始化保险库，设置主密码

        Args:
            master_password: 主密码

        Returns:
            是否成功
        """
        try:
            self._last_error = ''
            salt, verify_token = MasterKeyManager.create(
                master_password, PBKDF2_ITERATIONS
            )
            self._db.open()
            self._db.init_tables()
            derived_key = MasterKeyManager.derive_key(
                master_password, salt, PBKDF2_ITERATIONS
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
                        'vault:snapshot-key',
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
            self._is_unlocked = True
            return True
        except Exception as exc:
            self._last_error = str(exc) or '保险库初始化失败'
            logger.error("保险库初始化失败", exc_info=True)
            return False

    def unlock(self, master_password: str) -> bool:
        """使用主密码解锁保险库

        Args:
            master_password: 主密码

        Returns:
            是否成功
        """
        try:
            self._last_error = ''
            if not self._db.is_open and not self._db.open():
                raise RuntimeError('数据库无法打开')
            self._db.init_tables()

            salt_b64 = self._db.get_meta('master_salt')
            verify_token = self._db.get_meta('master_verify')

            if not salt_b64 or not verify_token:
                self._last_error = '保险库凭据不完整'
                return False

            salt = base64.b64decode(salt_b64)
            iterations_text = self._db.get_meta('master_kdf_iterations')
            if not iterations_text:
                raise RuntimeError('保险库缺少密钥派生参数')
            iterations = int(iterations_text)
            key = MasterKeyManager.verify(
                master_password, salt, verify_token, iterations
            )

            if key is None:
                return False

            self._key = key
            if self._db.get_meta('master_kdf') != 'pbkdf2-sha256':
                raise RuntimeError('不支持的主密钥派生格式')
            if self._db.get_meta('ciphertext_format') != EncryptionEngine.FORMAT_ID:
                raise RuntimeError('不支持的密文格式')
            self._key_epoch = self._db.get_meta('key_epoch')
            if not self._key_epoch:
                raise RuntimeError('保险库缺少当前格式的密钥版本')
            self._is_unlocked = True
            self._load_snapshot_key()
            return True
        except Exception as exc:
            self.lock()
            self._last_error = str(exc) or '保险库无法解锁'
            logger.warning("解锁失败", exc_info=True)
            return False

    def lock(self):
        """锁定保险库"""
        self._key = None
        self._snapshot_key = None
        self._is_unlocked = False

    def change_master_password(
        self, old_password: str, new_password: str
    ) -> bool:
        """修改主密码

        Args:
            old_password: 旧主密码
            new_password: 新主密码

        Returns:
            是否成功
        """
        try:
            salt_b64 = self._db.get_meta('master_salt')
            verify_token = self._db.get_meta('master_verify')
            if not salt_b64 or not verify_token:
                return False

            old_salt = base64.b64decode(salt_b64)
            iterations_text = self._db.get_meta('master_kdf_iterations')
            if not iterations_text:
                raise RuntimeError('保险库缺少密钥派生参数')
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
                return False

            new_salt, new_verify_token, _ = result

            # 用新密钥重新加密所有条目的敏感字段
            self._re_encrypt_all(new_password, new_salt, new_verify_token)

            return True
        except RuntimeError:
            raise  # 让 RuntimeError（如重加密失败）向上传播到 UI 层
        except Exception:
            return False

    def _re_encrypt_all(self, new_password: str, new_salt: bytes, new_verify_token: str):
        """使用新密钥重新加密所有条目（含已删除），事务保护"""
        assert self._key is not None

        old_key = self._key
        new_key = MasterKeyManager.derive_key(
            new_password, new_salt, PBKDF2_ITERATIONS
        )
        new_epoch = uuid.uuid4().hex

        # 获取所有条目（含已删除，确保改密后恢复仍可用）
        rows = self._db.get_entries(include_deleted=True)
        history_rows = self._db.get_all_password_history()

        # 使用真实事务：begin_transaction 抑制内部 commit
        self._db.begin_transaction()

        try:
            for raw_entry in rows:
                # 用旧密钥解密——失败时记录但中止整个操作
                try:
                    raw_entry.username = self._decrypt_entry_field(raw_entry, 'username', raw_entry.username, old_key)
                    raw_entry.password = self._decrypt_entry_field(raw_entry, 'password', raw_entry.password, old_key)
                    raw_entry.notes = self._decrypt_entry_field(raw_entry, 'notes', raw_entry.notes, old_key)
                    raw_entry.totp_secret = self._decrypt_entry_field(raw_entry, 'totp_secret', raw_entry.totp_secret, old_key)
                    if raw_entry.custom_fields:
                        raw_entry.custom_fields = self._decrypt_entry_field(
                            raw_entry, 'custom_fields', raw_entry.custom_fields, old_key
                        )
                except ValueError:
                    raise RuntimeError(
                        f"条目 {raw_entry.id} ({raw_entry.title}) 解密失败，"
                        f"数据可能已损坏。中止改密以保护数据完整性。"
                    )

                # 用新密钥重新加密并更新
                raw_entry.username = self._encrypt_entry_field(raw_entry, 'username', raw_entry.username, new_key)
                raw_entry.password = self._encrypt_entry_field(raw_entry, 'password', raw_entry.password, new_key)
                raw_entry.notes = self._encrypt_entry_field(raw_entry, 'notes', raw_entry.notes, new_key)
                raw_entry.custom_fields = self._encrypt_entry_field(raw_entry, 'custom_fields', raw_entry.custom_fields, new_key)
                raw_entry.totp_secret = self._encrypt_entry_field(raw_entry, 'totp_secret', raw_entry.totp_secret, new_key)

                self._db.update_entry(raw_entry, preserve_updated_at=True)

            for history in history_rows:
                try:
                    plaintext = EncryptionEngine.decrypt(
                        history.old_password_enc,
                        old_key,
                        self._aad(history.entry_crypto_id, 'password'),
                    )
                except ValueError as exc:
                    raise RuntimeError(
                        f"密码历史 {history.id} 解密失败，数据可能已损坏。"
                    ) from exc
                ciphertext = EncryptionEngine.encrypt(
                    plaintext,
                    new_key,
                    self._aad(history.entry_crypto_id, 'password'),
                )
                self._db.update_password_history_ciphertext(history.id, ciphertext)

            # 更新存储的验证信息
            self._db.set_meta('master_salt', base64.b64encode(new_salt).decode('ascii'))
            self._db.set_meta('master_verify', new_verify_token)
            self._db.set_meta('master_kdf', 'pbkdf2-sha256')
            self._db.set_meta('master_kdf_iterations', str(PBKDF2_ITERATIONS))
            self._db.set_meta('ciphertext_format', EncryptionEngine.FORMAT_ID)
            if self._snapshot_key is not None:
                self._db.set_meta(
                    'snapshot_key_enc',
                    EncryptionEngine.encrypt(
                        base64.b64encode(self._snapshot_key).decode('ascii'),
                        new_key,
                        'vault:snapshot-key',
                    ),
                )
            self._db.set_meta('key_epoch', new_epoch)

            # 全部成功 → 统一提交
            self._db.commit_transaction()
            self._key = new_key
            self._key_epoch = new_epoch
            self._db.secure_checkpoint()

        except Exception:
            # 回滚所有变更，保护数据一致性
            self._db.rollback_transaction()
            self._key = None
            self._is_unlocked = False
            logger.error("重加密失败: 回滚所有变更", exc_info=True)
            raise

    def _load_snapshot_key(self):
        key = self._key
        if key is None:
            raise RuntimeError('保险库未解锁')
        encrypted = self._db.get_meta('snapshot_key_enc')
        if not encrypted:
            raise RuntimeError('保险库缺少自动快照密钥')
        encoded = EncryptionEngine.decrypt(
            encrypted, key, 'vault:snapshot-key'
        )
        self._snapshot_key = base64.b64decode(encoded)
        if len(self._snapshot_key) != 32:
            raise RuntimeError('自动快照密钥损坏')

    @staticmethod
    def _aad(crypto_id: str, field_name: str) -> str:
        return f'entry:{crypto_id}:{field_name}'

    def _decrypt_entry_field(self, entry, field_name: str, value: str, key: bytes) -> str:
        if not value:
            return ''
        return EncryptionEngine.decrypt(
            value, key, self._aad(entry.crypto_id, field_name)
        )

    def _encrypt_entry_field(self, entry, field_name: str, value: str, key: bytes) -> str:
        if not value:
            return ''
        return EncryptionEngine.encrypt(
            value, key, self._aad(entry.crypto_id, field_name)
        )

    def close(self):
        """关闭保险库"""
        self.lock()
        self._db.close()
