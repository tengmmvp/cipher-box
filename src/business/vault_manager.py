"""保险库管理器 - 高层保险库操作"""

import base64
import logging
from typing import Optional

logger = logging.getLogger(__name__)

from ..config import ConfigManager
from ..crypto.master_key import MasterKeyManager
from ..crypto.encryption import EncryptionEngine
from ..database.db_manager import DatabaseManager


class VaultManager:
    """管理保险库的创建、解锁、锁定等操作"""

    def __init__(self, config: ConfigManager):
        self._config = config
        self._db = DatabaseManager(config.db_path)
        self._key: Optional[bytes] = None
        self._is_unlocked = False

    @property
    def db(self) -> DatabaseManager:
        return self._db

    @property
    def is_initialized(self) -> bool:
        """保险库是否已初始化（是否设置了主密码）"""
        if not self._config.db_path.exists():
            return False
        if not self._db._conn:
            self._db.open()
        salt_b64 = self._db.get_meta('master_salt')
        return salt_b64 is not None

    @property
    def is_unlocked(self) -> bool:
        return self._is_unlocked and self._key is not None

    @property
    def key(self) -> Optional[bytes]:
        return self._key

    def initialize(self, master_password: str) -> bool:
        """首次初始化保险库，设置主密码

        Args:
            master_password: 主密码

        Returns:
            是否成功
        """
        try:
            salt, verify_token = MasterKeyManager.create(master_password)
            self._db.open()
            self._db.init_tables()
            self._db.begin_transaction()
            try:
                self._db.set_meta('master_salt', base64.b64encode(salt).decode('ascii'))
                self._db.set_meta('master_verify', verify_token)
                self._db.set_meta('version', '1')
                self._db.commit_transaction()
            except Exception:
                self._db.rollback_transaction()
                raise
            self._key = MasterKeyManager.derive_key(master_password, salt)
            self._is_unlocked = True
            return True
        except Exception:
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
            if not self._db._conn:
                self._db.open()
            self._db.init_tables()

            salt_b64 = self._db.get_meta('master_salt')
            verify_token = self._db.get_meta('master_verify')

            if not salt_b64 or not verify_token:
                return False

            salt = base64.b64decode(salt_b64)
            key = MasterKeyManager.verify(master_password, salt, verify_token)

            if key is None:
                return False

            self._key = key
            self._is_unlocked = True
            return True
        except Exception:
            logger.warning("解锁失败", exc_info=True)
            return False

    def lock(self):
        """锁定保险库"""
        self._key = None
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
            result = MasterKeyManager.change_password(
                old_password, new_password, old_salt, verify_token
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
        new_key = MasterKeyManager.derive_key(new_password, new_salt)

        # 获取所有条目（含已删除，确保改密后恢复仍可用）
        rows = self._db.get_entries(include_deleted=True)
        history_rows = self._db.get_all_password_history()

        # 使用真实事务：begin_transaction 抑制内部 commit
        self._db.begin_transaction()

        try:
            failed_ids = []
            for raw_entry in rows:
                # 用旧密钥解密——失败时记录但中止整个操作
                try:
                    raw_entry.username = EncryptionEngine.decrypt(raw_entry.username, old_key) if raw_entry.username else ''
                    raw_entry.password = EncryptionEngine.decrypt(raw_entry.password, old_key) if raw_entry.password else ''
                    raw_entry.notes = EncryptionEngine.decrypt(raw_entry.notes, old_key) if raw_entry.notes else ''
                    raw_entry.totp_secret = EncryptionEngine.decrypt(raw_entry.totp_secret, old_key) if raw_entry.totp_secret else ''
                    if raw_entry.custom_fields:
                        raw_entry.custom_fields = EncryptionEngine.decrypt(raw_entry.custom_fields, old_key)
                except ValueError:
                    failed_ids.append(raw_entry.id)
                    raise RuntimeError(
                        f"条目 {raw_entry.id} ({raw_entry.title}) 解密失败，"
                        f"数据可能已损坏。中止改密以保护数据完整性。"
                    )

                # 用新密钥重新加密并更新
                raw_entry.username = EncryptionEngine.encrypt(raw_entry.username, new_key) if raw_entry.username else ''
                raw_entry.password = EncryptionEngine.encrypt(raw_entry.password, new_key) if raw_entry.password else ''
                raw_entry.notes = EncryptionEngine.encrypt(raw_entry.notes, new_key) if raw_entry.notes else ''
                raw_entry.custom_fields = EncryptionEngine.encrypt(raw_entry.custom_fields, new_key) if raw_entry.custom_fields else ''
                raw_entry.totp_secret = EncryptionEngine.encrypt(raw_entry.totp_secret, new_key) if raw_entry.totp_secret else ''

                self._db.update_entry(raw_entry, preserve_updated_at=True)

            for history in history_rows:
                try:
                    plaintext = EncryptionEngine.decrypt(history.old_password_enc, old_key)
                except ValueError as exc:
                    raise RuntimeError(
                        f"密码历史 {history.id} 解密失败，数据可能已损坏。"
                    ) from exc
                ciphertext = EncryptionEngine.encrypt(plaintext, new_key)
                self._db.update_password_history_ciphertext(history.id, ciphertext)

            # 更新存储的验证信息
            self._db.set_meta('master_salt', base64.b64encode(new_salt).decode('ascii'))
            self._db.set_meta('master_verify', new_verify_token)

            # 全部成功 → 统一提交
            self._db.commit_transaction()
            self._key = new_key

        except Exception:
            # 回滚所有变更，保护数据一致性
            self._db.rollback_transaction()
            self._key = None
            self._is_unlocked = False
            logger.error("重加密失败: 回滚所有变更", exc_info=True)
            raise

    def close(self):
        """关闭保险库"""
        self.lock()
        self._db.close()
