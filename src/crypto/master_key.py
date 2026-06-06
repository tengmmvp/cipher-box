"""主密码管理 - PBKDF2 密钥派生与验证"""

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .encryption import EncryptionEngine

# PBKDF2 迭代次数 (OWASP 2023 推荐)
PBKDF2_ITERATIONS = 600_000
SALT_SIZE = 32
KEY_SIZE = 32  # AES-256

# 验证令牌 - 用于验证主密码是否正确
VERIFY_PLAINTEXT = "CipherBox::MasterKey::Verification::v1"


class MasterKeyManager:
    """主密码密钥管理器"""

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """使用 PBKDF2-HMAC-SHA256 从密码派生 256 位密钥

        Args:
            password: 主密码明文
            salt: 随机盐值

        Returns:
            32 字节密钥
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        return kdf.derive(password.encode('utf-8'))

    @staticmethod
    def create(password: str) -> tuple[bytes, str]:
        """创建新的主密码凭据

        Args:
            password: 主密码

        Returns:
            (salt, encrypted_verify_token) 元组
        """
        salt = os.urandom(SALT_SIZE)
        key = MasterKeyManager.derive_key(password, salt)
        verify_token = EncryptionEngine.encrypt(VERIFY_PLAINTEXT, key)
        return salt, verify_token

    @staticmethod
    def verify(password: str, salt: bytes, verify_token: str) -> bytes | None:
        """验证主密码

        Args:
            password: 用户输入的密码
            salt: 存储的盐值
            verify_token: 存储的验证令牌

        Returns:
            验证成功返回派生密钥，失败返回 None
        """
        key = MasterKeyManager.derive_key(password, salt)
        try:
            decrypted = EncryptionEngine.decrypt(verify_token, key)
            if decrypted == VERIFY_PLAINTEXT:
                return key
        except ValueError:
            pass
        return None

    @staticmethod
    def change_password(
        old_password: str,
        new_password: str,
        old_salt: bytes,
        old_verify_token: str,
    ) -> tuple[bytes, str, bytes] | None:
        """修改主密码

        Args:
            old_password: 旧密码
            new_password: 新密码
            old_salt: 旧盐值
            old_verify_token: 旧验证令牌

        Returns:
            成功返回 (new_salt, new_verify_token, old_key) 元组，
            失败返回 None
        """
        old_key = MasterKeyManager.verify(old_password, old_salt, old_verify_token)
        if old_key is None:
            return None
        new_salt, new_verify_token = MasterKeyManager.create(new_password)
        return new_salt, new_verify_token, old_key
