"""主密码管理 - PBKDF2 密钥派生与验证"""

import hmac
import logging
import os
import warnings

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .encryption import EncryptionEngine

logger = logging.getLogger(__name__)

# PBKDF2 迭代次数 (OWASP 2023 推荐)
PBKDF2_ITERATIONS = 600_000
MIN_PBKDF2_ITERATIONS = 100_000
MAX_PBKDF2_ITERATIONS = 2_000_000
SALT_SIZE = 32
KEY_SIZE = 32  # AES-256

# 验证令牌 - 用于验证主密码是否正确。
# SECURITY NOTE: 验证明文和 AAD 硬编码于源码中。攻击者若获取了数据库文件，
# 可从此常量构造伪造的 verify_token。但伪造需要先完成 PBKDF2 密钥派生
# （600k 迭代），因此在实践中，暴力破解密码的成本远高于利用此常量的成本。
# 更改此值会破坏所有已存在的保险库，不可接受。
VERIFY_PLAINTEXT = "CipherBox::MasterKey::Verification"
VERIFY_AAD = "vault:master-verification"


class MasterKeyManager:
    """主密码密钥管理器"""

    @classmethod
    def _validate_iterations(cls, iterations: int) -> None:
        """校验 PBKDF2 迭代次数是否在安全范围内。"""
        if not MIN_PBKDF2_ITERATIONS <= iterations <= MAX_PBKDF2_ITERATIONS:
            raise ValueError('PBKDF2 参数无效')

    @classmethod
    def derive_backup_key(cls, password: str, salt: bytes, iterations: int) -> bytes:
        """从备份密码派生独立的备份加密密钥（与主密钥域分离）。"""
        cls._validate_iterations(iterations)
        return cls.derive_key(password, b'backup:' + salt, iterations)

    @classmethod
    def derive_backup_key_legacy(cls, password: str, salt: bytes, iterations: int) -> bytes:
        """旧版备份密钥派生（无域前缀），仅用于向后兼容旧备份文件。"""
        warnings.warn(
            "derive_backup_key_legacy 已废弃，将在未来版本移除。"
            "请使用 derive_backup_key 代替。",
            DeprecationWarning,
            stacklevel=2,
        )
        cls._validate_iterations(iterations)
        return cls.derive_key(password, salt, iterations)

    @classmethod
    def derive_key(
        cls,
        password: str,
        salt: bytes,
        iterations: int = PBKDF2_ITERATIONS,
    ) -> bytes:
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
            iterations=iterations,
        )
        return kdf.derive(password.encode('utf-8'))

    @classmethod
    def create(
        cls,
        password: str,
        iterations: int = PBKDF2_ITERATIONS,
    ) -> tuple[bytes, str, bytes]:
        """创建新的主密码凭据

        Args:
            password: 主密码

        Returns:
            (salt, encrypted_verify_token, derived_key) 元组
        """
        salt = os.urandom(SALT_SIZE)
        cls._validate_iterations(iterations)
        key = cls.derive_key(password, salt, iterations)
        verify_token = EncryptionEngine.encrypt(VERIFY_PLAINTEXT, key, VERIFY_AAD)
        logger.info("主密钥凭据已生成")
        return salt, verify_token, key

    @classmethod
    def verify(
        cls,
        password: str,
        salt: bytes,
        verify_token: str,
        iterations: int = PBKDF2_ITERATIONS,
    ) -> bytes | None:
        """验证主密码

        Args:
            password: 用户输入的密码
            salt: 存储的盐值
            verify_token: 存储的验证令牌

        Returns:
            验证成功返回派生密钥，失败返回 None
        """
        cls._validate_iterations(iterations)
        key = cls.derive_key(password, salt, iterations)
        try:
            decrypted = EncryptionEngine.decrypt(verify_token, key, VERIFY_AAD)
            if hmac.compare_digest(decrypted, VERIFY_PLAINTEXT):
                return key
        except ValueError:
            pass
        logger.debug("主密码验证失败")
        return None

    @classmethod
    def change_password(
        cls,
        old_password: str,
        new_password: str,
        old_salt: bytes,
        old_verify_token: str,
        old_iterations: int = PBKDF2_ITERATIONS,
        new_iterations: int = PBKDF2_ITERATIONS,
    ) -> tuple[bytes, str, bytes] | None:
        """修改主密码

        Args:
            old_password: 旧密码
            new_password: 新密码
            old_salt: 旧盐值
            old_verify_token: 旧验证令牌

        Returns:
            成功返回 (new_salt, new_verify_token, new_key) 三元组，失败返回 None。
            返回 new_key 以便调用方（VaultManager）复用 ``create`` 内部已派生的
            新密钥，避免在重加密流程中重复执行一次 PBKDF2 600k 迭代。
        """
        old_key = cls.verify(
            old_password, old_salt, old_verify_token, old_iterations
        )
        if old_key is None:
            return None
        new_salt, new_verify_token, new_key = cls.create(
            new_password, new_iterations
        )
        return new_salt, new_verify_token, new_key
