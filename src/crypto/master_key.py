"""主密码管理 — PBKDF2-HMAC-SHA256 密钥派生与验证。

使用 PBKDF2 从主密码派生 256 位 AES 密钥，迭代次数默认 600k，遵循 OWASP 2023 推荐。
密码验证不存储哈希，而是加密一段已知明文作为验证令牌来确认密码正确性，
验证令牌和 AAD 硬编码于源码中——伪造需要先完成 PBKDF2 派生，暴力破解成本远高于
利用此常量的成本。更改验证令牌值会破坏所有已存在的保险库。
"""

import hmac
import logging
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .encryption import EncryptionEngine

logger = logging.getLogger(__name__)

# PBKDF2 迭代次数，遵循 OWASP 2023 推荐
PBKDF2_ITERATIONS = 600_000
MIN_PBKDF2_ITERATIONS = 100_000
MAX_PBKDF2_ITERATIONS = 2_000_000
SALT_SIZE = 32
# PBKDF2 盐最小长度。空盐或过短盐会显著降低派生强度（空盐退化为固定盐），
# 拒绝过短输入避免静默降级。主盐 32 字节，备份盐经 b'backup:' 前缀后 39 字节。
MIN_SALT_SIZE = 16
KEY_SIZE = 32  # AES-256

# 验证令牌与 AAD。详细安全分析见模块文档。
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
    def _validate_salt(cls, salt: bytes) -> None:
        """校验盐值的类型与最小长度，防止空盐/过短盐导致派生强度静默降级。

        空盐会使 PBKDF2 退化为无盐派生，丧失针对彩虹表/预计算的防护；
        过短盐则降低唯一性。主路径盐为 32 字节随机，此处仅作下限守卫。
        """
        if not isinstance(salt, (bytes, bytearray)):
            raise TypeError(f'盐值类型无效：期望 bytes，实际 {type(salt).__name__}')
        if len(salt) < MIN_SALT_SIZE:
            raise ValueError(
                f'盐值过短：期望至少 {MIN_SALT_SIZE} 字节，实际 {len(salt)} 字节'
            )

    @classmethod
    def derive_backup_key(cls, password: str, salt: bytes, iterations: int) -> bytearray:
        """从备份密码派生独立的备份加密密钥，与主密钥域分离。

        先独立校验原始盐长度再拼接域前缀派生。若直接把 ``b'backup:' + salt``
        交给 derive_key，其内部 _validate_salt 校验的是拼接后的 7+len(salt)，
        调用方传 9 字节盐即可绕过 MIN_SALT_SIZE 下限，实际熵不足。
        """
        cls._validate_iterations(iterations)
        cls._validate_salt(salt)
        return cls.derive_key(password, b'backup:' + salt, iterations)

    @classmethod
    def derive_key(
        cls,
        password: str,
        salt: bytes,
        iterations: int = PBKDF2_ITERATIONS,
    ) -> bytearray:
        """使用 PBKDF2-HMAC-SHA256 从密码派生 256 位密钥

        Args:
            password: 主密码明文
            salt: 随机盐值

        Returns:
            32 字节密钥 bytearray。返回 bytearray 而非 bytes，以便
            secure_zero_buffer 真正清零；PBKDF2 内部派生的中间 bytes
            依赖 GC 回收。
        """
        if not isinstance(password, str):
            raise TypeError(f'密码类型无效：期望 str，实际 {type(password).__name__}')
        cls._validate_salt(salt)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=iterations,
        )
        return bytearray(kdf.derive(password.encode('utf-8')))

    @classmethod
    def create(
        cls,
        password: str,
        iterations: int = PBKDF2_ITERATIONS,
    ) -> tuple[bytes, str, bytearray]:
        """创建新的主密码凭据

        Args:
            password: 主密码

        Returns:
            由盐值、加密后的验证令牌、派生密钥构成的元组
        """
        salt = os.urandom(SALT_SIZE)
        cls._validate_iterations(iterations)
        key = cls.derive_key(password, salt, iterations)
        try:
            verify_token = EncryptionEngine.encrypt(VERIFY_PLAINTEXT, key, VERIFY_AAD)
        except Exception:
            # 验证令牌加密失败时 key 不再返回，原地清零已派生密钥，收缩驻留，
            # 避免异常路径泄漏派生密钥到调用栈帧后依赖 GC 回收。
            key[:] = b'\x00' * len(key)
            raise
        logger.info("主密钥凭据已生成")
        return salt, verify_token, key

    @classmethod
    def verify(
        cls,
        password: str,
        salt: bytes,
        verify_token: str,
        iterations: int = PBKDF2_ITERATIONS,
    ) -> bytearray | None:
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
        # 验证失败：派生密钥不再返回，原地清零收缩驻留（与 create 异常路径一致）。
        # 登录是最频繁的错误密码入口，避免每次输错都把 60 万次迭代派生的密钥留给 GC。
        key[:] = b'\x00' * len(key)
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
    ) -> tuple[bytes, str, bytearray] | None:
        """修改主密码

        Args:
            old_password: 旧密码
            new_password: 新密码
            old_salt: 旧盐值
            old_verify_token: 旧验证令牌

        Returns:
            成功时返回由新盐值、新验证令牌、新派生密钥构成的三元组，失败返回 None。
            其中新密钥直接复用 create 内部派生结果，避免重加密流程再次执行
            PBKDF2 的 60 万次迭代。
        """
        old_key = cls.verify(
            old_password, old_salt, old_verify_token, old_iterations
        )
        if old_key is None:
            return None
        try:
            new_salt, new_verify_token, new_key = cls.create(
                new_password, new_iterations
            )
            return new_salt, new_verify_token, new_key
        finally:
            # old_key 为 verify 返回的 bytearray（旧密钥派生结果），仅用于验证旧密码，
            # 验证通过后不再需要。原地清零收缩其在内存/swap 的驻留，与 _re_encrypt_all
            # 的旧密钥清理一致。bytearray 切片赋值实现原地擦除，不引入 utils.memory
            # 依赖以保持 crypto 层纯净（此处清零的是局部副本，不影响 KeyManager 内部对象）。
            old_key[:] = b'\x00' * len(old_key)
