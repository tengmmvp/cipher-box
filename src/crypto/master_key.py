"""主密码管理 — Argon2id 密钥派生与验证。

使用 Argon2id（OWASP 2024+ 首选内存硬化 KDF）从主密码派生 256 位 AES 密钥。
内存硬化使 GPU/ASIC 并行加速攻击的成本远高于 PBKDF2。密码验证不存储哈希，
而是加密一段已知明文（验证令牌）来确认密码正确性，验证令牌和 AAD 硬编码于
源码中——伪造需要先完成 Argon2id 派生，暴力破解成本远高于利用此常量的成本。
"""

import hmac
import logging
import os
from typing import NamedTuple

from argon2.low_level import Type, hash_secret_raw

from ..utils.memory import secure_zero_buffer
from .encryption import EncryptionEngine

logger = logging.getLogger(__name__)

# Argon2id 参数（OWASP 2024 推荐量级）。time_cost/memory_cost/parallelism 共同决定
# 派生强度；memory_cost 单位为 KiB，64*1024 即 64 MB，使 GPU 并行攻击需付出大量显存。
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 64 * 1024  # 64 MB（KiB）
ARGON2_PARALLELISM = 4
SALT_SIZE = 32
# Argon2id 盐最小长度。空盐或过短盐会显著降低派生强度（空盐退化为固定盐），
# 拒绝过短输入避免静默降级。主盐 32 字节，备份盐经 b'backup:' 前缀后 39 字节。
MIN_SALT_SIZE = 16
KEY_SIZE = 32  # AES-256

# KDF 参数校验范围：防 vault_meta 被篡改为明显异常的参数（如 memory_cost=8）后
# 仍被接受。下限为「格式校验」量级，故意低于 DEFAULT_KDF_PARAMS（time=3/64MB/p=4），
# 以兼容测试弱化参数与未来调参灵活性——派生强度的真正保证依赖 vault_meta_mac
# 完整性签名：攻击者无主密钥无法重算 MAC，故无法在保持解密可行的前提下篡改 KDF
# 参数（篡改会使派生密钥变化，verify_token 解密先行失败）。
MIN_ARGON2_TIME_COST = 2
MAX_ARGON2_TIME_COST = 10
MIN_ARGON2_MEMORY_COST = 16 * 1024  # 16 MB
MAX_ARGON2_MEMORY_COST = 1024 * 1024  # 1 GB
MIN_ARGON2_PARALLELISM = 1
MAX_ARGON2_PARALLELISM = 16

# KDF 标识，写入 vault_meta 的 master_kdf 字段，解锁时校验。
KDF_NAME = 'argon2id'


class KdfParams(NamedTuple):
    """Argon2id 派生参数，供 vault_meta 持久化与跨调用传递。"""

    time_cost: int
    memory_cost: int
    parallelism: int


DEFAULT_KDF_PARAMS = KdfParams(ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_PARALLELISM)

# 验证令牌与 AAD。详细安全分析见模块文档。
VERIFY_PLAINTEXT = "CipherBox::MasterKey::Verification"
VERIFY_AAD = "vault:master-verification"


class MasterKeyManager:
    """主密码密钥管理器。"""

    @classmethod
    def validate_params(cls, params: KdfParams) -> None:
        """公开校验 KDF 参数，供备份头等持久化格式在派生前复用。"""
        cls._validate_params(params)

    @classmethod
    def _validate_params(cls, params: KdfParams) -> None:
        """校验 Argon2id 参数是否在安全范围内，防止 meta 篡改导致静默降级。"""
        if not MIN_ARGON2_TIME_COST <= params.time_cost <= MAX_ARGON2_TIME_COST:
            raise ValueError('Argon2id time_cost 参数无效')
        if not MIN_ARGON2_MEMORY_COST <= params.memory_cost <= MAX_ARGON2_MEMORY_COST:
            raise ValueError('Argon2id memory_cost 参数无效')
        if not MIN_ARGON2_PARALLELISM <= params.parallelism <= MAX_ARGON2_PARALLELISM:
            raise ValueError('Argon2id parallelism 参数无效')

    @classmethod
    def _validate_salt(cls, salt: bytes) -> None:
        """校验盐值的类型与最小长度，防止空盐/过短盐导致派生强度静默降级。"""
        if not isinstance(salt, (bytes, bytearray)):
            raise TypeError(f'盐值类型无效：期望 bytes，实际 {type(salt).__name__}')
        if len(salt) < MIN_SALT_SIZE:
            raise ValueError(
                f'盐值过短：期望至少 {MIN_SALT_SIZE} 字节，实际 {len(salt)} 字节'
            )

    @classmethod
    def derive_backup_key(
        cls, password: str, salt: bytes, params: KdfParams = DEFAULT_KDF_PARAMS,
    ) -> bytearray:
        """从备份密码派生独立的备份加密密钥，与主密钥域分离。

        先独立校验原始盐长度再拼接域前缀派生。若直接把 ``b'backup:' + salt``
        交给 derive_key，其内部 _validate_salt 校验的是拼接后的 7+len(salt)，
        调用方传 9 字节盐即可绕过 MIN_SALT_SIZE 下限，实际熵不足。

        域分离用 ``b'backup:'`` 字符串前缀混入 Argon2id 的 salt 字段，而非独立
        HKDF info——功能上正确（不同 salt → 不同密钥），且经独立盐校验规避了前缀
        绕过。未来若新增第三域（如导出密钥），可演进为显式 HKDF domain separation
        以消除前缀碰撞的隐式假设。
        """
        cls._validate_params(params)
        cls._validate_salt(salt)
        return cls.derive_key(password, b'backup:' + salt, params)

    @classmethod
    def derive_key(
        cls,
        password: str,
        salt: bytes,
        params: KdfParams = DEFAULT_KDF_PARAMS,
    ) -> bytearray:
        """使用 Argon2id 从密码派生 256 位密钥

        Args:
            password: 主密码明文
            salt: 随机盐值
            params: Argon2id 参数

        Returns:
            32 字节密钥 bytearray。返回 bytearray 而非 bytes，以便
            _secure_zero 原地覆写底层缓冲（bytes 不可变只能清零副本）。
        """
        if not isinstance(password, str):
            raise TypeError(f'密码类型无效：期望 str，实际 {type(password).__name__}')
        cls._validate_salt(salt)
        return bytearray(hash_secret_raw(
            secret=password.encode('utf-8'),
            salt=bytes(salt),
            time_cost=params.time_cost,
            memory_cost=params.memory_cost,
            parallelism=params.parallelism,
            hash_len=KEY_SIZE,
            type=Type.ID,
        ))

    @classmethod
    def create(
        cls,
        password: str,
        params: KdfParams = DEFAULT_KDF_PARAMS,
    ) -> tuple[bytes, str, bytearray]:
        """创建新的主密码凭据

        Args:
            password: 主密码
            params: Argon2id 参数

        Returns:
            由盐值、加密后的验证令牌、派生密钥构成的元组
        """
        salt = os.urandom(SALT_SIZE)
        cls._validate_params(params)
        key = cls.derive_key(password, salt, params)
        try:
            verify_token = EncryptionEngine.encrypt(VERIFY_PLAINTEXT, key, VERIFY_AAD)
        except Exception:
            # 验证令牌加密失败时 key 不再返回，原地清零已派生密钥，收缩驻留，
            # 避免异常路径泄漏派生密钥到调用栈帧后依赖 GC 回收。
            secure_zero_buffer(key)
            raise
        logger.info("主密钥凭据已生成")
        return salt, verify_token, key

    @classmethod
    def verify(
        cls,
        password: str,
        salt: bytes,
        verify_token: str,
        params: KdfParams = DEFAULT_KDF_PARAMS,
    ) -> bytearray | None:
        """验证主密码

        Args:
            password: 用户输入的密码
            salt: 存储的盐值
            verify_token: 存储的验证令牌
            params: Argon2id 参数

        Returns:
            验证成功返回派生密钥，失败返回 None
        """
        cls._validate_params(params)
        key = cls.derive_key(password, salt, params)
        try:
            decrypted = EncryptionEngine.decrypt(verify_token, key, VERIFY_AAD)
        except ValueError as exc:
            # decrypt 将 InvalidTag（GCM 认证失败，即密码错误）与其他 ValueError
            # （令牌格式损坏）归一化为 ValueError。区分二者便于事后审计「密码错」
            # 与「令牌损坏」，诊断损坏的 verify_token 反复触发速率锁定的情况。
            logger.debug("主密码验证失败：令牌解密异常 %s", type(exc).__name__)
        else:
            if hmac.compare_digest(decrypted, VERIFY_PLAINTEXT):
                return key
            logger.debug("主密码验证失败：验证令牌明文不匹配（令牌可能损坏）")
        # 验证失败：派生密钥不再返回，原地清零收缩驻留。
        # 登录是最频繁的错误密码入口，避免每次输错都把 Argon2id 派生的密钥留给 GC。
        secure_zero_buffer(key)
        return None

    @classmethod
    def change_password(
        cls,
        old_password: str,
        new_password: str,
        old_salt: bytes,
        old_verify_token: str,
        old_params: KdfParams = DEFAULT_KDF_PARAMS,
        new_params: KdfParams = DEFAULT_KDF_PARAMS,
    ) -> tuple[bytes, str, bytearray] | None:
        """修改主密码

        Args:
            old_password: 旧密码
            new_password: 新密码
            old_salt: 旧盐值
            old_verify_token: 旧验证令牌
            old_params: 旧 Argon2id 参数
            new_params: 新 Argon2id 参数

        Returns:
            成功时返回由新盐值、新验证令牌、新派生密钥构成的三元组，失败返回 None。
            其中新密钥直接复用 create 内部派生结果，避免重加密流程再次执行
            Argon2id 派生。
        """
        old_key = cls.verify(
            old_password, old_salt, old_verify_token, old_params
        )
        if old_key is None:
            return None
        try:
            new_salt, new_verify_token, new_key = cls.create(
                new_password, new_params
            )
            return new_salt, new_verify_token, new_key
        finally:
            # old_key 为 verify 返回的 bytearray（旧密钥派生结果），仅用于验证旧密码，
            # 验证通过后不再需要。原地清零收缩其在内存/swap 的驻留。
            secure_zero_buffer(old_key)
