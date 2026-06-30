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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

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
# 拒绝过短输入避免静默降级。主盐 32 字节；备份密钥经 HKDF 派生，复用同一盐值。
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

# HKDF 域分离 info 标签。主密钥与备份密钥共享同一 Argon2id 主材料，经不同 info
# 派生实现域分离：HKDF 保证不同 info → 输出独立，消除原先用 salt 字符串前缀
# b'backup:' 做域分离时「主盐碰巧以 b'backup:' 开头则两域等价」的隐式碰撞假设。
# 新增密钥域（如导出密钥）只需追加常量并复用 _hkdf_expand。
_DOMAIN_INFO_MASTER = b'cipherbox:vault-master-key'
_DOMAIN_INFO_BACKUP = b'cipherbox:backup-key'


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
    def _derive_master_material(
        cls,
        password: str,
        salt: bytes,
        params: KdfParams = DEFAULT_KDF_PARAMS,
    ) -> bytearray:
        """Argon2id 派生 32 字节主材料，作为 HKDF 域分离的输入。

        含密码/盐/参数校验。返回 bytearray 以便调用方在 HKDF 派生后原地清零，
        避免主材料（可派生全部域密钥）长期驻留内存。

        主密钥与备份密钥共享同一主材料（同 password+salt 的 Argon2id 输出），
        经不同 HKDF info 派生实现域分离——见 :data:`_DOMAIN_INFO_MASTER` 说明。
        """
        if not isinstance(password, str):
            raise TypeError(f'密码类型无效：期望 str，实际 {type(password).__name__}')
        cls._validate_params(params)
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
    def _hkdf_expand(
        cls, material: bytes | bytearray, info: bytes,
    ) -> bytearray:
        """从主材料经 HKDF-Expand 派生 32 字节域密钥。

        用 HKDF-Expand（而非完整 HKDF extract+expand）：Argon2id 输出已是高熵伪
        随机材料，无需 extract 步骤，直接 expand 即可。返回 bytearray 以便清零。
        """
        return bytearray(
            HKDFExpand(
                algorithm=hashes.SHA256(), length=KEY_SIZE, info=info,
            ).derive(material)
        )

    @classmethod
    def derive_key(
        cls,
        password: str,
        salt: bytes,
        params: KdfParams = DEFAULT_KDF_PARAMS,
    ) -> bytearray:
        """使用 Argon2id + HKDF 从密码派生 256 位主密钥（保险库域）。

        先 Argon2id 派生主材料，再 HKDF-Expand 按 :data:`_DOMAIN_INFO_MASTER`
        派生主密钥。主材料在派生后原地清零。

        Args:
            password: 主密码明文
            salt: 随机盐值
            params: Argon2id 参数

        Returns:
            32 字节主密钥 bytearray。返回 bytearray 而非 bytes，以便
            secure_zero_buffer 原地清零底层缓冲（bytes 不可变只能清零副本）。
        """
        material = cls._derive_master_material(password, salt, params)
        try:
            return cls._hkdf_expand(material, _DOMAIN_INFO_MASTER)
        finally:
            secure_zero_buffer(material)

    @classmethod
    def derive_backup_key(
        cls, password: str, salt: bytes, params: KdfParams = DEFAULT_KDF_PARAMS,
    ) -> bytearray:
        """从备份密码派生独立的备份加密密钥（备份域），与主密钥域分离。

        与 :meth:`derive_key` 共享同一 Argon2id 主材料（同 password+salt），但经
        :data:`_DOMAIN_INFO_BACKUP` 的 HKDF info 派生。域分离由 HKDF info 显式
        保证（不同 info → 输出独立），消除原先用 salt 字符串前缀 ``b'backup:'``
        做域分离时「主盐碰巧以 ``b'backup:'`` 开头则两域等价」的隐式碰撞假设。
        新增第三域只需追加新的 ``_DOMAIN_INFO_*`` 常量并复用 _hkdf_expand。
        """
        material = cls._derive_master_material(password, salt, params)
        try:
            return cls._hkdf_expand(material, _DOMAIN_INFO_BACKUP)
        finally:
            secure_zero_buffer(material)

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
    def verify_password(
        cls,
        password: str,
        salt: bytes,
        verify_token: str,
        params: KdfParams = DEFAULT_KDF_PARAMS,
    ) -> bool:
        """仅验证主密码是否正确，不返回派生密钥（验证后立即清零）。

        供 :meth:`change_password` 等只需「是/否」判定的场景：:meth:`verify` 返回的
        派生密钥在改密流程中并未使用（重加密用已激活的 ``vault.key``），让调用方持有
        它只会多一份旧主密钥副本驻留内存。本方法内部仍经 :meth:`verify` 派生验证，
        但成功后立即 ``secure_zero_buffer`` 清零返回的密钥，调用方从不接触密钥副本。
        """
        key = cls.verify(password, salt, verify_token, params)
        if key is None:
            return False
        secure_zero_buffer(key)
        return True

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
        # 旧密码仅用于「是/否」验证：重加密用已激活的 vault.key，无需持有旧密钥副本。
        # verify_password 内部派生验证后立即清零，本方法不接触旧密钥，收缩改密窗口的
        # 密钥驻留面（原先经 verify 返回 old_key 在 finally 清零，多一份副本驻留）。
        if not cls.verify_password(
            old_password, old_salt, old_verify_token, old_params
        ):
            return None
        new_salt, new_verify_token, new_key = cls.create(
            new_password, new_params
        )
        return new_salt, new_verify_token, new_key
