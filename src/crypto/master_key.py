"""主密码管理 — Argon2id 密钥派生与验证。

使用 Argon2id（OWASP 首选内存硬化 KDF）从主密码派生 256 位 AES 密钥，内存硬化
使 GPU/ASIC 攻击成本远高于 PBKDF2。密码验证不存哈希，而是加密一段已知明文（验证
令牌）确认密码正确性——伪造需先完成 Argon2id 派生，成本远高于利用此硬编码常量。
"""

import hmac
import logging
import os
from typing import NamedTuple
from unicodedata import normalize

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from ..utils.memory import secure_zero_buffer
from .encryption import EncryptionEngine

logger = logging.getLogger(__name__)

# Argon2id 参数（OWASP 推荐量级）。memory_cost 单位为 KiB，64 MB 使 GPU 攻击需大量显存。
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 64 * 1024  # 64 MB（KiB）
ARGON2_PARALLELISM = 4
SALT_SIZE = 32
# 拒绝空盐/过短盐，避免派生强度静默降级。
MIN_SALT_SIZE = 16
KEY_SIZE = 32  # AES-256

# KDF 参数校验范围：下限为格式校验量级，故意低于 DEFAULT_KDF_PARAMS 以兼容测试与
# 调参。派生强度真正依赖 vault_meta_mac 完整性签名——无主密钥无法重算 MAC，篡改
# KDF 参数会使派生密钥变化、verify_token 解密先行失败。
MIN_ARGON2_TIME_COST = 2
MAX_ARGON2_TIME_COST = 10
MIN_ARGON2_MEMORY_COST = 16 * 1024  # 16 MB
MAX_ARGON2_MEMORY_COST = 1024 * 1024  # 1 GB
MIN_ARGON2_PARALLELISM = 1
MAX_ARGON2_PARALLELISM = 16

# KDF 标识，写入 vault_meta 的 master_kdf 字段，解锁时校验。
KDF_NAME = "argon2id"

# HKDF 域分离 info 标签：主密钥与备份密钥共享同一 Argon2id 主材料，经不同 info
# 派生（HKDF 保证不同 info → 输出独立）。新增密钥域只需追加常量并复用 _hkdf_expand。
_DOMAIN_INFO_MASTER = b"cipherbox:vault-master-key"
_DOMAIN_INFO_BACKUP = b"cipherbox:backup-key"
_DOMAIN_INFO_SHARE = b"cipherbox:share-key"  # 共享包域：限时加密共享包派生密钥


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
            raise ValueError("Argon2id time_cost 参数无效")
        if not MIN_ARGON2_MEMORY_COST <= params.memory_cost <= MAX_ARGON2_MEMORY_COST:
            raise ValueError("Argon2id memory_cost 参数无效")
        if not MIN_ARGON2_PARALLELISM <= params.parallelism <= MAX_ARGON2_PARALLELISM:
            raise ValueError("Argon2id parallelism 参数无效")

    @classmethod
    def _validate_salt(cls, salt: bytes) -> None:
        """校验盐值的类型与最小长度，防止空盐/过短盐导致派生强度静默降级。"""
        if not isinstance(salt, (bytes, bytearray)):
            raise TypeError(f"盐值类型无效：期望 bytes，实际 {type(salt).__name__}")
        if len(salt) < MIN_SALT_SIZE:
            raise ValueError(f"盐值过短：期望至少 {MIN_SALT_SIZE} 字节，实际 {len(salt)} 字节")

    @classmethod
    def _derive_master_material(
        cls,
        password: str,
        salt: bytes,
        params: KdfParams = DEFAULT_KDF_PARAMS,
    ) -> bytearray:
        """Argon2id 派生 32 字节主材料，作为 HKDF 域分离的输入。

        返回 bytearray 以便 HKDF 派生后原地清零，避免主材料（可派生全部域密钥）
        长期驻留内存。域分离见 :data:`_DOMAIN_INFO_MASTER`。
        """
        if not isinstance(password, str):
            raise TypeError(f"密码类型无效：期望 str，实际 {type(password).__name__}")
        cls._validate_params(params)
        cls._validate_salt(salt)
        # Unicode 归一化（NFC）：同一视觉密码在 NFC/NFD 下 UTF-8 字节不同，会派生出
        # 不同密钥——跨 OS 便携备份恢复、不同 IME/输入法输入若归一化不一致，将导致
        # 不可恢复的锁库。编码前统一 NFC，与 OS/IME 解耦。
        normalized = normalize("NFC", password)
        return bytearray(
            hash_secret_raw(
                secret=normalized.encode("utf-8"),
                salt=bytes(salt),
                time_cost=params.time_cost,
                memory_cost=params.memory_cost,
                parallelism=params.parallelism,
                hash_len=KEY_SIZE,
                type=Type.ID,
            )
        )

    @classmethod
    def _hkdf_expand(
        cls,
        material: bytes | bytearray,
        info: bytes,
    ) -> bytearray:
        """从主材料经 HKDF-Expand 派生 32 字节域密钥。

        Argon2id 输出已是高熵伪随机材料，无需 extract，直接 expand 即可。
        返回 bytearray 以便清零。
        """
        return bytearray(
            HKDFExpand(
                algorithm=hashes.SHA256(),
                length=KEY_SIZE,
                info=info,
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

        Args:
            password: 主密码明文
            salt: 随机盐值
            params: Argon2id 参数

        Returns:
            32 字节主密钥 bytearray。返回 bytearray 而非 bytes，以便
            secure_zero_buffer 原地清零（bytes 不可变只能清零副本）。
        """
        material = cls._derive_master_material(password, salt, params)
        try:
            return cls._hkdf_expand(material, _DOMAIN_INFO_MASTER)
        finally:
            secure_zero_buffer(material)

    @classmethod
    def derive_backup_key(
        cls,
        password: str,
        salt: bytes,
        params: KdfParams = DEFAULT_KDF_PARAMS,
    ) -> bytearray:
        """从备份密码派生独立的备份加密密钥（备份域），与主密钥域分离。

        与 :meth:`derive_key` 共享同一 Argon2id 主材料，经 :data:`_DOMAIN_INFO_BACKUP`
        的 HKDF info 派生实现域分离。
        """
        material = cls._derive_master_material(password, salt, params)
        try:
            return cls._hkdf_expand(material, _DOMAIN_INFO_BACKUP)
        finally:
            secure_zero_buffer(material)

    @classmethod
    def derive_share_key(
        cls,
        password: str,
        salt: bytes,
        params: KdfParams = DEFAULT_KDF_PARAMS,
    ) -> bytearray:
        """从共享密码派生限时加密共享包的密钥（共享域），与主/备份密钥域分离。

        与 :meth:`derive_key`/:meth:`derive_backup_key` 共享同一 Argon2id 主材料，
        经 :data:`_DOMAIN_INFO_SHARE` 的 HKDF info 派生实现域分离。共享包经此密钥
        AES-256-GCM 加密，接收方浏览器用同一 password+salt+params 复刻 Argon2id +
        HKDF-Expand 派生相同密钥解密。
        """
        material = cls._derive_master_material(password, salt, params)
        try:
            return cls._hkdf_expand(material, _DOMAIN_INFO_SHARE)
        finally:
            secure_zero_buffer(material)

    @classmethod
    def create(
        cls,
        password: str,
        params: KdfParams = DEFAULT_KDF_PARAMS,
    ) -> tuple[bytes, str, bytearray]:
        """创建新的主密码凭据。

        Returns:
            由盐值、加密后的验证令牌、派生密钥构成的元组
        """
        salt = os.urandom(SALT_SIZE)
        cls._validate_params(params)
        key = cls.derive_key(password, salt, params)
        try:
            verify_token = EncryptionEngine.encrypt(VERIFY_PLAINTEXT, key, VERIFY_AAD)
        except Exception:
            # 加密失败时 key 不返回，原地清零避免异常路径泄漏派生密钥到调用栈帧。
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
        """验证主密码。

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
        returned = False
        try:
            decrypted = EncryptionEngine.decrypt(verify_token, key, VERIFY_AAD)
            if hmac.compare_digest(decrypted, VERIFY_PLAINTEXT):
                returned = True
                return key
            logger.debug("主密码验证失败：验证令牌明文不匹配（令牌可能损坏）")
        except ValueError as exc:
            # InvalidTag（密码错误）与令牌格式损坏都归一为 ValueError，记录类型
            # 便于事后审计「密码错」与「令牌损坏」。
            logger.debug("主密码验证失败：令牌解密异常 %s", type(exc).__name__)
        finally:
            # finally 兜底覆盖所有非成功路径（含 decrypt 抛非 ValueError 异常，如
            # verify_token 非 str 时 startswith 抛 AttributeError），避免密钥残留栈帧
            # 依赖 GC。登录是最频繁的错误密码入口，每次输错都清零派生密钥。
            if not returned:
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

        供 :meth:`change_password` 等只需「是/否」判定的场景：改密重加密用已激活的
        ``vault.key``，让调用方持有 verify 派生的密钥只会多一份旧主密钥副本驻留。
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
        """修改主密码。

        Returns:
            成功返回新盐值、新验证令牌、新派生密钥三元组；失败返回 None。新密钥
            复用 create 内部派生结果，避免重加密再次 Argon2id 派生。
        """
        # 旧密码仅用于「是/否」验证：重加密用已激活的 vault.key，无需持有旧密钥副本；
        # verify_password 内部派生验证后立即清零，收缩改密窗口的密钥驻留面。
        if not cls.verify_password(old_password, old_salt, old_verify_token, old_params):
            return None
        new_salt, new_verify_token, new_key = cls.create(new_password, new_params)
        return new_salt, new_verify_token, new_key
