"""CipherBox 限时加密共享包二进制头部编解码、检视与密钥派生。无状态函数。

.cboxshare 格式：magic + 固定头（version/KDF 参数/expire_at/created_at）+ salt + 密文块
（:meth:`EncryptionEngine.encrypt_bytes` 产出：``CB2`` 前缀 + nonce + ct + tag，与备份格式
及 WebCrypto AES-GCM 字节布局兼容）。头纳入 GCM-AAD 防篡改（仿 backup_header_codec）。
expire_at 为软限制——嵌入元数据供解密器诚实提示，无法防恶意接收方（一旦解密即得明文）。
"""

import struct
from pathlib import Path
from typing import IO, Any

from ...crypto.master_key import DEFAULT_KDF_PARAMS, KdfParams, MasterKeyManager
from ...exceptions import PayloadTooLargeError, ShareError
from ...utils.file_security import validate_file_path

SHARE_MAGIC = b"CipherBoxShare\x00"
SHARE_FORMAT = "CipherBoxShare"
SHARE_VERSION = 1
SHARE_AAD = b"CipherBox:share"
SHARE_SALT_SIZE = 32

# 固定头：version(B) + time_cost(I) + memory_cost(I) + parallelism(I) + expire_at(Q) + created_at(Q)。
# expire_at/created_at 为 Unix 秒（UTC），expire_at=0（EXPIRE_NEVER）表示永不过期。
SHARE_HEADER_STRUCT = struct.Struct("<BIIIQQ")
SHARE_HEADER_SIZE = len(SHARE_MAGIC) + SHARE_HEADER_STRUCT.size + SHARE_SALT_SIZE

# 文件/payload 大小上限（小于备份，共享包设计为少量条目瞬时分享）。
MAX_SHARE_FILE_SIZE = 4 * 1024 * 1024
MAX_SHARE_PAYLOAD_SIZE = 2 * 1024 * 1024

# 不可信共享包解析时的 KDF 紧上界倍数（防内存耗尽 DoS，与 backup_header_codec 同思路）。
MAX_SHARE_KDF_MULTIPLIER = 2

# 永不过期标记值（expire_at 字段）。
EXPIRE_NEVER = 0


def derive_share_key(password: str, salt: bytes, params: KdfParams) -> bytearray:
    """用共享密码与 salt 派生 share_key，使用给定 KDF 参数。"""
    return MasterKeyManager.derive_share_key(password, salt, params)


def write_share_header(
    file: IO[bytes],
    salt: bytes,
    params: KdfParams,
    expire_at: int,
    created_at: int,
    *,
    version: int = SHARE_VERSION,
) -> None:
    """写入共享包头，持久化 KDF 参数与过期/创建时间。"""
    MasterKeyManager.validate_params(params)
    if len(salt) != SHARE_SALT_SIZE:
        raise ShareError("共享包盐长度无效")
    file.write(SHARE_MAGIC)
    file.write(
        SHARE_HEADER_STRUCT.pack(
            version,
            params.time_cost,
            params.memory_cost,
            params.parallelism,
            expire_at,
            created_at,
        )
    )
    file.write(salt)


def read_share_header(file: IO[bytes]) -> tuple[int, bytes, KdfParams, int, int]:
    """读取共享包头，返回 ``(version, salt, params, expire_at, created_at)``。"""
    file.seek(0)
    if file.read(len(SHARE_MAGIC)) != SHARE_MAGIC:
        raise ShareError("无效的共享包文件格式")
    raw = file.read(SHARE_HEADER_STRUCT.size)
    salt = file.read(SHARE_SALT_SIZE)
    if len(raw) != SHARE_HEADER_STRUCT.size or len(salt) != SHARE_SALT_SIZE:
        raise ShareError("共享包文件头已损坏")
    version, time_cost, memory_cost, parallelism, expire_at, created_at = (
        SHARE_HEADER_STRUCT.unpack(raw)
    )
    if version != SHARE_VERSION:
        raise ShareError(f"不支持的共享包版本：{version}")
    params = KdfParams(time_cost, memory_cost, parallelism)
    try:
        MasterKeyManager.validate_params(params)
    except ValueError as exc:
        # KDF 参数非法归一为 ShareError，避免裸 ValueError 兜底连带吞掉领域异常。
        raise ShareError("共享包 KDF 参数无效，可能已损坏") from exc
    return version, salt, params, expire_at, created_at


def share_header_aad(
    salt: bytes,
    params: KdfParams,
    expire_at: int,
    created_at: int,
    *,
    version: int = SHARE_VERSION,
) -> bytes:
    """构造共享包 payload 的 AAD：域前缀 + 完整头字节（magic + 头 struct + salt）。

    将明文头纳入 GCM 认证，使对头（KDF 参数/过期时间/版本）的任何篡改都致 payload
    解密失败，彻底关闭「改写头规避降级检查」的篡改路径。
    """
    return (
        SHARE_AAD
        + SHARE_MAGIC
        + SHARE_HEADER_STRUCT.pack(
            version,
            params.time_cost,
            params.memory_cost,
            params.parallelism,
            expire_at,
            created_at,
        )
        + salt
    )


def enforce_kdf_floor(params: KdfParams) -> None:
    """拒绝低于默认值的 Argon2id 参数（防降级，GCM 认证之外的纵深防御）。

    头篡改降级已在解密阶段由 :func:`share_header_aad` 的 GCM 认证拦截，本函数保留为
    派生前早期校验：投入 Argon2id（64MB 内存）前即拒绝异常参数，避免浪费派生开销。
    """
    floor = DEFAULT_KDF_PARAMS
    if (
        params.time_cost < floor.time_cost
        or params.memory_cost < floor.memory_cost
        or params.parallelism < floor.parallelism
    ):
        raise ShareError("共享包 KDF 参数异常，可能已被篡改")


def enforce_kdf_ceiling(params: KdfParams) -> None:
    """解析不可信共享包时拒绝远超默认的 Argon2id 参数，防内存耗尽 DoS。

    合法共享包恒以 DEFAULT_KDF_PARAMS 创建，紧上界不影响正常解密；恶意构造的极大参数
    会在派生前被早期拒绝，避免接收方浏览器/解析端 OOM。
    """
    m = MAX_SHARE_KDF_MULTIPLIER
    if (
        params.time_cost > DEFAULT_KDF_PARAMS.time_cost * m
        or params.memory_cost > DEFAULT_KDF_PARAMS.memory_cost * m
        or params.parallelism > DEFAULT_KDF_PARAMS.parallelism * m
    ):
        raise ShareError("共享包 KDF 参数异常（超出解析允许上界），可能已被篡改")


def inspect_share(filepath: str) -> dict[str, Any]:
    """读取共享包头，不解密内容。返回混合类型故标注 ``dict[str, Any]``。"""
    filepath = str(validate_file_path(filepath))
    if Path(filepath).stat().st_size > MAX_SHARE_FILE_SIZE:
        raise PayloadTooLargeError("共享包文件过大")
    with open(filepath, "rb") as file:
        version, _, params, expire_at, created_at = read_share_header(file)
        return {
            "format": SHARE_FORMAT,
            "version": version,
            "kdf": {
                "name": "argon2id",
                "time_cost": params.time_cost,
                "memory_cost": params.memory_cost,
                "parallelism": params.parallelism,
            },
            "expire_at": expire_at,
            "created_at": created_at,
        }


__all__ = [
    "EXPIRE_NEVER",
    "MAX_SHARE_FILE_SIZE",
    "MAX_SHARE_KDF_MULTIPLIER",
    "MAX_SHARE_PAYLOAD_SIZE",
    "SHARE_AAD",
    "SHARE_FORMAT",
    "SHARE_HEADER_SIZE",
    "SHARE_HEADER_STRUCT",
    "SHARE_MAGIC",
    "SHARE_SALT_SIZE",
    "SHARE_VERSION",
    "derive_share_key",
    "enforce_kdf_ceiling",
    "enforce_kdf_floor",
    "inspect_share",
    "read_share_header",
    "share_header_aad",
    "write_share_header",
]
