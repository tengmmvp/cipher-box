"""CipherBox 限时加密共享包二进制头部编解码、检视与密钥派生。无状态函数。

.cboxshare 格式：magic + 固定头（version/KDF 参数/expire_at/created_at）+ salt + 密文块
（:meth:`EncryptionEngine.encrypt_bytes` 产出：``CB2`` 前缀 + nonce + ct + tag，与备份格式
及 WebCrypto AES-GCM 字节布局兼容）。头纳入 GCM-AAD 防篡改（仿 backup/header_codec）。
expire_at 为软限制——嵌入元数据供解密器诚实提示，无法防恶意接收方（一旦解密即得明文）。

版本升级为破坏性：``SHARE_VERSION`` 一旦 bump，旧 ``decrypt.html`` 拒绝新 ``.cboxshare``、
新解密器拒绝旧包，双向不兼容；升级版本号时已分发的旧包须用对应旧版解密器，或重新生成。
"""

import struct
from pathlib import Path
from typing import IO, Any

from ....crypto.master_key import KdfParams, MasterKeyManager
from ....exceptions import PayloadTooLargeError, ShareError
from ....utils.file_security import validate_file_path

SHARE_MAGIC = b"CipherBoxShare\x00"
SHARE_FORMAT = "CipherBoxShare"
SHARE_VERSION = 1
# GCM-AAD 域前缀（跨语言契约）：浏览器解密器 decrypter_template.html 内联同值常量
# （``var SHARE_AAD = "CipherBox:share"``），修改须两端同步，否则解密认证失败。
SHARE_AAD = b"CipherBox:share"
SHARE_SALT_SIZE = 32

# 固定头：version(B) + time_cost(I) + memory_cost(I) + parallelism(I) + expire_at(Q) + created_at(Q)。
# expire_at/created_at 为 Unix 秒（UTC），expire_at=0（EXPIRE_NEVER）表示永不过期。
SHARE_HEADER_STRUCT = struct.Struct("<BIIIQQ")

# 文件/payload 大小上限（小于备份，共享包设计为少量条目瞬时分享）。
MAX_SHARE_FILE_SIZE = 4 * 1024 * 1024
MAX_SHARE_PAYLOAD_SIZE = 2 * 1024 * 1024

# 解密器（浏览器 JS）解析不可信共享包时的 KDF 紧上界倍数，防恶意极大参数致 OOM/冻结 DoS。
# Python 创建端恒以默认参数写入、不从不可信头派生 share key，故本常量无 Python 消费方；
# 保留为 decrypter_template.html 的 doDecrypt 内联校验（D.time*2 等）的契约锚点。
MAX_SHARE_KDF_MULTIPLIER = 2

# 永不过期标记值（expire_at 字段）。
EXPIRE_NEVER = 0


def derive_share_key(password: str, salt: bytes, params: KdfParams) -> bytearray:
    """用共享密码与 salt 派生 share_key，使用给定 KDF 参数。

    透传 :meth:`MasterKeyManager.derive_share_key` 作为 share 域密钥派生入口，与
    master/backup 域派生对称；集中于此使 share 调用方不直接耦合 MasterKeyManager。
    """
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


def header_aad(
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
    "SHARE_HEADER_STRUCT",
    "SHARE_MAGIC",
    "SHARE_SALT_SIZE",
    "SHARE_VERSION",
    "derive_share_key",
    "inspect_share",
    "read_share_header",
    "header_aad",
    "write_share_header",
]
