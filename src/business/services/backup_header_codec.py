"""CipherBox 固定格式的备份二进制头部编解码、检视与密钥派生。

所有函数均无状态：原 ``BackupRestoreManager`` 上的 staticmethod 迁移为模块级
函数，互调去掉 ``BackupRestoreManager.`` 前缀，改为直接函数名调用。
"""

import enum
import struct
from pathlib import Path
from typing import IO, Any

from ...crypto.master_key import DEFAULT_KDF_PARAMS, KdfParams, MasterKeyManager
from ...exceptions import BackupError, PayloadTooLargeError
from ...utils.file_security import validate_file_path
from ...utils.memory import secure_zero_buffer

BACKUP_MAGIC = b'CipherBoxBackup\x00'
BACKUP_FORMAT = 'CipherBoxBackup'
# 备份数据格式的版本号（写入 JSON 顶层 ``version`` 字段，恢复时由 backup_validator
# 校验）。与 BACKUP_FORMAT 同属备份格式标识的单一事实源——升级格式时同步 bump。
BACKUP_VERSION = 1
BACKUP_AAD = b'CipherBox:backup'
BACKUP_SALT_SIZE = 32

# 固定头：flags、Argon2 time/memory/parallelism，随后为 32 字节 salt。
BACKUP_HEADER_STRUCT = struct.Struct('<BIII')
BACKUP_HEADER_SIZE = len(BACKUP_MAGIC) + BACKUP_HEADER_STRUCT.size + BACKUP_SALT_SIZE
MAX_BACKUP_FILE_SIZE = 64 * 1024 * 1024
MAX_BACKUP_PAYLOAD_SIZE = 32 * 1024 * 1024


class BackupFlag(enum.IntEnum):
    """备份类型标志，用于二进制头部标识加密方式。

    使用 IntEnum 而非 IntFlag，因为 IntFlag 的 ~ 运算仅翻转已定义位，
    无法检测未知标志位。IntEnum 的 ~ 返回标准 int 按位取反，可正确检测非法组合。
    """

    PASSWORD = 1     # 使用独立备份密码加密
    SNAPSHOT = 2     # 使用快照密钥加密


def derive_backup_key(password: str, salt: bytes) -> bytearray:
    """用备份密码与 salt 派生 backup_key，使用 DEFAULT_KDF_PARAMS（备份恒以默认参数创建）。"""
    return MasterKeyManager.derive_backup_key(password, salt, DEFAULT_KDF_PARAMS)


def write_backup_header(file: IO[bytes], flags: BackupFlag, salt: bytes, params: KdfParams) -> None:
    """写入备份头，持久化实际 KDF 参数。"""
    MasterKeyManager.validate_params(params)
    if len(salt) != BACKUP_SALT_SIZE:
        raise BackupError('备份盐长度无效')
    file.write(BACKUP_MAGIC)
    file.write(BACKUP_HEADER_STRUCT.pack(
        int(flags),
        params.time_cost,
        params.memory_cost,
        params.parallelism,
    ))
    file.write(salt)


def read_backup_header(file: IO[bytes]) -> tuple[BackupFlag, bytes, KdfParams]:
    """读取备份头，解析标志位与持久化的 KDF 参数。"""
    file.seek(0)
    if file.read(len(BACKUP_MAGIC)) != BACKUP_MAGIC:
        raise BackupError('无效的备份文件格式')
    raw = file.read(BACKUP_HEADER_STRUCT.size)
    salt = file.read(BACKUP_SALT_SIZE)
    if len(raw) != BACKUP_HEADER_STRUCT.size or len(salt) != BACKUP_SALT_SIZE:
        raise BackupError('备份文件头已损坏')
    flag_value, time_cost, memory_cost, parallelism = (
        BACKUP_HEADER_STRUCT.unpack(raw)
    )
    if flag_value not in (BackupFlag.PASSWORD, BackupFlag.SNAPSHOT):
        raise BackupError('备份文件格式无效或已损坏')
    params = KdfParams(time_cost, memory_cost, parallelism)
    try:
        MasterKeyManager.validate_params(params)
    except ValueError as exc:
        # 头中的 KDF 参数非法属于「备份文件已损坏/被篡改」，归一为 BackupError，
        # 使调用方经 ``except BackupError`` 即可覆盖全部格式错误，无需裸 ValueError
        # 兜底（裸 ValueError 会连带吞掉 PayloadTooLargeError 等领域异常）。
        raise BackupError('备份文件 KDF 参数无效，可能已损坏') from exc
    return BackupFlag(flag_value), salt, params


def header_aad(flags: BackupFlag, salt: bytes, params: KdfParams) -> bytes:
    """构造备份 payload 的 AAD：固定域前缀 + 完整头字节（magic + KDF 参数 + salt）。

    将明文头纳入 GCM 认证，使对头（尤其 KDF 参数）的任何篡改都导致 payload
    解密失败，彻底关闭「改写头到 floor 以上的合法值以规避降级检查」的篡改路径
    （原先仅靠 enforce_kdf_floor 拒绝弱于默认值的降级）。读备份时用读到的头
    重建同一 AAD，故头与 payload 绑定、不可独立篡改。
    """
    return (
        BACKUP_AAD
        + BACKUP_MAGIC
        + BACKUP_HEADER_STRUCT.pack(
            int(flags), params.time_cost, params.memory_cost, params.parallelism,
        )
        + salt
    )


def enforce_kdf_floor(params: KdfParams) -> None:
    """拒绝低于创建默认值的 Argon2id 参数，作 GCM 认证之外的纵深防御。

    备份头已通过 :func:`header_aad` 纳入 payload 的 GCM 认证（头任何篡改都会
    使解密失败），故头篡改降级在解密阶段即被拦截。本函数保留为派生前早期校验：
    在投入 Argon2id 派生（64MB 内存）之前即拒绝异常参数，避免对必定解密失败的
    备份浪费派生开销。合法备份均以 ``DEFAULT_KDF_PARAMS`` 创建，不影响正常恢复。
    """
    floor = DEFAULT_KDF_PARAMS
    if (
        params.time_cost < floor.time_cost
        or params.memory_cost < floor.memory_cost
        or params.parallelism < floor.parallelism
    ):
        raise BackupError('备份文件 KDF 参数异常，可能已被篡改')


# 恢复不可信备份时的 KDF 紧上界倍数：备份头 KDF 参数由提供者控制，validate_params
# 的宽上界（1GB/time=10/p=16）不足以防社会工程下的内存耗尽 DoS。恢复路径额外限制
# 各分量不超过创建默认的此倍数，超出拒绝（合法备份恒用 DEFAULT_KDF_PARAMS）。
MAX_RESTORE_KDF_MULTIPLIER = 2


def enforce_kdf_ceiling(params: KdfParams) -> None:
    """恢复不可信备份时拒绝远超创建默认的 Argon2id 参数，防内存耗尽 DoS。

    合法备份恒以 ``DEFAULT_KDF_PARAMS`` 创建，故紧上界（DEFAULT 的
    ``MAX_RESTORE_KDF_MULTIPLIER`` 倍）不影响正常恢复；社会工程下被构造为
    1GB/time=10/p=16 的恶意备份会在派生（且在 vault_write_lock 内同步执行）前被
    早期拒绝，避免 UI 长时间冻结或 OOM。与 :func:`enforce_kdf_floor` 互补：floor
    防弱化降级，ceiling 防资源耗尽飙升。
    """
    m = MAX_RESTORE_KDF_MULTIPLIER
    if (
        params.time_cost > DEFAULT_KDF_PARAMS.time_cost * m
        or params.memory_cost > DEFAULT_KDF_PARAMS.memory_cost * m
        or params.parallelism > DEFAULT_KDF_PARAMS.parallelism * m
    ):
        raise BackupError('备份文件 KDF 参数异常（超出恢复允许上界），可能已被篡改')


def zero_backup_key_if_owned(flags: BackupFlag, key: bytearray | bytes | None) -> None:
    """清零 PASSWORD 路径派生的 backup_key；SNAPSHOT 路径借用 snapshot_key 不清零。

    集中「是否应清零」判定，使 create_backup 与 _restore_current 的清零逻辑共用
    单一来源，避免未来新增备份加密 flag 时漏改其中一处。key 为 None 时跳过
    （派生阶段异常致 backup_key 未定义的兜底）。
    """
    if flags == BackupFlag.PASSWORD and key is not None:
        secure_zero_buffer(key)


def inspect_backup(filepath: str) -> dict[str, Any]:
    """读取备份头，不解密内容。

    返回值键固定（format/password_required/snapshot_required/kdf），但值类型
    混合（str/bool/dict），故标注 dict[str, Any]。
    """
    filepath = str(validate_file_path(filepath))
    if Path(filepath).stat().st_size > MAX_BACKUP_FILE_SIZE:
        raise PayloadTooLargeError('备份文件过大')
    with open(filepath, 'rb') as file:
        flags, _salt, params = read_backup_header(file)
        return {
            'format': BACKUP_FORMAT,
            'password_required': flags == BackupFlag.PASSWORD,
            'snapshot_required': flags == BackupFlag.SNAPSHOT,
            'kdf': {
                'name': 'argon2id',
                'time_cost': params.time_cost,
                'memory_cost': params.memory_cost,
                'parallelism': params.parallelism,
            },
        }


# 显式声明模块公开 API，限定 `from ... import *` 的导出范围。
__all__ = [
    'BACKUP_AAD',
    'BACKUP_FORMAT',
    'BACKUP_VERSION',
    'BACKUP_HEADER_SIZE',
    'BACKUP_HEADER_STRUCT',
    'BACKUP_MAGIC',
    'BACKUP_SALT_SIZE',
    'BackupFlag',
    'MAX_BACKUP_FILE_SIZE',
    'MAX_BACKUP_PAYLOAD_SIZE',
    'MAX_RESTORE_KDF_MULTIPLIER',
    'derive_backup_key',
    'enforce_kdf_ceiling',
    'enforce_kdf_floor',
    'header_aad',
    'inspect_backup',
    'read_backup_header',
    'write_backup_header',
    'zero_backup_key_if_owned',
]
