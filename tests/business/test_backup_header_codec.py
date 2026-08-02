"""backup_header_codec 模块的编解码、检视与密钥派生测试。

覆盖二进制备份头的写入/读取往返、AAD 构造、KDF 参数下限与上界守卫、密钥派生
长度、密钥清零策略以及损坏头部（坏 magic/短头/坏 flag）的拒绝路径。
"""

import io

import pytest

from src.business.services import backup_header_codec
from src.business.services.backup_header_codec import (
    BACKUP_AAD,
    BACKUP_FORMAT,
    BACKUP_HEADER_STRUCT,
    BACKUP_MAGIC,
    BACKUP_SALT_SIZE,
    BackupFlag,
    derive_backup_key,
    enforce_kdf_floor,
    header_aad,
    inspect_backup,
    read_backup_header,
    write_backup_header,
    zero_backup_key_if_owned,
)
from src.crypto.master_key import DEFAULT_KDF_PARAMS, KdfParams
from src.exceptions import BackupError, PayloadTooLargeError


def _make_header_bytes(
    flags: BackupFlag = BackupFlag.PASSWORD,
    salt: bytes = b"\x00" * BACKUP_SALT_SIZE,
    params: KdfParams = DEFAULT_KDF_PARAMS,
) -> bytes:
    """构造与 write_backup_header 等价的二进制头部（便于直接篡改字节）。"""
    return (
        BACKUP_MAGIC
        + BACKUP_HEADER_STRUCT.pack(
            int(flags),
            params.time_cost,
            params.memory_cost,
            params.parallelism,
        )
        + salt
    )


class TestBackupHeaderRoundtrip:
    """写入/读取头部往返一致性。"""

    def test_roundtrip_password(self):
        """PASSWORD 标志与默认参数写入后应能完整读回。"""
        salt = b"\x11" * BACKUP_SALT_SIZE
        buf = io.BytesIO()
        write_backup_header(buf, BackupFlag.PASSWORD, salt, DEFAULT_KDF_PARAMS)
        buf.seek(0)
        flags, read_salt, params = read_backup_header(buf)
        assert flags == BackupFlag.PASSWORD
        assert read_salt == salt
        assert params == DEFAULT_KDF_PARAMS

    def test_roundtrip_snapshot(self):
        """SNAPSHOT 标志同样能完整往返。"""
        salt = b"\x22" * BACKUP_SALT_SIZE
        buf = io.BytesIO()
        write_backup_header(buf, BackupFlag.SNAPSHOT, salt, DEFAULT_KDF_PARAMS)
        flags, read_salt, params = read_backup_header(buf)
        assert flags == BackupFlag.SNAPSHOT
        assert read_salt == salt
        assert params == DEFAULT_KDF_PARAMS

    def test_write_rejects_invalid_salt_length(self):
        """盐长度不等于 BACKUP_SALT_SIZE 应拒绝。"""
        buf = io.BytesIO()
        with pytest.raises(BackupError, match="盐"):
            write_backup_header(
                buf,
                BackupFlag.PASSWORD,
                b"\x00" * 10,
                DEFAULT_KDF_PARAMS,
            )

    def test_write_rejects_invalid_params(self):
        """写入时非法 KDF 参数应被 MasterKeyManager.validate_params 拒绝。"""
        buf = io.BytesIO()
        with pytest.raises(ValueError):
            write_backup_header(
                buf,
                BackupFlag.PASSWORD,
                b"\x00" * BACKUP_SALT_SIZE,
                KdfParams(time_cost=1, memory_cost=16 * 1024, parallelism=1),
            )


class TestHeaderAad:
    """header_aad 内容构造。"""

    def test_aad_contains_magic_struct_and_salt(self):
        """AAD 应包含固定前缀 + magic + 结构化参数 + salt。"""
        salt = b"\xab" * BACKUP_SALT_SIZE
        aad = header_aad(BackupFlag.PASSWORD, salt, DEFAULT_KDF_PARAMS)
        assert aad.startswith(BACKUP_AAD + BACKUP_MAGIC)
        assert aad.endswith(salt)
        # 中段应包含 pack 后的 flags 与 KDF 参数
        packed = BACKUP_HEADER_STRUCT.pack(
            int(BackupFlag.PASSWORD),
            DEFAULT_KDF_PARAMS.time_cost,
            DEFAULT_KDF_PARAMS.memory_cost,
            DEFAULT_KDF_PARAMS.parallelism,
        )
        assert packed in aad

    def test_aad_differs_per_flag(self):
        """不同 flag 应生成不同 AAD（绑定加密方式到 payload）。"""
        salt = b"\x00" * BACKUP_SALT_SIZE
        aad1 = header_aad(BackupFlag.PASSWORD, salt, DEFAULT_KDF_PARAMS)
        aad2 = header_aad(BackupFlag.SNAPSHOT, salt, DEFAULT_KDF_PARAMS)
        assert aad1 != aad2

    def test_aad_differs_per_params(self):
        """KDF 参数变化应反映到 AAD（防头篡改降级）。"""
        salt = b"\x00" * BACKUP_SALT_SIZE
        weak = KdfParams(time_cost=2, memory_cost=16 * 1024, parallelism=1)
        aad_default = header_aad(BackupFlag.PASSWORD, salt, DEFAULT_KDF_PARAMS)
        aad_weak = header_aad(BackupFlag.PASSWORD, salt, weak)
        assert aad_default != aad_weak


class TestEnforceKdfFloor:
    """enforce_kdf_floor 拒绝低于默认值的参数。"""

    def test_rejects_low_time(self):
        with pytest.raises(BackupError, match="KDF"):
            enforce_kdf_floor(
                KdfParams(
                    time_cost=DEFAULT_KDF_PARAMS.time_cost - 1,
                    memory_cost=DEFAULT_KDF_PARAMS.memory_cost,
                    parallelism=DEFAULT_KDF_PARAMS.parallelism,
                )
            )

    def test_rejects_low_memory(self):
        with pytest.raises(BackupError, match="KDF"):
            enforce_kdf_floor(
                KdfParams(
                    time_cost=DEFAULT_KDF_PARAMS.time_cost,
                    memory_cost=DEFAULT_KDF_PARAMS.memory_cost - 1,
                    parallelism=DEFAULT_KDF_PARAMS.parallelism,
                )
            )

    def test_rejects_low_parallelism(self):
        with pytest.raises(BackupError, match="KDF"):
            enforce_kdf_floor(
                KdfParams(
                    time_cost=DEFAULT_KDF_PARAMS.time_cost,
                    memory_cost=DEFAULT_KDF_PARAMS.memory_cost,
                    parallelism=DEFAULT_KDF_PARAMS.parallelism - 1,
                )
            )

    def test_accepts_default(self):
        """默认参数不应被拒绝（floor 等于默认）。"""
        enforce_kdf_floor(DEFAULT_KDF_PARAMS)  # 不抛异常即通过


class TestEnforceKdfCeiling:
    """enforce_kdf_ceiling 拒绝远超默认的参数，防恢复路径内存耗尽 DoS。"""

    def test_accepts_default(self):
        """默认参数（合法备份恒用）不应被拒绝。"""
        backup_header_codec.enforce_kdf_ceiling(DEFAULT_KDF_PARAMS)

    def test_accepts_up_to_multiplier(self):
        """各分量恰为 DEFAULT 的倍数上限时通过。"""
        m = backup_header_codec.MAX_RESTORE_KDF_MULTIPLIER
        backup_header_codec.enforce_kdf_ceiling(
            KdfParams(
                DEFAULT_KDF_PARAMS.time_cost * m,
                DEFAULT_KDF_PARAMS.memory_cost * m,
                DEFAULT_KDF_PARAMS.parallelism * m,
            )
        )

    def test_rejects_oversized_time(self):
        m = backup_header_codec.MAX_RESTORE_KDF_MULTIPLIER
        with pytest.raises(BackupError, match="上界"):
            backup_header_codec.enforce_kdf_ceiling(
                KdfParams(
                    DEFAULT_KDF_PARAMS.time_cost * (m + 1),
                    DEFAULT_KDF_PARAMS.memory_cost,
                    DEFAULT_KDF_PARAMS.parallelism,
                )
            )

    def test_rejects_oversized_memory(self):
        m = backup_header_codec.MAX_RESTORE_KDF_MULTIPLIER
        with pytest.raises(BackupError, match="上界"):
            backup_header_codec.enforce_kdf_ceiling(
                KdfParams(
                    DEFAULT_KDF_PARAMS.time_cost,
                    DEFAULT_KDF_PARAMS.memory_cost * (m + 1),
                    DEFAULT_KDF_PARAMS.parallelism,
                )
            )

    def test_rejects_oversized_parallelism(self):
        m = backup_header_codec.MAX_RESTORE_KDF_MULTIPLIER
        with pytest.raises(BackupError, match="上界"):
            backup_header_codec.enforce_kdf_ceiling(
                KdfParams(
                    DEFAULT_KDF_PARAMS.time_cost,
                    DEFAULT_KDF_PARAMS.memory_cost,
                    DEFAULT_KDF_PARAMS.parallelism * (m + 1),
                )
            )


class TestInspectBackup:
    """inspect_backup 读头返回结构化字典。"""

    def test_inspect_password_backup(self, tmp_path):
        salt = b"\x33" * BACKUP_SALT_SIZE
        path = tmp_path / "pw.cbox"
        with open(path, "wb") as f:
            write_backup_header(f, BackupFlag.PASSWORD, salt, DEFAULT_KDF_PARAMS)
            f.write(b"payload-tail")  # 模拟 payload
        info = inspect_backup(str(path))
        assert info["format"] == BACKUP_FORMAT
        assert info["password_required"] is True
        assert info["snapshot_required"] is False
        assert info["kdf"]["name"] == "argon2id"
        assert info["kdf"]["time_cost"] == DEFAULT_KDF_PARAMS.time_cost
        assert info["kdf"]["memory_cost"] == DEFAULT_KDF_PARAMS.memory_cost
        assert info["kdf"]["parallelism"] == DEFAULT_KDF_PARAMS.parallelism

    def test_inspect_snapshot_backup(self, tmp_path):
        salt = b"\x44" * BACKUP_SALT_SIZE
        path = tmp_path / "snap.cbox"
        with open(path, "wb") as f:
            write_backup_header(f, BackupFlag.SNAPSHOT, salt, DEFAULT_KDF_PARAMS)
        info = inspect_backup(str(path))
        assert info["snapshot_required"] is True
        assert info["password_required"] is False

    def test_inspect_rejects_oversized_file(self, tmp_path, monkeypatch):
        """超过 MAX_BACKUP_FILE_SIZE 的文件应抛 PayloadTooLargeError。"""
        salt = b"\x00" * BACKUP_SALT_SIZE
        path = tmp_path / "big.cbox"
        with open(path, "wb") as f:
            write_backup_header(f, BackupFlag.PASSWORD, salt, DEFAULT_KDF_PARAMS)
        # 通过下调模块阈值使现有小文件判定为过大，避免写一个 64MB+ 真文件
        monkeypatch.setattr(
            backup_header_codec,
            "MAX_BACKUP_FILE_SIZE",
            1,
        )
        with pytest.raises(PayloadTooLargeError):
            inspect_backup(str(path))


class TestDeriveBackupKey:
    """derive_backup_key 返回 32 字节且受默认参数保护。"""

    def test_returns_32_bytes(self):
        salt = b"\x55" * BACKUP_SALT_SIZE
        key = derive_backup_key("SomePassword!1", salt)
        assert isinstance(key, bytearray)
        assert len(key) == 32

    def test_different_passwords_yield_different_keys(self):
        salt = b"\x00" * BACKUP_SALT_SIZE
        k1 = derive_backup_key("aaa", salt)
        k2 = derive_backup_key("bbb", salt)
        assert k1 != k2


class TestZeroBackupKeyIfOwned:
    """zero_backup_key_if_owned 的清零策略。"""

    def test_password_key_zeroed(self):
        key = bytearray(b"\x01" * 32)
        zero_backup_key_if_owned(BackupFlag.PASSWORD, key)
        assert bytes(key) == b"\x00" * 32

    def test_snapshot_key_not_zeroed(self):
        """SNAPSHOT 路径借用 snapshot_key，不应在此清零。"""
        original = b"\x02" * 32
        key = bytearray(original)
        zero_backup_key_if_owned(BackupFlag.SNAPSHOT, key)
        assert bytes(key) == original

    def test_none_key_skipped(self):
        """None（派生阶段异常的兜底）应静默跳过。"""
        zero_backup_key_if_owned(BackupFlag.PASSWORD, None)  # 不抛异常

    def test_password_bytes_key_zeroed(self):
        """bytes 类型 key 在 PASSWORD 路径也应被处理（虽不可变，仍传递给清零函数）。"""
        # bytes 不可变，secure_zero_buffer 对 bytes 是 no-op，但函数不应抛异常
        zero_backup_key_if_owned(BackupFlag.PASSWORD, b"\x03" * 32)


class TestCorruptedHeader:
    """损坏头部（坏 magic/短头/坏 flag）的拒绝路径。"""

    def test_bad_magic_rejected(self):
        """前缀不是 BACKUP_MAGIC 应抛 BackupError。"""
        buf = io.BytesIO(b"NOTCipherBox\x00\x00\x00" + b"\x00" * 50)
        with pytest.raises(BackupError, match="格式"):
            read_backup_header(buf)

    def test_short_header_rejected(self):
        """长度不足以容纳完整头（struct + salt）应抛 BackupError。"""
        buf = io.BytesIO(BACKUP_MAGIC + b"\x00" * 5)  # 缺失 struct 与 salt
        with pytest.raises(BackupError, match="损坏"):
            read_backup_header(buf)

    def test_bad_flag_rejected(self):
        """未定义的 flag 值（如 0、3、5）应被拒绝。"""
        salt = b"\x00" * BACKUP_SALT_SIZE
        # flag=0（非法）+ 默认 KDF 参数
        raw = (
            BACKUP_MAGIC
            + BACKUP_HEADER_STRUCT.pack(
                0,
                DEFAULT_KDF_PARAMS.time_cost,
                DEFAULT_KDF_PARAMS.memory_cost,
                DEFAULT_KDF_PARAMS.parallelism,
            )
            + salt
        )
        buf = io.BytesIO(raw)
        with pytest.raises(BackupError, match="格式"):
            read_backup_header(buf)

    def test_invalid_kdf_in_header_rejected(self):
        """头部 KDF 参数超出 validate_params 范围应被拒绝（归一为 BackupError）。"""
        salt = b"\x00" * BACKUP_SALT_SIZE
        raw = _make_header_bytes(
            BackupFlag.PASSWORD,
            salt,
            KdfParams(time_cost=1, memory_cost=16 * 1024, parallelism=1),
        )
        buf = io.BytesIO(raw)
        with pytest.raises(BackupError):
            read_backup_header(buf)

    def test_inspect_bad_magic_rejected(self, tmp_path):
        """inspect_backup 对坏 magic 也应抛 BackupError。"""
        path = tmp_path / "bad.cbox"
        path.write_bytes(b"NOT_MAGIC" + b"\x00" * 60)
        with pytest.raises(BackupError):
            inspect_backup(str(path))
