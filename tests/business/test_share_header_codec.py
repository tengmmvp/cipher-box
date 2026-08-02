"""share_header_codec 模块的编解码、检视与密钥派生测试。

覆盖限时加密共享包二进制头的写入/读取往返、AAD 构造、KDF 参数下限与上界守卫、
密钥派生、检视以及损坏头部（坏 magic/短头/坏版本/坏 KDF）的拒绝路径。
"""

import io

import pytest

from src.business.services import share_header_codec
from src.business.services.share_header_codec import (
    EXPIRE_NEVER,
    SHARE_AAD,
    SHARE_FORMAT,
    SHARE_HEADER_STRUCT,
    SHARE_MAGIC,
    SHARE_SALT_SIZE,
    SHARE_VERSION,
    derive_share_key,
    enforce_kdf_ceiling,
    enforce_kdf_floor,
    inspect_share,
    read_share_header,
    share_header_aad,
    write_share_header,
)
from src.crypto.master_key import DEFAULT_KDF_PARAMS, KdfParams
from src.exceptions import PayloadTooLargeError, ShareError

_EXPIRE = 1700000000
_CREATED = 1600000000
_SALT = b"\x11" * SHARE_SALT_SIZE


def _make_header_bytes(
    salt: bytes = _SALT,
    params: KdfParams = DEFAULT_KDF_PARAMS,
    expire_at: int = _EXPIRE,
    created_at: int = _CREATED,
    *,
    version: int = SHARE_VERSION,
) -> bytes:
    """构造与 write_share_header 等价的二进制头部（便于直接篡改字节）。"""
    return (
        SHARE_MAGIC
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


class TestShareHeaderRoundtrip:
    """写入/读取头部往返一致性。"""

    def test_roundtrip(self):
        buf = io.BytesIO()
        write_share_header(buf, _SALT, DEFAULT_KDF_PARAMS, _EXPIRE, _CREATED)
        buf.seek(0)
        version, salt, params, expire_at, created_at = read_share_header(buf)
        assert version == SHARE_VERSION
        assert salt == _SALT
        assert params == DEFAULT_KDF_PARAMS
        assert expire_at == _EXPIRE
        assert created_at == _CREATED

    def test_expire_never_roundtrip(self):
        """expire_at=EXPIRE_NEVER 表示永不过期，应完整往返。"""
        buf = io.BytesIO()
        write_share_header(buf, _SALT, DEFAULT_KDF_PARAMS, EXPIRE_NEVER, _CREATED)
        buf.seek(0)
        _, _, _, expire_at, _ = read_share_header(buf)
        assert expire_at == EXPIRE_NEVER

    def test_write_rejects_invalid_salt_length(self):
        buf = io.BytesIO()
        with pytest.raises(ShareError, match="盐"):
            write_share_header(buf, b"\x00" * 10, DEFAULT_KDF_PARAMS, _EXPIRE, _CREATED)

    def test_write_rejects_invalid_params(self):
        buf = io.BytesIO()
        with pytest.raises(ValueError):
            write_share_header(
                buf,
                _SALT,
                KdfParams(time_cost=1, memory_cost=16 * 1024, parallelism=1),
                _EXPIRE,
                _CREATED,
            )


class TestShareHeaderAad:
    """share_header_aad 内容构造。"""

    def test_aad_contains_magic_struct_and_salt(self):
        aad = share_header_aad(_SALT, DEFAULT_KDF_PARAMS, _EXPIRE, _CREATED)
        assert aad.startswith(SHARE_AAD + SHARE_MAGIC)
        assert aad.endswith(_SALT)
        packed = SHARE_HEADER_STRUCT.pack(
            SHARE_VERSION,
            DEFAULT_KDF_PARAMS.time_cost,
            DEFAULT_KDF_PARAMS.memory_cost,
            DEFAULT_KDF_PARAMS.parallelism,
            _EXPIRE,
            _CREATED,
        )
        assert packed in aad

    def test_aad_differs_per_expire(self):
        """过期时间变化应反映到 AAD（绑定过期到 payload，防头篡改改过期）。"""
        aad1 = share_header_aad(_SALT, DEFAULT_KDF_PARAMS, _EXPIRE, _CREATED)
        aad2 = share_header_aad(_SALT, DEFAULT_KDF_PARAMS, _EXPIRE + 1, _CREATED)
        assert aad1 != aad2

    def test_aad_differs_per_params(self):
        weak = KdfParams(time_cost=2, memory_cost=16 * 1024, parallelism=1)
        aad_default = share_header_aad(_SALT, DEFAULT_KDF_PARAMS, _EXPIRE, _CREATED)
        aad_weak = share_header_aad(_SALT, weak, _EXPIRE, _CREATED)
        assert aad_default != aad_weak


class TestEnforceKdfFloor:
    """enforce_kdf_floor 拒绝低于默认值的参数。"""

    def test_rejects_low_time(self):
        with pytest.raises(ShareError, match="KDF"):
            enforce_kdf_floor(
                KdfParams(
                    time_cost=DEFAULT_KDF_PARAMS.time_cost - 1,
                    memory_cost=DEFAULT_KDF_PARAMS.memory_cost,
                    parallelism=DEFAULT_KDF_PARAMS.parallelism,
                )
            )

    def test_accepts_default(self):
        enforce_kdf_floor(DEFAULT_KDF_PARAMS)  # 不抛异常即通过


class TestEnforceKdfCeiling:
    """enforce_kdf_ceiling 拒绝远超默认的参数，防解析路径内存耗尽 DoS。"""

    def test_accepts_default(self):
        enforce_kdf_ceiling(DEFAULT_KDF_PARAMS)

    def test_rejects_oversized_time(self):
        m = share_header_codec.MAX_SHARE_KDF_MULTIPLIER
        with pytest.raises(ShareError, match="上界"):
            enforce_kdf_ceiling(
                KdfParams(
                    DEFAULT_KDF_PARAMS.time_cost * (m + 1),
                    DEFAULT_KDF_PARAMS.memory_cost,
                    DEFAULT_KDF_PARAMS.parallelism,
                )
            )


class TestInspectShare:
    """inspect_share 读头返回结构化字典。"""

    def test_inspect(self, tmp_path):
        path = tmp_path / "test.cboxshare"
        with open(path, "wb") as f:
            write_share_header(f, _SALT, DEFAULT_KDF_PARAMS, _EXPIRE, _CREATED)
            f.write(b"payload-tail")
        info = inspect_share(str(path))
        assert info["format"] == SHARE_FORMAT
        assert info["version"] == SHARE_VERSION
        assert info["kdf"]["name"] == "argon2id"
        assert info["kdf"]["time_cost"] == DEFAULT_KDF_PARAMS.time_cost
        assert info["expire_at"] == _EXPIRE
        assert info["created_at"] == _CREATED

    def test_inspect_rejects_oversized_file(self, tmp_path, monkeypatch):
        path = tmp_path / "big.cboxshare"
        with open(path, "wb") as f:
            write_share_header(f, _SALT, DEFAULT_KDF_PARAMS, _EXPIRE, _CREATED)
        monkeypatch.setattr(share_header_codec, "MAX_SHARE_FILE_SIZE", 1)
        with pytest.raises(PayloadTooLargeError):
            inspect_share(str(path))


class TestDeriveShareKey:
    """derive_share_key 返回 32 字节。"""

    def test_returns_32_bytes(self):
        key = derive_share_key("SomePassword!1", _SALT, DEFAULT_KDF_PARAMS)
        assert isinstance(key, bytearray)
        assert len(key) == 32

    def test_different_passwords_yield_different_keys(self):
        k1 = derive_share_key("aaa", _SALT, DEFAULT_KDF_PARAMS)
        k2 = derive_share_key("bbb", _SALT, DEFAULT_KDF_PARAMS)
        assert k1 != k2


class TestCorruptedHeader:
    """损坏头部的拒绝路径。"""

    def test_bad_magic_rejected(self):
        buf = io.BytesIO(b"NOTCipherBoxShare\x00" + b"\x00" * 80)
        with pytest.raises(ShareError, match="格式"):
            read_share_header(buf)

    def test_short_header_rejected(self):
        buf = io.BytesIO(SHARE_MAGIC + b"\x00" * 5)
        with pytest.raises(ShareError, match="损坏"):
            read_share_header(buf)

    def test_bad_version_rejected(self):
        raw = _make_header_bytes(version=SHARE_VERSION + 1)
        buf = io.BytesIO(raw)
        with pytest.raises(ShareError, match="版本"):
            read_share_header(buf)

    def test_invalid_kdf_in_header_rejected(self):
        raw = _make_header_bytes(
            params=KdfParams(time_cost=1, memory_cost=16 * 1024, parallelism=1),
        )
        buf = io.BytesIO(raw)
        with pytest.raises(ShareError):
            read_share_header(buf)

    def test_inspect_bad_magic_rejected(self, tmp_path):
        path = tmp_path / "bad.cboxshare"
        path.write_bytes(b"NOT_MAGIC" + b"\x00" * 80)
        with pytest.raises(ShareError):
            inspect_share(str(path))
