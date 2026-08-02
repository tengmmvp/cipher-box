"""share_package 加密打包端到端测试。

覆盖 payload 采集（含/不含敏感字段差异）、``.cboxshare`` 加密-解密往返、头/密文篡改
拒绝、错密码拒绝、payload 超限，以及 create_share_package 两文件生成与取消语义。

autouse fixture 将 KDF 弱化（与 test_share_kdf.py 的 _TEST_PARAMS 同量级），加速
Argon2id 派生——本测试验证加密往返逻辑而非 KDF 强度。
"""

import io
import json

import pytest

from src.business.services import share_package
from src.business.services.share_header_codec import (
    EXPIRE_NEVER,
    SHARE_HEADER_STRUCT,
    SHARE_MAGIC,
    derive_share_key,
    read_share_header,
    share_header_aad,
)
from src.business.services.share_package import (
    build_share_payload,
    create_share_package,
)
from src.crypto.encryption import EncryptionEngine
from src.crypto.master_key import KdfParams
from src.exceptions import DecryptionError, PayloadTooLargeError
from src.models import CustomField, Entry

# 弱化但合法的 KDF（过 validate_params 下限），加速测试派生；生产用 DEFAULT_KDF_PARAMS。
_WEAK_PARAMS = KdfParams(time_cost=2, memory_cost=16 * 1024, parallelism=1)


@pytest.fixture(autouse=True)
def _weak_kdf(monkeypatch: pytest.MonkeyPatch) -> None:
    """全模块弱化 KDF，加速端到端往返（验证加密逻辑而非 Argon2id 强度）。"""
    monkeypatch.setattr(share_package, "DEFAULT_KDF_PARAMS", _WEAK_PARAMS)


def _make_entry(
    *,
    title: str = "测试条目",
    password: str = "secret123",
    totp: str = "JBSWY3DPEHPK3PXP",
) -> Entry:
    """构造已解密 Entry，含文本与密码两类自定义字段。"""
    return Entry(
        title=title,
        username="user1",
        password=password,
        url="https://example.com",
        tags="t1,t2",
        notes="一段备注",
        entry_type="login",
        totp_secret=totp,
        custom_fields=[
            CustomField("cf_text", "文本值", "text"),
            CustomField("cf_pwd", "机密值", "password"),
        ],
    )


def _decrypt_blob(blob: bytes, password: str) -> dict:
    """解密 .cboxshare 字节并返回 payload dict（验证端到端往返的辅助）。"""
    buf = io.BytesIO(blob)
    _version, salt, params, expire_at, created_at = read_share_header(buf)
    ct_block = buf.read()
    key = derive_share_key(password, salt, params)
    aad = share_header_aad(salt, params, expire_at, created_at)
    plain = EncryptionEngine.decrypt_bytes(ct_block, key, aad)
    return json.loads(plain)


class TestBuildSharePayload:
    """payload 采集与含/不含敏感字段差异。"""

    def test_payload_structure(self):
        payload = build_share_payload([_make_entry()], include_secrets=True)
        assert payload["format"] == "CipherBoxShare"
        assert payload["version"] == 1
        assert "created_at" in payload
        assert len(payload["entries"]) == 1

    def test_include_secrets_true_has_password_totp_and_pwd_field(self):
        payload = build_share_payload([_make_entry()], include_secrets=True)
        item = payload["entries"][0]
        assert item["password"] == "secret123"
        assert item["totp_secret"] == "JBSWY3DPEHPK3PXP"
        field_types = {f["field_type"] for f in item["custom_fields"]}
        assert "password" in field_types  # 含密码类型自定义字段

    def test_include_secrets_false_omits_password_totp_and_pwd_field(self):
        payload = build_share_payload([_make_entry()], include_secrets=False)
        item = payload["entries"][0]
        assert "password" not in item
        assert "totp_secret" not in item
        field_types = {f["field_type"] for f in item["custom_fields"]}
        assert "password" not in field_types  # 过滤密码类型自定义字段
        assert "text" in field_types  # 文本字段保留


class TestBuildShareBlobRoundtrip:
    """_build_share_blob 加密-解密端到端往返。"""

    def test_roundtrip_with_secrets(self):
        blob = share_package._build_share_blob(
            [_make_entry()],
            "sharepass",
            include_secrets=True,
            expire_at=EXPIRE_NEVER,
            created_at=1700000000,
        )
        data = _decrypt_blob(blob, "sharepass")
        item = data["entries"][0]
        assert item["title"] == "测试条目"
        assert item["password"] == "secret123"
        assert item["totp_secret"] == "JBSWY3DPEHPK3PXP"

    def test_roundtrip_without_secrets(self):
        blob = share_package._build_share_blob(
            [_make_entry()],
            "sharepass",
            include_secrets=False,
            expire_at=EXPIRE_NEVER,
            created_at=1700000000,
        )
        data = _decrypt_blob(blob, "sharepass")
        item = data["entries"][0]
        assert item["title"] == "测试条目"
        assert "password" not in item

    def test_tampered_salt_fails_decryption(self):
        """改 salt 字节：头仍合法读取，但 AAD（含原 salt）不匹配致解密失败。"""
        blob = share_package._build_share_blob(
            [_make_entry()],
            "sharepass",
            include_secrets=True,
            expire_at=EXPIRE_NEVER,
            created_at=1700000000,
        )
        tampered = bytearray(blob)
        salt_offset = len(SHARE_MAGIC) + SHARE_HEADER_STRUCT.size
        tampered[salt_offset] ^= 0xFF
        with pytest.raises(DecryptionError):
            _decrypt_blob(bytes(tampered), "sharepass")

    def test_tampered_ciphertext_fails_decryption(self):
        """改密文字节：GCM 认证失败致解密失败。"""
        blob = share_package._build_share_blob(
            [_make_entry()],
            "sharepass",
            include_secrets=True,
            expire_at=EXPIRE_NEVER,
            created_at=1700000000,
        )
        tampered = bytearray(blob)
        tampered[-1] ^= 0xFF  # 改末尾（tag 区）
        with pytest.raises(DecryptionError):
            _decrypt_blob(bytes(tampered), "sharepass")

    def test_wrong_password_fails(self):
        blob = share_package._build_share_blob(
            [_make_entry()],
            "sharepass",
            include_secrets=True,
            expire_at=EXPIRE_NEVER,
            created_at=1700000000,
        )
        with pytest.raises(DecryptionError):
            _decrypt_blob(blob, "wrong_password")

    def test_payload_too_large_raises(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(share_package, "MAX_SHARE_PAYLOAD_SIZE", 1)
        with pytest.raises(PayloadTooLargeError):
            share_package._build_share_blob(
                [_make_entry()],
                "sharepass",
                include_secrets=True,
                expire_at=EXPIRE_NEVER,
                created_at=1700000000,
            )


class TestCreateSharePackage:
    """create_share_package 两文件生成与取消语义。"""

    def test_creates_two_files(self, tmp_path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            share_package, "_render_decrypter_html", lambda: "<html>decrypter</html>"
        )
        result = create_share_package(
            [_make_entry()],
            "sharepass",
            include_secrets=True,
            expire_at=EXPIRE_NEVER,
            output_dir=str(tmp_path),
        )
        assert result is not None
        share_path, decrypter_path = result
        assert share_path.exists()
        assert decrypter_path.exists()
        assert share_path.suffix == ".cboxshare"
        assert decrypter_path.suffix == ".html"
        # .cboxshare 可被独立解密
        data = _decrypt_blob(share_path.read_bytes(), "sharepass")
        assert data["entries"][0]["title"] == "测试条目"
        # 解密器 HTML 内容写入
        assert "decrypter" in decrypter_path.read_text(encoding="utf-8")

    def test_cancel_returns_none(self, tmp_path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(share_package, "_render_decrypter_html", lambda: "<html></html>")
        result = create_share_package(
            [_make_entry()],
            "sharepass",
            include_secrets=True,
            expire_at=EXPIRE_NEVER,
            output_dir=str(tmp_path),
            cancel_check=lambda: True,
        )
        assert result is None
        # 取消时不产出任何文件
        assert not list(tmp_path.iterdir())
