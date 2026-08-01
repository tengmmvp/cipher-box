"""加密参数验证测试。

验证 EncryptionEngine 的 encrypt/decrypt/encrypt_bytes/decrypt_bytes 的参数
校验逻辑，以及解密失败时错误信息的脱敏行为，确保不向调用方泄露 MAC、tag
等内部加密术语。
"""

import pytest

from src.crypto.encryption import EncryptionEngine


class TestEncryptionValidation:
    """验证 EncryptionEngine 的参数校验逻辑。"""

    # --- encrypt 参数校验 ---

    def test_encrypt_rejects_short_key(self):
        """密钥长度不足 32 字节时拒绝加密。"""
        with pytest.raises(ValueError, match="AES-256"):
            EncryptionEngine.encrypt("test", b"short", "aad")

    def test_encrypt_rejects_non_bytes_key(self):
        """密钥非 bytes 类型时拒绝加密。"""
        with pytest.raises(TypeError):
            EncryptionEngine.encrypt("test", "not bytes", "aad")  # type: ignore[arg-type]

    def test_encrypt_rejects_non_string_plaintext(self):
        """明文非字符串时拒绝加密。"""
        with pytest.raises(AttributeError):
            EncryptionEngine.encrypt(123, b"\x00" * 32, "aad")  # type: ignore[arg-type]

    def test_encrypt_empty_string_returns_encrypted(self):
        """空明文仍走完整加密路径，AAD 参与认证。"""
        result = EncryptionEngine.encrypt("", b"\x00" * 32, "aad")
        assert result != ""
        assert result.startswith(EncryptionEngine.TEXT_PREFIX)
        decrypted = EncryptionEngine.decrypt(result, b"\x00" * 32, "aad")
        assert decrypted == ""

    # --- decrypt 参数校验 ---

    def test_decrypt_rejects_short_key(self):
        """密钥长度不足 32 字节时拒绝解密，最终由 AESGCM 校验触发。"""
        # 短密钥会先触发 base64 解码错误，被包装为 ValueError。
        with pytest.raises(ValueError):
            EncryptionEngine.decrypt("cb2:abc", b"short", "aad")

    def test_decrypt_rejects_non_bytes_key(self):
        """密钥非 bytes 类型时拒绝解密，内部 TypeError 被包装为 ValueError。"""
        with pytest.raises(ValueError):
            EncryptionEngine.decrypt("cb2:abc", "not bytes", "aad")  # type: ignore[arg-type]

    def test_decrypt_empty_string_raises(self):
        """空密文是非法输入，应抛出 ValueError。"""
        with pytest.raises(ValueError):
            EncryptionEngine.decrypt("", b"\x00" * 32, "aad")

    def test_decrypt_generic_error_message(self):
        """解密失败时不泄露内部异常信息，如 MAC、tag 等术语。"""
        with pytest.raises(ValueError) as exc_info:
            EncryptionEngine.decrypt("invalid_ciphertext", b"\x00" * 32, "aad")
        error_msg = str(exc_info.value)
        # 错误消息不应包含内部加密术语。
        assert "MAC" not in error_msg
        assert "tag" not in error_msg.lower()
        assert "InvalidTag" not in error_msg

    def test_decrypt_rejects_non_string_ciphertext(self):
        """密文非字符串时拒绝解密。

        非 str 是调用方类型 bug（真实路径密文恒为 str），与 decrypt_bytes 对非 bytes
        抛 TypeError 一致——类型错误不包装为 DecryptionError，直接抛 AttributeError。
        decrypt 的失败闭合仅覆盖「字符串密文的解密失败」（格式 / 长度 / base64 / GCM）。
        """
        with pytest.raises(AttributeError):
            EncryptionEngine.decrypt(123, b"\x00" * 32, "aad")  # type: ignore[arg-type]

    def test_decrypt_rejects_wrong_prefix(self):
        """密文前缀不正确时拒绝解密。"""
        with pytest.raises(ValueError):
            EncryptionEngine.decrypt("wrong_prefix:abc", b"\x00" * 32, "aad")

    # --- encrypt_bytes / decrypt_bytes 参数校验 ---

    def test_encrypt_bytes_rejects_non_bytes_data(self):
        """encrypt_bytes 拒绝非 bytes 数据。"""
        with pytest.raises(TypeError):
            EncryptionEngine.encrypt_bytes("string", b"\x00" * 32, "aad")  # type: ignore[arg-type]

    def test_decrypt_bytes_rejects_non_bytes_data(self):
        """decrypt_bytes 拒绝非 bytes 数据。"""
        with pytest.raises(TypeError):
            EncryptionEngine.decrypt_bytes("string", b"\x00" * 32, "aad")  # type: ignore[arg-type]

    def test_encrypt_bytes_rejects_short_key(self):
        """encrypt_bytes 拒绝短密钥。"""
        with pytest.raises(ValueError, match="AES-256"):
            EncryptionEngine.encrypt_bytes(b"data", b"short", "aad")

    def test_decrypt_bytes_rejects_short_key(self):
        """decrypt_bytes 拒绝短密钥，最终触发密文格式或长度无效错误。"""
        with pytest.raises(ValueError):
            EncryptionEngine.decrypt_bytes(b"cb2:abc", b"short", "aad")

    def test_encrypt_decrypt_bytes_roundtrip(self):
        """encrypt_bytes/decrypt_bytes 正确的往返加解密。"""
        key = b"\x00" * 32
        encrypted = EncryptionEngine.encrypt_bytes(b"hello world", key, "aad")
        assert isinstance(encrypted, bytes)
        assert encrypted != b"hello world"
        decrypted = EncryptionEngine.decrypt_bytes(encrypted, key, "aad")
        assert decrypted == b"hello world"

    def test_decrypt_bytes_tampered_ciphertext(self):
        """decrypt_bytes 对篡改的密文返回脱敏错误信息。"""
        key = b"\x00" * 32
        encrypted = EncryptionEngine.encrypt_bytes(b"secret", key, "aad")
        tampered = bytearray(encrypted)
        tampered[-1] ^= 0xFF
        with pytest.raises(ValueError):
            EncryptionEngine.decrypt_bytes(bytes(tampered), key, "aad")

    def test_encrypt_bytes_empty_data(self):
        """encrypt_bytes 空数据正常加密。"""
        key = b"\x00" * 32
        encrypted = EncryptionEngine.encrypt_bytes(b"", key, "aad")
        assert isinstance(encrypted, bytes)
        decrypted = EncryptionEngine.decrypt_bytes(encrypted, key, "aad")
        assert decrypted == b""
