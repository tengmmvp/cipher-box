"""加密参数验证测试 — 验证 encrypt/decrypt 的参数校验和脱敏错误信息"""

import pytest

from src.crypto.encryption import EncryptionEngine


class TestEncryptionValidation:
    """验证 EncryptionEngine 的参数校验逻辑。"""

    # --- encrypt 参数校验 ---

    def test_encrypt_rejects_short_key(self):
        """密钥长度不足 32 字节时拒绝加密。"""
        with pytest.raises(ValueError, match="AES-256"):
            EncryptionEngine.encrypt("test", b'short', "aad")

    def test_encrypt_rejects_non_bytes_key(self):
        """密钥非 bytes 类型时拒绝加密。"""
        with pytest.raises(TypeError):
            EncryptionEngine.encrypt("test", "not bytes", "aad")  # type: ignore[arg-type]

    def test_encrypt_rejects_non_string_plaintext(self):
        """明文非字符串时拒绝加密。"""
        with pytest.raises(AttributeError):
            EncryptionEngine.encrypt(123, b'\x00' * 32, "aad")  # type: ignore[arg-type]

    def test_encrypt_empty_string_returns_encrypted(self):
        """空字符串明文通过 sentinel 加密，AAD 参与认证。"""
        result = EncryptionEngine.encrypt("", b'\x00' * 32, "aad")
        assert result != ''
        assert result.startswith(EncryptionEngine.TEXT_PREFIX)
        decrypted = EncryptionEngine.decrypt(result, b'\x00' * 32, "aad")
        assert decrypted == ''

    # --- decrypt 参数校验 ---

    def test_decrypt_rejects_short_key(self):
        """密钥长度不足 32 字节时拒绝解密（通过 AESGCM 触发）。"""
        # 短密钥会先触发 base64 解码错误，被包装为 ValueError
        with pytest.raises(ValueError):
            EncryptionEngine.decrypt("cb:abc", b'short', "aad")

    def test_decrypt_rejects_non_bytes_key(self):
        """密钥非 bytes 类型时拒绝解密（通过 AESGCM 触发 TypeError，包装为 ValueError）。"""
        with pytest.raises(ValueError):
            EncryptionEngine.decrypt("cb:abc", "not bytes", "aad")  # type: ignore[arg-type]

    def test_decrypt_empty_string_returns_empty(self):
        """空密文直接返回空字符串。"""
        result = EncryptionEngine.decrypt("", b'\x00' * 32, "aad")
        assert result == ''

    def test_decrypt_generic_error_message(self):
        """解密失败时不泄露内部异常信息（如 MAC/tag）。"""
        with pytest.raises(ValueError) as exc_info:
            EncryptionEngine.decrypt("invalid_ciphertext", b'\x00' * 32, "aad")
        error_msg = str(exc_info.value)
        # 错误消息不应包含内部加密术语
        assert "MAC" not in error_msg
        assert "tag" not in error_msg.lower()
        assert "InvalidTag" not in error_msg

    def test_decrypt_rejects_non_string_ciphertext(self):
        """密文非字符串时拒绝解密。"""
        # 非 str 进入 decrypt 后触发 AttributeError，被 except 捕获并包装为 ValueError
        with pytest.raises(ValueError):
            EncryptionEngine.decrypt(123, b'\x00' * 32, "aad")  # type: ignore[arg-type]

    def test_decrypt_rejects_wrong_prefix(self):
        """密文前缀不正确时拒绝解密。"""
        with pytest.raises(ValueError):
            EncryptionEngine.decrypt("wrong_prefix:abc", b'\x00' * 32, "aad")

    # --- encrypt_bytes / decrypt_bytes 参数校验 ---

    def test_encrypt_bytes_rejects_non_bytes_data(self):
        """encrypt_bytes 拒绝非 bytes 数据。"""
        with pytest.raises(TypeError):
            EncryptionEngine.encrypt_bytes("string", b'\x00' * 32, "aad")  # type: ignore[arg-type]

    def test_decrypt_bytes_rejects_non_bytes_data(self):
        """decrypt_bytes 拒绝非 bytes 数据。"""
        with pytest.raises(TypeError):
            EncryptionEngine.decrypt_bytes("string", b'\x00' * 32, "aad")  # type: ignore[arg-type]

    def test_encrypt_bytes_rejects_short_key(self):
        """encrypt_bytes 拒绝短密钥。"""
        with pytest.raises(ValueError, match="AES-256"):
            EncryptionEngine.encrypt_bytes(b"data", b'short', "aad")

    def test_decrypt_bytes_rejects_short_key(self):
        """decrypt_bytes 拒绝短密钥（触发密文格式或长度无效）。"""
        with pytest.raises(ValueError):
            EncryptionEngine.decrypt_bytes(b"cb:abc", b'short', "aad")

    def test_encrypt_decrypt_bytes_roundtrip(self):
        """encrypt_bytes/decrypt_bytes 正确的往返加解密。"""
        key = b'\x00' * 32
        encrypted = EncryptionEngine.encrypt_bytes(b"hello world", key, "aad")
        assert isinstance(encrypted, bytes)
        assert encrypted != b"hello world"
        decrypted = EncryptionEngine.decrypt_bytes(encrypted, key, "aad")
        assert decrypted == b"hello world"

    def test_decrypt_bytes_tampered_ciphertext(self):
        """decrypt_bytes 对篡改的密文返回脱敏错误信息。"""
        key = b'\x00' * 32
        encrypted = EncryptionEngine.encrypt_bytes(b"secret", key, "aad")
        # 篡改密文
        tampered = bytearray(encrypted)
        tampered[-1] ^= 0xFF
        with pytest.raises(ValueError):
            EncryptionEngine.decrypt_bytes(bytes(tampered), key, "aad")

    def test_encrypt_bytes_empty_data(self):
        """encrypt_bytes 空数据正常加密。"""
        key = b'\x00' * 32
        encrypted = EncryptionEngine.encrypt_bytes(b"", key, "aad")
        assert isinstance(encrypted, bytes)
        decrypted = EncryptionEngine.decrypt_bytes(encrypted, key, "aad")
        assert decrypted == b""
