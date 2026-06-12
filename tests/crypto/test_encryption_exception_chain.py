"""测试 EncryptionEngine 异常链保留。

验证 decrypt 与 decrypt_bytes 在遇到无效或篡改数据时，通过 ``raise ... from exc``
保留原始异常链，使 __cause__ 不为空，便于开发者追踪根因。
"""
import pytest

from src.crypto.encryption import EncryptionEngine


class TestEncryptionExceptionChain:
    """验证解密失败时原始异常链被正确保留。"""

    def test_decrypt_invalid_data_preserves_cause(self):
        """decrypt 无效数据时应通过 from exc 保留原始异常链，便于调试。"""
        key = b'\x00' * 32
        # 构造无效密文，过短无法包含 nonce 加 tag。
        with pytest.raises(ValueError) as exc_info:
            EncryptionEngine.decrypt('invalid_data', key, 'aad')
        # __cause__ 应保留原始异常，方便开发者追踪根因。
        assert exc_info.value.__cause__ is not None

    def test_decrypt_bytes_invalid_data_preserves_cause(self):
        """decrypt_bytes 无效数据时应保留原始异常链。"""
        key = b'\x00' * 32
        # 使用正确前缀但无效的密文数据，触发内部 try/except 路径。
        with pytest.raises(ValueError) as exc_info:
            EncryptionEngine.decrypt_bytes(b'CBX' + b'\x00' * 28, key, 'aad')
        assert exc_info.value.__cause__ is not None

    def test_decrypt_tampered_ciphertext_raises(self):
        """篡改的密文应抛出 ValueError。"""
        key = b'\x00' * 32
        encrypted = EncryptionEngine.encrypt('test data', key, 'aad')
        # 篡改密文，修改最后几个字节。
        import base64
        raw = base64.b64decode(encrypted[len(EncryptionEngine.TEXT_PREFIX):])
        tampered = raw[:-4] + bytes([raw[-4] ^ 0xFF]) + raw[-3:]
        tampered_b64 = EncryptionEngine.TEXT_PREFIX + base64.b64encode(tampered).decode('ascii')
        with pytest.raises(ValueError):
            EncryptionEngine.decrypt(tampered_b64, key, 'aad')
