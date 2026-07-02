"""测试 EncryptionEngine 异常链保留。

验证 decrypt 与 decrypt_bytes 在遇到无效或篡改数据时，抛出 DecryptionError
（双继承 ValueError）并通过 ``raise ... from exc`` 保留原始异常链，使 __cause__
不为空，便于开发者追踪根因。格式不符 / 长度不足等确定性错误无底层异常，不产生链。
"""
import pytest

from src.crypto.encryption import EncryptionEngine
from src.exceptions import DecryptionError


class TestEncryptionExceptionChain:
    """验证解密失败时抛出 DecryptionError 并保留原始异常链。"""

    def test_decrypt_invalid_data_raises_decryption_error(self):
        """decrypt 无效数据时抛出 DecryptionError 并保留原始异常链。"""
        key = b'\x00' * 32
        # 正确前缀但 base64 非法（含下划线，非标准字母表）→ 走解码失败路径，保留异常链。
        # 格式不符 / 长度不足属确定性错误（无底层异常），不产生 __cause__；此处专门
        # 验证「可恢复异常被 raise ... from exc 链接」的契约。
        with pytest.raises(DecryptionError) as exc_info:
            EncryptionEngine.decrypt(EncryptionEngine.TEXT_PREFIX + 'invalid_data', key, 'aad')
        # DecryptionError 双继承 ValueError
        assert isinstance(exc_info.value, ValueError)
        # __cause__ 应保留原始异常（base64 解码错误），方便开发者追踪根因。
        assert exc_info.value.__cause__ is not None

    def test_decrypt_bytes_invalid_data_raises_decryption_error(self):
        """decrypt_bytes 无效数据时抛出 DecryptionError 并保留异常链。"""
        key = b'\x00' * 32
        # 使用正确前缀但无效的密文数据，触发内部 try/except 路径。
        with pytest.raises(DecryptionError) as exc_info:
            EncryptionEngine.decrypt_bytes(b'CB2' + b'\x00' * 28, key, 'aad')
        assert isinstance(exc_info.value, ValueError)
        assert exc_info.value.__cause__ is not None

    def test_decrypt_tampered_ciphertext_raises_decryption_error(self):
        """篡改的密文应抛出 DecryptionError（GCM 认证失败）。"""
        key = b'\x00' * 32
        encrypted = EncryptionEngine.encrypt('test data', key, 'aad')
        # 篡改密文，修改最后几个字节。
        import base64
        raw = base64.b64decode(encrypted[len(EncryptionEngine.TEXT_PREFIX):])
        tampered = raw[:-4] + bytes([raw[-4] ^ 0xFF]) + raw[-3:]
        tampered_b64 = EncryptionEngine.TEXT_PREFIX + base64.b64encode(tampered).decode('ascii')
        with pytest.raises(DecryptionError):
            EncryptionEngine.decrypt(tampered_b64, key, 'aad')
