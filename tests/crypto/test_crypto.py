"""加密模块测试"""

import os
import unittest

import pytest

from src.crypto.encryption import EncryptionEngine
from src.crypto.master_key import MasterKeyManager
from src.crypto.password_generator import PasswordGenerator


class TestEncryptionEngine(unittest.TestCase):
    """AES-256-GCM 加密解密测试"""

    AAD = 'test:secret'

    def test_encrypt_decrypt(self):
        key = os.urandom(32)
        plaintext = 'Hello, CipherBox!'
        encrypted = EncryptionEngine.encrypt(plaintext, key, self.AAD)
        self.assertNotEqual(encrypted, plaintext)
        decrypted = EncryptionEngine.decrypt(encrypted, key, self.AAD)
        self.assertEqual(decrypted, plaintext)

    def test_empty_string(self):
        key = os.urandom(32)
        # 空字符串现在走 sentinel 加密路径，确保 AAD 参与认证
        encrypted = EncryptionEngine.encrypt('', key, self.AAD)
        self.assertNotEqual(encrypted, '')
        self.assertTrue(encrypted.startswith(EncryptionEngine.TEXT_PREFIX))
        decrypted = EncryptionEngine.decrypt(encrypted, key, self.AAD)
        self.assertEqual(decrypted, '')
        # 旧版空密文（空字符串）仍能正确解密
        self.assertEqual(EncryptionEngine.decrypt('', key, self.AAD), '')

    def test_unicode(self):
        key = os.urandom(32)
        plaintext = '中文密码测试 <SEC> emojis <JOY>'
        encrypted = EncryptionEngine.encrypt(plaintext, key, self.AAD)
        decrypted = EncryptionEngine.decrypt(encrypted, key, self.AAD)
        self.assertEqual(decrypted, plaintext)

    def test_wrong_key_fails(self):
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        encrypted = EncryptionEngine.encrypt('secret', key1, self.AAD)
        with self.assertRaises(ValueError):
            EncryptionEngine.decrypt(encrypted, key2, self.AAD)

    def test_different_encryptions(self):
        """相同明文两次加密结果应不同（因为随机 nonce）"""
        key = os.urandom(32)
        enc1 = EncryptionEngine.encrypt('same text', key, self.AAD)
        enc2 = EncryptionEngine.encrypt('same text', key, self.AAD)
        self.assertNotEqual(enc1, enc2)

    def test_encrypt_decrypt_bytes(self):
        key = os.urandom(32)
        data = b'binary data test'
        encrypted = EncryptionEngine.encrypt_bytes(data, key, self.AAD)
        decrypted = EncryptionEngine.decrypt_bytes(encrypted, key, self.AAD)
        self.assertEqual(decrypted, data)

    def test_rejects_ciphertext_without_current_prefix(self):
        key = os.urandom(32)
        with self.assertRaises(ValueError):
            EncryptionEngine.decrypt('AAAA', key, self.AAD)
        with self.assertRaises(ValueError):
            EncryptionEngine.decrypt_bytes(b'legacy', key, self.AAD)


class TestMasterKeyManager(unittest.TestCase):
    """主密码管理测试"""

    def test_create_and_verify(self):
        salt, verify_token, derived_key = MasterKeyManager.create('test_password_123')
        self.assertIsNotNone(salt)
        self.assertIsNotNone(verify_token)
        self.assertEqual(len(salt), 32)

        key = MasterKeyManager.verify('test_password_123', salt, verify_token)
        self.assertIsNotNone(key)
        self.assertEqual(len(key), 32)

    def test_wrong_password(self):
        salt, verify_token, _ = MasterKeyManager.create('correct_password')
        key = MasterKeyManager.verify('wrong_password', salt, verify_token)
        self.assertIsNone(key)

    def test_change_password(self):
        old_salt, old_verify, _ = MasterKeyManager.create('old_password')
        result = MasterKeyManager.change_password(
            'old_password', 'new_password', old_salt, old_verify
        )
        self.assertIsNotNone(result)
        new_salt, new_verify, new_key = result
        # L4：change_password 返回复用 create 已派生的 new_key，
        # 调用方无需重复一次 PBKDF2 派生（32 字节 AES-256 密钥）
        self.assertEqual(len(new_key), 32)

        # 新密码应能验证
        key = MasterKeyManager.verify('new_password', new_salt, new_verify)
        self.assertIsNotNone(key)

        # 旧密码不应能验证
        key = MasterKeyManager.verify('old_password', new_salt, new_verify)
        self.assertIsNone(key)

    def test_change_wrong_old_password(self):
        old_salt, old_verify, _ = MasterKeyManager.create('real_password')
        result = MasterKeyManager.change_password(
            'wrong_password', 'new_password', old_salt, old_verify
        )
        self.assertIsNone(result)


class TestPasswordGenerator(unittest.TestCase):
    """密码生成器测试"""

    def test_generate_default(self):
        pwd = PasswordGenerator.generate()
        self.assertEqual(len(pwd), 16)

    def test_generate_custom_length(self):
        pwd = PasswordGenerator.generate(length=32)
        self.assertEqual(len(pwd), 32)

    def test_generate_min_length(self):
        pwd = PasswordGenerator.generate(length=2)
        self.assertEqual(len(pwd), 4)  # 最小 4

    def test_generate_no_uppercase(self):
        pwd = PasswordGenerator.generate(length=50, uppercase=False)
        self.assertFalse(any(c.isupper() for c in pwd))

    def test_generate_no_digits(self):
        pwd = PasswordGenerator.generate(length=50, digits=False, symbols=False)
        self.assertFalse(any(c.isdigit() for c in pwd))

    def test_strength_strong(self):
        result = PasswordGenerator.check_strength('MyStr0ng!P@ssw0rd#2024')
        self.assertGreaterEqual(result.score, 3)

    def test_strength_weak(self):
        result = PasswordGenerator.check_strength('123456')
        self.assertLessEqual(result.score, 1)
        self.assertTrue(result.is_common)

    def test_strength_empty(self):
        result = PasswordGenerator.check_strength('')
        self.assertEqual(result.score, 0)

    def test_strength_feedback(self):
        result = PasswordGenerator.check_strength('abc')
        self.assertTrue(len(result.feedback) > 0)

    def test_exclude_ambiguous(self):
        pwd = PasswordGenerator.generate(length=100, exclude_ambiguous=True)
        ambiguous = set('Il1O0o')
        self.assertFalse(any(c in ambiguous for c in pwd))


class TestEncryptionEdgeCases:
    """EncryptionEngine 边界行为测试。"""

    def test_encrypt_empty_string_no_aad(self):
        """空字符串现在通过 sentinel 加密，AAD 参与认证。"""
        result = EncryptionEngine.encrypt("", b'\x00' * 32, "any_aad")
        assert result != ''
        assert result.startswith(EncryptionEngine.TEXT_PREFIX)
        # 解密后应返回空字符串
        decrypted = EncryptionEngine.decrypt(result, b'\x00' * 32, "any_aad")
        assert decrypted == ''

    def test_decrypt_empty_string_no_aad(self):
        """空密文解密不消耗 AAD — 返回空字符串。"""
        result = EncryptionEngine.decrypt("", b'\x00' * 32, "any_aad")
        assert result == ''


class TestAESGCMCache:
    """AESGCM 实例缓存测试"""

    def setup_method(self):
        EncryptionEngine.clear_cache()

    def teardown_method(self):
        EncryptionEngine.clear_cache()

    def test_same_key_reuses_cipher(self):
        """相同密钥应复用同一 AESGCM 实例"""
        key = os.urandom(32)
        c1 = EncryptionEngine._get_cipher(key)
        c2 = EncryptionEngine._get_cipher(key)
        assert c1 is c2

    def test_different_key_creates_new_cipher(self):
        """不同密钥应创建不同的 AESGCM 实例"""
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        c1 = EncryptionEngine._get_cipher(key1)
        c2 = EncryptionEngine._get_cipher(key2)
        assert c1 is not c2

    def test_cache_cleared_on_lock(self):
        """缓存清除后旧条目不再命中"""
        key = os.urandom(32)
        c1 = EncryptionEngine._get_cipher(key)
        EncryptionEngine.clear_cache()
        c2 = EncryptionEngine._get_cipher(key)
        assert c1 is not c2

    def test_cache_hit_after_encrypt(self):
        """加密后再次获取同一 key 的 cipher 应命中缓存"""
        key = os.urandom(32)
        EncryptionEngine.encrypt('test data', key, 'aad')
        cached = EncryptionEngine._get_cipher(key)
        c = EncryptionEngine._get_cipher(key)
        assert c is cached

    def test_encrypt_decrypt_with_cached_cipher(self):
        """缓存 cipher 正确完成加解密"""
        key = os.urandom(32)
        plaintext = 'cache test 测试'
        encrypted = EncryptionEngine.encrypt(plaintext, key, 'aad')
        decrypted = EncryptionEngine.decrypt(encrypted, key, 'aad')
        assert decrypted == plaintext

    def test_decrypt_bytes_wrong_prefix(self):
        """decrypt_bytes 拒绝错误前缀。"""
        with pytest.raises(ValueError, match='不支持的密文字节格式'):
            EncryptionEngine.decrypt_bytes(b"WRONG" + b'\x00' * 28, b'\x00' * 32, "aad")

    def test_decrypt_bytes_too_short(self):
        """decrypt_bytes 拒绝过短密文。"""
        with pytest.raises(ValueError, match='密文长度无效'):
            EncryptionEngine.decrypt_bytes(b"CBX" + b'\x00' * 10, b'\x00' * 32, "aad")

    def test_decrypt_generic_no_internal_info(self):
        """decrypt 失败时不泄露内部异常信息。"""
        key = b'\x00' * 32
        # 使用正确前缀但无效数据
        with pytest.raises(ValueError) as exc_info:
            EncryptionEngine.decrypt("cb:AAAA", key, "aad")
        msg = str(exc_info.value)
        # 不应包含 Python 异常类型名
        assert "binascii" not in msg
        assert "Error" not in msg or "解密失败" in msg


class TestConstantTimeComparison:
    """恒定时间比较安全测试"""

    def test_constant_time_compare_correct_password(self):
        """验证正确密码的验证流程"""
        salt, verify_token, derived_key = MasterKeyManager.create('test_password')
        result = MasterKeyManager.verify('test_password', salt, verify_token)
        assert result is not None
        assert len(result) == 32  # 返回派生密钥

    def test_constant_time_compare_wrong_password(self):
        """验证错误密码返回 None"""
        salt, verify_token, derived_key = MasterKeyManager.create('test_password')
        result = MasterKeyManager.verify('wrong_password', salt, verify_token)
        assert result is None


if __name__ == '__main__':
    unittest.main()
