"""加密模块测试"""

import os
import sys
import unittest

# 确保项目根目录在路径中
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

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
        self.assertEqual(EncryptionEngine.encrypt('', key, self.AAD), '')
        self.assertEqual(EncryptionEngine.decrypt('', key, self.AAD), '')

    def test_unicode(self):
        key = os.urandom(32)
        plaintext = '中文密码测试 🔐 émojis 🎉'
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
        salt, verify_token = MasterKeyManager.create('test_password_123')
        self.assertIsNotNone(salt)
        self.assertIsNotNone(verify_token)
        self.assertEqual(len(salt), 32)

        key = MasterKeyManager.verify('test_password_123', salt, verify_token)
        self.assertIsNotNone(key)
        self.assertEqual(len(key), 32)

    def test_wrong_password(self):
        salt, verify_token = MasterKeyManager.create('correct_password')
        key = MasterKeyManager.verify('wrong_password', salt, verify_token)
        self.assertIsNone(key)

    def test_change_password(self):
        old_salt, old_verify = MasterKeyManager.create('old_password')
        result = MasterKeyManager.change_password(
            'old_password', 'new_password', old_salt, old_verify
        )
        self.assertIsNotNone(result)
        new_salt, new_verify, _old_key = result

        # 新密码应能验证
        key = MasterKeyManager.verify('new_password', new_salt, new_verify)
        self.assertIsNotNone(key)

        # 旧密码不应能验证
        key = MasterKeyManager.verify('old_password', new_salt, new_verify)
        self.assertIsNone(key)

    def test_change_wrong_old_password(self):
        old_salt, old_verify = MasterKeyManager.create('real_password')
        result = MasterKeyManager.change_password(
            'wrong_password', 'new_password', old_salt, old_verify
        )
        self.assertIsNone(result)


class TestPasswordGenerator(unittest.TestCase):
    """密码生成器测试"""

    def test_generate_default(self):
        pwd = PasswordGenerator.generate()
        self.assertEqual(len(pwd), 16)
        self.assertTrue(len(pwd) >= 16)

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


if __name__ == '__main__':
    unittest.main()
