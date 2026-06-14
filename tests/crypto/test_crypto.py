"""加密模块测试。

覆盖 EncryptionEngine 的 AES-256-GCM 加解密、MasterKeyManager 的主密码
派生与验证、PasswordGenerator 的生成与强度评估，以及 AESGCM 缓存行为、
常量时间比较等边界场景。
"""

import os

import pytest

from src.crypto.encryption import EncryptionEngine
from src.crypto.master_key import MasterKeyManager
from src.crypto.password_generator import PasswordGenerator

# ---------------------------------------------------------------------------
# TestEncryptionEngine
# ---------------------------------------------------------------------------

AAD = 'test:secret'


def test_encrypt_decrypt():
    key = os.urandom(32)
    plaintext = 'Hello, CipherBox!'
    encrypted = EncryptionEngine.encrypt(plaintext, key, AAD)
    assert encrypted != plaintext
    decrypted = EncryptionEngine.decrypt(encrypted, key, AAD)
    assert decrypted == plaintext


def test_empty_string():
    key = os.urandom(32)
    # 空字符串走 sentinel 加密路径，确保 AAD 参与认证。
    encrypted = EncryptionEngine.encrypt('', key, AAD)
    assert encrypted != ''
    assert encrypted.startswith(EncryptionEngine.TEXT_PREFIX)
    decrypted = EncryptionEngine.decrypt(encrypted, key, AAD)
    assert decrypted == ''
    # 空密文是非法输入，应抛出 ValueError。
    with pytest.raises(ValueError):
        EncryptionEngine.decrypt('', key, AAD)


def test_unicode():
    key = os.urandom(32)
    plaintext = '中文密码测试 <SEC> emojis <JOY>'
    encrypted = EncryptionEngine.encrypt(plaintext, key, AAD)
    decrypted = EncryptionEngine.decrypt(encrypted, key, AAD)
    assert decrypted == plaintext


def test_wrong_key_fails():
    key1 = os.urandom(32)
    key2 = os.urandom(32)
    encrypted = EncryptionEngine.encrypt('secret', key1, AAD)
    with pytest.raises(ValueError):
        EncryptionEngine.decrypt(encrypted, key2, AAD)


def test_different_encryptions():
    """相同明文两次加密结果应不同，因为每次使用随机 nonce。"""
    key = os.urandom(32)
    enc1 = EncryptionEngine.encrypt('same text', key, AAD)
    enc2 = EncryptionEngine.encrypt('same text', key, AAD)
    assert enc1 != enc2


def test_encrypt_decrypt_bytes():
    key = os.urandom(32)
    data = b'binary data test'
    encrypted = EncryptionEngine.encrypt_bytes(data, key, AAD)
    decrypted = EncryptionEngine.decrypt_bytes(encrypted, key, AAD)
    assert decrypted == data


def test_rejects_ciphertext_without_current_prefix():
    key = os.urandom(32)
    with pytest.raises(ValueError):
        EncryptionEngine.decrypt('AAAA', key, AAD)
    with pytest.raises(ValueError):
        EncryptionEngine.decrypt_bytes(b'legacy', key, AAD)


# ---------------------------------------------------------------------------
# TestMasterKeyManager
# ---------------------------------------------------------------------------

def test_create_and_verify():
    salt, verify_token, derived_key = MasterKeyManager.create('test_password_123')
    assert salt is not None
    assert verify_token is not None
    assert len(salt) == 32

    key = MasterKeyManager.verify('test_password_123', salt, verify_token)
    assert key is not None
    assert len(key) == 32


def test_wrong_password():
    salt, verify_token, _ = MasterKeyManager.create('correct_password')
    key = MasterKeyManager.verify('wrong_password', salt, verify_token)
    assert key is None


def test_change_password():
    old_salt, old_verify, _ = MasterKeyManager.create('old_password')
    result = MasterKeyManager.change_password(
        'old_password', 'new_password', old_salt, old_verify
    )
    assert result is not None
    new_salt, new_verify, new_key = result
    # change_password 返回复用 create 已派生的 new_key，调用方无需
    # 重复一次 Argon2id 派生即可得到 32 字节 AES-256 密钥。
    assert len(new_key) == 32

    # 新密码应能验证。
    key = MasterKeyManager.verify('new_password', new_salt, new_verify)
    assert key is not None

    # 旧密码不应能验证。
    key = MasterKeyManager.verify('old_password', new_salt, new_verify)
    assert key is None


def test_change_wrong_old_password():
    old_salt, old_verify, _ = MasterKeyManager.create('real_password')
    result = MasterKeyManager.change_password(
        'wrong_password', 'new_password', old_salt, old_verify
    )
    assert result is None


# ---------------------------------------------------------------------------
# TestPasswordGenerator
# ---------------------------------------------------------------------------

def test_generate_default():
    pwd = PasswordGenerator.generate()
    assert len(pwd) == 16


def test_generate_custom_length():
    pwd = PasswordGenerator.generate(length=32)
    assert len(pwd) == 32


def test_generate_min_length():
    pwd = PasswordGenerator.generate(length=2)
    assert len(pwd) == 4  # 强制不低于最小长度 4


def test_generate_no_uppercase():
    pwd = PasswordGenerator.generate(length=50, uppercase=False)
    assert not any(c.isupper() for c in pwd)


def test_generate_no_digits():
    pwd = PasswordGenerator.generate(length=50, digits=False, symbols=False)
    assert not any(c.isdigit() for c in pwd)


def test_strength_strong():
    result = PasswordGenerator.check_strength('MyStr0ng!P@ssw0rd#2024')
    assert result.score >= 3


def test_strength_weak():
    result = PasswordGenerator.check_strength('123456')
    assert result.score <= 1
    assert result.is_common


def test_strength_empty():
    result = PasswordGenerator.check_strength('')
    assert result.score == 0


def test_strength_feedback():
    result = PasswordGenerator.check_strength('abc')
    assert len(result.feedback) > 0


def test_exclude_ambiguous():
    pwd = PasswordGenerator.generate(length=100, exclude_ambiguous=True)
    ambiguous = set('Il1O0o')
    assert not any(c in ambiguous for c in pwd)


# ---------------------------------------------------------------------------
# TestEncryptionEdgeCases
# ---------------------------------------------------------------------------

def test_encrypt_empty_string_no_aad():
    """空字符串现在通过 sentinel 加密，AAD 参与认证。"""
    result = EncryptionEngine.encrypt("", b'\x00' * 32, "any_aad")
    assert result != ''
    assert result.startswith(EncryptionEngine.TEXT_PREFIX)
    # 解密后应返回空字符串
    decrypted = EncryptionEngine.decrypt(result, b'\x00' * 32, "any_aad")
    assert decrypted == ''


def test_decrypt_empty_string_raises():
    """空密文是非法输入，应抛出 ValueError。"""
    with pytest.raises(ValueError):
        EncryptionEngine.decrypt("", b'\x00' * 32, "any_aad")


# ---------------------------------------------------------------------------
# TestAESGCMCache
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _clear_aesgcm_cache():
    EncryptionEngine.clear_cache()
    yield
    EncryptionEngine.clear_cache()


def test_same_key_reuses_cipher():
    """相同密钥应复用同一 AESGCM 实例"""
    key = os.urandom(32)
    c1 = EncryptionEngine._get_cipher(key)
    c2 = EncryptionEngine._get_cipher(key)
    assert c1 is c2


def test_different_key_creates_new_cipher():
    """不同密钥应创建不同的 AESGCM 实例"""
    key1 = os.urandom(32)
    key2 = os.urandom(32)
    c1 = EncryptionEngine._get_cipher(key1)
    c2 = EncryptionEngine._get_cipher(key2)
    assert c1 is not c2


def test_cache_cleared_on_lock():
    """缓存清除后旧条目不再命中"""
    key = os.urandom(32)
    c1 = EncryptionEngine._get_cipher(key)
    EncryptionEngine.clear_cache()
    c2 = EncryptionEngine._get_cipher(key)
    assert c1 is not c2


def test_cache_hit_after_encrypt():
    """加密后再次获取同一 key 的 cipher 应命中缓存"""
    key = os.urandom(32)
    EncryptionEngine.encrypt('test data', key, 'aad')
    cached = EncryptionEngine._get_cipher(key)
    c = EncryptionEngine._get_cipher(key)
    assert c is cached


def test_encrypt_decrypt_with_cached_cipher():
    """缓存 cipher 正确完成加解密"""
    key = os.urandom(32)
    plaintext = 'cache test 测试'
    encrypted = EncryptionEngine.encrypt(plaintext, key, 'aad')
    decrypted = EncryptionEngine.decrypt(encrypted, key, 'aad')
    assert decrypted == plaintext


def test_decrypt_bytes_wrong_prefix():
    """decrypt_bytes 拒绝错误前缀。"""
    with pytest.raises(ValueError, match='不支持的密文字节格式'):
        EncryptionEngine.decrypt_bytes(b"WRONG" + b'\x00' * 28, b'\x00' * 32, "aad")


def test_decrypt_bytes_too_short():
    """decrypt_bytes 拒绝过短密文。"""
    with pytest.raises(ValueError, match='密文长度无效'):
        EncryptionEngine.decrypt_bytes(b"CBX" + b'\x00' * 10, b'\x00' * 32, "aad")


def test_decrypt_generic_no_internal_info():
    """decrypt 失败时不泄露内部异常信息。"""
    key = b'\x00' * 32
    # 使用正确前缀但无效数据。
    with pytest.raises(ValueError) as exc_info:
        EncryptionEngine.decrypt("cb:AAAA", key, "aad")
    msg = str(exc_info.value)
    # 不应包含 Python 异常类型名。
    assert "binascii" not in msg
    assert "Error" not in msg or "解密失败" in msg


# ---------------------------------------------------------------------------
# TestConstantTimeComparison
# ---------------------------------------------------------------------------

def test_constant_time_compare_correct_password():
    """验证正确密码的验证流程"""
    salt, verify_token, derived_key = MasterKeyManager.create('test_password')
    result = MasterKeyManager.verify('test_password', salt, verify_token)
    assert result is not None
    assert len(result) == 32  # 返回派生密钥


def test_constant_time_compare_wrong_password():
    """验证错误密码返回 None"""
    salt, verify_token, derived_key = MasterKeyManager.create('test_password')
    result = MasterKeyManager.verify('wrong_password', salt, verify_token)
    assert result is None
