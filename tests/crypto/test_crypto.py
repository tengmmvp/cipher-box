"""加密模块测试。

覆盖 EncryptionEngine 的 AES-256-GCM 加解密、MasterKeyManager 的主密码
派生与验证、PasswordGenerator 的生成与强度评估，以及 AESGCM 缓存行为、
常量时间比较等边界场景。
"""

import os

import pytest

from src.crypto.encryption import EncryptionEngine
from src.crypto.master_key import KdfParams, MasterKeyManager
from src.crypto.password_generator import PasswordGenerator
from src.exceptions import DecryptionError

AAD = "test:secret"


def test_encrypt_decrypt():
    key = os.urandom(32)
    plaintext = "Hello, CipherBox!"
    encrypted = EncryptionEngine.encrypt(plaintext, key, AAD)
    assert encrypted != plaintext
    decrypted = EncryptionEngine.decrypt(encrypted, key, AAD)
    assert decrypted == plaintext


def test_empty_string():
    key = os.urandom(32)
    # 空明文仍走完整加密路径，确保 AAD 参与认证。
    encrypted = EncryptionEngine.encrypt("", key, AAD)
    assert encrypted != ""
    assert encrypted.startswith(EncryptionEngine.TEXT_PREFIX)
    decrypted = EncryptionEngine.decrypt(encrypted, key, AAD)
    assert decrypted == ""
    with pytest.raises(ValueError):
        EncryptionEngine.decrypt("", key, AAD)


def test_unicode():
    key = os.urandom(32)
    plaintext = "中文密码测试 <SEC> emojis <JOY>"
    encrypted = EncryptionEngine.encrypt(plaintext, key, AAD)
    decrypted = EncryptionEngine.decrypt(encrypted, key, AAD)
    assert decrypted == plaintext


def test_wrong_key_fails():
    key1 = os.urandom(32)
    key2 = os.urandom(32)
    encrypted = EncryptionEngine.encrypt("secret", key1, AAD)
    with pytest.raises(ValueError):
        EncryptionEngine.decrypt(encrypted, key2, AAD)


def test_different_encryptions():
    """相同明文两次加密结果应不同，因为每次使用随机 nonce。"""
    key = os.urandom(32)
    enc1 = EncryptionEngine.encrypt("same text", key, AAD)
    enc2 = EncryptionEngine.encrypt("same text", key, AAD)
    assert enc1 != enc2


def test_encrypt_decrypt_bytes():
    key = os.urandom(32)
    data = b"binary data test"
    encrypted = EncryptionEngine.encrypt_bytes(data, key, AAD)
    decrypted = EncryptionEngine.decrypt_bytes(encrypted, key, AAD)
    assert decrypted == data


def test_rejects_ciphertext_without_current_prefix():
    key = os.urandom(32)
    with pytest.raises(ValueError):
        EncryptionEngine.decrypt("AAAA", key, AAD)
    with pytest.raises(ValueError):
        EncryptionEngine.decrypt_bytes(b"legacy", key, AAD)


def test_create_and_verify():
    salt, verify_token, derived_key = MasterKeyManager.create("test_password_123")
    assert salt is not None
    assert verify_token is not None
    assert len(salt) == 32

    key = MasterKeyManager.verify("test_password_123", salt, verify_token)
    assert key is not None
    assert len(key) == 32


def test_wrong_password():
    salt, verify_token, _ = MasterKeyManager.create("correct_password")
    key = MasterKeyManager.verify("wrong_password", salt, verify_token)
    assert key is None


def test_change_password():
    old_salt, old_verify, _ = MasterKeyManager.create("old_password")
    result = MasterKeyManager.change_password("old_password", "new_password", old_salt, old_verify)
    assert result is not None
    new_salt, new_verify, new_key = result
    # change_password 返回复用 create 已派生的 new_key，调用方无需
    # 重复一次 Argon2id 派生即可得到 32 字节 AES-256 密钥。
    assert len(new_key) == 32

    # 新密码应能验证。
    key = MasterKeyManager.verify("new_password", new_salt, new_verify)
    assert key is not None

    # 旧密码不应能验证。
    key = MasterKeyManager.verify("old_password", new_salt, new_verify)
    assert key is None


def test_change_wrong_old_password():
    old_salt, old_verify, _ = MasterKeyManager.create("real_password")
    result = MasterKeyManager.change_password(
        "wrong_password", "new_password", old_salt, old_verify
    )
    assert result is None


def test_password_unicode_normalization() -> None:
    """NFC 与 NFD 形式的同一视觉密码派生出相同密钥（归一化守护）。

    未归一化时 NFC/NFD 的 UTF-8 字节不同 → Argon2id 派生不同密钥 → 跨归一化输入
    （便携备份跨 OS 恢复、不同 IME/输入法）致不可恢复锁库。编码前统一 NFC 后，
    NFD 密码应能验证 NFC 创建的验证令牌。
    """
    salt, verify_token, _ = MasterKeyManager.create("café")  # NFC 形式
    nfd_password = "café"  # NFD（e + 组合重音），视觉同「café」但码点序列不同
    assert nfd_password != "café"  # 归一化前字符串确不相等
    key = MasterKeyManager.verify(nfd_password, salt, verify_token)
    assert key is not None  # NFD 密码能验证 NFC 令牌（归一化拉齐派生）


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
    result = PasswordGenerator.check_strength("MyStr0ng!P@ssw0rd#2024")
    assert result.score >= 3


def test_strength_weak():
    result = PasswordGenerator.check_strength("123456")
    assert result.score <= 1
    assert result.is_common


def test_strength_long_sequential_runway_detected():
    """长顺序串（≥6 连续 ASCII 步长）判为常见弱密码。

    回归守护：原连续模式用 ``$`` 锚定仅精确匹配 6 字符，15 字符纯顺序串漏检。
    """
    result = PasswordGenerator.check_strength("abcdefghijklmno")
    assert result.is_common


def test_strength_long_keyboard_runway_detected():
    """长键盘走查串（≥6 连续 QWERTY 行字符）判为常见弱密码。"""
    result = PasswordGenerator.check_strength("qwertyuiopasdf")
    assert result.is_common


@pytest.mark.parametrize(
    "pwd",
    [
        "poiuytrewqasdfg",  # 顶行反向（qwertyuiop 反转）
        "lkjhgfdsaqwerty",  # 中行反向（asdfghjkl 反转）
        "mnbvcxzqwertyui",  # 底行反向（zxcvbnm 反转）
    ],
)
def test_strength_reverse_keyboard_runway_detected(pwd):
    """反向键盘走查串（≥6 连续反向 QWERTY）判为常见弱密码。

    回归守护：原 ``_has_keyboard_runway`` 仅正向匹配，反向串漏检。覆盖三行
    （顶 qwertyuiop / 中 asdfghjkl / 底 zxcvbnm）反向，确保 ``_has_keyboard_runway``
    对 ``(row, row[::-1])`` 双向遍历三行均对称生效。
    """
    assert PasswordGenerator.check_strength(pwd).is_common


def test_strength_empty():
    result = PasswordGenerator.check_strength("")
    assert result.score == 0


def test_strength_feedback():
    result = PasswordGenerator.check_strength("abc")
    assert len(result.feedback) > 0


def test_exclude_ambiguous():
    pwd = PasswordGenerator.generate(length=100, exclude_ambiguous=True)
    ambiguous = set("Il1O0o")
    assert not any(c in ambiguous for c in pwd)


def test_encrypt_empty_string_no_aad():
    """空明文仍走完整加密路径，AAD 参与认证。"""
    result = EncryptionEngine.encrypt("", b"\x00" * 32, "any_aad")
    assert result != ""
    assert result.startswith(EncryptionEngine.TEXT_PREFIX)
    decrypted = EncryptionEngine.decrypt(result, b"\x00" * 32, "any_aad")
    assert decrypted == ""


def test_decrypt_empty_string_raises():
    """空密文是非法输入，应抛出 ValueError。"""
    with pytest.raises(ValueError):
        EncryptionEngine.decrypt("", b"\x00" * 32, "any_aad")


@pytest.fixture(autouse=True)
def _clear_aesgcm_cache():
    EncryptionEngine.clear_cache()
    yield
    EncryptionEngine.clear_cache()


def test_same_key_reuses_cipher():
    """相同密钥应复用同一 AESGCM 实例。"""
    key = os.urandom(32)
    c1 = EncryptionEngine._get_cipher(key)
    c2 = EncryptionEngine._get_cipher(key)
    assert c1 is c2


def test_different_key_creates_new_cipher():
    """不同密钥应创建不同的 AESGCM 实例。"""
    key1 = os.urandom(32)
    key2 = os.urandom(32)
    c1 = EncryptionEngine._get_cipher(key1)
    c2 = EncryptionEngine._get_cipher(key2)
    assert c1 is not c2


def test_cache_cleared_on_lock():
    """缓存清除后旧条目不再命中。"""
    key = os.urandom(32)
    c1 = EncryptionEngine._get_cipher(key)
    EncryptionEngine.clear_cache()
    c2 = EncryptionEngine._get_cipher(key)
    assert c1 is not c2


def test_cache_hit_after_encrypt():
    """加密后再次获取同一 key 的 cipher 应命中缓存。"""
    key = os.urandom(32)
    EncryptionEngine.encrypt("test data", key, "aad")
    cached = EncryptionEngine._get_cipher(key)
    c = EncryptionEngine._get_cipher(key)
    assert c is cached


def test_encrypt_decrypt_with_cached_cipher():
    """缓存 cipher 正确完成加解密。"""
    key = os.urandom(32)
    plaintext = "cache test 测试"
    encrypted = EncryptionEngine.encrypt(plaintext, key, "aad")
    decrypted = EncryptionEngine.decrypt(encrypted, key, "aad")
    assert decrypted == plaintext


def test_cache_respects_max_size():
    """_cipher_cache 不超过 _MAX_CACHE_SIZE，超限 LRU 淘汰最旧。

    A6：缓存降容收缩崩溃 dump 攻击面（AESGCM 内含 C 层 key schedule 副本），
    容量上限须有测试守护，防止后续误调大。
    """
    from src.crypto.encryption import _MAX_CACHE_SIZE, _cipher_cache

    # 用 _MAX_CACHE_SIZE + 3 个不同 key 各获取 cipher，触发 LRU 淘汰
    keys = [bytes([i]) + b"\x00" * 31 for i in range(_MAX_CACHE_SIZE + 3)]
    for key in keys:
        EncryptionEngine._get_cipher(key)
    assert len(_cipher_cache) == _MAX_CACHE_SIZE


def test_cache_key_false_skips_cache_all_methods():
    """cache_key=False 时 encrypt/decrypt/encrypt_bytes/decrypt_bytes 均不入缓存（SEC-046）。

    一次性密钥（share 包/备份密码派生密钥）调用后即 secure_zero，但缓存 AESGCM 持
    C 层密钥拷贝、清零不可达——须保证 cache_key=False 路径完全不触碰 _cipher_cache。
    以调用前后缓存快照逐项对比（含已存在条目的场景：非空缓存不被污染）。
    """
    from src.crypto.encryption import _cipher_cache

    # 预置一个缓存条目：验证「不新增」而非仅「缓存为空」
    warm_key = os.urandom(32)
    EncryptionEngine.encrypt("warm", warm_key, "aad")
    snapshot = dict(_cipher_cache)

    key = os.urandom(32)
    ct = EncryptionEngine.encrypt("payload", key, "aad", cache_key=False)
    blob = EncryptionEngine.encrypt_bytes(b"payload", key, "aad", cache_key=False)
    assert dict(_cipher_cache) == snapshot

    assert EncryptionEngine.decrypt(ct, key, "aad", cache_key=False) == "payload"
    assert EncryptionEngine.decrypt_bytes(blob, key, "aad", cache_key=False) == b"payload"
    assert dict(_cipher_cache) == snapshot


def test_get_cipher_cache_key_false_not_cached():
    """_get_cipher(cache_key=False) 直接构造 AESGCM，不写入/命中缓存（SEC-046）。"""
    from src.crypto.encryption import _cipher_cache

    key = os.urandom(32)
    snapshot = dict(_cipher_cache)

    c1 = EncryptionEngine._get_cipher(key, cache_key=False)
    c2 = EncryptionEngine._get_cipher(key, cache_key=False)

    assert dict(_cipher_cache) == snapshot
    assert c1 is not c2  # 每次直接构造，不走缓存复用


def test_decrypt_bytes_wrong_prefix():
    """decrypt_bytes 拒绝错误前缀。"""
    with pytest.raises(ValueError, match="不支持的密文字节格式"):
        EncryptionEngine.decrypt_bytes(b"WRONG" + b"\x00" * 28, b"\x00" * 32, "aad")


def test_decrypt_bytes_too_short():
    """decrypt_bytes 拒绝过短密文。"""
    with pytest.raises(ValueError, match="密文长度无效"):
        EncryptionEngine.decrypt_bytes(b"CB2" + b"\x00" * 10, b"\x00" * 32, "aad")


def test_decrypt_generic_no_internal_info():
    """decrypt 失败时不泄露内部异常信息。"""
    key = b"\x00" * 32
    # 使用正确前缀但无效数据。
    with pytest.raises(ValueError) as exc_info:
        EncryptionEngine.decrypt("cb2:AAAA", key, "aad")
    msg = str(exc_info.value)
    # 不应包含 Python 异常类型名。
    assert "binascii" not in msg
    assert "Error" not in msg or "解密失败" in msg


def test_constant_time_compare_correct_password():
    """验证正确密码的验证流程。"""
    salt, verify_token, derived_key = MasterKeyManager.create("test_password")
    result = MasterKeyManager.verify("test_password", salt, verify_token)
    assert result is not None
    assert len(result) == 32  # 返回派生密钥


def test_constant_time_compare_wrong_password():
    """验证错误密码返回 None。"""
    salt, verify_token, derived_key = MasterKeyManager.create("test_password")
    result = MasterKeyManager.verify("wrong_password", salt, verify_token)
    assert result is None


# ======== AAD 认证绑定负向测试 ========


def test_decrypt_with_wrong_aad_raises():
    """encrypt(AAD1) → decrypt(AAD2) 必抛 DecryptionError（GCM 认证 AAD 绑定）。

    AES-GCM 的 AAD（附加认证数据）参与认证标签计算但不加密；解密时须提供完全一致
    的 AAD，否则认证失败。这是「字段级域分离」（entry:<crypto_id>:<field>）能防止
    密文跨字段重放的安全基础——字段域标签作为 AAD 绑定后，A 字段的密文无法在
    B 字段解密通过。
    """
    key = os.urandom(32)
    encrypted = EncryptionEngine.encrypt("secret", key, "aad-1")
    with pytest.raises(DecryptionError):
        EncryptionEngine.decrypt(encrypted, key, "aad-2")


def test_decrypt_bytes_with_wrong_aad_raises():
    """encrypt_bytes(AAD1) → decrypt_bytes(AAD2) 必抛 DecryptionError（字节路径对称）。"""
    key = os.urandom(32)
    encrypted = EncryptionEngine.encrypt_bytes(b"data", key, b"aad-1")
    with pytest.raises(DecryptionError):
        EncryptionEngine.decrypt_bytes(encrypted, key, b"aad-2")


def test_decrypt_with_correct_aad_succeeds():
    """正对照：相同 AAD 加解密正常（AAD 绑定不破坏合法路径）。"""
    key = os.urandom(32)
    encrypted = EncryptionEngine.encrypt("secret", key, "same-aad")
    assert EncryptionEngine.decrypt(encrypted, key, "same-aad") == "secret"


def test_aad_empty_vs_nonempty_differ():
    """空 AAD 与非空 AAD 不可互换：encrypt('') → decrypt('x') 抛 DecryptionError。"""
    key = os.urandom(32)
    encrypted = EncryptionEngine.encrypt("secret", key, "")
    with pytest.raises(DecryptionError):
        EncryptionEngine.decrypt(encrypted, key, "non-empty")


@pytest.mark.parametrize("invalid_aad", [None, 123, 4.5, [], object()])
def test_aad_invalid_type_raises(invalid_aad: object) -> None:
    """None/int 等 AAD 抛 TypeError，而非静默按「无 AAD」加密（安全降级）。

    AESGCM 把 None 语义化为无 AAD；调用方误传时静默成功会丢失字段级域绑定，且
    不可见。``_aad_bytes`` 对非 str/bytes 显性失败，把调用方 bug 从静默降级转为报错。
    """
    key = os.urandom(32)
    with pytest.raises(TypeError):
        EncryptionEngine.encrypt("secret", key, invalid_aad)  # type: ignore[arg-type]


# ======== PasswordGenerator 每类字符≥1 保证 ========


def test_generate_includes_every_enabled_charset():
    """全类启用时，每种字符类至少出现一次（循环 50 次排除偶发）。

    PasswordGenerator 先从各类各取 1 字符再填充剩余，保证长度 ≥ 类数时每类 ≥1。
    此守护防止未来重构（如先填充再加类字符）破坏「每类必有」的不变量——后者会让
    短密码可能缺某类，削弱强度。
    """
    for _ in range(50):
        pwd = PasswordGenerator.generate(length=8)  # 默认全类启用
        assert any(c.isupper() for c in pwd), f"缺大写字母: {pwd!r}"
        assert any(c.islower() for c in pwd), f"缺小写字母: {pwd!r}"
        assert any(c.isdigit() for c in pwd), f"缺数字: {pwd!r}"
        assert any(not c.isalnum() for c in pwd), f"缺特殊字符: {pwd!r}"


def test_generate_min_length_4_satisfies_each_class():
    """length=4 恰好覆盖 4 类，每类恰好 1 字符（边界：长度==类数）。"""
    for _ in range(20):
        pwd = PasswordGenerator.generate(length=4)
        assert len(pwd) == 4
        assert any(c.isupper() for c in pwd)
        assert any(c.islower() for c in pwd)
        assert any(c.isdigit() for c in pwd)
        assert any(not c.isalnum() for c in pwd)


# ======== MasterKeyManager.validate_params MAX 边界 ========


def test_validate_params_accepts_upper_bounds():
    """上限值通过：time=10 / memory=1GB(1024*1024) / parallelism=16 均合法。

    validate_params 不派生（无 Argon2id 开销），仅范围校验；上界值须通过以兼容
    未来调参与高安全场景。
    """
    MasterKeyManager.validate_params(
        KdfParams(time_cost=10, memory_cost=1024 * 1024, parallelism=16)
    )


@pytest.mark.parametrize(
    "params",
    [
        KdfParams(time_cost=11, memory_cost=64 * 1024, parallelism=4),  # time 超上限
        KdfParams(time_cost=3, memory_cost=1024 * 1024 + 1, parallelism=4),  # memory 超 1GB
        KdfParams(time_cost=3, memory_cost=64 * 1024, parallelism=17),  # parallelism 超上限
    ],
)
def test_validate_params_rejects_above_max(params):
    """超上限的 KDF 参数被拒（防 vault_meta 篡改为异常值后静默接受降级/越界）。"""
    with pytest.raises(ValueError):
        MasterKeyManager.validate_params(params)


@pytest.mark.parametrize(
    "params",
    [
        KdfParams(time_cost=1, memory_cost=64 * 1024, parallelism=4),  # time 低于下限 2
        KdfParams(time_cost=3, memory_cost=16 * 1024 - 1, parallelism=4),  # memory 低于 16MB
        KdfParams(time_cost=3, memory_cost=64 * 1024, parallelism=0),  # parallelism 低于下限 1
    ],
)
def test_validate_params_rejects_below_min(params):
    """低于下限的参数被拒（防止静默降级到无保护强度）。"""
    with pytest.raises(ValueError):
        MasterKeyManager.validate_params(params)
