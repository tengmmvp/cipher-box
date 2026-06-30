"""crypto_utils 公共函数单元测试。

覆盖 encrypt_field 与 decrypt_field 的加密解密往返、strict 与容错模式、
matches_search 与 matches_tag 匹配逻辑、copy_entry_fields 与
build_entry_summary 字段处理、entry_aad 格式以及 require_vault_key
锁状态校验。
"""

import os
from typing import cast

import pytest

from src.business.managers.vault_manager import VaultManager
from src.business.services.crypto_utils import (
    build_entry_summary,
    copy_entry_fields,
    decrypt_field,
    encrypt_field,
    entry_aad,
    matches_search,
    matches_tag,
    require_vault_key,
)
from src.exceptions import DecryptionError, VaultLockedError
from src.models import CustomField, Entry, RawEntry


@pytest.fixture
def aes_key() -> bytes:
    """生成一个真实的 32 字节 AES-256 密钥。"""
    return os.urandom(32)


@pytest.fixture
def sample_entry() -> Entry:
    """返回一个通用的已解密 Entry 实例。"""
    return Entry(
        id=1,
        crypto_id='cid-001',
        title='GitHub',
        username='alice',
        password='s3cret!',
        url='https://github.com',
        tags='dev, coding',
        notes='my account',
        custom_fields=[CustomField(name='pin', value='1234')],
        entry_type='login',
        totp_secret='JBSWY3DPEHPK3PXP',
    )


@pytest.fixture
def raw_entry() -> RawEntry:
    """返回一个密文态 RawEntry 实例（加密字段为密文，custom_fields 为密文 str）。"""
    return RawEntry(
        id=1,
        crypto_id='cid-001',
        title='GitHub',
        username='cb2:encrypted',
        password='cb2:encrypted',
        url='https://github.com',
        tags='dev, coding',
        notes='cb2:encrypted',
        custom_fields='cb2:encrypted',
        entry_type='login',
        totp_secret='cb2:encrypted',
    )


class TestEncryptDecryptRoundTrip:
    """加密后解密应还原原文。"""

    def test_normal_text(self, aes_key):
        plain = 'Hello, CipherBox!'
        crypto_id = 'cid-roundtrip'
        ct = encrypt_field(plain, aes_key, crypto_id, 'title')
        assert isinstance(ct, str)
        assert ct != plain
        pt = decrypt_field(ct, aes_key, crypto_id, 'title')
        assert pt == plain

    def test_empty_string(self, aes_key):
        """空字符串经过加密-解密往返后仍为空字符串。"""
        ct = encrypt_field('', aes_key, 'cid-empty', 'notes')
        pt = decrypt_field(ct, aes_key, 'cid-empty', 'notes')
        assert pt == ''

    def test_unicode_content(self, aes_key):
        plain = '中文密码 🔐 éüñ'
        ct = encrypt_field(plain, aes_key, 'cid-uni', 'password')
        pt = decrypt_field(ct, aes_key, 'cid-uni', 'password')
        assert pt == plain

    def test_different_fields_produce_different_ciphertext(self, aes_key):
        """同一明文，不同字段名应产生不同密文，因 AAD 不同。"""
        crypto_id = 'cid-diff'
        ct1 = encrypt_field('same', aes_key, crypto_id, 'title')
        ct2 = encrypt_field('same', aes_key, crypto_id, 'username')
        assert ct1 != ct2


class TestDecryptFieldStrict:
    """strict=True 时无效密文应抛出 ValueError。"""

    def test_invalid_ciphertext_strict_raises(self, aes_key):
        with pytest.raises(ValueError):
            decrypt_field('not-valid-ciphertext', aes_key, 'cid-x', 'title', strict=True)

    def test_empty_ciphertext_strict_raises(self, aes_key):
        """空密文在 strict 模式下由 EncryptionEngine.decrypt 抛出 ValueError。"""
        # encrypt_field 对空串会加密哨兵值，此处直接传入无效字符串以触发 strict 路径
        with pytest.raises(ValueError):
            decrypt_field('cb2:!!!!', aes_key, 'cid-x', 'title', strict=True)

    def test_wrong_key_strict_raises(self, aes_key):
        wrong_key = os.urandom(32)
        ct = encrypt_field('secret', aes_key, 'cid-y', 'password')
        with pytest.raises(ValueError):
            decrypt_field(ct, wrong_key, 'cid-y', 'password', strict=True)


class TestDecryptFieldLenient:
    """strict=False 时无效密文应返回空字符串。"""

    def test_invalid_ciphertext_returns_empty(self, aes_key):
        result = decrypt_field('garbage', aes_key, 'cid-z', 'title')
        assert result == ''

    def test_wrong_key_returns_empty(self, aes_key):
        wrong_key = os.urandom(32)
        ct = encrypt_field('secret', aes_key, 'cid-w', 'password')
        result = decrypt_field(ct, wrong_key, 'cid-w', 'password')
        assert result == ''

    def test_empty_string_returns_empty(self, aes_key):
        """空密文字符串直接返回空，走兼容路径不做解密。"""
        result = decrypt_field('', aes_key, 'cid-e', 'title')
        assert result == ''


class TestMatchesSearch:
    """搜索匹配逻辑。"""

    def test_empty_query_matches_all(self, sample_entry):
        assert matches_search(sample_entry, '') is True

    def test_title_match(self, sample_entry):
        assert matches_search(sample_entry, 'GitHub') is True

    def test_title_case_insensitive(self, sample_entry):
        assert matches_search(sample_entry, 'github') is True
        assert matches_search(sample_entry, 'GITHUB') is True

    def test_username_match(self, sample_entry):
        assert matches_search(sample_entry, 'alice') is True

    def test_url_match(self, sample_entry):
        assert matches_search(sample_entry, 'github.com') is True

    def test_tags_match(self, sample_entry):
        assert matches_search(sample_entry, 'dev') is True
        assert matches_search(sample_entry, 'coding') is True

    def test_no_match(self, sample_entry):
        assert matches_search(sample_entry, 'nonexistent') is False

    def test_none_fields_no_crash(self):
        """title/username/url/tags 为 None 时不应崩溃。"""
        entry = Entry(title=cast(str, None), username=cast(str, None), url=cast(str, None), tags=cast(str, None))
        assert matches_search(entry, 'anything') is False
        assert matches_search(entry, '') is True


class TestMatchesTag:
    """标签匹配逻辑。"""

    def test_exact_match(self, sample_entry):
        assert matches_tag(sample_entry, 'dev') is True

    def test_case_insensitive(self, sample_entry):
        assert matches_tag(sample_entry, 'Dev') is True
        assert matches_tag(sample_entry, 'CODING') is True

    def test_empty_tag_matches_all(self, sample_entry):
        assert matches_tag(sample_entry, '') is True

    def test_no_match(self, sample_entry):
        assert matches_tag(sample_entry, 'nonexistent') is False

    def test_partial_tag_no_match(self, sample_entry):
        """标签是精确匹配，部分字符串不应匹配。"""
        assert matches_tag(sample_entry, 'cod') is False

    def test_multi_tag_partial_match(self):
        """多标签中只要有一个精确匹配即可。"""
        entry = Entry(tags='work, personal, social')
        assert matches_tag(entry, 'work') is True
        assert matches_tag(entry, 'personal') is True
        assert matches_tag(entry, 'social') is True
        assert matches_tag(entry, 'workpersonal') is False

    def test_none_tags(self):
        entry = Entry(tags=cast(str, None))
        assert matches_tag(entry, 'anything') is False
        assert matches_tag(entry, '') is True


class TestCopyEntryFields:
    """字段复制逻辑（密文态 RawEntry → 明文 Entry）。"""

    def test_basic_copy(self, raw_entry):
        copied = copy_entry_fields(raw_entry)
        assert copied.title == raw_entry.title
        assert copied.url == raw_entry.url
        assert copied is not raw_entry

    def test_override_specific_fields(self, raw_entry):
        copied = copy_entry_fields(raw_entry, title='New Title', username='bob')
        assert copied.title == 'New Title'
        assert copied.username == 'bob'
        assert copied.url == raw_entry.url

    def test_password_present_auto_set(self):
        """有密文密码时 password_present 自动为 True。"""
        raw = RawEntry(password='cb2:secret')
        copied = copy_entry_fields(raw)
        assert copied.password_present is True

    def test_password_present_false_when_empty(self):
        raw = RawEntry(password='')
        copied = copy_entry_fields(raw)
        assert copied.password_present is False

    def test_totp_present_auto_set(self):
        raw = RawEntry(totp_secret='cb2:JBSWY3DPEHPK3PXP')
        copied = copy_entry_fields(raw)
        assert copied.totp_present is True

    def test_totp_present_false_when_empty(self):
        raw = RawEntry(totp_secret='')
        copied = copy_entry_fields(raw)
        assert copied.totp_present is False

    def test_explicit_override_takes_precedence(self):
        """调用方显式提供 password_present 时应覆盖自动推断。"""
        raw = RawEntry(password='cb2:secret')
        copied = copy_entry_fields(raw, password_present=False)
        assert copied.password_present is False

    def test_custom_fields_override(self, raw_entry):
        """custom_fields 经 overrides 传入明文 list，正确设置到 Entry。"""
        fields = [CustomField(name='pin', value='1234')]
        copied = copy_entry_fields(raw_entry, custom_fields=fields)
        assert copied.custom_fields == fields


class TestBuildEntrySummary:
    """摘要 Entry 不含敏感字段。"""

    def test_sensitive_fields_cleared(self, raw_entry):
        summary = build_entry_summary(raw_entry)
        assert summary.password == ''
        assert summary.notes == ''
        assert summary.totp_secret == ''
        assert summary.custom_fields == []

    def test_username_default_empty(self, raw_entry):
        """不传 username 时默认为空字符串。"""
        summary = build_entry_summary(raw_entry)
        assert summary.username == ''

    def test_username_preserved_when_provided(self, raw_entry):
        summary = build_entry_summary(raw_entry, username='alice')
        assert summary.username == 'alice'

    def test_username_override(self, raw_entry):
        summary = build_entry_summary(raw_entry, username='override-user')
        assert summary.username == 'override-user'

    def test_non_sensitive_fields_preserved(self, raw_entry):
        summary = build_entry_summary(raw_entry)
        assert summary.title == raw_entry.title
        assert summary.url == raw_entry.url
        assert summary.tags == raw_entry.tags


class TestEntryAad:
    """AAD 字符串格式验证。"""

    def test_format(self):
        aad = entry_aad('cid-123', 'title')
        assert aad == 'entry:cid-123:title'

    def test_different_fields(self):
        a1 = entry_aad('cid-x', 'title')
        a2 = entry_aad('cid-x', 'username')
        assert a1 != a2

    def test_different_crypto_ids(self):
        a1 = entry_aad('cid-1', 'title')
        a2 = entry_aad('cid-2', 'title')
        assert a1 != a2


class TestRequireVaultKey:
    """保险库密钥获取。"""

    def test_returns_key_when_unlocked(self, aes_key):
        class FakeVaultManager:
            key = aes_key

        result = require_vault_key(cast(VaultManager, FakeVaultManager()))
        assert result == aes_key

    def test_raises_when_locked(self):
        class FakeVaultManager:
            key = None

        with pytest.raises(VaultLockedError):
            require_vault_key(cast(VaultManager, FakeVaultManager()))


class TestDecryptEntryToPortableDictStrict:
    """验证字段 strict 策略统一：任一加密字段损坏即抛 DecryptionError（不再返回 None）。"""

    def test_corrupt_notes_raises_decryption_error(self, aes_key):
        """notes 密文损坏时抛 DecryptionError，而非返回空 notes 的残缺字典。"""
        from src.business.services.crypto_utils import (
            decrypt_entry_to_portable_dict,
        )
        crypto_id = 'cid-bad-notes'
        raw = RawEntry(
            id=1, crypto_id=crypto_id,
            title=encrypt_field('Title', aes_key, crypto_id, 'title'),
            username=encrypt_field('user', aes_key, crypto_id, 'username'),
            password=encrypt_field('pwd', aes_key, crypto_id, 'password'),
            url=encrypt_field('url', aes_key, crypto_id, 'url'),
            tags=encrypt_field('t', aes_key, crypto_id, 'tags'),
            notes='cb2:invalidciphertext',  # 损坏的 notes 密文
            custom_fields='',
            totp_secret='',
        )
        with pytest.raises(DecryptionError):
            decrypt_entry_to_portable_dict(raw, aes_key, include_secrets=True)

    def test_corrupt_password_raises_decryption_error(self, aes_key):
        """password 密文损坏时抛 DecryptionError（统一 strict 后不再容错为空）。"""
        from src.business.services.crypto_utils import (
            decrypt_entry_to_portable_dict,
        )
        crypto_id = 'cid-bad-pwd'
        raw = RawEntry(
            id=1, crypto_id=crypto_id,
            title=encrypt_field('Title', aes_key, crypto_id, 'title'),
            username=encrypt_field('user', aes_key, crypto_id, 'username'),
            password='cb2:brokenpasswordcipher',
            url='', tags='', notes='', custom_fields='', totp_secret='',
        )
        with pytest.raises(DecryptionError):
            decrypt_entry_to_portable_dict(raw, aes_key, include_secrets=True)

    def test_all_valid_returns_full_dict(self, aes_key):
        """全部字段有效时返回完整字典，notes 正常解密。"""
        from src.business.services.crypto_utils import (
            decrypt_entry_to_portable_dict,
        )
        crypto_id = 'cid-ok'
        raw = RawEntry(
            id=1, crypto_id=crypto_id,
            title=encrypt_field('Title', aes_key, crypto_id, 'title'),
            username=encrypt_field('user', aes_key, crypto_id, 'username'),
            password=encrypt_field('pwd', aes_key, crypto_id, 'password'),
            url=encrypt_field('url', aes_key, crypto_id, 'url'),
            tags=encrypt_field('t', aes_key, crypto_id, 'tags'),
            notes=encrypt_field('secret-note', aes_key, crypto_id, 'notes'),
            custom_fields='',
            totp_secret='',
        )
        result = decrypt_entry_to_portable_dict(raw, aes_key, include_secrets=True)
        assert result is not None
        assert result['notes'] == 'secret-note'
        assert result['password'] == 'pwd'
