"""copy_entry_fields 与 build_entry_summary 工具函数测试。

验证 copy_entry_fields 的字段复制与覆盖行为，以及
build_entry_summary 生成的摘要条目不包含敏感字段。
"""

import dataclasses

from src.business.services.crypto_utils import build_entry_summary, copy_entry_fields
from src.models import RawEntry


# 本辅助函数设置密文态 RawEntry（custom_fields 为密文 str），与 conftest.py 的
# make_entry fixture（明文 Entry）不同，用于测试 RawEntry → Entry 的转换。
def _make_entry(**kwargs) -> RawEntry:
    kwargs.setdefault('id', 1)
    kwargs.setdefault('crypto_id', 'abc123')
    kwargs.setdefault('title', 'Test')
    kwargs.setdefault('username', 'user')
    kwargs.setdefault('password', 'pass')
    kwargs.setdefault('url', 'https://example.com')
    kwargs.setdefault('category_id', None)
    kwargs.setdefault('category_name', '')
    kwargs.setdefault('tags', '')
    kwargs.setdefault('notes', 'note')
    kwargs.setdefault('custom_fields', '')
    kwargs.setdefault('is_favorite', False)
    kwargs.setdefault('is_deleted', False)
    kwargs.setdefault('password_strength', 2)
    kwargs.setdefault('entry_type', 'login')
    kwargs.setdefault('totp_secret', '')
    kwargs.setdefault('created_at', '2024-01-01')
    kwargs.setdefault('updated_at', '2024-01-01')
    kwargs.setdefault('deleted_at', '')
    kwargs.setdefault('password_changed_at', '')
    return RawEntry(**kwargs)


class TestCopyEntryFields:
    """验证 copy_entry_fields 复制和覆盖行为。"""

    def test_copies_all_fields_by_default(self):
        raw = _make_entry()
        result = copy_entry_fields(raw)
        assert result.id == raw.id
        assert result.crypto_id == raw.crypto_id
        assert result.title == raw.title
        assert result.username == raw.username
        assert result.password == raw.password
        assert result.url == raw.url
        assert result.notes == raw.notes
        assert result.totp_secret == raw.totp_secret
        assert result.password_strength == raw.password_strength
        assert result.is_favorite == raw.is_favorite

    def test_overrides_specified_fields(self):
        raw = _make_entry(title='Original', username='old_user')
        result = copy_entry_fields(raw, title='New', username='new_user')
        assert result.title == 'New'
        assert result.username == 'new_user'
        # 未覆盖的字段保持原值
        assert result.id == raw.id
        assert result.password == raw.password

    def test_overrides_multiple_fields(self):
        raw = _make_entry(password='secret', notes='hidden', totp_secret='key')
        result = copy_entry_fields(raw, password='', notes='', totp_secret='')
        assert result.password == ''
        assert result.notes == ''
        assert result.totp_secret == ''


class TestBuildEntrySummary:
    """验证 build_entry_summary 不包含敏感字段。"""

    def test_summary_has_empty_sensitive_fields(self):
        raw = _make_entry(
            password='cb2:FIFSED/encrypted',
            notes='cb2:FIFSED/encrypted_notes',
            totp_secret='cb2:FIFSED/encrypted_totp',
            custom_fields='cb2:FIFSED/encrypted_fields',
        )
        summary = build_entry_summary(raw, username='decrypted_user')
        assert summary.password == ''
        assert summary.notes == ''
        assert summary.totp_secret == ''
        assert summary.custom_fields == []

    def test_summary_preserves_non_sensitive_fields(self):
        raw = _make_entry(
            title='My Entry',
            url='https://example.com',
            is_favorite=True,
            password_strength=3,
            entry_type='server',
        )
        summary = build_entry_summary(raw, username='user1')
        assert summary.title == 'My Entry'
        assert summary.url == 'https://example.com'
        assert summary.is_favorite is True
        assert summary.password_strength == 3
        assert summary.entry_type == 'server'
        assert summary.username == 'user1'

    def test_summary_default_username(self):
        raw = _make_entry(username='cb2:FIFSED/encrypted')
        summary = build_entry_summary(raw)
        assert summary.username == ''

    def test_summary_is_independent_copy(self):
        raw = _make_entry(title='Original')
        summary = build_entry_summary(raw, username='test')
        dataclasses.replace(summary, title='Modified')
        assert raw.title == 'Original'
