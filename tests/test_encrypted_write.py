"""S7: 加密字段断言测试 — 验证 _assert_encrypted 在启用时正确拦截明文。"""

import pytest

from src.database.db_manager import DatabaseManager
from src.database.models import Entry


@pytest.fixture
def secure_db(tmp_path):
    """创建一个启用了加密断言的 DatabaseManager 实例。"""
    db = DatabaseManager(tmp_path / 'test.db')
    db.open()
    db.init_tables()
    # 显式启用加密断言（conftest 的 autouse fixture 在类级别禁用了，
    # 此处通过实例属性覆盖恢复启用）
    db._enforce_encrypted_fields = True
    yield db
    db.close()


def _make_encrypted_entry(**overrides):
    """构建一个带有 cb: 前缀密文的 Entry（模拟已加密状态）。

    注意：此函数硬编码了 Entry dataclass 的全部字段。Entry 模型新增字段时，
    此处的 defaults 字典必须同步更新，否则构造时会因缺少默认值而报错。
    """
    defaults = dict(
        id=None,
        crypto_id='test-crypto-id',
        title='Test',
        username='cb:encrypted',
        password='cb:encrypted',
        url='',
        category_id=None,
        tags='',
        notes='cb:encrypted',
        custom_fields_enc='cb:encrypted',
        custom_fields='cb:encrypted',
        is_favorite=False,
        is_deleted=False,
        password_strength=3,
        entry_type='login',
        totp_secret='cb:encrypted',
        created_at='',
        updated_at='',
        deleted_at='',
        password_changed_at='',
        metadata_mac='',
    )
    defaults.update(overrides)
    return Entry(**defaults)


def _make_plain_entry(**overrides):
    """构建一个明文字段的 Entry（模拟未加密状态）。"""
    defaults = dict(
        id=None,
        crypto_id='test-crypto-id',
        title='Test',
        username='plaintext_user',
        password='plaintext_pwd',
        url='',
        category_id=None,
        tags='',
        notes='',
        custom_fields_enc='',
        custom_fields='',
        is_favorite=False,
        is_deleted=False,
        password_strength=3,
        entry_type='login',
        totp_secret='',
        created_at='',
        updated_at='',
        deleted_at='',
        password_changed_at='',
        metadata_mac='',
    )
    defaults.update(overrides)
    return Entry(**defaults)


class TestEncryptedWriteAssertions:
    """验证 DatabaseManager._assert_encrypted 的拦截行为。"""

    def test_add_entry_rejects_plaintext_username(self, secure_db):
        """add_entry 应拒绝明文 username（缺少 cb: 前缀）。"""
        entry = _make_plain_entry(username='plaintext_user', password='cb:enc', notes='cb:enc')
        with pytest.raises(ValueError, match="未加密"):
            secure_db.add_entry(entry)

    def test_add_entry_rejects_plaintext_password(self, secure_db):
        """add_entry 应拒绝明文 password。"""
        entry = _make_plain_entry(username='cb:enc', password='plaintext_pwd', notes='cb:enc')
        with pytest.raises(ValueError, match="未加密"):
            secure_db.add_entry(entry)

    def test_add_entry_rejects_plaintext_notes(self, secure_db):
        """add_entry 应拒绝明文 notes。"""
        entry = _make_plain_entry(username='cb:enc', password='cb:enc', notes='secret notes')
        with pytest.raises(ValueError, match="未加密"):
            secure_db.add_entry(entry)

    def test_encrypted_entry_accepted(self, secure_db):
        """cb: 前缀的密文应被 _assert_encrypted 放行。"""
        entry = _make_encrypted_entry()
        # 不应抛出异常（密文写入由实际加密产生，此处仅验证断言放行）
        entry_id = secure_db.add_entry(entry)
        assert entry_id is not None
