"""新功能测试。

覆盖 TOTP 生成与校验、条目类型常量与图标、密码历史的增删与上限排序、
数据库固定格式标识存储、entry_type 列落库，以及分类的条目计数与删除级联行为。
"""

import pytest

from src.crypto.totp import TOTPGenerator
from src.database.db_manager import DatabaseManager
from src.models import ENTRY_TYPE_LOGIN, ENTRY_TYPES, Category, Entry, RawEntry


def _make_entry(**kwargs) -> RawEntry:
    kwargs.setdefault('password', 'x')
    kwargs.setdefault('notes', '')
    kwargs.setdefault('custom_fields', '')
    return RawEntry(**kwargs)


# --- TestTOTP ---


def test_generate_valid_secret(monkeypatch):
    """RFC 6238 测试向量：固定 T=59 断言 6 位验证码 287082。"""
    # 完整 20 字节密钥 "12345678901234567890" 的 Base32 编码。
    # 截断的 10 字节密钥无法匹配 RFC 向量，此前仅断言长度的测试无效。
    secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
    monkeypatch.setattr('src.crypto.totp.time.time', lambda: 59)
    code = TOTPGenerator.generate(secret)
    assert code == '287082'


def test_generate_empty_secret():
    assert TOTPGenerator.generate('') == ''


def test_generate_invalid_secret():
    assert TOTPGenerator.generate('!!!invalid!!!') == ''


def test_remaining_seconds():
    remaining = TOTPGenerator.get_remaining_seconds()
    assert remaining > 0
    assert remaining <= 30


def test_validate_secret_valid():
    assert TOTPGenerator.validate_secret('JBSWY3DPEHPK3PXP')


def test_validate_secret_invalid():
    assert not TOTPGenerator.validate_secret('')
    assert not TOTPGenerator.validate_secret('!!!')


def test_two_codes_same_period():
    secret = 'JBSWY3DPEHPK3PXP'
    code1 = TOTPGenerator.generate(secret)
    code2 = TOTPGenerator.generate(secret)
    assert code1 == code2


# --- TestRawEntryTypes ---


def test_entry_type_constants():
    assert 'login' in ENTRY_TYPES
    assert 'card' in ENTRY_TYPES
    assert 'identity' in ENTRY_TYPES
    assert 'note' in ENTRY_TYPES
    assert 'server' in ENTRY_TYPES


def test_entry_type_icon():
    entry = RawEntry(title='Test', entry_type='card')
    assert entry.type_icon == '[CARD]'
    assert entry.type_label == '信用卡'


def test_entry_default_type():
    entry = RawEntry(title='Test')
    assert entry.entry_type == ENTRY_TYPE_LOGIN
    assert entry.type_icon == '[KEY]'


def test_has_totp():
    entry1 = RawEntry(title='A', totp_secret='')
    assert not entry1.has_totp

    entry2 = RawEntry(title='B', totp_secret='JBSWY3DPEHPK3PXP')
    assert entry2.has_totp


def test_entry_to_dict_with_type():
    entry = Entry(title='Test', entry_type='server', totp_secret='SECRET')
    d = entry.to_dict(include_password=True)
    assert d['entry_type'] == 'server'
    assert d['totp_secret'] == 'SECRET'

    d_no_pwd = entry.to_dict(include_password=False)
    assert 'totp_secret' not in d_no_pwd


# --- TestPasswordHistory ---


@pytest.fixture
def db_history(tmp_path):
    """创建一个临时数据库并初始化表结构，供密码历史测试使用。"""
    _db_path = tmp_path / 'test_vault.db'
    _db = DatabaseManager(_db_path, test_mode=True)
    _db.open()
    _db.init_tables()
    yield _db
    _db.close()


def test_add_password_history(db_history):
    entry = _make_entry(title='Test')
    entry_id = db_history.add_entry(entry)

    db_history.add_password_history(entry_id, 'old_encrypted_pwd_1')
    db_history.add_password_history(entry_id, 'old_encrypted_pwd_2')

    history = db_history.get_password_history(entry_id)
    assert len(history) == 2


def test_password_history_limit(db_history):
    """密码历史最多保留 10 条。"""
    entry = _make_entry(title='Test')
    entry_id = db_history.add_entry(entry)

    for i in range(15):
        db_history.add_password_history(entry_id, f'old_pwd_{i}')

    history = db_history.get_password_history(entry_id)
    assert len(history) == 10


def test_password_history_order(db_history):
    """密码历史按时间倒序排列。"""
    entry = _make_entry(title='Test')
    entry_id = db_history.add_entry(entry)

    db_history.add_password_history(entry_id, 'first')
    db_history.add_password_history(entry_id, 'second')

    history = db_history.get_password_history(entry_id)
    assert history[0].old_password_enc == 'second'
    assert history[1].old_password_enc == 'first'


# --- TestDatabaseFormat ---


def test_schema_format_stored(tmp_path):
    """数据库保存固定格式标识。"""
    db_path = tmp_path / 'test.db'
    db = DatabaseManager(db_path, test_mode=True)
    db.open()
    db.init_tables()

    schema_format = db.get_meta('schema_format')
    assert schema_format == 'cipherbox-schema'
    db.close()


def test_entry_type_column(tmp_path):
    """新条目落库后保留 entry_type 与 totp_secret 字段。"""
    db_path = tmp_path / 'test.db'
    db = DatabaseManager(db_path, test_mode=True)
    db.open()
    db.init_tables()

    entry = _make_entry(title='Typed', entry_type='server', totp_secret='SECRET')
    entry_id = db.add_entry(entry)

    retrieved = db.get_entry(entry_id)
    assert retrieved is not None
    assert retrieved.entry_type == 'server'
    assert retrieved.totp_secret == 'SECRET'
    db.close()


# --- TestCategoryManagement ---


@pytest.fixture
def db_category(tmp_path):
    """创建一个临时数据库并初始化表结构，供分类管理测试使用。"""
    _db_path = tmp_path / 'test.db'
    _db = DatabaseManager(_db_path, test_mode=True)
    _db.open()
    _db.init_tables()
    yield _db
    _db.close()


def test_get_category_entry_count(db_category):
    categories = db_category.get_categories()
    cat = categories[0]  # 未分类
    count = db_category.get_category_entry_count(cat.id)
    assert count == 0

    entry = _make_entry(title='Test', category_id=cat.id)
    db_category.add_entry(entry)
    count = db_category.get_category_entry_count(cat.id)
    assert count == 1


def test_delete_category_nullifies_entries(db_category):
    """删除分类后，该分类下条目的 category_id 被置空。"""
    cat = Category(name='临时分类', icon_char='🔧', color='#FF0000')
    cat_id = db_category.add_category(cat)

    entry = _make_entry(title='Test', category_id=cat_id)
    entry_id = db_category.add_entry(entry)

    db_category.delete_category(cat_id)
    retrieved = db_category.get_entry(entry_id)
    assert retrieved.category_id is None
