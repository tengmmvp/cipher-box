"""数据库模块测试"""

import tempfile
from pathlib import Path

import pytest

from src.database.db_manager import DatabaseManager
from src.models import Category, CustomField, Entry


# TODO: 迁移到 conftest.py make_entry fixture
def _make_entry(**kwargs) -> Entry:
    kwargs.setdefault('username', 'x')
    kwargs.setdefault('password', 'x')
    kwargs.setdefault('notes', '')
    kwargs.setdefault('custom_fields', '')
    return Entry(**kwargs)


# ---------------------------------------------------------------------------
# Fixture: 创建临时数据库，关闭加密断言
# ---------------------------------------------------------------------------

@pytest.fixture
def db(_disable_encrypted_assertions):
    """创建一个临时数据库并初始化表结构。

    _disable_encrypted_assertions 来自 conftest.py，通过依赖注入自动激活。
    """
    tmp_dir = tempfile.mkdtemp()
    db_path = Path(tmp_dir) / 'test_vault.db'
    database = DatabaseManager(db_path)
    database.open()
    database.init_tables()
    yield database
    database.close()
    try:
        db_path.unlink(missing_ok=True)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# TestDatabaseManager
# ---------------------------------------------------------------------------

def test_init_tables(db):
    """测试表初始化"""
    categories = db.get_categories()
    assert len(categories) > 0
    names = [c.name for c in categories]
    assert '未分类' in names


def test_meta_operations(db):
    """测试元数据读写"""
    db.set_meta('test_key', 'test_value')
    value = db.get_meta('test_key')
    assert value == 'test_value'

    value_none = db.get_meta('nonexistent')
    assert value_none is None


def test_add_get_category(db):
    """测试添加和获取分类"""
    cat = Category(name='测试分类', icon_char='🧪', color='#FF0000')
    cat_id = db.add_category(cat)
    assert cat_id > 0

    retrieved = db.get_category(cat_id)
    assert retrieved is not None
    assert retrieved.name == '测试分类'
    assert retrieved.icon_char == '🧪'


def test_add_get_entry(db):
    """测试添加和获取条目"""
    entry = _make_entry(
        title='测试条目',
        username='enc_user',
        password='enc_pwd',
        url='https://example.com',
        tags='test,demo',
        notes='enc_notes',
        custom_fields='enc_fields',
        is_favorite=True,
        password_strength=3,
    )
    entry_id = db.add_entry(entry)
    assert entry_id > 0

    retrieved = db.get_entry(entry_id)
    assert retrieved is not None
    assert retrieved.title == '测试条目'
    assert retrieved.url == 'https://example.com'
    assert retrieved.is_favorite


def test_soft_delete_restore(db):
    """测试软删除和恢复"""
    entry = _make_entry(title='待删除')
    entry_id = db.add_entry(entry)

    # 软删除
    db.soft_delete_entry(entry_id)
    deleted = db.get_entry(entry_id)
    assert deleted.is_deleted

    # 正常列表不包含
    active = db.get_entries(include_deleted=False)
    assert not any(e.id == entry_id for e in active)

    # 回收站包含
    trashed = db.get_entries(include_deleted=True)
    assert any(e.id == entry_id for e in trashed)

    # 恢复
    db.restore_entry(entry_id)
    restored = db.get_entry(entry_id)
    assert not restored.is_deleted


def test_permanent_delete(db):
    """测试永久删除"""
    entry = _make_entry(title='永久删除')
    entry_id = db.add_entry(entry)

    db.permanent_delete_entry(entry_id)
    retrieved = db.get_entry(entry_id)
    assert retrieved is None


def test_search(db):
    """测试搜索（search 参数已弃用，搜索由 EntryManager 在 Python 端执行）"""
    db.add_entry(_make_entry(title='GitHub 账号'))
    db.add_entry(_make_entry(title='Gitee 账号'))
    db.add_entry(_make_entry(title='Google 邮箱'))

    # search 参数已从 DB 层移除，返回全部条目
    results = db.get_entries()
    assert len(results) == 3

    # Python 端搜索由 EntryManager.get_entries 负责
    all_entries = db.get_entries()
    assert len(all_entries) == 3


def test_entry_count(db):
    """测试条目计数"""
    initial = db.get_entry_count()
    db.add_entry(_make_entry(title='新条目'))
    assert db.get_entry_count() == initial + 1


def test_nested_transaction_savepoint(db):
    """嵌套事务使用带引号的 savepoint 标识符"""
    with db.transaction():
        db.set_meta('test_key', 'outer')
        with db.transaction():
            db.set_meta('test_key', 'inner')
        # Inner should be committed (released savepoint)
        assert db.get_meta('test_key') == 'inner'

    # After outer commit, value should still be inner
    assert db.get_meta('test_key') == 'inner'


def test_get_all_tags_returns_only_tags(db):
    """get_all_tags 轻量查询只返回标签字段"""
    # Add entries with tags
    entry1 = _make_entry(title='A', tags='work,important')
    entry2 = _make_entry(title='B', tags='personal')
    entry3 = _make_entry(title='C', tags='')
    db.add_entry(entry1)
    db.add_entry(entry2)
    db.add_entry(entry3)

    tags_list = db.get_all_tags()
    assert isinstance(tags_list, list)
    assert all(isinstance(t, str) for t in tags_list)
    assert len(tags_list) == 3
    # Verify specific tag values are present
    assert 'work,important' in tags_list
    assert 'personal' in tags_list


def test_get_entries_with_limit(db):
    """get_entries limit 参数应限制返回数量"""
    for i in range(10):
        db.add_entry(_make_entry(title=f'条目{i}'))

    # 无 limit 返回全部
    all_entries = db.get_entries()
    assert len(all_entries) == 10

    # limit=3 只返回 3 条
    limited = db.get_entries(limit=3)
    assert len(limited) == 3

    # limit=0 返回空（SQL LIMIT 0）
    empty = db.get_entries(limit=0)
    assert len(empty) == 0

    # limit 大于总数时返回全部
    over = db.get_entries(limit=100)
    assert len(over) == 10


# ---------------------------------------------------------------------------
# TestModels
# ---------------------------------------------------------------------------

def test_entry_to_dict():
    entry = Entry(
        title='Test', username='user', password='pass',
        url='https://example.com', category_name='Test',
        tags='a,b', notes='note',
        custom_fields=[CustomField(name='key', value='val')],
    )
    d = entry.to_dict(include_password=True)
    assert d['title'] == 'Test'
    assert d['password'] == 'pass'

    d_no_pwd = entry.to_dict(include_password=False)
    assert 'password' not in d_no_pwd


def test_entry_from_dict():
    d = {
        'title': 'Test',
        'username': 'user',
        'password': 'pass',
        'url': 'https://example.com',
        'category': 'Test',
        'custom_fields': [{'name': 'key', 'value': 'val', 'field_type': 'text'}],
    }
    entry = Entry.from_dict(d)
    assert entry.title == 'Test'
    assert len(entry.custom_fields) == 1


def test_entry_tag_list():
    entry = Entry(tags='a, b, c')
    assert entry.get_tag_list() == ['a', 'b', 'c']

    entry2 = Entry(tags='')
    assert entry2.get_tag_list() == []
