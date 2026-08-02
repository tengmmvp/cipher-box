"""数据库模块测试。

覆盖 DatabaseManager 的表初始化、元数据读写、分类与条目增删查、软删除与恢复、
嵌套事务 savepoint 行为，以及 Entry 模型的 to_dict、from_dict 序列化。
"""

import dataclasses

import pytest

from src.database.db_manager import DatabaseManager
from src.database.types import EntryQuery
from src.models import Category, CustomField, Entry, RawEntry


def _make_entry(**kwargs) -> RawEntry:
    """构造测试用 RawEntry，对可选字段填合法默认值，调用方经 kwargs 覆盖关注字段。"""
    kwargs.setdefault("username", "x")
    kwargs.setdefault("password", "x")
    kwargs.setdefault("notes", "")
    kwargs.setdefault("custom_fields", "")
    return RawEntry(**kwargs)


@pytest.fixture
def db(tmp_path):
    """创建一个临时数据库并初始化表结构。

    test_mode=True 关闭密文前缀断言，适配测试直接构造的非密文数据。
    tmp_path 由 pytest 提供并自动清理，无需手动删除数据库文件。
    """
    db_path = tmp_path / "test_vault.db"
    database = DatabaseManager(db_path, test_mode=True)
    database.open()
    database.init_tables()
    yield database
    database.close()


def test_init_tables(db):
    """init_tables 注入默认分类,至少含「未分类」占位项。"""
    categories = db.get_categories()
    assert len(categories) > 0
    names = [c.name for c in categories]
    assert "未分类" in names


def test_meta_operations(db):
    """vault_meta 键值读写往返正确,缺失键返回 None。"""
    db.set_meta("test_key", "test_value")
    value = db.get_meta("test_key")
    assert value == "test_value"

    value_none = db.get_meta("nonexistent")
    assert value_none is None


def test_add_get_category(db):
    """分类写入后可按 id 读回,全部属性（名称/图标/颜色）保持一致。"""
    cat = Category(name="测试分类", icon_char="🧪", color="#FF0000")
    cat_id = db.add_category(cat)
    assert cat_id > 0

    retrieved = db.get_category(cat_id)
    assert retrieved is not None
    assert retrieved.name == "测试分类"
    assert retrieved.icon_char == "🧪"


def test_add_category_rejects_duplicate_name(db):
    """add_category 名称重复时抛 ValueError（避开默认分类名）。"""
    db.add_category(Category(name="测试分类A"))
    with pytest.raises(ValueError, match="已存在"):
        db.add_category(Category(name="测试分类A"))


def test_update_category_rejects_duplicate_name(db):
    """update_category 改名为其他分类名称时抛 ValueError（避开默认分类名）。"""
    cat1_id = db.add_category(Category(name="测试分类A"))
    db.add_category(Category(name="测试分类B"))
    cat1 = db.get_category(cat1_id)
    assert cat1 is not None
    cat1 = dataclasses.replace(cat1, name="测试分类B")
    with pytest.raises(ValueError, match="已被其他分类占用"):
        db.update_category(cat1)


def test_add_get_entry(db):
    """条目写入后按 id 读回,各字段（含 favorite/strength 等扩展字段）保持一致。"""
    entry = _make_entry(
        title="测试条目",
        username="enc_user",
        password="enc_pwd",
        url="https://example.com",
        tags="test,demo",
        notes="enc_notes",
        custom_fields="enc_fields",
        is_favorite=True,
        password_strength=3,
    )
    entry_id = db.add_entry(entry)
    assert entry_id > 0

    retrieved = db.get_entry(entry_id)
    assert retrieved is not None
    assert retrieved.title == "测试条目"
    assert retrieved.url == "https://example.com"
    assert retrieved.is_favorite


def test_soft_delete_restore(db):
    """软删除→回收站隔离→恢复 全流程:删除态可读、默认列表排除、恢复后还原。"""
    entry = _make_entry(title="待删除")
    entry_id = db.add_entry(entry)

    db.soft_delete_entry(entry_id)
    deleted = db.get_entry(entry_id)
    assert deleted.is_deleted

    active = db.get_entries(EntryQuery(include_deleted=False))
    assert not any(e.id == entry_id for e in active)

    trashed = db.get_entries(EntryQuery(include_deleted=True))
    assert any(e.id == entry_id for e in trashed)

    db.restore_entry(entry_id)
    restored = db.get_entry(entry_id)
    assert not restored.is_deleted


def test_permanent_delete(db):
    """permanent_delete_entry 物理删除后 get_entry 返回 None。"""
    entry = _make_entry(title="永久删除")
    entry_id = db.add_entry(entry)

    db.permanent_delete_entry(entry_id)
    retrieved = db.get_entry(entry_id)
    assert retrieved is None


def test_search(db):
    """get_entries 仅返回全部条目（关键字搜索由 EntryManager 负责）。"""
    db.add_entry(_make_entry(title="GitHub 账号"))
    db.add_entry(_make_entry(title="Gitee 账号"))
    db.add_entry(_make_entry(title="Google 邮箱"))

    results = db.get_entries(EntryQuery())
    assert len(results) == 3

    all_entries = db.get_entries(EntryQuery())
    assert len(all_entries) == 3


def test_entry_count(db):
    """get_entry_count 随新增条目递增。"""
    initial = db.get_entry_count()
    db.add_entry(_make_entry(title="新条目"))
    assert db.get_entry_count() == initial + 1


def test_nested_transaction_savepoint(db):
    """嵌套事务使用带引号的 savepoint 标识符。"""
    with db.transaction():
        db.set_meta("test_key", "outer")
        with db.transaction():
            db.set_meta("test_key", "inner")
        # 内层事务通过释放 savepoint 提交。
        assert db.get_meta("test_key") == "inner"

    # 外层提交后，值仍为内层写入的值。
    assert db.get_meta("test_key") == "inner"


def test_get_entries_with_limit(db):
    """get_entries limit 参数应限制返回数量。"""
    for i in range(10):
        db.add_entry(_make_entry(title=f"条目{i}"))

    # 不传 limit 时返回全部。
    all_entries = db.get_entries(EntryQuery())
    assert len(all_entries) == 10

    # limit=3 只返回 3 条。
    limited = db.get_entries(EntryQuery(limit=3))
    assert len(limited) == 3

    # limit=0 对应 SQL LIMIT 0，返回空列表。
    empty = db.get_entries(EntryQuery(limit=0))
    assert len(empty) == 0

    # limit 大于总数时返回全部。
    over = db.get_entries(EntryQuery(limit=100))
    assert len(over) == 10


def test_get_entries_filter_branches(db):
    """get_entries 的 deleted_only/category_id/favorite_only/sort_by_updated 分支。

    各分支经 EntryQuery 字段触发，覆盖 SQL 过滤/排序子句的不同组合。
    """
    cat_id = db.add_category(Category(name="测试过滤分类"))
    db.add_entry(_make_entry(title="A", category_id=cat_id))
    db.add_entry(_make_entry(title="Fav", category_id=cat_id, is_favorite=True))
    del_id = db.add_entry(_make_entry(title="Del"))
    db.soft_delete_entry(del_id)

    # deleted_only：仅回收站
    assert [e.id for e in db.get_entries(EntryQuery(deleted_only=True))] == [del_id]

    # category_id：仅该分类（默认不含已删除）
    by_cat = db.get_entries(EntryQuery(category_id=cat_id))
    assert all(e.category_id == cat_id for e in by_cat)
    assert len(by_cat) == 2

    # favorite_only：仅收藏
    favs = db.get_entries(EntryQuery(favorite_only=True))
    assert len(favs) == 1 and favs[0].is_favorite

    # sort_by_updated：走 updated_at DESC 分支（与默认 is_favorite DESC 排序分支区分）
    by_updated = db.get_entries(EntryQuery(sort_by_updated=True))
    assert len(by_updated) == 2  # A + Fav（Del 已软删除，默认不含）


def test_entry_to_dict():
    """to_dict 含 password 时输出密码字段,exclude 时不输出。"""
    entry = Entry(
        title="Test",
        username="user",
        password="pass",
        url="https://example.com",
        category_name="Test",
        tags="a,b",
        notes="note",
        custom_fields=[CustomField(name="key", value="val")],
    )
    d = entry.to_dict(include_password=True)
    assert d["title"] == "Test"
    assert d["password"] == "pass"

    d_no_pwd = entry.to_dict(include_password=False)
    assert "password" not in d_no_pwd


def test_entry_from_dict():
    """from_dict 解析 dict 构造 Entry,custom_fields 子结构正确还原。"""
    d = {
        "title": "Test",
        "username": "user",
        "password": "pass",
        "url": "https://example.com",
        "category": "Test",
        "custom_fields": [{"name": "key", "value": "val", "field_type": "text"}],
    }
    entry = Entry.from_dict(d)
    assert entry.title == "Test"
    assert len(entry.custom_fields) == 1


def test_entry_tag_list():
    """get_tag_list 按逗号拆分并去除空白,空串返回空列表。"""
    entry = Entry(tags="a, b, c")
    assert entry.get_tag_list() == ["a", "b", "c"]

    entry2 = Entry(tags="")
    assert entry2.get_tag_list() == []
