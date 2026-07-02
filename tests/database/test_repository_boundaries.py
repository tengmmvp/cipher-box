"""Repository 边界测试：密码历史截断与批量 ID 查询分页。

覆盖此前仅被间接路径触及的边界：add_password_history 截断到 MAX_PASSWORD_HISTORY
（off-by-one）、get_entries_by_ids 在 ID 数超过 SQLite 主机变量上限时的分批查询。
"""

import tempfile
from pathlib import Path

import pytest

from src.database import entry_repository
from src.database.db_manager import DatabaseManager
from src.database.types import EntryQuery
from src.exceptions import DatabaseError
from src.models import MAX_PASSWORD_HISTORY, RawEntry


def _make_entry(**kwargs) -> RawEntry:
    kwargs.setdefault('password', 'x')
    kwargs.setdefault('notes', '')
    kwargs.setdefault('custom_fields', '')
    return RawEntry(**kwargs)


@pytest.fixture
def db():
    _tmp_dir = tempfile.mkdtemp()
    _db_path = Path(_tmp_dir) / 'test_boundary.db'
    _db = DatabaseManager(_db_path, test_mode=True)
    _db.open()
    _db.init_tables()
    yield _db
    _db.close()
    try:
        _db_path.unlink(missing_ok=True)
    except Exception:
        pass


def test_password_history_truncated_to_max(db):
    """密码历史超过 MAX_PASSWORD_HISTORY 时截断为最新 N 条（off-by-one 边界）。"""
    entry = _make_entry(title='Truncated')
    entry_id = db.add_entry(entry)
    total = MAX_PASSWORD_HISTORY + 3
    for i in range(total):
        db.add_password_history(entry_id, f'enc_{i}', f't{i:04d}')
    history = db.get_password_history(entry_id)
    assert len(history) == MAX_PASSWORD_HISTORY
    # 按 changed_at DESC，最新（i 最大）排在首位
    assert history[0].old_password_enc == f'enc_{total - 1}'


def test_get_entries_by_ids_batches_large_id_lists(db, monkeypatch):
    """ID 数超过 _ID_BATCH_SIZE 时分批查询，全部返回且无错位/无遗漏。"""
    monkeypatch.setattr(entry_repository, '_ID_BATCH_SIZE', 2)
    ids = [db.add_entry(_make_entry(title=f'E{i}')) for i in range(5)]
    fetched = db.get_entries_by_ids(ids)
    assert {e.id for e in fetched} == set(ids)


def test_add_entry_converts_crypto_id_conflict_to_database_error(db):
    """crypto_id UNIQUE 冲突归一化为 DatabaseError，避免裸 sqlite3.IntegrityError 上泄。"""
    db.add_entry(_make_entry(crypto_id='dup-id', title='First'))
    duplicate = _make_entry(crypto_id='dup-id', title='Second')
    with pytest.raises(DatabaseError, match='唯一约束'):
        db.add_entry(duplicate)


def test_update_entries_batch_noop_on_empty(db):
    """空列表短路：不执行 SQL、不抛异常（改密重加密无变更条目的边界）。"""
    db.update_entries_batch([])  # 不应抛异常


def test_get_entries_by_ids_returns_empty_for_empty_input(db):
    """空 ID 列表短路返回 []，避免构造 IN () 非法 SQL。"""
    assert db.get_entries_by_ids([]) == []


def test_get_entries_by_ids_deduplicates_preserving_order(db):
    """dict.fromkeys 去重保序：重复 id 不导致行数膨胀或位置错位。"""
    id1 = db.add_entry(_make_entry(crypto_id='c1', title='A'))
    id2 = db.add_entry(_make_entry(crypto_id='c2', title='B'))
    fetched = db.get_entries_by_ids([id1, id2, id1, id2])
    assert [e.id for e in fetched] == [id1, id2]


def test_get_entries_after_id_cursor_paginates(db):
    """after_id 游标分页：返回 id > after_id 的条目，按 id ASC，LIMIT 下推 SQL。"""
    ids = [db.add_entry(_make_entry(crypto_id=f'c{i}', title=f'E{i}')) for i in range(5)]
    page = db.get_entries(EntryQuery(after_id=ids[1], limit=2))
    assert [e.id for e in page] == ids[2:4]
