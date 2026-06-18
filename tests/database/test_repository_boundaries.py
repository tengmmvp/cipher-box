"""Repository 边界测试：密码历史截断与批量 ID 查询分页。

覆盖此前仅被间接路径触及的边界：add_password_history 截断到 MAX_PASSWORD_HISTORY
（off-by-one）、get_entries_by_ids 在 ID 数超过 SQLite 主机变量上限时的分批查询。
"""

import tempfile
from pathlib import Path

import pytest

from src.database import entry_repository
from src.database.db_manager import DatabaseManager
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
    _db = DatabaseManager(_db_path)
    _db.open()
    _db.init_tables()
    yield _db
    _db.close()
    try:
        _db_path.unlink(missing_ok=True)
    except Exception:
        pass


@pytest.mark.usefixtures('_disable_encrypted_assertions')
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


@pytest.mark.usefixtures('_disable_encrypted_assertions')
def test_get_entries_by_ids_batches_large_id_lists(db, monkeypatch):
    """ID 数超过 _ID_BATCH_SIZE 时分批查询，全部返回且无错位/无遗漏。"""
    monkeypatch.setattr(entry_repository, '_ID_BATCH_SIZE', 2)
    ids = [db.add_entry(_make_entry(title=f'E{i}')) for i in range(5)]
    fetched = db.get_entries_by_ids(ids)
    assert {e.id for e in fetched} == set(ids)
