"""get_password_history_count 轻量查询测试"""

import tempfile
from pathlib import Path

import pytest

from src.database.db_manager import DatabaseManager
from src.models import Entry


# TODO: 迁移到 conftest.py make_entry fixture
def _make_entry(**kwargs) -> Entry:
    kwargs.setdefault('password', 'x')
    kwargs.setdefault('notes', '')
    kwargs.setdefault('custom_fields', '')
    return Entry(**kwargs)


@pytest.fixture
def db():
    _tmp_dir = tempfile.mkdtemp()
    _db_path = Path(_tmp_dir) / 'test_vault.db'
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
def test_count_zero_when_no_history(db):
    entry = _make_entry(title='No History')
    entry_id = db.add_entry(entry)
    count = db.get_password_history_count(entry_id)
    assert count == 0


@pytest.mark.usefixtures('_disable_encrypted_assertions')
def test_count_after_adding_history(db):
    entry = _make_entry(title='With History')
    entry_id = db.add_entry(entry)
    db.add_password_history(entry_id, 'enc_pwd_1', '2024-01-01')
    db.add_password_history(entry_id, 'enc_pwd_2', '2024-02-01')
    db.add_password_history(entry_id, 'enc_pwd_3', '2024-03-01')
    count = db.get_password_history_count(entry_id)
    assert count == 3


@pytest.mark.usefixtures('_disable_encrypted_assertions')
def test_count_per_entry_isolation(db):
    e1 = _make_entry(title='Entry 1')
    e2 = _make_entry(title='Entry 2')
    e1_id = db.add_entry(e1)
    e2_id = db.add_entry(e2)
    db.add_password_history(e1_id, 'enc1', '2024-01-01')
    db.add_password_history(e1_id, 'enc2', '2024-02-01')
    db.add_password_history(e2_id, 'enc3', '2024-03-01')
    assert db.get_password_history_count(e1_id) == 2
    assert db.get_password_history_count(e2_id) == 1
