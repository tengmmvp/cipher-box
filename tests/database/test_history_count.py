"""get_password_history_count 轻量查询测试。

验证 DatabaseManager.get_password_history_count 的计数正确性与条目隔离性，
覆盖无历史记录、新增历史记录后计数，以及不同条目历史记录互不干扰的场景。
"""

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
    """创建一个临时数据库并初始化表结构，关闭加密断言。"""
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
    """条目无密码历史时计数为 0。"""
    entry = _make_entry(title='No History')
    entry_id = db.add_entry(entry)
    count = db.get_password_history_count(entry_id)
    assert count == 0


@pytest.mark.usefixtures('_disable_encrypted_assertions')
def test_count_after_adding_history(db):
    """添加历史记录后计数随记录数增长。"""
    entry = _make_entry(title='With History')
    entry_id = db.add_entry(entry)
    db.add_password_history(entry_id, 'enc_pwd_1', '2024-01-01')
    db.add_password_history(entry_id, 'enc_pwd_2', '2024-02-01')
    db.add_password_history(entry_id, 'enc_pwd_3', '2024-03-01')
    count = db.get_password_history_count(entry_id)
    assert count == 3


@pytest.mark.usefixtures('_disable_encrypted_assertions')
def test_count_per_entry_isolation(db):
    """不同条目的密码历史计数相互隔离。"""
    e1 = _make_entry(title='Entry 1')
    e2 = _make_entry(title='Entry 2')
    e1_id = db.add_entry(e1)
    e2_id = db.add_entry(e2)
    db.add_password_history(e1_id, 'enc1', '2024-01-01')
    db.add_password_history(e1_id, 'enc2', '2024-02-01')
    db.add_password_history(e2_id, 'enc3', '2024-03-01')
    assert db.get_password_history_count(e1_id) == 2
    assert db.get_password_history_count(e2_id) == 1
