"""get_password_history_count 轻量查询测试"""

import tempfile
import unittest
from pathlib import Path

import pytest

from src.database.db_manager import DatabaseManager
from src.database.models import Entry


# TODO: 迁移到 conftest.py make_entry fixture（需将 unittest.TestCase 改为 pytest 风格）
def _make_entry(**kwargs) -> Entry:
    kwargs.setdefault('password', 'x')
    kwargs.setdefault('notes', '')
    kwargs.setdefault('custom_fields', '')
    return Entry(**kwargs)


@pytest.mark.usefixtures('_disable_encrypted_assertions')
class TestPasswordHistoryCount(unittest.TestCase):
    """验证 get_password_history_count 正确计数"""

    def setUp(self):
        self._tmp_dir = tempfile.mkdtemp()
        self._db_path = Path(self._tmp_dir) / 'test_vault.db'
        self._db = DatabaseManager(self._db_path)
        self._db.open()
        self._db.init_tables()

    def tearDown(self):
        self._db.close()
        try:
            self._db_path.unlink(missing_ok=True)
        except Exception:
            pass

    def test_count_zero_when_no_history(self):
        entry = _make_entry(title='No History')
        entry_id = self._db.add_entry(entry)
        count = self._db.get_password_history_count(entry_id)
        self.assertEqual(count, 0)

    def test_count_after_adding_history(self):
        entry = _make_entry(title='With History')
        entry_id = self._db.add_entry(entry)
        self._db.add_password_history(entry_id, 'enc_pwd_1', '2024-01-01')
        self._db.add_password_history(entry_id, 'enc_pwd_2', '2024-02-01')
        self._db.add_password_history(entry_id, 'enc_pwd_3', '2024-03-01')
        count = self._db.get_password_history_count(entry_id)
        self.assertEqual(count, 3)

    def test_count_per_entry_isolation(self):
        e1 = _make_entry(title='Entry 1')
        e2 = _make_entry(title='Entry 2')
        e1_id = self._db.add_entry(e1)
        e2_id = self._db.add_entry(e2)
        self._db.add_password_history(e1_id, 'enc1', '2024-01-01')
        self._db.add_password_history(e1_id, 'enc2', '2024-02-01')
        self._db.add_password_history(e2_id, 'enc3', '2024-03-01')
        self.assertEqual(self._db.get_password_history_count(e1_id), 2)
        self.assertEqual(self._db.get_password_history_count(e2_id), 1)


if __name__ == '__main__':
    unittest.main()
