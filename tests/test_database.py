"""数据库模块测试"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.database.db_manager import DatabaseManager
from src.database.models import Category, Entry, CustomField


def _make_entry(**kwargs) -> Entry:
    """创建测试用 Entry（确保 custom_fields 为字符串）"""
    kwargs.setdefault('username', 'x')
    kwargs.setdefault('password', 'x')
    kwargs.setdefault('notes', '')
    kwargs.setdefault('custom_fields', '')
    return Entry(**kwargs)


class TestDatabaseManager(unittest.TestCase):
    """数据库管理器测试"""

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

    def test_init_tables(self):
        """测试表初始化"""
        categories = self._db.get_categories()
        self.assertTrue(len(categories) > 0)
        names = [c.name for c in categories]
        self.assertIn('未分类', names)

    def test_meta_operations(self):
        """测试元数据读写"""
        self._db.set_meta('test_key', 'test_value')
        value = self._db.get_meta('test_key')
        self.assertEqual(value, 'test_value')

        value_none = self._db.get_meta('nonexistent')
        self.assertIsNone(value_none)

    def test_add_get_category(self):
        """测试添加和获取分类"""
        cat = Category(name='测试分类', icon_char='🧪', color='#FF0000')
        cat_id = self._db.add_category(cat)
        self.assertGreater(cat_id, 0)

        retrieved = self._db.get_category(cat_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.name, '测试分类')
        self.assertEqual(retrieved.icon_char, '🧪')

    def test_add_get_entry(self):
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
        entry_id = self._db.add_entry(entry)
        self.assertGreater(entry_id, 0)

        retrieved = self._db.get_entry(entry_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.title, '测试条目')
        self.assertEqual(retrieved.url, 'https://example.com')
        self.assertTrue(retrieved.is_favorite)

    def test_soft_delete_restore(self):
        """测试软删除和恢复"""
        entry = _make_entry(title='待删除')
        entry_id = self._db.add_entry(entry)

        # 软删除
        self._db.soft_delete_entry(entry_id)
        deleted = self._db.get_entry(entry_id)
        self.assertTrue(deleted.is_deleted)

        # 正常列表不包含
        active = self._db.get_entries(include_deleted=False)
        self.assertFalse(any(e.id == entry_id for e in active))

        # 回收站包含
        trashed = self._db.get_entries(include_deleted=True)
        self.assertTrue(any(e.id == entry_id for e in trashed))

        # 恢复
        self._db.restore_entry(entry_id)
        restored = self._db.get_entry(entry_id)
        self.assertFalse(restored.is_deleted)

    def test_permanent_delete(self):
        """测试永久删除"""
        entry = _make_entry(title='永久删除')
        entry_id = self._db.add_entry(entry)

        self._db.permanent_delete_entry(entry_id)
        retrieved = self._db.get_entry(entry_id)
        self.assertIsNone(retrieved)

    def test_search(self):
        """测试搜索"""
        self._db.add_entry(_make_entry(title='GitHub 账号'))
        self._db.add_entry(_make_entry(title='Gitee 账号'))
        self._db.add_entry(_make_entry(title='Google 邮箱'))

        results = self._db.get_entries(search='Git')
        self.assertEqual(len(results), 2)

        results = self._db.get_entries(search='Google')
        self.assertEqual(len(results), 1)

    def test_entry_count(self):
        """测试条目计数"""
        initial = self._db.get_entry_count()
        self._db.add_entry(_make_entry(title='新条目'))
        self.assertEqual(self._db.get_entry_count(), initial + 1)


class TestModels(unittest.TestCase):
    """数据模型测试"""

    def test_entry_to_dict(self):
        entry = Entry(
            title='Test', username='user', password='pass',
            url='https://example.com', category_name='Test',
            tags='a,b', notes='note',
            custom_fields=[CustomField(name='key', value='val')],
        )
        d = entry.to_dict()
        self.assertEqual(d['title'], 'Test')
        self.assertEqual(d['password'], 'pass')

        d_no_pwd = entry.to_dict(include_password=False)
        self.assertNotIn('password', d_no_pwd)

    def test_entry_from_dict(self):
        d = {
            'title': 'Test',
            'username': 'user',
            'password': 'pass',
            'url': 'https://example.com',
            'category': 'Test',
            'custom_fields': [{'name': 'key', 'value': 'val', 'field_type': 'text'}],
        }
        entry = Entry.from_dict(d)
        self.assertEqual(entry.title, 'Test')
        self.assertEqual(len(entry.custom_fields), 1)

    def test_entry_tag_list(self):
        entry = Entry(tags='a, b, c')
        self.assertEqual(entry.get_tag_list(), ['a', 'b', 'c'])

        entry2 = Entry(tags='')
        self.assertEqual(entry2.get_tag_list(), [])


if __name__ == '__main__':
    unittest.main()
