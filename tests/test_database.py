"""数据库模块测试"""

import tempfile
import unittest
from pathlib import Path

import pytest

from src.database.db_manager import DatabaseManager
from src.database.models import Category, CustomField, Entry


# TODO: 迁移到 conftest.py make_entry fixture（需将 unittest.TestCase 改为 pytest 风格）
def _make_entry(**kwargs) -> Entry:
    kwargs.setdefault('username', 'x')
    kwargs.setdefault('password', 'x')
    kwargs.setdefault('notes', '')
    kwargs.setdefault('custom_fields', '')
    return Entry(**kwargs)


@pytest.mark.usefixtures('_disable_encrypted_assertions')
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
        """测试搜索（search 参数已弃用，搜索由 EntryManager 在 Python 端执行）"""
        self._db.add_entry(_make_entry(title='GitHub 账号'))
        self._db.add_entry(_make_entry(title='Gitee 账号'))
        self._db.add_entry(_make_entry(title='Google 邮箱'))

        # search 参数已从 DB 层移除，返回全部条目
        results = self._db.get_entries()
        self.assertEqual(len(results), 3)

        # Python 端搜索由 EntryManager.get_entries 负责
        all_entries = self._db.get_entries()
        self.assertEqual(len(all_entries), 3)

    def test_entry_count(self):
        """测试条目计数"""
        initial = self._db.get_entry_count()
        self._db.add_entry(_make_entry(title='新条目'))
        self.assertEqual(self._db.get_entry_count(), initial + 1)

    def test_nested_transaction_savepoint(self):
        """嵌套事务使用带引号的 savepoint 标识符"""
        with self._db.transaction():
            self._db.set_meta('test_key', 'outer')
            with self._db.transaction():
                self._db.set_meta('test_key', 'inner')
            # Inner should be committed (released savepoint)
            self.assertEqual(self._db.get_meta('test_key'), 'inner')

        # After outer commit, value should still be inner
        self.assertEqual(self._db.get_meta('test_key'), 'inner')

    def test_get_all_tags_returns_only_tags(self):
        """get_all_tags 轻量查询只返回标签字段"""
        # Add entries with tags
        entry1 = _make_entry(title='A', tags='work,important')
        entry2 = _make_entry(title='B', tags='personal')
        entry3 = _make_entry(title='C', tags='')
        self._db.add_entry(entry1)
        self._db.add_entry(entry2)
        self._db.add_entry(entry3)

        tags_list = self._db.get_all_tags()
        self.assertIsInstance(tags_list, list)
        self.assertTrue(all(isinstance(t, str) for t in tags_list))
        self.assertEqual(len(tags_list), 3)
        # Verify specific tag values are present
        self.assertIn('work,important', tags_list)
        self.assertIn('personal', tags_list)

    def test_get_entries_with_limit(self):
        """get_entries limit 参数应限制返回数量"""
        for i in range(10):
            self._db.add_entry(_make_entry(title=f'条目{i}'))

        # 无 limit 返回全部
        all_entries = self._db.get_entries()
        self.assertEqual(len(all_entries), 10)

        # limit=3 只返回 3 条
        limited = self._db.get_entries(limit=3)
        self.assertEqual(len(limited), 3)

        # limit=0 返回空（SQL LIMIT 0）
        empty = self._db.get_entries(limit=0)
        self.assertEqual(len(empty), 0)

        # limit 大于总数时返回全部
        over = self._db.get_entries(limit=100)
        self.assertEqual(len(over), 10)


class TestModels(unittest.TestCase):
    """数据模型测试"""

    def test_entry_to_dict(self):
        entry = Entry(
            title='Test', username='user', password='pass',
            url='https://example.com', category_name='Test',
            tags='a,b', notes='note',
            custom_fields=[CustomField(name='key', value='val')],
        )
        d = entry.to_dict(include_password=True)
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
