"""新功能测试 - TOTP、密码历史、条目类型、模型增强"""

import tempfile
import unittest
from pathlib import Path

import pytest

from src.crypto.totp import TOTPGenerator
from src.database.db_manager import DatabaseManager
from src.database.models import ENTRY_TYPE_LOGIN, ENTRY_TYPES, Category, Entry


# TODO: 迁移到 conftest.py make_entry fixture（需将 unittest.TestCase 改为 pytest 风格）
def _make_entry(**kwargs) -> Entry:
    kwargs.setdefault('password', 'x')
    kwargs.setdefault('notes', '')
    kwargs.setdefault('custom_fields', '')
    return Entry(**kwargs)


class TestTOTP(unittest.TestCase):
    """TOTP 验证码生成器测试"""

    def test_generate_valid_secret(self):
        """已知密钥生成验证码"""
        # RFC 6238 测试向量: SHA1 + 时间戳 59 → 287082
        secret = 'GEZDGNBVGY3TQOJQ'  # "12345678901234567890" 的 Base32
        code = TOTPGenerator.generate(secret)
        self.assertEqual(len(code), 6)
        self.assertTrue(code.isdigit())

    def test_generate_empty_secret(self):
        """空密钥返回空字符串"""
        self.assertEqual(TOTPGenerator.generate(''), '')

    def test_generate_invalid_secret(self):
        """无效密钥返回空字符串"""
        self.assertEqual(TOTPGenerator.generate('!!!invalid!!!'), '')

    def test_remaining_seconds(self):
        """剩余秒数在有效范围内"""
        remaining = TOTPGenerator.get_remaining_seconds()
        self.assertGreater(remaining, 0)
        self.assertLessEqual(remaining, 30)

    def test_validate_secret_valid(self):
        """验证合法 Base32 密钥"""
        self.assertTrue(TOTPGenerator.validate_secret('JBSWY3DPEHPK3PXP'))

    def test_validate_secret_invalid(self):
        """验证无效密钥"""
        self.assertFalse(TOTPGenerator.validate_secret(''))
        self.assertFalse(TOTPGenerator.validate_secret('!!!'))

    def test_two_codes_same_period(self):
        """同一时间步长生成的验证码相同"""
        secret = 'JBSWY3DPEHPK3PXP'
        code1 = TOTPGenerator.generate(secret)
        code2 = TOTPGenerator.generate(secret)
        self.assertEqual(code1, code2)


class TestEntryTypes(unittest.TestCase):
    """条目类型模型测试"""

    def test_entry_type_constants(self):
        """验证所有类型常量"""
        self.assertIn('login', ENTRY_TYPES)
        self.assertIn('card', ENTRY_TYPES)
        self.assertIn('identity', ENTRY_TYPES)
        self.assertIn('note', ENTRY_TYPES)
        self.assertIn('server', ENTRY_TYPES)

    def test_entry_type_icon(self):
        """条目类型图标"""
        entry = Entry(title='Test', entry_type='card')
        self.assertEqual(entry.type_icon, '[CARD]')
        self.assertEqual(entry.type_label, '信用卡')

    def test_entry_default_type(self):
        """默认类型为 login"""
        entry = Entry(title='Test')
        self.assertEqual(entry.entry_type, ENTRY_TYPE_LOGIN)
        self.assertEqual(entry.type_icon, '[KEY]')

    def test_has_totp(self):
        """TOTP 状态检测"""
        entry1 = Entry(title='A', totp_secret='')
        self.assertFalse(entry1.has_totp)

        entry2 = Entry(title='B', totp_secret='JBSWY3DPEHPK3PXP')
        self.assertTrue(entry2.has_totp)

    def test_entry_to_dict_with_type(self):
        """导出包含类型信息"""
        entry = Entry(title='Test', entry_type='server', totp_secret='SECRET')
        d = entry.to_dict(include_password=True)
        self.assertEqual(d['entry_type'], 'server')
        self.assertEqual(d['totp_secret'], 'SECRET')

        d_no_pwd = entry.to_dict(include_password=False)
        self.assertNotIn('totp_secret', d_no_pwd)


@pytest.mark.usefixtures('_disable_encrypted_assertions')
class TestPasswordHistory(unittest.TestCase):
    """密码历史功能测试"""

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

    def test_add_password_history(self):
        """添加密码历史记录"""
        entry = _make_entry(title='Test')
        entry_id = self._db.add_entry(entry)

        self._db.add_password_history(entry_id, 'old_encrypted_pwd_1')
        self._db.add_password_history(entry_id, 'old_encrypted_pwd_2')

        history = self._db.get_password_history(entry_id)
        self.assertEqual(len(history), 2)

    def test_password_history_limit(self):
        """密码历史最多 10 条"""
        entry = _make_entry(title='Test')
        entry_id = self._db.add_entry(entry)

        for i in range(15):
            self._db.add_password_history(entry_id, f'old_pwd_{i}')

        history = self._db.get_password_history(entry_id)
        self.assertEqual(len(history), 10)

    def test_password_history_order(self):
        """密码历史按时间倒序"""
        entry = _make_entry(title='Test')
        entry_id = self._db.add_entry(entry)

        self._db.add_password_history(entry_id, 'first')
        self._db.add_password_history(entry_id, 'second')

        history = self._db.get_password_history(entry_id)
        self.assertEqual(history[0].old_password_enc, 'second')
        self.assertEqual(history[1].old_password_enc, 'first')


@pytest.mark.usefixtures('_disable_encrypted_assertions')
class TestDatabaseFormat(unittest.TestCase):
    """数据库固定格式测试"""

    def test_schema_format_stored(self):
        """数据库保存固定格式标识"""
        tmp_dir = tempfile.mkdtemp()
        db_path = Path(tmp_dir) / 'test.db'
        db = DatabaseManager(db_path)
        db.open()
        db.init_tables()

        schema_format = db.get_meta('schema_format')
        self.assertEqual(schema_format, 'cipherbox-schema')
        db.close()
        db_path.unlink(missing_ok=True)

    def test_entry_type_column(self):
        """新条目有 entry_type 字段"""
        tmp_dir = tempfile.mkdtemp()
        db_path = Path(tmp_dir) / 'test.db'
        db = DatabaseManager(db_path)
        db.open()
        db.init_tables()

        entry = _make_entry(title='Typed', entry_type='server', totp_secret='SECRET')
        entry_id = db.add_entry(entry)

        retrieved = db.get_entry(entry_id)
        self.assertEqual(retrieved.entry_type, 'server')
        self.assertEqual(retrieved.totp_secret, 'SECRET')
        db.close()
        db_path.unlink(missing_ok=True)


@pytest.mark.usefixtures('_disable_encrypted_assertions')
class TestCategoryManagement(unittest.TestCase):
    """分类管理增强测试"""

    def setUp(self):
        self._tmp_dir = tempfile.mkdtemp()
        self._db_path = Path(self._tmp_dir) / 'test.db'
        self._db = DatabaseManager(self._db_path)
        self._db.open()
        self._db.init_tables()

    def tearDown(self):
        self._db.close()
        try:
            self._db_path.unlink(missing_ok=True)
        except Exception:
            pass

    def test_get_category_entry_count(self):
        """获取分类下条目数量"""
        categories = self._db.get_categories()
        cat = categories[0]  # 未分类
        count = self._db.get_category_entry_count(cat.id)
        self.assertEqual(count, 0)

        entry = _make_entry(title='Test', category_id=cat.id)
        self._db.add_entry(entry)
        count = self._db.get_category_entry_count(cat.id)
        self.assertEqual(count, 1)

    def test_delete_category_nullifies_entries(self):
        """删除分类后条目 category_id 置空"""
        cat = Category(name='临时分类', icon_char='🔧', color='#FF0000')
        cat_id = self._db.add_category(cat)

        entry = _make_entry(title='Test', category_id=cat_id)
        entry_id = self._db.add_entry(entry)

        self._db.delete_category(cat_id)
        retrieved = self._db.get_entry(entry_id)
        self.assertIsNone(retrieved.category_id)


if __name__ == '__main__':
    unittest.main()
