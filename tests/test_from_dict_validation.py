"""Entry.from_dict entry_type 校验测试"""

import unittest

from src.database.models import ENTRY_TYPE_LOGIN, ENTRY_TYPES, Entry


class TestFromDictValidation(unittest.TestCase):
    """验证 Entry.from_dict 对 entry_type 的校验"""

    def _base_dict(self, **overrides):
        d = dict(
            title='Test',
            username='user',
            password='pass',
        )
        d.update(overrides)
        return d

    def test_valid_entry_types(self):
        """所有合法 entry_type 应正常构造"""
        for entry_type in ENTRY_TYPES:
            d = self._base_dict(entry_type=entry_type)
            entry = Entry.from_dict(d)
            self.assertEqual(entry.entry_type, entry_type)

    def test_default_entry_type_is_login(self):
        """不传 entry_type 应默认为 login"""
        entry = Entry.from_dict(self._base_dict())
        self.assertEqual(entry.entry_type, ENTRY_TYPE_LOGIN)

    def test_invalid_entry_type_raises(self):
        """非法 entry_type 应抛出 ValueError"""
        with self.assertRaises(ValueError) as ctx:
            Entry.from_dict(self._base_dict(entry_type='invalid_type'))
        self.assertIn('无效的条目类型', str(ctx.exception))

    def test_empty_entry_type_raises(self):
        """空字符串 entry_type 应抛出 ValueError"""
        with self.assertRaises(ValueError):
            Entry.from_dict(self._base_dict(entry_type=''))

    def test_numeric_entry_type_raises(self):
        """数字 entry_type 应抛出 ValueError（字符串 '123' 不是合法类型）"""
        with self.assertRaises(ValueError):
            Entry.from_dict(self._base_dict(entry_type='123'))
