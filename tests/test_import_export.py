"""导入导出测试"""

import os
import sys
import tempfile
import json
import csv
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.database.models import Entry, CustomField


class TestImportExport(unittest.TestCase):
    """导入导出逻辑测试"""

    def test_entry_json_roundtrip(self):
        """测试条目 JSON 序列化/反序列化"""
        entry = Entry(
            title='测试条目',
            username='user@example.com',
            password='MyP@ssw0rd',
            url='https://example.com',
            category_name='社交',
            tags='test,demo',
            notes='这是一条测试备注',
            custom_fields=[
                CustomField(name='API Key', value='sk-xxx', field_type='password'),
                CustomField(name='邮箱', value='test@test.com', field_type='email'),
            ],
            is_favorite=True,
            password_strength=3,
            created_at='2024-01-01T00:00:00',
            updated_at='2024-01-01T00:00:00',
        )

        # 导出
        d = entry.to_dict()
        self.assertEqual(d['title'], '测试条目')
        self.assertEqual(d['password'], 'MyP@ssw0rd')
        self.assertEqual(len(d['custom_fields']), 2)

        # 写入文件
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump({'entries': [d]}, f, ensure_ascii=False)
            filepath = f.name

        # 读回
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        restored = Entry.from_dict(data['entries'][0])
        self.assertEqual(restored.title, '测试条目')
        self.assertEqual(restored.username, 'user@example.com')
        self.assertEqual(restored.password, 'MyP@ssw0rd')
        self.assertEqual(len(restored.custom_fields), 2)
        self.assertEqual(restored.custom_fields[0].name, 'API Key')

        os.unlink(filepath)

    def test_entry_csv_export(self):
        """测试 CSV 导出"""
        entries = [
            Entry(title='Entry1', username='user1', password='pass1', url='https://a.com'),
            Entry(title='Entry2', username='user2', password='pass2', url='https://b.com'),
        ]

        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8-sig', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['title', 'username', 'password', 'url'], extrasaction='ignore')
            writer.writeheader()
            for e in entries:
                writer.writerow(e.to_dict())
            filepath = f.name

        with open(filepath, 'r', encoding='utf-8-sig', newline='') as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]['title'], 'Entry1')
        self.assertEqual(rows[1]['password'], 'pass2')

        os.unlink(filepath)

    def test_export_without_password(self):
        """测试不含密码的导出"""
        entry = Entry(title='Test', username='u', password='secret')
        d = entry.to_dict(include_password=False)
        self.assertNotIn('password', d)

    def test_custom_field_serialization(self):
        """测试自定义字段序列化"""
        cf = CustomField(name='test', value='val', field_type='password')
        d = cf.to_dict()
        self.assertEqual(d['name'], 'test')
        self.assertEqual(d['field_type'], 'password')

        restored = CustomField.from_dict(d)
        self.assertEqual(restored.name, 'test')
        self.assertEqual(restored.value, 'val')


if __name__ == '__main__':
    unittest.main()
