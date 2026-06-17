"""导入导出序列化测试。

覆盖 Entry 与 CustomField 的 JSON、CSV 序列化往返，以及
to_dict 在是否包含密码下的字段取舍。
"""

import csv
import json
import os
import tempfile
from typing import cast

from src.models import CustomField, Entry, Sensitive


def test_entry_json_roundtrip():
    """条目 JSON 序列化与反序列化往返。"""
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

    d = entry.to_dict(include_password=True)
    assert d['title'] == '测试条目'
    assert d['password'] == 'MyP@ssw0rd'
    assert len(d['custom_fields']) == 2

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
        json.dump({'entries': [d]}, f, ensure_ascii=False)
        filepath = f.name

    with open(filepath, encoding='utf-8') as f:
        data = json.load(f)

    restored = Entry.from_dict(data['entries'][0])
    assert restored.title == '测试条目'
    assert restored.username == 'user@example.com'
    assert restored.password == 'MyP@ssw0rd'
    assert len(restored.custom_fields) == 2
    assert cast(list[CustomField], restored.custom_fields)[0].name == 'API Key'

    os.unlink(filepath)


def test_entry_csv_export():
    """条目 CSV 导出。"""
    entries = [
        Entry(title='Entry1', username='user1', password='pass1', url='https://a.com'),
        Entry(title='Entry2', username='user2', password='pass2', url='https://b.com'),
    ]

    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8-sig', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['title', 'username', 'password', 'url'], extrasaction='ignore')
        writer.writeheader()
        for e in entries:
            writer.writerow(e.to_dict(include_password=True))
        filepath = f.name

    with open(filepath, encoding='utf-8-sig', newline='') as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    assert len(rows) == 2
    assert rows[0]['title'] == 'Entry1'
    assert rows[1]['password'] == 'pass2'

    os.unlink(filepath)


def test_export_without_password():
    """不含密码的导出应剔除 password 字段。"""
    entry = Entry(title='Test', username='u', password='secret')
    d = entry.to_dict(include_password=False)
    assert 'password' not in d


def test_entry_export_excludes_secrets_by_default():
    """默认导出应排除密码等敏感字段。"""
    entry = Entry(title='Test', password='secret')
    assert 'password' not in entry.to_dict()


def test_custom_field_serialization():
    """自定义字段序列化与反序列化往返。"""
    cf = CustomField(name='test', value='val', field_type='password')
    d = cf.to_dict()
    assert d['name'] == 'test'
    assert d['field_type'] == 'password'

    restored = CustomField.from_dict(d)
    assert restored.name == 'test'
    assert restored.value == 'val'


def test_sensitive_representations_are_redacted():
    secret = 'TopSecret!2026'
    entry = Entry(
        title='Account',
        password=Sensitive(secret),
        notes=secret,
        custom_fields=[CustomField('api_key', secret, 'password')],
    )

    assert secret not in repr(Sensitive(secret))
    assert secret not in repr(entry)
    assert secret not in repr(entry.custom_fields[0])
