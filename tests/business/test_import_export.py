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


def test_sanitize_url_scheme_rejects_dangerous_schemes():
    """url scheme 白名单：javascript:/data:/file: 清空，http/https/裸域名保留。

    覆盖全部导入路径（CSV/Chrome CSV/KeePass/JSON/Bitwarden 共享 _sanitize_url_scheme），
    防止恶意 scheme 被详情面板渲染为可点击链接导致钓鱼/协议注入。
    """
    from src.business.managers.importers.base import _sanitize_url_scheme
    # 危险 scheme 清空
    assert _sanitize_url_scheme('javascript:alert(1)') == ''
    assert _sanitize_url_scheme('data:text/html,<script>') == ''
    assert _sanitize_url_scheme('file:///etc/passwd') == ''
    assert _sanitize_url_scheme('vbscript:msgbox') == ''
    # 白名单 scheme 保留
    assert _sanitize_url_scheme('http://example.com') == 'http://example.com'
    assert _sanitize_url_scheme('https://example.com/path?q=1') == 'https://example.com/path?q=1'
    assert _sanitize_url_scheme('ftp://ftp.example.com') == 'ftp://ftp.example.com'
    assert _sanitize_url_scheme('ssh://user@host') == 'ssh://user@host'
    assert _sanitize_url_scheme('mailto:a@b.com') == 'mailto:a@b.com'
    # 空 scheme（裸域名/相对路径）保留，UI 点击按默认 http 处理
    assert _sanitize_url_scheme('example.com') == 'example.com'
    assert _sanitize_url_scheme('/relative/path') == '/relative/path'
    # 空串
    assert _sanitize_url_scheme('') == ''
    # 大小写不敏感
    assert _sanitize_url_scheme('JavaScript:alert(1)') == ''
    assert _sanitize_url_scheme('HTTPS://x.com') == 'HTTPS://x.com'


def test_sanitize_totp_secret_rejects_invalid():
    """totp_secret 清洗：无效 base32 或解码后过短清空，合法 secret 与 otpauth URI 保留。

    覆盖全部导入路径（CSV/KeePass/JSON/Bitwarden 共享 _sanitize_totp_secret），防止
    损坏密钥静默入库导致后续验证码生成失败且用户无反馈。
    """
    from src.business.managers.importers.base import _sanitize_totp_secret
    # 无效 base32（含非法字符）清空
    assert _sanitize_totp_secret('not-valid-base32!!!') == ''
    # 解码后过短（< 10 字节）清空
    assert _sanitize_totp_secret('ABCD') == ''
    # 空串保留为空
    assert _sanitize_totp_secret('') == ''
    # 合法 base32（base32('1234567890')，解码 10 字节）保留
    assert _sanitize_totp_secret('GEZDGNBVGY3TQOJQ') == 'GEZDGNBVGY3TQOJQ'
    # otpauth URI 保留（secret 参数为合法 base32）
    otpauth = 'otpauth://totp/Example:alice@google.com?secret=GEZDGNBVGY3TQOJQ&issuer=Example'
    assert _sanitize_totp_secret(otpauth) == otpauth


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


def test_import_from_bitwarden_json_sanitizes_url_and_totp(entry_mgr, tmp_path):
    """Bitwarden 导入清洗危险 url scheme 与无效 totp（与 CSV/JSON 路径一致）。

    回归 P2-1：此前 Bitwarden 路径遗漏 _sanitize_url_scheme / _sanitize_totp_secret，
    是唯一产出含 javascript: scheme 与无效 totp 条目的导入路径。
    """
    from src.business.managers.import_export import ImportExportManager

    mgr = ImportExportManager(entry_mgr)
    bw_path = tmp_path / 'bitwarden.json'
    bw_path.write_text(json.dumps({
        'items': [
            {
                'name': 'Danger',
                'type': 1,
                'login': {
                    'username': 'alice',
                    'password': 'Pass123!',
                    'uris': [{'uri': 'javascript:alert(1)'}],
                    'totp': 'not-valid-base32!!!',
                },
            },
            {
                'name': 'Safe',
                'type': 1,
                'login': {
                    'username': 'bob',
                    'password': 'Secret456@',
                    'uris': [{'uri': 'https://github.com'}],
                    'totp': 'GEZDGNBVGY3TQOJQ',  # base32('1234567890')，10 字节合法 secret
                },
            },
        ],
        'folders': [],
    }), encoding='utf-8')

    count = mgr.import_file(str(bw_path), 'bitwarden_json')

    assert count == 2
    by_title = {e.title: e for e in entry_mgr.get_entries()}
    danger = by_title['Danger']
    assert danger.url == ''              # javascript: scheme 已清空
    assert danger.totp_secret == ''      # 无效 base32 已清空
    safe = by_title['Safe']
    assert safe.url == 'https://github.com'
    assert safe.totp_secret == 'GEZDGNBVGY3TQOJQ'
