"""ReEncryptionService 单元测试。

使用 mock 数据库接口和真实加密引擎，验证密钥轮换服务在重加密条目
和密码历史时的正确性，包括批处理、损坏中止等场景。
"""

import json
import os
import uuid
from typing import cast

import pytest

from src.business.services import re_encryption as kr_module
from src.business.services.crypto_utils import decrypt_field, encrypt_field
from src.business.services.metadata_signer import MetadataSigner
from src.business.services.re_encryption import (
    ReEncryptedEntry,
    ReEncryptedHistory,
    ReEncryptionService,
)
from src.crypto.encryption import EncryptionEngine
from src.exceptions import DecryptionError
from src.models import PasswordHistory, RawEntry

# ---------------------------------------------------------------------------
# 辅助函数：生成随机 AES-256 密钥
# ---------------------------------------------------------------------------

def _random_key() -> bytes:
    return os.urandom(32)


# ---------------------------------------------------------------------------
# 辅助函数：构建数据库原始状态的 Entry，加密字段为密文字符串
# ---------------------------------------------------------------------------

def _make_raw_entry(
    entry_id: int,
    key: bytes,
    *,
    username: str = '',
    password: str = '',
    notes: str = '',
    totp_secret: str = '',
    custom_fields: list | None = None,
) -> RawEntry:
    """创建一个模拟数据库原始状态的 RawEntry，敏感字段已用 key 加密。"""
    crypto_id = uuid.uuid4().hex
    custom_json = json.dumps(custom_fields or [], ensure_ascii=False)

    return RawEntry(
        id=entry_id,
        crypto_id=crypto_id,
        title=f'条目{entry_id}',
        username=encrypt_field(username, key, crypto_id, 'username') if username else '',
        password=encrypt_field(password, key, crypto_id, 'password') if password else '',
        url=f'https://example.com/{entry_id}',
        category_id=None,
        tags='',
        notes=encrypt_field(notes, key, crypto_id, 'notes') if notes else '',
        custom_fields=encrypt_field(custom_json, key, crypto_id, 'custom_fields') if custom_json != '[]' else '',
        is_favorite=False,
        is_deleted=False,
        password_strength=0,
        entry_type='login',
        totp_secret=encrypt_field(totp_secret, key, crypto_id, 'totp_secret') if totp_secret else '',
        created_at='2025-01-01T00:00:00',
        updated_at='2025-01-01T00:00:00',
        deleted_at='',
        password_changed_at='2025-01-01T00:00:00',
        metadata_mac='',
    )


# ---------------------------------------------------------------------------
# MockDB：内存实现 ReEncryptionDB Protocol
# ---------------------------------------------------------------------------

class MockDB:
    """内存 mock，实现 ReEncryptionDB Protocol 四个方法。"""

    def __init__(self):
        self._entries: list[RawEntry] = []
        self._history: list[PasswordHistory] = []
        # 记录调用参数供断言
        self.updated_entry_batches: list[list] = []
        self.updated_history_batches: list[list] = []

    # -- 填充接口 --

    def add_entry(self, entry: RawEntry):
        self._entries.append(entry)

    def add_history(self, history: PasswordHistory):
        self._history.append(history)

    # -- ReEncryptionDB Protocol 实现 --

    def get_entries(self, *, include_deleted: bool, limit: int, after_id: int) -> list:
        """按 id 升序分页返回条目。"""
        filtered = [e for e in self._entries if cast(int, e.id) > after_id]
        return filtered[:limit]

    def update_entries_batch(self, rows: list) -> None:
        """记录批量更新行。"""
        self.updated_entry_batches.append(rows)

    def get_all_password_history_batch(self, after_id: int, limit: int) -> list:
        """按 id 升序分页返回密码历史。"""
        filtered = [h for h in self._history if (h.id or 0) > after_id]
        return filtered[:limit]

    def update_password_history_batch(self, rows: list) -> None:
        """记录批量更新行。"""
        self.updated_history_batches.append(rows)


# ---------------------------------------------------------------------------
# 测试：re_encrypt_entries，旧密钥加密的条目用新密钥重加密后可正确解密
# ---------------------------------------------------------------------------

def test_re_encrypt_entries_round_trip():
    """旧密钥加密的条目用新密钥重加密后，用新密钥可正确解密所有敏感字段。"""
    old_key = _random_key()
    new_key = _random_key()

    entry = _make_raw_entry(
        1, old_key,
        username='alice@example.com',
        password='S3cure!Pass',
        notes='这是备注',
        totp_secret='JBSWY3DPEHPK3PXP',
        custom_fields=[{'name': 'API Key', 'value': 'sk-12345', 'field_type': 'text'}],
    )

    db = MockDB()
    db.add_entry(entry)
    signer = MetadataSigner()
    service = ReEncryptionService(db, signer)

    service.re_encrypt_entries(old_key, new_key)

    # 应产生一批更新行
    assert len(db.updated_entry_batches) == 1
    rows = db.updated_entry_batches[0]
    assert len(rows) == 1
    row = rows[0]
    assert isinstance(row, ReEncryptedEntry)

    # 用新密钥解密验证
    crypto_id = row.crypto_id
    assert decrypt_field(row.username_enc, new_key, crypto_id, 'username') == 'alice@example.com'
    assert decrypt_field(row.password_enc, new_key, crypto_id, 'password') == 'S3cure!Pass'
    assert decrypt_field(row.notes_enc, new_key, crypto_id, 'notes') == '这是备注'
    assert decrypt_field(row.totp_secret_enc, new_key, crypto_id, 'totp_secret') == 'JBSWY3DPEHPK3PXP'

    custom_json = decrypt_field(row.custom_fields_enc, new_key, crypto_id, 'custom_fields')
    custom_fields = json.loads(custom_json)
    assert len(custom_fields) == 1
    assert custom_fields[0]['name'] == 'API Key'
    assert custom_fields[0]['value'] == 'sk-12345'

    # 签名应为有效 MAC
    assert len(row.metadata_mac) == 64  # HMAC-SHA256 hex digest

    EncryptionEngine.clear_cache()


# ---------------------------------------------------------------------------
# 测试：re_encrypt_entries 批处理，多批次正确处理
# ---------------------------------------------------------------------------

def test_re_encrypt_entries_batching():
    """超过批次大小时正确分批处理，所有条目都被重加密。"""
    old_key = _random_key()
    new_key = _random_key()
    num_entries = 250  # 超过 _RE_ENCRYPT_BATCH_SIZE 默认上限 200

    db = MockDB()
    for i in range(1, num_entries + 1):
        entry = _make_raw_entry(
            i, old_key,
            username=f'user{i}',
            password=f'pass{i}',
            notes=f'note{i}',
        )
        db.add_entry(entry)

    signer = MetadataSigner()
    service = ReEncryptionService(db, signer)

    service.re_encrypt_entries(old_key, new_key)

    # 应产生 2 批：第一批 200 条，第二批 50 条
    assert len(db.updated_entry_batches) == 2
    assert len(db.updated_entry_batches[0]) == 200
    assert len(db.updated_entry_batches[1]) == 50

    # 验证所有条目都可用新密钥解密
    all_rows = db.updated_entry_batches[0] + db.updated_entry_batches[1]
    for row in all_rows:
        plain_user = decrypt_field(row.username_enc, new_key, row.crypto_id, 'username')
        assert plain_user.startswith('user')
        plain_pass = decrypt_field(row.password_enc, new_key, row.crypto_id, 'password')
        assert plain_pass.startswith('pass')
        plain_notes = decrypt_field(row.notes_enc, new_key, row.crypto_id, 'notes')
        assert plain_notes.startswith('note')

    EncryptionEngine.clear_cache()


# ---------------------------------------------------------------------------
# 测试：re_encrypt_history，密码历史重加密正确
# ---------------------------------------------------------------------------

def test_re_encrypt_history_round_trip():
    """密码历史记录用新密钥重加密后可正确解密。"""
    old_key = _random_key()
    new_key = _random_key()
    crypto_id = uuid.uuid4().hex

    # 创建密码历史，old_password_enc 用旧密钥加密
    encrypted_password = encrypt_field('old_password_123', old_key, crypto_id, 'password')

    db = MockDB()
    db.add_history(PasswordHistory(
        id=1,
        entry_id=100,
        old_password_enc=encrypted_password,
        changed_at='2025-06-01T00:00:00',
        entry_crypto_id=crypto_id,
    ))

    signer = MetadataSigner()
    service = ReEncryptionService(db, signer)

    service.re_encrypt_history(old_key, new_key)

    # 应产生一批更新行
    assert len(db.updated_history_batches) == 1
    rows = db.updated_history_batches[0]
    assert len(rows) == 1
    row = rows[0]
    assert isinstance(row, ReEncryptedHistory)
    assert row.id == 1

    # 用新密钥解密验证
    plain = decrypt_field(row.ciphertext, new_key, crypto_id, 'password')
    assert plain == 'old_password_123'

    EncryptionEngine.clear_cache()


# ---------------------------------------------------------------------------
# 测试：re_encrypt_entries 损坏中止，解密失败时抛出 DecryptionError
# ---------------------------------------------------------------------------

def test_re_encrypt_entries_corruption_raises_decryption_error():
    """条目解密失败时抛出 DecryptionError 并中止重加密。

    crypto_utils.decrypt_field 默认容错模式会吞掉 ValueError，
    因此通过 patch 让 _decrypt_field_impl 在遇到损坏数据时重新抛出
    ValueError，触发 ReEncryptionService 中的 except ValueError 分支。
    """
    old_key = _random_key()
    new_key = _random_key()
    wrong_key = _random_key()

    # 用一个错误的密钥加密数据，导致用 old_key 解密时失败
    entry = _make_raw_entry(
        1, wrong_key,
        username='corrupted_user',
        password='corrupted_pass',
    )

    db = MockDB()
    db.add_entry(entry)
    signer = MetadataSigner()
    service = ReEncryptionService(db, signer)

    # patch 模块级引用，让解密失败时抛出 ValueError 而非静默返回空串
    original_decrypt = kr_module._decrypt_field_impl

    def strict_decrypt(encrypted, key, crypto_id, field_name, **kwargs):
        result = original_decrypt(encrypted, key, crypto_id, field_name, **kwargs)
        # decrypt_field 容错模式下返回空串表示解密失败
        if not result and encrypted:
            raise ValueError('模拟解密失败：密钥不匹配或数据损坏')
        return result

    with pytest.raises(DecryptionError):
        with pytest.MonkeyPatch().context() as m:
            m.setattr(kr_module, '_decrypt_field_impl', strict_decrypt)
            service.re_encrypt_entries(old_key, new_key)

    # 中止在第一条损坏条目，不应有更新操作
    assert len(db.updated_entry_batches) == 0

    EncryptionEngine.clear_cache()


# ---------------------------------------------------------------------------
# 测试：re_encrypt_history 损坏中止，密码历史解密失败时抛出 DecryptionError
# ---------------------------------------------------------------------------

def test_re_encrypt_history_corruption_raises_decryption_error():
    """密码历史解密失败时抛出 DecryptionError 并中止重加密。

    同 test_re_encrypt_entries_corruption_raises_decryption_error，
    通过 patch 让解密失败时抛出 ValueError 以触发错误处理路径。
    """
    old_key = _random_key()
    new_key = _random_key()
    wrong_key = _random_key()
    crypto_id = uuid.uuid4().hex

    # 用错误密钥加密，导致用 old_key 解密时失败
    encrypted_password = encrypt_field('some_password', wrong_key, crypto_id, 'password')

    db = MockDB()
    db.add_history(PasswordHistory(
        id=1,
        entry_id=100,
        old_password_enc=encrypted_password,
        changed_at='2025-06-01T00:00:00',
        entry_crypto_id=crypto_id,
    ))

    signer = MetadataSigner()
    service = ReEncryptionService(db, signer)

    # patch 模块级引用，让解密失败时抛出 ValueError
    original_decrypt = kr_module._decrypt_field_impl

    def strict_decrypt(encrypted, key, crypto_id, field_name, **kwargs):
        result = original_decrypt(encrypted, key, crypto_id, field_name, **kwargs)
        if not result and encrypted:
            raise ValueError('模拟解密失败：密钥不匹配或数据损坏')
        return result

    with pytest.raises(DecryptionError):
        with pytest.MonkeyPatch().context() as m:
            m.setattr(kr_module, '_decrypt_field_impl', strict_decrypt)
            service.re_encrypt_history(old_key, new_key)

    # 不应有任何更新操作
    assert len(db.updated_history_batches) == 0

    EncryptionEngine.clear_cache()
