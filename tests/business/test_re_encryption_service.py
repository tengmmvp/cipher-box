"""ReEncryptionService 单元测试。

使用 mock 数据库接口和真实加密引擎，验证密钥轮换服务在重加密条目
和密码历史时的正确性，包括批处理、损坏中止等场景。
"""

import json
import os
import uuid
from typing import cast

import pytest

from src.business.services.crypto_utils import (
    category_crypto_id,
    decrypt_field,
    encrypt_field,
)
from src.business.services.metadata_signer import MetadataSigner
from src.business.services.re_encryption import (
    ReEncryptedEntry,
    ReEncryptedHistory,
    ReEncryptionService,
)
from src.crypto.encryption import EncryptionEngine
from src.database.types import EntryQuery
from src.exceptions import DecryptionError
from src.models import Category, PasswordHistory, RawEntry


def _random_key() -> bytes:
    return os.urandom(32)


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
        title=encrypt_field(f'条目{entry_id}', key, crypto_id, 'title'),
        username=encrypt_field(username, key, crypto_id, 'username') if username else '',
        password=encrypt_field(password, key, crypto_id, 'password') if password else '',
        url=encrypt_field(f'https://example.com/{entry_id}', key, crypto_id, 'url'),
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


class MockDB:
    """内存 mock，实现 ReEncryptionDB Protocol。"""

    def __init__(self):
        self._entries: list[RawEntry] = []
        self._history: list[PasswordHistory] = []
        self._categories: list[Category] = []
        # 记录调用参数供断言
        self.updated_entry_batches: list[list] = []
        self.updated_history_batches: list[list] = []
        self.updated_categories: list[Category] = []

    def add_entry(self, entry: RawEntry):
        self._entries.append(entry)

    def add_history(self, history: PasswordHistory):
        self._history.append(history)

    def add_category(self, category: Category):
        self._categories.append(category)

    def get_entries(self, query: EntryQuery) -> list[RawEntry]:
        """按 id 升序分页返回条目。"""
        after = query.after_id or 0
        filtered = [e for e in self._entries if cast(int, e.id) > after]
        return filtered[:query.limit] if query.limit is not None else filtered

    def update_entries_batch(self, rows: list[ReEncryptedEntry]) -> None:
        """记录批量更新行。"""
        self.updated_entry_batches.append(rows)

    def get_all_password_history_batch(
        self, after_id: int = 0, limit: int = 200,
    ) -> list[PasswordHistory]:
        """按 id 升序分页返回密码历史。"""
        filtered = [h for h in self._history if (h.id or 0) > after_id]
        return filtered[:limit]

    def update_password_history_batch(self, rows: list[ReEncryptedHistory]) -> None:
        """记录批量更新行。"""
        self.updated_history_batches.append(rows)

    def get_categories(self, *, verify: bool = True) -> list[Category]:
        """返回填充的分类，供 re_encrypt_categories 测试。

        verify 参数为兼容 ReEncryptionDB Protocol（re_encrypt_categories 以
        verify=False 读取跳过验签）；mock 不验签，参数仅占位。
        """
        return list(self._categories)

    def update_categories_batch(self, categories: list[Category]) -> None:
        """记录重加密后的分类（re_encrypt_categories 经此批量写路径写入）。"""
        self.updated_categories.extend(categories)


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

    assert len(db.updated_entry_batches) == 1
    rows = db.updated_entry_batches[0]
    assert len(rows) == 1
    row = rows[0]
    assert isinstance(row, ReEncryptedEntry)

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

    assert len(row.metadata_mac) == 64  # HMAC-SHA256 hex digest

    EncryptionEngine.clear_cache()


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

    assert len(db.updated_entry_batches) == 2
    assert len(db.updated_entry_batches[0]) == 200
    assert len(db.updated_entry_batches[1]) == 50

    all_rows = db.updated_entry_batches[0] + db.updated_entry_batches[1]
    for row in all_rows:
        plain_user = decrypt_field(row.username_enc, new_key, row.crypto_id, 'username')
        assert plain_user.startswith('user')
        plain_pass = decrypt_field(row.password_enc, new_key, row.crypto_id, 'password')
        assert plain_pass.startswith('pass')
        plain_notes = decrypt_field(row.notes_enc, new_key, row.crypto_id, 'notes')
        assert plain_notes.startswith('note')

    EncryptionEngine.clear_cache()


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

    assert len(db.updated_history_batches) == 1
    rows = db.updated_history_batches[0]
    assert len(rows) == 1
    row = rows[0]
    assert isinstance(row, ReEncryptedHistory)
    assert row.id == 1

    plain = decrypt_field(row.ciphertext, new_key, crypto_id, 'password')
    assert plain == 'old_password_123'

    EncryptionEngine.clear_cache()


def test_re_encrypt_entries_corruption_raises_decryption_error():
    """条目解密失败时抛出 DecryptionError 并中止重加密（strict=True 真实路径）。

    用错误密钥加密的条目，用 old_key 解密必然失败；strict=True 使 decrypt_field
    直接抛 ValueError，被 re_encrypt_entries 的 except 捕获转为 DecryptionError，
    中止改密以保护数据完整性——而非 strict=False 下静默解密为空串再用新密钥
    加密写入（不可逆的数据丢失）。
    """
    old_key = _random_key()
    new_key = _random_key()
    wrong_key = _random_key()

    # 用错误密钥加密，导致用 old_key 解密时失败
    entry = _make_raw_entry(
        1, wrong_key,
        username='corrupted_user',
        password='corrupted_pass',
    )

    db = MockDB()
    db.add_entry(entry)
    signer = MetadataSigner()
    service = ReEncryptionService(db, signer)

    with pytest.raises(DecryptionError):
        service.re_encrypt_entries(old_key, new_key)

    assert len(db.updated_entry_batches) == 0

    EncryptionEngine.clear_cache()


def test_re_encrypt_history_corruption_raises_decryption_error():
    """密码历史解密失败时抛出 DecryptionError 并中止重加密（strict=True 真实路径）。

    同 test_re_encrypt_entries_corruption_raises_decryption_error，用错误密钥
    加密的密码历史，用 old_key 解密必然失败，strict=True 触发 DecryptionError
    中止改密。
    """
    old_key = _random_key()
    new_key = _random_key()
    wrong_key = _random_key()
    crypto_id = uuid.uuid4().hex

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

    with pytest.raises(DecryptionError):
        service.re_encrypt_history(old_key, new_key)

    assert len(db.updated_history_batches) == 0

    EncryptionEngine.clear_cache()


def test_re_encrypt_categories_round_trip():
    """分类名称用新密钥重加密后可正确解密（AAD 绑定 category_crypto_id）。"""
    old_key = _random_key()
    new_key = _random_key()

    cat_id = 1
    crypto_id = category_crypto_id(cat_id)
    encrypted_name = encrypt_field('工作分类', old_key, crypto_id, 'category_name')

    db = MockDB()
    db.add_category(Category(id=cat_id, name=encrypted_name))
    signer = MetadataSigner()
    service = ReEncryptionService(db, signer)

    service.re_encrypt_categories(old_key, new_key)

    assert len(db.updated_categories) == 1
    updated = db.updated_categories[0]
    assert updated.id == cat_id

    # 用新密钥解密验证（AAD 仍为 category_crypto_id(cat_id)）
    plain = decrypt_field(updated.name, new_key, crypto_id, 'category_name')
    assert plain == '工作分类'

    EncryptionEngine.clear_cache()


def test_re_encrypt_categories_corruption_raises_decryption_error():
    """分类名称解密失败时抛出 DecryptionError 并中止（strict=True 真实路径）。

    同 entries/history 损坏测试，用错误密钥加密的分类名，用 old_key 解密必然失败，
    strict=True 触发 DecryptionError 中止改密。
    """
    old_key = _random_key()
    new_key = _random_key()
    wrong_key = _random_key()

    cat_id = 1
    crypto_id = category_crypto_id(cat_id)
    encrypted_name = encrypt_field('损坏分类', wrong_key, crypto_id, 'category_name')

    db = MockDB()
    db.add_category(Category(id=cat_id, name=encrypted_name))
    signer = MetadataSigner()
    service = ReEncryptionService(db, signer)

    with pytest.raises(DecryptionError):
        service.re_encrypt_categories(old_key, new_key)

    assert len(db.updated_categories) == 0

    EncryptionEngine.clear_cache()
