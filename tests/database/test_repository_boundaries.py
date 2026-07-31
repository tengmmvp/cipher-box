"""Repository 边界测试：密码历史截断、批量 ID 查询分页与批量写 happy-path。

覆盖此前仅被间接路径触及的边界：add_password_history 截断到 MAX_PASSWORD_HISTORY
（off-by-one）、get_entries_by_ids 在 ID 数超过 SQLite 主机变量上限时的分批查询，
以及批量写（add_entries_batch / update_entries_batch / update_password_history_batch）
此前仅有空输入短路面、缺失真实加密落库的 happy-path。
"""

import os

import pytest

from src.crypto.encryption import EncryptionEngine
from src.database import entry_repository
from src.database.db_manager import DatabaseManager
from src.database.types import EntryQuery, ReEncryptedEntry, ReEncryptedHistory, VerifyMode
from src.exceptions import DatabaseError, TransactionError, VaultIntegrityError
from src.models import MAX_PASSWORD_HISTORY, RawEntry


def _make_entry(**kwargs) -> RawEntry:
    kwargs.setdefault('password', 'x')
    kwargs.setdefault('notes', '')
    kwargs.setdefault('custom_fields', '')
    return RawEntry(**kwargs)


@pytest.fixture
def db(tmp_path):
    """临时数据库，test_mode 关闭密文断言。

    tmp_path 由 pytest 提供并自动清理。
    """
    _db_path = tmp_path / 'test_boundary.db'
    _db = DatabaseManager(_db_path, test_mode=True)
    _db.open()
    _db.init_tables()
    yield _db
    _db.close()


def test_password_history_truncated_to_max(db):
    """密码历史超过 MAX_PASSWORD_HISTORY 时截断为最新 N 条（off-by-one 边界）。"""
    entry = _make_entry(title='Truncated')
    entry_id = db.add_entry(entry)
    total = MAX_PASSWORD_HISTORY + 3
    for i in range(total):
        db.add_password_history(entry_id, f'enc_{i}', f't{i:04d}')
    history = db.get_password_history(entry_id)
    assert len(history) == MAX_PASSWORD_HISTORY
    # 按 changed_at DESC，最新（i 最大）排在首位
    assert history[0].old_password_enc == f'enc_{total - 1}'


def test_get_entries_by_ids_batches_large_id_lists(db, monkeypatch):
    """ID 数超过 _ID_BATCH_SIZE 时分批查询，全部返回且无错位/无遗漏。"""
    monkeypatch.setattr(entry_repository, '_ID_BATCH_SIZE', 2)
    ids = [db.add_entry(_make_entry(title=f'E{i}')) for i in range(5)]
    fetched = db.get_entries_by_ids(ids)
    assert {e.id for e in fetched} == set(ids)


def test_add_entry_converts_crypto_id_conflict_to_database_error(db):
    """crypto_id UNIQUE 冲突归一化为 DatabaseError，避免裸 sqlite3.IntegrityError 上泄。"""
    db.add_entry(_make_entry(crypto_id='dup-id', title='First'))
    duplicate = _make_entry(crypto_id='dup-id', title='Second')
    with pytest.raises(DatabaseError, match='唯一约束'):
        db.add_entry(duplicate)


def test_update_entries_batch_noop_on_empty(db):
    """空列表短路：不执行 SQL、不抛异常（改密重加密无变更条目的边界）。"""
    db.update_entries_batch([])  # 不应抛异常


def test_get_entries_by_ids_returns_empty_for_empty_input(db):
    """空 ID 列表短路返回 []，避免构造 IN () 非法 SQL。"""
    assert db.get_entries_by_ids([]) == []


def test_get_entries_by_ids_deduplicates_preserving_order(db):
    """dict.fromkeys 去重保序：重复 id 不导致行数膨胀或位置错位。"""
    id1 = db.add_entry(_make_entry(crypto_id='c1', title='A'))
    id2 = db.add_entry(_make_entry(crypto_id='c2', title='B'))
    fetched = db.get_entries_by_ids([id1, id2, id1, id2])
    assert [e.id for e in fetched] == [id1, id2]


def test_get_entries_after_id_cursor_paginates(db):
    """after_id 游标分页：返回 id > after_id 的条目，按 id ASC，LIMIT 下推 SQL。"""
    ids = [db.add_entry(_make_entry(crypto_id=f'c{i}', title=f'E{i}')) for i in range(5)]
    page = db.get_entries(EntryQuery(after_id=ids[1], limit=2))
    assert [e.id for e in page] == ids[2:4]


def test_add_entry_foreign_key_violation_classified(db):
    """引用不存在分类的 FK 违规分流为「外键约束」，不误标为 crypto_id 冲突（#14 回归）。"""
    entry = _make_entry(category_id=999999, title='FK')
    with pytest.raises(DatabaseError, match='外键约束'):
        db.add_entry(entry)


def test_classify_entry_integrity_error_routes_by_message():
    """_classify_entry_integrity_error 按文案分流 FK/NOT NULL/唯一（#14 单元守护）。"""
    import sqlite3

    from src.database.entry_repository import _classify_entry_integrity_error

    fk = _classify_entry_integrity_error(
        '条目写入', sqlite3.IntegrityError('FOREIGN KEY constraint failed')
    )
    assert '外键约束' in str(fk)
    assert 'crypto_id' not in str(fk)

    nn = _classify_entry_integrity_error(
        '条目写入', sqlite3.IntegrityError('NOT NULL constraint failed: entries.title_enc')
    )
    assert '非空约束' in str(nn)
    assert 'crypto_id' not in str(nn)

    uq = _classify_entry_integrity_error(
        '条目写入', sqlite3.IntegrityError('UNIQUE constraint failed: entries.crypto_id')
    )
    assert 'crypto_id' in str(uq)


# === 批量写 happy-path ===
#
# 顶部 db fixture（test_mode=True）关闭了加密断言，仅覆盖空输入短路等控制流边界。
# 以下测试用真实 DatabaseManager（_enforce_encrypted_fields=True）+ EncryptionEngine
# 产出的合法 cb2: 密文，覆盖 add_entries_batch 分页反查、update_entries_batch 与
# update_password_history_batch 的 happy-path：此前三者仅有空输入短路面或零测试。

# 真实 AES-256 密钥，仅本模块批量写 happy-path 使用。模块加载时生成一次，
# 供 _enc 默认引用；新密钥场景（update_*_batch 验证重加密生效）显式传 key。
_BATCH_KEY = os.urandom(32)


@pytest.fixture
def secure_db(tmp_path):
    """启用加密断言的临时数据库，用于批量写 happy-path。

    非 test_mode → _enforce_encrypted_fields 默认 True，配合 EncryptionEngine 产出的
    合法 cb2: 密文，真实走 _assert_entry_encrypted_fields / _assert_encrypted 拦截路径，
    确保 happy-path 在生产态加密断言启用下成立（而非仅 test_mode 放行）。
    """
    database = DatabaseManager(tmp_path / 'batch_writes.db')
    database.open()
    database.init_tables()
    yield database
    database.close()


def _enc(plaintext: str, crypto_id: str, field: str, *, key: bytes = _BATCH_KEY) -> str:
    """产生合法 cb2: 密文，AAD 遵循 entry:<crypto_id>:<field> 域分离约定。"""
    return EncryptionEngine.encrypt(plaintext, key, f'entry:{crypto_id}:{field}')


def _make_encrypted_entry(crypto_id: str, title: str) -> RawEntry:
    """构建全部敏感字段为合法 cb2: 密文的 RawEntry，满足 _assert_entry_encrypted_fields。

    url/tags/notes/custom_fields/totp_secret 留空（断言对空值放行），仅给 title/
    username/password 三列填密文以覆盖加密列写回路径。
    """
    return RawEntry(
        crypto_id=crypto_id,
        title=_enc(title, crypto_id, 'title'),
        username=_enc('user-' + title, crypto_id, 'username'),
        password=_enc('pwd-' + title, crypto_id, 'password'),
        entry_type='login',
        password_strength=3,
    )


def test_add_entries_batch_happy_path_crosses_paging(secure_db):
    """add_entries_batch 插入 >1000 条（跨 _ID_BATCH_SIZE=500 分页边界），全部落库可读。

    1001 = 2*_ID_BATCH_SIZE + 1，反查 {crypto_id: id} 映射需分 3 批 IN 查询。
    验证：映射覆盖全部输入条目、值均为正整数（非 None）、全量落库可读、
    抽样首/中/尾三条（跨分页边界）的密文可解密回原明文。
    """
    entries = [
        _make_encrypted_entry(crypto_id=f'c{i:05d}', title=f'标题{i}')
        for i in range(1001)
    ]
    id_map = secure_db.add_entries_batch(entries)

    # 映射完整性：键集 == 输入 crypto_id 集，值全为正整数（executemany 不返回逐条
    # lastrowid，实现按 crypto_id 反查 id；分批 IN 查询不得遗漏）
    assert set(id_map) == {e.crypto_id for e in entries}
    assert len(id_map) == 1001
    assert all(isinstance(v, int) and v > 0 for v in id_map.values())

    # 全量落库可读
    fetched = secure_db.get_entries(EntryQuery(include_deleted=True))
    assert len(fetched) == 1001
    assert {e.crypto_id for e in fetched} == {e.crypto_id for e in entries}

    # 抽样首/中/尾（跨分页边界 500/1000），验证映射 id 指向的行密文可解密回原明文
    for sample_idx in (0, 500, 1000):
        crypto_id = f'c{sample_idx:05d}'
        entry_id = id_map[crypto_id]
        fetched_entry = secure_db.get_entry(entry_id)
        assert fetched_entry is not None
        assert fetched_entry.crypto_id == crypto_id
        assert EncryptionEngine.decrypt(
            fetched_entry.title, _BATCH_KEY, f'entry:{crypto_id}:title',
        ) == f'标题{sample_idx}'


def test_update_entries_batch_happy_path(secure_db):
    """update_entries_batch 批量重加密若干条目字段，读回解密验证更新生效。

    覆盖首行 _enc 采样断言放行 + executemany 位置绑定列序正确性：用新密钥重加密
    title/username/password 后读回，解密得新明文即证明写回列未错位。
    """
    entries = [
        _make_encrypted_entry(crypto_id=f'upd-{i}', title=f'原标题{i}')
        for i in range(3)
    ]
    id_map = secure_db.add_entries_batch(entries)

    new_key = os.urandom(32)
    rows = []
    for i, entry in enumerate(entries):
        crypto_id = entry.crypto_id
        rows.append(ReEncryptedEntry(
            crypto_id=crypto_id,
            title_enc=_enc(f'新标题{i}', crypto_id, 'title', key=new_key),
            username_enc=_enc(f'新用户{i}', crypto_id, 'username', key=new_key),
            password_enc=_enc(f'新密码{i}', crypto_id, 'password', key=new_key),
            url_enc='',
            category_id=None,
            tags_enc='',
            notes_enc='',
            custom_fields_enc='',
            is_favorite=0,
            password_strength=3,
            entry_type='login',
            totp_secret_enc='',
            updated_at='2026-07-31T00:00:00Z',
            password_changed_at='',
            metadata_mac='',
            id=id_map[crypto_id],
        ))
    secure_db.update_entries_batch(rows)

    # 读回解密：三个重加密字段均更新为新密钥下的新明文（列序不错位）
    for i, entry in enumerate(entries):
        crypto_id = entry.crypto_id
        updated = secure_db.get_entry(id_map[crypto_id])
        assert updated is not None
        assert EncryptionEngine.decrypt(
            updated.title, new_key, f'entry:{crypto_id}:title',
        ) == f'新标题{i}'
        assert EncryptionEngine.decrypt(
            updated.username, new_key, f'entry:{crypto_id}:username',
        ) == f'新用户{i}'
        assert EncryptionEngine.decrypt(
            updated.password, new_key, f'entry:{crypto_id}:password',
        ) == f'新密码{i}'


def test_update_password_history_batch_happy_path(secure_db):
    """update_password_history_batch 批量重加密密码历史，可按条目读回新密文。

    覆盖此前零测试的 update_password_history_batch：逐条 _assert_encrypted 放行 +
    executemany（old_password_enc, id）位置绑定，读回解密验证密文已更新为新密钥。
    """
    crypto_id = 'hist-1'
    entry_id = secure_db.add_entries_batch(
        [_make_encrypted_entry(crypto_id=crypto_id, title='带历史')],
    )[crypto_id]

    # 写入 2 条密码历史（< MAX_PASSWORD_HISTORY=10，不触发截断）
    secure_db.add_password_history(
        entry_id, _enc('old-pwd-1', crypto_id, 'password'), '2026-01-01T00:00:00Z',
    )
    secure_db.add_password_history(
        entry_id, _enc('old-pwd-2', crypto_id, 'password'), '2026-02-01T00:00:00Z',
    )
    history = secure_db.get_password_history(entry_id)
    assert len(history) == 2

    new_key = os.urandom(32)
    rows = [
        ReEncryptedHistory(
            ciphertext=_enc(f'new-pwd-{h.id}', crypto_id, 'password', key=new_key),
            id=h.id,
        )
        for h in history
    ]
    secure_db.update_password_history_batch(rows)

    # 按条目读回，解密得新明文（id 不错位、密文已替换）
    updated = secure_db.get_password_history(entry_id)
    assert len(updated) == 2
    by_id = {h.id: h for h in updated}
    for h in history:
        rec = by_id[h.id]
        assert EncryptionEngine.decrypt(
            rec.old_password_enc, new_key, f'entry:{crypto_id}:password',
        ) == f'new-pwd-{h.id}'


# === STRICT 验签与事务契约 ===


def test_get_entries_strict_raises_on_tampered_metadata_mac(vault, entry_mgr, make_entry):
    """VerifyMode.STRICT 在 metadata_mac 篡改时抛 VaultIntegrityError。

    vault fixture 经组合根装配真实 MetadataSigner（entry_verifier 已连线），add_entry
    写入的条目带合法 HMAC 签名。直接 UPDATE 篡改 mac 后，get_entries(STRICT) 验签
    失败抛出，区别于 LENIENT 仅标记、SKIP 完全跳过。
    """
    entry_id = entry_mgr.add_entry(make_entry(title='签名条目'))

    # 经 db 受管事务篡改 metadata_mac，破坏 HMAC 一致性
    with vault.db.transaction():
        vault.db._conn.execute(
            "UPDATE entries SET metadata_mac=? WHERE id=?",
            ('tampered_mac_value', entry_id),
        )

    with pytest.raises(VaultIntegrityError):
        vault.db.get_entries(EntryQuery(verify=VerifyMode.STRICT))


def test_get_entries_skip_does_not_raise_on_tampered_mac(vault, entry_mgr, make_entry):
    """VerifyMode.SKIP 对同一篡改库不抛（正对照），返回条目不验签。"""
    entry_id = entry_mgr.add_entry(make_entry(title='另一条目'))
    with vault.db.transaction():
        vault.db._conn.execute(
            "UPDATE entries SET metadata_mac=? WHERE id=?",
            ('tampered_mac_value', entry_id),
        )

    fetched = vault.db.get_entries(EntryQuery(verify=VerifyMode.SKIP))

    assert any(e.id == entry_id for e in fetched)


def test_clear_category_signatures_requires_active_transaction(db):
    """clear_category_signatures 在无活动事务时抛 TransactionError（契约守卫）。

    本方法不自行获取 db_lock，调用方（DatabaseManager.delete_category）须已在事务内。
    入口断言将此契约从注释升级为运行期检查，防止裸 DELETE 跨表不一致。
    """
    assert not db.in_transaction
    with pytest.raises(TransactionError, match='活动事务'):
        db._entry_repo.clear_category_signatures(999)


def test_delete_category_requires_active_transaction(db):
    """CategoryRepository.delete_category 在无活动事务时抛 TransactionError。"""
    assert not db.in_transaction
    with pytest.raises(TransactionError, match='活动事务'):
        db._category_repo.delete_category(1)
