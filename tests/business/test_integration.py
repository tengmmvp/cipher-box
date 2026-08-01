"""集成测试，覆盖加密、存储、解密的真实流程。

按业务管理器分组验证端到端行为：EntryManager 的增删改查与密码历史、
VaultManager 的初始化与改密重加密、BackupRestoreManager 的备份恢复
完整性、SecurityAnalyzer 的弱密码与重复检测、DatabaseManager 的事务
提交与回滚，以及 ImportExportManager 的 JSON 与 CSV 往返。
"""

import dataclasses
import os
import shutil
import tempfile
from pathlib import Path
from unittest.mock import PropertyMock, patch

import pytest

from src.business.managers.backup_restore import BackupRestoreManager
from src.business.managers.entry_cache import EntryCacheManager
from src.business.managers.import_export import ImportExportManager
from src.business.services.security_analyzer import SecurityAnalyzer
from src.crypto.encryption import EncryptionEngine
from src.database.db_manager import DatabaseManager
from src.exceptions import DatabaseError, VaultLockedError
from src.models import Category, CustomField, Entry, RawEntry
from tests.helpers import make_entry_manager, make_test_config, make_vault


@pytest.fixture()
def entry_mgr_env():
    """创建 VaultManager + EntryManager，返回 (entry_mgr, vault, tmp_dir)。"""
    tmp_dir = tempfile.mkdtemp()
    config = make_test_config(tmp_dir)
    vault = make_vault(config)
    vault.initialize("test_password_123")
    entry_mgr = make_entry_manager(vault)
    yield entry_mgr, vault, tmp_dir
    vault.close()
    shutil.rmtree(tmp_dir, ignore_errors=True)


def test_add_and_retrieve_entry(entry_mgr_env):
    """添加条目→解密获取→验证所有字段。"""
    entry_mgr, _vault, _tmp_dir = entry_mgr_env
    entry = Entry(
        title='测试网站',
        username='alice@example.com',
        password='Str0ng!P@ssw0rd',
        url='https://example.com',
        tags='测试,集成测试',
        notes='这是一条测试笔记',
        custom_fields=[
            CustomField(name='安全问题', value='小学名字', field_type='text'),
            CustomField(name='API Key', value='sk-12345', field_type='password'),
        ],
        entry_type='login',
        totp_secret='JBSWY3DPEHPK3PXP',
    )
    entry_id = entry_mgr.add_entry(entry)
    assert entry_id > 0

    # 获取并解密
    entries = entry_mgr.get_entries()
    assert len(entries) == 1

    decrypted = entries[0]
    assert decrypted.title == '测试网站'
    assert decrypted.username == 'alice@example.com'
    assert decrypted.password == 'Str0ng!P@ssw0rd'
    assert decrypted.url == 'https://example.com'
    assert decrypted.tags == '测试,集成测试'
    assert decrypted.notes == '这是一条测试笔记'
    assert decrypted.entry_type == 'login'
    assert decrypted.totp_secret == 'JBSWY3DPEHPK3PXP'

    # 验证自定义字段
    fields = decrypted.custom_fields
    assert isinstance(fields, list)
    assert len(fields) == 2
    assert fields[0].name == '安全问题'
    assert fields[0].value == '小学名字'
    assert fields[1].name == 'API Key'
    assert fields[1].value == 'sk-12345'


def test_update_preserves_password_history(entry_mgr_env):
    """更新密码→密码历史记录归档→验证旧密码可查。"""
    entry_mgr, _vault, _tmp_dir = entry_mgr_env
    # 1. 添加条目
    entry = Entry(
        title='历史记录测试',
        username='user1',
        password='OldPassword123!',
    )
    entry_id = entry_mgr.add_entry(entry)

    # 2. 修改密码
    entry = dataclasses.replace(entry, id=entry_id, password='NewPassword456!')
    entry_mgr.update_entry(entry)

    # 3. 查询密码历史，验证旧密码存在
    history = entry_mgr.password_history.get(entry_id)
    assert len(history) == 1

    # 解密历史记录中的旧密码
    decrypted_history = entry_mgr.password_history.decrypt(history)
    assert len(decrypted_history) == 1
    assert decrypted_history[0]['password'] == 'OldPassword123!'

    # 验证当前密码是新密码
    current = entry_mgr.get_entry(entry_id)
    assert current is not None
    assert current.password == 'NewPassword456!'


def test_search_by_username(entry_mgr_env):
    """搜索用户名能返回结果。"""
    entry_mgr, _vault, _tmp_dir = entry_mgr_env
    # 1. 添加两个 username 不同的条目
    entry_a = Entry(
        title='站点 A',
        username='alice@wonderland.com',
        password='P@ssw0rdA!',
    )
    entry_b = Entry(
        title='站点 B',
        username='bob@builder.com',
        password='P@ssw0rdB!',
    )
    entry_mgr.add_entry(entry_a)
    entry_mgr.add_entry(entry_b)

    # 2. 用 username 搜索
    results = entry_mgr.get_entry_summaries(search='alice')
    assert len(results) == 1
    assert results[0].username == 'alice@wonderland.com'

    # 搜索另一个
    results_b = entry_mgr.get_entry_summaries(search='bob')
    assert len(results_b) == 1
    assert results_b[0].username == 'bob@builder.com'

    # 搜索不存在的
    results_none = entry_mgr.get_entry_summaries(search='charlie')
    assert len(results_none) == 0


def test_toggle_favorite(entry_mgr_env):
    """切换收藏状态。"""
    entry_mgr, _vault, _tmp_dir = entry_mgr_env
    # 1. 添加条目
    entry = Entry(
        title='收藏测试',
        username='user_fav',
        password='Password123!',
    )
    entry_id = entry_mgr.add_entry(entry)

    # 2. 验证初始状态为非收藏
    entry_before = entry_mgr.get_entry(entry_id)
    assert entry_before is not None
    assert not entry_before.is_favorite

    # 3. toggle_favorite
    entry_mgr.toggle_favorite(entry_id)

    # 4. 获取条目验证 is_favorite 为 True
    entry_after = entry_mgr.get_entry(entry_id)
    assert entry_after is not None
    assert entry_after.is_favorite

    # 再次 toggle 应变回 False
    entry_mgr.toggle_favorite(entry_id)
    entry_final = entry_mgr.get_entry(entry_id)
    assert entry_final is not None
    assert not entry_final.is_favorite


def test_toggle_favorite_returns_new_state(entry_mgr_env):
    """toggle_favorite 应返回新的收藏状态。"""
    entry_mgr, _vault, _tmp_dir = entry_mgr_env
    entry = Entry(title='收藏返回值测试', username='fav_user', password='Password123!')
    entry_id = entry_mgr.add_entry(entry)

    # 初始状态应为非收藏
    new_state = entry_mgr.toggle_favorite(entry_id)
    assert new_state is True

    # 再次切换
    new_state = entry_mgr.toggle_favorite(entry_id)
    assert new_state is False


def test_toggle_favorite_nonexistent_returns_none(entry_mgr_env):
    """切换不存在条目的收藏状态应返回 None。"""
    entry_mgr, _vault, _tmp_dir = entry_mgr_env
    result = entry_mgr.toggle_favorite(99999)
    assert result is None


def test_get_all_tags(entry_mgr_env):
    """获取标签频率统计。"""
    entry_mgr, _vault, _tmp_dir = entry_mgr_env
    # 1. 添加多个带标签的条目
    entries_data = [
        Entry(title='E1', username='u1', password='P1!', tags='社交,邮箱'),
        Entry(title='E2', username='u2', password='P2!', tags='社交,工作'),
        Entry(title='E3', username='u3', password='P3!', tags='社交,邮箱,金融'),
    ]
    for e in entries_data:
        entry_mgr.add_entry(e)

    # 2. 调用 get_all_tags
    tags = entry_mgr.get_all_tags()

    # 3. 验证标签和频率正确
    tag_dict = dict(tags)
    assert tag_dict['社交'] == 3
    assert tag_dict['邮箱'] == 2
    assert tag_dict['工作'] == 1
    assert tag_dict['金融'] == 1


@pytest.fixture()
def vault_lifecycle_env():
    """创建临时目录和 config，返回 (config, tmp_dir)。"""
    tmp_dir = tempfile.mkdtemp()
    config = make_test_config(tmp_dir)
    yield config, tmp_dir
    shutil.rmtree(tmp_dir, ignore_errors=True)


def test_initialize_and_unlock(vault_lifecycle_env):
    """初始化→锁定→解锁→验证数据可读。"""
    config, _tmp_dir = vault_lifecycle_env
    master_pwd = "test_password_123"

    # 1. 初始化并添加条目
    vault = make_vault(config)
    assert vault.initialize(master_pwd)[0]
    assert vault.is_unlocked

    entry_mgr = make_entry_manager(vault)
    entry_id = entry_mgr.add_entry(Entry(
        title='持久化测试',
        username='persistent_user',
        password='PersistentP@ss!',
    ))
    assert entry_id > 0

    # 2. 锁定
    vault.lock()
    assert not vault.is_unlocked
    # MAINT-009：vault.key 锁定态 fail-fast（与 snapshot_key 对称），访问即抛 VaultLockedError
    with pytest.raises(VaultLockedError):
        _ = vault.key

    # 3. 解锁
    assert vault.unlock(master_pwd)[0]
    assert vault.is_unlocked
    assert vault.key is not None

    # 4. 验证数据可读
    entry_mgr2 = make_entry_manager(vault)
    entries = entry_mgr2.get_entries()
    assert len(entries) == 1
    assert entries[0].title == '持久化测试'
    assert entries[0].username == 'persistent_user'
    assert entries[0].password == 'PersistentP@ss!'

    # 用错误密码解锁应失败
    vault.lock()
    assert not vault.unlock("wrong_password")[0]

    vault.close()


def test_change_password_re_encrypts(vault_lifecycle_env):
    """改密后所有条目可用新密钥解密。"""
    config, _tmp_dir = vault_lifecycle_env
    old_pwd = "old_password_123"
    new_pwd = "new_password_456"

    # 1. 初始化 + 添加条目
    vault = make_vault(config)
    vault.initialize(old_pwd)
    entry_mgr = make_entry_manager(vault)

    totp_secret = 'JBSWY3DPEHPK3PXP'
    entry_id = entry_mgr.add_entry(Entry(
        title='改密测试',
        username='rekey_user',
        password='MySecretP@ss!',
        totp_secret=totp_secret,
    ))

    # 2. change_master_password
    assert vault.change_master_password(old_pwd, new_pwd)[0]

    # 3. 验证 get_entries 仍能正确解密
    entry_mgr2 = make_entry_manager(vault)
    entries = entry_mgr2.get_entries()
    assert len(entries) == 1
    assert entries[0].username == 'rekey_user'
    assert entries[0].password == 'MySecretP@ss!'

    # 4. 验证 totp_secret 也正确重加密
    assert entries[0].totp_secret == totp_secret

    # 5. 锁定后用新密码解锁，验证仍然可用
    vault.lock()
    assert vault.unlock(new_pwd)[0]
    entry_mgr3 = make_entry_manager(vault)
    entry = entry_mgr3.get_entry(entry_id)
    assert entry is not None
    assert entry.username == 'rekey_user'
    assert entry.password == 'MySecretP@ss!'
    assert entry.totp_secret == totp_secret

    # 6. 用旧密码解锁应失败
    vault.lock()
    assert not vault.unlock(old_pwd)[0]

    vault.close()


@pytest.fixture()
def backup_restore_env():
    """创建 VaultManager + EntryManager + BackupRestoreManager。"""
    tmp_dir = tempfile.mkdtemp()
    config = make_test_config(tmp_dir)
    vault = make_vault(config)
    vault.initialize("test_password_123")
    entry_mgr = make_entry_manager(vault)
    backup_mgr = BackupRestoreManager(vault, entry_mgr)
    yield entry_mgr, backup_mgr, vault, tmp_dir
    vault.close()
    shutil.rmtree(tmp_dir, ignore_errors=True)


def test_backup_and_restore_preserves_all_fields(backup_restore_env):
    """备份→恢复→验证 entry_type/totp/password_history 完整。"""
    entry_mgr, backup_mgr, _vault, tmp_dir = backup_restore_env
    # 1. 初始化并添加条目，包含 entry_type 与 totp_secret
    entry_id = entry_mgr.add_entry(Entry(
        title='备份测试',
        username='backup_user',
        password='OriginalP@ss!',
        entry_type='server',
        totp_secret='JBSWY3DPEHPK3PXP',
        tags='重要,服务器',
        notes='服务器凭据',
    ))

    # 2. 修改密码以产生历史记录
    entry = Entry(
        id=entry_id,
        title='备份测试',
        username='backup_user',
        password='UpdatedP@ss!',
        entry_type='server',
        totp_secret='JBSWY3DPEHPK3PXP',
        tags='重要,服务器',
        notes='服务器凭据',
    )
    entry_mgr.update_entry(entry)

    # 必须指定密码或使用快照密钥
    backup_path = str(Path(tmp_dir) / 'test_backup.cbox')
    assert backup_mgr.create_backup(backup_path, use_snapshot_key=True)
    assert os.path.exists(backup_path)

    # 4. 清空条目，通过恢复备份验证数据是否完整
    entry_mgr.permanent_delete_entry(entry_id)
    assert len(entry_mgr.get_entries()) == 0

    # 5. 恢复备份
    assert backup_mgr.restore_backup(backup_path)

    # 6. 验证所有字段完整
    entries = entry_mgr.get_entries()
    assert len(entries) == 1

    restored = entries[0]
    assert restored.title == '备份测试'
    assert restored.username == 'backup_user'
    assert restored.password == 'UpdatedP@ss!'
    assert restored.entry_type == 'server'
    assert restored.totp_secret == 'JBSWY3DPEHPK3PXP'
    assert restored.tags == '重要,服务器'
    assert restored.notes == '服务器凭据'

    # 验证密码历史恢复
    assert restored.id is not None
    history = entry_mgr.password_history.get(restored.id)
    decrypted_history = entry_mgr.password_history.decrypt(history)
    assert len(decrypted_history) == 1
    assert decrypted_history[0]['password'] == 'OriginalP@ss!'


def test_rejects_unknown_format(backup_restore_env):
    """仅接受 CipherBox 当前固定格式。"""
    _entry_mgr, backup_mgr, _vault, tmp_dir = backup_restore_env
    backup_path = str(Path(tmp_dir) / 'unknown_backup.cbox')
    with open(backup_path, 'wb') as f:
        f.write(b'CBOX-UNKNOWN')

    success, error = backup_mgr.restore_backup(backup_path)
    assert not success
    # BackupError 归一为固定友好文案；诊断记入日志，用户层文案含「格式」/「损坏」。
    assert '格式' in error or '损坏' in error


def test_snapshot_key_rotates_on_master_password_change(backup_restore_env):
    """改密时 snapshot_key 随主密钥轮换。

    旧 snapshot_key 加密的快照无法用轮换后的新 snapshot_key 恢复，以收缩
    历史明文泄漏面；改密后用新 snapshot_key 创建的快照仍可正常恢复。
    """
    entry_mgr, backup_mgr, vault, tmp_dir = backup_restore_env
    entry_mgr.add_entry(Entry(
        title='快照条目', password='SnapshotSecret!2026'
    ))
    old_backup_path = str(Path(tmp_dir) / 'old_snapshot.cbox')
    success, error = backup_mgr.create_backup(
        old_backup_path, use_snapshot_key=True
    )
    assert success, error

    assert vault.change_master_password(
        'test_password_123', 'NewMasterPassword!2026'
    )[0]

    # 旧 snapshot_key 加密的快照无法用新 snapshot_key 恢复
    success, error = backup_mgr.restore_backup(old_backup_path)
    assert not success
    assert '已损坏' in error or '密码错误' in error

    # 改密后用新 snapshot_key 创建的快照可正常恢复
    entry_mgr.add_entry(Entry(title='新条目', password='NewSecret!2026'))
    new_backup_path = str(Path(tmp_dir) / 'new_snapshot.cbox')
    success, error = backup_mgr.create_backup(
        new_backup_path, use_snapshot_key=True
    )
    assert success, error
    success, error = backup_mgr.restore_backup(new_backup_path)
    assert success, error


def test_unlock_after_master_change_verifies_vault_meta_mac(entry_mgr_env):
    """改密后 close → re-unlock 用新密码成功，验证 vault_meta_mac 用新域密钥重算且校验通过。

    守护审查 P1#2：改密流程 _re_encrypt_all 经 _meta_store.update 重算 vault_meta_mac
    （含新 key_epoch/salt/verify），unlock 时 compute_vault_meta_mac 用新域密钥比对——
    若 mac 用错域密钥或漏重算，unlock 会抛 VaultIntegrityError。间接验证条目 metadata_mac
    也用新域密钥重签（解锁后 get_entries 能正确解密与验签）。
    """
    entry_mgr, vault, _tmp_dir = entry_mgr_env
    entry_mgr.add_entry(Entry(title='改密前条目', username='u', password='p'))
    assert vault.change_master_password('test_password_123', 'NewMasterPassword!2026')[0]
    vault.close()
    success, error = vault.unlock('NewMasterPassword!2026')
    assert success, f'改密后解锁失败（vault_meta_mac 可能未用新域密钥重算）: {error}'
    # 改密后条目用新密钥重加密 + 重签 metadata_mac，解锁后可正确解密
    entries = entry_mgr.get_entries()
    assert any(e.title == '改密前条目' for e in entries)


@pytest.fixture()
def security_analyzer_env():
    """创建 VaultManager + EntryManager + SecurityAnalyzer。"""
    tmp_dir = tempfile.mkdtemp()
    config = make_test_config(tmp_dir)
    vault = make_vault(config)
    vault.initialize("test_password_123")
    entry_mgr = make_entry_manager(vault)
    analyzer = SecurityAnalyzer(vault, EntryCacheManager(vault))
    yield entry_mgr, analyzer, vault, tmp_dir
    vault.close()
    shutil.rmtree(tmp_dir, ignore_errors=True)


def test_full_analysis(security_analyzer_env):
    """full_analysis 一次性返回所有指标。"""
    entry_mgr, analyzer, _vault, _tmp_dir = security_analyzer_env
    shared_pwd = 'DuplicateP@ss!'
    # 弱密码
    entry_mgr.add_entry(Entry(
        title='弱条目',
        username='weak',
        password='123456',
    ))
    # 两个重复密码
    entry_mgr.add_entry(Entry(
        title='重复 A',
        username='dup_a',
        password=shared_pwd,
    ))
    entry_mgr.add_entry(Entry(
        title='重复 B',
        username='dup_b',
        password=shared_pwd,
    ))

    result = analyzer.full_analysis()

    # 验证返回结构完整
    assert 'total' in result
    assert 'weak_count' in result
    assert 'weak_entries' in result
    assert 'duplicate_groups' in result
    assert 'duplicate_count' in result
    assert 'old_entries' in result
    assert 'old' in result

    assert result['total'] == 3
    assert result['weak_count'] >= 1
    # 2 个重复密码中计为 1 个多余项
    assert result['duplicate_count'] == 1


@pytest.fixture()
def db_env():
    """创建 DatabaseManager。"""
    tmp_dir = tempfile.mkdtemp()
    db_path = Path(tmp_dir) / 'test_vault.db'
    db = DatabaseManager(db_path, test_mode=True)
    db.open()
    db.init_tables()
    yield db, tmp_dir
    db.close()
    shutil.rmtree(tmp_dir, ignore_errors=True)


def test_transaction_commit(db_env):
    """begin→多个操作→commit，所有变更持久化。"""
    db, _tmp_dir = db_env
    initial_count = db.get_entry_count()

    db.begin_transaction()
    try:
        # custom_fields 必须为字符串，不能为 list
        e1 = RawEntry(title='事务条目1', username='tx_user1', password='tx_pwd1',
                    notes='', custom_fields='')
        e2 = RawEntry(title='事务条目2', username='tx_user2', password='tx_pwd2',
                    notes='', custom_fields='')
        db.add_entry(e1)
        db.add_entry(e2)

        # 添加分类
        cat = Category(name='事务分类', icon_char='🔧', color='#FF0000')
        db.add_category(cat)

        db.commit_transaction()
    except Exception:
        db.rollback_transaction()
        raise

    # 验证所有变更已持久化
    assert db.get_entry_count() == initial_count + 2
    categories = db.get_categories()
    cat_names = [c.name for c in categories]
    assert '事务分类' in cat_names


def test_transaction_rollback(db_env):
    """begin→多个操作→rollback，所有变更丢弃。"""
    db, _tmp_dir = db_env
    initial_count = db.get_entry_count()

    db.begin_transaction()
    try:
        e = RawEntry(title='回滚条目', username='rb_user', password='rb_pwd',
                  notes='', custom_fields='')
        db.add_entry(e)

        # 添加分类
        cat = Category(name='回滚分类', icon_char='🔙', color='#000000')
        db.add_category(cat)

        # 回滚
        db.rollback_transaction()
    except Exception:
        db.rollback_transaction()
        raise

    # 验证所有变更已丢弃
    assert db.get_entry_count() == initial_count
    categories = db.get_categories()
    cat_names = [c.name for c in categories]
    assert '回滚分类' not in cat_names


@pytest.fixture()
def import_export_env():
    """创建 VaultManager + EntryManager + ImportExportManager。"""
    tmpdir = tempfile.mkdtemp()
    config = make_test_config(tmpdir)
    vault = make_vault(config)
    vault.initialize("test_password_123")
    entry_mgr = make_entry_manager(vault)
    import_export = ImportExportManager(entry_mgr)
    yield entry_mgr, import_export, vault, tmpdir
    vault.close()
    shutil.rmtree(tmpdir)


def test_json_roundtrip(import_export_env):
    """JSON 导出→导入→数据完整。"""
    entry_mgr, import_export, _vault, tmpdir = import_export_env
    # 1. 添加条目
    entry = Entry(
        title='导入导出测试',
        username='export_user@example.com',
        password='ExportP@ss123!',
        url='https://export.example.com',
        tags='导入,导出',
        notes='测试笔记',
    )
    entry_id = entry_mgr.add_entry(entry)
    assert entry_id > 0

    # 2. 导出 JSON
    entries = entry_mgr.get_entries()
    json_path = str(Path(tmpdir) / 'export.json')
    import_export.export_to_json(
        json_path, entries, include_password=True
    )
    assert os.path.exists(json_path)

    # 3. 删除条目
    entry_mgr.permanent_delete_entry(entry_id)
    assert len(entry_mgr.get_entries()) == 0

    # 4. 导入 JSON
    count = import_export.import_file(json_path, 'json')
    assert count == 1

    # 5. 验证数据完整
    restored = entry_mgr.get_entries()
    assert len(restored) == 1
    assert restored[0].title == '导入导出测试'
    assert restored[0].username == 'export_user@example.com'
    assert restored[0].password == 'ExportP@ss123!'
    assert restored[0].url == 'https://export.example.com'
    assert restored[0].tags == '导入,导出'
    assert restored[0].notes == '测试笔记'


def test_csv_roundtrip(import_export_env):
    """CSV 导出→导入→基本字段保留。"""
    entry_mgr, import_export, _vault, tmpdir = import_export_env
    # 1. 添加条目
    entry = Entry(
        title='CSV测试条目',
        username='csv_user@example.com',
        password='CsvP@ss456!',
        url='https://csv.example.com',
        tags='csv,测试',
        notes='CSV笔记',
    )
    entry_id = entry_mgr.add_entry(entry)
    assert entry_id > 0

    # 2. 导出 CSV
    entries = entry_mgr.get_entries()
    csv_path = str(Path(tmpdir) / 'export.csv')
    import_export.export_to_csv(
        csv_path, entries, include_password=True
    )
    assert os.path.exists(csv_path)

    # 3. 删除条目
    entry_mgr.permanent_delete_entry(entry_id)
    assert len(entry_mgr.get_entries()) == 0

    # 4. 导入 CSV
    count = import_export.import_file(csv_path, 'csv')
    assert count == 1

    # 5. 验证 title、username、url 等基本字段
    restored = entry_mgr.get_entries()
    assert len(restored) == 1
    assert restored[0].title == 'CSV测试条目'
    assert restored[0].username == 'csv_user@example.com'
    assert restored[0].url == 'https://csv.example.com'


def test_decrypt_with_wrong_key():
    """用错误密钥解密应抛出 ValueError。"""
    key1 = os.urandom(32)
    key2 = os.urandom(32)

    aad = 'test:integration'
    ciphertext = EncryptionEngine.encrypt("hello", key1, aad)
    assert ciphertext != ''

    # AES-GCM 会因 tag 校验失败而抛出 ValueError
    with pytest.raises(ValueError):
        EncryptionEngine.decrypt(ciphertext, key2, aad)


def test_backup_with_locked_vault():
    """锁定状态创建备份应失败。"""
    tmp_dir = tempfile.mkdtemp()
    config = make_test_config(tmp_dir)
    vault = make_vault(config)
    vault.initialize("test_password_123")
    backup_mgr = BackupRestoreManager(vault, make_entry_manager(vault))

    # 锁定保险库
    vault.lock()
    assert not vault.is_unlocked

    # 锁定状态下创建备份应返回失败及错误信息
    backup_path = str(Path(tmp_dir) / 'locked_backup.cbox')
    result = backup_mgr.create_backup(backup_path)
    assert not result[0]
    assert len(result[1]) > 0

    vault.close()
    shutil.rmtree(tmp_dir)


def test_change_password_wrong_old():
    """旧密码错误时改密应失败。"""
    tmp_dir = tempfile.mkdtemp()
    config = make_test_config(tmp_dir)
    vault = make_vault(config)
    vault.initialize("OriginalMaster!2026")

    # 用错误的旧密码改密应返回 False
    result = vault.change_master_password(
        "WrongOldMaster!2026", "NewMasterPassword!2026"
    )
    assert not result[0]

    # 验证原密码仍然可用
    vault.lock()
    assert vault.unlock("OriginalMaster!2026")[0]

    vault.close()
    shutil.rmtree(tmp_dir)


def test_ensure_db_open_raises_when_db_cannot_open():
    """ensure_db_open 在 DB 打开失败时应抛 DatabaseError（命令-查询分离，ARCH-004）。

    is_initialized 现为纯查询，打开数据库的副作用与失败判定移至 ensure_db_open 命令侧：
    打开失败时显式抛 DatabaseError 而非静默降级，避免调用方误判为未初始化。
    """
    tmp_dir = tempfile.mkdtemp()
    config = make_test_config(tmp_dir)
    vault = make_vault(config)

    # 确保 db_path 存在使文件检查通过
    db_file = Path(tmp_dir) / 'vault.db'
    db_file.touch()

    # 让 is_open 返回 False、open() 返回 False，模拟数据库无法打开
    with patch.object(type(vault._db), 'is_open', new_callable=PropertyMock, return_value=False):
        with patch.object(vault._db, 'open', return_value=False):
            with pytest.raises(DatabaseError):
                vault.ensure_db_open()

    vault.close()
    shutil.rmtree(tmp_dir)
