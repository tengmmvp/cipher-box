"""备份密钥派生测试。

验证 MasterKeyManager.derive_backup_key 基于 Argon2id 从备份密码派生密钥的
确定性、salt 与密码变更下的差异化输出，以及与主密钥域的分离；并端到端
验证非密码备份的创建与恢复流程。
"""

import os
from pathlib import Path

import pytest

from src.crypto.master_key import MasterKeyManager
from tests.helpers import make_entry_manager, make_test_config, make_vault


def _make_config(tmp_dir):
    return make_test_config(tmp_dir)


@pytest.fixture()
def vault_and_key(tmp_path):
    """创建并初始化 VaultManager，返回 vault、key、tmp_dir 三元组。

    tmp_dir 由 pytest ``tmp_path`` 提供（Path 类型）并自动清理，无需手动删除。
    """
    tmp_dir = tmp_path
    config = _make_config(tmp_dir)
    vault = make_vault(config)
    vault.initialize('TestBackupKey!2026')
    key = vault.key
    assert key is not None
    yield vault, key, tmp_dir
    vault.close()


def test_derive_backup_key_deterministic():
    """相同备份密码与 salt 应派生出相同的备份密钥。"""
    salt = os.urandom(32)
    k1 = MasterKeyManager.derive_backup_key('backup_pw', salt)
    k2 = MasterKeyManager.derive_backup_key('backup_pw', salt)
    assert k1 == k2
    assert len(k1) == 32


def test_derive_backup_key_different_salt():
    """不同 salt 应派生出不同的备份密钥。"""
    pwd = 'backup_pw'
    assert (
        MasterKeyManager.derive_backup_key(pwd, os.urandom(32))
        != MasterKeyManager.derive_backup_key(pwd, os.urandom(32))
    )


def test_derive_backup_key_different_password():
    """不同备份密码应派生出不同的备份密钥。"""
    salt = os.urandom(32)
    assert (
        MasterKeyManager.derive_backup_key('pw_a', salt)
        != MasterKeyManager.derive_backup_key('pw_b', salt)
    )


def test_derive_backup_key_isolated_from_master_key():
    """备份密钥与主密钥域分离：相同 password+salt 下两者不同。

    derive_backup_key 与 derive_key 共享同一 Argon2id 主材料，但经不同 HKDF
    info（_DOMAIN_INFO_BACKUP vs _DOMAIN_INFO_MASTER）派生，HKDF 保证不同 info
    → 输出独立——即便备份密码与主密码相同、salt 相同，派生结果也不同，
    避免备份密钥泄露等价于主密钥泄露。
    """
    salt = os.urandom(32)
    backup_key = MasterKeyManager.derive_backup_key('same_pw', salt)
    master_key = MasterKeyManager.derive_key('same_pw', salt)
    assert backup_key != master_key


def test_create_and_restore_non_password_backup(vault_and_key):
    """端到端验证：非密码备份的创建和恢复。"""
    vault, _key, tmp_dir = vault_and_key
    from src.business.managers.backup_restore import BackupRestoreManager
    from src.models import Entry

    entry_mgr = make_entry_manager(vault)
    entry = Entry(title='备份测试', username='user', password='secret123')
    entry_id = entry_mgr.add_entry(entry)

    backup_mgr = BackupRestoreManager(vault, entry_mgr)
    backup_path = Path(tmp_dir) / 'test_backup.cbbox'
    success, msg = backup_mgr.create_backup(str(backup_path), use_snapshot_key=True)
    assert success, f'备份创建失败: {msg}'
    assert backup_path.exists()

    from src.business.services.backup_header_codec import inspect_backup

    info = inspect_backup(str(backup_path))
    assert info is not None
    # 快照密钥备份不要求用户提供密码
    assert not info.get('password_required', True)

    # 先软删除再永久删除，使保险库清空
    entry_mgr.delete_entry(entry_id)
    entry_mgr.permanent_delete_entry(entry_id)
    assert entry_mgr.get_entry_count(include_deleted=True) == 0

    success, msg = backup_mgr.restore_backup(str(backup_path))
    assert success, f'恢复失败: {msg}'
    assert entry_mgr.get_entry_count(include_deleted=False) == 1


def test_create_without_password_or_snapshot_rejected(vault_and_key):
    """不指定备份密码且不使用快照密钥时，创建应被拒绝。"""
    vault, _key, tmp_dir = vault_and_key
    from src.business.managers.backup_restore import BackupRestoreManager
    backup_mgr = BackupRestoreManager(vault, make_entry_manager(vault))
    backup_path = Path(tmp_dir) / 'rejected_backup.cbbox'
    success, _ = backup_mgr.create_backup(str(backup_path))
    assert not success
    assert not backup_path.exists()


def test_derive_key_rejects_short_or_empty_salt():
    """derive_key 拒绝空盐或过短盐，防止 Argon2id 退化为弱派生。"""
    with pytest.raises(ValueError):
        MasterKeyManager.derive_key('pw', b'')
    with pytest.raises(ValueError):
        MasterKeyManager.derive_key('pw', b'short')  # 5 字节 < MIN_SALT_SIZE

    # 合法长度盐正常派生 32 字节密钥
    key = MasterKeyManager.derive_key('pw', os.urandom(32))
    assert len(key) == 32


def test_derive_backup_key_rejects_empty_salt():
    """derive_backup_key 经 _derive_master_material 校验盐最小长度，空盐应拒绝。"""
    with pytest.raises(ValueError):
        MasterKeyManager.derive_backup_key('pw', b'')
