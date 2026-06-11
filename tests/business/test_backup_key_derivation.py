"""备份密钥派生测试 — 验证备份密钥 HMAC 派生"""

import hashlib
import hmac
import os
import tempfile
from pathlib import Path

import pytest

from src.business.managers.vault_manager import VaultManager
from tests.helpers import make_test_config


def _make_config(tmp_dir: str):
    return make_test_config(tmp_dir)


@pytest.fixture()
def vault_and_key():
    """创建并初始化 VaultManager，返回 (vault, key, tmp_dir)"""
    tmp_dir = tempfile.mkdtemp()
    config = _make_config(tmp_dir)
    vault = VaultManager(config)
    vault.initialize('test_backup_key')
    key = vault.key
    assert key is not None
    yield vault, key, tmp_dir
    vault.close()


def test_hmac_deterministic(vault_and_key):
    """相同密钥和 salt 应产生相同的派生密钥"""
    _vault, key, _tmp_dir = vault_and_key
    salt = os.urandom(16)
    k1 = hmac.new(
        key, b'cipherbox:backup-key-v1' + salt, hashlib.sha256
    ).digest()
    k2 = hmac.new(
        key, b'cipherbox:backup-key-v1' + salt, hashlib.sha256
    ).digest()
    assert k1 == k2


def test_different_salt_produces_different_key(vault_and_key):
    """不同 salt 应产生不同的派生密钥"""
    _vault, key, _tmp_dir = vault_and_key
    salt1 = os.urandom(16)
    salt2 = os.urandom(16)
    k1 = hmac.new(
        key, b'cipherbox:backup-key-v1' + salt1, hashlib.sha256
    ).digest()
    k2 = hmac.new(
        key, b'cipherbox:backup-key-v1' + salt2, hashlib.sha256
    ).digest()
    assert k1 != k2


def test_different_master_key_produces_different_backup_key(vault_and_key):
    """不同主密钥应产生不同的备份密钥"""
    _vault, key, _tmp_dir = vault_and_key
    salt = os.urandom(16)
    key2 = os.urandom(32)
    k1 = hmac.new(
        key, b'cipherbox:backup-key-v1' + salt, hashlib.sha256
    ).digest()
    k2 = hmac.new(
        key2, b'cipherbox:backup-key-v1' + salt, hashlib.sha256
    ).digest()
    assert k1 != k2


def test_create_and_restore_non_password_backup(vault_and_key):
    """端到端验证：非密码备份的创建和恢复"""
    vault, _key, tmp_dir = vault_and_key
    from src.business.managers.backup_restore import BackupRestoreManager
    from src.business.managers.entry_manager import EntryManager
    from src.models import Entry

    entry_mgr = EntryManager(vault)
    # 创建测试条目
    entry = Entry(title='备份测试', username='user', password='secret123')
    entry_id = entry_mgr.add_entry(entry)

    # 创建快照密钥备份
    backup_mgr = BackupRestoreManager(vault)
    backup_path = Path(tmp_dir) / 'test_backup.cbbox'
    success, msg = backup_mgr.create_backup(str(backup_path), use_snapshot_key=True)
    assert success, f'备份创建失败: {msg}'
    assert backup_path.exists()

    # 检查备份
    info = backup_mgr.inspect_backup(str(backup_path))
    assert info is not None
    assert not info.get('password_required', True)  # 非密码备份

    # 删除条目后恢复
    entry_mgr.delete_entry(entry_id)  # 软删除
    entry_mgr.permanent_delete_entry(entry_id)  # 永久删除
    assert entry_mgr.get_entry_count(include_deleted=True) == 0

    success, msg = backup_mgr.restore_backup(str(backup_path))
    assert success, f'恢复失败: {msg}'
    assert entry_mgr.get_entry_count(include_deleted=False) == 1


def test_create_without_password_or_snapshot_rejected(vault_and_key):
    """不指定备份密码且不使用快照密钥时，创建应被拒绝。"""
    vault, _key, tmp_dir = vault_and_key
    from src.business.managers.backup_restore import BackupRestoreManager
    backup_mgr = BackupRestoreManager(vault)
    backup_path = Path(tmp_dir) / 'rejected_backup.cbbox'
    success, _ = backup_mgr.create_backup(str(backup_path))
    assert not success
    assert not backup_path.exists()
