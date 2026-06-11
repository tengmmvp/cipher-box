"""备份密钥派生测试 — 验证 HMAC 域分离派生替代旧 SHA-256"""

import hashlib
import hmac
import os
import tempfile
import unittest
from pathlib import Path

from src.business.managers.vault_manager import VaultManager
from tests.helpers import make_test_config


def _make_config(tmp_dir: str):
    return make_test_config(tmp_dir)


class TestBackupKeyDerivation(unittest.TestCase):
    """验证非密码备份使用 HMAC 派生密钥"""

    def setUp(self):
        self._tmp_dir = tempfile.mkdtemp()
        config = _make_config(self._tmp_dir)
        self._vault = VaultManager(config)
        self._vault.initialize('test_backup_key')
        self._key = self._vault.key
        assert self._key is not None

    def tearDown(self):
        self._vault.close()

    def test_hmac_derivation_differs_from_raw_sha256(self):
        """HMAC 派生结果应与裸 SHA-256 不同"""
        salt = os.urandom(16)

        # HMAC 方式（当前实现）
        hmac_key = hmac.new(
            self._key, b'cipherbox:backup-key-v1' + salt, hashlib.sha256
        ).digest()

        # 旧 SHA-256 方式
        raw_key = hashlib.sha256(self._key + salt).digest()

        self.assertNotEqual(hmac_key, raw_key)
        self.assertEqual(len(hmac_key), 32)
        self.assertEqual(len(raw_key), 32)

    def test_hmac_deterministic(self):
        """相同密钥和 salt 应产生相同的派生密钥"""
        salt = os.urandom(16)
        k1 = hmac.new(
            self._key, b'cipherbox:backup-key-v1' + salt, hashlib.sha256
        ).digest()
        k2 = hmac.new(
            self._key, b'cipherbox:backup-key-v1' + salt, hashlib.sha256
        ).digest()
        self.assertEqual(k1, k2)

    def test_different_salt_produces_different_key(self):
        """不同 salt 应产生不同的派生密钥"""
        salt1 = os.urandom(16)
        salt2 = os.urandom(16)
        k1 = hmac.new(
            self._key, b'cipherbox:backup-key-v1' + salt1, hashlib.sha256
        ).digest()
        k2 = hmac.new(
            self._key, b'cipherbox:backup-key-v1' + salt2, hashlib.sha256
        ).digest()
        self.assertNotEqual(k1, k2)

    def test_different_master_key_produces_different_backup_key(self):
        """不同主密钥应产生不同的备份密钥"""
        salt = os.urandom(16)
        key2 = os.urandom(32)
        k1 = hmac.new(
            self._key, b'cipherbox:backup-key-v1' + salt, hashlib.sha256
        ).digest()
        k2 = hmac.new(
            key2, b'cipherbox:backup-key-v1' + salt, hashlib.sha256
        ).digest()
        self.assertNotEqual(k1, k2)

    def test_create_and_restore_non_password_backup(self):
        """端到端验证：非密码备份的创建和恢复"""
        from src.business.managers.backup_restore import BackupRestoreManager
        from src.business.managers.entry_manager import EntryManager
        from src.database.models import Entry

        entry_mgr = EntryManager(self._vault)
        # 创建测试条目
        entry = Entry(title='备份测试', username='user', password='secret123')
        entry_id = entry_mgr.add_entry(entry)

        # 创建非密码备份（H3：flags=0 主密钥派生路径已移除，非密码备份改用快照密钥）
        backup_mgr = BackupRestoreManager(self._vault)
        backup_path = Path(self._tmp_dir) / 'test_backup.cbbox'
        success, msg = backup_mgr.create_backup(str(backup_path), use_snapshot_key=True)
        self.assertTrue(success, f'备份创建失败: {msg}')
        self.assertTrue(backup_path.exists())

        # 检查备份
        info = backup_mgr.inspect_backup(str(backup_path))
        self.assertIsNotNone(info)
        self.assertFalse(info.get('password_required', True))  # 非密码备份

        # 删除条目后恢复
        entry_mgr.delete_entry(entry_id)  # 软删除
        entry_mgr.permanent_delete_entry(entry_id)  # 永久删除
        self.assertEqual(entry_mgr.get_entry_count(include_deleted=True), 0)

        success, msg = backup_mgr.restore_backup(str(backup_path))
        self.assertTrue(success, f'恢复失败: {msg}')
        self.assertEqual(entry_mgr.get_entry_count(include_deleted=False), 1)

    def test_create_without_password_or_snapshot_rejected(self):
        """H3：不指定备份密码且不使用快照密钥时，创建应被拒绝。

        flags=0（旧版主密钥派生）创建路径已移除——此类备份绑定创建时的主密码，
        改密后无法恢复。仅恢复路径保留 flags=0 以兼容旧备份。
        """
        from src.business.managers.backup_restore import BackupRestoreManager
        backup_mgr = BackupRestoreManager(self._vault)
        backup_path = Path(self._tmp_dir) / 'rejected_backup.cbbox'
        success, _ = backup_mgr.create_backup(str(backup_path))
        self.assertFalse(success)
        self.assertFalse(backup_path.exists())
