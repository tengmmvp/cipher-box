"""备份恢复边界场景测试 — 损坏文件、截断数据、超大备份等"""

import os
import shutil
import struct
import tempfile
from pathlib import Path

import pytest

from src.business.managers.backup_restore import (
    BACKUP_FORMAT,
    BACKUP_MAGIC,
    MAX_BACKUP_FILE_SIZE,
    MAX_BACKUP_PAYLOAD_SIZE,
    BackupRestoreManager,
)
from src.business.managers.entry_manager import EntryManager
from src.business.managers.vault_manager import VaultManager
from src.crypto.encryption import EncryptionEngine
from src.database.models import Entry


class TestBackupCorruption:
    """备份文件损坏边界场景"""

    @pytest.fixture(autouse=True)
    def setup_vault(self, tmp_path, vault_config):
        self._tmp_dir = str(tmp_path)
        self._vault = VaultManager(vault_config)
        self._vault.initialize("test_password_12345")
        self._entry_mgr = EntryManager(self._vault)
        self._backup_mgr = BackupRestoreManager(self._vault)
        # 添加一些测试数据
        self._entry_mgr.add_entry(Entry(
            title='测试条目', username='user1', password='pass123',
            url='https://example.com', notes='备注', entry_type='login',
        ))
        yield
        self._vault.close()

    def _create_valid_backup(self, filepath: str, password: str = 'backup_pwd'):
        """创建一个有效的密码保护备份"""
        success, error = self._backup_mgr.create_backup(filepath, password)
        assert success, f'创建备份失败: {error}'
        return filepath

    def test_rejects_truncated_backup(self):
        """截断的备份文件应被拒绝"""
        path = os.path.join(self._tmp_dir, 'truncated.cbox')
        self._create_valid_backup(path)
        # 截断文件到一半
        full_size = os.path.getsize(path)
        with open(path, 'r+b') as f:
            f.truncate(full_size // 2)
        success, error = self._backup_mgr.restore_backup(path, 'backup_pwd')
        assert not success
        assert '损坏' in error

    def test_rejects_corrupted_magic_bytes(self):
        """损坏的 magic bytes 应被拒绝"""
        path = os.path.join(self._tmp_dir, 'bad_magic.cbox')
        with open(path, 'wb') as f:
            f.write(b'CORRUPTED_HEADER\x00')
            f.write(b'\x00' * 100)
        success, error = self._backup_mgr.restore_backup(path)
        assert not success

    def test_rejects_empty_file(self):
        """空文件应被拒绝"""
        path = os.path.join(self._tmp_dir, 'empty.cbox')
        Path(path).write_bytes(b'')
        success, error = self._backup_mgr.restore_backup(path)
        assert not success

    def test_rejects_random_bytes(self):
        """随机字节数据应被拒绝"""
        path = os.path.join(self._tmp_dir, 'random.cbox')
        Path(path).write_bytes(os.urandom(256))
        success, error = self._backup_mgr.restore_backup(path)
        assert not success

    def test_rejects_wrong_backup_password(self):
        """错误的备份密码应被拒绝"""
        path = os.path.join(self._tmp_dir, 'wrong_pwd.cbox')
        self._create_valid_backup(path, 'correct_password')
        success, error = self._backup_mgr.restore_backup(path, 'wrong_password')
        assert not success

    def test_rejects_password_required_backup_without_password(self):
        """需要密码的备份但未提供密码应被拒绝"""
        path = os.path.join(self._tmp_dir, 'no_pwd.cbox')
        self._create_valid_backup(path, 'some_password')
        success, error = self._backup_mgr.restore_backup(path, None)
        assert not success

    def test_inspect_backup_returns_correct_info(self):
        """inspect_backup 应返回正确的备份信息"""
        path = os.path.join(self._tmp_dir, 'inspect.cbox')
        self._create_valid_backup(path, 'test_password')
        info = BackupRestoreManager.inspect_backup(path)
        assert info['password_required']
        assert not info['snapshot_required']

    def test_inspect_snapshot_backup(self):
        """检查快照备份应标记为 snapshot_required"""
        path = os.path.join(self._tmp_dir, 'snapshot.cbox')
        success, error = self._backup_mgr.create_backup(path, use_snapshot_key=True)
        assert success, f'快照备份失败: {error}'
        info = BackupRestoreManager.inspect_backup(path)
        assert not info['password_required']
        assert info['snapshot_required']

    def test_restore_and_verify_data_integrity(self):
        """恢复后数据应与原始数据一致"""
        # 创建备份
        path = os.path.join(self._tmp_dir, 'verify.cbox')
        self._create_valid_backup(path, 'verify_pwd')

        # 获取原始数据
        original = self._entry_mgr.get_entries()[0]

        # 恢复备份
        success, error = self._backup_mgr.restore_backup(path, 'verify_pwd')
        assert success, f'恢复失败: {error}'

        # 验证恢复后的数据
        restored = self._entry_mgr.get_entries()[0]
        assert restored.title == original.title
        assert restored.username == original.username
        assert restored.password == original.password
        assert restored.url == original.url
        assert restored.notes == original.notes

    def test_inspect_rejects_unknown_flags(self):
        """包含未知标志的备份应被拒绝"""
        path = os.path.join(self._tmp_dir, 'bad_flags.cbox')
        with open(path, 'wb') as f:
            f.write(BACKUP_MAGIC)
            f.write(struct.pack('<B', 0xFF))  # 无效标志
        with pytest.raises(ValueError):
            BackupRestoreManager.inspect_backup(path)

    def test_backup_with_snapshot_key(self):
        """使用快照密钥的备份应可恢复"""
        path = os.path.join(self._tmp_dir, 'snapshot_restore.cbox')
        success, error = self._backup_mgr.create_backup(path, use_snapshot_key=True)
        assert success, f'快照备份失败: {error}'

        success, error = self._backup_mgr.restore_backup(path)
        assert success, f'快照恢复失败: {error}'

    def test_backup_preserves_deleted_entries(self):
        """备份应保留已删除的条目"""
        entry_id = self._entry_mgr.add_entry(Entry(
            title='将被删除', username='u', password='p', entry_type='login',
        ))
        self._entry_mgr.delete_entry(entry_id)

        path = os.path.join(self._tmp_dir, 'with_deleted.cbox')
        self._create_valid_backup(path, 'pwd')

        success, error = self._backup_mgr.restore_backup(path, 'pwd')
        assert success, f'恢复失败: {error}'

        # 验证已删除条目也被恢复
        all_entries = self._entry_mgr.get_entries(include_deleted=True)
        deleted = [e for e in all_entries if e.is_deleted]
        assert len(deleted) >= 1


class TestBackupSizeLimits:
    """备份大小限制测试"""

    def test_inspect_rejects_oversized_file(self):
        """过大的备份文件应被拒绝"""
        path = os.path.join(tempfile.mkdtemp(), 'huge.cbox')
        try:
            # 创建一个超过限制的假文件（仅头部正确）
            with open(path, 'wb') as f:
                f.write(BACKUP_MAGIC)
                f.write(b'\x00' * (MAX_BACKUP_FILE_SIZE + 1))
            with pytest.raises(ValueError):
                BackupRestoreManager.inspect_backup(path)
        finally:
            Path(path).unlink(missing_ok=True)
            os.rmdir(os.path.dirname(path))


class TestAADCentralization:
    """验证 AAD 集中化 — crypto_utils.entry_aad 是唯一来源"""

    def test_entry_aad_format(self):
        from src.business.services.crypto_utils import entry_aad
        aad = entry_aad('abc123', 'password')
        assert aad == 'entry:abc123:password'

    def test_entry_aad_different_fields(self):
        from src.business.services.crypto_utils import entry_aad
        aad1 = entry_aad('id1', 'username')
        aad2 = entry_aad('id1', 'password')
        assert aad1 != aad2

    def test_entry_aad_different_crypto_ids(self):
        from src.business.services.crypto_utils import entry_aad
        aad1 = entry_aad('id1', 'password')
        aad2 = entry_aad('id2', 'password')
        assert aad1 != aad2
