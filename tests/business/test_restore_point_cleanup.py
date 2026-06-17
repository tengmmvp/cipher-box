"""恢复点启动重试清理测试。

验证 VaultManager.purge_restore_points 删除残留的 pre_restore_*.cbox 恢复点，
收缩历史明文泄漏面。恢复点为恢复操作前的临时全量明文快照，恢复成功后应删除；
之前因文件占用 purge 失败的残留在应用启动时重试清理。
"""
from src.business.managers.vault_manager import VaultManager


class TestRestorePointCleanup:
    """验证恢复点启动重试清理逻辑。"""

    def test_purge_removes_restore_points(self, vault_config):
        vault = VaultManager(vault_config)
        vault.initialize("test_password_12345")
        try:
            backups_dir = vault.data_dir / 'backups'
            backups_dir.mkdir(parents=True, exist_ok=True)
            # 模拟之前 purge 失败残留的恢复点（含恢复前全部条目明文）
            restore_point = backups_dir / 'pre_restore_abc123.cbox'
            restore_point.write_bytes(b'fake restore point payload')
            assert restore_point.exists()

            failed = vault.purge_restore_points()

            assert failed == []
            assert not restore_point.exists()
        finally:
            vault.close()

    def test_purge_keeps_regular_snapshots(self, vault_config):
        """purge_restore_points 仅清理 pre_restore_*，不动 cipherbox_snapshot_*。

        cipherbox_snapshot_* 可能为有效的定期自动快照，不应被启动清理删除。
        """
        vault = VaultManager(vault_config)
        vault.initialize("test_password_12345")
        try:
            backups_dir = vault.data_dir / 'backups'
            backups_dir.mkdir(parents=True, exist_ok=True)
            restore_point = backups_dir / 'pre_restore_xyz.cbox'
            snapshot = backups_dir / 'cipherbox_snapshot_keep.cbox'
            restore_point.write_bytes(b'restore point')
            snapshot.write_bytes(b'auto snapshot')

            vault.purge_restore_points()

            assert not restore_point.exists()
            assert snapshot.exists()  # 自动快照不受影响
        finally:
            vault.close()

    def test_purge_missing_directory_is_noop(self, vault_config):
        """backups 目录不存在时安全无操作，返回空失败列表。"""
        vault = VaultManager(vault_config)
        vault.initialize("test_password_12345")
        try:
            failed = vault.purge_restore_points()
            assert failed == []
        finally:
            vault.close()
