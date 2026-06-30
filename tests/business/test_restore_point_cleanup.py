"""恢复点启动重试清理测试。

验证 VaultManager.purge_restore_points 删除残留的 pre_restore_*.cbox 恢复点，
收缩历史明文泄漏面。恢复点为恢复操作前的临时全量明文快照，恢复成功后应删除；
之前因文件占用 purge 失败的残留在应用启动时重试清理。
"""
from pathlib import Path

from src.business.managers.restore_point_manager import RestorePointManager
from tests.helpers import make_vault


class TestRestorePointCleanup:
    """验证恢复点启动重试清理逻辑。"""

    def test_purge_removes_restore_points(self, vault_config):
        vault = make_vault(vault_config)
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
        vault = make_vault(vault_config)
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
        vault = make_vault(vault_config)
        vault.initialize("test_password_12345")
        try:
            failed = vault.purge_restore_points()
            assert failed == []
        finally:
            vault.close()

    def test_clear_all_removes_restore_points_and_returns_count(self, vault_config):
        """RestorePointManager.clear_all 删除全部 pre_restore_* 并返回删除数。

        恢复点含恢复前全部条目明文，是泄漏面最大的产物；clear_all 是 UI 手动
        清理的唯一入口，须有回归守护其「真删除 + 计数正确」契约，防止 glob
        模式漂移或返回值语义变化导致「用户以为已清理实则残留」的假阳性安全。
        """
        vault = make_vault(vault_config)
        vault.initialize("test_password_12345")
        try:
            backups_dir = vault.data_dir / 'backups'
            backups_dir.mkdir(parents=True, exist_ok=True)
            for i in range(3):
                (backups_dir / f'pre_restore_{i}.cbox').write_bytes(b'restore point payload')

            mgr = RestorePointManager(vault)
            assert mgr.count() == 3

            deleted = mgr.clear_all()

            assert deleted == 3
            assert mgr.count() == 0
            assert not any(backups_dir.glob('pre_restore_*.cbox'))
        finally:
            vault.close()

    def test_clear_all_preserves_snapshots(self, vault_config):
        """clear_all 仅清理 pre_restore_*，保留定期自动快照 cipherbox_snapshot_*。"""
        vault = make_vault(vault_config)
        vault.initialize("test_password_12345")
        try:
            backups_dir = vault.data_dir / 'backups'
            backups_dir.mkdir(parents=True, exist_ok=True)
            restore_point = backups_dir / 'pre_restore_keep.cbox'
            snapshot = backups_dir / 'cipherbox_snapshot_auto.cbox'
            restore_point.write_bytes(b'restore point')
            snapshot.write_bytes(b'auto snapshot')

            RestorePointManager(vault).clear_all()

            assert not restore_point.exists()
            assert snapshot.exists()
        finally:
            vault.close()

    def test_clear_all_returns_partial_count_on_purge_failure(
        self, vault_config, monkeypatch
    ):
        """部分失败时返回值 = 总数 − 失败数，且失败文件残留、成功文件真删。"""
        vault = make_vault(vault_config)
        vault.initialize("test_password_12345")
        try:
            backups_dir = vault.data_dir / 'backups'
            backups_dir.mkdir(parents=True, exist_ok=True)
            target = backups_dir / 'pre_restore_1.cbox'
            for i in range(3):
                (backups_dir / f'pre_restore_{i}.cbox').write_bytes(b'payload')

            # mock 底层 secure_delete_file 对指定文件抛 OSError，让真实 secure_purge
            # 遍历执行：成功文件真删、失败文件收集。模拟外部进程占用单文件场景，
            # 同时覆盖「计数」「失败残留」「成功真删」三个契约。
            import src.utils.purge_files as purge_mod
            real_delete = purge_mod.secure_delete_file

            def _fail_target(path: Path) -> None:
                if Path(path).name == target.name:
                    raise OSError('模拟文件被占用')
                real_delete(path)

            monkeypatch.setattr(purge_mod, 'secure_delete_file', _fail_target)

            deleted = RestorePointManager(vault).clear_all()

            assert deleted == 2  # 3 个总数 − 1 个失败
            assert target.exists()  # 失败文件残留
            assert not (backups_dir / 'pre_restore_0.cbox').exists()  # 成功文件真删
            assert not (backups_dir / 'pre_restore_2.cbox').exists()
        finally:
            vault.close()


def test_change_master_password_reports_purge_failure(vault, monkeypatch):
    """改密成功但旧快照清理失败时返回 (True, 带明文泄漏提示)，不静默成功。

    守护「改密成功 + purge 失败」的用户可见反馈路径：snapshot_key 已轮换，但旧
    snapshot_key 加密的快照/恢复点含历史明文未删净，须明确告知用户而非笼统成功。
    启动期 purge_restore_points 会重试其中 pre_restore_* 残留，cipherbox_snapshot_*
    由 retention 淘汰，故此处仅验证反馈文案可见。
    """
    backups_dir = vault.data_dir / 'backups'
    backups_dir.mkdir(parents=True, exist_ok=True)
    stale = backups_dir / 'cipherbox_snapshot_stale.cbox'
    stale.write_bytes(b'stale snapshot encrypted with old snapshot_key')

    # mock purge_snapshot_backups 报告失败（模拟文件被外部进程占用未删净）
    monkeypatch.setattr(vault, 'purge_snapshot_backups', lambda: [stale])

    success, msg = vault.change_master_password('TestPassword123!', 'NewPassword456!')

    assert success is True
    assert '未能删除' in msg
