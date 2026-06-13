"""自动快照 ``maybe_auto_backup`` 测试。

覆盖间隔跳过、强制备份与保留数清理三条主路径，该方法此前无测试覆盖。
"""

from src.business.managers.backup_restore import BackupRestoreManager


def _snapshots(config) -> list:
    return list((config.data_dir / 'backups').glob('cipherbox_snapshot_*.cbox'))


def test_maybe_auto_backup_disabled(vault, vault_config):
    """未启用自动备份时直接成功返回，不创建快照。"""
    mgr = BackupRestoreManager(vault)
    vault_config.set('auto_backup_enabled', False)

    ok, err = mgr.maybe_auto_backup(vault_config, force=True)

    assert ok and err == ''
    assert _snapshots(vault_config) == []


def test_maybe_auto_backup_force_creates_snapshot(vault, vault_config):
    """force=True 忽略间隔检查，创建一份快照。"""
    mgr = BackupRestoreManager(vault)
    vault_config.set('auto_backup_enabled', True)

    ok, err = mgr.maybe_auto_backup(vault_config, force=True)

    assert ok, err
    assert len(_snapshots(vault_config)) == 1


def test_maybe_auto_backup_interval_skip(vault, vault_config):
    """间隔内的非强制调用应跳过，不新增快照。"""
    mgr = BackupRestoreManager(vault)
    vault_config.set('auto_backup_enabled', True)
    vault_config.set('auto_backup_interval_hours', 24)

    ok, _ = mgr.maybe_auto_backup(vault_config, force=True)
    assert ok
    assert len(_snapshots(vault_config)) == 1

    # 刚备份过，elapsed 接近 0 < 24h，应跳过
    ok2, _ = mgr.maybe_auto_backup(vault_config, force=False)
    assert ok2
    assert len(_snapshots(vault_config)) == 1


def test_maybe_auto_backup_retention(vault, vault_config):
    """超出保留数的旧快照被清理，总数收敛到 retention。"""
    mgr = BackupRestoreManager(vault)
    backup_dir = vault_config.data_dir / 'backups'
    backup_dir.mkdir(parents=True, exist_ok=True)
    vault_config.set('auto_backup_enabled', True)
    vault_config.set('auto_backup_retention', 2)
    # 预置 4 个旧时间戳快照文件（内容不重要，清理仅按文件名排序删除）
    for i in range(4):
        (backup_dir / f'cipherbox_snapshot_2023010{i}_000000.cbox').write_bytes(b'x')

    ok, _ = mgr.maybe_auto_backup(vault_config, force=True)

    assert ok
    # force 新建一份当前时间戳快照后，retention 清理使总数收敛到 2
    assert len(_snapshots(vault_config)) == 2
