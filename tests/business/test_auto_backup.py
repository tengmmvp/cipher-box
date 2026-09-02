"""自动快照 ``maybe_auto_backup`` 测试。

覆盖间隔跳过、强制备份、保留数清理与协作取消等主路径。
"""

from tests.helpers import make_backup_manager, make_entry_manager


def _snapshots(config) -> list:
    return list((config.data_dir / "backups").glob("cipherbox_snapshot_*.cbox"))


def test_maybe_auto_backup_disabled(vault, vault_config):
    """未启用自动备份时直接成功返回，不创建快照。"""
    mgr = make_backup_manager(vault)
    vault_config.set("auto_backup_enabled", False)

    ok, err = mgr.maybe_auto_backup(vault_config, force=False)

    assert ok and err == ""
    assert _snapshots(vault_config) == []


def test_maybe_auto_backup_force_bypasses_disabled_setting(vault, vault_config):
    """force=True 必须真正绕过自动备份开关，供改密后强制快照使用。"""
    mgr = make_backup_manager(vault)
    vault_config.set("auto_backup_enabled", False)

    ok, err = mgr.maybe_auto_backup(vault_config, force=True)

    assert ok, err
    assert len(_snapshots(vault_config)) == 1


def test_maybe_auto_backup_force_creates_snapshot(vault, vault_config):
    """force=True 忽略间隔检查，创建一份快照。"""
    mgr = make_backup_manager(vault)
    vault_config.set("auto_backup_enabled", True)

    ok, err = mgr.maybe_auto_backup(vault_config, force=True)

    assert ok, err
    assert len(_snapshots(vault_config)) == 1


def test_maybe_auto_backup_interval_skip(vault, vault_config):
    """间隔内的非强制调用应跳过，不新增快照。"""
    mgr = make_backup_manager(vault)
    vault_config.set("auto_backup_enabled", True)
    vault_config.set("auto_backup_interval_hours", 24)

    ok, _ = mgr.maybe_auto_backup(vault_config, force=True)
    assert ok
    assert len(_snapshots(vault_config)) == 1

    # 刚备份过，elapsed 接近 0 < 24h，应跳过
    ok2, _ = mgr.maybe_auto_backup(vault_config, force=False)
    assert ok2
    assert len(_snapshots(vault_config)) == 1


def test_maybe_auto_backup_retention(vault, vault_config):
    """超出保留数的旧快照被清理，总数收敛到 retention。"""
    mgr = make_backup_manager(vault)
    backup_dir = vault_config.data_dir / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    vault_config.set("auto_backup_enabled", True)
    vault_config.set("auto_backup_retention", 2)
    # 预置 4 个旧时间戳快照文件（内容不重要，清理仅按文件名排序删除）
    for i in range(4):
        (backup_dir / f"cipherbox_snapshot_2023010{i}_000000.cbox").write_bytes(b"x")

    ok, _ = mgr.maybe_auto_backup(vault_config, force=True)

    assert ok
    # force 新建一份当前时间戳快照后，retention 清理使总数收敛到 2
    assert len(_snapshots(vault_config)) == 2


def test_maybe_auto_backup_cancelled(vault, vault_config):
    """cancel_check 返回真时中止备份，不产出快照。

    覆盖 close_to_tray / 锁定场景下后台备份的协作取消：业务层在全量解密循环
    中检查 cancel_check，及时退出避免隐藏/锁定后继续持密钥解密。
    """
    from src.models import Entry

    mgr = make_backup_manager(vault)
    vault_config.set("auto_backup_enabled", True)
    # 添加条目使全量解密循环执行，cancel_check 才有机会被检查触发
    make_entry_manager(vault).add_entry(Entry(title="t", username="u", password="p"))

    ok, err = mgr.maybe_auto_backup(vault_config, force=True, cancel_check=lambda: True)

    assert not ok
    assert "取消" in err
    assert _snapshots(vault_config) == []


def test_maybe_auto_backup_preserves_integrity_warning(vault, vault_config):
    """自动备份时间戳保存保留完整性告警（QL-064 补齐）。

    maybe_auto_backup 成功后的 ``config.save()`` 是后台自动写盘而非用户驱动的
    配置修复：若走默认清零语义，本会话检出过的篡改告警被静默清除，抑制
    MainWindow 的完整性用户通知（与 register_security_sentinel 的哨兵登记
    写盘语义一致，均传 keep_integrity_warning=True）。
    """
    mgr = make_backup_manager(vault)
    vault_config.set("auto_backup_enabled", True)
    # 模拟本会话加载时检出篡改：告警置位（save 默认语义会将其清零）
    vault_config._integrity_warning = True  # noqa: SLF001

    ok, err = mgr.maybe_auto_backup(vault_config, force=True)

    assert ok and err == ""
    assert len(_snapshots(vault_config)) == 1
    # 告警未被后台写盘清零：check_integrity 仍失败（用户通知仍可触达）
    assert not vault_config.check_integrity()
