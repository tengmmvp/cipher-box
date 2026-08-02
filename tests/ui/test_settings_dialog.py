"""SettingsDialog 接线测试：控件值→config 写入 + 持久化失败回滚（MAINT-3）。

业务层（``ConfigManager`` 的 ``_is_valid``/``get_safe``/原子 ``save``）已由 ``tests/config``
覆盖；本文件守护「对话框控件值→``_SETTINGS_MAP``→``config.set``→持久化」接线层，
以及 ``save`` 失败时内存配置回滚（防内存已写新值而磁盘仍旧值的不一致）。
"""

from src.config import ConfigManager


def _make_dialog(tmp_path):
    from src.ui.dialogs.settings_dialog import SettingsDialog

    config = ConfigManager.for_testing(tmp_path)
    return SettingsDialog(config), config


def test_save_settings_writes_widget_values_to_config(qapp, tmp_path):
    """``_save_settings`` 把控件值经 ``_SETTINGS_MAP`` 写入 ``config`` 并持久化。"""
    dlg, config = _make_dialog(tmp_path)
    dlg._auto_lock_spin.setValue(10)
    dlg._theme_combo.setCurrentIndex(1)  # 深色
    dlg._save_settings()
    assert config.get("auto_lock_minutes") == 10
    assert config.get("theme") == "dark"


def test_save_settings_rolls_back_on_persistence_failure(qapp, tmp_path, monkeypatch):
    """``config.save`` 失败时回滚内存配置到快照，保持内存与磁盘（旧值）一致。"""
    dlg, config = _make_dialog(tmp_path)
    original = config.get("auto_lock_minutes")
    dlg._auto_lock_spin.setValue(15)

    def _raise_save():
        raise OSError("disk full")

    monkeypatch.setattr(config, "save", _raise_save)
    monkeypatch.setattr(
        "src.ui.dialogs.settings_dialog.QMessageBox.critical",
        lambda *a, **k: None,
    )
    dlg._save_settings()
    # 关键接线：``save`` 失败后内存配置回滚到原值，而非残留控件新值 15
    assert config.get("auto_lock_minutes") == original
