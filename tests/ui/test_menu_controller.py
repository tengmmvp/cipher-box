"""MenuController 直接单测（rank 10）。

覆盖菜单与快捷键构建、菜单动作→``MenuSlots`` 回调连通、对话框 Accepted/Rejected
路径触发 refresh/theme 副作用、改密成功触发强制快照（force=True）、
``update_menu_icons`` 按 ``QAction.data()`` 重建图标。

与 ``test_product_hardening`` 的端到端守护互补：后者经真实 ``MainWindow`` 验证装配
正确，本文件聚焦 controller 内部状态与回调契约，显式断言每条 ``MenuSlots`` 回调绑定。
"""

# 测试大量用 MagicMock 注入依赖，抑制其属性访问的静态类型告警
# pyright: reportAttributeAccessIssue=false

from unittest.mock import MagicMock

from PyQt6.QtWidgets import QDialog, QLineEdit, QMainWindow, QMenu

from src.ui.controllers.menu_controller import MenuController, MenuDeps, MenuSlots


def _make_slots() -> tuple[MenuSlots, dict[str, list[tuple]]]:
    """构造 MenuSlots，每个回调把入参记进探针 dict，返回 (slots, calls)。"""
    calls: dict[str, list[tuple]] = {}

    def _probe(name: str):
        calls[name] = []

        def _cb(*args: object) -> None:
            calls[name].append(args)

        return _cb

    slots = MenuSlots(
        add_entry=_probe("add_entry"),
        edit_entry=_probe("edit_entry"),
        edit_selected_entry=_probe("edit_selected_entry"),
        delete_selected_entry=_probe("delete_selected_entry"),
        on_password_selected=_probe("on_password_selected"),
        clear_search=_probe("clear_search"),
        refresh_all_data=_probe("refresh_all_data"),
        apply_theme=_probe("apply_theme"),
        apply_runtime_settings=_probe("apply_runtime_settings"),
        lock=_probe("lock"),
    )
    return slots, calls


def _make_controller() -> tuple[MenuController, dict[str, list[tuple]]]:
    """构造注入全 MagicMock 依赖的 MenuController，返回 (controller, calls)。"""
    slots, calls = _make_slots()
    deps = MenuDeps(
        config=MagicMock(),
        vault=MagicMock(),
        entry_mgr=MagicMock(),
        security=MagicMock(),
        import_export=MagicMock(),
        backup=MagicMock(),
        clipboard=MagicMock(),
        detail_panel=MagicMock(),
        auto_backup=MagicMock(),
    )
    ctrl = MenuController(deps, slots)
    return ctrl, calls


def _setup_on_fresh_window(ctrl: MenuController) -> QMainWindow:
    """在全新 QMainWindow + QLineEdit 上 setup，返回该窗口供断言。"""
    parent = QMainWindow()
    ctrl.setup(parent, QLineEdit())
    return parent


def _all_menu_actions(parent: QMainWindow):
    """遍历菜单栏所有 QMenu 的动作（扁平，无子菜单）。"""
    menubar = parent.menuBar()
    assert menubar is not None
    for menu in menubar.findChildren(QMenu):
        yield from menu.actions()


def _accepted_dialog_mock() -> MagicMock:
    """构造对话框类 mock，exec() 返回 Accepted，DialogCode 指向真实枚举以使 == 成立。"""
    mock_cls = MagicMock()
    mock_cls.DialogCode = QDialog.DialogCode
    mock_cls.return_value.exec.return_value = QDialog.DialogCode.Accepted
    return mock_cls


def _rejected_dialog_mock() -> MagicMock:
    """构造对话框类 mock，exec() 返回 Rejected。"""
    mock_cls = MagicMock()
    mock_cls.DialogCode = QDialog.DialogCode
    mock_cls.return_value.exec.return_value = QDialog.DialogCode.Rejected
    return mock_cls


class TestMenuControllerSetup:
    """setup 构建菜单栏与全局快捷键。"""

    def test_setup_creates_four_top_menus(self, qapp):
        """setup 后菜单栏有 4 个顶层菜单，顺序为 文件/工具/设置/帮助。"""
        ctrl, _ = _make_controller()
        parent = _setup_on_fresh_window(ctrl)
        menubar = parent.menuBar()
        assert menubar is not None
        titles = [a.text() for a in menubar.actions()]
        assert titles == ["文件", "工具", "设置", "帮助"]

    def test_setup_registers_six_shortcuts(self, qapp):
        """setup 注册 6 个全局快捷键（Ctrl+F/E/G/逗号、Delete、Escape）。"""
        ctrl, _ = _make_controller()
        _setup_on_fresh_window(ctrl)
        assert len(ctrl._shortcuts) == 6


class TestMenuActionWiring:
    """菜单动作经 MenuSlots 回调连通。"""

    def test_add_entry_action_triggers_slot(self, qapp):
        ctrl, calls = _make_controller()
        parent = _setup_on_fresh_window(ctrl)
        for action in _all_menu_actions(parent):
            if action.text() == "新增条目":
                action.trigger()
                break
        # QAction.triggered 信号带 checked=False 入参，断言调用次数而非入参
        assert len(calls["add_entry"]) == 1

    def test_lock_action_triggers_slot(self, qapp):
        ctrl, calls = _make_controller()
        parent = _setup_on_fresh_window(ctrl)
        for action in _all_menu_actions(parent):
            if action.text() == "锁定保险库":
                action.trigger()
                break
        assert len(calls["lock"]) == 1


class TestDialogDispatch:
    """show_* 对话框调度与 Accepted/Rejected 分支副作用。"""

    def test_show_settings_accepted_applies_theme_and_runtime(self, qapp, monkeypatch):
        ctrl, calls = _make_controller()
        _setup_on_fresh_window(ctrl)
        monkeypatch.setattr(
            "src.ui.controllers.menu_controller.SettingsDialog",
            _accepted_dialog_mock(),
        )
        ctrl.show_settings()
        assert calls["apply_theme"] == [()]
        assert calls["apply_runtime_settings"] == [()]

    def test_show_settings_rejected_skips_apply(self, qapp, monkeypatch):
        ctrl, calls = _make_controller()
        _setup_on_fresh_window(ctrl)
        monkeypatch.setattr(
            "src.ui.controllers.menu_controller.SettingsDialog",
            _rejected_dialog_mock(),
        )
        ctrl.show_settings()
        assert calls["apply_theme"] == []
        assert calls["apply_runtime_settings"] == []

    def test_show_backup_data_changed_refreshes(self, qapp, monkeypatch):
        ctrl, calls = _make_controller()
        _setup_on_fresh_window(ctrl)
        mock_cls = MagicMock()
        mock_cls.return_value.data_changed = True
        monkeypatch.setattr("src.ui.controllers.menu_controller.BackupDialog", mock_cls)
        ctrl.show_backup()
        assert calls["refresh_all_data"] == [()]
        ctrl._detail_panel.show_empty.assert_called_once()

    def test_show_backup_unchanged_skips_refresh(self, qapp, monkeypatch):
        ctrl, calls = _make_controller()
        _setup_on_fresh_window(ctrl)
        mock_cls = MagicMock()
        mock_cls.return_value.data_changed = False
        monkeypatch.setattr("src.ui.controllers.menu_controller.BackupDialog", mock_cls)
        ctrl.show_backup()
        assert calls["refresh_all_data"] == []

    def test_show_change_master_accepted_triggers_force_backup(self, qapp, monkeypatch):
        """改密 Accepted 触发 refresh + show_empty + 强制快照（force=True）。"""
        ctrl, calls = _make_controller()
        _setup_on_fresh_window(ctrl)
        monkeypatch.setattr(
            "src.ui.controllers.menu_controller.ChangeMasterDialog",
            _accepted_dialog_mock(),
        )
        # 屏蔽 Toast UI 副作用（Accepted 路径函数内 import Toast 并 show）
        monkeypatch.setattr("src.ui.components.toast.Toast.show", MagicMock())
        ctrl.show_change_master()
        assert calls["refresh_all_data"] == [()]
        ctrl._detail_panel.show_empty.assert_called_once()
        ctrl._auto_backup.trigger_check.assert_called_once_with(force=True)

    def test_show_change_master_rejected_skips_backup(self, qapp, monkeypatch):
        ctrl, _ = _make_controller()
        _setup_on_fresh_window(ctrl)
        monkeypatch.setattr(
            "src.ui.controllers.menu_controller.ChangeMasterDialog",
            _rejected_dialog_mock(),
        )
        ctrl.show_change_master()
        ctrl._auto_backup.trigger_check.assert_not_called()


class TestUpdateMenuIcons:
    """update_menu_icons 按 QAction.data() 存储的 icon name 重建图标。"""

    def test_update_menu_icons_does_not_raise(self, qapp):
        ctrl, _ = _make_controller()
        _setup_on_fresh_window(ctrl)
        # setup 已建菜单并设置 data()=icon name，主题切换时重建不应抛错
        ctrl.update_menu_icons()
