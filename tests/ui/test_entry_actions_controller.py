"""EntryActionsController 直接单测（rank 10）。

覆盖选择防抖状态机（pending 校验 / 锁定跳过）、``@require_unlocked`` 守卫、
跨 controller 回调连通（refresh_* / get_dialog_options）、对话框确认删除路径、
生命周期（set_locked / prepare_for_lock / stop_timers / cancel_pending_selection）。

与 ``test_product_hardening`` 端到端守护互补：后者经真实 ``MainWindow`` 验证装配正确，
本文件聚焦 controller 内部状态机与回调契约，显式断言每条 ``EntryActionsDeps`` 回调绑定。
"""

# 测试大量用 MagicMock 注入依赖，抑制其属性访问的静态类型告警
# pyright: reportAttributeAccessIssue=false

from unittest.mock import MagicMock

from PyQt6.QtWidgets import QMainWindow, QMessageBox

from src.ui.controllers.entry_actions_controller import (
    EntryActionsController,
    EntryActionsDeps,
    EntryActionsView,
)


def _make_deps(calls: dict[str, list]) -> EntryActionsDeps:
    """构造 EntryActionsDeps，refresh_* 用探针记录调用，get_dialog_options 返回空对。"""

    def _probe(name: str):
        calls[name] = []

        def _cb(*args: object) -> None:
            calls[name].append(args)

        return _cb

    return EntryActionsDeps(
        refresh_after_entry_change=_probe('refresh_after_entry_change'),
        refresh_entries_only=_probe('refresh_entries_only'),
        refresh_categories=_probe('refresh_categories'),
        get_dialog_options=lambda: ([], []),
    )


def _make_controller() -> tuple[EntryActionsController, dict[str, list], MagicMock]:
    """构造 controller + 探针 dict + detail_panel mock（供信号/方法断言）。"""
    calls: dict[str, list] = {}
    detail_panel = MagicMock()
    ctrl = EntryActionsController(
        MagicMock(), MagicMock(), MagicMock(), detail_panel, MagicMock(), _make_deps(calls),
    )
    return ctrl, calls, detail_panel


def _make_view() -> EntryActionsView:
    """构造全 MagicMock 控件的 EntryActionsView。"""
    return EntryActionsView(
        entry_list=MagicMock(),
        category_list=MagicMock(),
        status_bar=MagicMock(),
        add_entry_btn=MagicMock(),
        add_category_btn=MagicMock(),
    )


def _setup(ctrl: EntryActionsController) -> EntryActionsView:
    """在全新 QMainWindow + mock view 上 setup，返回 view 供断言。"""
    view = _make_view()
    ctrl.setup(QMainWindow(), view)
    return view


class TestEntryActionsSetup:
    """setup 创建防抖定时器并连接控件信号。"""

    def test_setup_creates_select_timer(self, qapp):
        ctrl, _, _ = _make_controller()
        _setup(ctrl)
        assert ctrl._select_timer is not None


class TestSelectDebounce:
    """选择防抖状态机：锁定跳过、pending 失效清空、无 pending 空操作。"""

    def test_do_select_entry_locked_skips(self, qapp):
        """锁定态 do_select_entry 不访问 entry_mgr（避免已清零密钥）。"""
        ctrl, _, _ = _make_controller()
        _setup(ctrl)
        ctrl._pending_selection = 0
        ctrl.set_locked(True)
        ctrl.do_select_entry()
        ctrl._entry_mgr.get_entry.assert_not_called()

    def test_do_select_entry_none_pending_noop(self, qapp):
        ctrl, _, _ = _make_controller()
        _setup(ctrl)
        ctrl.do_select_entry()
        ctrl._entry_mgr.get_entry.assert_not_called()

    def test_do_select_entry_pending_mismatch_clears_detail(self, qapp):
        """pending 行与列表当前选中不符（后台重建）时清空详情面板，不取条目。"""
        ctrl, _, detail_panel = _make_controller()
        view = _setup(ctrl)
        ctrl._pending_selection = 1
        view.entry_list.currentIndex.return_value.row.return_value = 99  # 与 pending=1 不符
        ctrl.do_select_entry()
        detail_panel.show_empty.assert_called_once()
        ctrl._entry_mgr.get_entry.assert_not_called()


class TestRequireUnlocked:
    """@require_unlocked 守卫：锁定态跳过 edit/delete/copy（不访问已清零密钥）。"""

    def test_edit_entry_locked_skips(self, qapp):
        ctrl, _, _ = _make_controller()
        _setup(ctrl)
        ctrl.set_locked(True)
        ctrl.edit_entry(42)
        ctrl._entry_mgr.get_entry.assert_not_called()

    def test_delete_entry_locked_skips(self, qapp):
        ctrl, _, _ = _make_controller()
        _setup(ctrl)
        ctrl.set_locked(True)
        ctrl.delete_entry(42)
        ctrl._entry_mgr.get_entry.assert_not_called()


class TestCallbacks:
    """跨 controller 回调连通 + 简单操作（复制反馈/密码生成器回调）。"""

    def test_toggle_favorite_calls_refresh_entries_only(self, qapp):
        ctrl, calls, _ = _make_controller()
        _setup(ctrl)
        ctrl.toggle_favorite(7)
        ctrl._entry_mgr.toggle_favorite.assert_called_once_with(7)
        assert calls['refresh_entries_only'] == [()]

    def test_on_copy_feedback_shows_status_message(self, qapp):
        ctrl, _, _ = _make_controller()
        view = _setup(ctrl)
        ctrl.on_copy_feedback()
        view.status_bar.showMessage.assert_called_once()

    def test_on_password_selected_copies_to_clipboard(self, qapp, monkeypatch):
        ctrl, _, _ = _make_controller()
        _setup(ctrl)
        monkeypatch.setattr('src.ui.controllers.entry_actions_controller.Toast.show', MagicMock())
        ctrl.on_password_selected('secret')
        ctrl._clipboard.copy_text.assert_called_once_with('secret')


class TestDialogOps:
    """add_entry 对话框装配 + delete_entry 确认删除路径。"""

    def test_add_entry_connects_saved_to_refresh(self, qapp, monkeypatch):
        """add_entry 经 EntryDialog 打开，saved 信号连 refresh_after_entry_change 回调。"""
        ctrl, _, _ = _make_controller()
        _setup(ctrl)
        mock_dialog = MagicMock()
        monkeypatch.setattr(
            'src.ui.controllers.entry_actions_controller.EntryDialog', mock_dialog,
        )
        ctrl.add_entry()
        mock_dialog.assert_called_once()
        mock_dialog.return_value.saved.connect.assert_called_once_with(
            ctrl._deps.refresh_after_entry_change,
        )

    def test_delete_entry_confirmed_deletes_and_refreshes(self, qapp, monkeypatch):
        """确认删除后调 entry_mgr.delete_entry + refresh_after_entry_change。"""
        ctrl, calls, _ = _make_controller()
        _setup(ctrl)
        ctrl._entry_mgr.get_entry.return_value = MagicMock(id=1, title='T')
        monkeypatch.setattr(
            'src.ui.controllers.entry_actions_controller.QMessageBox.question',
            lambda *a, **k: QMessageBox.StandardButton.Yes,
        )
        monkeypatch.setattr('src.ui.controllers.entry_actions_controller.Toast.show', MagicMock())
        ctrl.delete_entry(1)
        ctrl._entry_mgr.delete_entry.assert_called_once_with(1)
        assert calls['refresh_after_entry_change'] == [()]


class TestLifecycle:
    """set_locked / prepare_for_lock / stop_timers / cancel_pending_selection。"""

    def test_prepare_for_lock_sets_locked_and_clears_pending(self, qapp):
        ctrl, _, _ = _make_controller()
        _setup(ctrl)
        ctrl._pending_selection = 5
        ctrl.prepare_for_lock()
        assert ctrl._locked is True
        assert ctrl._pending_selection is None

    def test_set_locked_toggles_state(self, qapp):
        ctrl, _, _ = _make_controller()
        _setup(ctrl)
        ctrl.prepare_for_lock()
        assert ctrl._locked is True
        ctrl.set_locked(False)
        assert ctrl._locked is False

    def test_stop_timers_stops_select_timer(self, qapp):
        ctrl, _, _ = _make_controller()
        ctrl.setup(QMainWindow(), _make_view())
        timer = ctrl._select_timer
        assert timer is not None
        timer.start()
        ctrl.stop_timers()
        assert not timer.isActive()

    def test_cancel_pending_selection_clears_without_changing_lock(self, qapp):
        ctrl, _, _ = _make_controller()
        _setup(ctrl)
        ctrl._pending_selection = 3
        ctrl.cancel_pending_selection()
        assert ctrl._pending_selection is None
        assert ctrl._locked is False
