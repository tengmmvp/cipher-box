"""MainWindow 退出/托盘/主题生命周期顺序测试（stub 控件，不真跑完整 UI）。

范式仿 ``test_emergency_cancel``：``MainWindow.__new__(MainWindow)`` + stub
控件/属性，面向方法名打桩，不构造真实控件树。覆盖三块零测试的生命周期路径：

- ``_perform_exit_cleanup``：重点守护 ARCH-009——模态对话框 reject 必须先于
  ``vault.close``，顺序错会触发 sqlite 连接撕裂 + QThread running 析构崩溃；
- ``_secure_hide_to_tray``：隐藏到托盘前的明文清理序列（面板清空/剪贴板清空/
  定时器停止/pending 取消/worker 停止）；
- ``_apply_theme``：主题切换的图标清单重建与 delegate 颜色缓存清理。
"""

from unittest.mock import MagicMock

from PyQt6.QtWidgets import QDialog

from src.ui.windows.main_window import MainWindow

_MW_MODULE = "src.ui.windows.main_window"


def _record(order: list, name: str):
    """返回把 name 追加进 order 的探针函数（供 MagicMock side_effect）。"""

    def _cb(*args, **kwargs):
        order.append(name)

    return _cb


def _patch_qapp(monkeypatch, widgets: list) -> MagicMock:
    """替换 main_window 模块级 QApplication 符号为可控替身，返回假 app 实例。

    仅替换模块局部名，不影响全局真实 QApplication；instance() 返回 MagicMock
    使 ``isinstance(app, QApplication)``（替身类）为 False，跳过 app 级样式设置。
    """
    app = MagicMock()

    class _FakeQApplication:
        @staticmethod
        def instance():
            return app

        @staticmethod
        def topLevelWidgets():
            return list(widgets)

    monkeypatch.setattr(f"{_MW_MODULE}.QApplication", _FakeQApplication)
    return app


def _make_exit_window(order: list, *, tray) -> MainWindow:
    """构造 stub MainWindow，各清理步骤经 side_effect 记录进 order。"""
    mw = MainWindow.__new__(MainWindow)
    mw._auto_lock = MagicMock()
    mw._auto_lock.remove_session_filter.side_effect = _record(order, "session_filter")
    mw._list_refresh = MagicMock()
    mw._list_refresh.shutdown.side_effect = _record(order, "list_shutdown")
    mw._auto_backup = MagicMock()
    mw._auto_backup.shutdown.side_effect = _record(order, "auto_backup_shutdown")
    mw._clipboard = MagicMock()
    mw._clipboard.clear_now.side_effect = _record(order, "clipboard_clear")
    mw._vault = MagicMock()
    mw._vault.close.side_effect = _record(order, "vault_close")
    mw._tray = tray
    if tray is not None:
        tray.hide.side_effect = _record(order, "tray_hide")
    return mw


class TestPerformExitCleanup:
    """_perform_exit_cleanup 调用序列：对话框 reject 必须先于 vault.close（ARCH-009）。"""

    def test_rejects_modal_dialogs_before_closing_vault(self, monkeypatch):
        """模态对话框 reject 先于 vault.close，防 sqlite 撕裂 + QThread 析构崩溃。"""
        order: list = []
        dialog = MagicMock(spec=QDialog)
        dialog.reject.side_effect = _record(order, "dialog_reject")
        app = _patch_qapp(monkeypatch, [dialog])
        mw = _make_exit_window(order, tray=MagicMock())

        mw._perform_exit_cleanup()

        # ARCH-009 关键顺序：对话框 worker 先退出，vault 后关闭
        assert order.index("dialog_reject") < order.index("vault_close")
        # 完整序列：事件过滤器/会话过滤器 → worker 停止 → 对话框 reject →
        # 剪贴板清空 → vault 关闭 → 托盘隐藏
        assert order == [
            "session_filter",
            "list_shutdown",
            "auto_backup_shutdown",
            "dialog_reject",
            "clipboard_clear",
            "vault_close",
            "tray_hide",
        ]
        dialog.reject.assert_called_once_with()
        app.removeEventFilter.assert_called_once_with(mw)

    def test_clipboard_cleared_before_vault_close(self, monkeypatch):
        """剪贴板明文清理先于 vault.close（关库后无法再取密钥清剪贴板）。"""
        order: list = []
        _patch_qapp(monkeypatch, [])
        mw = _make_exit_window(order, tray=None)

        mw._perform_exit_cleanup()

        assert order.index("clipboard_clear") < order.index("vault_close")

    def test_workers_shutdown_before_dialog_reject(self, monkeypatch):
        """后台 worker 停止先于对话框 reject（reject 内等待不再有活跃 worker）。"""
        order: list = []
        dialog = MagicMock(spec=QDialog)
        dialog.reject.side_effect = _record(order, "dialog_reject")
        _patch_qapp(monkeypatch, [dialog])
        mw = _make_exit_window(order, tray=None)

        mw._perform_exit_cleanup()

        assert order.index("list_shutdown") < order.index("dialog_reject")
        assert order.index("auto_backup_shutdown") < order.index("dialog_reject")

    def test_no_tray_skips_tray_hide_without_error(self, monkeypatch):
        """无托盘实例（_tray=None）时跳过托盘隐藏，不抛异常。"""
        order: list = []
        _patch_qapp(monkeypatch, [])
        mw = _make_exit_window(order, tray=None)

        mw._perform_exit_cleanup()

        assert "tray_hide" not in order
        assert order[-1] == "vault_close"

    def test_non_dialog_toplevel_widgets_not_rejected(self, monkeypatch):
        """非 QDialog 顶层控件不被 reject（reject 仅针对模态对话框）。"""
        order: list = []
        plain_widget = MagicMock()  # 无 spec：isinstance(plain, QDialog) 为 False
        dialog = MagicMock(spec=QDialog)
        dialog.reject.side_effect = _record(order, "dialog_reject")
        _patch_qapp(monkeypatch, [plain_widget, dialog])
        mw = _make_exit_window(order, tray=None)

        mw._perform_exit_cleanup()

        dialog.reject.assert_called_once()
        plain_widget.reject.assert_not_called()

    def test_no_dialogs_closes_vault_directly(self, monkeypatch):
        """无模态对话框时直接走到 vault.close，不因空列表异常。"""
        order: list = []
        _patch_qapp(monkeypatch, [])
        mw = _make_exit_window(order, tray=None)

        mw._perform_exit_cleanup()

        assert "vault_close" in order


class TestSecureHideToTray:
    """_secure_hide_to_tray 明文清理序列（托盘态保持解锁，不关 vault）。"""

    def test_clears_plaintext_and_stops_workers_in_order(self, monkeypatch):
        """面板清空→剪贴板清空→定时器停止→pending 取消→worker 停止，vault 不关闭。"""
        order: list = []
        mw = MainWindow.__new__(MainWindow)
        mw._detail_panel = MagicMock()
        mw._detail_panel.show_empty.side_effect = _record(order, "panel_clear")
        mw._clipboard = MagicMock()
        mw._clipboard.clear_now.side_effect = _record(order, "clipboard_clear")
        mw._list_refresh = MagicMock()
        mw._list_refresh.stop_timers.side_effect = _record(order, "list_stop_timers")
        mw._list_refresh.shutdown.side_effect = _record(order, "list_shutdown")
        mw._entry_actions = MagicMock()
        mw._entry_actions.stop_timers.side_effect = _record(order, "entry_stop_timers")
        mw._entry_actions.cancel_pending_selection.side_effect = _record(order, "cancel_pending")
        mw._auto_backup = MagicMock()
        mw._auto_backup.shutdown.side_effect = _record(order, "auto_backup_shutdown")
        toast_mgr = MagicMock()
        monkeypatch.setattr(f"{_MW_MODULE}.ToastManager", toast_mgr)

        mw._secure_hide_to_tray()

        assert order == [
            "panel_clear",
            "clipboard_clear",
            "list_stop_timers",
            "entry_stop_timers",
            "cancel_pending",
            "list_shutdown",
            "auto_backup_shutdown",
        ]
        toast_mgr.cancel_all_for.assert_called_once_with(mw)
        # 托盘态不关 vault、不触碰密钥（方法体内无 vault 访问即可成立）
        mw._detail_panel.show_empty.assert_called_once_with()
        mw._clipboard.clear_now.assert_called_once_with()

    def test_stops_pending_selection_debounce(self, monkeypatch):
        """隐藏到托盘取消 pending 选择，防止托盘态防抖回调触发解密。"""
        mw = MainWindow.__new__(MainWindow)
        mw._detail_panel = MagicMock()
        mw._clipboard = MagicMock()
        mw._list_refresh = MagicMock()
        mw._entry_actions = MagicMock()
        mw._auto_backup = MagicMock()
        monkeypatch.setattr(f"{_MW_MODULE}.ToastManager", MagicMock())

        mw._secure_hide_to_tray()

        mw._entry_actions.cancel_pending_selection.assert_called_once_with()
        mw._list_refresh.stop_timers.assert_called_once_with()
        mw._entry_actions.stop_timers.assert_called_once_with()


class TestApplyTheme:
    """_apply_theme：主题切换触发图标清单重建与 delegate 缓存清理。"""

    def _make_window(self, current: str, new: str) -> MainWindow:
        mw = MainWindow.__new__(MainWindow)
        mw._config = MagicMock()
        mw._config.get.return_value = new
        mw._current_theme = current
        # 实例属性覆盖 host 方法/控件（不构造真实控件树）
        mw._build_filter_list = MagicMock()
        mw._menu = MagicMock()
        mw._brand_icon = MagicMock()
        mw._add_entry_btn = MagicMock()
        mw._search_action = MagicMock()
        mw._tray = MagicMock()
        mw._entry_delegate = MagicMock()
        mw._entry_list = MagicMock()
        mw._list_refresh = MagicMock()
        mw._detail_panel = MagicMock()
        return mw

    def _patch_theme_deps(self, monkeypatch, widgets: list | None = None):
        """patch 主题相关模块级符号（set_theme/get_style/图标/Toast/QApplication）。"""
        app = _patch_qapp(monkeypatch, widgets or [])
        set_theme = MagicMock()
        get_style = MagicMock(return_value="")
        set_icon_with_text = MagicMock()
        icon_pixmap = MagicMock(return_value=None)
        icon_fn = MagicMock(return_value=None)
        toast_mgr = MagicMock()
        monkeypatch.setattr(f"{_MW_MODULE}.set_theme", set_theme)
        monkeypatch.setattr(f"{_MW_MODULE}.get_style", get_style)
        monkeypatch.setattr(f"{_MW_MODULE}.set_icon_with_text", set_icon_with_text)
        monkeypatch.setattr(f"{_MW_MODULE}.icon_pixmap", icon_pixmap)
        monkeypatch.setattr(f"{_MW_MODULE}.icon", icon_fn)
        monkeypatch.setattr(f"{_MW_MODULE}.ToastManager", toast_mgr)
        return {
            "app": app,
            "set_theme": set_theme,
            "set_icon_with_text": set_icon_with_text,
            "toast": toast_mgr,
        }

    def test_theme_change_rebuilds_icon_inventory(self, monkeypatch):
        """主题变化：重建筛选列表与菜单图标、重设按钮/搜索框图标、托盘解锁态。"""
        mw = self._make_window(current="light", new="dark")
        deps = self._patch_theme_deps(monkeypatch)

        mw._apply_theme()

        assert mw._current_theme == "dark"
        deps["set_theme"].assert_called_once_with("dark")
        mw._build_filter_list.assert_called_once_with()
        mw._menu.update_menu_icons.assert_called_once_with()
        deps["set_icon_with_text"].assert_called_once()
        mw._search_action.setIcon.assert_called_once()
        mw._tray.set_locked.assert_called_once_with(False)

    def test_theme_change_clears_delegate_cache_and_rebuilds_list(self, monkeypatch):
        """主题变化：清 delegate 颜色缓存并重建筛选列表（烘焙色需重算）。"""
        mw = self._make_window(current="light", new="dark")
        self._patch_theme_deps(monkeypatch)

        mw._apply_theme()

        mw._entry_delegate.clear_color_cache.assert_called_once_with()
        mw._entry_list.update.assert_called_once_with()
        mw._list_refresh.rebuild_for_theme.assert_called_once_with()

    def test_theme_change_with_selection_refreshes_detail_force(self, monkeypatch):
        """有选中条目时强制刷新详情面板（恢复用户当前查看的条目）。"""
        mw = self._make_window(current="light", new="dark")
        self._patch_theme_deps(monkeypatch)
        current = MagicMock()
        mw._detail_panel.current_entry = current

        mw._apply_theme()

        mw._detail_panel.show_entry.assert_called_once_with(current, force=True)
        mw._detail_panel.show_empty.assert_not_called()

    def test_theme_change_without_selection_shows_empty(self, monkeypatch):
        """无选中条目时详情面板置空（不恢复用户已取消选择的条目）。"""
        mw = self._make_window(current="light", new="dark")
        self._patch_theme_deps(monkeypatch)
        mw._detail_panel.current_entry = None

        mw._apply_theme()

        mw._detail_panel.show_empty.assert_called_once_with()
        mw._detail_panel.show_entry.assert_not_called()

    def test_theme_unchanged_is_noop(self, monkeypatch):
        """主题未变时不触发任何重建（避免无谓的图标/缓存重算）。"""
        mw = self._make_window(current="light", new="light")
        deps = self._patch_theme_deps(monkeypatch)

        mw._apply_theme()

        mw._build_filter_list.assert_not_called()
        mw._menu.update_menu_icons.assert_not_called()
        deps["set_theme"].assert_not_called()
        mw._entry_delegate.clear_color_cache.assert_not_called()
        mw._list_refresh.rebuild_for_theme.assert_not_called()
        deps["toast"].refresh_for.assert_not_called()

    def test_theme_change_refreshes_active_toasts(self, monkeypatch):
        """主题变化刷新活跃 Toast 的烘焙配色。"""
        mw = self._make_window(current="light", new="dark")
        deps = self._patch_theme_deps(monkeypatch)

        mw._apply_theme()

        deps["toast"].refresh_for.assert_called_once_with(mw)
