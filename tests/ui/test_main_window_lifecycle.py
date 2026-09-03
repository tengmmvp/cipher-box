"""MainWindow 退出/托盘/主题生命周期顺序测试（真实构造 + stub 业务成员）。

经 ``main_window_factory.make_main_window`` 走真实构造链（与 app.py 的
``MainWindow(build_business_context(...))`` 同构，业务成员为预配置 mock），替代
原 ``MainWindow.__new__(MainWindow)`` 手工布线 10+ 私有属性的深链耦合——半初始化
对象上未布线属性缺失，重构新增依赖只能靠 AttributeError 兜底发现。各测试再把
需观测顺序的协作方覆写为 MagicMock 探针（实例属性赋值遮蔽真实属性）。覆盖：

- ``_perform_exit_cleanup``：重点守护 ARCH-009——模态对话框 reject 必须先于
  ``vault.close``，顺序错会触发 sqlite 连接撕裂 + QThread running 析构崩溃；
- ``_secure_hide_to_tray``：隐藏到托盘前的明文清理序列（面板清空/剪贴板清空/
  定时器停止/pending 取消/worker 停止）；
- ``_apply_theme``：主题切换的图标清单重建与 delegate 颜色缓存清理；
- ``_notify_irreversible_worker_wait``：锁定/退出等待不可中断 worker 前的托盘
  系统通知（PERF-082）。
"""

from unittest.mock import MagicMock

from PyQt6.QtWidgets import QDialog

from src.ui.components.widgets import WorkerBackedDialog
from tests.ui.main_window_factory import make_main_window

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


def _attach_exit_recorders(mw, ctx, order: list, *, tray) -> None:
    """把退出清理序列的各协作方覆写为记录探针（遮蔽工厂构造的真实实例）。"""
    mw._auto_lock = MagicMock()
    mw._auto_lock.remove_session_filter.side_effect = _record(order, "session_filter")
    mw._list_refresh = MagicMock()
    mw._list_refresh.shutdown.side_effect = _record(order, "list_shutdown")
    mw._auto_backup = MagicMock()
    mw._auto_backup.shutdown.side_effect = _record(order, "auto_backup_shutdown")
    mw._clipboard = MagicMock()
    mw._clipboard.clear_now.side_effect = _record(order, "clipboard_clear")
    ctx.vault.close.side_effect = _record(order, "vault_close")
    mw._tray = tray
    if tray is not None:
        tray.hide.side_effect = _record(order, "tray_hide")


def _make_exit_window(tmp_path, order: list, *, tray) -> tuple:
    """真实构造的 MainWindow，各清理步骤经 side_effect 记录进 order。"""
    mw, ctx = make_main_window(tmp_path)
    _attach_exit_recorders(mw, ctx, order, tray=tray)
    return mw, ctx


class TestPerformExitCleanup:
    """_perform_exit_cleanup 调用序列：对话框 reject 必须先于 vault.close（ARCH-009）。"""

    def test_rejects_modal_dialogs_before_closing_vault(self, qapp, tmp_path, monkeypatch):
        """模态对话框 reject 先于 vault.close，防 sqlite 撕裂 + QThread 析构崩溃。"""
        order: list = []
        dialog = MagicMock(spec=QDialog)
        dialog.reject.side_effect = _record(order, "dialog_reject")
        app = _patch_qapp(monkeypatch, [dialog])
        mw, _ctx = _make_exit_window(tmp_path, order, tray=MagicMock())

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

    def test_clipboard_cleared_before_vault_close(self, qapp, tmp_path, monkeypatch):
        """剪贴板明文清理先于 vault.close（关库后无法再取密钥清剪贴板）。"""
        order: list = []
        _patch_qapp(monkeypatch, [])
        mw, _ctx = _make_exit_window(tmp_path, order, tray=None)

        mw._perform_exit_cleanup()

        assert order.index("clipboard_clear") < order.index("vault_close")

    def test_workers_shutdown_before_dialog_reject(self, qapp, tmp_path, monkeypatch):
        """后台 worker 停止先于对话框 reject（reject 内等待不再有活跃 worker）。"""
        order: list = []
        dialog = MagicMock(spec=QDialog)
        dialog.reject.side_effect = _record(order, "dialog_reject")
        _patch_qapp(monkeypatch, [dialog])
        mw, _ctx = _make_exit_window(tmp_path, order, tray=None)

        mw._perform_exit_cleanup()

        assert order.index("list_shutdown") < order.index("dialog_reject")
        assert order.index("auto_backup_shutdown") < order.index("dialog_reject")

    def test_no_tray_skips_tray_hide_without_error(self, qapp, tmp_path, monkeypatch):
        """无托盘实例（_tray=None）时跳过托盘隐藏，不抛异常。"""
        order: list = []
        _patch_qapp(monkeypatch, [])
        mw, _ctx = _make_exit_window(tmp_path, order, tray=None)

        mw._perform_exit_cleanup()

        assert "tray_hide" not in order
        assert order[-1] == "vault_close"

    def test_non_dialog_toplevel_widgets_not_rejected(self, qapp, tmp_path, monkeypatch):
        """非 QDialog 顶层控件不被 reject（reject 仅针对模态对话框）。"""
        order: list = []
        plain_widget = MagicMock()  # 无 spec：isinstance(plain, QDialog) 为 False
        dialog = MagicMock(spec=QDialog)
        dialog.reject.side_effect = _record(order, "dialog_reject")
        _patch_qapp(monkeypatch, [plain_widget, dialog])
        mw, _ctx = _make_exit_window(tmp_path, order, tray=None)

        mw._perform_exit_cleanup()

        dialog.reject.assert_called_once()
        plain_widget.reject.assert_not_called()

    def test_no_dialogs_closes_vault_directly(self, qapp, tmp_path, monkeypatch):
        """无模态对话框时直接走到 vault.close，不因空列表异常。"""
        order: list = []
        _patch_qapp(monkeypatch, [])
        mw, _ctx = _make_exit_window(tmp_path, order, tray=None)

        mw._perform_exit_cleanup()

        assert "vault_close" in order


def _busy_dialog(qapp, *, cancel_on_close: bool) -> WorkerBackedDialog:
    """构造真实 WorkerBackedDialog 实例（占位控件），worker 为运行中的替身。

    用真实实例而非 ``MagicMock(spec=...)``：``_worker`` 是仅类级注解的属性（无
    值），spec 替身访问它会抛 AttributeError；真实实例可经实例属性自由赋值，
    isinstance 检查天然通过。
    """
    dialog = WorkerBackedDialog()
    dialog._worker = MagicMock()
    dialog._worker.isRunning.return_value = True
    dialog._cancel_on_close = lambda: cancel_on_close  # type: ignore[method-assign]
    return dialog


class TestIrreversibleWorkerWaitNotify:
    """锁定/退出等待不可中断 worker 前的托盘系统通知（PERF-082）。

    清理-等待序列会阻塞主线程直至恢复/导入 worker 完成（50k 库 15-25s），
    冻结无提示易致用户强杀进程；通知经托盘 showMessage（原生系统通知）发出，
    无托盘时退化为 info 日志。不做真实 120s 等待集成测试，仅验证触发点。
    """

    def test_busy_irreversible_dialog_sends_tray_message(self, qapp, tmp_path, monkeypatch):
        """运行中的不可中断对话框 worker → 托盘系统通知一次。"""
        tray = MagicMock()
        dialog = _busy_dialog(qapp, cancel_on_close=False)
        _patch_qapp(monkeypatch, [dialog])
        mw, _ctx = make_main_window(tmp_path)
        mw._tray = tray

        mw._notify_irreversible_worker_wait()

        tray.showMessage.assert_called_once()
        args = tray.showMessage.call_args.args
        assert "等待" in args[0] or "后台任务" in args[0]  # 标题或正文含等待语义
        assert "后台任务" in args[1]

    def test_idle_dialog_does_not_notify(self, qapp, tmp_path, monkeypatch):
        """对话框 worker 已结束 → 不发通知（等待序列不阻塞，无需提示）。"""
        tray = MagicMock()
        dialog = _busy_dialog(qapp, cancel_on_close=False)
        dialog._worker.isRunning.return_value = False
        _patch_qapp(monkeypatch, [dialog])
        mw, _ctx = make_main_window(tmp_path)
        mw._tray = tray

        mw._notify_irreversible_worker_wait()

        tray.showMessage.assert_not_called()

    def test_cancellable_running_worker_does_not_notify(self, qapp, tmp_path, monkeypatch):
        """可取消 worker 运行中 → 不发通知（reject 会取消而非长等待）。"""
        tray = MagicMock()
        dialog = _busy_dialog(qapp, cancel_on_close=True)
        _patch_qapp(monkeypatch, [dialog])
        mw, _ctx = make_main_window(tmp_path)
        mw._tray = tray

        mw._notify_irreversible_worker_wait()

        tray.showMessage.assert_not_called()

    def test_no_tray_falls_back_to_log_without_error(self, qapp, tmp_path, monkeypatch):
        """托盘禁用（_tray=None）时不抛异常，退化为日志（锁定路径不因此阻断）。"""
        dialog = _busy_dialog(qapp, cancel_on_close=False)
        _patch_qapp(monkeypatch, [dialog])
        mw, _ctx = make_main_window(tmp_path)

        mw._notify_irreversible_worker_wait()  # 不抛即通过

    def test_plain_dialog_only_never_notifies(self, qapp, tmp_path, monkeypatch):
        """非 WorkerBackedDialog 的普通 QDialog（无 worker 契约）不触发通知。"""
        tray = MagicMock()
        dialog = MagicMock(spec=QDialog)
        _patch_qapp(monkeypatch, [dialog])
        mw, _ctx = make_main_window(tmp_path)
        mw._tray = tray

        mw._notify_irreversible_worker_wait()

        tray.showMessage.assert_not_called()

    def test_prepare_for_lock_notifies_before_waiting_workers(self, qapp, tmp_path, monkeypatch):
        """prepare_for_lock 的通知先于 _shutdown_workers 与对话框 reject。"""
        order: list = []
        dialog = MagicMock(spec=QDialog)
        dialog.reject.side_effect = _record(order, "dialog_reject")
        _patch_qapp(monkeypatch, [dialog])
        mw, _ctx = make_main_window(tmp_path)
        mw._tray = MagicMock()
        mw._entry_actions = MagicMock()
        mw._auto_lock = MagicMock()
        mw._list_refresh = MagicMock()
        mw._list_refresh.prepare_for_lock.side_effect = _record(order, "list_prepare")
        mw._list_refresh.shutdown.side_effect = _record(order, "list_shutdown")
        mw._list_refresh.stop_timers.side_effect = _record(order, "list_stop_timers")
        mw._auto_backup = MagicMock()
        mw._auto_backup.shutdown.side_effect = _record(order, "auto_backup_shutdown")
        mw._entry_model = MagicMock()
        mw._detail_panel = MagicMock()
        mw._clipboard = MagicMock()
        mw._count_label = MagicMock()
        mw._status_bar = MagicMock()
        # 注入检测桩：直接命中「存在不可中断 worker」分支验证调用点顺序
        mw._has_irreversible_running_worker = lambda: _record(order, "notify")() or True
        monkeypatch.setattr(f"{_MW_MODULE}.ToastManager", MagicMock())

        mw.prepare_for_lock()

        assert order.index("notify") < order.index("list_shutdown")
        assert order.index("notify") < order.index("dialog_reject")

    def test_exit_cleanup_notifies_before_waiting_workers(self, qapp, tmp_path, monkeypatch):
        """_perform_exit_cleanup 的通知先于 _shutdown_workers（退出路径同款）。"""
        order: list = []
        _patch_qapp(monkeypatch, [])
        mw, _ctx = _make_exit_window(tmp_path, order, tray=MagicMock())
        mw._has_irreversible_running_worker = lambda: _record(order, "notify")() or True

        mw._perform_exit_cleanup()

        assert order.index("notify") < order.index("list_shutdown")
        assert order.index("notify") < order.index("vault_close")


class TestSecureHideToTray:
    """_secure_hide_to_tray 明文清理序列（托盘态保持解锁，不关 vault）。"""

    def test_clears_plaintext_and_stops_workers_in_order(self, qapp, tmp_path, monkeypatch):
        """面板清空→剪贴板清空→定时器停止→pending 取消→worker 停止，vault 不关闭。"""
        order: list = []
        mw, _ctx = make_main_window(tmp_path)
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

    def test_stops_pending_selection_debounce(self, qapp, tmp_path, monkeypatch):
        """隐藏到托盘取消 pending 选择，防止托盘态防抖回调触发解密。"""
        mw, _ctx = make_main_window(tmp_path)
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

    def _make_window(self, tmp_path, current: str, new: str) -> tuple:
        """真实构造窗口，主题配置为 new、内存主题标记为 current（构造后覆写）。"""
        mw, ctx = make_main_window(tmp_path)
        ctx.config.set("theme", new)
        # 实例属性覆盖 host 方法/控件（不构造真实控件树）
        mw._current_theme = current
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
        return mw, ctx

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

    def test_theme_change_rebuilds_icon_inventory(self, qapp, tmp_path, monkeypatch):
        """主题变化：重建筛选列表与菜单图标、重设按钮/搜索框图标、托盘解锁态。"""
        mw, _ctx = self._make_window(tmp_path, current="light", new="dark")
        deps = self._patch_theme_deps(monkeypatch)

        mw._apply_theme()

        assert mw._current_theme == "dark"
        deps["set_theme"].assert_called_once_with("dark")
        mw._build_filter_list.assert_called_once_with()
        mw._menu.update_menu_icons.assert_called_once_with()
        deps["set_icon_with_text"].assert_called_once()
        mw._search_action.setIcon.assert_called_once()
        mw._tray.set_locked.assert_called_once_with(False)

    def test_theme_change_clears_delegate_cache_and_rebuilds_list(
        self, qapp, tmp_path, monkeypatch
    ):
        """主题变化：清 delegate 颜色缓存并重建筛选列表（烘焙色需重算）。"""
        mw, _ctx = self._make_window(tmp_path, current="light", new="dark")
        self._patch_theme_deps(monkeypatch)

        mw._apply_theme()

        mw._entry_delegate.clear_color_cache.assert_called_once_with()
        mw._entry_list.update.assert_called_once_with()
        mw._list_refresh.rebuild_for_theme.assert_called_once_with()

    def test_theme_change_with_selection_refreshes_detail_force(self, qapp, tmp_path, monkeypatch):
        """有选中条目时强制刷新详情面板（恢复用户当前查看的条目）。"""
        mw, _ctx = self._make_window(tmp_path, current="light", new="dark")
        self._patch_theme_deps(monkeypatch)
        current = MagicMock()
        mw._detail_panel.current_entry = current

        mw._apply_theme()

        # data_epoch/data_version 回传面板记录的世代与版本快照（SEC-054/063
        # 必传签名，force 重建复用路径）
        mw._detail_panel.show_entry.assert_called_once_with(
            current,
            force=True,
            data_epoch=mw._detail_panel.current_data_epoch,
            data_version=mw._detail_panel.current_data_version,
        )
        mw._detail_panel.show_empty.assert_not_called()

    def test_theme_change_without_selection_shows_empty(self, qapp, tmp_path, monkeypatch):
        """无选中条目时详情面板置空（不恢复用户已取消选择的条目）。"""
        mw, _ctx = self._make_window(tmp_path, current="light", new="dark")
        self._patch_theme_deps(monkeypatch)
        mw._detail_panel.current_entry = None

        mw._apply_theme()

        mw._detail_panel.show_empty.assert_called_once_with()
        mw._detail_panel.show_entry.assert_not_called()

    def test_theme_unchanged_is_noop(self, qapp, tmp_path, monkeypatch):
        """主题未变时不触发任何重建（避免无谓的图标/缓存重算）。"""
        mw, _ctx = self._make_window(tmp_path, current="light", new="light")
        deps = self._patch_theme_deps(monkeypatch)

        mw._apply_theme()

        mw._build_filter_list.assert_not_called()
        mw._menu.update_menu_icons.assert_not_called()
        deps["set_theme"].assert_not_called()
        mw._entry_delegate.clear_color_cache.assert_not_called()
        mw._list_refresh.rebuild_for_theme.assert_not_called()
        deps["toast"].refresh_for.assert_not_called()

    def test_theme_change_refreshes_active_toasts(self, qapp, tmp_path, monkeypatch):
        """主题变化刷新活跃 Toast 的烘焙配色。"""
        mw, _ctx = self._make_window(tmp_path, current="light", new="dark")
        deps = self._patch_theme_deps(monkeypatch)

        mw._apply_theme()

        deps["toast"].refresh_for.assert_called_once_with(mw)


class TestPersistWindowStateKeepsIntegrityWarning:
    """_persist_window_state 的退出路径自动写盘保留完整性告警（QL-064 补全）。"""

    def test_window_state_save_keeps_integrity_warning(self, qapp, tmp_path):
        """告警置位 + 窗口状态持久化后告警仍在（退出不清篡改证据）。

        closeEvent/托盘退出的 save 不是用户驱动的配置修复，本会话检出的完整性
        告警不得被静默清零（与哨兵登记同语义）；窗口几何/排序非安全敏感，保留
        告警不影响其持久化——磁盘文件照常以本机密钥重签，下个会话自然无告警。
        """
        mw, ctx = make_main_window(tmp_path)
        config = ctx.config
        # 建立干净签名的 config 后篡改 JSON（保留旧签名）→ 重载检出签名失配
        config.save()
        raw = config.config_path.read_text(encoding="utf-8")
        json_text, sig_line = raw.rsplit("\n", 1)
        config.config_path.write_text(
            json_text.replace('"theme": "light"', '"theme": "dark"') + "\n" + sig_line,
            encoding="utf-8",
        )
        config.load()
        assert not config.check_integrity()

        mw._persist_window_state()

        # 告警仍在：退出路径的自动写盘不消除篡改证据
        assert not config.check_integrity()
        assert config.integrity_reason == "mismatch"
        # 窗口状态确已持久化（save 真实落盘且带新签名）
        assert config.get("window_geometry") is not None
        assert "#__sig__:" in config.config_path.read_text(encoding="utf-8")
