"""CipherBoxApp.run() 状态机测试（stub 登录窗口/主窗口，不驱动真实 GUI）。

范式与 ``tests/test_app.py`` 一致：``CipherBoxApp.__new__`` 绕过 ``__init__`` 的
QApplication/日志/QLockFile 副作用，手动注入 mock 状态；``LoginWindow`` /
``MainWindow`` / ``build_business_context`` 经 monkeypatch 替换为可控桩，从中提取
``on_login`` 闭包直接调用，避免驱动真实登录事件循环。覆盖：

- ``run()``：主题应用、退出码透传、单实例锁失败短路、KeyboardInterrupt 兜底清理；
- ``_show_login``：登录成功构造并显示主窗、登录取消退出、首显完整性告警分支、
  登录窗构造失败（损坏库）弹窗后干净退出（ARCH-061）、锁定后取消退出补齐主窗
  退出清理（ARCH-062）；
- ``_on_lock``：隐藏 → prepare_for_lock → vault.lock → 重回登录的顺序与主窗复用；
- ``_install_crash_handlers`` / ``notify``：excepthook 替换与级联、清理失败不外抛、
  slot 异常兜底返回 False。
"""

import logging
import sys
from unittest.mock import MagicMock

from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtWidgets import QApplication, QDialog

from src.app import CipherBoxApp, CipherBoxApplication

_APP_MODULE = "src.app"
_ACCEPTED = QDialog.DialogCode.Accepted
_REJECTED = QDialog.DialogCode.Rejected


class _FakeQtApp(QObject):
    """QApplication 替身：QObject 提供 aboutToQuit 真实信号，其余方法逐项记录调用。"""

    aboutToQuit = pyqtSignal()

    def __init__(self, exec_result: int = 0, exec_error: BaseException | None = None):
        super().__init__()
        self._exec_result = exec_result
        self._exec_error = exec_error
        self.calls: list[tuple] = []

    def exec(self) -> int:
        self.calls.append(("exec",))
        if self._exec_error is not None:
            raise self._exec_error
        return self._exec_result

    def setStyleSheet(self, sheet: str) -> None:
        self.calls.append(("setStyleSheet", sheet))

    def setApplicationName(self, name: str) -> None:
        self.calls.append(("setApplicationName", name))

    def setOrganizationName(self, name: str) -> None:
        self.calls.append(("setOrganizationName", name))

    def setApplicationVersion(self, version: str) -> None:
        self.calls.append(("setApplicationVersion", version))

    def quit(self) -> None:
        self.calls.append(("quit",))

    def _has(self, name: str) -> bool:
        return any(call[0] == name for call in self.calls)


def _make_app(exec_result: int = 0, exec_error: BaseException | None = None) -> CipherBoxApp:
    """构造注入 mock 状态的 CipherBoxApp（绕过 __init__ 的全局副作用）。"""
    app = CipherBoxApp.__new__(CipherBoxApp)
    app._app = _FakeQtApp(exec_result=exec_result, exec_error=exec_error)
    app._config = MagicMock()
    app._config.get.return_value = "dark"
    app._vault = MagicMock()
    app._main_window = None
    app._running = False
    app._instance_lock = MagicMock()
    app._instance_lock.tryLock.return_value = True
    return app


def _install_scripted_login(monkeypatch, results: list) -> list:
    """替换 src.app.LoginWindow 为脚本化桩，返回按序创建的实例列表。

    results 依次作为各实例 ``exec()`` 的返回值（耗尽后回退 Rejected）；桩捕获
    ``login_success.connect`` 注册的 ``on_login`` 闭包供测试手动触发。
    """
    instances: list = []

    class _ScriptedLogin:
        """LoginWindow 桩：捕获 login_success 回调、按脚本返回 exec 结果。"""

        DialogCode = QDialog.DialogCode

        def __init__(self, vault, config):
            self.login_success = MagicMock()
            self.exec_calls = 0
            instances.append(self)

        def exec(self):
            self.exec_calls += 1
            return results.pop(0) if results else _REJECTED

        def deleteLater(self):
            pass

    monkeypatch.setattr(f"{_APP_MODULE}.LoginWindow", _ScriptedLogin)
    return instances


def _install_main_window(monkeypatch) -> tuple:
    """替换 MainWindow 构造与 build_business_context，返回 (ctor, ctx_factory)。"""
    ctx = MagicMock(name="business_context")
    mw_ctor = MagicMock(name="MainWindow")
    monkeypatch.setattr(f"{_APP_MODULE}.MainWindow", mw_ctor)
    monkeypatch.setattr(f"{_APP_MODULE}.build_business_context", MagicMock(return_value=ctx))
    return mw_ctor, ctx


def _trigger_login_success(login) -> None:
    """提取桩捕获的 on_login 闭包并触发，模拟登录成功信号。"""
    on_login = login.login_success.connect.call_args[0][0]
    on_login()


# ==================================================================== run()


class TestRunStateMachine:
    """run() 主题应用、退出码与单实例/中断兜底。"""

    def test_run_applies_theme_and_returns_exec_code(self, monkeypatch):
        """run() 应激活主题、应用样式与元数据，并透传 exec() 退出码，最终解锁实例锁。"""
        app = _make_app(exec_result=7)
        set_theme = MagicMock()
        monkeypatch.setattr("src.ui.resources.theme_colors.set_theme", set_theme)
        monkeypatch.setattr(f"{_APP_MODULE}.get_style", MagicMock(return_value="QSS"))
        _install_scripted_login(monkeypatch, [_REJECTED])  # 登录取消 → 退出
        _install_main_window(monkeypatch)

        assert app.run() == 7

        set_theme.assert_called_once_with("dark")
        fake = app._app
        assert fake._has("setStyleSheet")
        assert ("setApplicationName", "CipherBox") in fake.calls
        assert fake._has("setApplicationVersion")
        # 登录取消后停止运行并请求退出事件循环
        assert app._running is False
        assert fake._has("quit")
        # finally 分支释放单实例锁
        app._instance_lock.tryLock.assert_called_once()
        app._instance_lock.unlock.assert_called_once()

    def test_run_second_instance_returns_1_without_login(self, monkeypatch):
        """单实例锁获取失败：警告用户、返回 1、不显示登录窗，且不解锁（从未持锁）。"""
        app = _make_app()
        app._instance_lock.tryLock.return_value = False
        warnings: list = []
        monkeypatch.setattr(
            f"{_APP_MODULE}.QMessageBox.warning", lambda *a, **k: warnings.append(a)
        )
        # run() 会激活全局主题：patch 掉避免跨测试泄漏主题状态
        monkeypatch.setattr("src.ui.resources.theme_colors.set_theme", MagicMock())
        instances = _install_scripted_login(monkeypatch, [_ACCEPTED])

        assert app.run() == 1

        assert warnings and warnings[0][1] == "CipherBox"
        assert instances == []  # 未构造登录窗口
        assert app._running is False
        app._instance_lock.unlock.assert_not_called()  # 未持锁不误释放他人锁

    def test_run_keyboard_interrupt_cleans_up_and_unlocks(self, monkeypatch):
        """exec() 抛 KeyboardInterrupt（SIGINT）：兜底清理后返回 1，finally 仍解锁。"""
        app = _make_app(exec_error=KeyboardInterrupt())
        app._emergency_cleanup = MagicMock()
        monkeypatch.setattr(f"{_APP_MODULE}.get_style", MagicMock(return_value=""))
        monkeypatch.setattr("src.ui.resources.theme_colors.set_theme", MagicMock())
        _install_scripted_login(monkeypatch, [_REJECTED])
        _install_main_window(monkeypatch)

        assert app.run() == 1

        # Ctrl+C 路径显式触发非全量清理（不等待 worker，避免阻塞退出）
        app._emergency_cleanup.assert_called_once_with(full=False)
        app._instance_lock.unlock.assert_called_once()


# ================================================================ 登录路径


class TestLoginFlow:
    """_show_login / on_login：登录成功、取消与首显完整性告警。"""

    def test_login_success_builds_and_shows_main_window(self, monkeypatch):
        """登录成功：经业务上下文构造 MainWindow、连接 lock_requested、刷新并显示。"""
        app = _make_app()
        app._running = True
        instances = _install_scripted_login(monkeypatch, [_ACCEPTED])
        mw_ctor, ctx = _install_main_window(monkeypatch)

        app._show_login()
        _trigger_login_success(instances[0])

        mw_ctor.assert_called_once_with(ctx)
        mw = mw_ctor.return_value
        assert app._main_window is mw
        mw.lock_requested.connect.assert_called_once_with(app._on_lock)
        mw.refresh_after_unlock.assert_called_once_with()
        mw.show.assert_called_once_with()

    def test_login_rejected_quits_without_main_window(self, monkeypatch):
        """登录取消：不构造主窗、停止运行并请求退出。"""
        app = _make_app()
        app._running = True
        instances = _install_scripted_login(monkeypatch, [_REJECTED])
        mw_ctor, _ctx = _install_main_window(monkeypatch)

        app._show_login()

        assert app._running is False
        assert app._main_window is None
        mw_ctor.assert_not_called()
        assert app._app._has("quit")
        assert instances[0].exec_calls == 1

    def test_login_rejected_after_lock_runs_exit_cleanup_before_quit(self, monkeypatch):
        """锁定后登录窗被拒绝：quit 前经主窗公共包装补齐退出清理（ARCH-062）。"""
        app = _make_app()
        app._running = True
        instances = _install_scripted_login(monkeypatch, [_ACCEPTED, _REJECTED])
        mw_ctor, _ctx = _install_main_window(monkeypatch)

        app._show_login()
        _trigger_login_success(instances[0])
        mw = mw_ctor.return_value
        order: list = []
        mw.perform_exit_cleanup.side_effect = lambda: order.append("cleanup")
        monkeypatch.setattr(app._app, "quit", lambda: order.append("quit"))

        app._on_lock()  # 锁定 → 第二个登录窗被拒 → 退出

        assert order == ["cleanup", "quit"]  # 清理先于 quit
        assert app._running is False

    def test_login_window_construction_failure_shows_critical_and_quits(self, monkeypatch):
        """登录窗构造抛 SchemaError（损坏库）：翻译文案弹窗后干净退出，不外抛（ARCH-061）。"""
        from src.exceptions import SchemaError

        app = _make_app()
        app._running = True

        class _FailingLogin:
            """LoginWindow 桩：构造即抛 SchemaError（模拟损坏库打开失败）。"""

            DialogCode = QDialog.DialogCode

            def __init__(self, vault, config):
                raise SchemaError("cipherbox-schema 标识不匹配")

        monkeypatch.setattr(f"{_APP_MODULE}.LoginWindow", _FailingLogin)
        criticals: list = []
        monkeypatch.setattr(
            f"{_APP_MODULE}.QMessageBox.critical", lambda *a, **k: criticals.append(a)
        )

        app._show_login()  # 不得外抛

        assert len(criticals) == 1
        assert criticals[0][1] == "启动失败"
        # 文案含 to_user_message 对 SchemaError 的固定中文映射
        assert "数据库结构异常" in criticals[0][2]
        assert app._running is False
        assert app._app._has("quit")

    @staticmethod
    def _prepare_first_show(monkeypatch, reason: str):
        app = _make_app()
        app._running = True
        instances = _install_scripted_login(monkeypatch, [_ACCEPTED])
        _install_main_window(monkeypatch)
        app._config.check_integrity.return_value = False
        app._config.integrity_reason = reason
        warnings: list = []
        monkeypatch.setattr(
            f"{_APP_MODULE}.QMessageBox.warning", lambda *a, **k: warnings.append(a)
        )
        app._show_login()
        _trigger_login_success(instances[0])
        return app, warnings

    def test_first_show_missing_integrity_signature_warns(self, monkeypatch):
        """首显时签名缺失（reason=missing）：提示措辞指向「签名缺失」。"""
        _app_, warnings = self._prepare_first_show(monkeypatch, "missing")

        assert len(warnings) == 1
        assert "签名缺失" in warnings[0][2]

    def test_first_show_corrupt_integrity_warns(self, monkeypatch):
        """首显时签名不符（其他 reason）：提示措辞指向「校验失败」。"""
        _app_, warnings = self._prepare_first_show(monkeypatch, "mismatch")

        assert len(warnings) == 1
        assert "完整性校验失败" in warnings[0][2]

    def test_relogin_after_first_show_skips_integrity_warning(self, monkeypatch):
        """锁定后重登（first_show=False）：不再重复完整性告警。"""
        app = _make_app()
        app._running = True
        instances = _install_scripted_login(monkeypatch, [_ACCEPTED, _ACCEPTED])
        mw_ctor, _ctx = _install_main_window(monkeypatch)
        app._config.check_integrity.return_value = False  # 即使校验失败
        warnings: list = []
        monkeypatch.setattr(
            f"{_APP_MODULE}.QMessageBox.warning", lambda *a, **k: warnings.append(a)
        )

        app._show_login()
        _trigger_login_success(instances[0])
        first_show_warnings = len(warnings)
        app._on_lock()  # 回到登录
        _trigger_login_success(instances[1])

        # 首显告警一次（校验确实失败），重登后不再重复
        assert first_show_warnings == 1
        assert len(warnings) == 1


# ================================================================ 锁定循环


class TestLockLoop:
    """_on_lock：锁定顺序与重回登录循环。"""

    def test_lock_hides_prepares_then_locks_vault_in_order(self, monkeypatch):
        """锁定请求：主窗 hide → prepare_for_lock → vault.lock → 重显登录窗口。"""
        app = _make_app()
        app._running = True
        instances = _install_scripted_login(monkeypatch, [_ACCEPTED, _REJECTED])
        mw_ctor, _ctx = _install_main_window(monkeypatch)

        app._show_login()
        _trigger_login_success(instances[0])
        mw = mw_ctor.return_value
        order: list = []
        mw.hide.side_effect = lambda: order.append("hide")
        mw.prepare_for_lock.side_effect = lambda: order.append("prepare_for_lock")
        app._vault.lock.side_effect = lambda: order.append("vault_lock")

        app._on_lock()

        # hide 先于 prepare_for_lock：锁定收敛窗口立即消失，而非等待 worker 期间滞留
        assert order == ["hide", "prepare_for_lock", "vault_lock"]
        # 重回登录：第二个登录窗口被构造且 exec 再次进入（可重试）
        assert len(instances) == 2
        assert instances[1].exec_calls == 1
        # 第二轮登录取消 → 运行停止
        assert app._running is False

    def test_relogin_reuses_main_window_instance(self, monkeypatch):
        """锁定后重登：复用既有主窗实例，仅重新 refresh + show，不再构造。"""
        app = _make_app()
        app._running = True
        instances = _install_scripted_login(monkeypatch, [_ACCEPTED, _ACCEPTED])
        mw_ctor, _ctx = _install_main_window(monkeypatch)

        app._show_login()
        _trigger_login_success(instances[0])
        app._on_lock()
        _trigger_login_success(instances[1])

        mw_ctor.assert_called_once()  # 全程仅构造一次
        mw = mw_ctor.return_value
        assert mw.refresh_after_unlock.call_count == 2
        assert mw.show.call_count == 2


# ============================================================ 崩溃兜底


class TestCrashHandlers:
    """_install_crash_handlers：excepthook 替换、级联原钩子与 aboutToQuit 接线。"""

    def _install(self, monkeypatch, cleanup) -> tuple[CipherBoxApp, MagicMock]:
        """安装崩溃钩子并返回 (app, 级联原钩子 mock)。

        先经 monkeypatch 替换 ``sys.excepthook`` 为 mock（确保 teardown 恢复原始
        钩子），被测代码将其捕获为级联原钩子——mock 即可断言「原钩子仍被调用」。
        """
        app = _make_app()
        app._emergency_cleanup = cleanup
        chained = MagicMock(name="original")
        monkeypatch.setattr(sys, "excepthook", chained)
        app._install_crash_handlers()
        return app, chained

    def test_excepthook_replaced_and_cleans_up_full(self, monkeypatch):
        """安装后 sys.excepthook 被替换：触发时执行 full 清理并级联原钩子，不崩溃。"""
        cleanup = MagicMock()
        chained = MagicMock()
        monkeypatch.setattr(sys, "excepthook", chained)
        app = _make_app()
        app._emergency_cleanup = cleanup

        app._install_crash_handlers()

        assert sys.excepthook is not chained  # 已被替换
        err = ValueError("boom")
        sys.excepthook(ValueError, err, None)  # 调用不得崩溃

        # excepthook 对应进程仍存活：full=True 等待后台 worker
        cleanup.assert_called_once_with(full=True)
        chained.assert_called_once_with(ValueError, err, None)

    def test_cleanup_failure_inside_excepthook_does_not_propagate(self, monkeypatch):
        """清理自身抛异常时钩子不得外抛（崩溃兜底绝不能再崩溃），原钩子仍被级联。"""
        cleanup = MagicMock(side_effect=RuntimeError("cleanup also fails"))
        _app_, chained = self._install(monkeypatch, cleanup)

        sys.excepthook(ValueError("x"), ValueError("x"), None)  # 不抛即通过

        chained.assert_called_once()

    def test_about_to_quit_triggers_partial_cleanup(self, monkeypatch):
        """aboutToQuit（正常退出路径）触发 full=False 清理：不等待 worker 以免阻塞。"""
        cleanup = MagicMock()
        app, _chained = self._install(monkeypatch, cleanup)

        app._app.aboutToQuit.emit()

        cleanup.assert_called_once_with(full=False)


class TestNotifyFallback:
    """CipherBoxApplication.notify：slot 异常兜底记录并返回 False。"""

    def test_slot_exception_logged_and_returns_false(self, monkeypatch, caplog):
        """slot 回调抛异常：记录完整 traceback、返回 False，不向 Qt 传播。"""
        monkeypatch.setattr(
            QApplication, "notify", MagicMock(side_effect=RuntimeError("slot boom"))
        )
        app = CipherBoxApplication.__new__(CipherBoxApplication)

        with caplog.at_level(logging.ERROR, logger="src.app"):
            assert app.notify(object(), object()) is False

        assert any("信号槽" in r.message for r in caplog.records)

    def test_normal_dispatch_passes_through(self, monkeypatch):
        """正常分发：透传 super().notify 的返回值。"""
        ok = MagicMock(return_value=True)
        monkeypatch.setattr(QApplication, "notify", ok)
        app = CipherBoxApplication.__new__(CipherBoxApplication)

        assert app.notify(object(), object()) is True
