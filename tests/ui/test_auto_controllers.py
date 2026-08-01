"""AutoBackupController 与 AutoLockController 直接单测（rank 10）。

业务编排（maybe_auto_backup、WTS 注册降级）已由 test_product_hardening 端到端覆盖；
本文件守护控制器的内部状态机：worker 运行中跳过、idle 启动、定时器按解锁态启停、
WTS 注册的环境短路与幂等——这些分支在端到端测试中难以稳定触发。
"""

# 测试大量用 MagicMock 注入依赖，抑制其属性访问的静态类型告警
# pyright: reportAttributeAccessIssue=false

from unittest.mock import MagicMock

from src.ui.controllers.auto_backup_controller import AutoBackupController
from src.ui.controllers.auto_lock_controller import AutoLockController


class TestAutoBackupController:
    """AutoBackupController._run_async 状态机守护。"""

    def test_run_async_skips_when_worker_running(self, qapp):
        """上一备份 worker 仍运行时跳过新请求，避免覆盖引用致孤儿线程在锁定后访问已清零密钥。"""
        ctrl = AutoBackupController(MagicMock(), MagicMock(), MagicMock())
        ctrl._vault.is_unlocked = True
        running = MagicMock()
        running.isRunning.return_value = True
        ctrl._worker = running
        ctrl._run_async()
        # worker 未被替换（新请求被跳过），maybe_auto_backup 未被调用
        assert ctrl._worker is running
        ctrl._backup.maybe_auto_backup.assert_not_called()

    def test_run_async_starts_worker_and_wires_cancel_check(self, qapp, monkeypatch):
        """idle 时启动 worker；task 调 maybe_auto_backup 并传入可调用的 cancel_check。"""
        ctrl = AutoBackupController(MagicMock(), MagicMock(), MagicMock())
        ctrl._vault.is_unlocked = True
        captured: dict = {}

        class _FakeWorker:
            def __init__(self, func, parent=None):
                captured['func'] = func
                self.error = MagicMock()

            def cancel_check(self):
                return False

            def start(self):
                captured['started'] = True

        monkeypatch.setattr(
            'src.ui.controllers.auto_backup_controller.BackgroundWorker', _FakeWorker,
        )
        ctrl._run_async()
        assert captured.get('started') is True
        # 执行捕获的 task：验证 maybe_auto_backup 被调，且 cancel_check 是可调用探针
        captured['func']()
        ctrl._backup.maybe_auto_backup.assert_called_once()
        kwargs = ctrl._backup.maybe_auto_backup.call_args.kwargs
        assert callable(kwargs['cancel_check'])


class TestAutoLockController:
    """AutoLockController.reset_timer 与 setup_session_notification 守护。"""

    def test_reset_timer_stops_when_locked(self, qapp):
        """未解锁时停止定时器，不在锁定态空转重启。"""
        ctrl = AutoLockController(MagicMock(), MagicMock(), lambda: None)
        timer = MagicMock()
        ctrl._lock_timer = timer
        ctrl._vault.is_unlocked = False
        ctrl._config.get_safe.return_value = 5
        ctrl.reset_timer()
        timer.stop.assert_called_once()
        timer.start.assert_not_called()

    def test_reset_timer_starts_with_configured_minutes(self, qapp):
        """已解锁时按 auto_lock_minutes（分钟→毫秒）启动定时器。"""
        ctrl = AutoLockController(MagicMock(), MagicMock(), lambda: None)
        timer = MagicMock()
        ctrl._lock_timer = timer
        ctrl._vault.is_unlocked = True
        ctrl._config.get_safe.return_value = 5
        ctrl.reset_timer()
        timer.start.assert_called_once_with(5 * 60 * 1000)

    def test_reset_timer_stops_when_disabled_with_session_lock(self, qapp):
        """auto_lock_minutes=0(用户禁用)且会话锁屏联动可用时停止,依赖系统锁屏兜底。"""
        ctrl = AutoLockController(MagicMock(), MagicMock(), lambda: None)
        timer = MagicMock()
        ctrl._lock_timer = timer
        ctrl._vault.is_unlocked = True
        ctrl._config.get_safe.return_value = 0
        # 会话锁屏联动可用:0 为合法禁用,放行
        ctrl._wts_registered = True
        ctrl.reset_timer()
        timer.stop.assert_called_once()
        timer.start.assert_not_called()

    def test_reset_timer_clamps_zero_in_degraded_path(self, qapp):
        """退化路径(无会话锁屏联动)下 auto_lock_minutes=0 不允许禁用,降级为默认值启动。

        SEC-005:非 Windows / WTS 注册失败 / 测试环境下无系统锁屏兜底,0 即彻底无自动
        锁定,须强制一个不可关闭的空闲锁定上限。
        """
        from src.config import DEFAULT_CONFIG
        ctrl = AutoLockController(MagicMock(), MagicMock(), lambda: None)
        timer = MagicMock()
        ctrl._lock_timer = timer
        ctrl._vault.is_unlocked = True
        ctrl._config.get_safe.return_value = 0
        # 退化路径:_wts_registered 保持默认 False
        ctrl.reset_timer()
        timer.start.assert_called_once_with(DEFAULT_CONFIG['auto_lock_minutes'] * 60 * 1000)
        timer.stop.assert_not_called()

    def test_setup_session_notification_short_circuits_on_disable_env(self, qapp, monkeypatch):
        """CIPHERBOX_DISABLE_WTS 设置时跳过 WTS 注册（不安装过滤器），降级为仅超时锁定。"""
        monkeypatch.setenv('CIPHERBOX_DISABLE_WTS', '1')
        ctrl = AutoLockController(MagicMock(), MagicMock(), lambda: None)
        ctrl.setup_session_notification(MagicMock())
        assert ctrl._wts_setup_attempted is True
        assert ctrl._wts_registered is False
        assert ctrl._session_filter is None

    def test_setup_session_notification_is_idempotent(self, qapp, monkeypatch):
        """_wts_setup_attempted 守卫使注册仅发生一次，二次调用直接短路不抛错。"""
        monkeypatch.setenv('CIPHERBOX_DISABLE_WTS', '1')
        ctrl = AutoLockController(MagicMock(), MagicMock(), lambda: None)
        ctrl.setup_session_notification(MagicMock())
        # 二次调用不应抛错且状态不变（幂等）
        ctrl.setup_session_notification(MagicMock())
        assert ctrl._wts_setup_attempted is True
        assert ctrl._wts_registered is False
