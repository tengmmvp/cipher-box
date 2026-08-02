"""``wait_worker_shutdown``（单数）测试。

与 ``test_ui_workers.py``（覆盖 ``BackgroundWorker`` 信号发射）互补，本文件聚焦
``src/ui/components/workers.py::wait_worker_shutdown`` 的四条关闭分支：

- None / 未运行 → 短路返回 True。
- cancel=False → 仅等待、不请求协作取消（写入副作用操作的安全关闭）。
- 超时后仍运行 → 兜底再等一个同等周期（error 告警）。
- 兜底后仍运行 → 记 critical 后放弃等待，返回 False（避免关闭永久卡死）。

复用 ``test_emergency_cancel.py`` 的假 worker 模式，扩展为可控 ``isRunning()``
序列，以驱动 wait_worker_shutdown 内多次 ``isRunning()`` 探测的分支选择。
"""

import logging

from src.ui.components.workers import wait_worker_shutdown


class _FakeWorker:
    """``BackgroundWorker`` 替身：按预定序列响应 isRunning()，记录 cancel/wait。

    ``running_sequence`` 给出 ``isRunning()`` 逐次调用的返回值（按调用顺序消费）；
    耗尽后返回 False。这样可精确驱动 wait_worker_shutdown 的「entry 检查 / 首次 wait
    后 / 兜底 wait 后 / 最终 return」四次 isRunning() 探测。
    """

    def __init__(self, running_sequence: list[bool]) -> None:
        self._running = list(running_sequence)
        self.cancel_calls = 0
        self.wait_calls: list[int] = []

    def isRunning(self) -> bool:
        if self._running:
            return self._running.pop(0)
        return False

    def cancel(self) -> None:
        self.cancel_calls += 1

    def wait(self, timeout: int) -> bool:
        self.wait_calls.append(timeout)
        return True


class TestWaitWorkerShutdown:
    """wait_worker_shutdown 的短路、cancel 分支与超时兜底关闭。"""

    def test_none_worker_short_circuits(self):
        """worker=None 直接返回 True，无 cancel/wait 调用。"""
        assert wait_worker_shutdown(None) is True

    def test_not_running_short_circuits(self):
        """worker 未运行（isRunning()=False）直接返回 True。"""
        worker = _FakeWorker([False])
        assert wait_worker_shutdown(worker, timeout=100) is True
        assert worker.wait_calls == []
        assert worker.cancel_calls == 0

    def test_cancel_false_only_waits_no_cancel_request(self):
        """cancel=False：正常运行结束后等待，但不请求协作取消。

        恢复/导入等有写入副作用的操作传 False，仅等其自然完成以确保数据一致性，
        不发取消信号中断写入半途。
        """
        # isRunning 序列：entry=True，首次 wait 后 False，其后两次检查 False
        worker = _FakeWorker([True, False, False, False])

        result = wait_worker_shutdown(worker, cancel=False, timeout=300)

        assert result is True
        assert worker.cancel_calls == 0  # 未请求取消
        assert worker.wait_calls == [300]  # 仅一次等待（首_wait 即结束）

    def test_default_cancel_true_requests_cancel(self):
        """cancel 默认 True：entry 运行中 → 调 cancel() 后 wait()。"""
        worker = _FakeWorker([True, False, False, False])

        result = wait_worker_shutdown(worker, timeout=300)

        assert result is True
        assert worker.cancel_calls == 1
        assert worker.wait_calls == [300]

    def test_timeout_triggers_secondary_wait_and_logs_error(self, caplog):
        """首次 wait 超时后仍运行 → 兜底再等一个同等周期，并记 error 告警。

        QThread 析构时处于 running 会触发 Qt 致命警告并崩溃；兜底等待提升可见性，
        正常 cancel_check 应使长操作快速退出，不应频繁触发此告警。
        """
        # isRunning：entry=True，首_wait 后仍 True（触发兜底），兜底_wait 后 False
        worker = _FakeWorker([True, True, False, False])

        with caplog.at_level(logging.ERROR, logger="src.ui.components.workers"):
            result = wait_worker_shutdown(worker, timeout=200)

        assert result is True
        assert worker.wait_calls == [200, 200]  # 两次等待
        assert worker.cancel_calls == 1
        assert any("仍在运行" in r.message for r in caplog.records)

    def test_critical_abandons_when_still_running_after_secondary_wait(self, caplog):
        """兜底等待后仍运行（极端卡死）→ 记 critical 后放弃，返回 False。

        继续无限等待会让关闭永久挂起，比 QThread 析构警告更影响体验；放弃等待由
        调用方决定后续，不调 terminate() 以免留下未释放资源与不一致状态。
        """
        # isRunning：四次探测全 True（永不停止）
        worker = _FakeWorker([True, True, True, True])

        with caplog.at_level(logging.CRITICAL, logger="src.ui.components.workers"):
            result = wait_worker_shutdown(worker, timeout=150)

        assert result is False
        assert worker.wait_calls == [150, 150]  # 兜底仅一次额外等待，不无限重试
        assert any("放弃等待" in r.message for r in caplog.records)

    def test_timeout_none_uses_default_constant(self, monkeypatch):
        """timeout=None 时从 ``constants.WORKER_WAIT_TIMEOUT_MS`` 取默认值。"""
        # patch constants 模块的常量，验证 wait 收到该值
        from src.ui.resources import constants

        monkeypatch.setattr(constants, "WORKER_WAIT_TIMEOUT_MS", 4321)
        worker = _FakeWorker([True, False, False, False])

        wait_worker_shutdown(worker)  # timeout 默认 None

        assert worker.wait_calls == [4321]
