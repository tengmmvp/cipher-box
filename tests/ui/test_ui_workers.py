"""BackgroundWorker 基础测试。

覆盖后台工作器的 finished 与 error 信号发射、异常上报、取消后抑制信号，
以及返回 None 时信号仍正常发射的行为。
"""

from src.ui.components.workers import BackgroundWorker


class TestBackgroundWorker:
    """BackgroundWorker 信号发射和错误处理测试。"""

    def test_finished_emits_result(self, qapp):
        """正常函数应通过 finished 信号返回结果。"""
        results = []

        worker = BackgroundWorker(lambda: (True, 'ok'), None)
        worker.finished.connect(lambda r: results.append(r))
        worker.start()

        # 等待线程完成
        worker.wait(5000)
        # 处理待发信号
        qapp.processEvents()

        assert len(results) == 1
        assert results[0] == (True, 'ok')

    def test_error_emits_on_exception(self, qapp):
        """函数抛异常应通过 error 信号报告。"""
        errors = []

        def _fail():
            raise RuntimeError('test error')

        worker = BackgroundWorker(_fail, None)
        worker.error.connect(lambda e: errors.append(e))
        worker.start()

        worker.wait(5000)
        qapp.processEvents()

        assert len(errors) == 1
        assert 'test error' in errors[0]

    def test_cancelled_worker_no_signal(self, qapp):
        """已取消的工作器不应发射 finished 信号。"""
        results = []

        import threading
        barrier = threading.Event()

        def _slow():
            barrier.wait(timeout=5)
            return (True, 'should not emit')

        worker = BackgroundWorker(_slow, None)
        worker.finished.connect(lambda r: results.append(r))
        worker.start()

        # 立即取消
        worker.cancel()
        barrier.set()  # 让函数继续

        worker.wait(5000)
        qapp.processEvents()

        assert len(results) == 0

    def test_none_result_emitted(self, qapp):
        """函数返回 None 时 finished 信号仍发射 None。"""
        results = []

        worker = BackgroundWorker(lambda: None, None)
        worker.finished.connect(lambda r: results.append(r))
        worker.start()

        worker.wait(5000)
        qapp.processEvents()

        assert len(results) == 1
        assert results[0] is None
