"""后台工作线程，将耗时操作移出主线程。

提供支持协作取消、进度报告与异常捕获的通用 BackgroundWorker，避免阻塞
Qt 事件循环。工作函数完成后会主动释放闭包引用，防止其长期持有密码等
敏感数据。
"""

import logging
import threading

from PyQt6.QtCore import QThread, pyqtSignal

logger = logging.getLogger(__name__)


class BackgroundWorker(QThread):
    """通用后台任务执行器，支持协作取消和进度报告。

    用法::

        worker = BackgroundWorker(lambda: some_heavy_function(arg1, arg2))
        worker.finished.connect(self._on_done)
        worker.error.connect(self._on_error)
        worker.start()

    带进度::

        def heavy_task():
            for i in range(100):
                worker.emit_progress(i, 100)
                do_work(i)
            return result

        worker = BackgroundWorker(heavy_task)
        worker.progress.connect(lambda cur, total: progress_bar.setValue(cur))
        worker.start()

    取消::

        worker.cancel()      # 设置取消标志
        worker.wait(3000)     # 等待线程结束
    """

    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    cancelled = pyqtSignal()
    progress = pyqtSignal(int, int)

    def __init__(self, func, parent=None):
        """初始化后台工作线程。

        Args:
            func: 要在线程中执行的函数。闭包可能捕获敏感数据如密码，
                函数执行完毕后 self._func 会被置 None 以释放闭包引用。
            parent: 父对象。若提供，QThread 作为 parent 的子对象，在 parent
                销毁时一同被销毁。调用方须确保 parent 销毁前 worker 已完成
                即调用 cancel() + wait()，否则可能导致崩溃。
        """
        super().__init__(parent)
        self._func = func
        self._cancel_event = threading.Event()

    @property
    def is_cancelled(self) -> bool:
        """工作函数可定期检查此属性以实现提前退出。"""
        return self._cancel_event.is_set()

    def cancel(self):
        """请求协作取消。工作函数需自行检查 is_cancelled 并提前返回。"""
        self._cancel_event.set()

    def emit_progress(self, current: int, total: int):
        """从工作函数内部发射进度信号，线程安全。

        从工作线程调用时，信号通过 Qt 的队列连接安全传递到主线程。
        """
        self.progress.emit(current, total)

    def run(self):
        func = self._func
        if func is None:
            return
        try:
            result = func()
            if self._cancel_event.is_set():
                self.cancelled.emit()
            else:
                self.finished.emit(result)
        except Exception as e:
            if self._cancel_event.is_set():
                logger.debug('已取消的工作器异常：%s', e)
                return
            self.error.emit(str(e))
        finally:
            # 释放闭包引用，可能捕获密码等敏感数据
            self._func = None
