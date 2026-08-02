"""后台工作线程，将耗时操作移出主线程。

提供支持协作取消、进度报告与异常捕获的通用 BackgroundWorker，避免阻塞
Qt 事件循环。工作函数完成后会主动释放闭包引用，防止其长期持有密码等
敏感数据。
"""

import logging
import threading
from collections.abc import Callable
from typing import Any, Generic, TypeVar

from PyQt6.QtCore import QObject, QThread, pyqtSignal

from ...exceptions import CipherBoxError
from ..error_messages import to_user_message

logger = logging.getLogger(__name__)

_T = TypeVar("_T")


def _worker_error_message(exc: Exception) -> str:
    """归一化 worker 异常为 error 信号消息。

    领域异常（CipherBoxError 家族）经 to_user_message 翻译为友好文案，避免内部
    细节或潜在明文经 ``str(exc)`` 泄漏到 UI；非领域异常保留 ``str(exc)`` 的可操作
    消息。完整堆栈已在调用方经 ``logger.error(exc_info=True)`` 记录，error 信号只
    承载用户可见文案，不承担诊断职责。
    """
    if isinstance(exc, CipherBoxError):
        return to_user_message(exc)
    return str(exc)


class BackgroundWorker(QThread, Generic[_T]):
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

    def __init__(self, func: Callable[[], _T], parent: QObject | None = None):
        """初始化后台工作线程。

        Args:
            func: 要在线程中执行的函数。闭包可能捕获敏感数据如密码，
                函数执行完毕后 self._func 会被置 None 以释放闭包引用。泛型参数
                ``_T`` 由 func 返回类型推断，使 worker 的结果类型可静态追踪
                （``finished`` 信号因 PyQt 运行时仍是 ``object``，消费侧仍需收窄）。
            parent: 父对象。若提供，QThread 作为 parent 的子对象，在 parent
                销毁时一同被销毁。调用方须确保 parent 销毁前 worker 已完成
                即调用 cancel() + wait()，否则可能导致崩溃。
        """
        super().__init__(parent)
        self._func: Callable[[], _T] | None = func
        self._cancel_event = threading.Event()

    @property
    def is_cancelled(self) -> bool:
        """工作函数可定期检查此属性以实现提前退出。"""
        return self._cancel_event.is_set()

    def cancel(self) -> None:
        """请求协作取消。工作函数需自行检查 is_cancelled 并提前返回。"""
        self._cancel_event.set()

    def cancel_check(self) -> bool:
        """取消探针的 :class:`Callable[[], bool]` 形式。

        与 :attr:`is_cancelled` 同义（前者是属性访问，本方法是无参绑定方法），
        便于直接传入业务层期望 ``Callable[[], bool]`` 的 ``cancel_check`` 形参。
        """
        return self._cancel_event.is_set()

    def emit_progress(self, current: int, total: int) -> None:
        """从工作函数内部发射进度信号，线程安全。

        从工作线程调用时，信号通过 Qt 的队列连接安全传递到主线程。
        """
        self.progress.emit(current, total)

    def run(self) -> None:
        """工作线程主体，``func`` 在此于工作线程执行。

        ``func`` 内禁止直接操作 Qt 控件——控件仅可在主线程访问；结果须经由
        ``finished``/``error``/``progress`` 等信号回到主线程，Qt 自动以队列连接跨线程投递。
        """
        func = self._func
        if func is None:
            return
        try:
            result = func()
        except Exception as e:
            # 异常意味着操作真正失败，即使此刻被取消也必须上报错误；
            # 否则用户会误以为操作成功（如导出失败时静默关闭对话框）。
            # cancelled 信号只在 func 正常返回但检测到取消请求时发出，
            # 以区分「干净取消」与「取消途中真正出错」。
            # error 信号只传消息字符串给 UI（用户可见），完整堆栈在 worker 线程
            # 记录到日志，避免「error 信号已脱离异常上下文，exc_info 无堆栈可诊断」。
            logger.error("后台 worker 执行失败", exc_info=True)
            self.error.emit(_worker_error_message(e))
        else:
            if self._cancel_event.is_set():
                self.cancelled.emit()
            else:
                self.finished.emit(result)
        finally:
            # 释放闭包引用，可能捕获密码等敏感数据
            self._func = None


def wait_worker_shutdown(
    worker: BackgroundWorker[Any] | None,
    *,
    cancel: bool = True,
    timeout: int | None = None,
) -> bool:
    """取消并等待后台 worker 结束，统一关闭时的取消-等待模式。

    Args:
        worker: BackgroundWorker 实例，为 None 或未运行时直接返回。
        cancel: 是否先请求协作取消。恢复/导入等有写入副作用的操作传 False，
            仅等待其自然完成以确保数据一致性。
        timeout: 等待超时毫秒，默认 WORKER_WAIT_TIMEOUT_MS。

    供对话框 reject 与主窗口锁定/关闭时复用。
    """
    if worker is None or not worker.isRunning():
        return True
    if timeout is None:
        from ..resources.constants import WORKER_WAIT_TIMEOUT_MS

        timeout = WORKER_WAIT_TIMEOUT_MS
    if cancel:
        worker.cancel()
    worker.wait(timeout)
    # 超时后 worker 仍运行属异常：父对象析构时 QThread 处于 running 会触发
    # Qt 致命警告（QThread: Destroyed while thread is still running）并崩溃。
    # 记录 error 提升可见性；配合业务层 cancel_check 应使长操作快速退出，
    # 正常情况下不会触发此告警。
    if worker.isRunning():
        logger.error(
            "后台 worker 等待 %dms 后仍在运行，再等待一个同等周期作为兜底",
            timeout,
        )
        worker.wait(timeout)
    if worker.isRunning():
        # 兜底超时后仍运行属极端异常（worker 卡死）。继续无限等待会让关闭永久
        # 挂起，比 QThread 析构警告更影响体验；记录 critical 后放弃等待，由调用方
        # 决定后续（接受可能的 Qt 警告）。不调用 terminate()，因其强制终止可能
        # 留下未释放的资源与不一致状态。
        logger.critical(
            "后台 worker 兜底等待 %dms 后仍在运行，放弃等待以避免关闭永久卡死",
            timeout,
        )
    return not worker.isRunning()
