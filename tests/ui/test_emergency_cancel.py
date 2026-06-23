"""验证 MainWindow.emergency_cancel_workers 紧急取消逻辑。

覆盖 A4 修复：遍历 ``_entry_workers`` 全集（含并发 entry worker），而非仅
``_entry_worker`` 单引用（最后一个）；``wait_timeout_ms > 0`` 时取消后短超时等待，
让持密钥解密的 worker 退出协作循环后再 lock 清零，收缩「已锁定」后明文残留窗口。
"""

# 跳过 __init__ 的裸 MainWindow 注入 _FakeWorker（非 BackgroundWorker 子类）与
# MagicMock，类型不匹配仅限测试替身，故关闭 pyright 属性/参数类型检查。
# pyright: reportAttributeAccessIssue=false, reportArgumentType=false

from unittest.mock import MagicMock


class _FakeWorker:
    """模拟 BackgroundWorker，记录 cancel/wait 调用。"""

    def __init__(self, ident: str) -> None:
        self.ident = ident
        self.cancelled = False
        self.waited_ms: int | None = None

    def cancel(self) -> None:
        self.cancelled = True

    def wait(self, ms: int) -> bool:
        self.waited_ms = ms
        return True


def _make_main_window():
    """构造跳过 __init__ 的 MainWindow 裸实例，手动注入 emergency_cancel_workers 依赖。"""
    from src.ui.windows.main_window import MainWindow
    mw = MainWindow.__new__(MainWindow)
    mw._auto_backup = MagicMock()
    mw._status_worker = None
    mw._entry_workers = set()
    return mw


class TestEmergencyCancelWorkers:
    def test_cancels_all_entry_workers_and_status(self):
        """遍历 _entry_workers 全集 + _status_worker，全部取消。

        修复前仅 cancel _entry_worker 单引用（最后一个并发 worker），漏 cancel 其余
        并发 entry worker——它们残留持密钥继续解密，与 lock() 清零竞态。
        """
        mw = _make_main_window()
        status = _FakeWorker('status')
        entries = [_FakeWorker(f'entry{i}') for i in range(3)]
        mw._status_worker = status
        for w in entries:
            mw._entry_workers.add(w)

        mw.emergency_cancel_workers()

        assert status.cancelled
        assert all(w.cancelled for w in entries)
        mw._auto_backup.cancel.assert_called_once()

    def test_no_wait_by_default(self):
        """默认 wait_timeout_ms=0，不调用 wait（aboutToQuit 之外的路径不阻塞）。"""
        mw = _make_main_window()
        status = _FakeWorker('status')
        mw._status_worker = status

        mw.emergency_cancel_workers()

        assert status.cancelled
        assert status.waited_ms is None

    def test_wait_when_timeout_positive(self):
        """wait_timeout_ms>0 时取消后对每个 worker 调 wait(超时)。"""
        mw = _make_main_window()
        status = _FakeWorker('status')
        entries = [_FakeWorker('e0'), _FakeWorker('e1')]
        mw._status_worker = status
        for w in entries:
            mw._entry_workers.add(w)

        mw.emergency_cancel_workers(wait_timeout_ms=400)

        assert status.waited_ms == 400
        assert all(w.waited_ms == 400 for w in entries)

    def test_skips_none_worker(self):
        """_status_worker=None 时跳过，不报错。"""
        mw = _make_main_window()
        mw._status_worker = None

        mw.emergency_cancel_workers()  # 不抛异常

        mw._auto_backup.cancel.assert_called_once()
