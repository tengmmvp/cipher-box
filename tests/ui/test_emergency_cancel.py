"""验证 ListRefreshController.cancel_all_workers / wait_workers 与 host 编排。

覆盖：遍历 ``_entry_workers`` 全集（含并发 entry worker）+ ``_status_worker``，
而非仅 ``_entry_worker`` 单引用（最后一个）；``wait_timeout_ms > 0`` 时取消后短超时
等待，让持密钥解密的 worker 退出协作循环后再 lock 清零，收缩「已锁定」后明文残留窗口。

host ``emergency_cancel_workers`` 为 thin wrapper（auto_backup.cancel +
list_refresh.cancel_all_workers + 可选 wait_workers），其编排在此一并验证。
"""

# _FakeWorker 非 BackgroundWorker 子类，类型不匹配仅限测试替身，关闭属性/参数检查。
# pyright: reportAttributeAccessIssue=false, reportArgumentType=false

from unittest.mock import MagicMock

from src.ui.controllers.list_refresh_controller import ListRefreshController


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


def _make_controller() -> ListRefreshController:
    """构造跳过 __init__ 的 ListRefreshController 裸实例，手动注入 worker 状态。"""
    ctrl = ListRefreshController.__new__(ListRefreshController)
    ctrl._status_worker = None
    ctrl._entry_workers = set()
    return ctrl


class TestCancelAllWorkers:
    def test_cancels_all_entry_workers_and_status(self):
        """遍历 _entry_workers 全集 + _status_worker，全部取消。

        漏 cancel 并发 entry worker 会让它们残留持密钥继续解密，与 lock() 清零竞态。
        """
        ctrl = _make_controller()
        status = _FakeWorker('status')
        entries = [_FakeWorker(f'entry{i}') for i in range(3)]
        ctrl._status_worker = status
        for w in entries:
            ctrl._entry_workers.add(w)

        ctrl.cancel_all_workers()

        assert status.cancelled
        assert all(w.cancelled for w in entries)

    def test_no_wait_by_default(self):
        """cancel_all_workers 仅取消不等待（wait 由 wait_workers 单独调）。"""
        ctrl = _make_controller()
        status = _FakeWorker('status')
        ctrl._status_worker = status

        ctrl.cancel_all_workers()

        assert status.cancelled
        assert status.waited_ms is None

    def test_wait_when_timeout_positive(self):
        """wait_workers 对每个 worker 调 wait(超时)。"""
        ctrl = _make_controller()
        status = _FakeWorker('status')
        entries = [_FakeWorker('e0'), _FakeWorker('e1')]
        ctrl._status_worker = status
        for w in entries:
            ctrl._entry_workers.add(w)

        ctrl.wait_workers(400)

        assert status.waited_ms == 400
        assert all(w.waited_ms == 400 for w in entries)

    def test_skips_none_worker(self):
        """_status_worker=None 时跳过，不报错。"""
        ctrl = _make_controller()
        ctrl._status_worker = None

        ctrl.cancel_all_workers()  # 不抛异常


class TestHostEmergencyCancelWorkers:
    """host emergency_cancel_workers 编排：auto_backup + list_refresh 委托。"""

    def _make_host(self):
        from src.ui.windows.main_window import MainWindow
        mw = MainWindow.__new__(MainWindow)
        mw._auto_backup = MagicMock()
        mw._list_refresh = MagicMock()
        return mw

    def test_delegates_cancel_to_list_refresh_and_auto_backup(self):
        mw = self._make_host()
        mw.emergency_cancel_workers()
        mw._auto_backup.cancel.assert_called_once()
        mw._list_refresh.cancel_all_workers.assert_called_once()
        mw._list_refresh.wait_workers.assert_not_called()

    def test_waits_when_timeout_positive(self):
        mw = self._make_host()
        mw.emergency_cancel_workers(wait_timeout_ms=400)
        mw._list_refresh.wait_workers.assert_called_once_with(400)
