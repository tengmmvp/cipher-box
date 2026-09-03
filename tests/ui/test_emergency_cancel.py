"""验证 ListRefreshController.cancel_all_workers / wait_workers 与 host 编排。

cancel_all_workers / wait_workers 委托 EntryRefreshCoordinator 取消/等待 entry/tag
worker 全集（含并发 entry worker），并在本控制器处理 status worker——避免漏 cancel
并发 worker 残留持密钥继续解密、与 lock() 清零竞态。coordinator 自身的全集取消语义
由其自身测试覆盖，本文件聚焦 ListRefreshController 的委托编排 + status worker 处理。

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
    """构造跳过 __init__ 的 ListRefreshController 裸实例，注入 mock coordinator + status worker。"""
    ctrl = ListRefreshController.__new__(ListRefreshController)
    ctrl._coordinator = MagicMock()
    ctrl._status_worker = None
    return ctrl


class TestCancelAllWorkers:
    """cancel_all_workers / wait_workers 对 coordinator 与 status worker 的委托编排。"""

    def test_cancels_via_coordinator_and_status(self):
        """cancel_all_workers 委托 coordinator 取消 entry/tag worker + 取消 status worker。"""
        ctrl = _make_controller()
        status = _FakeWorker("status")
        ctrl._status_worker = status

        ctrl.cancel_all_workers()

        ctrl._coordinator.cancel_all.assert_called_once()
        assert status.cancelled

    def test_no_wait_by_default(self):
        """cancel_all_workers 仅取消不等待（wait 由 wait_workers 单独调）。"""
        ctrl = _make_controller()
        status = _FakeWorker("status")
        ctrl._status_worker = status

        ctrl.cancel_all_workers()

        assert status.cancelled
        assert status.waited_ms is None

    def test_wait_when_timeout_positive(self):
        """wait_workers 委托 coordinator.wait + 对 status worker 调 wait（超时）。"""
        ctrl = _make_controller()
        status = _FakeWorker("status")
        ctrl._status_worker = status

        ctrl.wait_workers(400)

        ctrl._coordinator.wait.assert_called_once_with(400)
        assert status.waited_ms == 400

    def test_skips_none_worker(self):
        """_status_worker=None 时跳过，不报错。"""
        ctrl = _make_controller()
        ctrl._status_worker = None

        ctrl.cancel_all_workers()  # 不抛异常


class TestHostEmergencyCancelWorkers:
    """host emergency_cancel_workers 编排：auto_backup + list_refresh 委托。

    host 经 ``main_window_factory.make_main_window`` 真实构造（替代原
    ``MainWindow.__new__`` 手工布线——半初始化对象上未布线属性缺失，新增依赖只能
    靠 AttributeError 兜底发现），再把两个协作 controller 覆写为 MagicMock 探针
    （实例属性赋值遮蔽工厂构造的真实实例）。
    """

    def _make_host(self, qapp, tmp_path):
        from tests.ui.main_window_factory import make_main_window

        mw, _ctx = make_main_window(tmp_path)
        mw._auto_backup = MagicMock()
        mw._list_refresh = MagicMock()
        return mw

    def test_delegates_cancel_to_list_refresh_and_auto_backup(self, qapp, tmp_path):
        """无超时参数时，仅委托 ``auto_backup.cancel`` 与 ``list_refresh.cancel_all_workers``，不调 ``wait_workers``。"""
        mw = self._make_host(qapp, tmp_path)
        mw.emergency_cancel_workers()
        mw._auto_backup.cancel.assert_called_once()
        mw._list_refresh.cancel_all_workers.assert_called_once()
        mw._list_refresh.wait_workers.assert_not_called()

    def test_waits_when_timeout_positive(self, qapp, tmp_path):
        """传正 ``wait_timeout_ms`` 时，额外委托 ``list_refresh.wait_workers`` 等待 worker 收尾。"""
        mw = self._make_host(qapp, tmp_path)
        mw.emergency_cancel_workers(wait_timeout_ms=400)
        mw._list_refresh.wait_workers.assert_called_once_with(400)
