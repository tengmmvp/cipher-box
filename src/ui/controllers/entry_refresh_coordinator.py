"""ListRefreshController 的异步刷新协调器：worker 池与 generation 守卫。

管 entry/tag 两类后台 worker 的启动、取消与过期结果丢弃。generation 计数器 +
请求指纹（filter/category/search）双重守卫：快速连续刷新或过滤器切换后，旧 worker
的延迟回调被短路丢弃，不刷新 UI。结果应用与新鲜度判定经 ``CoordinatorDeps`` 回调
注入，避免 coordinator -> controller 的逆向依赖。
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from PyQt6.QtWidgets import QMainWindow

from ..components.workers import BackgroundWorker, wait_worker_shutdown

logger = logging.getLogger(__name__)


@dataclass
class ScrollRestore:
    """列表刷新后的滚动/选中恢复参数（仅过滤器未变时恢复）。"""

    should_restore_position: bool
    saved_row: int


# entry 异步 fetcher 工厂：接受 cancel_check，返回 (条目列表, 标题)。
# cancel_check 由 coordinator 注入（worker.cancel_check），使长循环可协作取消。
EntryFetchFactory = Callable[[Callable[[], bool]], tuple[list[Any], str]]
# tag 异步 fetcher：直接返回标签列表，无 cancel_check（标签查询无长循环）。
TagFetchFn = Callable[[], list[tuple[str, int]]]


@dataclass(frozen=True)
class CoordinatorDeps:
    """Coordinator 注入回调，避免 coordinator -> controller 逆向依赖。

    - ``is_locked``: 锁定态快照（worker 完成回调据此丢弃结果）。
    - ``is_entry_stale``: entry 请求指纹是否已被取代（filter/category/search 任一变更）。
    - ``apply_entries``: 应用 entry 刷新结果（含滚动恢复）。
    - ``apply_tags``: 应用 tag 刷新结果（重建下拉）。
    - ``show_loading``: 异步加载占位文案。
    """

    is_locked: Callable[[], bool]
    is_entry_stale: Callable[[str, int | None, str], bool]
    apply_entries: Callable[[list[Any], str, ScrollRestore], None]
    apply_tags: Callable[[list[tuple[str, int]]], None]
    show_loading: Callable[[str], None]


class EntryRefreshCoordinator:
    """管理 entry/tag 异步刷新的 worker 池、generation 守卫与过期结果丢弃。

    host 生命周期（锁定/关闭/隐藏到托盘/紧急取消）经 ``shutdown`` / ``cancel_all`` /
    ``wait`` 委托本协调器；controller 在 ``refresh_entries`` / ``refresh_tag_filter``
    的异步分支调用 ``start_async_entry_refresh`` / ``start_async_tag_refresh``。
    """

    def __init__(self, parent: QMainWindow, deps: CoordinatorDeps) -> None:
        self._parent = parent
        self._deps = deps
        # worker / generation
        self._entry_worker: BackgroundWorker | None = None
        self._entry_workers: set[BackgroundWorker] = set()
        self._entry_refresh_generation = 0
        self._tag_worker: BackgroundWorker | None = None
        self._tag_refresh_generation = 0

    # ========== entry 异步刷新 ==========

    def cancel_entry_worker(self) -> None:
        """取消当前 entry worker（同步刷新路径调用，清引用让旧回调短路）。

        同步路径不推进 generation（省去无谓计数），靠 ``_done`` 的请求指纹校验
        （``is_entry_stale``）丢弃旧 worker 的延迟回调。
        """
        if self._entry_worker is not None:
            self._entry_worker.cancel()
            self._entry_worker = None

    def start_async_entry_refresh(
        self,
        filter_key: str,
        category_id: int | None,
        search: str,
        build_fetch: EntryFetchFactory,
        scroll_restore: ScrollRestore,
    ) -> None:
        """启动后台 entry 刷新，完成后回主线程渲染（过期结果丢弃）。

        generation 计数器推进使「被更新的刷新取代」的旧 worker 结果丢弃；请求指纹
        （filter/category/search）校验兜底同步路径（同步取消不推进 generation）。
        """
        if self._entry_worker is not None:
            self._entry_worker.cancel()
        self._entry_refresh_generation += 1
        generation = self._entry_refresh_generation
        deps = self._deps

        def _fetch() -> tuple[list[Any], str]:
            # worker 是下方赋值的自由变量，闭包延迟绑定（_fetch 在 worker.run 时执行，
            # worker 已赋值）。cancel_check 直接用 BackgroundWorker 提供的绑定方法。
            return build_fetch(worker.cancel_check)

        worker = BackgroundWorker(_fetch, parent=self._parent)
        self._entry_worker = worker
        self._entry_workers.add(worker)
        deps.show_loading("加载中...")

        def _release() -> None:
            self._entry_workers.discard(worker)
            if self._entry_worker is worker:
                self._entry_worker = None

        def _done(result: Any) -> None:
            if (
                deps.is_locked()
                or generation != self._entry_refresh_generation
                or deps.is_entry_stale(filter_key, category_id, search)
            ):
                _release()
                return
            entries, title = result
            _release()
            deps.apply_entries(entries, title, scroll_restore)

        def _on_error(_message: str) -> None:
            _release()
            logger.warning("条目后台加载失败: %s", _message)
            # 仅当本 worker 仍为活动刷新时才提示失败：已被取代的过期错误不覆盖当前
            # 刷新的 loading 态（与 _done 的 generation 守卫对称，QL-004）。
            if (
                deps.is_locked()
                or generation != self._entry_refresh_generation
                or deps.is_entry_stale(filter_key, category_id, search)
            ):
                return
            deps.show_loading("加载失败，请重试")

        worker.finished.connect(_done)
        worker.error.connect(_on_error)
        worker.cancelled.connect(_release)
        worker.start()

    # ========== tag 异步刷新 ==========

    def start_async_tag_refresh(self, fetch_fn: TagFetchFn) -> None:
        """后台获取全部标签，完成后回主线程重建下拉（陈旧结果丢弃）。

        标签 worker 加入 ``_entry_workers``，复用 shutdown / cancel_all 的取消；
        ``_tag_refresh_generation`` 防陈旧（快速连续刷新时只应用最新一批）。
        """
        if self._tag_worker is not None:
            self._tag_worker.cancel()
        self._tag_refresh_generation += 1
        generation = self._tag_refresh_generation
        deps = self._deps

        worker = BackgroundWorker(fetch_fn, parent=self._parent)
        self._tag_worker = worker
        self._entry_workers.add(worker)

        def _release() -> None:
            self._entry_workers.discard(worker)
            if self._tag_worker is worker:
                self._tag_worker = None

        def _done(result: Any) -> None:
            # 锁定或已被更新的刷新取代时丢弃结果，避免对已锁定 vault 或过期下拉应用。
            if deps.is_locked() or generation != self._tag_refresh_generation:
                _release()
                return
            _release()
            deps.apply_tags(result)

        def _on_error(_message: str) -> None:
            _release()
            # 标签下拉失败用户感知低（显示为无标签），记 warning 保留可诊断性（QL-004）。
            logger.warning("标签后台加载失败: %s", _message)

        worker.finished.connect(_done)
        worker.error.connect(_on_error)
        worker.cancelled.connect(_release)
        worker.start()

    # ========== worker 生命周期 ==========

    def shutdown(self) -> None:
        """取消并等待所有 entry/tag worker 结束（host shutdown 调用）。"""
        for worker in tuple(self._entry_workers):
            wait_worker_shutdown(worker)
        self._entry_workers.clear()
        self._entry_worker = None
        self._tag_worker = None

    def cancel_all(self) -> None:
        """紧急取消 entry/tag worker（不等待），供 host emergency_cancel_workers / prepare_for_lock。

        遍历 ``_entry_workers`` 全集快照（含并发 entry worker 与 tag worker），而非仅
        ``_entry_worker`` 单引用（最后一个），避免漏 cancel 并发 worker 残留持密钥继续
        解密、与 lock() 清零竞态。
        """
        for worker in tuple(self._entry_workers):
            try:
                worker.cancel()
            except RuntimeError:
                pass

    def wait(self, timeout_ms: int) -> None:
        """取消后等待 entry/tag worker 退出（host emergency_cancel_workers 的 wait 分支）。"""
        for worker in tuple(self._entry_workers):
            try:
                worker.wait(timeout_ms)
            except RuntimeError:
                pass
