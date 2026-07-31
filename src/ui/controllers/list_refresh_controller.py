"""MainWindow 筛选、排序、数据刷新控制器（组合化，从 _MainWindowFiltersMixin 迁移）。

普通类（非 QObject），遵循 EntryActionsController/MenuController 范式：``__init__``
注入 manager 与跨 controller 回调（``ListRefreshDeps``），``setup(parent, view)`` 接收
QObject 父（MainWindow）与冻结 dataclass view-handle（``ListRefreshView``），创建 3 个
防抖/状态定时器、连接 8 个控件信号、初始化填充列表。

吸收原 Filters Mixin 的全部刷新/过滤/状态栏/worker 逻辑：6 个 worker/generation
（entry_worker/entry_workers/tag_worker/status_worker + entry/tag 两个 generation）、
3 定时器（search/entry_change/status）、过滤器/分类/标签/搜索/缓存状态。host 生命周期
（锁定/关闭/隐藏到托盘/紧急取消）经 ``shutdown`` / ``cancel_all_workers`` / ``stop_timers``
/ ``prepare_for_lock`` 委托本控制器，消除原 Filters Mixin 跨 ``self`` 的隐式契约。
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

from PyQt6.QtCore import QModelIndex, Qt, QTimer
from PyQt6.QtWidgets import QListWidgetItem, QMainWindow

from ..components.empty_state_widget import EmptyStateWidget
from ..components.workers import BackgroundWorker, wait_worker_shutdown
from ..resources.constants import (
    ASYNC_SEARCH_THRESHOLD,
    MS_ENTRY_CHANGE_DEBOUNCE,
    MS_SEARCH_DEBOUNCE,
    MS_STATUS_BAR_DEBOUNCE,
)
from ..resources.icons import (
    EMPTY_FOLDER,
    EMPTY_GENERIC,
    EMPTY_SEARCH,
    EMPTY_SUCCESS,
    EMPTY_TRASH,
    EMPTY_VAULT,
    FOLDER,
    icon,
)
from ._locked_guard import require_unlocked

if TYPE_CHECKING:
    from PyQt6.QtWidgets import (
        QComboBox,
        QLabel,
        QLineEdit,
        QListView,
        QListWidget,
        QStackedWidget,
        QStatusBar,
    )

    from ...business.managers.entry_manager import EntryManager
    from ...business.services.security_analyzer import SecurityAnalyzer, SecurityReport
    from ...config import ConfigManager
    from ...models import Category
    from ..components.detail_panel import DetailPanel
    from ..components.entry_list_widget import EntryListModel
    from ..controllers.entry_list_controller import EntryListController
    from ..controllers.sidebar_controller import SidebarController

logger = logging.getLogger(__name__)

# 搜索结果渲染上限：超大库下避免一次性渲染过多条目卡死 UI
_MAX_SEARCH_RESULTS_DISPLAY = 1000


@dataclass
class _ScrollRestore:
    """列表刷新后的滚动/选中恢复参数（仅过滤器未变时恢复）。"""

    should_restore_position: bool
    saved_scroll: int
    saved_row: int


@dataclass(frozen=True)
class ListRefreshView:
    """ListRefreshController 操作的控件引用（控件仍是 MainWindow 的 host 属性）。

    经冻结 dataclass 取引用，不持有 host 自身以避免环依赖；``test_product_hardening``
    等对 ``window._entry_model`` / ``window._status_bar`` 的访问零改动。
    """

    search_edit: QLineEdit
    entry_list: QListView
    entry_model: EntryListModel
    category_list: QListWidget
    tag_combo: QComboBox
    sort_combo: QComboBox
    filter_list: QListWidget
    list_stack: QStackedWidget
    list_title: QLabel
    count_label: QLabel
    status_bar: QStatusBar
    warning_label: QLabel
    stats_label: QLabel
    detail_panel: DetailPanel


@dataclass(frozen=True)
class ListRefreshDeps:
    """跨 controller 回调：on_add_entry 绑 EntryActionsController.add_entry（空态操作）。"""

    on_add_entry: Callable[[], None]


class ListRefreshController:
    """筛选、排序、列表刷新（含异步）、状态栏、空态与相关事件处理。

    worker / generation / 定时器 / 过滤器态全迁入本控制器；host 经生命周期方法
    （``shutdown`` / ``cancel_all_workers`` / ``stop_timers`` / ``prepare_for_lock`` /
    ``refresh_after_unlock``）委托，保持原有 6 条关闭路径的 worker 不变量。
    """

    _parent: QMainWindow
    _view: ListRefreshView

    def __init__(
        self,
        config: ConfigManager,
        entry_mgr: EntryManager,
        security: SecurityAnalyzer,
        entry_list_ctrl: EntryListController,
        sidebar_ctrl: SidebarController,
        deps: ListRefreshDeps,
    ) -> None:
        self._config = config
        self._entry_mgr = entry_mgr
        self._security = security
        self._entry_list_ctrl = entry_list_ctrl
        self._sidebar_ctrl = sidebar_ctrl
        self._deps = deps
        self._locked = False
        # 过滤器状态
        self._current_filter = 'all'
        self._current_category_id: int | None = None
        self._current_search = ''
        self._current_tag = ''
        # 缓存
        self._cached_categories: list[Category] = []
        self._cached_tag_names: list[str] = []
        self._cached_total_entries = -1
        self._last_refresh_filter: str | None = None
        # worker / generation
        self._status_worker: BackgroundWorker | None = None
        self._entry_worker: BackgroundWorker | None = None
        self._entry_workers: set[BackgroundWorker] = set()
        self._entry_refresh_generation = 0
        self._tag_worker: BackgroundWorker | None = None
        self._tag_refresh_generation = 0
        # 定时器（setup 创建，parent=host 保证 Qt 线程亲和性与析构自动断开）
        self._status_timer: QTimer | None = None
        self._entry_change_timer: QTimer | None = None
        self._search_timer: QTimer | None = None

    def setup(self, parent: QMainWindow, view: ListRefreshView) -> None:
        """创建 3 定时器、连接 8 个控件信号并初始化填充列表。须在控件创建后调用。"""
        self._parent = parent
        self._view = view

        # 状态栏安全摘要防抖定时器
        self._status_timer = QTimer(parent)
        self._status_timer.setSingleShot(True)
        self._status_timer.setInterval(MS_STATUS_BAR_DEBOUNCE)
        self._status_timer.timeout.connect(self.update_status_bar)

        # 条目变更防抖定时器，合并短时间内连续的刷新请求
        self._entry_change_timer = QTimer(parent)
        self._entry_change_timer.setSingleShot(True)
        self._entry_change_timer.setInterval(MS_ENTRY_CHANGE_DEBOUNCE)
        self._entry_change_timer.timeout.connect(self._do_refresh_after_entry_change)

        # 搜索输入防抖定时器
        self._search_timer = QTimer(parent)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(MS_SEARCH_DEBOUNCE)
        self._search_timer.timeout.connect(self.do_search)

        # 控件信号连接（_build_* 仅建控件，connect 集中于此）
        view.search_edit.textChanged.connect(self.on_search_input)
        view.tag_combo.currentIndexChanged.connect(self.on_tag_changed)
        view.filter_list.currentItemChanged.connect(self.on_filter_changed)
        view.category_list.currentItemChanged.connect(self.on_category_changed)
        view.sort_combo.currentIndexChanged.connect(self.on_sort_changed)

        # 构造期初始化填充（原 _build_sidebar 内联调用 + __init__ _refresh_entries）
        self.refresh_categories()
        self.refresh_tag_filter()
        self.refresh_entries()
        self.update_status_bar()

    # ======== 锁定态与生命周期 ========

    def set_locked(self, locked: bool) -> None:
        """host 经 refresh_after_unlock(False) 广播解锁态（锁定态由 prepare_for_lock 设）。"""
        self._locked = locked

    def prepare_for_lock(self) -> None:
        """锁定前置：标记锁定态、清搜索输入、失效缓存。

        定时器停止与 worker 取消/等待由 host ``_stop_ui_timers`` / ``shutdown`` 统一
        调度，保持原 prepare_for_lock「先清状态 → 停定时器 → 等待 worker」的顺序。
        """
        self._locked = True
        self._current_search = ''
        view = self._view
        view.search_edit.blockSignals(True)
        view.search_edit.clear()
        view.search_edit.blockSignals(False)
        self._invalidate_security_cache()
        self._entry_mgr.invalidate_caches()

    def refresh_after_unlock(self) -> None:
        """解锁后刷新分类/标签/条目（首次解锁由 host 经 _first_unlock 跳过）。"""
        self.refresh_categories()
        self.refresh_tag_filter()
        self.refresh_entries()

    def stop_timers(self) -> None:
        """停止全部 UI 定时器（host _stop_ui_timers 调用）。"""
        for timer in (self._search_timer, self._entry_change_timer, self._status_timer):
            if timer is not None:
                timer.stop()

    def start_status_timer(self) -> None:
        """启动状态栏刷新定时器（host refresh_after_unlock / _show_from_tray 调用）。"""
        if self._status_timer is not None:
            self._status_timer.start()

    def rebuild_for_theme(self) -> None:
        """主题切换后重建分类列表图标与空态（颜色烘焙到 QIcon/EmptyStateWidget 需重建）。

        分类列表的 FOLDER 图标与空态 EmptyStateWidget 的颜色在创建时烘焙，update()
        不刷新，须重建。供 host ``_apply_theme`` 调用。
        """
        self.refresh_categories()
        if self._view.list_stack.currentWidget() is not self._view.entry_list:
            self._show_empty_state()

    def shutdown(self) -> None:
        """取消并等待所有后台 worker 结束，避免 QThread running 析构崩溃。

        统一 status/entry/tag 三类 worker 的关闭：取消（协作取消标志）并等待其退出，
        超时则记 error（见 ``wait_worker_shutdown``）。锁定、退出、隐藏到托盘前调用。
        """
        wait_worker_shutdown(self._status_worker)
        self._status_worker = None
        for worker in tuple(self._entry_workers):
            wait_worker_shutdown(worker)
        self._entry_workers.clear()
        self._entry_worker = None
        self._tag_worker = None

    def cancel_all_workers(self) -> None:
        """紧急取消后台 worker（不等待），供 host emergency_cancel_workers / prepare_for_lock。

        遍历 ``_entry_workers`` 全集快照（含并发 entry worker）+ status_worker，而非仅
        ``_entry_worker`` 单引用（最后一个），避免漏 cancel 并发 worker 残留持密钥继续
        解密、与 lock() 清零竞态。
        """
        workers = (self._status_worker, *tuple(self._entry_workers))
        for worker in workers:
            if worker is None:
                continue
            try:
                worker.cancel()
            except RuntimeError:
                pass

    def wait_workers(self, timeout_ms: int) -> None:
        """取消后等待 worker 退出（host emergency_cancel_workers 的 wait 分支）。"""
        workers = (self._status_worker, *tuple(self._entry_workers))
        for worker in workers:
            if worker is None:
                continue
            try:
                worker.wait(timeout_ms)
            except RuntimeError:
                pass

    @property
    def cached_categories(self) -> list[Category]:
        """供 EntryActionsController 新增/编辑对话框预填分类（host _get_dialog_options）。"""
        return self._cached_categories

    @property
    def cached_tag_names(self) -> list[str]:
        """供 EntryActionsController 标签自动补全（host _get_dialog_options）。"""
        return self._cached_tag_names

    # ========== 排序 ==========

    def get_sort_config(self) -> tuple[str, str]:
        """获取当前排序字段和方向（host closeEvent 持久化调用）。"""
        return self._entry_list_ctrl.get_sort_config(self._view.sort_combo.currentIndex())

    def on_sort_changed(self) -> None:
        """排序选项变更。仅更新内存配置，持久化由 closeEvent 统一完成。"""
        field, order = self.get_sort_config()
        self._config.set('sort_field', field)
        self._config.set('sort_order', order)
        self.refresh_entries()

    def _sort_entries(self, entries: list) -> list:
        """对条目列表排序。"""
        return self._entry_list_ctrl.sort_entries(entries, self._view.sort_combo.currentIndex())

    # ========== 数据操作 ==========

    def refresh_categories(self) -> None:
        selected_category_id = self._current_category_id
        category_list = self._view.category_list
        category_list.blockSignals(True)
        category_list.clear()

        all_item = QListWidgetItem('全部分类')
        all_item.setData(Qt.ItemDataRole.UserRole, None)
        all_item.setIcon(icon(FOLDER))
        category_list.addItem(all_item)

        categories = self._sidebar_ctrl.get_categories()
        category_counts = self._sidebar_ctrl.get_category_entry_counts()
        for cat in categories:
            if cat.id is None:
                continue
            label = self._sidebar_ctrl.build_category_label(cat, category_counts.get(cat.id, 0))
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, cat.id)
            category_list.addItem(item)

        target_row = 0
        if selected_category_id is not None:
            for row in range(category_list.count()):
                selected_item = category_list.item(row)
                if selected_item and selected_item.data(Qt.ItemDataRole.UserRole) == selected_category_id:
                    target_row = row
                    break
            else:
                self._current_category_id = None
        category_list.setCurrentRow(target_row)
        category_list.blockSignals(False)
        self._cached_categories = categories

    def refresh_tag_filter(self, entry_count: int | None = None) -> None:
        # 标签下拉的 get_all_tags() 在缓存失效（改密/锁定/标签变更）时需全量解密全部
        # 条目 tags 字段，大库下同步会卡主线程。仅在「大库 且 缓存失效」时移入后台线程；
        # 缓存命中或小库时直接同步重建下拉，省去无谓的 QThread 创建与跨线程信号开销。
        count = (
            entry_count
            if entry_count is not None
            else self._entry_mgr.get_entry_count(include_deleted=True)
        )
        if count >= ASYNC_SEARCH_THRESHOLD and not self._sidebar_ctrl.tags_cache_valid:
            self._start_async_tag_refresh()
            return
        self._apply_tag_filter(self._sidebar_ctrl.get_all_tags())

    def _start_async_tag_refresh(self) -> None:
        """后台获取全部标签，完成后回主线程重建下拉。

        标签 worker 加入 _entry_workers，复用 shutdown / cancel_all_workers 的取消；
        _tag_refresh_generation 防陈旧（快速连续刷新时只应用最新一批）。
        """
        if self._tag_worker is not None:
            self._tag_worker.cancel()
        self._tag_refresh_generation += 1
        generation = self._tag_refresh_generation

        worker = BackgroundWorker(self._sidebar_ctrl.get_all_tags, parent=self._parent)
        self._tag_worker = worker
        self._entry_workers.add(worker)

        def _release() -> None:
            self._entry_workers.discard(worker)
            if self._tag_worker is worker:
                self._tag_worker = None

        def _done(result: Any) -> None:
            # 锁定或已被更新的刷新取代时丢弃结果，避免对已锁定 vault 或过期下拉应用。
            if self._locked or generation != self._tag_refresh_generation:
                _release()
                return
            _release()
            self._apply_tag_filter(result)

        worker.finished.connect(_done)
        worker.error.connect(lambda _message: _release())
        worker.cancelled.connect(_release)
        worker.start()

    def _apply_tag_filter(self, all_tags: list[tuple[str, int]]) -> None:
        """用给定标签列表重建标签下拉，保留当前选中（若仍存在）。"""
        from ..resources.constants import MAX_TAG_AUTOCOMPLETE

        current = self._current_tag
        tag_combo = self._view.tag_combo
        tag_combo.blockSignals(True)
        tag_combo.clear()
        tag_combo.addItem('全部标签', '')
        for tag, count in all_tags:
            tag_combo.addItem(f'{tag}  ·  {count}', tag)
        index = tag_combo.findData(current)
        tag_combo.setCurrentIndex(index if index >= 0 else 0)
        if index < 0:
            self._current_tag = ''
        tag_combo.blockSignals(False)
        self._cached_tag_names = [t[0] for t in all_tags[:MAX_TAG_AUTOCOMPLETE]]

    # ======== 过滤器数据获取：委托给 EntryListController ========

    def _fetch_for_filter(
        self,
        filter_key: str,
        *,
        category_id: int | None = None,
        search: str | None = None,
        cancel_check: Callable[[], bool] | None = None,
        use_current_state: bool = True,
    ) -> tuple[list, str]:
        """按过滤器键获取数据，参数绑定基于当前 UI 状态。

        过滤器→方法的映射复用 EntryListController.get_fetcher。各 fetcher 所需的当前
        分类、搜索等参数在此按 filter_key 统一绑定。排序在数据获取阶段完成（同步与
        异步 worker 均在此排序），使 _apply_entry_results 仅负责渲染。
        """
        effective_search = self._current_search if use_current_state else (search or '')
        effective_category = self._current_category_id if use_current_state else category_id
        fetcher = self._entry_list_ctrl.get_fetcher(filter_key)
        if filter_key == 'all':
            entries, title = fetcher(effective_category, effective_search, cancel_check)
        elif filter_key in ('favorite', 'recent', 'trash'):
            entries, title = fetcher(effective_search, cancel_check)
        else:
            entries, title = fetcher()  # weak、duplicate 无参数
        if filter_key in ('all', 'favorite', 'trash'):
            entries = self._sort_entries(entries)
        return entries, title

    def _current_category_name(self) -> str:
        """返回当前选中分类的名称，无选中分类时返回空字符串。"""
        if self._current_category_id is None:
            return ''
        for category in self._cached_categories:
            if category.id == self._current_category_id:
                return category.name
        return ''

    def refresh_entries(self, entry_count: int | None = None) -> None:
        # 重建列表后选择防抖的 pending 若已失效，由 EntryActionsController.do_select_entry
        # 的「pending 行 != 当前选中行 → show_empty」校验兜底，故此处不再跨控制器取消
        # （避免 list_refresh → entry_actions 的逆向依赖）。
        view = self._view
        # 记录滚动位置和当前选中行，重建后恢复，提升列表刷新体验。仅在当前过滤器
        # 未变时恢复同一数据集的刷新；切换过滤器后数据集不同，不应恢复旧位置。
        saved_filter = self._last_refresh_filter
        current_filter = self._current_filter
        should_restore_position = (saved_filter == current_filter)
        self._last_refresh_filter = current_filter
        scrollbar = view.entry_list.verticalScrollBar()
        scroll_restore = _ScrollRestore(
            should_restore_position=should_restore_position,
            saved_scroll=(
                scrollbar.value() if should_restore_position and scrollbar is not None else 0
            ),
            saved_row=view.entry_list.currentIndex().row() if should_restore_position else -1,
        )

        # 异步刷新条件：条目数超阈值时移入后台线程。all/favorite/trash 无论是否搜索都
        # 需全量解密，大库下须异步；recent 仅在有搜索时全量解密；weak/duplicate 来自
        # 缓存安全摘要，无需异步。
        filter_key = self._current_filter
        needs_async = (
            filter_key in ('all', 'favorite', 'trash')
            or (filter_key == 'recent' and self._current_search)
        )
        if (
            needs_async
            and (entry_count if entry_count is not None
                 else self._entry_mgr.get_entry_count(include_deleted=True))
            >= ASYNC_SEARCH_THRESHOLD
        ):
            self._start_async_entry_refresh(
                current_filter,
                self._current_category_id,
                self._current_search,
                scroll_restore,
            )
            return

        if self._entry_worker is not None:
            self._entry_worker.cancel()
            self._entry_worker = None
        entries, title = self._fetch_for_filter(self._current_filter)
        self._apply_entry_results(entries, title, scroll_restore)

    def _start_async_entry_refresh(
        self,
        filter_key: str,
        category_id: int | None,
        search: str,
        scroll_restore: _ScrollRestore,
    ) -> None:
        if self._entry_worker is not None:
            self._entry_worker.cancel()
        self._entry_refresh_generation += 1
        generation = self._entry_refresh_generation

        def _fetch() -> tuple[list, str]:
            # worker 是下方赋值的自由变量，闭包延迟绑定（_fetch 在 worker.run 时执行，
            # worker 已赋值）。cancel_check 直接用 BackgroundWorker 提供的绑定方法。
            return self._fetch_for_filter(
                filter_key,
                category_id=category_id,
                search=search,
                cancel_check=worker.cancel_check,
                use_current_state=False,
            )

        worker = BackgroundWorker(_fetch, parent=self._parent)
        self._entry_worker = worker
        self._entry_workers.add(worker)
        self._view.count_label.setText('加载中...')

        def _release() -> None:
            self._entry_workers.discard(worker)
            if self._entry_worker is worker:
                self._entry_worker = None

        def _done(result: Any) -> None:
            if (
                self._locked
                or generation != self._entry_refresh_generation
                or self._current_filter != filter_key
                or self._current_category_id != category_id
                or self._current_search != search
            ):
                _release()
                return
            entries, title = result
            _release()
            self._apply_entry_results(entries, title, scroll_restore)

        worker.finished.connect(_done)
        worker.error.connect(lambda _message: _release())
        worker.cancelled.connect(_release)
        worker.start()

    def _apply_entry_results(
        self,
        entries: list,
        title: str,
        scroll_restore: _ScrollRestore,
    ) -> None:
        view = self._view
        # 分类筛选下显示分类名作为标题，而非 fetcher 默认的「全部条目」
        if self._current_category_id is not None:
            title = self._current_category_name() or title
        view.list_title.setText(title)

        if self._current_search and self._current_filter in ('weak', 'duplicate'):
            entries = self._entry_list_ctrl.filter_by_search(entries, self._current_search)

        if self._current_tag:
            entries = self._entry_list_ctrl.filter_by_tag(entries, self._current_tag)

        # 渲染上限：超大库下避免一次性渲染过多条目卡死 UI。
        original_count = len(entries)
        truncated = original_count > _MAX_SEARCH_RESULTS_DISPLAY
        if truncated:
            entries = entries[:_MAX_SEARCH_RESULTS_DISPLAY]

        # Model/View：一次替换全部数据，QListView 按需经 delegate 绘制。
        view.entry_model.set_entries(entries)

        # 恢复滚动位置和选中行，仅在过滤器未变时恢复。
        if (
            scroll_restore.should_restore_position
            and not self._current_search
            and 0 <= scroll_restore.saved_row < view.entry_model.rowCount()
        ):
            view.entry_list.setCurrentIndex(view.entry_model.index(scroll_restore.saved_row))
        if scroll_restore.should_restore_position:
            scrollbar = view.entry_list.verticalScrollBar()
            if scrollbar is not None:
                scrollbar.setValue(scroll_restore.saved_scroll)

        if truncated:
            view.count_label.setText(f'前 {len(entries)} 项（共 {original_count} 项）')
        else:
            view.count_label.setText(f'{len(entries)} 项')

        if entries:
            view.list_stack.setCurrentWidget(view.entry_list)
        else:
            self._show_empty_state()

    def _show_empty_state(self) -> None:
        """根据当前场景显示不同的空状态提示。"""
        view = self._view
        # 清除旧的空状态 widget，即索引 1 及之后的所有 widget
        while view.list_stack.count() > 1:
            old = view.list_stack.widget(1)
            if old is None:
                break
            view.list_stack.removeWidget(old)
            old.deleteLater()

        icon_name, title, subtitle, action_text, slot = self._resolve_empty_state()
        empty = EmptyStateWidget(
            icon_name=icon_name, title=title, subtitle=subtitle, action_text=action_text,
        )
        if slot is not None:
            empty.action_clicked.connect(slot)
        view.list_stack.addWidget(empty)
        view.list_stack.setCurrentWidget(empty)

    def _resolve_empty_state(self) -> tuple[str, str, str, str, Callable[[], None] | None]:
        """按优先级解析当前空状态配置（7 种场景线性判断，首个命中即返回）。"""
        if self._current_search:
            return (EMPTY_SEARCH, '没有找到匹配的条目', '尝试不同的搜索关键词', '清除搜索', self.clear_search)
        filter_name = self._current_filter
        if filter_name == 'trash':
            return (EMPTY_TRASH, '回收站是空的', '删除的条目会出现在这里', '', None)
        if filter_name in ('weak', 'duplicate'):
            # 缓存未就绪时显示「分析中」，避免空列表被误读为「无弱/重复密码」
            if self._is_security_analyzing():
                label = '密码强度' if filter_name == 'weak' else '重复密码'
                return (EMPTY_GENERIC, f'正在分析{label}...', '请稍候', '', None)
            if filter_name == 'weak':
                return (EMPTY_SUCCESS, '没有发现弱密码', '所有密码强度良好', '', None)
            return (EMPTY_SUCCESS, '没有重复密码', '所有密码都是唯一的', '', None)
        if filter_name == 'recent':
            return (EMPTY_SUCCESS, '没有近期更新', '最近没有修改过条目', '', None)
        if self._current_category_id is not None:
            return (EMPTY_FOLDER, '该分类下暂无条目', '新增或编辑条目时可选择该分类', '', None)
        # 仅默认/空库分支需要总数，惰性查询避免其他空态场景的无谓 DB 访问
        total_entries = self._cached_total_entries
        if total_entries < 0:
            total_entries = self._entry_mgr.get_entry_count()
            self._cached_total_entries = total_entries
        if total_entries == 0:
            return (EMPTY_VAULT, '还没有密码条目', '点击工具栏「新增」按钮开始添加', '新增条目', self._deps.on_add_entry)
        return (EMPTY_GENERIC, '暂无条目', '', '', None)

    def _is_security_analyzing(self) -> bool:
        """security 分析是否仍在进行（缓存未就绪），供 weak/duplicate 空态共享。"""
        return self._security.get_cached_counts(
            self._config.get('old_password_warning_days')
        ) is None

    def update_status_bar(self) -> None:
        days = self._config.get('old_password_warning_days')
        # 快速路径：缓存命中时仅取计数——get_cached_counts 跳过 get_cached_report 经
        # _refilter_cache 的 Entry 深拷贝，状态栏只需四个计数。
        counts = self._security.get_cached_counts(days)
        if counts is not None:
            self._render_status(
                counts.total, counts.weak_count, counts.duplicate_count, counts.old,
            )
            return
        # 缓存未命中：显示占位文本，异步执行分析
        status_bar = self._view.status_bar
        status_bar.showMessage('安全分析中...')
        if self._status_worker and self._status_worker.isRunning():
            return
        worker = BackgroundWorker(
            lambda: self._security.get_or_compute_report(days),
            parent=self._parent,
        )
        self._status_worker = worker

        def _on_finished(summary: object) -> None:
            # 锁定后或非当前 worker 的延迟回调均不应用，避免访问已清零状态
            if self._locked or self._status_worker is not worker:
                return
            report = cast('SecurityReport', summary)
            self._render_status(
                report['total'], report['weak_count'],
                report['duplicate_count'], report['old'],
            )
            if self._status_worker is worker:
                self._status_worker = None

        worker.finished.connect(_on_finished)

        def _on_error(_msg: str) -> None:
            if self._locked or self._status_worker is not worker:
                return
            status_bar.showMessage('安全分析暂时不可用')
            if self._status_worker is worker:
                self._status_worker = None

        worker.error.connect(_on_error)
        worker.start()

    def _render_status(
        self, total: int, weak: int, duplicate: int, old_count: int,
    ) -> None:
        """据四项安全计数渲染状态栏统计标签、状态栏消息与过期警告。"""
        view = self._view
        try:
            view.stats_label.setText(f'共 {total} 项')
            parts = [f'总计 {total} 条']
            if weak > 0:
                parts.append(f'弱密码 {weak}')
            if duplicate > 0:
                parts.append(f'重复 {duplicate}')
            view.status_bar.showMessage('  |  '.join(parts))
            # 密码过期警告：复用实例属性，避免 findChild
            warning_label = view.warning_label
            if old_count > 0:
                warning_label.setText(f'  {old_count} 个密码已过期  ')
                warning_label.show()
                if warning_label.parent() is not view.status_bar:
                    view.status_bar.addPermanentWidget(warning_label)
            else:
                warning_label.hide()
        except (ValueError, RuntimeError):
            logger.debug("状态栏安全分析失败", exc_info=True)
            view.status_bar.showMessage('安全分析暂时不可用')

    # ========== 事件处理 ==========

    def _invalidate_security_cache(self) -> None:
        self._security.invalidate_cache()

    def refresh_all_data(self) -> None:
        """全量刷新：分类 + 标签 + 条目 + 安全摘要。

        用于数据发生重大变更的场景，如导入、备份恢复、修改主密码。
        """
        self._invalidate_security_cache()
        # 失效空态总数缓存与滚动位置恢复标记：数据整体替换后应重算
        self._cached_total_entries = -1
        self._last_refresh_filter = None
        self.refresh_categories()
        self.refresh_tag_filter()
        self.refresh_entries()
        self.start_status_timer()

    def refresh_after_entry_change(self) -> None:
        """条目变更后请求刷新，通过防抖合并多次快速操作。"""
        if self._entry_change_timer is not None:
            self._entry_change_timer.start()

    def _do_refresh_after_entry_change(self) -> None:
        """执行条目变更后的全量刷新，由防抖定时器触发。

        分类和标签看似总与上次相同，但编辑/删除操作可能改变分类下的条目计数、
        移除某条目使用的最后一个标签等。防抖定时器以 100ms 间隔已合并快速连续操作，
        三次轻量查询即分类、计数和标签的开销可接受。对于确定不改变分类/标签的操作
        如切换收藏，使用 refresh_entries_only。
        """
        # 安全缓存失效已通过 EntryManager 回调自动完成，此处无需再调用
        self._cached_total_entries = -1
        self._last_refresh_filter = None
        # 取一次含删除的计数，供 tag/entries 的异步阈值判断共享，避免两次 COUNT(*)。
        entry_count = self._entry_mgr.get_entry_count(include_deleted=True)
        self.refresh_categories()
        self.refresh_tag_filter(entry_count)
        self.refresh_entries(entry_count)
        self.start_status_timer()

    def refresh_entries_only(self) -> None:
        """仅刷新条目列表和状态栏，不刷新分类/标签/安全摘要（用于切换收藏等轻量操作）。"""
        self.refresh_entries()
        self.start_status_timer()

    def on_search_input(self, _text: str) -> None:
        if self._search_timer is not None:
            self._search_timer.start()

    @require_unlocked
    def on_tag_changed(self, _index: int = -1) -> None:
        # _index 接收 currentIndexChanged 的信号参数并忽略：@require_unlocked 的
        # wrapper 用 *args 透传，会破坏 PyQt6 对「槽签名少于信号参数」的自动截断，
        # 故被装饰槽须显式接收其连接信号的全部参数（其余槽已与信号参数对齐）。
        self._current_tag = self._view.tag_combo.currentData() or ''
        self.refresh_entries()

    @require_unlocked
    def do_search(self) -> None:
        self._current_search = self._view.search_edit.text().strip()
        self.refresh_entries()

    @require_unlocked
    def on_filter_changed(self, current: QListWidgetItem | None, _previous: QListWidgetItem | None) -> None:
        if current:
            self._current_filter = current.data(Qt.ItemDataRole.UserRole)
            self._current_category_id = None
            # 切换过滤器使总数缓存失效，避免空库文案误判（EMPTY_VAULT/EMPTY_GENERIC）
            self._cached_total_entries = -1
            category_list = self._view.category_list
            category_list.blockSignals(True)
            category_list.setCurrentRow(-1)
            category_list.blockSignals(False)
            self.refresh_entries()

    @require_unlocked
    def on_category_changed(self, current: QListWidgetItem | None, _previous: QListWidgetItem | None) -> None:
        if current:
            self._current_category_id = current.data(Qt.ItemDataRole.UserRole)
            self._current_filter = 'all'
            self._cached_total_entries = -1
            filter_list = self._view.filter_list
            filter_list.blockSignals(True)
            filter_list.setCurrentRow(0)
            filter_list.blockSignals(False)
            # 列表标题由 refresh_entries 根据 _current_category_id 统一设置，
            # 避免此处设置的分类名随后被 fetcher 返回的标题覆盖
            self.refresh_entries()

    def clear_search(self) -> None:
        """快捷键：清空搜索。"""
        search_edit = self._view.search_edit
        if search_edit.text():
            search_edit.clear()
        else:
            self._view.entry_list.setCurrentIndex(QModelIndex())
            self._view.detail_panel.show_empty()
