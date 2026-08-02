"""MainWindow 筛选、排序、数据刷新控制器。

普通类（非 QObject）：``__init__`` 注入 manager 与跨 controller 回调
（``ListRefreshDeps``），``setup(parent, view)`` 接收 QObject 父与冻结
dataclass view-handle（``ListRefreshView``），创建 3 个防抖/状态定时器、连接 8 个
控件信号、初始化填充列表。

职责收敛为「事件->刷新策略」编排 + 渲染：异步刷新的 worker 池与 generation 守卫
（entry/tag worker、过期结果丢弃、滚动恢复）下沉至 ``EntryRefreshCoordinator``；
状态栏渲染经 ``StatusBarRenderer``、空态解析经 ``EmptyStateResolver`` 下沉。
host 生命周期（锁定/关闭/隐藏到托盘/紧急取消）经 ``shutdown`` /
``cancel_all_workers`` / ``stop_timers`` / ``prepare_for_lock`` 委托本控制器。
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from PyQt6.QtCore import QModelIndex, Qt, QTimer
from PyQt6.QtWidgets import QListWidgetItem, QMainWindow

from ...config import CFG_OLD_PASSWORD_WARNING_DAYS, CFG_SORT_FIELD, CFG_SORT_ORDER
from ..components.empty_state_widget import EmptyStateWidget
from ..components.workers import BackgroundWorker, wait_worker_shutdown
from ..resources.constants import (
    ASYNC_SEARCH_THRESHOLD,
    MAX_SEARCH_RESULTS_DISPLAY,
    MAX_TAG_AUTOCOMPLETE,
    MS_ENTRY_CHANGE_DEBOUNCE,
    MS_SEARCH_DEBOUNCE,
    MS_STATUS_BAR_DEBOUNCE,
)
from ..resources.icons import (
    FOLDER,
    icon,
)
from ._locked_guard import require_unlocked
from .entry_refresh_coordinator import (
    CoordinatorDeps,
    EntryRefreshCoordinator,
    ScrollRestore,
)
from .list_refresh_helpers import (
    EmptyStateContext,
    EmptyStateResolver,
    StatusBarRenderer,
    StatusBarView,
)

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
    from ...models import Category, Entry
    from ..components.detail_panel import DetailPanel
    from ..components.entry_list_widget import EntryListModel
    from ..controllers.entry_list_controller import EntryListController
    from ..controllers.sidebar_controller import SidebarController

logger = logging.getLogger(__name__)


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

    host 经生命周期方法（``shutdown`` / ``cancel_all_workers`` / ``stop_timers`` /
    ``prepare_for_lock`` / ``refresh_after_unlock``）委托，保持原有 6 条关闭路径的
    worker 不变量。
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
        self._current_filter = "all"
        self._current_category_id: int | None = None
        self._current_search = ""
        self._current_tag = ""
        # 缓存
        self._cached_categories: list[Category] = []
        self._cached_tag_names: list[str] = []
        self._cached_total_entries = -1
        self._last_refresh_filter: str | None = None
        # status worker（状态栏安全摘要专用，独立于 entry/tag 刷新）
        self._status_worker: BackgroundWorker | None = None
        # entry/tag 异步刷新协调器（setup 创建，管 worker 池与 generation 守卫）
        self._coordinator: EntryRefreshCoordinator
        # 定时器（setup 创建，parent=host 保证 Qt 线程亲和性与析构自动断开）
        self._status_timer: QTimer | None = None
        self._entry_change_timer: QTimer | None = None
        self._search_timer: QTimer | None = None

    def setup(self, parent: QMainWindow, view: ListRefreshView) -> None:
        """创建协调器、3 定时器、连接 8 个控件信号并初始化填充列表。须在控件创建后调用。"""
        self._parent = parent
        self._view = view

        # 异步刷新协调器：worker 池与 generation 守卫下沉，结果应用/新鲜度判定经回调注入
        self._coordinator = EntryRefreshCoordinator(
            parent,
            CoordinatorDeps(
                is_locked=lambda: self._locked,
                is_entry_stale=self._is_entry_request_stale,
                apply_entries=self._apply_entry_results,
                apply_tags=self._apply_tag_filter,
                show_loading=view.count_label.setText,
            ),
        )

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

        # 构造期初始化填充列表
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
        self._current_search = ""
        view = self._view
        view.search_edit.blockSignals(True)
        view.search_edit.clear()
        view.search_edit.blockSignals(False)
        # 分类名/标签名经加密存储（name_enc/tags_enc）视为敏感，锁定时须连同 UI 缓存
        # 与控件一并清空，与条目/详情/剪贴板的清零纪律对齐，收缩锁定后内存残留面。
        self._cached_categories = []
        self._cached_tag_names = []
        view.category_list.blockSignals(True)
        view.category_list.clear()
        view.category_list.blockSignals(False)
        view.tag_combo.blockSignals(True)
        view.tag_combo.clear()
        view.tag_combo.blockSignals(False)
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
        entry/tag worker 经 coordinator 关闭，status worker 在本控制器关闭。
        """
        wait_worker_shutdown(self._status_worker)
        self._status_worker = None
        self._coordinator.shutdown()

    def cancel_all_workers(self) -> None:
        """紧急取消后台 worker（不等待），供 host emergency_cancel_workers / prepare_for_lock。

        coordinator 遍历 entry/tag worker 全集快照（含并发 entry worker），status worker
        在本控制器取消——避免漏 cancel 并发 worker 残留持密钥继续解密、与 lock() 清零竞态。
        """
        self._coordinator.cancel_all()
        if self._status_worker is not None:
            try:
                self._status_worker.cancel()
            except RuntimeError:
                pass

    def wait_workers(self, timeout_ms: int) -> None:
        """取消后等待 worker 退出（host emergency_cancel_workers 的 wait 分支）。"""
        self._coordinator.wait(timeout_ms)
        if self._status_worker is not None:
            try:
                self._status_worker.wait(timeout_ms)
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
        self._config.set(CFG_SORT_FIELD, field)
        self._config.set(CFG_SORT_ORDER, order)
        self.refresh_entries()

    def _sort_entries(self, entries: list[Entry]) -> list[Entry]:
        return self._entry_list_ctrl.sort_entries(entries, self._view.sort_combo.currentIndex())

    # ========== 数据操作 ==========

    def refresh_categories(self) -> None:
        selected_category_id = self._current_category_id
        category_list = self._view.category_list
        category_list.blockSignals(True)
        category_list.clear()

        all_item = QListWidgetItem("全部分类")
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
                if (
                    selected_item
                    and selected_item.data(Qt.ItemDataRole.UserRole) == selected_category_id
                ):
                    target_row = row
                    break
            else:
                self._current_category_id = None
        category_list.setCurrentRow(target_row)
        category_list.blockSignals(False)
        self._cached_categories = categories

    def refresh_tag_filter(self, entry_count: int | None = None) -> None:
        # get_all_tags() 在缓存失效（改密/锁定/标签变更）时需全量解密全部条目 tags
        # 字段，大库下同步会卡主线程。仅在「大库 且 缓存失效」时移入后台线程；
        # 缓存命中或小库时直接同步重建下拉，省去无谓的 QThread 创建与跨线程信号开销。
        count = (
            entry_count
            if entry_count is not None
            else self._entry_mgr.get_entry_count(include_deleted=True)
        )
        if count >= ASYNC_SEARCH_THRESHOLD and not self._sidebar_ctrl.tags_cache_valid:
            self._coordinator.start_async_tag_refresh(self._sidebar_ctrl.get_all_tags)
            return
        # 同步分支取消在飞的异步 tag worker（与 refresh_entries 同步分支调 cancel_entry_worker
        # 对称）：推进 tag generation 使其延迟 _done 回调丢弃，避免旧标签快照覆盖刚渲染结果。
        self._coordinator.cancel_tag_worker()
        self._apply_tag_filter(self._sidebar_ctrl.get_all_tags())

    def _apply_tag_filter(self, all_tags: list[tuple[str, int]]) -> None:
        """用给定标签列表重建标签下拉，保留当前选中（若仍存在）。"""
        current = self._current_tag
        tag_combo = self._view.tag_combo
        tag_combo.blockSignals(True)
        tag_combo.clear()
        tag_combo.addItem("全部标签", "")
        for tag, count in all_tags:
            tag_combo.addItem(f"{tag}  ·  {count}", tag)
        index = tag_combo.findData(current)
        tag_combo.setCurrentIndex(index if index >= 0 else 0)
        if index < 0:
            self._current_tag = ""
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
        effective_search = self._current_search if use_current_state else (search or "")
        effective_category = self._current_category_id if use_current_state else category_id
        fetcher = self._entry_list_ctrl.get_fetcher(filter_key)
        if filter_key == "all":
            entries, title = fetcher(effective_category, effective_search, cancel_check)
        elif filter_key in ("favorite", "recent", "trash"):
            entries, title = fetcher(effective_search, cancel_check)
        else:
            entries, title = fetcher()  # weak、duplicate 无参数
        if filter_key in ("all", "favorite", "trash"):
            entries = self._sort_entries(entries)
        return entries, title

    def _current_category_name(self) -> str:
        """返回当前选中分类的名称，无选中分类时返回空字符串。"""
        if self._current_category_id is None:
            return ""
        for category in self._cached_categories:
            if category.id == self._current_category_id:
                return category.name
        return ""

    def refresh_entries(self, entry_count: int | None = None) -> None:
        # 重建列表后选择防抖的 pending 若已失效，由 EntryActionsController.do_select_entry
        # 的「pending 行 != 当前选中行 → show_empty」校验兜底，故此处不再跨控制器取消
        # （避免 list_refresh → entry_actions 的逆向依赖）。
        view = self._view
        # 记录滚动位置和当前选中行，重建后恢复，提升列表刷新体验。仅在当前过滤器
        # 未变时恢复同一数据集的刷新；切换过滤器后数据集不同，不应恢复旧位置。
        saved_filter = self._last_refresh_filter
        current_filter = self._current_filter
        should_restore_position = saved_filter == current_filter
        self._last_refresh_filter = current_filter
        scroll_restore = ScrollRestore(
            should_restore_position=should_restore_position,
            saved_row=view.entry_list.currentIndex().row() if should_restore_position else -1,
        )

        # 异步刷新条件：条目数超阈值时移入后台线程。all/favorite/trash 无论是否搜索都
        # 需全量解密，大库下须异步；recent 仅在有搜索时全量解密；weak/duplicate 来自
        # 缓存安全摘要，无需异步。
        filter_key = self._current_filter
        needs_async = filter_key in ("all", "favorite", "trash") or (
            filter_key == "recent" and self._current_search
        )
        if (
            needs_async
            and (
                entry_count
                if entry_count is not None
                else self._entry_mgr.get_entry_count(include_deleted=True)
            )
            >= ASYNC_SEARCH_THRESHOLD
        ):
            self._coordinator.start_async_entry_refresh(
                current_filter,
                self._current_category_id,
                self._current_search,
                self._build_entry_fetch(current_filter),
                scroll_restore,
            )
            return

        self._coordinator.cancel_entry_worker()
        entries, title = self._fetch_for_filter(self._current_filter)
        self._apply_entry_results(entries, title, scroll_restore)

    def _build_entry_fetch(
        self,
        filter_key: str,
    ) -> Callable[[Callable[[], bool]], tuple[list, str]]:
        """构造异步 fetcher 工厂：冻结当前 filter/category/search，注入 cancel_check。

        闭包捕获赋值时的 ``_current_*`` 快照（非运行时读取）——worker 在后台线程执行
        时读快照，而非主线程可能已变更的当前状态。
        """
        category_id = self._current_category_id
        search = self._current_search

        def fetch(cancel_check: Callable[[], bool]) -> tuple[list, str]:
            return self._fetch_for_filter(
                filter_key,
                category_id=category_id,
                search=search,
                cancel_check=cancel_check,
                use_current_state=False,
            )

        return fetch

    def _is_entry_request_stale(
        self,
        filter_key: str,
        category_id: int | None,
        search: str,
    ) -> bool:
        """worker 捕获的请求指纹是否已被当前 UI 状态取代（供 coordinator 过期判定）。

        与 coordinator 的 generation 计数器构成双重守卫：generation 处理「filter 未变但
        数据版本已变」（如永久删除降计数触发同步分支），指纹处理「filter/category/search
        已切换」。worker 协作取消后仍可能延迟回调，两道守卫共同丢弃过期结果。
        """
        return (
            self._current_filter != filter_key
            or self._current_category_id != category_id
            or self._current_search != search
        )

    def _apply_entry_results(
        self,
        entries: list[Entry],
        title: str,
        scroll_restore: ScrollRestore,
    ) -> None:
        view = self._view
        # 分类筛选下显示分类名作为标题，而非 fetcher 默认的「全部条目」
        if self._current_category_id is not None:
            title = self._current_category_name() or title
        view.list_title.setText(title)

        if self._current_search and self._current_filter in ("weak", "duplicate"):
            entries = self._entry_list_ctrl.filter_by_search(entries, self._current_search)

        if self._current_tag:
            entries = self._entry_list_ctrl.filter_by_tag(entries, self._current_tag)

        # 渲染上限：超大库下避免一次性渲染过多条目卡死 UI。
        original_count = len(entries)
        truncated = original_count > MAX_SEARCH_RESULTS_DISPLAY
        if truncated:
            entries = entries[:MAX_SEARCH_RESULTS_DISPLAY]

        # 异步刷新期间用户可能已滚动旧列表；set_entries 会重置滚动条，故先捕获实时
        # 滚动位置，重建后据此恢复（同步路径下 live_scroll 即刷新前位置，行为等效；
        # 异步路径下沿用用户当前关注位置，避免 worker 返回后视图被拉回旧位置）。
        scrollbar = view.entry_list.verticalScrollBar()
        live_scroll = scrollbar.value() if scrollbar is not None else 0
        # Model/View：一次替换全部数据，QListView 按需经 delegate 绘制。
        view.entry_model.set_entries(entries)

        # 恢复滚动位置和选中行，仅在过滤器未变时恢复。
        if (
            scroll_restore.should_restore_position
            and not self._current_search
            and 0 <= scroll_restore.saved_row < view.entry_model.rowCount()
        ):
            view.entry_list.setCurrentIndex(view.entry_model.index(scroll_restore.saved_row))
        if scroll_restore.should_restore_position and scrollbar is not None:
            scrollbar.setValue(live_scroll)

        if truncated:
            view.count_label.setText(f"前 {len(entries)} 项（共 {original_count} 项）")
        else:
            view.count_label.setText(f"{len(entries)} 项")

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

        spec = EmptyStateResolver.resolve(self._build_empty_state_context())
        empty = EmptyStateWidget(
            icon_name=spec.icon_name,
            title=spec.title,
            subtitle=spec.subtitle,
            action_text=spec.action_text,
        )
        if spec.action_slot is not None:
            empty.action_clicked.connect(spec.action_slot)
        view.list_stack.addWidget(empty)
        view.list_stack.setCurrentWidget(empty)

    def _build_empty_state_context(self) -> EmptyStateContext:
        """构造空态解析入参快照；总数经 ``_cached_total_entries`` 缓存解析后注入。"""
        # total_entries 经缓存惰性解析：resolver 为无 DB 访问的纯函数，总数由 controller
        # 在此解析后注入。缓存命中时零查询，失效（-1）时查一次 COUNT 并回填缓存。
        total_entries = self._cached_total_entries
        if total_entries < 0:
            total_entries = self._entry_mgr.get_entry_count()
            self._cached_total_entries = total_entries
        return EmptyStateContext(
            current_search=self._current_search,
            current_filter=self._current_filter,
            current_category_id=self._current_category_id,
            total_entries=total_entries,
            is_analyzing=self._is_security_analyzing(),
            on_clear_search=self.clear_search,
            on_add_entry=self._deps.on_add_entry,
        )

    def _is_security_analyzing(self) -> bool:
        """security 分析是否仍在进行（缓存未就绪），供 weak/duplicate 空态共享。"""
        return (
            self._security.get_cached_counts(self._config.get(CFG_OLD_PASSWORD_WARNING_DAYS))
            is None
        )

    def update_status_bar(self) -> None:
        days = self._config.get(CFG_OLD_PASSWORD_WARNING_DAYS)
        # 快速路径：缓存命中时仅取计数——get_cached_counts 跳过 get_cached_report 经
        # _refilter_cache 的 Entry 深拷贝，状态栏只需四个计数。
        counts = self._security.get_cached_counts(days)
        if counts is not None:
            self._render_status(
                counts.total,
                counts.weak_count,
                counts.duplicate_count,
                counts.old,
            )
            return
        # 缓存未命中：显示占位文本，异步执行分析
        status_bar = self._view.status_bar
        status_bar.showMessage("安全分析中...")
        if self._status_worker and self._status_worker.isRunning():
            return
        worker = BackgroundWorker(
            lambda: self._security.get_or_compute_report(days, cancel_check=worker.cancel_check),
            parent=self._parent,
        )
        self._status_worker = worker

        def _on_finished(summary: object) -> None:
            # 锁定后或非当前 worker 的延迟回调均不应用，避免访问已清零状态
            if self._locked or self._status_worker is not worker:
                return
            report = cast("SecurityReport", summary)
            self._render_status(
                report["total"],
                report["weak_count"],
                report["duplicate_count"],
                report["old"],
            )
            if self._status_worker is worker:
                self._status_worker = None

        worker.finished.connect(_on_finished)

        def _on_error(_msg: str) -> None:
            if self._locked or self._status_worker is not worker:
                return
            status_bar.showMessage("安全分析暂时不可用")
            if self._status_worker is worker:
                self._status_worker = None

        worker.error.connect(_on_error)
        worker.start()

    def _render_status(
        self,
        total: int,
        weak: int,
        duplicate: int,
        old_count: int,
    ) -> None:
        """据四项安全计数渲染状态栏；纯渲染下沉 StatusBarRenderer，控件引用经快照注入。"""
        StatusBarRenderer.render(
            StatusBarView(
                stats_label=self._view.stats_label,
                status_bar=self._view.status_bar,
                warning_label=self._view.warning_label,
            ),
            total,
            weak,
            duplicate,
            old_count,
        )

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

        分类和标签看似总与上次相同，但编辑/删除可能改变分类下条目计数、移除某条目
        使用的最后一个标签。防抖定时器已合并快速连续操作，三次轻量查询开销可接受；
        确定不改变分类/标签的操作（如切换收藏）用 refresh_entries_only。
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
        self._current_tag = self._view.tag_combo.currentData() or ""
        self.refresh_entries()

    @require_unlocked
    def do_search(self) -> None:
        self._current_search = self._view.search_edit.text().strip()
        self.refresh_entries()

    @require_unlocked
    def on_filter_changed(
        self, current: QListWidgetItem | None, _previous: QListWidgetItem | None
    ) -> None:
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
    def on_category_changed(
        self, current: QListWidgetItem | None, _previous: QListWidgetItem | None
    ) -> None:
        if current:
            self._current_category_id = current.data(Qt.ItemDataRole.UserRole)
            self._current_filter = "all"
            self._cached_total_entries = -1
            filter_list = self._view.filter_list
            filter_list.blockSignals(True)
            filter_list.setCurrentRow(0)
            filter_list.blockSignals(False)
            # 列表标题由 refresh_entries 根据 _current_category_id 统一设置，
            # 避免此处设置的分类名随后被 fetcher 返回的标题覆盖
            self.refresh_entries()

    def clear_search(self) -> None:
        search_edit = self._view.search_edit
        if search_edit.text():
            search_edit.clear()
        else:
            self._view.entry_list.setCurrentIndex(QModelIndex())
            self._view.detail_panel.show_empty()
