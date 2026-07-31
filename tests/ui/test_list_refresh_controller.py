"""ListRefreshController 直接单测（rank 10）。

筛选、排序、列表刷新、状态栏、worker 生命周期此前经 ``_MainWindowFiltersMixin``
隐式覆盖，组合化迁出（Mixin→普通类 + ``ListRefreshDeps`` 回调 + ``ListRefreshView``
控件引用）后首次直接单测：3 定时器创建、锁定态守卫、``@require_unlocked`` 跳过、
刷新防抖定时器、排序配置委托、``clear_search`` 分支、生命周期方法与缓存 property。

worker 异步刷新的状态机（generation 守卫、锁定丢弃回调）经 ``test_product_hardening``
端到端守护覆盖；本文件聚焦 controller 同步路径与状态。``_make_controller`` 配置
mock 返回空集合，使 ``setup`` 的初始填充（refresh_categories/tag_filter/entries/
status_bar）可在无真实数据下运行。
"""

# 测试大量用 MagicMock 注入依赖，抑制其属性访问的静态类型告警
# pyright: reportAttributeAccessIssue=false

from unittest.mock import MagicMock

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QListWidgetItem, QMainWindow

from src.ui.controllers.list_refresh_controller import (
    ListRefreshController,
    ListRefreshDeps,
    ListRefreshView,
)


def _make_view() -> ListRefreshView:
    """构造全 MagicMock 控件的 ListRefreshView，配置 setup 初始填充所需的返回值。"""
    view = ListRefreshView(
        search_edit=MagicMock(),
        entry_list=MagicMock(),
        entry_model=MagicMock(),
        category_list=MagicMock(),
        tag_combo=MagicMock(),
        sort_combo=MagicMock(),
        filter_list=MagicMock(),
        list_stack=MagicMock(),
        list_title=MagicMock(),
        count_label=MagicMock(),
        status_bar=MagicMock(),
        warning_label=MagicMock(),
        stats_label=MagicMock(),
        detail_panel=MagicMock(),
    )
    # _show_empty_state 的 `while list_stack.count() > 1` 需返回可比较 int
    view.list_stack.count.return_value = 1
    # _apply_tag_filter 的 findData(current) 需返回可比较 int
    view.tag_combo.findData.return_value = 0
    return view


def _make_controller() -> ListRefreshController:
    """构造 controller，配置 mock 使 setup 初始填充（空集合）可运行。"""
    entry_list_ctrl = MagicMock()
    entry_list_ctrl.get_fetcher.return_value = lambda *a, **k: ([], '标题')
    entry_list_ctrl.sort_entries.return_value = []
    sidebar_ctrl = MagicMock()
    sidebar_ctrl.get_categories.return_value = []
    sidebar_ctrl.get_category_entry_counts.return_value = {}
    sidebar_ctrl.get_all_tags.return_value = []
    sidebar_ctrl.tags_cache_valid = True
    entry_mgr = MagicMock()
    entry_mgr.get_entry_count.return_value = 0
    security = MagicMock()
    security.get_cached_counts.return_value = MagicMock(
        total=0, weak_count=0, duplicate_count=0, old=0,
    )
    return ListRefreshController(
        MagicMock(), entry_mgr, security, entry_list_ctrl, sidebar_ctrl,
        ListRefreshDeps(on_add_entry=MagicMock()),
    )


def _setup(ctrl: ListRefreshController) -> ListRefreshView:
    """在全新 QMainWindow + mock view 上 setup，返回 view 供断言。"""
    view = _make_view()
    ctrl.setup(QMainWindow(), view)
    return view


class TestSetup:
    def test_setup_creates_three_timers(self, qapp):
        """setup 创建状态栏/条目变更/搜索三个防抖定时器。"""
        ctrl = _make_controller()
        _setup(ctrl)
        assert ctrl._status_timer is not None
        assert ctrl._entry_change_timer is not None
        assert ctrl._search_timer is not None


class TestLifecycle:
    def test_prepare_for_lock_sets_locked_and_clears_search(self, qapp):
        """prepare_for_lock 标记锁定态并清空搜索输入。"""
        ctrl = _make_controller()
        view = _setup(ctrl)
        ctrl.prepare_for_lock()
        assert ctrl._locked is True
        assert ctrl._current_search == ''
        view.search_edit.clear.assert_called_once()

    def test_set_locked_toggles_state(self, qapp):
        ctrl = _make_controller()
        _setup(ctrl)
        ctrl.prepare_for_lock()
        assert ctrl._locked is True
        ctrl.set_locked(False)
        assert ctrl._locked is False

    def test_stop_timers_stops_all_three(self, qapp):
        ctrl = _make_controller()
        ctrl.setup(QMainWindow(), _make_view())
        timers = (ctrl._status_timer, ctrl._entry_change_timer, ctrl._search_timer)
        for timer in timers:
            assert timer is not None
            timer.start()
        ctrl.stop_timers()
        assert not any(timer.isActive() for timer in timers)

    def test_start_status_timer_starts(self, qapp):
        ctrl = _make_controller()
        ctrl.setup(QMainWindow(), _make_view())
        ctrl.start_status_timer()
        assert ctrl._status_timer is not None
        assert ctrl._status_timer.isActive()


class TestCachedProperties:
    def test_cached_properties_initial_empty(self, qapp):
        ctrl = _make_controller()
        assert ctrl.cached_categories == []
        assert ctrl.cached_tag_names == []


class TestRequireUnlocked:
    def test_on_filter_changed_locked_skips(self, qapp):
        """锁定态 on_filter_changed 不改 _current_filter（守卫跳过）。"""
        ctrl = _make_controller()
        _setup(ctrl)
        ctrl.set_locked(True)
        item = QListWidgetItem()
        item.setData(Qt.ItemDataRole.UserRole, 'favorite')
        ctrl.on_filter_changed(item, None)
        assert ctrl._current_filter == 'all'


class TestCallbacks:
    def test_refresh_after_entry_change_starts_debounce_timer(self, qapp):
        """refresh_after_entry_change 启动条目变更防抖定时器。"""
        ctrl = _make_controller()
        _setup(ctrl)
        ctrl.refresh_after_entry_change()
        assert ctrl._entry_change_timer is not None
        assert ctrl._entry_change_timer.isActive()

    def test_get_sort_config_delegates_to_entry_list_ctrl(self, qapp):
        """get_sort_config 透传 sort_combo 当前索引给 EntryListController。"""
        ctrl = _make_controller()
        view = _make_view()
        view.sort_combo.currentIndex.return_value = 2
        ctrl.setup(QMainWindow(), view)
        ctrl.get_sort_config()
        ctrl._entry_list_ctrl.get_sort_config.assert_called_once_with(2)

    def test_clear_search_with_text_clears_input(self, qapp):
        ctrl = _make_controller()
        view = _make_view()
        view.search_edit.text.return_value = 'abc'
        ctrl.setup(QMainWindow(), view)
        ctrl.clear_search()
        view.search_edit.clear.assert_called_once()

    def test_clear_search_empty_clears_selection_and_detail(self, qapp):
        """搜索框已空时 Escape 清空选中与详情面板（快捷键二次按 Escape 语义）。"""
        ctrl = _make_controller()
        view = _make_view()
        view.search_edit.text.return_value = ''
        ctrl.setup(QMainWindow(), view)
        ctrl.clear_search()
        view.entry_list.setCurrentIndex.assert_called_once()
        view.detail_panel.show_empty.assert_called_once()
