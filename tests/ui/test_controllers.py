"""UI 控制器纯数据逻辑单元测试。

EntryListController 与 SidebarController 设计为不依赖 PyQt6 控件的纯数据逻辑，
便于直接单测。本文件覆盖其无副作用的纯方法。
"""

# 测试文件大量使用 MagicMock 注入依赖，抑制其属性/函数成员访问的静态类型推断告警
# pyright: reportAttributeAccessIssue=false, reportFunctionMemberAccess=false

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from src.ui.controllers.entry_list_controller import EntryListController
from src.ui.controllers.sidebar_controller import SidebarController


def _entry_list_controller():
    """构造注入 mock 依赖的列表控制器实例。"""
    return EntryListController(MagicMock(), MagicMock(), MagicMock())


def _sidebar_controller():
    """构造注入 mock 依赖的侧边栏控制器实例。"""
    return SidebarController(MagicMock())


class TestGetSortConfig:
    """EntryListController.get_sort_config 的索引边界与有效返回守护。"""

    def test_out_of_range_returns_default(self):
        """越界索引应回退默认排序配置。"""
        ctrl = _entry_list_controller()
        assert ctrl.get_sort_config(-1) == ("updated_at", "desc")
        assert ctrl.get_sort_config(999) == ("updated_at", "desc")

    def test_valid_index_returns_field_and_order(self):
        """有效索引应返回非空字段名与合法排序方向。"""
        ctrl = _entry_list_controller()
        field, order = ctrl.get_sort_config(0)
        assert isinstance(field, str) and field
        assert order in ("asc", "desc")


class TestSortEntries:
    """EntryListController.sort_entries 排序结果的不变量守护。"""

    def test_preserves_length(self):
        """排序不应改变条目集合大小与成员。"""
        ctrl = _entry_list_controller()
        entries = [
            SimpleNamespace(title="b", updated_at="1", created_at="1", password_strength=0),
            SimpleNamespace(title="a", updated_at="2", created_at="2", password_strength=0),
        ]
        result = ctrl.sort_entries(entries, 0)
        assert len(result) == 2
        assert {e.title for e in result} == {"a", "b"}


class TestGetFetcher:
    """EntryListController.get_fetcher 的过滤器键映射与兜底。"""

    def test_known_filters_return_callables(self):
        """已知的过滤器键应都返回可调用 fetcher。"""
        ctrl = _entry_list_controller()
        for key in ("all", "favorite", "weak", "duplicate", "recent", "trash"):
            assert callable(ctrl.get_fetcher(key))

    def test_unknown_filter_falls_back_to_all(self):
        """未知过滤器键应兜底到全量 fetcher。"""
        ctrl = _entry_list_controller()
        # bound method 每次访问创建新对象，比较底层函数而非对象身份
        assert ctrl.get_fetcher("nonexistent").__func__ is EntryListController.fetch_all


class TestFetchLimitPushdown:
    """fetcher 统一透传 limit+排序、manager 分流 SQL/内存路径（PERF-072/073/078 守护）。

    8 种排序统一传 limit 与 order_by/order_desc：SQL 白名单字段+无搜索由 manager
    下推 SQL（50k 实测 ~50ms）；标题序与搜索路径走「窄投影全量 → 内存 meta 排序 →
    仅前 limit 回查」（标题序 50k 实测 ~1750→~300ms）。fetcher 层不再做路径判断
    ——此前「标题序不下推、搜索不下推」的分支已收敛进 manager（PERF-078）。
    """

    @pytest.mark.parametrize(
        "sort_index,expected_field,expected_desc",
        [
            (0, "updated_at", True),  # 更新时间 ↓（SQL 下推）
            (1, "updated_at", False),  # 更新时间 ↑（SQL 下推）
            (2, "title", False),  # 标题 A→Z（内存 meta 排序）
            (3, "title", True),  # 标题 Z→A（内存 meta 排序）
            (4, "password_strength", True),  # 强度 高→低
            (5, "password_strength", False),  # 强度 低→高
            (6, "created_at", True),  # 创建时间 ↓
            (7, "created_at", False),  # 创建时间 ↑
        ],
    )
    def test_all_orders_pass_limit_and_sort(self, sort_index, expected_field, expected_desc):
        """8 种排序全部统一传 limit+order_by+order_desc（路径分流在 manager）。"""
        from src.ui.resources.constants import MAX_SEARCH_RESULTS_DISPLAY

        ctrl = _entry_list_controller()
        ctrl.fetch_all(None, "", None, sort_index=sort_index)
        kwargs = ctrl._entry_mgr.get_entry_summaries.call_args.kwargs
        assert kwargs["limit"] == MAX_SEARCH_RESULTS_DISPLAY
        assert kwargs["order_by"] == expected_field
        assert kwargs["order_desc"] is expected_desc

    def test_search_path_also_passes_limit_and_sort(self):
        """搜索路径同样传 limit+order_by（PERF-078）：manager 内存排序后截断，
        匹配仍全量（加密字段不可先截断后过滤），语义与 SQL ORDER BY+LIMIT 同构。"""
        from src.ui.resources.constants import MAX_SEARCH_RESULTS_DISPLAY

        ctrl = _entry_list_controller()
        ctrl.fetch_all(None, "关键词", None, sort_index=2)  # 标题 A→Z（asc）
        kwargs = ctrl._entry_mgr.get_entry_summaries.call_args.kwargs
        assert kwargs["search"] == "关键词"
        assert kwargs["limit"] == MAX_SEARCH_RESULTS_DISPLAY
        assert kwargs["order_by"] == "title"
        assert kwargs["order_desc"] is False

    @pytest.mark.parametrize(
        "fetcher_name,extra_kwargs",
        [
            ("fetch_favorite", {"favorite_only": True}),
            ("fetch_trash", {"deleted_only": True}),
        ],
    )
    def test_favorite_trash_pass_limit_and_sort(self, fetcher_name, extra_kwargs):
        """收藏/回收站：与 fetch_all 同款统一透传（PERF-078）。"""
        from src.ui.resources.constants import MAX_SEARCH_RESULTS_DISPLAY

        ctrl = _entry_list_controller()
        fetcher = getattr(ctrl, fetcher_name)
        fetcher("", None, sort_index=0)
        kwargs = ctrl._entry_mgr.get_entry_summaries.call_args.kwargs
        assert kwargs["limit"] == MAX_SEARCH_RESULTS_DISPLAY
        assert kwargs["order_by"] == "updated_at"
        assert all(kwargs.get(k) is v for k, v in extra_kwargs.items())

        # 标题序与搜索路径同样透传（不再有 fetcher 层的不下推分支）
        fetcher("", None, sort_index=2)
        followup = ctrl._entry_mgr.get_entry_summaries.call_args.kwargs
        assert followup["limit"] == MAX_SEARCH_RESULTS_DISPLAY
        assert followup["order_by"] == "title"

        fetcher("词", None, sort_index=0)
        searching = ctrl._entry_mgr.get_entry_summaries.call_args.kwargs
        assert searching["limit"] == MAX_SEARCH_RESULTS_DISPLAY

    def test_fetch_recent_accepts_sort_index(self):
        """fetch_recent 接受 sort_index 而不抛 TypeError（PERF-072 统一调用签名契约）。"""
        ctrl = _entry_list_controller()
        ctrl._entry_mgr.get_recent_summaries.return_value = []
        ctrl.fetch_recent("", None, sort_index=5)  # 任意索引均被忽略（本视图固定排序）
        ctrl._entry_mgr.get_recent_summaries.assert_called_once()

    def test_sort_option_fields_all_expressible(self):
        """UI 排序选项字段集 == SQL 白名单 ∪ {title}（PERF-078 双源守护）。

        fetcher 把 SORT_OPTIONS 的字段名直接透传给 manager：SQL 字段经
        ORDER_BY_FIELDS 下推、title 走内存 meta 排序——选项字段落在两集合之外
        会使该排序静默退化为复合序（内存路径的 order_by 不匹配任何键时不重排）。
        测试层锚定选项字段集与两集合的并集一致。
        """
        from src.database.types import ORDER_BY_FIELDS
        from src.ui.resources.constants import SORT_OPTIONS

        option_fields = {field for _, field, _ in SORT_OPTIONS}
        assert option_fields == ORDER_BY_FIELDS | {"title"}


class TestBuildCategoryLabel:
    """SidebarController.build_category_label 的计数显示与完整性告警分支。"""

    @staticmethod
    def _cat():
        return SimpleNamespace(icon_char="[KEY]", name="社交", integrity_error=False)

    def test_with_entries_shows_count(self):
        """条目数大于零时标签带计数后缀。"""
        ctrl = _sidebar_controller()
        assert ctrl.build_category_label(self._cat(), 5) == "[KEY] 社交 (5)"

    def test_zero_entries_omits_count(self):
        """条目数为零时标签省略计数。"""
        ctrl = _sidebar_controller()
        assert ctrl.build_category_label(self._cat(), 0) == "[KEY] 社交"

    def test_integrity_error_shows_warning(self):
        """分类元数据完整性失败时（integrity_error=True）标签前加 ⚠ 警告。"""
        ctrl = _sidebar_controller()
        cat = SimpleNamespace(icon_char="[KEY]", name="社交", integrity_error=True)
        assert ctrl.build_category_label(cat, 3) == "[KEY] ⚠ 社交 (3)"


class TestBuildDeleteMessage:
    """SidebarController.build_delete_message 的分类缺失与条目计数文案。"""

    @staticmethod
    def _ctrl_with_category(name, count):
        # 直接持有 MagicMock 引用，避免通过类型为 EntryManager 的属性访问 return_value
        entry_mgr = MagicMock()
        entry_mgr.categories.get_category.return_value = (
            SimpleNamespace(name=name) if name else None
        )
        entry_mgr.categories.get_category_entry_count.return_value = count
        return SidebarController(entry_mgr)

    def test_missing_category_returns_empty(self):
        """分类不存在时返回空消息与空名。"""
        ctrl = self._ctrl_with_category(None, 0)
        msg, has_entries, name = ctrl.build_delete_message(42)
        assert msg == ""
        assert has_entries is False
        assert name == ""

    def test_empty_category_no_extra_warning(self):
        """空分类不追加条目删除警告。"""
        ctrl = self._ctrl_with_category("工作", 0)
        msg, has_entries, name = ctrl.build_delete_message(1)
        assert "工作" in msg
        assert has_entries is False
        assert name == "工作"

    def test_category_with_entries_adds_warning(self):
        """含条目的分类追加删除条目警告。"""
        ctrl = self._ctrl_with_category("金融", 3)
        msg, has_entries, name = ctrl.build_delete_message(1)
        assert "3" in msg
        assert has_entries is True
        assert name == "金融"


class TestFetchAll:
    """EntryListController.fetch_all 的无搜索 LIMIT 下推（PERF-066/073）。"""

    def test_no_search_pushes_render_cap_limit(self):
        """无搜索时把渲染上限与排序字段一同下推 SQL（PERF-066/073）。

        UI 渲染本就截断到 MAX_SEARCH_RESULTS_DISPLAY；ORDER BY 字段序截断使集合与
        用户所选排序一致，免去大库全量拉取+逐行验签+Entry 构造。
        """
        from src.ui.resources.constants import MAX_SEARCH_RESULTS_DISPLAY

        ctrl = _entry_list_controller()
        ctrl.fetch_all(None, "")
        ctrl._entry_mgr.get_entry_summaries.assert_called_once_with(
            category_id=None,
            search="",
            cancel_check=None,
            limit=MAX_SEARCH_RESULTS_DISPLAY,
            order_by="updated_at",
            order_desc=True,
        )

    def test_search_path_passes_limit_and_sort(self):
        """有搜索时同样透传 limit+排序（PERF-078）：manager 内存排序后取前 limit
        回查——匹配仍全量（加密字段不可先截断后过滤），截断语义与 SQL
        ORDER BY+LIMIT 同构，宽搜索词的全量回查悬崖一并收口。"""
        from src.ui.resources.constants import MAX_SEARCH_RESULTS_DISPLAY

        ctrl = _entry_list_controller()
        ctrl.fetch_all(3, "关键词")
        ctrl._entry_mgr.get_entry_summaries.assert_called_once_with(
            category_id=3,
            search="关键词",
            cancel_check=None,
            limit=MAX_SEARCH_RESULTS_DISPLAY,
            order_by="updated_at",
            order_desc=True,
        )


class TestFetchRecent:
    """EntryListController.fetch_recent 的 SQL 下推与内存排序分支。"""

    def test_no_search_uses_sql_recent_summaries(self):
        """无搜索时下推到 get_recent_summaries（SQL ORDER BY updated_at DESC LIMIT），
        controller 不做内存排序，直接透传 DB 已排序结果，避免全量解密。"""
        from src.ui.controllers.entry_list_controller import RECENT_ENTRY_LIMIT

        ctrl = _entry_list_controller()
        entries = [
            SimpleNamespace(title="最新", updated_at="2026-01-01"),
            SimpleNamespace(title="较新", updated_at="2025-01-01"),
            SimpleNamespace(title="旧条目", updated_at="2020-01-01"),
        ]
        ctrl._entry_mgr.get_recent_summaries.return_value = entries
        result, label = ctrl.fetch_recent("")
        assert label == "近期更新"
        # 透传 get_recent_summaries 的返回（DB 层已排序截断）
        assert [e.title for e in result] == ["最新", "较新", "旧条目"]
        ctrl._entry_mgr.get_recent_summaries.assert_called_once_with(limit=RECENT_ENTRY_LIMIT)
        # 无搜索不走全量解密路径
        ctrl._entry_mgr.get_entry_summaries.assert_not_called()

    def test_search_path_sorts_in_memory(self):
        """有搜索时因加密字段无法 SQL 过滤，全量解密后内存按 updated_at 排序。"""
        ctrl = _entry_list_controller()
        entries = [
            SimpleNamespace(title="旧条目", updated_at="2020-01-01"),
            SimpleNamespace(title="较新", updated_at="2025-01-01"),
            SimpleNamespace(title="最新", updated_at="2026-01-01"),
        ]
        ctrl._entry_mgr.get_entry_summaries.return_value = entries
        result, label = ctrl.fetch_recent("关键词")
        assert label == "近期更新"
        assert [e.title for e in result] == ["最新", "较新", "旧条目"]

    def test_search_path_truncates_to_limit(self):
        """搜索路径条目数超过 RECENT_ENTRY_LIMIT 时内存截断到上限。"""
        from src.ui.controllers.entry_list_controller import RECENT_ENTRY_LIMIT

        ctrl = _entry_list_controller()
        entries = [
            SimpleNamespace(title=f"e{i:03d}", updated_at=f"2020-01-{(i % 28) + 1:02d}")
            for i in range(RECENT_ENTRY_LIMIT + 5)
        ]
        ctrl._entry_mgr.get_entry_summaries.return_value = entries
        result, _ = ctrl.fetch_recent("关键词")
        assert len(result) == RECENT_ENTRY_LIMIT
