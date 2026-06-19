"""UI 控制器纯数据逻辑单元测试。

EntryListController 与 SidebarController 从 MainWindow 拆分，设计为不依赖
PyQt6 控件的纯数据逻辑，便于直接单测。本文件覆盖其无副作用的纯方法，填补此前
仅被 main_window_filters 间接覆盖的盲区。
"""

# 测试文件大量使用 MagicMock 注入依赖，抑制其属性/函数成员访问的静态类型推断告警
# pyright: reportAttributeAccessIssue=false, reportFunctionMemberAccess=false

from types import SimpleNamespace
from unittest.mock import MagicMock

from src.ui.controllers.entry_list_controller import EntryListController
from src.ui.controllers.sidebar_controller import SidebarController


def _entry_list_controller():
    return EntryListController(MagicMock(), MagicMock(), MagicMock())


def _sidebar_controller():
    return SidebarController(MagicMock(), MagicMock())


class TestGetSortConfig:
    def test_out_of_range_returns_default(self):
        ctrl = _entry_list_controller()
        assert ctrl.get_sort_config(-1) == ('updated_at', 'desc')
        assert ctrl.get_sort_config(999) == ('updated_at', 'desc')

    def test_valid_index_returns_field_and_order(self):
        ctrl = _entry_list_controller()
        field, order = ctrl.get_sort_config(0)
        assert isinstance(field, str) and field
        assert order in ('asc', 'desc')


class TestSortEntries:
    def test_preserves_length(self):
        ctrl = _entry_list_controller()
        entries = [
            SimpleNamespace(title='b', updated_at='1', created_at='1', password_strength=0),
            SimpleNamespace(title='a', updated_at='2', created_at='2', password_strength=0),
        ]
        result = ctrl.sort_entries(entries, 0)
        assert len(result) == 2
        assert {e.title for e in result} == {'a', 'b'}


class TestGetFetcher:
    def test_known_filters_return_callables(self):
        ctrl = _entry_list_controller()
        for key in ('all', 'favorite', 'weak', 'duplicate', 'recent', 'trash'):
            assert callable(ctrl.get_fetcher(key))

    def test_unknown_filter_falls_back_to_all(self):
        ctrl = _entry_list_controller()
        # bound method 每次访问创建新对象，比较底层函数而非对象身份
        assert ctrl.get_fetcher('nonexistent').__func__ is EntryListController.fetch_all


class TestBuildCategoryLabel:
    @staticmethod
    def _cat():
        return SimpleNamespace(icon_char='[KEY]', name='社交')

    def test_with_entries_shows_count(self):
        ctrl = _sidebar_controller()
        assert ctrl.build_category_label(self._cat(), 5) == '[KEY] 社交 (5)'

    def test_zero_entries_omits_count(self):
        ctrl = _sidebar_controller()
        assert ctrl.build_category_label(self._cat(), 0) == '[KEY] 社交'


class TestBuildDeleteMessage:
    @staticmethod
    def _ctrl_with_category(name, count):
        # 直接持有 MagicMock 引用，避免通过类型为 EntryManager 的属性访问 return_value
        entry_mgr = MagicMock()
        entry_mgr.categories.get_category.return_value = (
            SimpleNamespace(name=name) if name else None
        )
        entry_mgr.categories.get_category_entry_count.return_value = count
        return SidebarController(entry_mgr, MagicMock())

    def test_missing_category_returns_empty(self):
        ctrl = self._ctrl_with_category(None, 0)
        msg, has_entries, name = ctrl.build_delete_message(42)
        assert msg == ''
        assert has_entries is False
        assert name == ''

    def test_empty_category_no_extra_warning(self):
        ctrl = self._ctrl_with_category('工作', 0)
        msg, has_entries, name = ctrl.build_delete_message(1)
        assert '工作' in msg
        assert has_entries is False
        assert name == '工作'

    def test_category_with_entries_adds_warning(self):
        ctrl = self._ctrl_with_category('金融', 3)
        msg, has_entries, name = ctrl.build_delete_message(1)
        assert '3' in msg
        assert has_entries is True
        assert name == '金融'


class TestFetchRecent:
    def test_no_search_uses_sql_recent_summaries(self):
        """无搜索时下推到 get_recent_summaries（SQL ORDER BY updated_at DESC LIMIT），
        controller 不做内存排序，直接透传 DB 已排序结果，避免全量解密。"""
        from src.ui.controllers.entry_list_controller import RECENT_ENTRY_LIMIT
        ctrl = _entry_list_controller()
        entries = [
            SimpleNamespace(title='最新', updated_at='2026-01-01'),
            SimpleNamespace(title='较新', updated_at='2025-01-01'),
            SimpleNamespace(title='旧条目', updated_at='2020-01-01'),
        ]
        ctrl._entry_mgr.get_recent_summaries.return_value = entries
        result, label = ctrl.fetch_recent('')
        assert label == '近期更新'
        # 透传 get_recent_summaries 的返回（DB 层已排序截断）
        assert [e.title for e in result] == ['最新', '较新', '旧条目']
        ctrl._entry_mgr.get_recent_summaries.assert_called_once_with(limit=RECENT_ENTRY_LIMIT)
        # 无搜索不走全量解密路径
        ctrl._entry_mgr.get_entry_summaries.assert_not_called()

    def test_search_path_sorts_in_memory(self):
        """有搜索时因加密字段无法 SQL 过滤，全量解密后内存按 updated_at 排序。"""
        ctrl = _entry_list_controller()
        entries = [
            SimpleNamespace(title='旧条目', updated_at='2020-01-01'),
            SimpleNamespace(title='较新', updated_at='2025-01-01'),
            SimpleNamespace(title='最新', updated_at='2026-01-01'),
        ]
        ctrl._entry_mgr.get_entry_summaries.return_value = entries
        result, label = ctrl.fetch_recent('关键词')
        assert label == '近期更新'
        assert [e.title for e in result] == ['最新', '较新', '旧条目']

    def test_search_path_truncates_to_limit(self):
        """搜索路径条目数超过 RECENT_ENTRY_LIMIT 时内存截断到上限。"""
        from src.ui.controllers.entry_list_controller import RECENT_ENTRY_LIMIT
        ctrl = _entry_list_controller()
        entries = [
            SimpleNamespace(title=f'e{i:03d}', updated_at=f'2020-01-{(i % 28) + 1:02d}')
            for i in range(RECENT_ENTRY_LIMIT + 5)
        ]
        ctrl._entry_mgr.get_entry_summaries.return_value = entries
        result, _ = ctrl.fetch_recent('关键词')
        assert len(result) == RECENT_ENTRY_LIMIT
