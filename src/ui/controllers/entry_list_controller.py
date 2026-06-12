"""条目列表控制器 — 从 MainWindow 筛选逻辑中提取的纯数据操作

负责排序配置读取、条目排序、各过滤器数据获取及搜索/标签过滤。
不导入任何 PyQt6 控件，不操作 UI。
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable

from ..resources.constants import RECENT_ENTRY_LIMIT, SORT_OPTIONS

if TYPE_CHECKING:
    from ...business.managers.entry_manager import EntryManager
    from ...business.services.security_analyzer import SecurityAnalyzer
    from ...config import ConfigManager

# 排序选项来自共享常量，作为单一事实来源
_SORT_OPTIONS = SORT_OPTIONS


class EntryListController:
    """条目列表的纯数据逻辑控制器。

    通过构造函数注入 ``entry_manager`` 和 ``config``，
    不持有任何 UI 控件引用。
    """

    def __init__(
        self,
        entry_manager: EntryManager,
        security: SecurityAnalyzer,
        config: ConfigManager,
    ):
        self._entry_mgr = entry_manager
        self._security = security
        self._config = config

    # ========== 排序 ==========

    def get_sort_config(self, sort_index: int) -> tuple[str, str]:
        """根据排序下拉框索引返回 (field, order)。

        Args:
            sort_index: 排序下拉框 ``QComboBox.currentIndex()`` 的值。
        """
        if 0 <= sort_index < len(_SORT_OPTIONS):
            _, field, order = _SORT_OPTIONS[sort_index]
            return field, order
        return 'updated_at', 'desc'

    def get_sort_config_from_config(self) -> tuple[str, str]:
        """直接从配置中读取排序字段和方向。"""
        return (
            self._config.get('sort_field', 'updated_at'),
            self._config.get('sort_order', 'desc'),
        )

    def sort_entries(self, entries: list, sort_index: int) -> list:
        """对条目列表排序。

        Args:
            entries: 待排序条目列表。
            sort_index: 排序下拉框当前索引。
        """
        field, order = self.get_sort_config(sort_index)

        def sort_key(e):
            if field == 'title':
                return (e.title or '').lower()
            elif field == 'password_strength':
                return e.password_strength
            elif field == 'created_at':
                return e.created_at or ''
            else:  # updated_at
                return e.updated_at or ''

        reverse = (order == 'desc')
        return sorted(entries, key=sort_key, reverse=reverse)

    # ========== 过滤器数据获取 ==========

    def fetch_all(
        self,
        category_id: int | None,
        search: str,
    ) -> tuple[list, str]:
        """获取全部条目，可按分类和搜索过滤。"""
        return self._entry_mgr.get_entry_summaries(
            category_id=category_id,
            search=search,
        ), '全部条目'

    def fetch_favorite(self, search: str) -> tuple[list, str]:
        """获取收藏条目。"""
        return (
            self._entry_mgr.get_entry_summaries(favorite_only=True, search=search),
            '收藏',
        )

    def fetch_weak(self) -> tuple[list, str]:
        """获取弱密码条目。"""
        summary = self.get_security_summary()
        return (summary or {}).get('weak_entries', []), '弱密码（全部分类）'

    def fetch_duplicate(self) -> tuple[list, str]:
        """获取重复密码条目。"""
        summary = self.get_security_summary()
        groups = (summary or {}).get('duplicate_groups', [])
        return [e for group in groups for e in group], '重复密码（全部分类）'

    def fetch_recent(self, search: str) -> tuple[list, str]:
        """获取近期更新条目。

        search 为空时，limit 直接在 SQL 层截断，高效取最近 N 条。
        search 非空时，必须先全量查询（get_entry_summaries 已不下推 limit），
        再按 updated_at 排序后截断，否则「先 SQL 截断再内存过滤」会使
        近期+搜索的命中数远少于实际匹配数。
        """
        entries = self._entry_mgr.get_entry_summaries(
            search=search, limit=RECENT_ENTRY_LIMIT,
        )
        entries.sort(key=lambda e: e.updated_at or '', reverse=True)
        if search:
            entries = entries[:RECENT_ENTRY_LIMIT]
        return entries, '近期更新'

    def fetch_trash(self, search: str) -> tuple[list, str]:
        """获取回收站条目。"""
        return (
            self._entry_mgr.get_entry_summaries(deleted_only=True, search=search),
            '回收站',
        )

    def get_fetcher(self, filter_key: str) -> Callable[..., tuple[list, str]]:
        """获取过滤器对应的数据获取方法。"""
        fetchers: dict[str, Callable[..., tuple[list, str]]] = {
            'all': self.fetch_all,
            'favorite': self.fetch_favorite,
            'weak': self.fetch_weak,
            'duplicate': self.fetch_duplicate,
            'recent': self.fetch_recent,
            'trash': self.fetch_trash,
        }
        return fetchers.get(filter_key, self.fetch_all)

    # ========== 搜索与标签过滤 ==========

    @staticmethod
    def filter_by_search(entries: list, search: str) -> list:
        """在弱密码/重复密码过滤器中对结果施加搜索过滤。"""
        from ...business.managers.entry_manager import EntryManager
        return [e for e in entries if EntryManager.matches_search(e, search)]

    @staticmethod
    def filter_by_tag(entries: list, tag: str) -> list:
        """按标签过滤条目。"""
        from ...business.managers.entry_manager import EntryManager
        return [e for e in entries if EntryManager.matches_tag(e, tag)]

    # ========== 安全摘要 ==========

    def get_security_summary(self) -> dict | None:
        """返回缓存的安全分析结果，不触发同步计算。

        当缓存未就绪时返回 None，调用方应处理此情况。
        """
        return self._security.get_cached_report(
            self._config.get('old_password_warning_days', 90)
        )
