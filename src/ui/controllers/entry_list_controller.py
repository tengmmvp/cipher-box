"""条目列表控制器 — 从 MainWindow 筛选逻辑中提取的纯数据操作。

负责排序配置读取、条目排序、各过滤器数据获取及搜索/标签过滤。
不导入任何 PyQt6 控件，不操作 UI。
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from ...business.services.crypto_utils import matches_search, matches_tag
from ..resources.constants import RECENT_ENTRY_LIMIT, SORT_OPTIONS

if TYPE_CHECKING:
    from ...business.managers.entry_manager import EntryManager
    from ...business.services.security_analyzer import SecurityAnalyzer, SecurityReport
    from ...config import ConfigManager
    from ...models import Entry


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
    ) -> None:
        self._entry_mgr = entry_manager
        self._security = security
        self._config = config

    # ========== 排序 ==========

    def get_sort_config(self, sort_index: int) -> tuple[str, str]:
        """根据排序下拉框索引返回排序字段与方向。

        Args:
            sort_index: 排序下拉框 ``QComboBox.currentIndex()`` 的值。
        """
        if 0 <= sort_index < len(SORT_OPTIONS):
            _, field, order = SORT_OPTIONS[sort_index]
            return field, order
        return 'updated_at', 'desc'

    def sort_entries(self, entries: list[Entry], sort_index: int) -> list[Entry]:
        """对条目列表排序。

        Args:
            entries: 待排序条目列表。
            sort_index: 排序下拉框当前索引。
        """
        field, order = self.get_sort_config(sort_index)

        def sort_key(e: Entry) -> Any:
            if field == 'title':
                return (e.title or '').lower()
            elif field == 'password_strength':
                # password_strength 可能为 None（未评估），统一回退 0，
                # 避免与 int 混排时 Python3 抛 TypeError。
                return e.password_strength or 0
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
        cancel_check: Callable[[], bool] | None = None,
    ) -> tuple[list[Entry], str]:
        """获取全部条目，可按分类和搜索过滤。"""
        return self._entry_mgr.get_entry_summaries(
            category_id=category_id,
            search=search,
            cancel_check=cancel_check,
        ), '全部条目'

    def fetch_favorite(
        self,
        search: str,
        cancel_check: Callable[[], bool] | None = None,
    ) -> tuple[list[Entry], str]:
        """获取收藏条目。"""
        return (
            self._entry_mgr.get_entry_summaries(
                favorite_only=True, search=search, cancel_check=cancel_check,
            ),
            '收藏',
        )

    def fetch_weak(self, cancel_check: Callable[[], bool] | None = None) -> tuple[list[Entry], str]:
        """获取弱密码条目。

        ``cancel_check`` 仅为与其余 fetcher 统一签名而保留（弱密码来自已缓存的安全
        摘要，无长循环可取消），当前忽略，消除异步入口放宽时抛 TypeError 的隐患。
        """
        del cancel_check  # 签名对齐，无实际用途
        summary = self.get_security_summary()
        weak = summary['weak_entries'] if summary is not None else []
        return weak, '弱密码（全部分类）'

    def fetch_duplicate(self, cancel_check: Callable[[], bool] | None = None) -> tuple[list[Entry], str]:
        """获取重复密码条目（``cancel_check`` 同 fetch_weak，仅签名对齐）。"""
        del cancel_check
        summary = self.get_security_summary()
        groups = summary['duplicate_groups'] if summary is not None else []
        return [e for group in groups for e in group], '重复密码（全部分类）'

    def fetch_recent(
        self,
        search: str,
        cancel_check: Callable[[], bool] | None = None,
    ) -> tuple[list[Entry], str]:
        """获取近期更新条目，按 updated_at 降序取最近 N 条。

        无搜索时下推 ORDER BY updated_at DESC LIMIT 到 SQL（经
        ``get_recent_summaries``），避免拉全量内存排序再截断的全量解密开销；
        有搜索时因加密字段无法 SQL 过滤，仍需全量解密后内存过滤、排序再截断。
        """
        if search:
            entries = self._entry_mgr.get_entry_summaries(
                search=search, cancel_check=cancel_check,
            )
            entries.sort(key=lambda e: e.updated_at or '', reverse=True)
            entries = entries[:RECENT_ENTRY_LIMIT]
        else:
            entries = self._entry_mgr.get_recent_summaries(limit=RECENT_ENTRY_LIMIT)
        return entries, '近期更新'

    def fetch_trash(
        self,
        search: str,
        cancel_check: Callable[[], bool] | None = None,
    ) -> tuple[list[Entry], str]:
        """获取回收站条目。"""
        return (
            self._entry_mgr.get_entry_summaries(
                deleted_only=True, search=search, cancel_check=cancel_check,
            ),
            '回收站',
        )

    def get_fetcher(self, filter_key: str) -> Callable[..., tuple[list[Entry], str]]:
        """获取过滤器对应的数据获取方法。"""
        fetchers: dict[str, Callable[..., tuple[list[Entry], str]]] = {
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
    def filter_by_search(entries: list[Entry], search: str) -> list[Entry]:
        """在弱密码/重复密码过滤器中对结果施加搜索过滤。"""
        return [e for e in entries if matches_search(e, search)]

    @staticmethod
    def filter_by_tag(entries: list[Entry], tag: str) -> list[Entry]:
        """按标签过滤条目。"""
        return [e for e in entries if matches_tag(e, tag)]

    # ========== 安全摘要 ==========

    def get_security_summary(self) -> SecurityReport | None:
        """返回缓存的安全分析结果，不触发同步计算。

        当缓存未就绪时返回 None，调用方应处理此情况。
        """
        return self._security.get_cached_report(
            self._config.get('old_password_warning_days')
        )
