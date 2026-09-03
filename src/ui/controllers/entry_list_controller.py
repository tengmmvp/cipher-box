"""条目列表控制器：纯数据操作。

负责排序配置读取、各过滤器数据获取及搜索/标签过滤，
不导入任何 PyQt6 控件、不操作 UI。
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from ...business.services.entry_search_match import matches_search, matches_tag
from ...config import CFG_OLD_PASSWORD_WARNING_DAYS
from ..resources.constants import (
    MAX_SEARCH_RESULTS_DISPLAY,
    RECENT_ENTRY_LIMIT,
    SORT_OPTIONS,
)

if TYPE_CHECKING:
    from ...business.managers.entry_manager import EntryManager
    from ...business.services.security_analyzer import SecurityAnalyzer, SecurityReport
    from ...config import ConfigManager
    from ...models import Entry


class EntryListController:
    """条目列表的纯数据逻辑控制器，不持有任何 UI 控件引用。"""

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
    # UI 侧无独立重排路径（QL-074）：列表排序统一由 manager 分流（SQL 字段序下推
    # 或 PERF-078 内存路径），本控制器只提供排序配置读取（get_sort_config）。

    def get_sort_config(self, sort_index: int) -> tuple[str, str]:
        """根据排序下拉框索引返回排序字段与方向。

        Args:
            sort_index: 排序下拉框 ``QComboBox.currentIndex()`` 的值。
        """
        if 0 <= sort_index < len(SORT_OPTIONS):
            _, field, order = SORT_OPTIONS[sort_index]
            return field, order
        return "updated_at", "desc"

    # ========== 过滤器数据获取 ==========

    def fetch_all(
        self,
        category_id: int | None,
        search: str,
        cancel_check: Callable[[], bool] | None = None,
        *,
        sort_index: int = 0,
    ) -> tuple[list[Entry], str]:
        """获取全部条目，可按分类和搜索过滤。

        PERF-066/073/078：统一传渲染上限（MAX_SEARCH_RESULTS_DISPLAY）与用户所选
        排序，由 manager 分流——SQL 白名单字段 + 无搜索经 ``ORDER BY 字段 LIMIT``
        下推（50k 温态实测 1.8-3s → ~50-70ms）；标题序（密文列不可 SQL 排序）与
        搜索路径走「窄投影全量 → 内存 meta 排序 → 仅前 limit 回查宽行」（标题序
        50k 实测 ~1750 → ~300ms，宽搜索词命中回查不再全量）。UI 渲染本就截断到
        该上限（``_apply_entry_results``），三条路径的截断集合均=排序序前 N。

        已知取舍：标签过滤在 UI 侧后置施加（业务层 EntryQuery 无 tag 参数），截断后
        的标签子集可能漏掉索引序上限之外的命中——与渲染截断同级的损失面；库内总数
        语义由状态栏/侧边栏/空态的独立 COUNT 保持，不依赖本列表长度。
        """
        field, order = self.get_sort_config(sort_index)
        return self._entry_mgr.get_entry_summaries(
            category_id=category_id,
            search=search,
            cancel_check=cancel_check,
            limit=MAX_SEARCH_RESULTS_DISPLAY,
            order_by=field,
            order_desc=(order == "desc"),
        ), "全部条目"

    def fetch_favorite(
        self,
        search: str,
        cancel_check: Callable[[], bool] | None = None,
        *,
        sort_index: int = 0,
    ) -> tuple[list[Entry], str]:
        """获取收藏条目，可按搜索过滤。

        统一传 limit+order_by 由 manager 分流（PERF-078，对齐 fetch_all）：50k 库
        （22.5k 收藏）冷 1409ms → 与 fetch_all 同级；标题序/搜索路径同样走内存
        meta 排序 + 前 N 回查。
        """
        field, order = self.get_sort_config(sort_index)
        return (
            self._entry_mgr.get_entry_summaries(
                favorite_only=True,
                search=search,
                cancel_check=cancel_check,
                limit=MAX_SEARCH_RESULTS_DISPLAY,
                order_by=field,
                order_desc=(order == "desc"),
            ),
            "收藏",
        )

    def fetch_weak(self, cancel_check: Callable[[], bool] | None = None) -> tuple[list[Entry], str]:
        """获取弱密码条目。

        ``cancel_check`` 仅为与其余 fetcher 统一签名而保留（弱密码来自已缓存的安全
        摘要，无长循环可取消），当前忽略，消除异步入口放宽时抛 TypeError 的隐患。
        """
        del cancel_check  # 签名对齐，无实际用途
        summary = self.get_security_summary()
        weak = summary["weak_entries"] if summary is not None else []
        return weak, "弱密码（全部分类）"

    def fetch_duplicate(
        self, cancel_check: Callable[[], bool] | None = None
    ) -> tuple[list[Entry], str]:
        """获取重复密码条目（``cancel_check`` 同 fetch_weak，仅签名对齐）。"""
        del cancel_check
        summary = self.get_security_summary()
        groups = summary["duplicate_groups"] if summary is not None else []
        return [e for group in groups for e in group], "重复密码（全部分类）"

    def fetch_recent(
        self,
        search: str,
        cancel_check: Callable[[], bool] | None = None,
        *,
        sort_index: int = 0,
    ) -> tuple[list[Entry], str]:
        """获取近期更新条目，按 updated_at 降序取最近 N 条。

        无搜索时下推 ORDER BY updated_at DESC LIMIT 到 SQL（经
        ``get_recent_summaries``）；有搜索时同样传 limit+排序由 manager 走
        PERF-078 内存路径（窄投影全量匹配 → meta 排序 → 仅前 N 回查宽行），
        与原「全量回查+UI 内存 sort+截断」同构而免全量物化（PERF-081）。

        ``sort_index`` 仅为与 fetch_all/fetch_favorite/fetch_trash 统一调用签名而
        保留（PERF-072）：本视图固定 updated_at↓ 序、不参与排序切换，忽略该值。
        """
        del sort_index  # 签名对齐，本视图固定排序
        if search:
            entries = self._entry_mgr.get_entry_summaries(
                search=search,
                cancel_check=cancel_check,
                limit=RECENT_ENTRY_LIMIT,
                order_by="updated_at",
                order_desc=True,
            )
        else:
            entries = self._entry_mgr.get_recent_summaries(limit=RECENT_ENTRY_LIMIT)
        return entries, "近期更新"

    def fetch_trash(
        self,
        search: str,
        cancel_check: Callable[[], bool] | None = None,
        *,
        sort_index: int = 0,
    ) -> tuple[list[Entry], str]:
        """获取回收站条目（已软删除），可按搜索过滤。

        统一传 limit+order_by 由 manager 分流（PERF-078，对齐 fetch_all/
        fetch_favorite）。与 fetch_all 同为**近似**等价：回收站条目保留
        is_favorite（软删除不清收藏），复合序下收藏优先的取舍面与 fetch_all
        一致；字段序下推后截断严格按所选排序，无此取舍。
        """
        field, order = self.get_sort_config(sort_index)
        return (
            self._entry_mgr.get_entry_summaries(
                deleted_only=True,
                search=search,
                cancel_check=cancel_check,
                limit=MAX_SEARCH_RESULTS_DISPLAY,
                order_by=field,
                order_desc=(order == "desc"),
            ),
            "回收站",
        )

    def get_fetcher(self, filter_key: str) -> Callable[..., tuple[list[Entry], str]]:
        """按过滤器键返回对应的 fetcher，未知键回退 fetch_all。"""
        fetchers: dict[str, Callable[..., tuple[list[Entry], str]]] = {
            "all": self.fetch_all,
            "favorite": self.fetch_favorite,
            "weak": self.fetch_weak,
            "duplicate": self.fetch_duplicate,
            "recent": self.fetch_recent,
            "trash": self.fetch_trash,
        }
        return fetchers.get(filter_key, self.fetch_all)

    # ========== 搜索与标签过滤 ==========

    @staticmethod
    def filter_by_search(entries: list[Entry], search: str) -> list[Entry]:
        """在弱密码/重复密码过滤器中对结果施加搜索过滤。"""
        return [e for e in entries if matches_search(e, search)]

    @staticmethod
    def filter_by_tag(entries: list[Entry], tag: str) -> list[Entry]:
        """对条目列表施加标签过滤，与 filter_by_search 对称。"""
        return [e for e in entries if matches_tag(e, tag)]

    # ========== 安全摘要 ==========

    def get_security_summary(self) -> SecurityReport | None:
        """返回缓存的安全分析结果，不触发同步计算。

        当缓存未就绪时返回 None，调用方应处理此情况。
        """
        return self._security.get_cached_report(self._config.get(CFG_OLD_PASSWORD_WARNING_DAYS))
