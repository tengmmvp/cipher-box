"""ListRefreshController 的纯渲染辅助：空态解析与状态栏渲染。

两类无状态视图逻辑：

- :class:`EmptyStateResolver` 按优先级解析当前空态（7 种场景），消费冻结
  :class:`EmptyStateContext`（过滤态 + 总数 + 分析中标志 + 回调），不访问 controller 状态；
- :class:`StatusBarRenderer` 据四项安全计数渲染状态栏控件，消费冻结
  :class:`StatusBarView`（stats/status_bar/warning_label 控件）。

worker 生命周期刻意留在 controller，本模块仅依赖 PyQt6 控件与图标常量，零 controller 依赖。
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, NamedTuple

from ..resources.icons import (
    EMPTY_FOLDER,
    EMPTY_GENERIC,
    EMPTY_SEARCH,
    EMPTY_SUCCESS,
    EMPTY_TRASH,
    EMPTY_VAULT,
)

if TYPE_CHECKING:
    from PyQt6.QtWidgets import QLabel, QStatusBar

logger = logging.getLogger(__name__)


class EmptyStateSpec(NamedTuple):
    """空态解析结果：图标名、标题、副标题、操作按钮文案与点击回调（无操作时为 None）。"""

    icon_name: str
    title: str
    subtitle: str
    action_text: str
    action_slot: Callable[[], None] | None


@dataclass(frozen=True)
class EmptyStateContext:
    """空态解析的入参快照（controller 在展示空态时构造）。

    ``total_entries`` 由 controller 经 ``_cached_total_entries`` 缓存解析后传入，
    使 resolver 保持无 DB 访问的纯函数特性。``is_analyzing`` 为 security 分析是否
    仍在进行（缓存未就绪），供 weak/duplicate 区分「分析中」与「无结果」。
    """

    current_search: str
    current_filter: str
    current_category_id: int | None
    total_entries: int
    is_analyzing: bool
    on_clear_search: Callable[[], None]
    on_add_entry: Callable[[], None]


class EmptyStateResolver:
    """按优先级解析当前空态配置（7 种场景线性判断，首个命中即返回）。"""

    @staticmethod
    def resolve(context: EmptyStateContext) -> EmptyStateSpec:
        # 优先级：搜索 → 回收站 → 弱/重复（含分析中）→ 近期 → 分类 → 空库 → 兜底
        if context.current_search:
            return EmptyStateSpec(
                EMPTY_SEARCH,
                "没有找到匹配的条目",
                "尝试不同的搜索关键词",
                "清除搜索",
                context.on_clear_search,
            )
        filter_name = context.current_filter
        if filter_name == "trash":
            return EmptyStateSpec(
                EMPTY_TRASH,
                "回收站是空的",
                "删除的条目会出现在这里",
                "",
                None,
            )
        if filter_name in ("weak", "duplicate"):
            # 缓存未就绪时显示「分析中」，避免空列表被误读为「无弱/重复密码」
            if context.is_analyzing:
                label = "密码强度" if filter_name == "weak" else "重复密码"
                return EmptyStateSpec(
                    EMPTY_GENERIC,
                    f"正在分析{label}...",
                    "请稍候",
                    "",
                    None,
                )
            if filter_name == "weak":
                return EmptyStateSpec(
                    EMPTY_SUCCESS,
                    "没有发现弱密码",
                    "所有密码强度良好",
                    "",
                    None,
                )
            return EmptyStateSpec(
                EMPTY_SUCCESS,
                "没有重复密码",
                "所有密码都是唯一的",
                "",
                None,
            )
        if filter_name == "recent":
            return EmptyStateSpec(
                EMPTY_SUCCESS,
                "没有近期更新",
                "最近没有修改过条目",
                "",
                None,
            )
        if context.current_category_id is not None:
            return EmptyStateSpec(
                EMPTY_FOLDER,
                "该分类下暂无条目",
                "新增或编辑条目时可选择该分类",
                "",
                None,
            )
        # 默认/空库分支：total_entries 已由 controller 解析传入
        if context.total_entries == 0:
            return EmptyStateSpec(
                EMPTY_VAULT,
                "还没有密码条目",
                "点击工具栏「新增」按钮开始添加",
                "新增条目",
                context.on_add_entry,
            )
        return EmptyStateSpec(EMPTY_GENERIC, "暂无条目", "", "", None)


@dataclass(frozen=True)
class StatusBarView:
    """状态栏渲染所需的控件引用（controller view 的子集）。"""

    stats_label: QLabel
    status_bar: QStatusBar
    warning_label: QLabel


class StatusBarRenderer:
    """据四项安全计数渲染状态栏统计标签、状态栏消息与过期警告。"""

    @staticmethod
    def render(
        view: StatusBarView,
        total: int,
        weak: int,
        duplicate: int,
        old_count: int,
    ) -> None:
        try:
            view.stats_label.setText(f"共 {total} 项")
            parts = [f"总计 {total} 条"]
            if weak > 0:
                parts.append(f"弱密码 {weak}")
            if duplicate > 0:
                parts.append(f"重复 {duplicate}")
            view.status_bar.showMessage("  |  ".join(parts))
            # 密码过期警告：复用实例属性，避免 findChild
            warning_label = view.warning_label
            if old_count > 0:
                warning_label.setText(f"  {old_count} 个密码已过期  ")
                warning_label.show()
                if warning_label.parent() is not view.status_bar:
                    view.status_bar.addPermanentWidget(warning_label)
            else:
                warning_label.hide()
        except (ValueError, RuntimeError):
            logger.debug("状态栏安全分析失败", exc_info=True)
            view.status_bar.showMessage("安全分析暂时不可用")
