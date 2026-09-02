"""list_refresh_helpers 纯渲染辅助测试：空态解析与状态栏渲染。

EmptyStateResolver 为无 Qt 控件依赖的纯函数（7 场景优先级），直接断言解析
结果；StatusBarRenderer 消费真实 QLabel/QStatusBar（离屏）断言渲染文案与
过期警告显隐。
"""

import pytest
from PyQt6.QtWidgets import QLabel, QStatusBar

from src.ui.controllers.list_refresh_helpers import (
    EmptyStateContext,
    EmptyStateResolver,
    StatusBarRenderer,
    StatusBarView,
)


def _context(**overrides) -> EmptyStateContext:
    """构造空态解析入参，默认「无搜索 + all 过滤 + 空库」。"""
    base = dict(
        current_search="",
        current_filter="all",
        current_category_id=None,
        total_entries=0,
        is_analyzing=False,
        on_clear_search=lambda: None,
        on_add_entry=lambda: None,
    )
    return EmptyStateContext(**{**base, **overrides})


class TestEmptyStateResolver:
    """7 种空态场景的优先级解析。"""

    def test_search_miss_highest_priority(self):
        """搜索无结果优先级最高（即便同时在回收站/空库场景）。"""
        spec = EmptyStateResolver.resolve(
            _context(current_search="kw", current_filter="trash", total_entries=0)
        )
        assert spec.title == "没有找到匹配的条目"
        assert spec.action_text == "清除搜索"

    def test_trash_empty(self):
        """回收站空态（无操作按钮）。"""
        spec = EmptyStateResolver.resolve(_context(current_filter="trash"))
        assert spec.title == "回收站是空的"
        assert spec.action_slot is None

    def test_weak_analyzing(self):
        """弱密码视图分析中显示「正在分析」（缓存未就绪与无结果的区分）。"""
        spec = EmptyStateResolver.resolve(_context(current_filter="weak", is_analyzing=True))
        assert spec.title == "正在分析密码强度..."

    def test_duplicate_analyzing(self):
        """重复密码视图分析中文案。"""
        spec = EmptyStateResolver.resolve(_context(current_filter="duplicate", is_analyzing=True))
        assert spec.title == "正在分析重复密码..."

    def test_weak_all_good(self):
        """弱密码视图无结果（分析完成）。"""
        spec = EmptyStateResolver.resolve(_context(current_filter="weak"))
        assert spec.title == "没有发现弱密码"

    def test_duplicate_all_good(self):
        """重复密码视图无结果（分析完成）。"""
        spec = EmptyStateResolver.resolve(_context(current_filter="duplicate"))
        assert spec.title == "没有重复密码"

    def test_recent_empty(self):
        """近期更新空态。"""
        spec = EmptyStateResolver.resolve(_context(current_filter="recent"))
        assert spec.title == "没有近期更新"

    def test_category_empty(self):
        """分类下无条目。"""
        spec = EmptyStateResolver.resolve(_context(current_category_id=7, total_entries=5))
        assert spec.title == "该分类下暂无条目"

    def test_empty_vault_with_add_action(self):
        """空库场景携带「新增条目」操作与注册的回调。"""
        called = []
        ctx = _context(total_entries=0, on_add_entry=lambda: called.append(1))
        spec = EmptyStateResolver.resolve(ctx)
        assert spec.title == "还没有密码条目"
        assert spec.action_text == "新增条目"
        assert spec.action_slot is ctx.on_add_entry
        spec.action_slot()
        assert called == [1]

    def test_fallback_generic_when_entries_exist(self):
        """非空库但当前视图无条的兜底空态（无操作）。"""
        spec = EmptyStateResolver.resolve(_context(total_entries=10))
        assert spec.title == "暂无条目"
        assert spec.action_slot is None

    def test_spec_is_immutable_snapshot(self):
        """解析结果为不可变 NamedTuple 快照。"""
        spec = EmptyStateResolver.resolve(_context())
        with pytest.raises(AttributeError):
            spec.title = "x"  # type: ignore[misc]

    def test_context_frozen(self):
        """入参快照冻结（防调用方解析后原地改参造成解析结果漂移）。"""
        ctx = _context()
        with pytest.raises(AttributeError):
            ctx.current_filter = "trash"  # type: ignore[misc]


class TestStatusBarRenderer:
    """状态栏四项安全计数渲染。"""

    def _view(self, qapp):
        stats = QLabel()
        status_bar = QStatusBar()
        warning = QLabel()
        return StatusBarView(stats_label=stats, status_bar=status_bar, warning_label=warning), (
            stats,
            status_bar,
            warning,
        )

    def test_renders_counts_and_parts(self, qapp):
        """总数进统计标签；weak/duplicate>0 拼进状态栏消息。"""
        view, (stats, status_bar, _warning) = self._view(qapp)
        StatusBarRenderer.render(view, total=5, weak=2, duplicate=1, old_count=0)
        assert stats.text() == "共 5 项"
        assert status_bar.currentMessage() == "总计 5 条  |  弱密码 2  |  重复 1"

    def test_zero_risks_omitted_from_message(self, qapp):
        """weak/duplicate 为 0 时不拼接对应段。"""
        view, (_stats, status_bar, _warning) = self._view(qapp)
        StatusBarRenderer.render(view, total=3, weak=0, duplicate=0, old_count=0)
        assert status_bar.currentMessage() == "总计 3 条"

    def test_old_warning_shown_when_nonzero(self, qapp):
        """过期计数 >0 显示警告标签并挂为状态栏永久控件。"""
        view, (_stats, _status_bar, warning) = self._view(qapp)
        StatusBarRenderer.render(view, total=3, weak=0, duplicate=0, old_count=4)
        assert warning.isVisible() or not warning.isHidden()  # show() 已调用
        assert "4 个密码已过期" in warning.text()

    def test_old_warning_hidden_when_zero(self, qapp):
        """过期计数为 0 隐藏警告标签。"""
        view, (_stats, _status_bar, warning) = self._view(qapp)
        warning.show()
        StatusBarRenderer.render(view, total=3, weak=0, duplicate=0, old_count=0)
        assert warning.isHidden()

    def test_renderer_failure_falls_back_to_message(self, qapp, monkeypatch):
        """渲染异常（控件已销毁等 ValueError/RuntimeError）降级为固定提示。"""
        view, (_stats, status_bar, _warning) = self._view(qapp)

        def _boom(*_args, **_kwargs):
            raise RuntimeError("widget destroyed")

        monkeypatch.setattr(QLabel, "setText", _boom)
        StatusBarRenderer.render(view, total=1, weak=0, duplicate=0, old_count=0)
        assert status_bar.currentMessage() == "安全分析暂时不可用"
