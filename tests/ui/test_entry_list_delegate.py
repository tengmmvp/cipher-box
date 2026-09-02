"""EntryItemDelegate.paint 离屏渲染冒烟测试（152 行核心视觉路径的零覆盖补齐）。

不构造真实 QListView：QPixmap 画布 + QPainter 直接调 ``paint``，断言不抛异常且
关键分支可触发。分支触达经 delegate 的颜色缓存键（``_color_cache``）作观测面——
强度圆点会请求 ``strength_N``、完整性警示请求 ``danger``、删除徽章请求
``danger_light``、选中态请求 ``accent_light``，各分支执行与否由缓存键的出现证明。
"""

import dataclasses

import pytest
from PyQt6.QtGui import QColor, QPainter, QPixmap
from PyQt6.QtWidgets import QStyle, QStyleOptionViewItem

from src.models import Entry
from src.ui.components.entry_list_widget import (
    FAVORITE_MARKER,
    EntryItemDelegate,
    EntryListModel,
)


def _entry(**overrides) -> Entry:
    """构造测试用明文摘要 Entry（默认 login + 有密码）。"""
    entry = Entry(
        title="站点",
        username="alice",
        url="https://example.com/path",
        category_name="工作",
        entry_type="login",
        password_strength=3,
        password_present=True,
    )
    return dataclasses.replace(entry, **overrides)


def _paint_one(delegate: EntryItemDelegate, entry: Entry, *, selected: bool, width=360) -> None:
    """在离屏 QPixmap 上对单个条目执行一次 delegate.paint。"""
    pixmap = QPixmap(width, EntryItemDelegate.ROW_HEIGHT)
    pixmap.fill(QColor(0, 0, 0, 0))
    option = QStyleOptionViewItem()
    option.rect = pixmap.rect()
    if selected:
        option.state = QStyle.StateFlag.State_Selected
    model = EntryListModel()
    model.set_entries([entry])
    painter = QPainter(pixmap)
    try:
        delegate.paint(painter, option, model.index(0, 0))
    finally:
        painter.end()


@pytest.fixture
def delegate(qapp):
    """每用例独立 delegate（颜色缓存作为分支观测面，须互不污染）。"""
    return EntryItemDelegate()


class TestPaintSmoke:
    """paint 各视觉分支：不抛异常 + 分支可触发（缓存键证明）。"""

    def test_plain_login_entry_paints_without_error(self, delegate):
        """普通条目（有密码 + 有用户名/分类/netloc 副标题）渲染不抛异常。"""
        _paint_one(delegate, _entry(), selected=False)
        assert "bg_card" in delegate._color_cache

    def test_strength_dot_branch_uses_strength_color(self, delegate):
        """password_present 的条目绘制强度圆点（请求 strength_3 颜色）。"""
        entry = _entry(password_strength=3)
        _paint_one(delegate, entry, selected=False)
        assert "strength_3" in delegate._color_cache

    def test_strength_clamped_to_token_range(self, delegate):
        """超范围强度（5）钳制到 strength_4 档，不抛异常。"""
        _paint_one(delegate, _entry(password_strength=5), selected=False)
        assert "strength_4" in delegate._color_cache

    def test_no_password_skips_strength_dot(self, delegate):
        """无密码条目（password_present=False）不绘制强度圆点（无 strength 键）。"""
        _paint_one(delegate, _entry(password_present=False, password_strength=0), selected=False)
        assert not any(key.startswith("strength_") for key in delegate._color_cache)

    def test_integrity_warning_branch_uses_danger(self, delegate):
        """integrity_error 条目绘制完整性警示符（请求 danger 颜色）。"""
        _paint_one(delegate, _entry(integrity_error=True), selected=False)
        assert "danger" in delegate._color_cache

    def test_deleted_badge_branch_uses_danger_light(self, delegate):
        """回收站条目绘制「已删除」徽章（请求 danger_light 底色）。"""
        _paint_one(delegate, _entry(is_deleted=True), selected=False)
        assert "danger_light" in delegate._color_cache

    def test_selected_state_uses_accent_light(self, delegate):
        """选中态用 accent_light 卡片底色 + accent 左侧高亮条。"""
        _paint_one(delegate, _entry(), selected=True)
        assert "accent_light" in delegate._color_cache
        assert "accent" in delegate._color_cache

    def test_favorite_marker_prefixed_in_title(self, delegate):
        """收藏条目标题带 ★ 前缀（FAVORITE_MARKER 与标题拼接，渲染不抛）。"""
        assert FAVORITE_MARKER == "★ "
        _paint_one(delegate, _entry(is_favorite=True), selected=False)

    def test_minimal_entry_paints_without_error(self, delegate):
        """空字段条目（无标题/无副标题素材）走「(无标题)/无额外信息」兜底，不抛。"""
        entry = Entry(password_present=False)
        _paint_one(delegate, entry, selected=False)

    def test_missing_entry_falls_back_to_parent_paint(self, delegate, qapp):
        """index 取不到 Entry（data 为 None）时回退父类绘制，不抛异常。"""
        pixmap = QPixmap(200, EntryItemDelegate.ROW_HEIGHT)
        option = QStyleOptionViewItem()
        option.rect = pixmap.rect()
        model = EntryListModel()  # 空模型：data() 返回 None
        painter = QPainter(pixmap)
        try:
            delegate.paint(painter, option, model.index(0, 0))
        finally:
            painter.end()

    def test_none_painter_is_early_return(self, delegate, qapp):
        """painter 为 None 时早退（Qt 信号形态防御），不抛异常。"""
        option = QStyleOptionViewItem()
        model = EntryListModel()
        model.set_entries([_entry()])
        delegate.paint(None, option, model.index(0, 0))

    def test_narrow_width_keeps_minimum_text_width(self, delegate):
        """极窄行宽触发 text_width 下限 40px 分支，不抛异常。"""
        _paint_one(delegate, _entry(), selected=False, width=12)


class TestColorFontCache:
    """paint 之外的缓存行为：颜色缓存清空与字体缓存复用。"""

    def test_clear_color_cache_empties(self, delegate):
        """clear_color_cache 清空颜色缓存（主题切换入口）。"""
        _paint_one(delegate, _entry(), selected=False)
        assert delegate._color_cache
        delegate.clear_color_cache()
        assert not delegate._color_cache

    def test_get_color_caches_qcolor(self, delegate):
        """_get_color 命中缓存返回同一 QColor 实例。"""
        first = delegate._get_color("bg_card")
        second = delegate._get_color("bg_card")
        assert first is second
        assert isinstance(first, QColor)

    def test_size_hint_row_height(self, delegate, qapp):
        """sizeHint 返回 ROW_HEIGHT 高度（委托行高的稳定契约）。"""
        from PyQt6.QtCore import QSize

        option = QStyleOptionViewItem()
        option.rect.setWidth(300)
        model = EntryListModel()
        model.set_entries([_entry()])
        hint = delegate.sizeHint(option, model.index(0, 0))
        assert hint.height() == EntryItemDelegate.ROW_HEIGHT
        assert isinstance(hint, QSize)
