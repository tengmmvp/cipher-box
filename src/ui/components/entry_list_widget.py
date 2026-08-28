"""条目列表的轻量委托绘制。

通过 QStyledItemDelegate 按需绘制条目卡片，避免为每条记录创建常驻 QWidget，
从而在大量条目下保持低内存占用与流畅滚动。绘制时缓存主题颜色与字体对象，
并在主题切换时清空颜色缓存以重新解析。
"""

from typing import Any

from PyQt6.QtCore import QAbstractItemModel, QModelIndex, QObject, QRectF, QSize, Qt
from PyQt6.QtGui import QColor, QFont, QPainter, QPen
from PyQt6.QtWidgets import QStyle, QStyledItemDelegate, QStyleOptionViewItem

from ...models import Entry
from ..resources.constants import FONT_FAMILY_FALLBACKS, FONT_FAMILY_PRIMARY
from ..resources.radius import RADIUS_CARD, RADIUS_TINY
from ..resources.strings import entry_type_icon
from ..resources.theme_colors import c

FAVORITE_MARKER = "★ "

# `paint` 行内垂直布局不变量（单位：像素）。
# 标题区域必须完整落在副标题区域之前，避免两段文本垂直重叠。
_TITLE_Y_OFFSET = 7  # 绘制基线 Y 偏移（相对 rect.top()）
_TITLE_HEIGHT = 22
# 副标题紧接标题区域之后留 1px 间隔，由前两个不变量派生，
# 改标题区几何时副标题自动跟随，杜绝两段文本重叠的回归。
_SUBTITLE_Y_OFFSET = _TITLE_Y_OFFSET + _TITLE_HEIGHT + 1
if _TITLE_Y_OFFSET + _TITLE_HEIGHT > _SUBTITLE_Y_OFFSET:
    raise RuntimeError("标题区域与副标题区域重叠：paint 垂直布局不变量被破坏")


def _resolve_font_family() -> str:
    """返回当前平台上第一个可用的字体族名称。

    惰性初始化：由 ``EntryItemDelegate`` 在实例属性 ``_resolved_family`` 中缓存，
    首次需要主字体时解析一次，之后所有绘制调用复用已解析的值。

    PyQt6 ≥ 6.5 不再支持 ``QFontDatabase()`` 构造，需使用静态方法 ``families()``。
    """
    from PyQt6.QtGui import QFontDatabase

    # PyQt6 ≥ 6.5: `families()` 为静态方法；Pyright 类型桩仍标注为实例方法，需忽略。
    available = QFontDatabase.families()  # pyright: ignore[reportCallIssue]
    if FONT_FAMILY_PRIMARY in available:
        return FONT_FAMILY_PRIMARY
    for fallback in FONT_FAMILY_FALLBACKS:
        if fallback in available:
            return fallback
    return available[0] if available else "sans-serif"


class EntryListModel(QAbstractItemModel):
    """条目列表数据模型，按需向 delegate 提供 ``Entry`` 摘要。

    ``set_entries`` 一次替换全部数据，``QListView`` 仅对可见行调用 ``data()``/``paint``，
    避免为每条目创建常驻 item 对象，降低大库下的内存占用与刷新开销。加密字段无法
    SQL 过滤需内存匹配，但 item 对象开销与逐项 ``setData`` 消除。
    """

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._entries: list[Entry] = []

    def set_entries(self, entries: list[Entry]) -> None:
        """整体替换条目数据，触发视图按需重绘。"""
        self.beginResetModel()
        self._entries = list(entries)
        self.endResetModel()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._entries)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: ARG002
        return 1

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or role != Qt.ItemDataRole.UserRole:
            return None
        row = index.row()
        if 0 <= row < len(self._entries):
            return self._entries[row]
        return None

    def index(self, row: int, column: int = 0, parent: QModelIndex = QModelIndex()) -> QModelIndex:
        if not self.hasIndex(row, column, parent):
            return QModelIndex()
        return self.createIndex(row, column)

    def parent(self, child: QModelIndex) -> QModelIndex:  # type: ignore[override]  # noqa: ARG002
        return QModelIndex()


class EntryItemDelegate(QStyledItemDelegate):
    """按需绘制条目卡片，避免为每条记录创建常驻 ``QWidget``。"""

    ROW_HEIGHT = 62
    # 布局常量，单位为像素
    CARD_PADDING_H = 4
    CARD_PADDING_V = 2
    CARD_RADIUS = RADIUS_CARD
    ACCENT_BAR_WIDTH = 3  # 选中时左侧高亮条宽度
    ICON_SIZE = 28
    ICON_OFFSET_X = 10
    ICON_OFFSET_Y = 13
    TEXT_LEFT_OFFSET = 48  # 图标区域之后的文本起始位置
    MARKER_RIGHT_MARGIN = 22  # 右侧强度/警示标记距右边距离
    DELETE_BADGE_WIDTH = 48
    DELETE_BADGE_HEIGHT = 20
    _TEXT_RIGHT_MARGIN = 38
    _DELETE_TEXT_RIGHT_EXTRA = 28  # 删除徽章额外保留宽度
    # `paint` 内行内垂直坐标偏移（相对 `rect.top()`）。
    # `_TITLE_Y_OFFSET` / `_TITLE_HEIGHT` / `_SUBTITLE_Y_OFFSET` 直接引用模块级不变量
    # 常量（模块加载时由 raise `RuntimeError` 校验几何关系），避免类属性复制的双份事实源。
    _SUBTITLE_HEIGHT = 19
    _MARKER_DOT_Y_OFFSET = 10  # 强度圆点 Y 偏移
    _MARKER_DOT_WIDTH = 12  # 强度圆点绘制区域宽度
    _MARKER_DOT_HEIGHT = 16  # 强度圆点绘制区域高度
    _MARKER_BANG_Y_OFFSET = 30  # 完整性警示符 Y 偏移
    _DELETE_BADGE_Y_OFFSET = 20  # 已删除徽章 Y 偏移
    _DELETE_BADGE_X_BACK = 9  # 已删除徽章距右侧标记的回退量

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        # 直接缓存 QColor 对象（PERF-071）：paint 每行约 8 次 QColor(hex) 构造
        # （实测 ~1.8µs/次），改缓存命中后省 ~13µs/行；QColor 为隐式共享值类型，
        # setPen/setBrush 按需拷贝，跨 paint 复用安全。主题切换经 clear_color_cache
        # 一并失效。
        self._color_cache: dict[str, QColor] = {}
        self._font_cache: dict[tuple, QFont] = {}
        # 实例级缓存的主字体族，惰性解析：避免模块级可变状态，提升可测试性。
        self._resolved_family: str | None = None

    def _get_font(self, family: str, size: int, weight: int = -1) -> QFont:
        """获取 ``QFont``，带缓存避免 ``paint()`` 重复创建。"""
        # 首次需要主字体时解析；用 `None` 标志避免解析结果恰为初始值时重复解析
        if family == FONT_FAMILY_PRIMARY:
            if self._resolved_family is None:
                self._resolved_family = _resolve_font_family()
            actual_family = self._resolved_family
        else:
            actual_family = family
        key = (actual_family, size, weight)
        font = self._font_cache.get(key)
        if font is None:
            font = QFont(actual_family, size, weight)
            self._font_cache[key] = font
        return font

    def _get_color(self, key: str) -> QColor:
        """获取主题颜色对应的 QColor，带缓存，主题切换时需清空。"""
        color = self._color_cache.get(key)
        if color is None:
            color = QColor(c(key))
            self._color_cache[key] = color
        return color

    def _get_strength_color(self, score: int) -> QColor:
        """获取密码强度圆点 QColor（strength_0..4），与 _get_color 共用缓存。"""
        return self._get_color(f"strength_{min(score, 4)}")

    def clear_color_cache(self) -> None:
        """清空颜色缓存，主题切换时调用。"""
        self._color_cache.clear()

    def sizeHint(self, option: QStyleOptionViewItem, index: QModelIndex) -> QSize:  # noqa: ARG002
        return QSize(option.rect.width(), self.ROW_HEIGHT)

    def paint(
        self,
        painter: QPainter | None,
        option: QStyleOptionViewItem,
        index: QModelIndex,
    ) -> None:
        """按需绘制单个条目卡片。

        重写 ``QStyledItemDelegate.paint``，在 ``painter`` 上一次性合成卡片：圆角
        背景与边框、选中态左侧高亮条、类型图标、标题（含收藏星标）与副标题（用户名
        /分类/netloc 拼接，均按可用宽度省略）、密码强度圆点、完整性警示符、已删除
        徽章。颜色经 ``_get_color`` 缓存为 ``QColor`` 对象（PERF-071，含强度色
        ``_get_strength_color``）、字体经 ``_get_font`` 缓存，避免每帧重建；
        行内垂直布局由模块级常量 ``_TITLE_Y_OFFSET`` 等守护，防止文本区域重叠。
        ``painter`` 为 ``None`` 或取不到 ``Entry`` 时回退父类绘制。
        """
        if painter is None:
            return
        entry = index.data(Qt.ItemDataRole.UserRole)
        if entry is None:
            super().paint(painter, option, index)
            return

        get_color = self._get_color
        get_strength_color = self._get_strength_color
        get_font = self._get_font

        painter.save()
        try:
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            rect = QRectF(
                option.rect.adjusted(
                    self.CARD_PADDING_H,
                    self.CARD_PADDING_V,
                    -self.CARD_PADDING_H,
                    -self.CARD_PADDING_V,
                )
            )
            selected = bool(option.state & QStyle.StateFlag.State_Selected)
            background = get_color("accent_light") if selected else get_color("bg_card")
            painter.setPen(QPen(get_color("border_light"), 1))
            painter.setBrush(background)
            painter.drawRoundedRect(rect, self.CARD_RADIUS, self.CARD_RADIUS)
            if selected:
                painter.fillRect(
                    QRectF(rect.left(), rect.top(), self.ACCENT_BAR_WIDTH, rect.height()),
                    get_color("accent"),
                )

            icon_rect = QRectF(
                rect.left() + self.ICON_OFFSET_X,
                rect.top() + self.ICON_OFFSET_Y,
                self.ICON_SIZE,
                self.ICON_SIZE,
            )
            painter.setPen(get_color("text_primary"))
            painter.setFont(get_font(FONT_FAMILY_PRIMARY, 15))
            # 类型图标占位符经 UI 展示查表（ARCH-037），login 回退由查表函数承载。
            painter.drawText(
                icon_rect, Qt.AlignmentFlag.AlignCenter, entry_type_icon(entry.entry_type)
            )

            text_left = rect.left() + self.TEXT_LEFT_OFFSET
            right_reserved = (
                self.DELETE_BADGE_WIDTH + self._DELETE_TEXT_RIGHT_EXTRA
                if entry.is_deleted
                else self._TEXT_RIGHT_MARGIN
            )
            text_width = max(40, rect.right() - text_left - right_reserved)
            title = entry.title or "(无标题)"
            if entry.is_favorite:
                title = f"{FAVORITE_MARKER}{title}"
            painter.setFont(get_font(FONT_FAMILY_PRIMARY, 11, QFont.Weight.DemiBold))
            painter.setPen(get_color("text_primary"))
            title_text = painter.fontMetrics().elidedText(
                title, Qt.TextElideMode.ElideRight, int(text_width)
            )
            painter.drawText(
                QRectF(text_left, rect.top() + _TITLE_Y_OFFSET, text_width, _TITLE_HEIGHT),
                Qt.AlignmentFlag.AlignVCenter,
                title_text,
            )

            subtitle_parts = []
            if entry.username:
                subtitle_parts.append(entry.username)
            if entry.category_name and entry.category_name != "未分类":
                subtitle_parts.append(entry.category_name)
            if entry.url:
                # 提取 netloc 并剥离 userinfo（user:pass@），避免凭据泄露到列表副标题
                netloc = entry.url.split("://", 1)[-1].split("/", 1)[0].split("@")[-1]
                subtitle_parts.append(netloc)
            subtitle = " · ".join(subtitle_parts) if subtitle_parts else "无额外信息"
            painter.setFont(get_font(FONT_FAMILY_PRIMARY, 10))
            painter.setPen(get_color("text_secondary"))
            subtitle_text = painter.fontMetrics().elidedText(
                subtitle, Qt.TextElideMode.ElideRight, int(text_width)
            )
            painter.drawText(
                QRectF(
                    text_left, rect.top() + _SUBTITLE_Y_OFFSET, text_width, self._SUBTITLE_HEIGHT
                ),
                Qt.AlignmentFlag.AlignVCenter,
                subtitle_text,
            )

            marker_x = rect.right() - self.MARKER_RIGHT_MARGIN
            if entry.password_present:
                painter.setPen(get_strength_color(entry.password_strength))
                painter.setFont(get_font(FONT_FAMILY_PRIMARY, 8))
                painter.drawText(
                    QRectF(
                        marker_x,
                        rect.top() + self._MARKER_DOT_Y_OFFSET,
                        self._MARKER_DOT_WIDTH,
                        self._MARKER_DOT_HEIGHT,
                    ),
                    Qt.AlignmentFlag.AlignCenter,
                    "●",
                )
            if entry.integrity_error:
                painter.setPen(get_color("danger"))
                painter.setFont(get_font(FONT_FAMILY_PRIMARY, 10, QFont.Weight.Bold))
                painter.drawText(
                    QRectF(
                        marker_x,
                        rect.top() + self._MARKER_BANG_Y_OFFSET,
                        self._MARKER_DOT_WIDTH,
                        self._MARKER_DOT_HEIGHT,
                    ),
                    Qt.AlignmentFlag.AlignCenter,
                    "!",
                )

            if entry.is_deleted:
                badge = QRectF(
                    rect.right()
                    - self.MARKER_RIGHT_MARGIN
                    - self.DELETE_BADGE_WIDTH
                    + self._DELETE_BADGE_X_BACK,
                    rect.top() + self._DELETE_BADGE_Y_OFFSET,
                    self.DELETE_BADGE_WIDTH,
                    self.DELETE_BADGE_HEIGHT,
                )
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(get_color("danger_light"))
                painter.drawRoundedRect(badge, RADIUS_TINY, RADIUS_TINY)
                painter.setPen(get_color("danger"))
                painter.setFont(get_font(FONT_FAMILY_PRIMARY, 7))
                painter.drawText(badge, Qt.AlignmentFlag.AlignCenter, "已删除")
        finally:
            painter.restore()
