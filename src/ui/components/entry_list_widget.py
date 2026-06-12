"""条目列表的轻量委托绘制。

通过 QStyledItemDelegate 按需绘制条目卡片，避免为每条记录创建常驻 QWidget，
从而在大量条目下保持低内存占用与流畅滚动。绘制时缓存主题颜色与字体对象，
并在主题切换时清空颜色缓存以重新解析。
"""

from PyQt6.QtCore import QModelIndex, QRectF, QSize, Qt
from PyQt6.QtGui import QColor, QFont, QPainter, QPen
from PyQt6.QtWidgets import QStyle, QStyledItemDelegate, QStyleOptionViewItem

from ...models import ENTRY_TYPE_LOGIN, ENTRY_TYPES
from ..resources.constants import FONT_FAMILY_FALLBACKS, FONT_FAMILY_PRIMARY
from ..resources.theme_colors import c, get_strength_color

# 收藏标记字符
FAVORITE_MARKER = '★ '


def _resolve_font_family() -> str:
    """返回当前平台上第一个可用的字体族名称。

    模块级惰性初始化：_RESOLVED_FONT_FAMILY 在首次 paint 时解析一次，
    之后所有绘制调用复用已解析的值。

    PyQt6 ≥ 6.5 不再支持 QFontDatabase() 构造，需使用静态方法 families()。
    """
    from PyQt6.QtGui import QFontDatabase
    # PyQt6 ≥ 6.5: families() 为静态方法，无需构造 QFontDatabase 实例。
    # Pyright 类型桩仍将其标注为实例方法，需忽略。
    available = QFontDatabase.families()  # pyright: ignore[reportCallIssue]
    if FONT_FAMILY_PRIMARY in available:
        return FONT_FAMILY_PRIMARY
    for fallback in FONT_FAMILY_FALLBACKS:
        if fallback in available:
            return fallback
    return available[0] if available else 'sans-serif'

_RESOLVED_FONT_FAMILY: str | None = None  # 延迟解析，首次 paint 时确定


class EntryItemDelegate(QStyledItemDelegate):
    """按需绘制条目卡片，避免为每条记录创建常驻 QWidget。"""

    ROW_HEIGHT = 62
    # 布局常量，单位为像素
    CARD_PADDING_H = 4       # 卡片水平内边距
    CARD_PADDING_V = 2       # 卡片垂直内边距
    CARD_RADIUS = 7          # 卡片圆角
    ACCENT_BAR_WIDTH = 3     # 选中时左侧高亮条宽度
    ICON_SIZE = 28           # 类型图标尺寸
    ICON_OFFSET_X = 10       # 图标距左边距离
    ICON_OFFSET_Y = 13       # 图标距顶部距离
    TEXT_LEFT_OFFSET = 48    # 文本起始水平位置，图标区域之后
    MARKER_RIGHT_MARGIN = 22 # 右侧标记距离右边距离
    DELETE_BADGE_WIDTH = 48  # "已删除"徽章宽度
    DELETE_BADGE_HEIGHT = 20
    _TEXT_RIGHT_MARGIN = 38           # 文本区域右侧保留宽度
    _DELETE_TEXT_RIGHT_EXTRA = 28     # 删除徽章额外保留宽度

    def __init__(self, parent=None):
        super().__init__(parent)
        self._color_cache: dict[str, str] = {}
        self._font_cache: dict[tuple, QFont] = {}

    def _get_font(self, family: str, size: int, weight: int = -1) -> QFont:
        """获取 QFont，带缓存避免 paint() 重复创建。"""
        global _RESOLVED_FONT_FAMILY
        # 首次需要主字体时解析；用 None 标志避免解析结果恰为初始值时重复解析
        if family == FONT_FAMILY_PRIMARY:
            if _RESOLVED_FONT_FAMILY is None:
                _RESOLVED_FONT_FAMILY = _resolve_font_family()
            actual_family = _RESOLVED_FONT_FAMILY
        else:
            actual_family = family
        key = (actual_family, size, weight)
        font = self._font_cache.get(key)
        if font is None:
            font = QFont(actual_family, size, weight)
            self._font_cache[key] = font
        return font

    def _get_color(self, key: str) -> str:
        """获取主题颜色，带缓存，主题切换时需清空。"""
        if key not in self._color_cache:
            self._color_cache[key] = c(key)
        return self._color_cache[key]

    def clear_color_cache(self):
        """清空颜色缓存，主题切换时调用。"""
        self._color_cache.clear()

    def sizeHint(self, option, index):
        return QSize(option.rect.width(), self.ROW_HEIGHT)

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index: QModelIndex):  # pyright: ignore[reportIncompatibleMethodOverride]
        entry = index.data(Qt.ItemDataRole.UserRole)
        if entry is None:
            super().paint(painter, option, index)
            return

        get_color = self._get_color
        get_font = self._get_font

        painter.save()
        try:
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            rect = QRectF(option.rect.adjusted(self.CARD_PADDING_H, self.CARD_PADDING_V,
                                               -self.CARD_PADDING_H, -self.CARD_PADDING_V))
            selected = bool(option.state & QStyle.StateFlag.State_Selected)
            background = get_color('accent_light') if selected else get_color('bg_card')
            painter.setPen(QPen(QColor(get_color('border_light')), 1))
            painter.setBrush(QColor(background))
            painter.drawRoundedRect(rect, self.CARD_RADIUS, self.CARD_RADIUS)
            if selected:
                painter.fillRect(
                    QRectF(rect.left(), rect.top(), self.ACCENT_BAR_WIDTH, rect.height()),
                    QColor(get_color('accent')),
                )

            icon_rect = QRectF(rect.left() + self.ICON_OFFSET_X, rect.top() + self.ICON_OFFSET_Y,
                               self.ICON_SIZE, self.ICON_SIZE)
            painter.setPen(QColor(get_color('text_primary')))
            painter.setFont(get_font(FONT_FAMILY_PRIMARY, 15))
            type_info = ENTRY_TYPES.get(
                entry.entry_type, ENTRY_TYPES[ENTRY_TYPE_LOGIN]
            )
            painter.drawText(icon_rect, Qt.AlignmentFlag.AlignCenter, type_info['icon'])

            text_left = rect.left() + self.TEXT_LEFT_OFFSET
            right_reserved = self.DELETE_BADGE_WIDTH + self._DELETE_TEXT_RIGHT_EXTRA if entry.is_deleted else self._TEXT_RIGHT_MARGIN
            text_width = max(40, rect.right() - text_left - right_reserved)
            title = entry.title or '(无标题)'
            if entry.is_favorite:
                title = f'{FAVORITE_MARKER}{title}'
            painter.setFont(get_font(FONT_FAMILY_PRIMARY, 10, QFont.Weight.DemiBold))
            painter.setPen(QColor(get_color('text_primary')))
            title_text = painter.fontMetrics().elidedText(
                title, Qt.TextElideMode.ElideRight, int(text_width)
            )
            painter.drawText(
                QRectF(text_left, rect.top() + 7, text_width, 22),
                Qt.AlignmentFlag.AlignVCenter,
                title_text,
            )

            subtitle_parts = []
            if entry.username:
                subtitle_parts.append(entry.username)
            if entry.category_name and entry.category_name != '未分类':
                subtitle_parts.append(entry.category_name)
            if entry.url:
                # 提取 netloc 并剥离 userinfo（user:pass@），避免凭据泄露到列表副标题
                netloc = entry.url.split('://', 1)[-1].split('/', 1)[0].split('@')[-1]
                subtitle_parts.append(netloc)
            subtitle = ' · '.join(subtitle_parts) if subtitle_parts else '无额外信息'
            painter.setFont(get_font(FONT_FAMILY_PRIMARY, 8))
            painter.setPen(QColor(get_color('text_secondary')))
            subtitle_text = painter.fontMetrics().elidedText(
                subtitle, Qt.TextElideMode.ElideRight, int(text_width)
            )
            painter.drawText(
                QRectF(text_left, rect.top() + 30, text_width, 19),
                Qt.AlignmentFlag.AlignVCenter,
                subtitle_text,
            )

            marker_x = rect.right() - self.MARKER_RIGHT_MARGIN
            if entry.password_present:
                painter.setPen(QColor(get_strength_color(entry.password_strength)))
                painter.setFont(get_font(FONT_FAMILY_PRIMARY, 8))
                painter.drawText(
                    QRectF(marker_x, rect.top() + 10, 12, 16),
                    Qt.AlignmentFlag.AlignCenter,
                    '●',
                )
            if entry.integrity_error:
                painter.setPen(QColor(get_color('danger')))
                painter.setFont(get_font(FONT_FAMILY_PRIMARY, 10, QFont.Weight.Bold))
                painter.drawText(
                    QRectF(marker_x, rect.top() + 30, 12, 16),
                    Qt.AlignmentFlag.AlignCenter,
                    '!',
                )

            if entry.is_deleted:
                badge = QRectF(rect.right() - self.MARKER_RIGHT_MARGIN - self.DELETE_BADGE_WIDTH + 9,
                               rect.top() + 20, self.DELETE_BADGE_WIDTH, self.DELETE_BADGE_HEIGHT)
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(QColor(get_color('danger_light')))
                painter.drawRoundedRect(badge, 4, 4)
                painter.setPen(QColor(get_color('danger')))
                painter.setFont(get_font(FONT_FAMILY_PRIMARY, 7))
                painter.drawText(badge, Qt.AlignmentFlag.AlignCenter, '已删除')
        finally:
            painter.restore()
