"""条目列表的轻量委托绘制。"""

from PyQt6.QtCore import QRectF, QSize, Qt
from PyQt6.QtGui import QColor, QFont, QPainter, QPen
from PyQt6.QtWidgets import QStyle, QStyledItemDelegate

from ..database.models import ENTRY_TYPE_LOGIN, ENTRY_TYPES
from .resources.theme_colors import c, get_strength_color


class EntryItemDelegate(QStyledItemDelegate):
    """按需绘制条目卡片，避免为每条记录创建常驻 QWidget。"""

    ROW_HEIGHT = 62

    def sizeHint(self, option, index):
        return QSize(option.rect.width(), self.ROW_HEIGHT)

    def paint(self, painter: QPainter, option, index):
        entry = index.data(Qt.ItemDataRole.UserRole)
        if entry is None:
            super().paint(painter, option, index)
            return

        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(option.rect.adjusted(4, 2, -4, -2))
        selected = bool(option.state & QStyle.StateFlag.State_Selected)
        background = c('accent_light') if selected else c('bg_card')
        painter.setPen(QPen(QColor(c('border_light')), 1))
        painter.setBrush(QColor(background))
        painter.drawRoundedRect(rect, 7, 7)
        if selected:
            painter.fillRect(
                QRectF(rect.left(), rect.top(), 3, rect.height()),
                QColor(c('accent')),
            )

        icon_rect = QRectF(rect.left() + 10, rect.top() + 13, 28, 28)
        painter.setPen(QColor(c('text_primary')))
        painter.setFont(QFont('Microsoft YaHei UI', 15))
        type_info = ENTRY_TYPES.get(
            entry.entry_type, ENTRY_TYPES[ENTRY_TYPE_LOGIN]
        )
        painter.drawText(icon_rect, Qt.AlignmentFlag.AlignCenter, type_info['icon'])

        text_left = rect.left() + 48
        right_reserved = 76 if entry.is_deleted else 38
        text_width = max(40, rect.right() - text_left - right_reserved)
        title = entry.title or '(无标题)'
        if entry.is_favorite:
            title = f'★ {title}'
        painter.setFont(QFont('Microsoft YaHei UI', 10, QFont.Weight.DemiBold))
        painter.setPen(QColor(c('text_primary')))
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
            subtitle_parts.append(entry.url.split('://', 1)[-1].split('/', 1)[0])
        subtitle = ' · '.join(subtitle_parts) if subtitle_parts else '无额外信息'
        painter.setFont(QFont('Microsoft YaHei UI', 8))
        painter.setPen(QColor(c('text_secondary')))
        subtitle_text = painter.fontMetrics().elidedText(
            subtitle, Qt.TextElideMode.ElideRight, int(text_width)
        )
        painter.drawText(
            QRectF(text_left, rect.top() + 30, text_width, 19),
            Qt.AlignmentFlag.AlignVCenter,
            subtitle_text,
        )

        marker_x = rect.right() - 22
        if entry.password_present or entry.password:
            painter.setPen(QColor(get_strength_color(entry.password_strength)))
            painter.setFont(QFont('Microsoft YaHei UI', 8))
            painter.drawText(
                QRectF(marker_x, rect.top() + 10, 12, 16),
                Qt.AlignmentFlag.AlignCenter,
                '●',
            )
        if entry.integrity_error:
            painter.setPen(QColor(c('danger')))
            painter.setFont(QFont('Microsoft YaHei UI', 10, QFont.Weight.Bold))
            painter.drawText(
                QRectF(marker_x, rect.top() + 30, 12, 16),
                Qt.AlignmentFlag.AlignCenter,
                '!',
            )

        if entry.is_deleted:
            badge = QRectF(rect.right() - 61, rect.top() + 20, 48, 20)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(c('danger_light')))
            painter.drawRoundedRect(badge, 4, 4)
            painter.setPen(QColor(c('danger')))
            painter.setFont(QFont('Microsoft YaHei UI', 7))
            painter.drawText(badge, Qt.AlignmentFlag.AlignCenter, '已删除')

        painter.restore()
