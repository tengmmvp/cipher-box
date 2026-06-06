"""条目列表自定义 Widget - 卡片式展示，含类型图标与强度指示"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
)
from PyQt6.QtCore import Qt
from html import escape

from ..database.models import Entry, ENTRY_TYPES, ENTRY_TYPE_LOGIN
from ..ui.resources.theme_colors import c, get_strength_color
from ..ui.resources.icons import icon_pixmap, STAR, SIZE_STAR


class EntryItemWidget(QWidget):
    """条目列表自定义控件 - 卡片式布局"""

    def __init__(self, entry: Entry, parent=None, highlight: str = ''):
        super().__init__(parent)
        self._entry = entry
        self._highlight = highlight
        self._setup_ui()

    def _setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(10)

        # 左侧：类型图标
        type_info = ENTRY_TYPES.get(self._entry.entry_type, ENTRY_TYPES[ENTRY_TYPE_LOGIN])
        type_icon = QLabel(type_info['icon'])
        type_icon.setFixedSize(28, 28)
        type_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        type_icon.setStyleSheet(
            f'font-size: 18px; background: {c("bg_card")}; border-radius: 6px;'
        )
        layout.addWidget(type_icon)

        # 中间：标题 + 副标题
        text_container = QVBoxLayout()
        text_container.setSpacing(2)

        # 标题行：收藏星标 + 标题
        title_row = QHBoxLayout()
        title_row.setSpacing(4)

        if self._entry.is_favorite:
            fav = QLabel()
            fav.setPixmap(icon_pixmap(STAR, size=SIZE_STAR))
            fav.setFixedSize(SIZE_STAR, SIZE_STAR)
            title_row.addWidget(fav)

        title_text = self._highlight_text(self._entry.title or '(无标题)', self._highlight)
        title_label = QLabel(title_text)
        title_label.setStyleSheet(
            f'font-weight: bold; font-size: 13px; color: {c("text_primary")}; background: transparent;'
        )
        title_label.setTextFormat(Qt.TextFormat.RichText)
        title_label.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
        title_row.addWidget(title_label, 1)
        text_container.addLayout(title_row)

        # 副标题行
        subtitle_parts = []
        if self._entry.username:
            subtitle_parts.append(self._entry.username)
        if self._entry.category_name and self._entry.category_name != '未分类':
            subtitle_parts.append(self._entry.category_name)
        if self._entry.url:
            url = self._entry.url
            if '://' in url:
                url = url.split('://')[1]
            url = url.split('/')[0]
            if len(url) > 25:
                url = url[:25] + '...'
            subtitle_parts.append(url)

        subtitle = ' · '.join(subtitle_parts) if subtitle_parts else '无额外信息'
        subtitle_text = self._highlight_text(subtitle, self._highlight)
        subtitle_label = QLabel(subtitle_text)
        subtitle_label.setStyleSheet(
            f'font-size: 11px; color: {c("text_secondary")}; background: transparent;'
        )
        subtitle_label.setTextFormat(Qt.TextFormat.RichText)
        subtitle_label.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
        text_container.addWidget(subtitle_label)

        layout.addLayout(text_container, 1)

        # 右侧：密码强度指示点 + 已删除标记
        right_layout = QVBoxLayout()
        right_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # 强度指示点
        strength = self._entry.password_strength
        if self._entry.password_present or self._entry.password:
            color = get_strength_color(strength)
            strength_text = {0: '很弱', 1: '弱', 2: '一般', 3: '强', 4: '很强'}.get(strength, '')
            dot = QLabel('●')
            dot.setStyleSheet(f'color: {color}; font-size: 10px; background: transparent;')
            dot.setAlignment(Qt.AlignmentFlag.AlignCenter)
            dot.setToolTip(f'密码强度: {strength_text}')
            right_layout.addWidget(dot)

        if self._entry.integrity_error:
            warning = QLabel('!')
            warning.setToolTip(f'数据完整性异常：{self._entry.integrity_message}')
            warning.setStyleSheet(
                f'color: {c("danger")}; font-weight: bold; background: transparent;'
            )
            right_layout.addWidget(warning)

        layout.addLayout(right_layout)

        # 已删除标记
        if self._entry.is_deleted:
            tag = QLabel('已删除')
            tag.setStyleSheet(
                f'font-size: 10px; color: {c("danger")}; '
                f'background: {c("danger_light")}; border-radius: 3px; padding: 1px 6px;'
            )
            layout.addWidget(tag)

    def set_selected(self, selected: bool):
        """设置选中状态视觉反馈"""
        if selected:
            self.setStyleSheet(
                f'background: {c("accent_light")}; '
                f'border-left: 3px solid {c("accent")};'
            )
        else:
            self.setStyleSheet(
                f'background: {c("bg_card")}; '
                f'border-left: none;'
            )

    @staticmethod
    def _highlight_text(text: str, keyword: str) -> str:
        """将文本中匹配关键词的部分用 HTML span 高亮"""
        if not keyword:
            return escape(text)
        keyword_lower = keyword.lower()
        text_lower = text.lower()
        idx = text_lower.find(keyword_lower)
        if idx < 0:
            return escape(text)
        before = escape(text[:idx])
        match = escape(text[idx:idx + len(keyword)])
        after = escape(text[idx + len(keyword):])
        highlight_color = c('accent_light')
        text_color = c('accent_text')
        return (f'{before}<span style="background: {highlight_color}; color: {text_color}; '
                f'border-radius: 2px; padding: 0 2px;">{match}</span>{after}')
