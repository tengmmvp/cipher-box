"""空状态组件 - 友好的空列表/无结果提示"""

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ..ui.resources.constants import BTN_ACTION
from ..ui.resources.icons import EMPTY_GENERIC, SIZE_EMPTY, icon_pixmap
from ..ui.resources.theme_colors import c


class EmptyStateWidget(QWidget):
    """空状态提示组件"""

    action_clicked = pyqtSignal()

    def __init__(
        self,
        icon_name: str = EMPTY_GENERIC,
        title: str = '暂无数据',
        subtitle: str = '',
        action_text: str = '',
        parent=None,
    ):
        super().__init__(parent)
        self._setup_ui(icon_name, title, subtitle, action_text)

    def _setup_ui(self, icon_name: str, title: str, subtitle: str, action_text: str):
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(8)

        # 图标
        icon_label = QLabel()
        icon_label.setPixmap(icon_pixmap(icon_name, size=SIZE_EMPTY))
        icon_label.setFixedSize(SIZE_EMPTY, SIZE_EMPTY)
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon_label)

        # 主标题
        title_label = QLabel(title)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet(f'font-size: 14px; color: {c("text_secondary")};')
        layout.addWidget(title_label)

        # 副标题
        if subtitle:
            sub_label = QLabel(subtitle)
            sub_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            sub_label.setStyleSheet(f'font-size: 12px; color: {c("text_muted")};')
            sub_label.setWordWrap(True)
            layout.addWidget(sub_label)

        # 操作按钮
        if action_text:
            action_btn = QPushButton(action_text)
            action_btn.setObjectName('primaryBtn')
            action_btn.setFixedSize(*BTN_ACTION)
            action_btn.clicked.connect(self.action_clicked.emit)
            layout.addSpacing(8)

            btn_layout = QVBoxLayout()
            btn_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            btn_layout.addWidget(action_btn)
            layout.addLayout(btn_layout)
