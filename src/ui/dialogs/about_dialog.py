"""关于对话框，展示应用名称、版本与技术栈等静态信息。"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ... import __app_name__, __version__
from ..components.widgets import setup_dialog_flags
from ..resources.constants import BTN_DIALOG, DIALOG_ABOUT_MIN_SIZE
from ..resources.icons import draw_logo_pixmap
from ..resources.theme_colors import c


class AboutDialog(QDialog):
    """展示 CipherBox 版本、加密算法与技术栈的只读对话框。"""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        self.setWindowTitle(f'关于 {__app_name__}')
        self.setMinimumSize(*DIALOG_ABOUT_MIN_SIZE)
        setup_dialog_flags(self)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(36, 30, 36, 30)

        # 图标和名称
        pixmap = draw_logo_pixmap(size=64, font_size=28)

        icon = QLabel()
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon.setPixmap(pixmap)
        layout.addWidget(icon)

        name = QLabel(__app_name__)
        name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        name.setStyleSheet('font-size: 20px; font-weight: bold;')
        layout.addWidget(name)

        version = QLabel(f'版本 {__version__}')
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        version.setObjectName('formMutedPlain')
        layout.addWidget(version)

        desc = QLabel(
            '一款安全的本地密码管理器\n'
            '使用 AES-256-GCM 加密存储所有敏感数据\n'
            '所有数据保存在本地，不上传至任何服务器'
        )
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc.setStyleSheet(f'color: {c("text_secondary")}; font-size: 12px;')
        desc.setWordWrap(True)
        layout.addWidget(desc)

        tech = QLabel(
            '技术栈：Python + PyQt6\n'
            '加密算法：AES-256-GCM（cryptography）+ Argon2id（argon2-cffi）\n'
            '数据存储：SQLite'
        )
        tech.setAlignment(Qt.AlignmentFlag.AlignCenter)
        tech.setObjectName('formMutedSmall')
        tech.setWordWrap(True)
        layout.addWidget(tech)

        layout.addStretch()

        # 关闭按钮
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        close_btn = QPushButton('关闭')
        close_btn.setFixedSize(*BTN_DIALOG)
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
