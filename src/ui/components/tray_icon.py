"""系统托盘图标。

提供保险库状态指示、右键菜单与双击唤出主窗口等系统托盘交互。
图标根据锁定状态切换颜色与文字，无外部图标文件，统一通过代码绘制生成。
"""

from __future__ import annotations

from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtGui import QAction, QColor, QIcon
from PyQt6.QtWidgets import QMenu, QSystemTrayIcon

from ..resources.icons import draw_logo_pixmap
from ..resources.theme_colors import c


class TrayIcon(QSystemTrayIcon):
    """系统托盘图标管理，提供状态指示、右键菜单与唤出交互。"""

    show_window = pyqtSignal()
    lock_vault = pyqtSignal()
    quit_app = pyqtSignal()

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)

        # 使用文字作为图标，不依赖外部图标文件
        self.setIcon(TrayIcon._create_icon(QColor(c('brand')), 'C'))

        self.setToolTip('CipherBox')

        self._create_menu()

        self.activated.connect(self._on_activated)

    @staticmethod
    def _create_icon(color: QColor, text: str) -> QIcon:
        """根据背景色和文字生成托盘图标。

        长文本（len>2，如 'LOCK'）在 32px 画布会溢出裁剪，缩短为首字符
        并使用与单字符一致的字号，保证图标清晰可读。
        """
        bg = color.name() if isinstance(color, QColor) else str(color)
        if len(text) > 2:
            text = text[0]
        pixmap = draw_logo_pixmap(
            size=32,
            bg_color=bg,
            text=text,
            text_color=c('text_on_accent'),
            font_size=12 if len(text) > 1 else 16,
        )
        return QIcon(pixmap)

    def set_locked(self, locked: bool) -> None:
        """切换锁定/解锁状态的托盘图标。"""
        if locked:
            self.setIcon(TrayIcon._create_icon(QColor(c('text_muted')), 'LOCK'))
            self.setToolTip('CipherBox（已锁定）')
        else:
            self.setIcon(TrayIcon._create_icon(QColor(c('brand')), 'C'))
            self.setToolTip('CipherBox')

    def _create_menu(self):
        menu = QMenu()

        show_action = QAction('显示主窗口', self)
        show_action.triggered.connect(self.show_window.emit)
        menu.addAction(show_action)

        lock_action = QAction('锁定保险库', self)
        lock_action.triggered.connect(self.lock_vault.emit)
        menu.addAction(lock_action)

        menu.addSeparator()

        quit_action = QAction('退出', self)
        quit_action.triggered.connect(self.quit_app.emit)
        menu.addAction(quit_action)

        self.setContextMenu(menu)

    def _on_activated(self, reason):
        """托盘图标激活事件处理，仅响应双击以唤出主窗口。"""
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.show_window.emit()
