"""系统托盘图标"""

from PyQt6.QtWidgets import QSystemTrayIcon, QMenu
from PyQt6.QtGui import QAction, QIcon, QPixmap, QPainter, QColor, QFont
from PyQt6.QtCore import Qt, pyqtSignal

from .resources.theme_colors import c


class TrayIcon(QSystemTrayIcon):
    """系统托盘图标管理"""

    show_window = pyqtSignal()
    lock_vault = pyqtSignal()
    quit_app = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)

        # 使用文字作为图标（无外部图标文件）
        self.setIcon(TrayIcon._create_icon(QColor(c('brand')), 'C'))

        self.setToolTip('CipherBox 密匣')

        self._create_menu()

        self.activated.connect(self._on_activated)

    @staticmethod
    def _create_icon(color: QColor, text: str) -> QIcon:
        """根据背景色和文字生成托盘图标"""
        pixmap = QPixmap(32, 32)
        pixmap.fill(QColor(0, 0, 0, 0))
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setBrush(color)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRoundedRect(2, 2, 28, 28, 6, 6)
        painter.setPen(QColor('white'))
        font_size = 12 if len(text) > 1 else 16
        painter.setFont(QFont('Arial', font_size, QFont.Weight.Bold))
        painter.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, text)
        painter.end()
        return QIcon(pixmap)

    def set_locked(self, locked: bool):
        """切换锁定/解锁状态的托盘图标"""
        if locked:
            self.setIcon(TrayIcon._create_icon(QColor(c('text_muted')), '🔒'))
            self.setToolTip('CipherBox 密匣（已锁定）')
        else:
            self.setIcon(TrayIcon._create_icon(QColor(c('brand')), 'C'))
            self.setToolTip('CipherBox 密匣')

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
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.show_window.emit()
