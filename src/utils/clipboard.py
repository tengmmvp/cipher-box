"""剪贴板管理器 - 复制密码后自动清空"""

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import QTimer


class ClipboardManager:
    """管理剪贴板复制与自动清空"""

    def __init__(self, clear_seconds: int = 30):
        self._clear_seconds = clear_seconds
        self._last_copied: str = ''
        self._timer = QTimer()
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._clear_clipboard)

    @property
    def clear_seconds(self) -> int:
        return self._clear_seconds

    @clear_seconds.setter
    def clear_seconds(self, value: int):
        self._clear_seconds = max(0, value)

    def copy_text(self, text: str):
        """复制文本到剪贴板，并设置自动清空定时器"""
        if not text:
            return
        clipboard = QApplication.clipboard()
        if clipboard:
            clipboard.setText(text)
            self._last_copied = text

        if self._clear_seconds > 0:
            self._timer.start(self._clear_seconds * 1000)

    def _clear_clipboard(self):
        """清空剪贴板（仅当内容仍为上次复制的文本时才清空）"""
        clipboard = QApplication.clipboard()
        if clipboard:
            current_text = clipboard.text()
            if current_text == self._last_copied:
                clipboard.clear()
            self._last_copied = ''

    def cancel(self):
        """取消自动清空"""
        self._timer.stop()

    def clear_now(self):
        """立即清理应用写入的敏感剪贴板内容。"""
        self._timer.stop()
        self._clear_clipboard()
