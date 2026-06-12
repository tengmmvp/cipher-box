"""剪贴板管理器 — 复制密码后自动清空。"""

import hmac
import logging
import os

from PyQt6.QtCore import QTimer
from PyQt6.QtGui import QClipboard
from PyQt6.QtWidgets import QApplication

# 每次会话随机生成 HMAC 密钥，避免硬编码可被预测
_CLIPBOARD_HMAC_KEY: bytes = os.urandom(32)

logger = logging.getLogger(__name__)


class ClipboardManager:
    """管理剪贴板复制与自动清空。

    ClipboardManager 是由 MainWindow 持有的长生命周期对象，因此内部
    QTimer 虽未指定 parent，但随 ClipboardManager 一同被 MainWindow
    管理，生命周期安全。
    """

    def __init__(self, clear_seconds: int = 30):
        self._clear_seconds = clear_seconds
        self._last_copied_hash: bytes = b''
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
        """复制文本到剪贴板，并设置自动清空定时器。

        同时设置 X11 Primary Selection 中键粘贴缓冲区，
        确保自动清理时两个缓冲区都被清除。
        """
        if not text:
            return
        clipboard = QApplication.clipboard()
        if clipboard:
            clipboard.setText(text)
            # X11 Primary Selection：Linux 下中键粘贴使用的独立缓冲区
            if clipboard.supportsSelection():
                clipboard.setText(text, QClipboard.Mode.Selection)
            self._last_copied_hash = hmac.digest(_CLIPBOARD_HMAC_KEY, text.encode('utf-8'), 'sha256')
            if self._clear_seconds > 0:
                self._timer.start(self._clear_seconds * 1000)

    def _clear_clipboard(self):
        """清空剪贴板，仅当内容仍为上次复制的文本时才清空。"""
        self._timer.stop()
        clipboard = QApplication.clipboard()
        if clipboard:
            current_text = clipboard.text()
            if self._last_copied_hash:
                current_hash = hmac.digest(_CLIPBOARD_HMAC_KEY, current_text.encode('utf-8'), 'sha256')
                if hmac.compare_digest(current_hash, self._last_copied_hash):
                    # clipboard.clear 在剪贴板被其它进程占用或模式不支持时
                    # 可能抛 RuntimeError；捕获以免中断锁定等后续清理流程
                    try:
                        clipboard.clear()
                        # 同步清除 X11 Primary Selection
                        if clipboard.supportsSelection():
                            clipboard.clear(QClipboard.Mode.Selection)
                    except RuntimeError:
                        logger.warning("剪贴板清空失败（可能被占用）", exc_info=True)
                    self._last_copied_hash = b''
                else:
                    # 用户已复制其他内容，原始内容已不在剪贴板中
                    self._last_copied_hash = b''

    def cancel(self):
        """取消自动清空"""
        self._timer.stop()

    def clear_now(self):
        """立即清理应用写入的敏感剪贴板内容。"""
        self._timer.stop()
        self._clear_clipboard()
