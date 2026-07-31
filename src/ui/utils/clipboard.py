"""剪贴板管理器 — 复制密码后自动清空。"""

import hmac
import logging
import os

from PyQt6.QtCore import QObject, QTimer
from PyQt6.QtGui import QClipboard
from PyQt6.QtWidgets import QApplication

from ..resources.constants import CLIPBOARD_CLEAR_SECONDS_DEFAULT

# 会话级 key，用于常数时间比对剪贴板内容是否仍为上次写入值（非认证用途）。
# 每次进程启动随机生成；仅在 _clear_clipboard 中以 hmac.compare_digest 比对
# 剪贴板当前内容是否仍是本会话写入的密码以决定是否清空。即便攻击者已知此 key
# 也无法借此读取密码内容（不涉及跨进程认证或防篡改）。
_CLIPBOARD_HMAC_KEY: bytes = os.urandom(32)

logger = logging.getLogger(__name__)


def _hmac_of(text: str) -> bytes:
    """对文本计算会话级 HMAC 摘要，用于常数时间比对剪贴板内容。"""
    return hmac.digest(_CLIPBOARD_HMAC_KEY, text.encode('utf-8'), 'sha256')


class ClipboardManager(QObject):
    """管理剪贴板复制与自动清空。

    继承 QObject 使内部 QTimer 以本对象为 parent，避免无主定时器在异常关闭
    路径触发 Qt 告警；由 MainWindow 持有，随其生命周期回收。
    """

    def __init__(self, clear_seconds: int = CLIPBOARD_CLEAR_SECONDS_DEFAULT):
        super().__init__()
        self._clear_seconds = clear_seconds
        # text() 与 X11 Primary Selection 独立记 hash：Linux 下二者可分别替换，
        # 独立校验避免一方被替换时另一方仍残留密码（Windows 不支持 Selection）。
        self._last_text_hash: bytes = b''
        self._last_selection_hash: bytes = b''
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._clear_clipboard)

    @property
    def clear_seconds(self) -> int:
        return self._clear_seconds

    @clear_seconds.setter
    def clear_seconds(self, value: int) -> None:
        self._clear_seconds = max(0, value)

    def copy_text(self, text: str) -> None:
        """复制文本到剪贴板，并设置自动清空定时器。

        同时写入 X11 Primary Selection 中键粘贴缓冲区，确保定时清空时一并清除。
        """
        if not text:
            return
        clipboard = QApplication.clipboard()
        if clipboard:
            clipboard.setText(text)
            self._last_text_hash = _hmac_of(text)
            # X11 Primary Selection：Linux 下中键粘贴使用的独立缓冲区
            if clipboard.supportsSelection():
                clipboard.setText(text, QClipboard.Mode.Selection)
                self._last_selection_hash = _hmac_of(text)
            else:
                self._last_selection_hash = b''
            if self._clear_seconds > 0:
                self._timer.start(self._clear_seconds * 1000)

    def _clear_clipboard(self) -> None:
        """清空剪贴板，仅当缓冲区内容仍为上次复制的文本时才清空。

        text() 与 Selection 独立校验，避免用户已替换的一方被误清、仍为密码的一方残留。
        """
        self._timer.stop()
        clipboard = QApplication.clipboard()
        if not clipboard:
            return
        if self._last_text_hash:
            if hmac.compare_digest(_hmac_of(clipboard.text()), self._last_text_hash):
                # clipboard.clear 被其它进程占用或模式不支持时可能抛 RuntimeError，
                # 捕获以免中断锁定等后续清理流程
                try:
                    clipboard.clear()
                except RuntimeError:
                    # clear 被占用时用空字符串覆盖明文兜底，缩短密码残留窗口
                    try:
                        clipboard.setText('')
                    except RuntimeError:
                        logger.error("剪贴板清空与覆盖均失败，明文可能残留", exc_info=True)
                    else:
                        logger.warning("剪贴板 clear 失败，已用空字符串覆盖明文", exc_info=True)
            self._last_text_hash = b''
        if self._last_selection_hash and clipboard.supportsSelection():
            if hmac.compare_digest(
                _hmac_of(clipboard.text(QClipboard.Mode.Selection)),
                self._last_selection_hash,
            ):
                try:
                    clipboard.clear(QClipboard.Mode.Selection)
                except RuntimeError:
                    try:
                        clipboard.setText('', QClipboard.Mode.Selection)
                    except RuntimeError:
                        logger.error("Selection 清空与覆盖均失败，明文可能残留", exc_info=True)
                    else:
                        logger.warning("Selection clear 失败，已用空字符串覆盖明文", exc_info=True)
            self._last_selection_hash = b''

    def cancel(self) -> None:
        """取消自动清空。"""
        self._timer.stop()

    def clear_now(self) -> None:
        """立即清理应用写入的敏感剪贴板内容。"""
        self._timer.stop()
        self._clear_clipboard()
