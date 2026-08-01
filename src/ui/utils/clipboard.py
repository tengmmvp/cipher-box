"""剪贴板管理器 — 复制密码后自动清空。"""

import hmac
import logging
import os
import sys

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

# Windows 剪贴板历史排除（SEC-001）：注册 ExcludeClipboardContentFromMonitorProcessing
# 格式并随密码一同写入，使 Win+V 历史与云剪贴板不捕获密码。Qt 不暴露该 Win32 能力，
# 故经 ctypes 调用 user32/kernel32。仅 Windows 加载，其余平台提供无操作占位。
# 用 ``sys.platform == 'win32'`` 字面量比较而非中间变量：mypy 据此按平台缩窄，识别
# typeshed 中 Windows 专属的 ctypes.WinDLL，避免非 Windows CI 报 attr-defined。
if sys.platform == 'win32':
    import ctypes
    from ctypes import wintypes

    _user32 = ctypes.WinDLL('user32')
    _kernel32 = ctypes.WinDLL('kernel32')
    _EXCLUDE_CLIPBOARD_FORMAT = 'ExcludeClipboardContentFromMonitorProcessing'
    # 显式标注 argtypes/restype：WinDLL 默认按 c_int（32 位）收发返回值，64 位 Windows
    # 下句柄为 64 位指针会被截断致空句柄/崩溃。
    _user32.RegisterClipboardFormatW.argtypes = [wintypes.LPCWSTR]
    _user32.RegisterClipboardFormatW.restype = wintypes.UINT
    _user32.OpenClipboard.argtypes = [wintypes.HWND]
    _user32.OpenClipboard.restype = wintypes.BOOL
    _user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    _user32.SetClipboardData.restype = wintypes.HANDLE
    _user32.CloseClipboard.restype = wintypes.BOOL
    _kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    _kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
    _kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    _kernel32.GlobalLock.restype = wintypes.LPVOID
    _kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    _kernel32.GlobalFree.argtypes = [wintypes.HGLOBAL]


    def _exclude_from_clipboard_history() -> None:
        """向剪贴板追加 ExcludeClipboardContentFromMonitorProcessing 格式（SEC-001）。

        密码仍在剪贴板可用，但该标记使 Win+V 历史与云剪贴板跳过本次写入。
        SetClipboardData 成功后 hmem 所有权转交剪贴板系统（不可 GlobalFree）；失败则
        自行释放防泄漏。剪贴板被占用（OpenClipboard 失败）时跳过——密码仍可用但降级
        进入历史（尽力而为，非致命）。
        """
        try:
            fmt = _user32.RegisterClipboardFormatW(_EXCLUDE_CLIPBOARD_FORMAT)
            if not fmt or not _user32.OpenClipboard(None):
                return
            hmem = 0
            try:
                hmem = _kernel32.GlobalAlloc(0x2000, 1)  # GMEM_MOVEABLE=0x2000；1 字节空载体
                if not hmem:
                    return
                ptr = _kernel32.GlobalLock(hmem)
                if ptr:
                    (ctypes.c_char * 1).from_address(ptr)[0] = b'\x00'
                    _kernel32.GlobalUnlock(hmem)
                if _user32.SetClipboardData(fmt, hmem):
                    hmem = 0  # 所有权转交剪贴板，标记不再释放
            finally:
                _user32.CloseClipboard()
                if hmem:
                    _kernel32.GlobalFree(hmem)
        except OSError:
            logger.warning("注册剪贴板历史排除格式失败，密码可能进入剪贴板历史", exc_info=True)
else:
    def _exclude_from_clipboard_history() -> None:
        """非 Windows：无操作（无 Win+V 历史排除需求）。"""
        return


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
            _exclude_from_clipboard_history()  # SEC-001：Win+V 历史/云剪贴板排除（Windows）
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
