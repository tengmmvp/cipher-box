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

# Windows 剪贴板原子写入（SEC-CLIP-001）：单次 OpenClipboard 周期内同时写 CF_UNICODETEXT
# 与 ExcludeClipboardContentFromMonitorProcessing 标记，使 Win+V 历史/云剪贴板不捕获密码，
# 并消除文本与标记分两次写入（剪贴板序号 N 与 N+1）的时序窗口。Qt 不暴露该 Win32 能力，
# 故经 ctypes 调用 user32/kernel32。仅 Windows 加载，其余平台返回 False 回退 Qt setText。
# 用 ``sys.platform == 'win32'`` 字面量比较而非中间变量：mypy 据此按平台缩窄，识别
# typeshed 中 Windows 专属的 ctypes.WinDLL，避免非 Windows CI 报 attr-defined。
if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _user32 = ctypes.WinDLL("user32")
    _kernel32 = ctypes.WinDLL("kernel32")
    _EXCLUDE_CLIPBOARD_FORMAT = "ExcludeClipboardContentFromMonitorProcessing"
    _CF_UNICODETEXT = 13
    # 显式标注 argtypes/restype：WinDLL 默认按 c_int（32 位）收发返回值，64 位 Windows
    # 下句柄为 64 位指针会被截断致空句柄/崩溃。
    _user32.RegisterClipboardFormatW.argtypes = [wintypes.LPCWSTR]
    _user32.RegisterClipboardFormatW.restype = wintypes.UINT
    _user32.OpenClipboard.argtypes = [wintypes.HWND]
    _user32.OpenClipboard.restype = wintypes.BOOL
    _user32.EmptyClipboard.argtypes = []
    _user32.EmptyClipboard.restype = wintypes.HANDLE
    _user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    _user32.SetClipboardData.restype = wintypes.HANDLE
    _user32.CloseClipboard.restype = wintypes.BOOL
    _kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    _kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
    _kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    _kernel32.GlobalLock.restype = wintypes.LPVOID
    _kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    _kernel32.GlobalFree.argtypes = [wintypes.HGLOBAL]
    _kernel32.RtlMoveMemory.argtypes = [wintypes.LPVOID, ctypes.c_char_p, ctypes.c_size_t]

    # GMEM_MOVEABLE=0x2000：SetClipboardData 要求可移动全局内存。
    _GMEM_MOVEABLE = 0x2000

    def _set_clipboard_data(fmt: int, data: bytes) -> bool:
        """分配全局内存、拷贝 data、SetClipboardData（SEC-CLIP-001 辅助）。

        成功后 hmem 所有权转交剪贴板系统（不可 GlobalFree）；失败则自行释放防泄漏。
        """
        hmem = _kernel32.GlobalAlloc(_GMEM_MOVEABLE, max(1, len(data)))
        if not hmem:
            return False
        ptr = _kernel32.GlobalLock(hmem)
        if ptr:
            _kernel32.RtlMoveMemory(ptr, data, len(data))
            _kernel32.GlobalUnlock(hmem)
        if _user32.SetClipboardData(fmt, hmem):
            return True  # 所有权转交剪贴板
        _kernel32.GlobalFree(hmem)
        return False

    def _copy_with_history_exclusion(text: str) -> bool:
        """单次 OpenClipboard 周期原子写 CF_UNICODETEXT + Win+V 历史排除标记（SEC-CLIP-001）。

        文本与排除标记在同一次打开/清空/写入/关闭周期内提交，剪贴板序号只递增一次，
        监视器处理时两格式同时在场——消除 setText 与排除标记分两次写入（序号 N 与 N+1）
        致密码在标记就位前被快照进 Win+V 历史/云剪贴板的时序窗口。成功返回 True；剪贴板
        被占用或分配失败返回 False，调用方回退 Qt setText。
        """
        try:
            if not _user32.OpenClipboard(None):
                return False
            try:
                _user32.EmptyClipboard()
                # CF_UNICODETEXT：UTF-16LE 编码 + 2 字节 null 终止符
                if not _set_clipboard_data(_CF_UNICODETEXT, text.encode("utf-16-le") + b"\x00\x00"):
                    return False
                # Win+V 历史/云剪贴板排除标记（注册失败则仅写文本，降级）
                fmt = _user32.RegisterClipboardFormatW(_EXCLUDE_CLIPBOARD_FORMAT)
                if fmt:
                    _set_clipboard_data(fmt, b"\x00")
                return True
            finally:
                _user32.CloseClipboard()
        except OSError:
            logger.warning("原子写入剪贴板失败，回退 Qt setText", exc_info=True)
            return False
else:

    def _copy_with_history_exclusion(text: str) -> bool:
        """非 Windows：无 Win+V 历史排除需求，返回 False 使调用方走 Qt setText。"""
        return False


def _hmac_of(text: str) -> bytes:
    """对文本计算会话级 HMAC 摘要，用于常数时间比对剪贴板内容。"""
    return hmac.digest(_CLIPBOARD_HMAC_KEY, text.encode("utf-8"), "sha256")


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
        self._last_text_hash: bytes = b""
        self._last_selection_hash: bytes = b""
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
            # SEC-CLIP-001：Windows 下单次 OpenClipboard 原子写文本 + Win+V 历史排除标记，
            # 消除 setText 与排除标记分两次写入的时序窗口；非 Windows 或失败回退 Qt setText。
            if not _copy_with_history_exclusion(text):
                clipboard.setText(text)
            self._last_text_hash = _hmac_of(text)
            # X11 Primary Selection：Linux 下中键粘贴使用的独立缓冲区
            if clipboard.supportsSelection():
                clipboard.setText(text, QClipboard.Mode.Selection)
                self._last_selection_hash = _hmac_of(text)
            else:
                self._last_selection_hash = b""
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
                        clipboard.setText("")
                    except RuntimeError:
                        logger.error("剪贴板清空与覆盖均失败，明文可能残留", exc_info=True)
                    else:
                        logger.warning("剪贴板 clear 失败，已用空字符串覆盖明文", exc_info=True)
            self._last_text_hash = b""
        if self._last_selection_hash and clipboard.supportsSelection():
            if hmac.compare_digest(
                _hmac_of(clipboard.text(QClipboard.Mode.Selection)),
                self._last_selection_hash,
            ):
                try:
                    clipboard.clear(QClipboard.Mode.Selection)
                except RuntimeError:
                    try:
                        clipboard.setText("", QClipboard.Mode.Selection)
                    except RuntimeError:
                        logger.error("Selection 清空与覆盖均失败，明文可能残留", exc_info=True)
                    else:
                        logger.warning("Selection clear 失败，已用空字符串覆盖明文", exc_info=True)
            self._last_selection_hash = b""

    def cancel(self) -> None:
        """取消自动清空。"""
        self._timer.stop()

    def clear_now(self) -> None:
        """立即清理应用写入的敏感剪贴板内容。

        吞 RuntimeError：剪贴板被占用（X11/远程会话）时 ``text()`` 读取也可能抛，
        不应中断锁定/隐藏到托盘等关键清理流程（与 emergency_clear_clipboard 对齐）。
        """
        self._timer.stop()
        try:
            self._clear_clipboard()
        except RuntimeError:
            logger.error("立即清空剪贴板失败，明文可能残留", exc_info=True)
