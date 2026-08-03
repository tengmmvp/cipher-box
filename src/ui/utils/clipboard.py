"""剪贴板管理器 — 敏感文本复制与定时自动清空。

复制密码后启动 singleShot 定时器，到时仅当剪贴板内容仍为本会话写入值（HMAC 常数时间
比对）才清空，避免误清用户后续复制的其它内容。关键设计：

- ``SEC-016``：Windows 下经 ctypes 在单次 ``OpenClipboard`` 周期原子写入
  CF_UNICODETEXT 与 Win+V 历史/云剪贴板排除标记，消除文本与标记分两次写入（剪贴板
  序号 N 与 N+1）致密码在标记就位前被快照进历史的时序窗口；非 Windows 或失败回退
  Qt ``setText``。
- ``SEC-017``：``text()`` / ``clear()`` / ``setText()`` 在剪贴板被其他进程占用
  （X11/远程会话/Windows 抢占）时可能抛 ``RuntimeError``，全程吞异常降级，不阻断 UI
  或锁定/隐藏到托盘等关键清理流程。
- fail-safe：读取失败即无法判定内容是否仍是密码，按安全优先强制清空（宁可误清不留密码），
  避免 singleShot 定时器已停而密码无限期残留。
- X11 Primary Selection 与 text() 独立记 hash 比对，避免一方被替换时另一方仍残留密码。

继承 ``QObject`` 使内部 ``QTimer`` 以本对象为 parent；由 ``MainWindow`` 持有，随其
生命周期回收。
"""

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

# Windows 剪贴板原子写入（SEC-016）：单次 OpenClipboard 周期内同时写 CF_UNICODETEXT
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
        """分配全局内存、拷贝 data、SetClipboardData（SEC-016 辅助）。

        成功后 hmem 所有权转交剪贴板系统（不可 GlobalFree）；失败则自行释放防泄漏。
        """
        hmem = _kernel32.GlobalAlloc(_GMEM_MOVEABLE, max(1, len(data)))
        if not hmem:
            return False
        ptr = _kernel32.GlobalLock(hmem)
        if not ptr:
            # GlobalLock 失败（ptr=0）：不可继续 SetClipboardData 提交未初始化内存
            # （会令剪贴板持有任意堆内容）。释放 hmem 防泄漏，返回 False 使调用方
            # 回退 Qt setText。
            _kernel32.GlobalFree(hmem)
            return False
        _kernel32.RtlMoveMemory(ptr, data, len(data))
        _kernel32.GlobalUnlock(hmem)
        if _user32.SetClipboardData(fmt, hmem):
            return True  # 所有权转交剪贴板
        _kernel32.GlobalFree(hmem)
        return False

    def _copy_with_history_exclusion(text: str) -> bool:
        """单次 OpenClipboard 周期原子写 CF_UNICODETEXT + Win+V 历史排除标记（SEC-016）。

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
                # Win+V 历史/云剪贴板排除标记（注册失败则仅写文本，降级）。标记写入失败
                # 不可静默——文本已在剪贴板但无排除保护，密码可能进历史/云同步，须告警可见。
                fmt = _user32.RegisterClipboardFormatW(_EXCLUDE_CLIPBOARD_FORMAT)
                if fmt and not _set_clipboard_data(fmt, b"\x00"):
                    logger.warning("Win+V 历史排除标记写入失败，密码可能出现在剪贴板历史/云同步")
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
        写入失败（Windows 下剪贴板被其他进程持续占用致 setText 抛 RuntimeError）降级：
        记 warning 不崩 UI，不设 hash/不启定时器——``_clear_clipboard`` 仅在确认内容
        仍为本会话写入时清空，写入未成功则无内容可清。
        """
        if not text:
            return
        clipboard = QApplication.clipboard()
        if clipboard:
            # SEC-016：Windows 下单次 OpenClipboard 原子写文本 + Win+V 历史排除标记，
            # 消除 setText 与排除标记分两次写入的时序窗口；非 Windows 或失败回退 Qt setText。
            if not _copy_with_history_exclusion(text):
                # setText 容错（SEC-017）：与 _clear_clipboard 的 text() 读取容错对称——
                # H1 已使读取失败降级，写入失败同样须降级，否则 Windows 下剪贴板被占用时
                # 复制操作直接崩 UI。写入失败则无内容可清，直接返回不设 hash/不定时。
                try:
                    clipboard.setText(text)
                except RuntimeError:
                    logger.warning("写入剪贴板失败（被占用），复制未完成", exc_info=True)
                    return
            self._last_text_hash = _hmac_of(text)
            # X11 Primary Selection：Linux 下中键粘贴使用的独立缓冲区
            if clipboard.supportsSelection():
                try:
                    clipboard.setText(text, QClipboard.Mode.Selection)
                except RuntimeError:
                    # Selection 写入失败不影响主文本已复制；selection 残留由 hash 为空
                    # （_clear_clipboard 跳过该缓冲区比对）兜底，不阻断复制流程。
                    logger.warning("写入 X11 Primary Selection 失败", exc_info=True)
                    self._last_selection_hash = b""
                else:
                    self._last_selection_hash = _hmac_of(text)
            else:
                self._last_selection_hash = b""
            if self._clear_seconds > 0:
                self._timer.start(self._clear_seconds * 1000)

    def _clear_clipboard(self) -> None:
        """清空剪贴板，仅当缓冲区内容仍为上次复制的文本时才清空。

        text() 与 Selection 独立校验，避免用户已替换的一方被误清、仍为密码的一方残留。

        fail-safe：``text()`` 在 X11/远程会话剪贴板被占用时也可能抛 RuntimeError（见
        ``clear_now`` docstring）。读取失败即无法判定剪贴板是否仍是本会话写入的密码，
        此时宁可误清也不留密码——按「仍可能是密码」强制清空。这避免了 ``text()`` 抛错时
        ``clear()`` 从未执行、``_last_text_hash`` 未清零、singleShot 定时器已停导致的
        密码无限期残留（fail-unsafe）。
        """
        self._timer.stop()
        clipboard = QApplication.clipboard()
        if not clipboard:
            return
        if self._last_text_hash:
            self._clear_clipboard_mode(clipboard, QClipboard.Mode.Clipboard, self._last_text_hash)
            self._last_text_hash = b""
        if self._last_selection_hash and clipboard.supportsSelection():
            self._clear_clipboard_mode(
                clipboard, QClipboard.Mode.Selection, self._last_selection_hash
            )
            self._last_selection_hash = b""

    @staticmethod
    def _clear_clipboard_mode(
        clipboard: QClipboard, mode: QClipboard.Mode, expected_hash: bytes
    ) -> None:
        """按指定模式清空剪贴板，fail-safe。

        ``text(mode)`` 读取失败 → 无法判定内容 → 按安全优先强制清空（宁可误清不留密码）；
        ``clear(mode)`` 被占用时退回 ``setText("")`` 覆盖明文兜底，缩短残留窗口。
        """
        try:
            matches = hmac.compare_digest(_hmac_of(clipboard.text(mode)), expected_hash)
        except RuntimeError:
            # 读不到内容 → 无法判定是否仍是密码 → 按安全优先强制清空
            matches = True
        if not matches:
            return
        try:
            clipboard.clear(mode)
        except RuntimeError:
            try:
                clipboard.setText("", mode)
            except RuntimeError:
                logger.error("%s 清空与覆盖均失败，明文可能残留", mode.name, exc_info=True)
            else:
                logger.warning("%s clear 失败，已用空字符串覆盖明文", mode.name, exc_info=True)

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
