"""ClipboardManager 单元测试。

覆盖剪贴板复制与读取、自动清空计时器启停、取消清空、仅清空匹配内容以避免
误清用户后续复制，以及空字符串不触发清空等核心行为。
"""

import hmac
import sys

import pytest
from PyQt6.QtWidgets import QApplication

from src.ui.utils.clipboard import _CLIPBOARD_HMAC_KEY, ClipboardManager


def _read_system_clipboard() -> str:
    """读取系统剪贴板文本，跨平台验证 copy_text 写入。

    Windows 下 ``ClipboardManager.copy_text`` 经 Win32 直写系统剪贴板（SEC-CLIP-001），
    而 Qt 在 offscreen 平台（CI）的 clipboard 不接系统剪贴板、``clipboard.text()`` 读
    不到 Win32 写入；故 Windows 用 Win32 GetClipboardData 直读，与写入对称。其余平台
    copy_text 走 Qt setText，用 clipboard.text() 读一致。
    """
    clipboard = QApplication.clipboard()
    if sys.platform != "win32":
        return clipboard.text() if clipboard else ""
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32")
    user32.OpenClipboard.argtypes = [wintypes.HWND]
    user32.OpenClipboard.restype = wintypes.BOOL
    user32.GetClipboardData.argtypes = [wintypes.UINT]
    user32.GetClipboardData.restype = wintypes.HANDLE
    user32.CloseClipboard.restype = wintypes.BOOL
    if not user32.OpenClipboard(None):
        return ""
    try:
        ptr = user32.GetClipboardData(13)  # CF_UNICODETEXT
        if not ptr:
            return ""
        return ctypes.wstring_at(ptr) or ""
    finally:
        user32.CloseClipboard()


class TestClipboardManager:
    """ClipboardManager 的复制读取、自动清空计时器、仅清匹配内容与空串处理测试。"""

    @pytest.fixture(autouse=True)
    def _ensure_qapp(self, qapp):
        """在 setup_method 之前确保 QApplication 已创建。"""
        self._qapp = qapp

    def setup_method(self):
        # 清空全局剪贴板，隔离前序测试 copy_text 的残留。QApplication 剪贴板是
        # 进程级共享状态，若不清，前序测试写入的文本会干扰本测试 _clear_clipboard
        # 的匹配判定（compare_digest 比对 clipboard.text() 与 _last_text_hash）。
        clipboard = QApplication.clipboard()
        if clipboard is not None:
            clipboard.clear()
        self.mgr = ClipboardManager(clear_seconds=30)

    def teardown_method(self):
        # 停止单次定时器，避免跨测试到期回调清空共享系统剪贴板污染其他测试
        self.mgr._timer.stop()

    # ---- 基础复制与获取 ----

    def test_copy_and_get(self):
        """复制文本后剪贴板可以获取到相同内容。"""
        text = "MySecretPassword123!"
        self.mgr.copy_text(text)

        clipboard = QApplication.clipboard()
        assert clipboard is not None
        assert _read_system_clipboard() == text
        expected_hash = hmac.digest(_CLIPBOARD_HMAC_KEY, text.encode("utf-8"), "sha256")
        assert self.mgr._last_text_hash == expected_hash

    # ---- 自动清空计时器 ----

    def test_auto_clear_timer(self):
        """设置自动清空后计时器正常启动。"""
        self.mgr.clear_seconds = 5
        self.mgr.copy_text("secret")

        assert self.mgr._timer.isActive(), "Timer should be active after copy"
        self.mgr._timer.stop()

    # ---- 取消清空 ----

    def test_cancel_clear(self):
        """取消清空后计时器停止。"""
        self.mgr.clear_seconds = 10
        self.mgr.copy_text("secret")

        assert self.mgr._timer.isActive()
        self.mgr.cancel()
        assert not self.mgr._timer.isActive(), "Timer should be stopped after cancel"

    # ---- 仅清空匹配内容 ----

    def test_clear_only_matching(self):
        """只清空与上次复制匹配的内容。"""
        self.mgr.clear_seconds = 1
        self.mgr.copy_text("password_A")

        # 模拟用户在自动清空之前手动复制了其他内容
        clipboard = QApplication.clipboard()
        assert clipboard is not None
        clipboard.setText("user_typed_something_else")

        # 手动触发清空回调
        self.mgr._clear_clipboard()

        # 剪贴板应保留用户手动复制的内容，不被误清
        assert clipboard.text() == "user_typed_something_else"

    # ---- 空字符串不触发 ----

    def test_empty_copy(self):
        """复制空字符串不触发清空定时器。"""
        self.mgr.copy_text("")

        # _last_text_hash 应保持初始空值，未被设置
        assert self.mgr._last_text_hash == b""
        assert not self.mgr._timer.isActive()

    # ---- fail-safe：text() 抛错时强制清空 ----

    def test_clear_forces_when_text_raises_runtime_error(self):
        """text() 抛 RuntimeError 时按 fail-safe 强制清空（H1 回归守护）。

        X11/远程会话剪贴板被占用时 ``text()`` 读取可能抛 RuntimeError，读取失败即无法
        判定内容，须按「仍可能是密码」matches=True 强制 clear，而非旧实现上抛中断致
        clear 从未执行、hash 未清零、密码无限期残留。直接测 ``_clear_clipboard_mode``
        （用 MagicMock 绕过真实 QClipboard 的 C++ 绑定限制）。
        """
        from unittest.mock import MagicMock

        from PyQt6.QtGui import QClipboard

        mock_clip = MagicMock()
        mock_clip.text.side_effect = RuntimeError("clipboard busy")
        ClipboardManager._clear_clipboard_mode(
            mock_clip, QClipboard.Mode.Clipboard, b"any_expected_hash"
        )
        mock_clip.clear.assert_called_once_with(QClipboard.Mode.Clipboard)
