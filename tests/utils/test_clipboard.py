"""ClipboardManager 单元测试。

覆盖剪贴板复制与读取、自动清空计时器启停、取消清空、仅清空匹配内容以避免
误清用户后续复制，以及空字符串不触发清空等核心行为。
"""

import hmac

import pytest
from PyQt6.QtWidgets import QApplication

from src.utils.clipboard import _CLIPBOARD_HMAC_KEY, ClipboardManager


class TestClipboardManager:
    """ClipboardManager 核心逻辑测试"""

    @pytest.fixture(autouse=True)
    def _ensure_qapp(self, qapp):
        """在 setup_method 之前确保 QApplication 已创建。"""
        self._qapp = qapp

    def setup_method(self):
        self.mgr = ClipboardManager(clear_seconds=30)

    # ---- 基础复制与获取 ----

    def test_copy_and_get(self):
        """复制文本后剪贴板可以获取到相同内容"""
        text = "MySecretPassword123!"
        self.mgr.copy_text(text)

        clipboard = QApplication.clipboard()
        assert clipboard is not None
        assert clipboard.text() == text
        expected_hash = hmac.digest(_CLIPBOARD_HMAC_KEY, text.encode('utf-8'), 'sha256')
        assert self.mgr._last_text_hash == expected_hash

    # ---- 自动清空计时器 ----

    def test_auto_clear_timer(self):
        """设置自动清空后计时器正常启动"""
        self.mgr.clear_seconds = 5
        self.mgr.copy_text("secret")

        assert self.mgr._timer.isActive(), "Timer should be active after copy"
        self.mgr._timer.stop()

    # ---- 取消清空 ----

    def test_cancel_clear(self):
        """取消清空后计时器停止"""
        self.mgr.clear_seconds = 10
        self.mgr.copy_text("secret")

        assert self.mgr._timer.isActive()
        self.mgr.cancel()
        assert not self.mgr._timer.isActive(), "Timer should be stopped after cancel"

    # ---- 仅清空匹配内容 ----

    def test_clear_only_matching(self):
        """只清空与上次复制匹配的内容"""
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
        """复制空字符串不触发清空定时器"""
        self.mgr.copy_text("")

        # _last_text_hash 应保持初始空值，未被设置
        assert self.mgr._last_text_hash == b''
        assert not self.mgr._timer.isActive()
