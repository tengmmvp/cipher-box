"""ClipboardManager 单元测试"""

import sys
import pytest
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import QTimer

from src.utils.clipboard import ClipboardManager


# ---------------------------------------------------------------------------
# 确保 QApplication 单例存在（PyQt6 要求）
# ---------------------------------------------------------------------------
_app = QApplication.instance()
if _app is None:
    _app = QApplication(sys.argv)


class TestClipboardManager:
    """ClipboardManager 核心逻辑测试"""

    def setup_method(self):
        self.mgr = ClipboardManager(clear_seconds=30)

    # ---- 基础复制与获取 ----

    def test_copy_and_get(self):
        """复制文本后剪贴板可以获取到相同内容"""
        text = "MySecretPassword123!"
        self.mgr.copy_text(text)

        clipboard = QApplication.clipboard()
        assert clipboard.text() == text
        assert self.mgr._last_copied == text

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

    def test_clear_only_matching(self, qapp):
        """只清空与上次复制匹配的内容"""
        self.mgr.clear_seconds = 1
        self.mgr.copy_text("password_A")

        # 模拟用户在自动清空之前手动复制了其他内容
        clipboard = QApplication.clipboard()
        clipboard.setText("user_typed_something_else")

        # 手动触发清空回调
        self.mgr._clear_clipboard()

        # 剪贴板应保留用户手动复制的内容，不被误清
        assert clipboard.text() == "user_typed_something_else"

    # ---- 空字符串不触发 ----

    def test_empty_copy(self):
        """复制空字符串不触发清空定时器"""
        self.mgr.copy_text("")

        clipboard = QApplication.clipboard()
        # _last_copied 应保持初始空字符串，未被设置
        assert self.mgr._last_copied == ''
        assert not self.mgr._timer.isActive()


# ---------------------------------------------------------------------------
# pytest-qt 插件兼容：提供 qapp fixture（若未安装 pytest-qt）
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def qapp():
    """返回已创建的 QApplication 单例，供需要 qapp fixture 的测试使用。"""
    return QApplication.instance() or QApplication(sys.argv)
