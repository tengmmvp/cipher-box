"""UI 共享工具函数测试。

覆盖被多个对话框复用的纯函数与 GUI 辅助函数：setup_dialog_flags（移除帮助按钮）、
set_label_severity（severity 动态属性）。
"""

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QDialog, QLabel

from src.ui.components.widgets import set_label_severity, setup_dialog_flags


class TestSetupDialogFlags:
    """setup_dialog_flags 移除对话框帮助按钮。"""

    def test_removes_help_button_hint(self, qapp):
        """调用后应清除对话框的帮助按钮标志。"""
        dialog = QDialog()
        setup_dialog_flags(dialog)
        assert not (dialog.windowFlags() & Qt.WindowType.WindowContextHelpButtonHint)

    def test_preserves_other_flags(self, qapp):
        """仅移除帮助按钮，其余窗口标志应保持不变。"""
        dialog = QDialog()
        original_without_help = dialog.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint
        setup_dialog_flags(dialog)
        assert (
            dialog.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint
        ) == original_without_help

    def test_idempotent(self, qapp):
        """重复调用应保持幂等，不破坏窗口标志。"""
        dialog = QDialog()
        setup_dialog_flags(dialog)
        setup_dialog_flags(dialog)  # 二次调用不应破坏标志
        assert not (dialog.windowFlags() & Qt.WindowType.WindowContextHelpButtonHint)


class TestSetLabelSeverity:
    """set_label_severity 设置 severity 动态属性。"""

    def test_sets_error_severity(self, qapp):
        """传入 error 时应写入对应的 severity 动态属性。"""
        label = QLabel()
        set_label_severity(label, "error")
        assert label.property("severity") == "error"

    def test_sets_success_severity(self, qapp):
        """传入 success 时应写入对应的 severity 动态属性。"""
        label = QLabel()
        set_label_severity(label, "success")
        assert label.property("severity") == "success"

    def test_changes_severity(self, qapp):
        """已设过 severity 后再次设置应覆盖为最新值。"""
        label = QLabel()
        set_label_severity(label, "success")
        set_label_severity(label, "error")
        assert label.property("severity") == "error"
