"""UI 共享工具函数测试。

覆盖被多个对话框复用的纯函数与 GUI 辅助函数：setup_dialog_flags（移除帮助按钮）、
set_label_severity（severity 动态属性）。这些函数原先仅经集成测试间接覆盖，
本测试补充直接单元覆盖以加强回归保护。
"""

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QDialog, QLabel

from src.ui.components.widgets import set_label_severity, setup_dialog_flags


class TestSetupDialogFlags:
    """setup_dialog_flags 移除对话框帮助按钮。"""

    def test_removes_help_button_hint(self, qapp):
        dialog = QDialog()
        setup_dialog_flags(dialog)
        assert not (dialog.windowFlags() & Qt.WindowType.WindowContextHelpButtonHint)

    def test_preserves_other_flags(self, qapp):
        dialog = QDialog()
        original_without_help = dialog.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint
        setup_dialog_flags(dialog)
        assert (dialog.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint) == original_without_help

    def test_idempotent(self, qapp):
        dialog = QDialog()
        setup_dialog_flags(dialog)
        setup_dialog_flags(dialog)  # 二次调用不应破坏标志
        assert not (dialog.windowFlags() & Qt.WindowType.WindowContextHelpButtonHint)


class TestSetLabelSeverity:
    """set_label_severity 设置 severity 动态属性。"""

    def test_sets_error_severity(self, qapp):
        label = QLabel()
        set_label_severity(label, 'error')
        assert label.property('severity') == 'error'

    def test_sets_success_severity(self, qapp):
        label = QLabel()
        set_label_severity(label, 'success')
        assert label.property('severity') == 'success'

    def test_changes_severity(self, qapp):
        label = QLabel()
        set_label_severity(label, 'success')
        set_label_severity(label, 'error')
        assert label.property('severity') == 'error'
