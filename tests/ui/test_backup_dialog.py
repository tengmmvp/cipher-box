"""BackupDialog 接线测试：控件值→业务参数→结果文案（MAINT-013）。

业务层（``BackupRestoreManager.create_backup/restore_backup``、``inspect_backup``）已由
``tests/business`` 充分覆盖；本文件守护「对话框控件值→正确业务参数→领域结果→用户文案」
接线层，防止控件默认值漂移、参数错位、异常文案回归逃过测试。

模态对话框（``QInputDialog``/``QMessageBox``/``QFileDialog``）与 ``BackgroundWorker`` 经 monkeypatch
替换，避免真实模态阻塞与 ``QThread`` 异步——聚焦「参数传递与文案映射」这一同步接线契约。
"""

from unittest.mock import MagicMock

import pytest
from PyQt6.QtWidgets import QMessageBox


def _yes_recorder(cap: dict, key: str):
    """返回一个 mock：记录调用并返回 Yes（供 warning/question 确认通过）。"""

    def _fn(*args, **kwargs):
        cap.setdefault(key, []).append(args)
        return QMessageBox.StandardButton.Yes

    return _fn


def _recorder(cap: dict, key: str):
    """返回一个 mock：仅记录调用（information/critical 返回值不被使用）。"""

    def _fn(*args, **kwargs):
        cap.setdefault(key, []).append(args)
        return None

    return _fn


@pytest.fixture
def patched_modals(monkeypatch):
    """mock 模态对话框与 BackgroundWorker，返回捕获容器。

    - QInputDialog 不在此处 mock：backup/restore 的密码输入由各测试按需注入
      （调用次数与返回值因路径而异，集中 mock 会掩盖接线差异）。
    - warning/question 返回 Yes 使危险操作确认通过；information/critical 仅记录。
    - BackgroundWorker 替换为捕获任务闭包的假对象，不真正启动 QThread。
    """
    cap: dict = {}

    monkeypatch.setattr(
        "src.ui.dialogs.backup_dialog.QMessageBox.information",
        _recorder(cap, "info"),
    )
    monkeypatch.setattr(
        "src.ui.dialogs.backup_dialog.QMessageBox.critical",
        _recorder(cap, "critical"),
    )
    monkeypatch.setattr(
        "src.ui.dialogs.backup_dialog.QMessageBox.warning",
        _yes_recorder(cap, "warning"),
    )
    monkeypatch.setattr(
        "src.ui.dialogs.backup_dialog.QMessageBox.question",
        _yes_recorder(cap, "question"),
    )

    def _fake_worker(run, parent=None):
        cap["run"] = run
        worker = MagicMock()
        worker.is_cancelled = False
        return worker

    monkeypatch.setattr("src.ui.dialogs.backup_dialog.BackgroundWorker", _fake_worker)
    return cap


def _make_dialog():
    from src.ui.dialogs.backup_dialog import BackupDialog

    return BackupDialog(MagicMock())


class TestBackupDialogWiring:
    """BackupDialog 接线守护：业务结果→UI 状态与文案、控件值→业务参数。"""

    def test_backup_done_success_sets_state_and_text(self, qapp, patched_modals, monkeypatch):
        """_on_backup_done 成功：标记 data_changed、置成功状态、弹成功框。"""
        dlg = _make_dialog()
        dlg._worker = MagicMock()  # sentinel：sender() 与之比较通过
        monkeypatch.setattr(dlg, "sender", lambda: dlg._worker)
        dlg._on_backup_done((True, ""))
        assert dlg.data_changed is True
        assert "成功" in dlg._status_label.text()
        assert patched_modals["info"]

    def test_backup_done_failure_shows_business_error_text(self, qapp, patched_modals, monkeypatch):
        """_on_backup_done 失败：置失败状态并把业务返回的错误文案呈现给用户。"""
        dlg = _make_dialog()
        dlg._worker = MagicMock()
        monkeypatch.setattr(dlg, "sender", lambda: dlg._worker)
        dlg._on_backup_done((False, "备份密码不正确"))
        assert "失败" in dlg._status_label.text()
        # 关键接线：业务错误文案须透传到用户可见的 critical 对话框
        assert any("备份密码不正确" in str(arg) for arg in patched_modals["critical"])

    def test_do_backup_passes_path_and_password_to_manager(self, qapp, patched_modals, monkeypatch):
        """_do_backup 把所选路径与两次输入一致的密码传给 create_backup。"""
        from src.ui.dialogs.backup_dialog import BackupDialog

        # 两次 QInputDialog：设置密码 + 确认密码，返回一致的强密码
        inputs = iter([("StrongPwd!2026", True), ("StrongPwd!2026", True)])
        monkeypatch.setattr(
            "src.ui.dialogs.backup_dialog.QInputDialog.getText",
            lambda *a, **k: next(inputs),
        )
        monkeypatch.setattr(
            "src.ui.dialogs.backup_dialog.PasswordService.validate_master_password",
            lambda *a, **k: (True, ""),
        )
        mgr = MagicMock()
        mgr.create_backup.return_value = (True, "")
        dlg = BackupDialog(mgr)
        dlg._do_backup("/tmp/test.cbox")
        # 模拟 worker 线程执行捕获的任务闭包
        result = patched_modals["run"]()
        mgr.create_backup.assert_called_once()
        call = mgr.create_backup.call_args
        assert call.args[0] == "/tmp/test.cbox"
        assert call.args[1] == "StrongPwd!2026"
        assert call.kwargs.get("cancel_check") is not None
        assert result == (True, "")

    def test_do_restore_passes_path_and_password_to_manager(
        self, qapp, patched_modals, monkeypatch
    ):
        """_do_restore 把路径与输入密码传给 restore_backup（password_required 路径）。"""
        from src.ui.dialogs.backup_dialog import BackupDialog

        monkeypatch.setattr(
            "src.ui.dialogs.backup_dialog.inspect_backup",
            lambda p: {"password_required": True},
        )
        monkeypatch.setattr(
            "src.ui.dialogs.backup_dialog.QInputDialog.getText",
            lambda *a, **k: ("RestorePwd!2026", True),
        )
        mgr = MagicMock()
        mgr.restore_backup.return_value = (True, "")
        dlg = BackupDialog(mgr)
        dlg._do_restore("/tmp/backup.cbox")
        result = patched_modals["run"]()
        mgr.restore_backup.assert_called_once_with("/tmp/backup.cbox", "RestorePwd!2026")
        assert result == (True, "")
