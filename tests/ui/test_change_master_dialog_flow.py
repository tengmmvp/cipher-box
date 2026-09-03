"""改密对话框流程接线测试：提交→后台 worker→完成/失败/警告文案。

业务层（``VaultManager.change_master_password`` 的全量重加密事务）已由
``tests/business`` 覆盖；本文件守护对话框接线层：``_on_change`` 把旧/新密码闭包
传给后台 worker 并进入 busy 态（按钮禁用 + 明文输入即清）、``_on_change_done``
对成功 / purge 降级警告 / 失败三形态的文案映射与可重试性。模态 ``QMessageBox`` 与
``BackgroundWorker`` 经 monkeypatch 替换，不真正启动 QThread（MAINT-013 同款范式，
参照 ``test_backup_dialog``）。
"""

from unittest.mock import MagicMock

import pytest
from PyQt6.QtWidgets import QMessageBox


def _yes_recorder(cap: dict, key: str):
    """返回一个 mock：记录调用并返回 Yes（供 warning 确认通过）。"""

    def _fn(*args, **kwargs):
        cap.setdefault(key, []).append(args)
        return QMessageBox.StandardButton.Yes

    return _fn


def _recorder(cap: dict, key: str):
    """返回一个 mock：仅记录调用（information/critical 返回值不被使用）。"""

    def _fn(*args, **kwargs):
        cap.setdefault(key, []).append(args)

    return _fn


@pytest.fixture
def patched_modals(monkeypatch):
    """mock 模态对话框与 BackgroundWorker，返回捕获容器。

    warning 返回 Yes 使改密确认通过；information/critical 仅记录；
    BackgroundWorker 替换为捕获任务闭包的假对象，不真正启动 QThread。
    """
    cap: dict = {}

    monkeypatch.setattr(
        "src.ui.dialogs.change_master_dialog.QMessageBox.warning",
        _yes_recorder(cap, "warning"),
    )
    monkeypatch.setattr(
        "src.ui.dialogs.change_master_dialog.QMessageBox.information",
        _recorder(cap, "info"),
    )
    monkeypatch.setattr(
        "src.ui.dialogs.change_master_dialog.QMessageBox.critical",
        _recorder(cap, "critical"),
    )

    class _FakeWorker:
        def __init__(self, run, parent=None):
            cap["run"] = run
            cap["worker"] = self
            self.finished = MagicMock()
            self.error = MagicMock()

        def start(self):
            """不真正启动 QThread：任务闭包由测试按需同步执行。"""

    monkeypatch.setattr("src.ui.dialogs.change_master_dialog.BackgroundWorker", _FakeWorker)
    return cap


def _make_dialog(tmp_path):
    from src.business.services.rate_limiter import RateLimiter
    from src.ui.dialogs.change_master_dialog import ChangeMasterDialog

    vault = MagicMock()
    vault.data_dir = tmp_path
    # 限流器经注入（ARCH-043）：内存态实例（无状态文件）即可驱动对话框接线测试
    return ChangeMasterDialog(vault, RateLimiter())


def _fill_and_submit(dlg, old: str, new: str) -> None:
    """填入三个密码框并触发修改（等价 confirm_pwd 回车/点击修改按钮）。"""
    dlg._old_pwd.setText(old)
    dlg._new_pwd.setText(new)
    dlg._confirm_pwd.setText(new)
    dlg._on_change()


def _arm_worker_callback(dlg, monkeypatch):
    """置当前 worker 并把 sender() 指向它，使 finalize_worker_if_current 通过。"""
    dlg._worker = MagicMock()
    monkeypatch.setattr(dlg, "sender", lambda: dlg._worker)


class TestChangeMasterDialogFlow:
    """改密对话框接线守护：参数传递、busy 态与三形态完成文案。"""

    def test_change_submits_reencryption_and_clears_inputs(self, qapp, patched_modals, tmp_path):
        """_on_change 把旧/新密码经闭包传给 worker 任务，进入 busy 态并即清明文输入。"""
        dlg = _make_dialog(tmp_path)
        dlg._vault.change_master_password.return_value = (True, "")
        _fill_and_submit(dlg, "OldMaster#Password1", "NewMaster#Password2026")

        # worker 已创建且持有重加密任务闭包；执行闭包验证参数接线
        assert dlg._worker is patched_modals["worker"]
        result = patched_modals["run"]()
        dlg._vault.change_master_password.assert_called_once_with(
            "OldMaster#Password1", "NewMaster#Password2026"
        )
        assert result == (True, "")

        # busy 态：按钮禁用、提示重加密中、三个密码框已清（启动即清，缩短明文驻留）
        assert not dlg._change_btn.isEnabled()
        assert "正在重新加密所有数据" in dlg._msg_label.text()
        assert dlg._old_pwd.text() == ""
        assert dlg._new_pwd.text() == ""
        assert dlg._confirm_pwd.text() == ""

    def test_change_done_success_records_and_accepts(
        self, qapp, patched_modals, tmp_path, monkeypatch
    ):
        """重加密成功：record_success、成功文案弹窗并 accept 关闭对话框。"""
        from PyQt6.QtWidgets import QDialog

        dlg = _make_dialog(tmp_path)
        record_success = MagicMock()
        monkeypatch.setattr(dlg._rate_limiter, "record_success", record_success)
        _arm_worker_callback(dlg, monkeypatch)
        dlg._change_btn.setEnabled(False)  # 模拟 busy 态进入完成回调

        dlg._on_change_done((True, ""))

        record_success.assert_called_once()
        assert any("主密码已修改成功" in str(arg) for arg in patched_modals["info"])
        assert dlg.result() == QDialog.DialogCode.Accepted.value
        assert dlg._change_btn.isEnabled()

    def test_change_done_success_appends_purge_warning(
        self, qapp, patched_modals, tmp_path, monkeypatch
    ):
        """成功但 purge 降级时：warning 文案拼接在成功文案后一并提示用户手动清理。"""
        dlg = _make_dialog(tmp_path)
        _arm_worker_callback(dlg, monkeypatch)
        warning = "部分旧快照/恢复点清理失败，建议手动清理以收缩历史明文泄漏面"

        dlg._on_change_done((True, warning))

        joined = "\n\n".join(str(arg) for arg in patched_modals["info"][0])
        assert "主密码已修改成功" in joined
        assert warning in joined

    def test_change_done_failure_keeps_retryable(self, qapp, patched_modals, tmp_path, monkeypatch):
        """认证失败：错误文案透传到状态栏、计入限流、按钮复位可重试、不关闭。

        ARCH-042 契约下 (False, ...) 唯一语义为认证失败（旧主密码错误），一律计入
        速率限制；系统/策略错误走 _on_change_error 异常通道（见下个测试）。
        """
        from PyQt6.QtWidgets import QDialog

        from src.business.managers.vault_lifecycle import CHANGE_AUTH_FAILED_MESSAGE

        dlg = _make_dialog(tmp_path)
        _arm_worker_callback(dlg, monkeypatch)
        dlg._change_btn.setEnabled(False)

        dlg._on_change_done((False, CHANGE_AUTH_FAILED_MESSAGE))

        assert dlg._msg_label.text() == CHANGE_AUTH_FAILED_MESSAGE
        assert dlg._rate_limiter.fail_count == 1  # 认证失败计入速率限制
        assert dlg._change_btn.isEnabled()
        assert dlg.result() == QDialog.DialogCode.Rejected.value

    def test_change_error_never_counts_toward_rate_limit(
        self, qapp, patched_modals, tmp_path, monkeypatch
    ):
        """系统/策略错误经异常通道呈现：不计入速率限制，不惩罚遭遇故障的用户。"""
        dlg = _make_dialog(tmp_path)
        _arm_worker_callback(dlg, monkeypatch)
        dlg._change_btn.setEnabled(False)

        dlg._on_change_error("新密码不能与当前主密码相同")

        assert any("新密码不能与当前主密码相同" in str(arg) for arg in patched_modals["critical"])
        assert dlg._rate_limiter.fail_count == 0
        assert dlg._change_btn.isEnabled()

    def test_change_error_shows_critical_and_reenables(
        self, qapp, patched_modals, tmp_path, monkeypatch
    ):
        """worker 异常路径：错误文本经 critical 弹窗呈现，按钮复位可重试。"""
        dlg = _make_dialog(tmp_path)
        _arm_worker_callback(dlg, monkeypatch)
        dlg._change_btn.setEnabled(False)

        dlg._on_change_error("后台线程异常退出")

        assert any("后台线程异常退出" in str(arg) for arg in patched_modals["critical"])
        assert dlg._change_btn.isEnabled()
        assert dlg._msg_label.text() == ""
