"""ImportExportDialog 接线测试：控件值 → 业务参数 → worker 结果呈现。

范式同 ``test_backup_dialog``（MAINT-013 接线守护）：mock 业务 manager，patch
模态 ``QMessageBox`` 与 ``BackgroundWorker``（捕获任务闭包不真启 QThread），
设控件值后触发动作、模拟 worker 线程执行闭包，断言对话框→manager 的传参：

- 导出：「包含密码」单选 → get_entries_for_export 的 include_secrets 实参，
  格式下拉 → export_to_json/export_to_csv 分发；
- 导入：三种去重策略下拉 → import_file 的 duplicate_action 实参；
- worker 错误路径：业务异常经 error 信号文案呈现失败状态，busy 复位不崩溃。

不深入导入后的缓存语义（由业务层测试覆盖），只守护传参接线。
"""

from unittest.mock import MagicMock

import pytest
from PyQt6.QtWidgets import QMessageBox


def _yes(cap: dict, key: str):
    """返回记录调用并返回 Yes 的函数（供确认类模态通过）。"""

    def _fn(*args, **kwargs):
        cap.setdefault(key, []).append(args)
        return QMessageBox.StandardButton.Yes

    return _fn


def _no(cap: dict, key: str):
    """返回记录调用并返回 No 的函数（供拒绝类分支测试）。"""

    def _fn(*args, **kwargs):
        cap.setdefault(key, []).append(args)
        return QMessageBox.StandardButton.No

    return _fn


def _fake_worker_factory(cap: dict):
    """构造假 BackgroundWorker：捕获任务闭包，不真启 QThread。"""

    def _fake_worker(run, parent=None):
        cap["run"] = run
        worker = MagicMock()
        worker.is_cancelled = False
        return worker

    return _fake_worker


@pytest.fixture
def wired(monkeypatch):
    """patch 确认类模态为 Yes + 假 BackgroundWorker，返回捕获容器。"""
    cap: dict = {}
    monkeypatch.setattr(
        "src.ui.dialogs.import_export_dialog.QMessageBox.warning", _yes(cap, "warning")
    )
    monkeypatch.setattr(
        "src.ui.dialogs.import_export_dialog.QMessageBox.information", _yes(cap, "info")
    )
    monkeypatch.setattr(
        "src.ui.dialogs.import_export_dialog.QMessageBox.question", _yes(cap, "question")
    )
    monkeypatch.setattr(
        "src.ui.dialogs.import_export_dialog.BackgroundWorker", _fake_worker_factory(cap)
    )
    return cap


def _make_dialog():
    """构造注入 mock manager 的对话框，返回 (dlg, import_export, entry_mgr)。"""
    from src.ui.dialogs.import_export_dialog import ImportExportDialog

    entry_mgr = MagicMock()
    entry_mgr.get_entries_for_export.return_value = []
    import_export = MagicMock()
    dlg = ImportExportDialog(import_export, entry_mgr)
    dlg._selected_path = "/tmp/cipherbox_export.json"
    return dlg, import_export, entry_mgr


class TestExportWiring:
    """导出：包含密码单选 → include_secrets 实参；格式下拉 → 分发。"""

    def test_include_password_checked_passes_true(self, qapp, wired):
        """勾选「包含密码」→ get_entries_for_export 收到 include_secrets=True。"""
        dlg, import_export, entry_mgr = _make_dialog()
        dlg._include_pwd_radio.setChecked(True)

        dlg._do_export("/tmp/cipherbox_export.json")
        wired["run"]()

        call = entry_mgr.get_entries_for_export.call_args
        assert call.args[0] is True
        assert call.kwargs.get("cancel_check") is not None
        # 二次确认警告必须弹出（明文风险提示）
        assert wired["warning"]
        import_export.export_to_json.assert_called_once()

    def test_include_password_unchecked_passes_false(self, qapp, wired):
        """不勾选（默认）→ include_secrets=False，走 information 提示而非警告。"""
        dlg, import_export, entry_mgr = _make_dialog()
        assert dlg._exclude_pwd_radio.isChecked()  # 默认不包含密码

        dlg._do_export("/tmp/cipherbox_export.json")
        wired["run"]()

        assert entry_mgr.get_entries_for_export.call_args.args[0] is False
        # 不含密码走安全提示（information），不应弹明文风险警告（warning）
        assert wired["info"]
        assert "warning" not in wired  # 记录器仅在真实调用时建键

    def test_include_password_flag_forwarded_to_serializer(self, qapp, wired):
        """include_secrets 实参透传到 export_to_json（控制序列化是否含密码列）。"""
        dlg, import_export, _ = _make_dialog()
        dlg._include_pwd_radio.setChecked(True)

        dlg._do_export("/tmp/cipherbox_export.json")
        wired["run"]()

        call = import_export.export_to_json.call_args
        assert call.args[0] == "/tmp/cipherbox_export.json"
        assert call.args[2] is True  # (path, entries, include_password)

    def test_csv_format_dispatches_to_csv_exporter(self, qapp, wired):
        """格式选 CSV → 走 export_to_csv，不调 export_to_json。"""
        dlg, import_export, _ = _make_dialog()
        dlg._format_combo.setCurrentIndex(1)

        dlg._do_export("/tmp/cipherbox_export.csv")
        wired["run"]()

        import_export.export_to_csv.assert_called_once()
        import_export.export_to_json.assert_not_called()

    def test_declined_confirmation_starts_no_worker(self, qapp, monkeypatch):
        """用户在明文风险警告上选「否」→ 不启动 worker、不触发导出采集。"""
        cap: dict = {}
        monkeypatch.setattr(
            "src.ui.dialogs.import_export_dialog.QMessageBox.warning", _no(cap, "warning")
        )
        monkeypatch.setattr(
            "src.ui.dialogs.import_export_dialog.BackgroundWorker", _fake_worker_factory(cap)
        )
        dlg, import_export, entry_mgr = _make_dialog()
        dlg._include_pwd_radio.setChecked(True)

        dlg._do_export("/tmp/cipherbox_export.json")

        assert "run" not in cap  # worker 未启动
        entry_mgr.get_entries_for_export.assert_not_called()
        import_export.export_to_json.assert_not_called()


class TestImportWiring:
    """导入：去重策略下拉 → import_file 的 duplicate_action 实参。"""

    @pytest.mark.parametrize(
        ("combo_idx", "expected_action"),
        [
            (0, "skip"),  # 跳过已有条目
            (1, "overwrite"),  # 覆盖已有条目
            (2, "import_all"),  # 仍然全部导入
        ],
        ids=["skip", "overwrite", "import_all"],
    )
    def test_duplicate_strategy_forwarded_to_import_file(
        self, qapp, wired, combo_idx, expected_action
    ):
        """三种去重策略单选 → import_file 的 duplicate_action 实参一一对应。"""
        dlg, import_export, _ = _make_dialog()
        # 切到导入模式：buttonClicked 仅经用户点击触发，测试手动驱动模式切换回调
        dlg._mode_group.button(1).setChecked(True)
        dlg._on_mode_changed()
        assert dlg._is_export is False
        dlg._duplicate_combo.setCurrentIndex(combo_idx)
        path = "/tmp/import.json"
        dlg._selected_path = path

        dlg._do_import(path)
        wired["run"]()

        call = import_export.import_file.call_args
        assert call.args[0] == path
        assert call.args[1] == "json"  # 默认格式 JSON (CipherBox)
        assert call.kwargs["duplicate_action"] == expected_action

    def test_import_confirmation_shows_current_strategy_text(self, qapp, wired):
        """确认对话框弹出且正文含当前去重策略文案（用户可预期的操作确认）。"""
        dlg, _, _ = _make_dialog()
        dlg._mode_group.button(1).setChecked(True)
        dlg._on_mode_changed()
        dlg._duplicate_combo.setCurrentIndex(1)  # 覆盖已有条目
        dlg._selected_path = "/tmp/import.json"

        dlg._do_import("/tmp/import.json")

        assert wired["question"]
        assert any("覆盖已有条目" in str(arg) for arg in wired["question"][0])

    def test_import_worker_marked_uncancellable(self, qapp, wired):
        """导入 worker 启动时记录 _worker_is_export=False（关闭时等待而非取消）。"""
        dlg, _, _ = _make_dialog()
        dlg._mode_group.button(1).setChecked(True)
        dlg._on_mode_changed()
        dlg._selected_path = "/tmp/import.json"

        dlg._do_import("/tmp/import.json")

        assert dlg._worker_is_export is False


class TestWorkerErrorPaths:
    """worker 错误路径：异常文案呈现失败状态，busy 复位，对话框不崩溃。"""

    def _simulate_busy(self, dlg, monkeypatch):
        """置 busy 态并以 sentinel worker 模拟运行中回调来源。"""
        dlg._set_busy(True)
        sentinel = MagicMock()
        dlg._worker = sentinel
        monkeypatch.setattr(dlg, "sender", lambda: sentinel)

    def test_export_error_shows_failure_state(self, qapp, wired, monkeypatch):
        """导出失败：状态标签含错误文案、主按钮恢复可用、worker 引用释放。"""
        dlg, _, _ = _make_dialog()
        self._simulate_busy(dlg, monkeypatch)

        dlg._on_export_error("数据可能已损坏")

        assert "导出失败" in dlg._status_label.text()
        assert "数据可能已损坏" in dlg._status_label.text()
        assert dlg._action_btn.isEnabled()  # busy 复位
        assert dlg._worker is None  # 当前 worker 已释放

    def test_import_error_shows_failure_state(self, qapp, wired, monkeypatch):
        """导入失败：状态标签含错误文案、busy 复位，不崩溃。"""
        dlg, _, _ = _make_dialog()
        self._simulate_busy(dlg, monkeypatch)

        dlg._on_import_error("文件格式无效")

        assert "导入失败" in dlg._status_label.text()
        assert "文件格式无效" in dlg._status_label.text()
        assert dlg._action_btn.isEnabled()

    def test_stale_worker_error_is_ignored(self, qapp, wired, monkeypatch):
        """过期 worker 的 error 回调被忽略（不覆盖新一轮操作的状态）。"""
        dlg, _, _ = _make_dialog()
        dlg._set_busy(True)
        stale = MagicMock()
        dlg._worker = MagicMock()  # 当前 worker 已换新
        monkeypatch.setattr(dlg, "sender", lambda: stale)

        dlg._on_export_error("过期消息")

        # 过期回调未复位 busy：主按钮仍禁用，状态非失败文案
        assert not dlg._action_btn.isEnabled()

    def test_export_done_success_text(self, qapp, wired, monkeypatch):
        """导出成功：呈现成功文案与条数，busy 复位（selected_path 为空跳过权限收紧）。"""
        dlg, _, _ = _make_dialog()
        dlg._selected_path = None
        self._simulate_busy(dlg, monkeypatch)

        dlg._on_export_done(3)

        assert "成功导出 3 条记录" in dlg._status_label.text()
        assert dlg._action_btn.isEnabled()

    def test_import_done_success_emits_completed(self, qapp, wired, monkeypatch):
        """导入成功（>0 条）：呈现成功文案并 emit import_completed 供外部刷新。"""
        dlg, _, _ = _make_dialog()
        emitted: list[bool] = []
        dlg.import_completed.connect(lambda: emitted.append(True))
        self._simulate_busy(dlg, monkeypatch)

        dlg._on_import_done(5)

        assert "成功导入 5 条记录" in dlg._status_label.text()
        assert emitted == [True]

    def test_import_done_zero_does_not_emit(self, qapp, wired, monkeypatch):
        """导入 0 条：不 emit import_completed（无数据变更）。"""
        dlg, _, _ = _make_dialog()
        emitted: list[bool] = []
        dlg.import_completed.connect(lambda: emitted.append(True))
        self._simulate_busy(dlg, monkeypatch)

        dlg._on_import_done(0)

        assert emitted == []
