"""SecurityDashboard 接线测试：报告数据→健康评分/统计卡片/列表渲染（P3-17）。

业务层（``SecurityAnalyzer.get_or_compute_report``/``compute_health_score``）已由
``tests/business`` 充分覆盖；本文件守护「后台 worker 回调→控件渲染」接线层，
防止健康评分公式错位、统计卡片计数漂移、列表填充与修复入口回归逃过测试。

后台 ``BackgroundWorker`` 经 monkeypatch 替换为捕获任务闭包的假对象，避免真实
``QThread`` 异步——聚焦「报告数据→控件状态」这一同步渲染契约。
"""

from __future__ import annotations

import dataclasses
from unittest.mock import MagicMock

import pytest
from PyQt6.QtWidgets import QDialog, QLabel, QPushButton

from src.business.services.security_analyzer import SecurityAnalyzer
from src.config import CFG_OLD_PASSWORD_WARNING_DAYS
from src.models import Entry
from tests.helpers import make_test_config


def _entry(entry_id: int, **overrides) -> Entry:
    """构造测试用明文 Entry：id 必填，其余字段用默认空值，可经 overrides 覆盖。"""
    return dataclasses.replace(Entry(id=entry_id), **overrides)


def _report(*, weak=None, duplicates=None, old=None, total=0) -> dict:
    """构造 ``get_or_compute_report`` 风格的报告字典，供 _on_data_loaded 消费。"""
    return {
        "total": total,
        "weak_entries": list(weak or []),
        "duplicate_groups": list(duplicates or []),
        "old_entries": list(old or []),
    }


@pytest.fixture
def patched_worker(monkeypatch):
    """mock ``BackgroundWorker``：捕获任务闭包但不启动真实 QThread。

    返回捕获容器：``cap["run"]`` 为 worker 任务闭包。假 worker 预置
    ``isRunning()->False`` 与 ``cancel_check()->False``，使对话框关闭路径
    （``_prepare_close``→``wait_worker_shutdown``）在 worker 已释放后不阻塞。
    """
    cap: dict = {}

    def _fake_worker(run, parent=None):
        cap["run"] = run
        worker = MagicMock()
        worker.isRunning.return_value = False
        worker.cancel_check.return_value = False
        return worker

    monkeypatch.setattr("src.ui.dialogs.security_dashboard.BackgroundWorker", _fake_worker)
    return cap


def _make_dialog(tmp_path):
    """构造 SecurityDashboard：security/entry_mgr 用 mock，config 用真实测试实例。"""
    from src.ui.dialogs.security_dashboard import SecurityDashboard

    security = MagicMock()
    entry_mgr = MagicMock()
    config = make_test_config(tmp_path)
    return SecurityDashboard(security, entry_mgr, config), security, config


def _deliver_report(dlg, monkeypatch, analysis: dict) -> None:
    """模拟 worker.finished 信号投递：让 sender() 返回当前 worker 后调用 _on_data_loaded。

    ``_on_data_loaded`` 入口校验 ``self.sender() is self._worker`` 防 reject 后旧 worker
    回调；此处把 ``sender`` 桩为 ``dlg._worker`` 使守卫通过，复现真实信号路径。
    """
    monkeypatch.setattr(dlg, "sender", lambda: dlg._worker)
    dlg._on_data_loaded(analysis)


class TestSecurityDashboardRendering:
    """SecurityDashboard 接线守护：报告数据→健康评分/统计卡片/列表渲染。"""

    def test_health_score_and_stat_cards_reflect_counts(
        self, qapp, tmp_path, patched_worker, monkeypatch
    ):
        """给定弱/重复组/过期计数与 total，健康评分与三张统计卡片渲染对应数值。"""
        from src.ui.dialogs.security_dashboard import _HealthScoreWidget
        from src.ui.resources.theme_colors import c

        dlg, _, _ = _make_dialog(tmp_path)
        weak = [_entry(1), _entry(2)]
        duplicates = [[_entry(3), _entry(4)]]
        old = [_entry(5), _entry(6), _entry(7)]
        report = _report(weak=weak, duplicates=duplicates, old=old, total=100)

        _deliver_report(dlg, monkeypatch, report)

        # 健康评分：weak=2 / 重复组=1 / old=3 / total=100 → 100-(30+10+15)=45
        expected = 45
        assert dlg._health_widget._score == expected
        assert SecurityAnalyzer.compute_health_score(2, 1, 3, 100) == expected
        # 45 分落在 40≤score<60 区间，应映射到 warning_orange 颜色 token
        assert _HealthScoreWidget._health_score_color(expected) == c("warning_orange")

        # 统计卡片计数：弱密码=2、重复密码=1（按组计）、过期=3
        assert dlg._weak_card._count_label.text() == "2"
        assert dlg._dup_card._count_label.text() == "1"
        assert dlg._old_card._count_label.text() == "3"

    def test_weak_tab_populates_rows_with_strength_badge(
        self, qapp, tmp_path, patched_worker, monkeypatch
    ):
        """弱密码 tab 为每条弱密码生成一行，标题按条目 title、徽章按强度渲染。"""
        dlg, _, _ = _make_dialog(tmp_path)
        weak = [
            _entry(10, title="GitHub", username="alice", password_strength=1),
            _entry(11, title="Twitter", username="", password_strength=0),
        ]
        _deliver_report(dlg, monkeypatch, _report(weak=weak, total=10))

        titles = [
            lbl.text()
            for lbl in dlg._weak_container.findChildren(QLabel)
            if lbl.objectName() == "secRowTitle"
        ]
        assert titles == ["GitHub", "Twitter"]

        badges = [
            lbl.text()
            for lbl in dlg._weak_container.findChildren(QLabel)
            if lbl.text().startswith("强度")
        ]
        assert badges == ["强度 1", "强度 0"]

    def test_duplicate_tab_populates_groups(self, qapp, tmp_path, patched_worker, monkeypatch):
        """重复密码 tab 按组展示，每组标注被共用的条目数并列出成员。"""
        dlg, _, _ = _make_dialog(tmp_path)
        group = [
            _entry(20, title="Site A", username="a"),
            _entry(21, title="Site B", username="b"),
        ]
        _deliver_report(dlg, monkeypatch, _report(duplicates=[group], total=5))

        group_labels = [
            lbl.text()
            for lbl in dlg._dup_container.findChildren(QLabel)
            if lbl.objectName() == "dupGroupLabel"
        ]
        assert group_labels == ["同一密码被 2 个条目使用"]

        titles = [
            lbl.text()
            for lbl in dlg._dup_container.findChildren(QLabel)
            if lbl.objectName() == "secRowTitle"
        ]
        assert titles == ["Site A", "Site B"]

    def test_old_tab_populates_entries_with_days_badge(
        self, qapp, tmp_path, patched_worker, monkeypatch
    ):
        """过期密码 tab 展示条目，徽章用 config 的过期天数阈值。"""
        dlg, _, config = _make_dialog(tmp_path)
        days = config.get(CFG_OLD_PASSWORD_WARNING_DAYS)
        old = [_entry(30, title="Old Site", password_changed_at="2024-01-01 00:00:00")]
        _deliver_report(dlg, monkeypatch, _report(old=old, total=5))

        titles = [
            lbl.text()
            for lbl in dlg._old_container.findChildren(QLabel)
            if lbl.objectName() == "secRowTitle"
        ]
        assert titles == ["Old Site"]

        badges = [
            lbl.text()
            for lbl in dlg._old_container.findChildren(QLabel)
            if lbl.text().startswith(">")
        ]
        assert badges == [f"> {days}天"]

    def test_empty_report_shows_full_score_and_hints(
        self, qapp, tmp_path, patched_worker, monkeypatch
    ):
        """空报告（无任何风险）展示健康评分 100 与三个 tab 的空态提示。"""
        dlg, _, _ = _make_dialog(tmp_path)
        _deliver_report(dlg, monkeypatch, _report(total=0))

        assert dlg._health_widget._score == 100
        # 三张统计卡片均显示 0
        assert dlg._weak_card._count_label.text() == "0"
        assert dlg._dup_card._count_label.text() == "0"
        assert dlg._old_card._count_label.text() == "0"

        weak_hints = [
            lbl.text()
            for lbl in dlg._weak_container.findChildren(QLabel)
            if lbl.objectName() == "secEmptyHint"
        ]
        assert weak_hints == ["没有发现弱密码，做得好！"]
        dup_hints = [
            lbl.text()
            for lbl in dlg._dup_container.findChildren(QLabel)
            if lbl.objectName() == "secEmptyHint"
        ]
        assert dup_hints == ["没有发现重复密码。"]
        old_hints = [
            lbl.text()
            for lbl in dlg._old_container.findChildren(QLabel)
            if lbl.objectName() == "secEmptyHint"
        ]
        assert old_hints == ["没有过期密码。"]

    def test_fix_button_records_pending_id_and_accepts(
        self, qapp, tmp_path, patched_worker, monkeypatch
    ):
        """点击弱密码条目的「修复」按钮记录 entry_id 并 accept 退出对话框。"""
        dlg, _, _ = _make_dialog(tmp_path)
        _deliver_report(
            dlg,
            monkeypatch,
            _report(weak=[_entry(42, title="Weak", password_strength=0)], total=5),
        )

        fix_btns = [
            b
            for b in dlg._weak_container.findChildren(QPushButton)
            if b.objectName() == "secFixBtn"
        ]
        assert len(fix_btns) == 1
        fix_btns[0].click()

        assert dlg.pending_fix_id == 42
        assert dlg.result() == QDialog.DialogCode.Accepted

    def test_load_data_passes_config_days_to_analyzer(
        self, qapp, tmp_path, patched_worker, monkeypatch
    ):
        """_load_data 读取 config 过期天数，并经 worker 闭包传给 get_or_compute_report。"""
        dlg, security, config = _make_dialog(tmp_path)
        expected_days = config.get(CFG_OLD_PASSWORD_WARNING_DAYS)
        security.get_or_compute_report.return_value = _report(total=0)

        # 执行捕获的 worker 任务闭包，模拟后台线程运行
        result = patched_worker["run"]()

        security.get_or_compute_report.assert_called_once()
        call = security.get_or_compute_report.call_args
        assert call.args[0] == expected_days
        assert callable(call.kwargs.get("cancel_check"))
        assert result["total"] == 0
