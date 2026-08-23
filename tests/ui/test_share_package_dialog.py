"""SharePackageDialog 接线测试：共享密码预校验与 worker 启动（QL-028）。

业务层（``create_share_package`` 的加密/双文件原子写）已由 ``tests/business`` 覆盖；
本文件守护「密码框输入→预校验门禁→worker 启动」接线层：UI 预校验必须与业务层
``PasswordService.validate_master_password``（≥15 字符 + 强度检查）同口径，弱密码在
提交前被拦截并展示业务层文案，而不是过门禁后到 worker 才以 ShareError 失败。

``QMessageBox.warning`` 与 ``BackgroundWorker`` 经 monkeypatch 替换，避免真实模态
阻塞与 ``QThread`` 异步；``create_share_package`` 按需打桩，聚焦同步接线契约。
"""

from pathlib import Path
from unittest.mock import MagicMock

import pytest


def _recorder(cap: dict, key: str):
    """返回一个 mock：记录 QMessageBox.warning 的调用参数。"""

    def _fn(*args, **kwargs):
        cap.setdefault(key, []).append(args)
        return None

    return _fn


@pytest.fixture
def patched_modals(monkeypatch):
    """mock warning 与 BackgroundWorker，返回捕获容器。

    - warning 仅记录（预校验失败路径不依赖返回值）；
    - BackgroundWorker 替换为记录任务闭包的假对象，不真正启动 QThread。
    """
    cap: dict = {}
    monkeypatch.setattr(
        "src.ui.dialogs.share_package_dialog.QMessageBox.warning",
        _recorder(cap, "warning"),
    )

    def _fake_worker(run, parent=None):
        cap.setdefault("runs", []).append(run)
        return MagicMock()

    monkeypatch.setattr("src.ui.dialogs.share_package_dialog.BackgroundWorker", _fake_worker)
    return cap


def _make_dialog():
    """构造绑定单个条目、已选定输出目录的 SharePackageDialog。"""
    from src.models import Entry
    from src.ui.dialogs.share_package_dialog import SharePackageDialog

    dlg = SharePackageDialog(Entry(title="测试条目"))
    dlg._selected_dir = "D:/tmp/share_out"
    return dlg


def _fill_password(dlg, password: str) -> None:
    """填入共享密码与确认框（保持一致），触发强度标签副作用无碍。"""
    dlg._pwd_edit.setText(password)
    dlg._confirm_edit.setText(password)


class TestSharePasswordPrevalidation:
    """共享密码预校验：与业务层 validate_master_password 同口径（QL-028）。"""

    def test_password_below_business_min_blocked_before_worker(self, qapp, patched_modals):
        """8-14 位密码过旧 UI 门禁（本地 8 字符下限）→ 现须被业务口径拦截。

        断言三要点：warning 弹出、文案为业务层口径（含 15 字符下限）、
        BackgroundWorker 未启动（不进入加密流程）。
        """
        dlg = _make_dialog()
        _fill_password(dlg, "abcd1234")  # 8 位：旧本地门禁会放行
        dlg._execute()
        assert patched_modals["warning"]
        assert any("15 个字符" in str(arg) for arg in patched_modals["warning"][0])
        assert not patched_modals.get("runs")

    def test_long_but_repetitive_password_blocked(self, qapp, patched_modals):
        """长度达标但重复字符过多的密码 → 同样被预校验拦截（强度维度）。"""
        dlg = _make_dialog()
        _fill_password(dlg, "aaaaaaaaaaaaaaaaaaaa")  # 20 位但唯一字符数 ≤2
        dlg._execute()
        assert patched_modals["warning"]
        assert any("重复" in str(arg) for arg in patched_modals["warning"][0])
        assert not patched_modals.get("runs")

    def test_valid_password_passes_precheck_and_starts_worker(
        self, qapp, patched_modals, monkeypatch
    ):
        """合法强密码放行：无 warning，worker 启动且密码原样传给业务层。"""
        business = MagicMock(return_value=(Path("a.cboxshare"), Path("decrypt.html")))
        monkeypatch.setattr("src.ui.dialogs.share_package_dialog.create_share_package", business)
        dlg = _make_dialog()
        _fill_password(dlg, "Xk7$mQ2#wE9&bT4@yU1!")
        dlg._execute()
        assert not patched_modals.get("warning")
        assert len(patched_modals["runs"]) == 1
        # 模拟 worker 线程执行捕获的任务闭包，验证密码接线无错位
        patched_modals["runs"][0]()
        business.assert_called_once()
        assert business.call_args.args[1] == "Xk7$mQ2#wE9&bT4@yU1!"
        assert business.call_args.kwargs.get("output_dir") == "D:/tmp/share_out"
