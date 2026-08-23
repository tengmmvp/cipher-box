"""SharePackageDialog 接线测试：控件值→业务参数与入口守卫。

业务层（``share.package.create_share_package`` 的加密/双文件原子写入/回滚/取消语义）
已由 ``tests/business/test_share_package.py`` 覆盖；本文件守护「对话框控件值→正确
业务参数」接线层：共享密码预校验拦截、有效期预设→``expire_at`` 秒数映射（含「永不」
→ ``EXPIRE_NEVER``）、含/不含密码开关透传，以及 ``open_share_package_dialog`` 对
完整性异常条目的统一拒绝入口。

密码预校验用例刻意与具体阈值解耦：6 位过短密码在任何已知阈值（8/15 字符）下均应
被拦截；合法用例使用 ≥15 位四类字符强密码，阈值调整前后均放行。

模态对话框（QMessageBox/QFileDialog）与 ``BackgroundWorker`` 经 monkeypatch 替换，
避免真实模态阻塞与 ``QThread`` 异步——聚焦同步接线契约（与 test_backup_dialog 同
范式）。输出目录经 ``_selected_dir`` 直接注入，绕过 QFileDialog。
"""

import dataclasses
import time
from unittest.mock import MagicMock

import pytest

from src.business.services.share.package import EXPIRE_NEVER
from src.models import Entry

# 强共享密码：16 位且含大小写/数字/符号，任何已知阈值与强度策略下均合法。
_STRONG_PASSWORD = "Xk9#mQv2$Lp7!wRz"

# 有效期预设契约：(下拉索引, 显示名, 相对秒数)；offset=0 表示永不过期。
_TTL_CASES = [
    (0, "1 小时", 3600),
    (1, "24 小时", 86400),
    (2, "7 天", 604800),
    (3, "30 天", 2592000),
    (4, "永不", 0),
]


def _recorder(cap: dict, key: str):
    """返回一个 mock：仅记录调用（warning/information/critical 返回值不被使用）。"""

    def _fn(*args, **kwargs):
        cap.setdefault(key, []).append(args)
        return None

    return _fn


@pytest.fixture
def patched_wiring(monkeypatch):
    """mock 模态对话框、BackgroundWorker 与 create_share_package，返回捕获容器。"""
    cap: dict = {}
    monkeypatch.setattr(
        "src.ui.dialogs.share_package_dialog.QMessageBox.warning",
        _recorder(cap, "warning"),
    )
    monkeypatch.setattr(
        "src.ui.dialogs.share_package_dialog.QMessageBox.information",
        _recorder(cap, "info"),
    )
    monkeypatch.setattr(
        "src.ui.dialogs.share_package_dialog.QMessageBox.critical",
        _recorder(cap, "critical"),
    )
    create = MagicMock(return_value=(MagicMock(name="share"), MagicMock(name="html")))
    monkeypatch.setattr("src.ui.dialogs.share_package_dialog.create_share_package", create)
    cap["create"] = create

    def _fake_worker(run, parent=None):
        cap["run"] = run
        return MagicMock()

    monkeypatch.setattr("src.ui.dialogs.share_package_dialog.BackgroundWorker", _fake_worker)
    return cap


def _make_entry(**overrides) -> Entry:
    """构造测试用已解密 Entry，integrity 等运行时字段经 overrides 注入。"""
    entry = Entry(
        title="接线测试条目",
        username="wire-user",
        password="WireSecret-9!",
        entry_type="login",
    )
    return dataclasses.replace(entry, **overrides)


def _make_dialog(qapp, entry: Entry | None = None):
    from src.ui.dialogs.share_package_dialog import SharePackageDialog

    return SharePackageDialog(entry if entry is not None else _make_entry())


def _fill_valid_form(dlg, *, password: str = _STRONG_PASSWORD) -> None:
    """填入合法表单：强密码（两次一致）+ 已选输出目录。"""
    dlg._pwd_edit.setText(password)
    dlg._confirm_edit.setText(password)
    dlg._selected_dir = "D:/tmp/share-out"


class TestSharePasswordPrecheck:
    """共享密码预校验：过短密码在提交前被拦截，不触发创建流程。"""

    def test_short_password_blocked_before_create(self, qapp, patched_wiring):
        """6 位密码低于任何已知阈值（8/15）：弹警告、不启动 worker、不触达业务层。"""
        dlg = _make_dialog(qapp)
        _fill_valid_form(dlg, password="Ab1!xy")
        dlg._execute()
        assert patched_wiring["warning"], "过短密码应弹出警告提示"
        assert "run" not in patched_wiring, "过短密码不应启动创建 worker"
        patched_wiring["create"].assert_not_called()


class TestExpiryPresetWiring:
    """有效期预设→create_share_package 的 expire_at 秒数映射。"""

    @pytest.mark.parametrize("index,label,offset", _TTL_CASES, ids=[c[1] for c in _TTL_CASES])
    def test_ttl_preset_maps_to_expire_at_seconds(self, qapp, patched_wiring, index, label, offset):
        """各 TTL 预设的相对秒数正确下传：offset 秒映射为「当前时间+offset」，
        「永不」精确映射为 ``EXPIRE_NEVER``（0），其余用执行前后时间夹逼容忍时钟抖动。"""
        dlg = _make_dialog(qapp)
        # 预设清单防漂移：下拉项顺序与秒数契约须与 _EXPIRY_OPTIONS 一致
        assert dlg._expiry_combo.itemText(index) == label
        _fill_valid_form(dlg)
        dlg._expiry_combo.setCurrentIndex(index)

        t0 = time.time()
        dlg._execute()
        t1 = time.time()

        assert "run" in patched_wiring
        patched_wiring["run"]()  # 模拟 worker 线程执行捕获的任务闭包
        patched_wiring["create"].assert_called_once()
        call = patched_wiring["create"].call_args
        assert call.args[0] == [dlg._entry]
        assert call.args[1] == _STRONG_PASSWORD
        assert call.kwargs["include_secrets"] is True
        assert call.kwargs["output_dir"] == "D:/tmp/share-out"
        assert call.kwargs["cancel_check"] is not None
        expire_at = call.kwargs["expire_at"]
        if offset == 0:
            assert expire_at == EXPIRE_NEVER
        else:
            # int(time.time()) 截断使下界可能比 t0+offset 小 1 秒，下界放宽 1 秒容忍
            assert t0 + offset - 1 <= expire_at <= t1 + offset, (
                f"预设「{label}」应映射为当前时间 + {offset} 秒，实际 {expire_at}"
            )


class TestIncludeSecretsWiring:
    """含/不含密码开关→include_secrets 透传。"""

    def test_exclude_password_radio_passes_include_secrets_false(self, qapp, patched_wiring):
        """选「不含密码」时 include_secrets=False 下传业务层。"""
        dlg = _make_dialog(qapp)
        _fill_valid_form(dlg)
        dlg._exclude_radio.setChecked(True)
        dlg._execute()
        patched_wiring["run"]()
        assert patched_wiring["create"].call_args.kwargs["include_secrets"] is False


class TestOpenSharePackageDialogGuard:
    """open_share_package_dialog 入口守卫：完整性异常条目拒绝开对话框。"""

    def test_integrity_error_entry_rejected_at_entry_point(self, qapp, monkeypatch):
        """完整性异常条目被拒绝并弹 critical（含无法解密字段名），不构造对话框。"""
        from src.ui.dialogs import share_package_dialog as mod

        cap: dict = {"critical": [], "constructed": 0}
        monkeypatch.setattr(mod.QMessageBox, "critical", _recorder(cap, "critical"))

        class _SentinelDialog:
            def __init__(self, *args, **kwargs):
                cap["constructed"] += 1

        monkeypatch.setattr(mod, "SharePackageDialog", _SentinelDialog)

        entry = _make_entry(integrity_error=True, integrity_message="password")
        mod.open_share_package_dialog(entry, parent=None)

        assert cap["constructed"] == 0, "完整性异常条目不应打开共享对话框"
        assert cap["critical"]
        text = " ".join(str(arg) for arg in cap["critical"][0])
        assert "无法解密" in text
        assert "password" in text

    def test_healthy_entry_opens_dialog(self, qapp, monkeypatch):
        """正常条目经入口正常构造对话框（守卫不误伤健康路径）。"""
        from src.ui.dialogs import share_package_dialog as mod

        cap = {"constructed": 0}

        class _SentinelDialog:
            def __init__(self, entry, parent=None):
                cap["constructed"] += 1

            def exec(self):
                return 0

            def deleteLater(self):
                pass

        monkeypatch.setattr(mod, "SharePackageDialog", _SentinelDialog)
        mod.open_share_package_dialog(_make_entry(), parent=None)
        assert cap["constructed"] == 1
