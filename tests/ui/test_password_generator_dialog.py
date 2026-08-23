"""PasswordGeneratorDialog 接线测试：生成配置→PasswordService 参数与结果契约。

守护「控件值（长度滑杆/字符集勾选）→ ``PasswordService.generate`` 参数映射」、
「生成结果填充输出框与强度标签」、「复制经 ClipboardManager（不绕过自动清除直写
系统剪贴板）」与「使用此密码」信号契约。生成核心（字符集覆盖/排除模糊字符）由
crypto 层测试覆盖，此处聚焦对话框接线。

另守护复制反馈定时器的生命周期（QL-032）：定时器以对话框为 parent，对话框不经
reject/close 直接销毁（如测试回收 fixture 对顶层 widget ``deleteLater``）时随销毁
停止，回调不访问已 deleteLater 的按钮（Windows C 层 access violation 回归）。

``PasswordService.generate`` 经 monkeypatch 替换为 MagicMock（构造即触发的首次生成
亦走 mock，测试内 ``reset_mock`` 后聚焦目标调用）；``QMessageBox.warning`` 经
monkeypatch 捕获，避免真实模态阻塞。
"""

import gc
import weakref
from unittest.mock import MagicMock

import pytest
from PyQt6 import sip
from PyQt6.QtWidgets import QApplication


def _recorder(cap: dict, key: str):
    """返回一个 mock：仅记录 QMessageBox.warning 的调用参数。"""

    def _fn(*args, **kwargs):
        cap.setdefault(key, []).append(args)
        return None

    return _fn


@pytest.fixture
def patched_warning(monkeypatch):
    """捕获 QMessageBox.warning，避免模态对话框阻塞测试。"""
    cap: dict = {}
    monkeypatch.setattr(
        "src.ui.dialogs.password_generator_dialog.QMessageBox.warning",
        _recorder(cap, "warning"),
    )
    return cap


def _make_dialog(qapp, clipboard=None):
    from src.ui.dialogs.password_generator_dialog import PasswordGeneratorDialog

    return PasswordGeneratorDialog(clipboard_manager=clipboard)


def _mock_generate(monkeypatch, return_value: str = "Mocked-Gen-9xA") -> MagicMock:
    """替换 PasswordService.generate 为 MagicMock 并返回之。"""
    gen = MagicMock(return_value=return_value)
    monkeypatch.setattr("src.ui.dialogs.password_generator_dialog.PasswordService.generate", gen)
    return gen


class TestGenerateWiring:
    """长度/字符集控件值→生成参数映射与结果填充。"""

    def test_open_generates_password_with_slider_default_length(self, qapp):
        """构造即生成：输出框非空、长度等于滑杆值、强度标签就绪（真实服务）。"""
        dlg = _make_dialog(qapp)
        text = dlg._password_display.text()
        assert text, "构造后应立即生成一个密码"
        assert len(text) == dlg._length_slider.value()
        assert dlg._strength_label.text().startswith("强度：")

    def test_slider_value_passed_as_length(self, qapp, monkeypatch):
        """长度滑杆值原样传给 generate 的 length 参数，长度标签同步刷新。"""
        gen = _mock_generate(monkeypatch)
        dlg = _make_dialog(qapp)
        gen.reset_mock()
        gen.return_value = "Mocked-Gen-42xZ"

        dlg._length_slider.setValue(42)
        dlg._generate()

        gen.assert_called_once()
        kwargs = gen.call_args.kwargs
        assert kwargs["length"] == 42
        assert kwargs["uppercase"] is True
        assert kwargs["lowercase"] is True
        assert kwargs["digits"] is True
        assert kwargs["symbols"] is True
        assert kwargs["exclude_ambiguous"] is False
        assert dlg._length_label.text() == "42"
        assert dlg._password_display.text() == "Mocked-Gen-42xZ"
        assert dlg._strength_label.text().startswith("强度：")

    def test_charset_checkboxes_map_to_flags(self, qapp, monkeypatch):
        """字符集勾选组合→flags 映射：仅小写 + 排除模糊字符。"""
        gen = _mock_generate(monkeypatch)
        dlg = _make_dialog(qapp)
        gen.reset_mock()

        dlg._upper_check.setChecked(False)
        dlg._lower_check.setChecked(True)
        dlg._digits_check.setChecked(False)
        dlg._symbols_check.setChecked(False)
        dlg._exclude_ambiguous.setChecked(True)
        dlg._generate()

        kwargs = gen.call_args.kwargs
        assert kwargs["uppercase"] is False
        assert kwargs["lowercase"] is True
        assert kwargs["digits"] is False
        assert kwargs["symbols"] is False
        assert kwargs["exclude_ambiguous"] is True

    def test_all_charsets_unchecked_warns_and_keeps_last_password(
        self, qapp, patched_warning, monkeypatch
    ):
        """全不勾选的防护行为：弹警告拒绝生成、保留上次结果（现状为拒绝而非保底）。"""
        dlg = _make_dialog(qapp)  # 构造即真实生成，输出框已有内容
        before = dlg._password_display.text()
        assert before

        gen = _mock_generate(monkeypatch)
        for chk in (
            dlg._upper_check,
            dlg._lower_check,
            dlg._digits_check,
            dlg._symbols_check,
        ):
            chk.setChecked(False)
        dlg._generate()

        gen.assert_not_called()
        assert patched_warning["warning"], "全不勾选应弹出警告"
        assert dlg._password_display.text() == before, "被拒绝的生成不应覆盖上次结果"


class TestCopyAndUse:
    """复制/使用按钮契约。"""

    def test_copy_button_uses_clipboard_manager(self, qapp):
        """复制按钮把输出框内容经 ClipboardManager.copy_text 送入剪贴板。"""
        clipboard = MagicMock()
        dlg = _make_dialog(qapp, clipboard=clipboard)
        expected = dlg._password_display.text()
        assert expected

        dlg._copy_password()

        clipboard.copy_text.assert_called_once_with(expected)
        assert dlg._copy_feedback_timer is not None, "复制后应启动按钮文案复位定时器"
        # 关闭对话框停掉反馈定时器：避免其在后续测试的 teardown processEvents 中
        # 触发并访问已 deleteLater 的按钮控件（Windows 下 C 层 access violation）。
        dlg.reject()

    def test_copy_without_clipboard_manager_is_safe(self, qapp):
        """ClipboardManager 缺失时复制不抛异常（不绕过自动清除直写系统剪贴板）。"""
        dlg = _make_dialog(qapp)  # clipboard_manager=None
        dlg._copy_password()  # 不应抛异常
        assert dlg._copy_feedback_timer is not None, "按钮反馈定时器仍应启动"
        dlg.reject()  # 停掉反馈定时器，避免 teardown 期间触发已删控件

    def test_use_password_emits_signal_and_clears_display(self, qapp):
        """「使用此密码」发出 password_selected 信号并清除输出框明文驻留。"""
        received: list[str] = []
        dlg = _make_dialog(qapp)
        expected = dlg._password_display.text()
        assert expected
        dlg.password_selected.connect(received.append)

        dlg._use_password()

        assert received == [expected]
        assert dlg._password_display.text() == ""


class TestFeedbackTimerLifecycle:
    """复制反馈定时器生命周期（QL-032）：随对话框销毁，不悬挂访问已删控件。"""

    def test_feedback_timer_parented_to_dialog_and_active(self, qapp):
        """反馈定时器以对话框为 parent 且启动后处于活动态（parent 归属是销毁即停的前提）。"""
        dlg = _make_dialog(qapp)
        dlg._copy_password()

        timer = dlg._copy_feedback_timer
        assert timer is not None
        assert timer.parent() is dlg, "反馈定时器必须父子化到对话框（QL-032）"
        assert timer.isActive()

        dlg.reject()

    def test_feedback_timer_dies_with_dialog_without_reject(self, qapp):
        """启动反馈定时器后不经 reject 直接销毁对话框：定时器随对话框 C++ 销毁，
        processEvents 不触发已删按钮的回调（Windows C 层 access violation 回归）。"""
        dlg = _make_dialog(qapp)
        dlg._copy_password()
        timer = dlg._copy_feedback_timer
        timer_ref = weakref.ref(timer)
        assert timer is not None and timer.isActive()

        # 直接销毁对话框 C++ 对象（deleteLater 在本测试环境下的 DeferredDelete 推进
        # 不确定，sip.delete 等价于「父窗口直接销毁子对话框」的确定性销毁）。
        sip.delete(dlg)

        # 危险状态成立：按钮 C++ 已释放；定时器须同步随父销毁，回调才无对象可访问。
        assert sip.isdeleted(dlg._copy_btn), "按钮 C++ 对象应随对话框销毁"
        assert sip.isdeleted(timer), "反馈定时器应随对话框销毁（parent 归属，QL-032）"
        QApplication.processEvents()  # 对象销毁后再推进事件循环：定时器事件已不存在

        del dlg, timer
        gc.collect()
        assert timer_ref() is None, "定时器 Python wrapper 应可回收（无悬挂引用）"

    def test_restore_callback_skips_deleted_button(self, qapp):
        """复位回调对已销毁的按钮静默跳过（与 detail_panel._restore 同款守卫）。"""
        dlg = _make_dialog(qapp)
        dlg._copy_password()
        sip.delete(dlg._copy_btn)
        assert sip.isdeleted(dlg._copy_btn)

        dlg._restore_copy_label()  # 不应抛 RuntimeError / 崩溃

        dlg.reject()
