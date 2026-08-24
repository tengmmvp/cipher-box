"""密码历史与 TOTP 组件测试（stub EntryManager，验证渲染与定时器生命周期）。

- ``PasswordHistoryWidget``：摘要按钮→展开渲染、掩码/揭示切换、超时自动掩码、
  复制回调与信号、截断到 ``MAX_HISTORY_DISPLAY``、``clear()`` 停止自管定时器并
  掩码已渲染明文（行删除与定时器交错的回归守护）；
- ``TOTPWidget``：构建显示验证码/倒计时、私有 ``_refresh`` 刷新、无 secret/验证码
  失效时停止定时器、复制信号、``clear()`` 销毁区域与 ``resume_if_active`` 守卫。

EntryManager 经 MagicMock 注入（password_history/totp 子服务返回构造数据），
隔离真实解密路径；UI 控件构造经 qapp fixture。定时器到期用 ``timeout.emit()``
直接触发（比真实等待稳定），布局/延迟校正用 processEvents 推进。
"""

from unittest.mock import MagicMock

from PyQt6 import sip
from PyQt6.QtCore import QCoreApplication, QEvent
from PyQt6.QtWidgets import QGroupBox, QLabel, QPushButton, QVBoxLayout, QWidget

from src.ui.components.password_history_widget import PasswordHistoryWidget
from src.ui.components.totp_widget import TOTPWidget
from src.ui.resources.constants import MAX_HISTORY_DISPLAY, PWD_MASK

# ============================================================ PasswordHistoryWidget


def _make_container(qapp) -> tuple[QWidget, QVBoxLayout]:
    parent = QWidget()
    layout = QVBoxLayout(parent)
    parent.show()
    qapp.processEvents()
    return parent, layout


def _make_hist_mgr(records: list[dict]) -> MagicMock:
    """构造密码历史服务 mock：get 返回记录数、decrypt 透传并捕获输出供断言。"""
    mgr = MagicMock()
    mgr.password_history.get_count.return_value = len(records)
    mgr.password_history.get.return_value = list(records)
    decrypted_outputs: list[list] = []

    def _decrypt(rows):
        out = [dict(r) for r in rows]
        decrypted_outputs.append(out)
        return out

    mgr.password_history.decrypt.side_effect = _decrypt
    mgr._decrypted_outputs = decrypted_outputs
    return mgr


def _records(n: int, prefix: str = "pwd") -> list[dict]:
    return [
        {"changed_at": f"2026-01-{i + 1:02d} 12:00", "password": f"{prefix}-{i}"} for i in range(n)
    ]


def _expand_button(layout: QVBoxLayout) -> QPushButton:
    """取布局中的摘要展开按钮（含「点击展开」文案）。"""
    for i in range(layout.count()):
        widget = layout.itemAt(i).widget()
        if isinstance(widget, QPushButton) and "点击展开" in widget.text():
            return widget
    raise AssertionError("布局中未找到密码历史摘要按钮")


def _history_group(layout: QVBoxLayout) -> QGroupBox:
    """取布局中的密码历史分组框。"""
    for i in range(layout.count()):
        widget = layout.itemAt(i).widget()
        if isinstance(widget, QGroupBox) and widget.title() == "密码历史":
            return widget
    raise AssertionError("布局中未找到密码历史分组框")


def _buttons_by_tooltip(group: QGroupBox, tooltip: str) -> list[QPushButton]:
    """按 tooltip 取分组框内的显示/复制按钮（findChildren 按创建序即行序）。"""
    return [b for b in group.findChildren(QPushButton) if b.toolTip() == tooltip]


class TestPasswordHistoryWidget:
    """密码历史折叠区：摘要、展开渲染与显隐切换。"""

    def test_no_history_renders_nothing(self, qapp):
        """无历史记录：不渲染摘要按钮（空历史态）。"""
        _parent, layout = _make_container(qapp)
        w = PasswordHistoryWidget()
        mgr = _make_hist_mgr([])

        w.build_stub(1, mgr, layout)  # type: ignore[arg-type]

        assert layout.count() == 0

    def test_none_manager_is_defensive_noop(self, qapp):
        """entry_manager 为 None：不渲染且不抛异常（防御分支）。"""
        _parent, layout = _make_container(qapp)
        w = PasswordHistoryWidget()

        w.build_stub(1, None, layout)  # type: ignore[arg-type]

        assert layout.count() == 0
        assert w._entry_mgr is None

    def test_summary_button_shows_record_count(self, qapp):
        """有历史：渲染摘要按钮并显示记录数，未展开前不解密。"""
        _parent, layout = _make_container(qapp)
        w = PasswordHistoryWidget()
        mgr = _make_hist_mgr(_records(3))

        w.build_stub(7, mgr, layout)  # type: ignore[arg-type]

        btn = _expand_button(layout)
        assert "3 条记录" in btn.text()
        mgr.password_history.get_count.assert_called_once_with(7)
        mgr.password_history.decrypt.assert_not_called()  # 延迟解密：点击前不接触明文

    def test_expand_renders_rows_masked_and_pops_plaintext(self, qapp):
        """展开：渲染时间/掩码密码/显隐/复制按钮，明文仅存间接引用列表。"""
        _parent, layout = _make_container(qapp)
        w = PasswordHistoryWidget()
        records = _records(3, prefix="secret")
        mgr = _make_hist_mgr(records)

        w.build_stub(1, mgr, layout)  # type: ignore[arg-type]
        _expand_button(layout).click()

        group = _history_group(layout)
        assert [lbl.text() for lbl in w._pwd_labels] == [PWD_MASK] * 3  # 初始掩码
        assert w._history_passwords == ["secret-0", "secret-1", "secret-2"]
        # 解密输出 dict 中的明文副本被显式 pop 收缩驻留面
        assert all("password" not in d for d in mgr._decrypted_outputs[0])
        # 时间标签按记录渲染（排除同分组内的掩码密码 QLabel）
        time_texts = [
            lbl.text() for lbl in group.findChildren(QLabel) if lbl.text().startswith("2026-")
        ]
        assert time_texts == ["2026-01-01 12:00", "2026-01-02 12:00", "2026-01-03 12:00"]
        assert len(_buttons_by_tooltip(group, "显示/隐藏")) == 3
        assert len(_buttons_by_tooltip(group, "复制密码")) == 3

    def test_expand_truncates_to_max_display(self, qapp):
        """超过 MAX_HISTORY_DISPLAY 条：先截断再解密，只渲染最近 N 条。"""
        _parent, layout = _make_container(qapp)
        w = PasswordHistoryWidget()
        records = _records(MAX_HISTORY_DISPLAY + 3)
        mgr = _make_hist_mgr(records)

        w.build_stub(1, mgr, layout)  # type: ignore[arg-type]
        _expand_button(layout).click()

        # decrypt 收到的是截断后的前 N 条（避免持锁解密全量历史）
        assert len(mgr._decrypted_outputs[0]) == MAX_HISTORY_DISPLAY
        assert len(w._pwd_labels) == MAX_HISTORY_DISPLAY

    def test_decrypt_empty_keeps_summary_button(self, qapp):
        """有计数但解密结果为空：不渲染分组，摘要按钮保留（可重试展开）。"""
        _parent, layout = _make_container(qapp)
        w = PasswordHistoryWidget()
        mgr = _make_hist_mgr(_records(2))
        mgr.password_history.decrypt.return_value = None
        mgr.password_history.decrypt.side_effect = None

        w.build_stub(1, mgr, layout)  # type: ignore[arg-type]
        _expand_button(layout).click()

        assert layout.count() == 1  # 摘要按钮仍在
        assert w._pwd_labels == []

    def test_toggle_reveal_and_mask_with_timer(self, qapp):
        """揭示显示明文并按可见时长启动定时器，再点掩码并停止定时器。"""
        _parent, layout = _make_container(qapp)
        w = PasswordHistoryWidget()
        w.set_callbacks(get_pwd_visible_ms=lambda: 1500, copy_with_feedback=MagicMock())
        mgr = _make_hist_mgr(_records(2, prefix="p"))

        w.build_stub(1, mgr, layout)  # type: ignore[arg-type]
        _expand_button(layout).click()
        show_btns = _buttons_by_tooltip(_history_group(layout), "显示/隐藏")

        show_btns[0].click()  # 揭示第一行
        assert w._pwd_labels[0].text() == "p-0"
        timer = w._own_timers[0]
        assert timer.isActive()
        assert timer.interval() == 1500

        show_btns[0].click()  # 手动掩码
        assert w._pwd_labels[0].text() == PWD_MASK
        assert not timer.isActive()

    def test_timeout_remaskes_without_clearing_slot(self, qapp):
        """显示超时：仅重置掩码不清槽位，支持再次揭示。"""
        _parent, layout = _make_container(qapp)
        w = PasswordHistoryWidget()
        w.set_callbacks(get_pwd_visible_ms=lambda: 60000, copy_with_feedback=MagicMock())
        mgr = _make_hist_mgr(_records(1, prefix="k"))

        w.build_stub(1, mgr, layout)  # type: ignore[arg-type]
        _expand_button(layout).click()
        show_btns = _buttons_by_tooltip(_history_group(layout), "显示/隐藏")
        show_btns[0].click()
        assert w._pwd_labels[0].text() == "k-0"

        w._own_timers[0].timeout.emit()  # 直接触发超时回调（稳定于真实等待）

        assert w._pwd_labels[0].text() == PWD_MASK
        assert w._history_passwords == ["k-0"]  # 槽位保留：可再次揭示
        show_btns[0].click()
        assert w._pwd_labels[0].text() == "k-0"

    def test_toggle_without_callbacks_reveals_without_timer(self, qapp):
        """未注入回调：揭示仍显示明文，但不启动定时器（防御分支）。"""
        _parent, layout = _make_container(qapp)
        w = PasswordHistoryWidget()
        mgr = _make_hist_mgr(_records(1, prefix="n"))

        w.build_stub(1, mgr, layout)  # type: ignore[arg-type]
        _expand_button(layout).click()
        _buttons_by_tooltip(_history_group(layout), "显示/隐藏")[0].click()

        assert w._pwd_labels[0].text() == "n-0"
        assert not w._own_timers[0].isActive()

    def test_copy_button_invokes_callback_and_signal(self, qapp):
        """复制按钮：经回调复制对应行明文并发射 copy_feedback 信号。"""
        _parent, layout = _make_container(qapp)
        w = PasswordHistoryWidget()
        copy_fn = MagicMock()
        w.set_callbacks(get_pwd_visible_ms=lambda: 1000, copy_with_feedback=copy_fn)
        feedback: list = []
        w.copy_feedback.connect(lambda: feedback.append(1))
        mgr = _make_hist_mgr(_records(2, prefix="c"))

        w.build_stub(1, mgr, layout)  # type: ignore[arg-type]
        _expand_button(layout).click()
        copy_btns = _buttons_by_tooltip(_history_group(layout), "复制密码")

        copy_btns[1].click()

        btn_arg, text_arg = copy_fn.call_args[0]
        assert btn_arg is copy_btns[1]
        assert text_arg == "c-1"
        assert feedback == [1]

    def test_copy_without_callback_is_noop(self, qapp):
        """未注入复制回调：点击复制按钮不抛异常（防御分支）。"""
        _parent, layout = _make_container(qapp)
        w = PasswordHistoryWidget()
        mgr = _make_hist_mgr(_records(1, prefix="q"))

        w.build_stub(1, mgr, layout)  # type: ignore[arg-type]
        _expand_button(layout).click()
        _buttons_by_tooltip(_history_group(layout), "复制密码")[0].click()  # 不抛即通过

    def test_clear_masks_labels_stops_timers_and_releases(self, qapp):
        """clear()：停止自管定时器、掩码已渲染明文、释放间接引用与 entry_mgr。"""
        _parent, layout = _make_container(qapp)
        w = PasswordHistoryWidget()
        w.set_callbacks(get_pwd_visible_ms=lambda: 60000, copy_with_feedback=MagicMock())
        mgr = _make_hist_mgr(_records(2, prefix="z"))

        w.build_stub(1, mgr, layout)  # type: ignore[arg-type]
        _expand_button(layout).click()
        _buttons_by_tooltip(_history_group(layout), "显示/隐藏")[0].click()
        labels = list(w._pwd_labels)
        timers = list(w._own_timers)
        assert timers[0].isActive()

        w.clear()

        assert all(not t.isActive() for t in timers)  # 定时器停：到期回调不再触达旧控件
        assert w._own_timers == []
        assert labels[0].text() == PWD_MASK  # deleteLater 异步销毁前明文已擦除
        assert w._history_passwords == []
        assert w._entry_mgr is None
        qapp.processEvents()  # 推进事件循环验证无残留定时器崩溃

    def test_clear_then_rebuild_renders_new_history(self, qapp):
        """行删除与定时器交错：clear 后重建新条目历史，旧定时器保持停止。"""
        _parent, layout = _make_container(qapp)
        w = PasswordHistoryWidget()
        w.set_callbacks(get_pwd_visible_ms=lambda: 60000, copy_with_feedback=MagicMock())
        mgr_a = _make_hist_mgr(_records(3, prefix="a"))
        mgr_b = _make_hist_mgr(_records(2, prefix="b"))

        w.build_stub(1, mgr_a, layout)  # type: ignore[arg-type]
        _expand_button(layout).click()
        timer_a = w._own_timers[0]

        w.clear()
        w.build_stub(2, mgr_b, layout)  # type: ignore[arg-type]
        _expand_button(layout).click()

        assert not timer_a.isActive()  # 旧定时器不复活
        assert len(w._own_timers) == 2  # 新行各自新定时器
        assert w._history_passwords == ["b-0", "b-1"]
        assert w._pwd_labels[0].text() == PWD_MASK
        qapp.processEvents()  # 交错销毁/重建后推进事件循环不崩溃


# ==================================================================== TOTPWidget


def _make_totp_mgr(
    state: dict | None = None,
    refreshed_code: str | None = "654321",
    remaining: int = 14,
) -> MagicMock:
    """构造 totp 子服务 mock：get_state/generate_cached/remaining_seconds 返回构造值。"""
    mgr = MagicMock()
    mgr.totp.get_state.return_value = state
    mgr.totp.generate_cached.return_value = refreshed_code
    mgr.totp.remaining_seconds.return_value = remaining
    return mgr


def _valid_state() -> dict:
    return {"code": "123456", "remaining": 15, "period": 30}


class TestTOTPWidget:
    """TOTP 验证码区：构建显示、刷新、复制与生命周期。"""

    def test_start_builds_code_countdown_and_timer(self, qapp):
        """有 secret：构建验证码/进度条并启动每秒刷新定时器。"""
        _parent, layout = _make_container(qapp)
        w = TOTPWidget()
        mgr = _make_totp_mgr(_valid_state())

        w.start(9, mgr, layout, secret=None)  # type: ignore[arg-type]

        assert w._code_label is not None
        assert w._code_label.text() == "123456"
        assert w._bar.value() == 15
        assert (w._bar.minimum(), w._bar.maximum()) == (0, 30)
        assert w._timer.isActive()
        assert layout.count() == 1
        mgr.totp.get_state.assert_called_once_with(9, preloaded_secret=None)

    def test_start_forwards_preloaded_secret(self, qapp):
        """调用方已解密的 secret 经 preloaded_secret 透传，避免二次解密。"""
        _parent, layout = _make_container(qapp)
        w = TOTPWidget()
        mgr = _make_totp_mgr(_valid_state())

        w.start(3, mgr, layout, secret="JBSWY3DPEHPK3PXP")  # type: ignore[arg-type]

        mgr.totp.get_state.assert_called_once_with(3, preloaded_secret="JBSWY3DPEHPK3PXP")

    def test_refresh_updates_code_and_countdown(self, qapp):
        """刷新：验证码取最新 generate_cached，倒计时经 remaining_seconds 重算。"""
        _parent, layout = _make_container(qapp)
        w = TOTPWidget()
        mgr = _make_totp_mgr(_valid_state(), refreshed_code="999999", remaining=7)

        w.start(5, mgr, layout)  # type: ignore[arg-type]
        w._refresh()  # 直接调用私有刷新（稳定于等待真实 1s 定时器）

        assert w._code_label.text() == "999999"
        assert w._bar.value() == 7
        mgr.totp.generate_cached.assert_called_once_with(5)
        mgr.totp.remaining_seconds.assert_called_once_with(30)

    def test_refresh_without_state_stops_timer(self, qapp):
        """无 secret/损坏 secret（get_state=None）：不渲染任何区域。"""
        _parent, layout = _make_container(qapp)
        w = TOTPWidget()
        mgr = _make_totp_mgr(None)

        w.start(5, mgr, layout)  # type: ignore[arg-type]

        assert layout.count() == 0
        assert w._code_label is None
        assert w._entry_id is None
        assert not w._timer.isActive()

    def test_refresh_stops_when_code_unavailable(self, qapp):
        """刷新时验证码不可得（条目被删/缓存失效）：停止定时器不再空转。"""
        _parent, layout = _make_container(qapp)
        w = TOTPWidget()
        mgr = _make_totp_mgr(_valid_state(), refreshed_code=None)

        w.start(5, mgr, layout)  # type: ignore[arg-type]
        assert w._timer.isActive()
        w._refresh()

        assert not w._timer.isActive()

    def test_copy_emits_current_code_and_feedback(self, qapp):
        """复制按钮：发射携带当前验证码的 copy_requested 与 copy_feedback。"""
        _parent, layout = _make_container(qapp)
        w = TOTPWidget()
        mgr = _make_totp_mgr(_valid_state(), refreshed_code="246810")
        requested: list = []
        feedback: list = []
        w.copy_requested.connect(lambda code: requested.append(code))
        w.copy_feedback.connect(lambda: feedback.append(1))

        w.start(5, mgr, layout)  # type: ignore[arg-type]
        w._refresh()  # 刷新到最新验证码后复制（始终取最新值）
        frame = layout.itemAt(0).widget()
        copy_btn = frame.findChild(QPushButton)
        assert copy_btn is not None
        copy_btn.click()

        assert requested == ["246810"]
        assert feedback == [1]

    def test_clear_destroys_frame_and_clears_plaintext(self, qapp):
        """clear()：清空验证码明文、停止定时器并销毁已加入布局的 TOTP 区域。"""
        _parent, layout = _make_container(qapp)
        w = TOTPWidget()
        mgr = _make_totp_mgr(_valid_state())

        w.start(5, mgr, layout)  # type: ignore[arg-type]
        frame = w._totp_frame
        label = w._code_label
        assert frame is not None and label is not None

        w.clear()

        assert label.text() == ""  # deleteLater 前先擦除可见明文
        assert not w._timer.isActive()
        assert w._code_label is None and w._bar is None and w._totp_frame is None
        assert w._entry_id is None
        # 清除后的迟到刷新（定时器已停，此处直调）走守卫分支：不抛异常、不重启定时器
        w._refresh()
        assert not w._timer.isActive()
        # 显式派发 DeferredDelete 队列完成析构（无运行中的事件循环时 processEvents
        # 不保证处理 deleteLater，sendPostedEvents 是确定性的推进方式）
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        assert sip.isdeleted(frame)

    def test_stop_and_resume_if_active(self, qapp):
        """stop 停止定时器；resume_if_active 仅在仍有活跃 TOTP 区域时重启。"""
        _parent, layout = _make_container(qapp)
        w = TOTPWidget()
        mgr = _make_totp_mgr(_valid_state())

        w.start(5, mgr, layout)  # type: ignore[arg-type]
        w.stop()
        assert not w._timer.isActive()
        w.resume_if_active()
        assert w._timer.isActive()

        # 清除后无活跃区域：resume 不再重启（避免无谓启停）
        w.clear()
        w.resume_if_active()
        assert not w._timer.isActive()
