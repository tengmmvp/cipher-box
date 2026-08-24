"""Toast 通知组件测试 — 类型样式、堆叠重排、自动消失与交互。

覆盖 ``toast.py`` 的三块职责：

- ``ToastWidget``：四类型配色应用、未知类型回退 info、自动关闭定时器启停、
  鼠标悬停暂停/恢复（enterEvent/leaveEvent）、操作按钮回调；
- ``ToastManager``：按父窗口复用实例、多条 Toast 从右下角向上堆叠重排
  （``_reposition_all``）、移除后清理 Manager 引用、``cancel_all`` 清空回调；
- ``Toast`` 静态入口 + ``refresh_for`` 主题切换重烘焙配色。

定时器与动画推进用 ``QTest.qWait``（PyQt6 stub 将其误标为实例方法，cast 消除
类型误差，范式同 ``test_product_hardening``）。
"""

from collections.abc import Callable
from typing import cast
from unittest.mock import MagicMock

from PyQt6 import sip
from PyQt6.QtCore import QEvent, QPointF
from PyQt6.QtGui import QEnterEvent
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QPushButton, QWidget

from src.ui.components.toast import Toast, ToastManager, ToastWidget
from src.ui.resources import theme_colors
from src.ui.resources.constants import (
    TOAST_HOVER_RESTART_MS,
    TOAST_MARGIN_BOTTOM,
    TOAST_MARGIN_RIGHT,
    TOAST_SPACING,
    TOAST_WIDTH,
)


def _qwait(ms: int) -> None:
    """QTest.qWait 包装：推进事件循环等待定时器/动画到期（stub 误标为实例方法）。"""
    cast(Callable[[int], None], QTest.qWait)(ms)


def _make_parent(qapp, width: int = 800, height: int = 600) -> QWidget:
    parent = QWidget()
    parent.resize(width, height)
    parent.show()
    return parent


def _close_btn(toast: ToastWidget) -> QPushButton:
    """取 Toast 的关闭按钮（无操作按钮时为唯一 QPushButton）。"""
    btns = toast.findChildren(QPushButton)
    assert btns, "Toast 应含关闭按钮"
    return btns[0]


def _action_btn(toast: ToastWidget) -> QPushButton:
    """取 Toast 的操作按钮（带文字的第二个按钮）。"""
    btns = [b for b in toast.findChildren(QPushButton) if b.text()]
    assert len(btns) == 1, "应恰好有一个带文字的操作按钮"
    return btns[0]


class TestToastTypeStyles:
    """ToastWidget 类型配色应用与未知类型回退。"""

    def test_each_type_applies_own_colors(self, qapp):
        """success/error/info/warning 四类型各自应用对应背景与边框色。"""
        for toast_type in ("success", "error", "info", "warning"):
            toast = ToastWidget(message="m", toast_type=toast_type)
            sheet = toast.styleSheet()
            assert theme_colors.c(f"toast_{toast_type}_bg") in sheet
            assert theme_colors.c(f"toast_{toast_type}_border") in sheet
            # 左侧强调竖条使用类型边框色
            assert theme_colors.c(f"toast_{toast_type}_border") in toast._accent_bar.styleSheet()

    def test_unknown_type_falls_back_to_info(self, qapp):
        """未定义类型回退 info 配色，不抛异常、不渲染成无样式卡片。

        各类型背景色相同（浅色主题均为 #ffffff），以类型边框色区分回退结果。
        """
        toast = ToastWidget(message="m", toast_type="bogus")
        sheet = toast.styleSheet()
        assert theme_colors.c("toast_info_border") in sheet
        assert theme_colors.c("toast_success_border") not in sheet


class TestToastShowLifecycle:
    """show_toash 的显隐与自动关闭定时器。"""

    def test_show_starts_auto_close_timer(self, qapp):
        """duration>0 显示后自动关闭定时器激活。"""
        toast = ToastWidget(message="m", duration=3000)
        toast.show_toast()
        assert toast._auto_close_timer.isActive()

    def test_zero_duration_never_auto_closes(self, qapp):
        """duration=0（常驻）不启动自动关闭定时器。"""
        toast = ToastWidget(message="m", duration=0)
        toast.show_toast()
        assert not toast._auto_close_timer.isActive()

    def test_auto_close_removes_from_manager(self, qapp):
        """到期淡出后被 Manager 移除，末条移除后清理父窗口的 Manager 引用。"""
        parent = _make_parent(qapp)
        toast = Toast.show(parent, "自动消失", duration=60)
        assert parent in ToastManager._instances

        _qwait(600)  # 60ms 定时器 + 200ms 淡出动画 + 余量

        assert sip.isdeleted(toast)  # deleteLater 已被事件循环处理
        assert parent not in ToastManager._instances
        assert ToastManager.get_manager(parent)._toasts == []

    def test_manual_close_button_dismisses(self, qapp):
        """点击关闭按钮触发淡出移除，无需等自动到期。"""
        parent = _make_parent(qapp)
        toast = Toast.show(parent, "手动关闭", duration=0)

        _close_btn(toast).click()

        _qwait(600)
        assert sip.isdeleted(toast)
        assert parent not in ToastManager._instances

    def test_action_button_invokes_callback_then_fades(self, qapp):
        """操作按钮点击：先执行回调再淡出关闭。"""
        parent = _make_parent(qapp)
        callback = MagicMock()
        toast = Toast.show(
            parent, "已删除", duration=0, action_text="撤销", action_callback=callback
        )

        _action_btn(toast).click()

        callback.assert_called_once_with()
        _qwait(600)
        assert parent not in ToastManager._instances


class TestToastManagerStacking:
    """ToastManager 实例复用与多条堆叠重排。"""

    def test_get_manager_reuses_instance_per_parent(self, qapp):
        """同一父窗口复用同一 Manager，不同父窗口各得一份。"""
        parent_a = _make_parent(qapp)
        parent_b = _make_parent(qapp)
        try:
            mgr_a1 = ToastManager.get_manager(parent_a)
            mgr_a2 = ToastManager.get_manager(parent_a)
            mgr_b = ToastManager.get_manager(parent_b)
            assert mgr_a1 is mgr_a2
            assert mgr_a1 is not mgr_b
        finally:
            ToastManager._instances.pop(parent_a, None)
            ToastManager._instances.pop(parent_b, None)

    def test_multiple_toasts_stack_bottom_up(self, qapp):
        """两条 Toast 从右下角向上堆叠：后加的贴底，先加的在其上方。"""
        parent = _make_parent(qapp)
        first = Toast.show(parent, "第一条", duration=0)
        _qwait(20)  # 让 singleShot(0, reposition) 与首次布局稳定
        second = Toast.show(parent, "第二条", duration=0)
        _qwait(20)

        mgr = ToastManager.get_manager(parent)
        assert mgr._toasts == [first, second]

        expected_x = parent.width() - TOAST_WIDTH - TOAST_MARGIN_RIGHT
        assert first.x() == expected_x
        assert second.x() == expected_x
        # 先显示的在上方（y 更小），两者间至少隔一个卡片高 + 间距
        assert first.y() < second.y()
        assert second.y() - first.y() >= TOAST_SPACING + 20
        # 贴底者不超过底边距上界
        assert second.y() + second.height() <= parent.height() - TOAST_MARGIN_BOTTOM + 1

    def test_cancel_all_clears_callbacks_and_fades(self, qapp):
        """cancel_all（锁定前调用）：清空操作回调并全部淡出。"""
        parent = _make_parent(qapp)
        callback = MagicMock()
        t1 = Toast.show(parent, "一", duration=0, action_text="撤销", action_callback=callback)
        t2 = Toast.show(parent, "二", duration=30000)

        ToastManager.cancel_all_for(parent)

        assert t1._action_callback is None  # 回调清空：淡出中点击不触发撤销
        _qwait(600)
        assert parent not in ToastManager._instances
        callback.assert_not_called()

    def test_refresh_for_reapplies_theme_colors(self, qapp):
        """主题切换后 refresh_for 重烘焙背景配色为新主题色。"""
        parent = _make_parent(qapp)
        theme_colors.set_theme("light")  # 显式基线，免疫其他测试泄漏的主题状态
        toast = Toast.show(parent, "主题", toast_type=Toast.SUCCESS, duration=0)
        light_sheet = toast.styleSheet()
        try:
            theme_colors.set_theme("dark")
            ToastManager.refresh_for(parent)
            dark_sheet = toast.styleSheet()
            assert theme_colors.c("toast_success_bg") in dark_sheet
            assert dark_sheet != light_sheet
        finally:
            theme_colors.set_theme("light")


class TestToastHoverPause:
    """鼠标悬停暂停/恢复自动关闭。"""

    def _hover_in(self, toast: ToastWidget) -> None:
        toast.enterEvent(QEnterEvent(QPointF(1, 1), QPointF(1, 1), QPointF(1, 1)))

    def _hover_out(self, toast: ToastWidget) -> None:
        toast.leaveEvent(QEvent(QEvent.Type.Leave))

    def test_enter_pauses_leave_restarts_timer(self, qapp):
        """悬停停止自动关闭定时器；移开后以缩短时长重启（不超过原 duration）。"""
        parent = _make_parent(qapp)
        toast = Toast.show(parent, "悬停我", duration=30000)
        try:
            assert toast._auto_close_timer.isActive()

            self._hover_in(toast)
            assert not toast._auto_close_timer.isActive()

            self._hover_out(toast)
            assert toast._auto_close_timer.isActive()
            assert toast._auto_close_timer.interval() == TOAST_HOVER_RESTART_MS
        finally:
            toast._start_fade_out()
            ToastManager._instances.pop(parent, None)

    def test_hover_out_on_zero_duration_keeps_persistent(self, qapp):
        """常驻 Toast（duration=0）移开鼠标也不启动自动关闭。"""
        parent = _make_parent(qapp)
        toast = Toast.show(parent, "常驻", duration=0)
        try:
            self._hover_in(toast)
            self._hover_out(toast)
            assert not toast._auto_close_timer.isActive()
        finally:
            toast._start_fade_out()
            ToastManager._instances.pop(parent, None)
