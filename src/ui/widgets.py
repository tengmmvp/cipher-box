"""可复用 UI 组件 - 提取自多个对话框/面板的重复模式"""

from __future__ import annotations

import time

from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtWidgets import (
    QLabel,
    QLineEdit,
    QPushButton,
)

from ..config import RATE_LIMITS
from ..crypto.password_generator import PasswordGenerator
from ..ui.resources.constants import BTN_ICON
from ..ui.resources.icons import EYE, LOCK, set_icon
from ..ui.resources.theme_colors import get_strength_color

# ---------------------------------------------------------------------------
# 0. 对话框状态标签格式化
# ---------------------------------------------------------------------------

def format_status(success: bool, message: str) -> str:
    """格式化对话框操作状态标签。"""
    prefix = '[OK]' if success else '[X]'
    return f'{prefix} {message}'


# ---------------------------------------------------------------------------
# 1. 密码显示/隐藏切换按钮
# ---------------------------------------------------------------------------

def create_password_toggle_btn(
    target_edit: QLineEdit,
    eye_icon: str = EYE,
    lock_icon: str = LOCK,
    *,
    auto_hide_seconds: int | None = None,
) -> QPushButton:
    """创建密码显示/隐藏切换按钮。

    Parameters
    ----------
    target_edit : QLineEdit
        需要切换 echoMode 的密码输入框。
    eye_icon / lock_icon : str
        图标常量，默认使用 EYE / LOCK。
    auto_hide_seconds : int | None
        若提供，密码显示指定秒数后自动重新隐藏并恢复图标。

    Returns
    -------
    QPushButton
        已连接 clicked 信号的切换按钮。
    """
    btn = QPushButton()
    btn.setObjectName('iconBtn')
    btn.setFixedSize(*BTN_ICON)
    set_icon(btn, eye_icon)
    btn.setToolTip('显示/隐藏密码')

    # 可选的自动隐藏定时器
    auto_timer: QTimer | None = None
    if auto_hide_seconds is not None:
        auto_timer = QTimer(btn)
        auto_timer.setSingleShot(True)

        def _on_auto_hide():
            target_edit.setEchoMode(QLineEdit.EchoMode.Password)
            set_icon(btn, eye_icon)

        auto_timer.timeout.connect(_on_auto_hide)
        # 存储到按钮属性上，防止 GC 回收，同时允许外部访问
        btn._auto_hide_timer = auto_timer

    def _toggle():
        if target_edit.echoMode() == QLineEdit.EchoMode.Password:
            target_edit.setEchoMode(QLineEdit.EchoMode.Normal)
            set_icon(btn, lock_icon)
            if auto_timer is not None:
                auto_timer.start(auto_hide_seconds * 1000)
        else:
            target_edit.setEchoMode(QLineEdit.EchoMode.Password)
            set_icon(btn, eye_icon)
            if auto_timer is not None:
                auto_timer.stop()

    btn.clicked.connect(_toggle)
    return btn


# ---------------------------------------------------------------------------
# 2. 密码强度标签更新
# ---------------------------------------------------------------------------

def update_strength_label(
    label: QLabel,
    password: str,
    *,
    prefix: str = '强度：',
    font_size: str = '12px',
    extra_style: str = '',
) -> None:
    """根据密码内容更新强度标签的文本和颜色。

    Parameters
    ----------
    label : QLabel
        用于显示强度提示的标签。
    password : str
        当前密码文本。为空时清除标签。
    prefix : str
        强度文本前缀，默认 ``'强度：'``。
    font_size : str
        字体大小 CSS 值。
    extra_style : str
        附加 CSS 样式片段（如 ``'font-weight: bold;'``）。
    """
    if password:
        strength = PasswordGenerator.check_strength(password)
        color = get_strength_color(strength.score)
        label.setText(f'{prefix}{strength.label}')
        label.setStyleSheet(
            f'color: {color}; font-size: {font_size}; {extra_style}'
        )
    else:
        label.setText('')
        if extra_style:
            label.setStyleSheet(extra_style)


# ---------------------------------------------------------------------------
# 3. 移除 WindowContextHelpButtonHint
# ---------------------------------------------------------------------------

def setup_dialog_flags(dialog) -> None:
    """移除对话框标题栏上的「?» 帮助按钮。

    等价于::

        dialog.setWindowFlags(dialog.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)

    Parameters
    ----------
    dialog : QDialog
        目标对话框实例。
    """
    dialog.setWindowFlags(
        dialog.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint
    )


# ---------------------------------------------------------------------------
# 4. 布局清空工具
# ---------------------------------------------------------------------------

def clear_layout(layout, disconnect_signals: bool = True) -> None:
    """递归清除布局中的所有控件和子布局。

    Args:
        layout: 要清除的布局
        disconnect_signals: 是否在删除前断开 widget 信号连接（默认 True）。
            防止 deleteLater 到实际删除之间信号触发不一致状态。
    """
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget:
            if disconnect_signals:
                # 断开常见的可点击控件信号，减少 deleteLater 窗口期风险
                if hasattr(widget, 'clicked'):
                    try:
                        widget.clicked.disconnect()
                    except (TypeError, RuntimeError):
                        pass
            widget.deleteLater()
        child_layout = item.layout()
        if child_layout:
            clear_layout(child_layout, disconnect_signals)
        # QSpacerItem 等其他项由布局所有权自动回收


# ---------------------------------------------------------------------------
# 5. 速率限制（登录 / 修改主密码）
# ---------------------------------------------------------------------------

def apply_rate_limit(fail_count: int) -> int:
    """根据失败次数计算锁定秒数（递增退避）。

    Parameters
    ----------
    fail_count : int
        累计失败次数。

    Returns
    -------
    int
        应锁定的秒数，0 表示不锁定。
    """
    for threshold, seconds in reversed(RATE_LIMITS):
        if fail_count >= threshold:
            return seconds
    return 0


class RateLimiter:
    """登录/改密等敏感操作的速率限制器（递增退避）。

    封装失败计数、锁定时间戳、过期重置等状态管理，
    消除 LoginWindow / ChangeMasterDialog 中的重复逻辑。

    Usage::

        limiter = RateLimiter()
        msg = limiter.check()          # None = 可继续，str = 锁定提示
        limiter.record_success()       # 重置计数
        secs = limiter.record_failure()  # 返回锁定秒数（0 = 不锁定）
    """

    def __init__(self) -> None:
        self._fail_count: int = 0
        self._lock_until: float = 0.0

    def check(self) -> str | None:
        """检查是否处于锁定状态。

        Returns
        -------
        str | None
            锁定提示消息（含剩余秒数）或 ``None``（可继续）。
            如果锁定已过期，自动重置计数。
        """
        if self._lock_until and time.monotonic() < self._lock_until:
            remaining = int(self._lock_until - time.monotonic()) + 1
            return f'尝试次数过多，请等待 {remaining} 秒后重试'
        if self._lock_until and time.monotonic() >= self._lock_until:
            self._fail_count = 0
            self._lock_until = 0.0
        return None

    def record_success(self) -> None:
        """记录成功，重置失败计数。"""
        self._fail_count = 0

    def record_failure(self) -> int:
        """记录失败并根据策略计算锁定秒数。

        Returns
        -------
        int
            锁定秒数，0 表示不锁定（仅计数）。
        """
        self._fail_count += 1
        lock_seconds = apply_rate_limit(self._fail_count)
        if lock_seconds > 0:
            self._lock_until = time.monotonic() + lock_seconds
        return lock_seconds


# ---------------------------------------------------------------------------
# 6. Worker 释放工具
# ---------------------------------------------------------------------------

def release_worker(dialog) -> None:
    """安全释放对话框持有的 BackgroundWorker。

    断开所有信号并将 ``dialog._worker`` 置 None，防止对话框关闭后
    Worker 回调访问已销毁的控件。应在 reject() 和完成回调中调用。

    Parameters
    ----------
    dialog : QDialog
        持有 ``_worker`` 属性的对话框实例。
    """
    worker = getattr(dialog, '_worker', None)
    if worker is None:
        return
    for sig_name in ('finished', 'error', 'cancelled', 'progress'):
        try:
            getattr(worker, sig_name).disconnect()
        except (TypeError, RuntimeError):
            pass
    dialog._worker = None
