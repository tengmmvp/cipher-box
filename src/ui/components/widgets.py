"""可复用 UI 组件与工具函数。

提取自多个对话框与面板的重复模式，涵盖状态标签格式化、密码显示切换、
强度标签更新、对话框标志位清理、布局清空、速率限制与后台线程释放等
无状态工具，供 UI 各层共享。
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any, Protocol

from PyQt6.QtCore import QObject, Qt, QTimer
from PyQt6.QtGui import QCloseEvent
from PyQt6.QtWidgets import (
    QDialog,
    QLabel,
    QLayout,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QWidget,
)

from ...business.services.password_service import PasswordService
from ..resources.constants import BTN_DIALOG, BTN_ICON
from ..resources.icons import EYE, LOCK, set_icon
from ..resources.strings import DLG_TITLE_ERROR
from ..resources.theme_colors import get_strength_color
from .workers import wait_worker_shutdown

if TYPE_CHECKING:
    from .workers import BackgroundWorker

# ======== 信号断开与取消按钮 ========

def disconnect_all(connections: Iterable[tuple[Any, object]]) -> None:
    """断开一组 (signal, slot) 连接，未连接的吞 TypeError。

    Qt 重复断开已断开的信号会抛 TypeError，此 helper 统一吞掉。
    """
    for signal, slot in connections:
        try:
            signal.disconnect(slot)
        except TypeError:
            pass


def create_cancel_button(parent_dialog: QDialog) -> QPushButton:
    """构造统一的「取消」按钮：固定尺寸并绑定 reject。"""
    btn = QPushButton('取消')
    btn.setFixedSize(*BTN_DIALOG)
    btn.clicked.connect(parent_dialog.reject)
    return btn


def create_icon_button(
    icon_name: str,
    tooltip: str,
    *,
    visible: bool = True,
    object_name: str = 'iconBtn',
) -> QPushButton:
    """构造统一的图标按钮：固定 BTN_ICON 尺寸、语义 objectName、图标与提示。

    返回未连接 clicked 信号的按钮，由调用方按需连接。
    """
    btn = QPushButton()
    btn.setObjectName(object_name)
    btn.setFixedSize(*BTN_ICON)
    set_icon(btn, icon_name)
    btn.setToolTip(tooltip)
    if not visible:
        btn.hide()
    return btn


# ======== 密码显示/隐藏切换按钮 ========

def create_password_toggle_btn(
    target_edit: QLineEdit,
    eye_icon: str = EYE,
    lock_icon: str = LOCK,
    *,
    auto_hide_seconds: int | None = None,
) -> PasswordToggleBtn:
    """创建密码显示/隐藏切换按钮。

    返回 :class:`PasswordToggleBtn`，调用方可通过其 ``show_password`` /
    ``hide_password`` 公共方法显式控制，无需反射读取动态属性。

    Args:
        target_edit: 需要切换 echoMode 的密码输入框。
        eye_icon / lock_icon: 图标常量，默认使用 EYE / LOCK。
        auto_hide_seconds: 若提供，密码显示指定秒数后自动重新隐藏并恢复图标。

    Returns:
        已连接 clicked 信号的 :class:`PasswordToggleBtn` 实例。
    """
    return PasswordToggleBtn(
        target_edit, eye_icon, lock_icon, auto_hide_seconds=auto_hide_seconds,
    )


class PasswordToggleBtn(QPushButton):
    """密码显示/隐藏切换按钮，封装 echoMode 切换与可选自动隐藏定时器。

    暴露 ``show_password`` / ``hide_password`` 公共方法而非经 Qt 动态属性反射
    取回定时器，避免属性名拼写错误导致定时器不启动、密码长时间明文。
    """

    def __init__(
        self,
        target_edit: QLineEdit,
        eye_icon: str = EYE,
        lock_icon: str = LOCK,
        *,
        auto_hide_seconds: int | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._target = target_edit
        self._eye_icon = eye_icon
        self._lock_icon = lock_icon
        self.setObjectName('iconBtn')
        self.setFixedSize(*BTN_ICON)
        set_icon(self, eye_icon)
        self.setToolTip('显示/隐藏密码')

        # 可选自动隐藏定时器；parent 为 self，随按钮一并回收
        self._auto_hide_seconds = auto_hide_seconds
        self._auto_timer: QTimer | None = None
        if auto_hide_seconds is not None:
            self._auto_timer = QTimer(self)
            self._auto_timer.setSingleShot(True)
            self._auto_timer.timeout.connect(self.hide_password)

        self.clicked.connect(self._toggle)

    def _toggle(self) -> None:
        if self._target.echoMode() == QLineEdit.EchoMode.Password:
            self.show_password()
        else:
            self.hide_password()

    def show_password(self, *, seconds: int | None = None) -> None:
        """显示密码明文，并按指定秒数启动自动隐藏定时器。

        Args:
            seconds: 自动隐藏秒数；为 None 时回退到构造时的 ``auto_hide_seconds``，
                两者均无则仅切换显示不启动定时器。
        """
        self._target.setEchoMode(QLineEdit.EchoMode.Normal)
        set_icon(self, self._lock_icon)
        if self._auto_timer is not None:
            delay = seconds if seconds is not None else self._auto_hide_seconds
            if delay is not None:
                self._auto_timer.start(delay * 1000)

    def hide_password(self) -> None:
        """隐藏密码并恢复 eye 图标，停止自动隐藏定时器。"""
        self._target.setEchoMode(QLineEdit.EchoMode.Password)
        set_icon(self, self._eye_icon)
        if self._auto_timer is not None:
            self._auto_timer.stop()


# ======== 密码强度标签更新 ========

def update_strength_label(
    label: QLabel,
    password: str,
    *,
    prefix: str = '强度：',
    font_size: str = '12px',
    extra_style: str = '',
) -> None:
    """根据密码内容更新强度标签的文本和颜色。

    Args:
        label: 用于显示强度提示的标签。
        password: 当前密码文本，为空时清除标签。
        prefix: 强度文本前缀，默认 ``'强度：'``。
        font_size: 字体大小 CSS 值。
        extra_style: 附加 CSS 样式片段，例如 ``'font-weight: bold;'``。
    """
    if password:
        strength = PasswordService.check_strength(password)
        color = get_strength_color(strength.score)
        label.setText(f'{prefix}{strength.label}')
        label.setStyleSheet(
            f'color: {color}; font-size: {font_size}; {extra_style}'
        )
    else:
        label.setText('')
        if extra_style:
            label.setStyleSheet(extra_style)


# ======== 移除 WindowContextHelpButtonHint ========

def setup_dialog_flags(dialog: QDialog) -> None:
    """移除对话框标题栏上的「?» 帮助按钮。

    等价于::

        dialog.setWindowFlags(dialog.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)

    Args:
        dialog: 目标对话框实例。
    """
    dialog.setWindowFlags(
        dialog.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint
    )


# ======== 布局清空工具 ========

# clear_layout 断开的常见可变控件信号：覆盖按钮/输入框/下拉/复选/滑动/动作等，防
# deleteLater 到实际删除间信号触发访问已删控件（如 type_combo.currentIndexChanged
# 闭包持有已 deleteLater 的 value_edit）。getattr 动态探测，无该信号的控件跳过。
_CLEAR_LAYOUT_SIGNALS = (
    'clicked', 'toggled', 'stateChanged',
    'textChanged', 'textEdited', 'editingFinished',
    'currentIndexChanged', 'currentTextChanged',
    'valueChanged', 'sliderMoved',
    'triggered', 'changed',
)


def clear_layout(layout: QLayout, disconnect_signals: bool = True) -> None:
    """递归清除布局中的所有控件和子布局。

    Args:
        layout: 要清除的布局。
        disconnect_signals: 是否在删除前断开 widget 信号连接，默认为 True。
            用于防止 deleteLater 到实际删除之间信号触发不一致状态。
    """
    while layout.count():
        item = layout.takeAt(0)
        if item is None:
            continue
        widget = item.widget()
        if widget:
            if disconnect_signals:
                # 断开原因与 getattr 探测策略见模块级 _CLEAR_LAYOUT_SIGNALS 注释与本函数 docstring
                for sig_name in _CLEAR_LAYOUT_SIGNALS:
                    sig = getattr(widget, sig_name, None)
                    if sig is not None:
                        try:
                            sig.disconnect()  # pyright: ignore[reportAttributeAccessIssue]
                        except (TypeError, RuntimeError):
                            pass
            widget.deleteLater()
        child_layout = item.layout()
        if child_layout:
            clear_layout(child_layout, disconnect_signals)
        # QSpacerItem 等其他项由布局所有权自动回收


# ======== Worker 释放工具 ========

class WorkerHost(Protocol):
    """持有 BackgroundWorker 的对话框协议，约束 release_worker 的入参类型。

    所有运行后台 worker 的对话框声明 ``_worker: BackgroundWorker | None`` 即满足
    本协议。用 Protocol 而非具体 QDialog 子类：release_worker 只依赖「持有 _worker」
    这一结构契约，且属性访问使「_worker 被重命名」能在静态类型检查阶段暴露，
    而非运行时静默返回 None、worker 信号未断开、关闭后回调访问已销毁控件。
    ``sender`` 源自 QObject，所有实现者均为 QDialog（QObject 子类），故纳入协议
    以支持 :func:`finalize_worker_if_current` 的过期 worker 守卫。
    """

    _worker: BackgroundWorker | None

    def sender(self) -> QObject | None: ...


def release_worker(dialog: WorkerHost) -> None:
    """安全释放对话框持有的 BackgroundWorker。

    断开所有信号并将 ``dialog._worker`` 置 None，防止对话框关闭后
    Worker 回调访问已销毁的控件。应在 reject() 和完成回调中调用。

    Args:
        dialog: 持有 ``_worker`` 属性的对话框实例（满足 :class:`WorkerHost`）。
    """
    worker = dialog._worker
    if worker is None:
        return
    for sig_name in ('finished', 'error', 'cancelled', 'progress'):
        try:
            getattr(worker, sig_name).disconnect()
        except (TypeError, RuntimeError):
            pass
    dialog._worker = None


def finalize_worker_if_current(dialog: WorkerHost) -> bool:
    """过期 worker 守卫 + 当前 worker 释放。

    若回调来自当前 worker 则释放并返回 True，否则返回 False（调用方应直接
    ``return`` 忽略过期 worker 的结果）。典型用法::

        if not finalize_worker_if_current(self):
            return
        self._set_busy(False)  # busy 复位在释放之后，顺序对 UI 状态无影响
        # ...处理结果...

    Args:
        dialog: 持有 ``_worker`` 的对话框（满足 :class:`WorkerHost`）。

    Returns:
        True 表示回调来自当前 worker 且已释放；False 表示来自过期 worker。
    """
    if dialog.sender() is not dialog._worker:
        return False
    release_worker(dialog)
    return True


# ======== Worker 后台对话框基类 ========

logger = logging.getLogger(__name__)


class WorkerBackedDialog(QDialog):
    """持有后台 worker 的对话框基类，统一封装关闭等待与 worker 释放语义。

    聚合 5 个对话框（backup/import_export/login/change_master/security_dashboard）
    重复的样板：reject 时按 ``_cancel_on_close`` 决定取消或仅等待 worker 完成，
    不可取消操作（恢复/导入，有写入副作用）运行期间拒绝关闭；统一 worker.error
    信号处理（释放当前 worker + 复位 busy + 记录日志 + 状态提示 + 错误对话框）。
    子类经覆写钩子定制行为。

    子类约定：
    - 在 ``_setup_ui`` 中赋值 ``_primary_action_btn`` 与 ``_status_label`` 即可获得
      默认 ``_set_busy`` 实现；busy 语义不同的子类可覆写 ``_set_busy``。
    - 有写入副作用的操作覆写 ``_cancel_on_close`` 返回 False（仅等待不取消）。
    - reject 前需额外清理（如清除密码、请求取消）覆写 ``_before_reject`` /
      ``_after_release``。
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._worker: BackgroundWorker | None = None
        self._primary_action_btn: QPushButton | None = None
        self._status_label: QLabel | None = None

    def _cancel_on_close(self) -> bool:
        """reject 时是否取消正在运行的 worker。

        默认 True（可安全取消）；有写入副作用的操作（恢复/导入）覆写为 False，
        使 reject 仅等待 worker 完成而非中断，保证数据一致性。closeEvent 亦据此
        在运行期间拒绝关闭以避免 QThread 销毁警告与数据不一致。
        """
        return True

    def _before_reject(self) -> None:
        """等待 worker 前的钩子（如请求 vault 取消），默认无操作。"""

    def _after_release(self) -> None:
        """worker 释放后、``super().reject()`` 前的钩子（如清除敏感输入），默认无操作。"""

    def reject(self) -> None:
        """关闭前按 ``_cancel_on_close`` 等待后台 worker 完成并释放引用。

        完成后释放 worker 引用，防止对话框关闭后 worker 回调访问已销毁控件。
        """
        self._before_reject()
        wait_worker_shutdown(self._worker, cancel=self._cancel_on_close())
        release_worker(self)
        self._after_release()
        super().reject()

    def closeEvent(self, a0: QCloseEvent | None) -> None:
        """不可取消 worker 运行时拒绝关闭，避免中断写入副作用。"""
        if (a0 is not None and self._worker is not None
                and self._worker.isRunning() and not self._cancel_on_close()):
            self._on_close_blocked()
            a0.ignore()
            return
        super().closeEvent(a0)

    def _on_close_blocked(self) -> None:
        """closeEvent 拒绝关闭时的提示，子类覆写以更新状态标签。"""

    def _set_busy(self, busy: bool) -> None:
        """busy 态切换：禁用/启用主操作按钮并更新状态标签。

        依赖子类在 ``_setup_ui`` 中赋值的 ``_primary_action_btn`` 与 ``_status_label``；
        二者未赋值时该方法为无操作，便于 busy 语义不同的子类不参与此默认流程。
        """
        if self._primary_action_btn is not None:
            self._primary_action_btn.setEnabled(not busy)
        if self._status_label is not None:
            if busy:
                self._status_label.setText('处理中...')
                set_label_severity(self._status_label, 'accent')
            else:
                self._status_label.setText('')

    def _report_worker_error(
        self,
        error_msg: str,
        *,
        status_text: str,
        message: str,
        log_message: str | None = None,
    ) -> bool:
        """统一 worker.error 信号处理。

        依次：过期 worker 守卫（``finalize_worker_if_current``）→ 复位 busy →
        记录日志 → 状态标签置错误文案 → 弹出错误对话框。供子类 ``_on_*_error``
        回调直接调用，消除 5 对话框重复的「finalize + _set_busy(False) + log +
        status + critical」样板。

        Args:
            error_msg: worker.error 携带的异常消息。
            status_text: 写入状态标签的错误文案。
            message: 错误对话框正文。
            log_message: 日志模板（``logger.error(log_message, error_msg)``），
                为 None 时不记日志。

        Returns:
            True 表示回调来自当前 worker（已释放并处理）；False 表示来自过期 worker。
        """
        if not finalize_worker_if_current(self):
            return False
        self._set_busy(False)
        if log_message is not None:
            logger.error(log_message, error_msg)
        if self._status_label is not None:
            self._status_label.setText(status_text)
            set_label_severity(self._status_label, 'error')
        QMessageBox.critical(self, DLG_TITLE_ERROR, message)
        return True


def set_label_severity(label: QLabel, severity: str) -> None:
    """设置消息/状态标签的 severity 动态属性并刷新 QSS。

    severity 取 'error'/'accent'/'success'，对应 QSS 的
    QLabel#formMessage[severity=...] / QLabel#formStatus[severity=...] 颜色。
    setProperty 后需 unpolish+polish 触发 QSS 属性选择器重算，主题切换时由
    app.setStyleSheet 全局刷新，运行时改 severity 由本函数局部刷新。
    """
    label.setProperty('severity', severity)
    style = label.style()
    if style is not None:
        style.unpolish(label)
        style.polish(label)
