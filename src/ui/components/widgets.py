"""可复用 UI 组件与工具函数。

提取自多个对话框与面板的重复模式，涵盖状态标签格式化、密码显示切换、
强度标签更新、对话框标志位清理、布局清空、速率限制与后台线程释放等
无状态工具，供 UI 各层共享。
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QLabel,
    QLineEdit,
    QPushButton,
)

from ...business.services.password_service import PasswordService
from ...config import RATE_LIMITS
from ...utils.file_security import secure_file
from ..resources.constants import BTN_ICON
from ..resources.icons import EYE, LOCK, set_icon
from ..resources.theme_colors import get_strength_color

# ======== 对话框状态标签格式化 ========

def format_status(success: bool, message: str) -> str:
    """格式化对话框操作状态标签。"""
    prefix = '[OK]' if success else '[X]'
    return f'{prefix} {message}'


# ======== 密码显示/隐藏切换按钮 ========

def create_password_toggle_btn(
    target_edit: QLineEdit,
    eye_icon: str = EYE,
    lock_icon: str = LOCK,
    *,
    auto_hide_seconds: int | None = None,
) -> 'PasswordToggleBtn':
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

    暴露 ``show_password`` / ``hide_password`` 公共方法，替代此前通过 Qt
    动态属性 ``autoHideTimer`` 反射取回定时器的脆弱契约：属性名拼写错误或
    改用其他可见时长来源时旧实现会静默失效（定时器不启动 → 密码长时间明文）。
    """

    def __init__(
        self,
        target_edit: QLineEdit,
        eye_icon: str = EYE,
        lock_icon: str = LOCK,
        *,
        auto_hide_seconds: int | None = None,
        parent=None,
    ):
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

    def _toggle(self):
        if self._target.echoMode() == QLineEdit.EchoMode.Password:
            self.show_password()
        else:
            self.hide_password()

    def show_password(self, *, seconds: int | None = None):
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

    def hide_password(self):
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

def setup_dialog_flags(dialog) -> None:
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

def clear_layout(layout, disconnect_signals: bool = True) -> None:
    """递归清除布局中的所有控件和子布局。

    Args:
        layout: 要清除的布局。
        disconnect_signals: 是否在删除前断开 widget 信号连接，默认为 True。
            用于防止 deleteLater 到实际删除之间信号触发不一致状态。
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


# ======== 速率限制 ========

def apply_rate_limit(fail_count: int) -> int:
    """根据失败次数计算锁定秒数，采用递增退避策略。

    Args:
        fail_count: 累计失败次数。

    Returns:
        应锁定的秒数，0 表示不锁定。
    """
    for threshold, seconds in reversed(RATE_LIMITS):
        if fail_count >= threshold:
            return seconds
    return 0


class RateLimiter:
    """登录/改密等敏感操作的速率限制器，采用递增退避策略。

    封装失败计数、锁定时间戳、过期重置等状态管理，
    消除 LoginWindow / ChangeMasterDialog 中的重复逻辑。

    Usage::

        limiter = RateLimiter()
        msg = limiter.check()          # None = 可继续，str = 锁定提示
        limiter.record_success()       # 重置计数
        secs = limiter.record_failure()  # 返回锁定秒数，0 表示不锁定
    """

    def __init__(self, state_path: str | Path | None = None) -> None:
        self._fail_count: int = 0
        self._lock_until: float = 0.0
        self._state_path = Path(state_path) if state_path is not None else None
        self._load_state()

    @property
    def _sentinel_path(self) -> Path | None:
        """哨兵文件路径，与状态文件配对，标记限流系统已正常初始化过。

        用于区分状态文件「首次使用（哨兵缺失）」与「被恶意删除（哨兵存在）」，
        关闭「删除 login_rate_limit.json 即归零计数」的绕过路径。
        """
        if self._state_path is None:
            return None
        return self._state_path.with_name(self._state_path.name + '.sentinel')

    def _ensure_sentinel(self) -> None:
        """首次成功持久化状态时创建哨兵，标记限流系统已初始化。

        创建失败仅告警不中断——哨兵缺失最坏退化为「无法检测删除」，与改造前
        行为一致，不会比原实现更弱。
        """
        sentinel = self._sentinel_path
        if sentinel is None or sentinel.exists():
            return
        try:
            sentinel.parent.mkdir(parents=True, exist_ok=True)
            sentinel.write_bytes(b'1')
            secure_file(sentinel)
        except OSError:
            logging.getLogger(__name__).warning(
                "限流哨兵文件创建失败，删除检测将降级", exc_info=True,
            )

    def _load_state(self) -> None:
        if self._state_path is None:
            return
        if not self._state_path.exists():
            # 状态文件缺失：区分「首次使用」与「被恶意删除」。首次成功持久化
            # 状态时会同步写哨兵（见 _ensure_sentinel），故哨兵存在而状态文件
            # 缺失意味着状态被外部删除——降级到最高阶梯锁定，与「文件损坏」
            # 路径一致，避免删文件直接绕过限流。哨兵缺失则为首次正常使用，
            # 计数保持 0，不误伤新用户。
            if self._sentinel_path is not None and self._sentinel_path.exists():
                logging.getLogger(__name__).warning(
                    "限流状态文件缺失但哨兵存在，判定为被删除，降级最高阶梯锁定"
                )
                self._fail_count = RATE_LIMITS[-1][0]
                self._lock_until = time.time() + RATE_LIMITS[-1][1]
                self._save_state()
            return
        try:
            data = json.loads(self._state_path.read_text(encoding='utf-8'))
            fail_count = data.get('fail_count', 0)
            lock_until = data.get('lock_until', 0.0)
            if type(fail_count) is not int or fail_count < 0:
                raise ValueError('失败次数无效')
            if not isinstance(lock_until, (int, float)) or lock_until < 0:
                raise ValueError('锁定时间无效')
            self._fail_count = fail_count
            self._lock_until = float(lock_until)
        except (OSError, ValueError, json.JSONDecodeError, AttributeError):
            # 状态损坏时按最高阶梯短暂锁定，避免删除/破坏状态文件直接绕过限流。
            self._fail_count = RATE_LIMITS[-1][0]
            self._lock_until = time.time() + RATE_LIMITS[-1][1]
            self._save_state()

    def _save_state(self) -> None:
        if self._state_path is None:
            return
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self._state_path.with_name(self._state_path.name + '.tmp')
        payload = json.dumps({
            'fail_count': self._fail_count,
            'lock_until': self._lock_until,
        })
        try:
            with open(temp_path, 'w', encoding='utf-8') as file:
                file.write(payload)
                file.flush()
                os.fsync(file.fileno())
            secure_file(temp_path)
            os.replace(temp_path, self._state_path)
            secure_file(self._state_path)
            # 状态已成功落盘：确保哨兵存在，使后续「状态文件被删除」可被检测。
            self._ensure_sentinel()
        except OSError:
            # 写盘失败（只读盘/磁盘满/权限）不应中断登录流程：RateLimiter 是
            # 内存限流，持久化仅为跨会话保留；失败时内存状态仍生效，仅记日志。
            logging.getLogger(__name__).warning(
                "登录限流状态写盘失败，本次仅内存生效", exc_info=True
            )
        finally:
            temp_path.unlink(missing_ok=True)

    def check(self) -> str | None:
        """检查是否处于锁定状态。

        如果锁定已过期，自动重置计数。

        Returns:
            锁定提示消息，含剩余秒数；若可继续则返回 ``None``。
        """
        now = time.time()
        if self._lock_until and now < self._lock_until:
            remaining = int(self._lock_until - now) + 1
            return f'尝试次数过多，请等待 {remaining} 秒后重试'
        if self._lock_until and now >= self._lock_until:
            # 锁定到期：允许重试，但**保留 fail_count**，使下一轮失败仍能爬升到
            # 更高退避档位。原先到期即清零会让攻击者每轮重置回最低档
            # （3 次→10s→清零→3 次→10s…），递增退避名存实亡。保留计数后，持续
            # 失败者会逐档爬升到 30/60/120 秒；合法用户最终成功登录时由
            # record_success 清零，不受影响。
            self._lock_until = 0.0
            self._save_state()
        return None

    def record_success(self) -> None:
        """记录成功，重置失败计数。"""
        self._fail_count = 0
        self._lock_until = 0.0
        self._save_state()

    def record_failure(self) -> int:
        """记录失败并根据策略计算锁定秒数。

        Returns:
            锁定秒数，0 表示仅计数不锁定。
        """
        self._fail_count += 1
        lock_seconds = apply_rate_limit(self._fail_count)
        if lock_seconds > 0:
            self._lock_until = time.time() + lock_seconds
        self._save_state()
        return lock_seconds


# ======== Worker 释放工具 ========

def release_worker(dialog) -> None:
    """安全释放对话框持有的 BackgroundWorker。

    断开所有信号并将 ``dialog._worker`` 置 None，防止对话框关闭后
    Worker 回调访问已销毁的控件。应在 reject() 和完成回调中调用。

    Args:
        dialog: 持有 ``_worker`` 属性的对话框实例。
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


def set_label_severity(label, severity):
    """设置消息/状态标签的 severity 动态属性并刷新 QSS。

    severity 取 'error'/'accent'/'success'，对应 QSS 的
    QLabel#formMessage[severity=...] / QLabel#formStatus[severity=...] 颜色。
    setProperty 后需 unpolish+polish 触发 QSS 属性选择器重算，主题切换时由
    app.setStyleSheet 全局刷新，运行时改 severity 由本函数局部刷新。

    供 change_master/login 的消息标签与 backup/import_export 的状态标签复用，
    消除重复的 setStyleSheet 颜色字符串。
    """
    label.setProperty('severity', severity)
    style = label.style()
    style.unpolish(label)
    style.polish(label)
