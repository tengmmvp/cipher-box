"""轻量级 Toast 通知组件 - 支持多类型、堆叠显示、淡入淡出动画"""

from PyQt6.QtWidgets import (
    QWidget, QFrame, QHBoxLayout, QVBoxLayout, QLabel,
    QPushButton, QGraphicsOpacityEffect, QGraphicsDropShadowEffect,
)
from PyQt6.QtCore import (
    Qt, QTimer, QPropertyAnimation, QEasingCurve, pyqtSignal,
)
from PyQt6.QtGui import QColor

from .resources.theme_colors import c
from .resources.icons import icon_pixmap, set_icon, SUCCESS, ERROR, WARNING, INFO, CLOSE, SIZE_TOAST


def _parse_shadow_color(color_str: str) -> QColor:
    """解析 rgba 颜色字符串为 QColor"""
    color_str = color_str.strip()
    if color_str.startswith('rgba('):
        parts = color_str[5:-1].split(',')
        r, g, b = int(parts[0].strip()), int(parts[1].strip()), int(parts[2].strip())
        a = int(float(parts[3].strip()) * 255) if len(parts) > 3 else 255
        return QColor(r, g, b, a)
    if color_str.startswith('rgb('):
        parts = color_str[4:-1].split(',')
        r, g, b = int(parts[0].strip()), int(parts[1].strip()), int(parts[2].strip())
        return QColor(r, g, b, 255)
    return QColor(color_str)


class ToastWidget(QFrame):
    """单个 Toast 通知卡片

    使用 QGraphicsOpacityEffect 实现淡入淡出（子控件无法使用 windowOpacity）。
    阴影通过在 ToastWidget 外层套一个 ShadowContainer 实现，
    这样 opacity 效果和阴影效果分别作用于不同的 widget，互不冲突。
    """

    closed = pyqtSignal(object)  # 通知 ToastManager 移除自身

    # 类型常量
    SUCCESS = 'success'
    ERROR = 'error'
    INFO = 'info'
    WARNING = 'warning'

    # 类型对应的图标
    _ICONS = {
        SUCCESS: SUCCESS,
        ERROR: ERROR,
        INFO: INFO,
        WARNING: WARNING,
    }

    def __init__(
        self,
        message: str,
        toast_type: str = 'info',
        duration: int = 3000,
        action_text: str = '',
        action_callback=None,
        parent=None,
    ):
        super().__init__(parent)
        self._toast_type = toast_type
        self._duration = duration
        self._action_callback = action_callback
        self._auto_close_timer = QTimer(self)
        self._auto_close_timer.setSingleShot(True)
        self._auto_close_timer.timeout.connect(self._start_fade_out)

        # 透明度效果
        self._opacity_effect = QGraphicsOpacityEffect(self)
        self._opacity_effect.setOpacity(0.0)
        self.setGraphicsEffect(self._opacity_effect)
        self._shadow_frame: QFrame | None = None  # 阴影层（由 ToastManager 设置）

        self._setup_ui(message, toast_type, action_text)
        self._apply_style(toast_type)

    # ------------------------------------------------------------------ UI
    def _setup_ui(self, message: str, toast_type: str, action_text: str):
        """构建内部布局"""
        self.setFixedWidth(320)
        self.setMinimumHeight(20)

        # 根布局：左边彩色竖条 + 内容区
        root_layout = QHBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # 左侧彩色竖条
        self._accent_bar = QFrame(self)
        self._accent_bar.setFixedWidth(4)
        root_layout.addWidget(self._accent_bar)

        # 内容容器
        content_widget = QWidget(self)
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(12, 10, 8, 10)
        content_layout.setSpacing(6)

        # 第一行：图标 + 消息 + 关闭按钮
        top_row = QHBoxLayout()
        top_row.setSpacing(8)

        # 类型图标
        icon_name = self._ICONS.get(toast_type, INFO)
        icon_label = QLabel()
        icon_label.setPixmap(icon_pixmap(icon_name, size=SIZE_TOAST))
        icon_label.setFixedSize(SIZE_TOAST, SIZE_TOAST)
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        top_row.addWidget(icon_label)

        # 消息文本
        msg_label = QLabel(message)
        msg_label.setWordWrap(True)
        msg_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        msg_label.setStyleSheet(
            f'font-size: 13px; color: {c("text_primary")}; background: transparent; border: none;'
        )
        top_row.addWidget(msg_label, 1)

        # 关闭按钮
        close_btn = QPushButton()
        close_btn.setFixedSize(20, 20)
        close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        close_btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        close_btn.clicked.connect(self._start_fade_out)
        set_icon(close_btn, CLOSE)
        close_btn.setObjectName('iconBtn')
        top_row.addWidget(close_btn)

        content_layout.addLayout(top_row)

        # 第二行：可选操作按钮（右对齐）
        if action_text:
            action_btn = QPushButton(action_text)
            action_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            action_btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            action_btn.setStyleSheet(f"""
                QPushButton {{
                    border: none;
                    background: transparent;
                    color: {c("accent")};
                    font-size: 12px;
                    font-weight: bold;
                    padding: 2px 4px;
                    border-radius: 3px;
                }}
                QPushButton:hover {{
                    background: {c("accent_light")};
                }}
            """)
            action_btn.clicked.connect(self._on_action_clicked)
            action_row = QHBoxLayout()
            action_row.addStretch()
            action_row.addWidget(action_btn)
            content_layout.addLayout(action_row)

        root_layout.addWidget(content_widget, 1)

    # ------------------------------------------------------------- 样式
    def _apply_style(self, toast_type: str):
        """根据类型应用样式"""
        type_key = (
            toast_type
            if toast_type in (self.SUCCESS, self.ERROR, self.INFO, self.WARNING)
            else self.INFO
        )
        bg_color = c(f'toast_{type_key}_bg')
        border_color = c(f'toast_{type_key}_border')

        self.setStyleSheet(f"""
            ToastWidget {{
                background-color: {bg_color};
                border: 1px solid {border_color};
                border-radius: 8px;
                border-left: none;
            }}
        """)
        self._accent_bar.setStyleSheet(f"""
            QFrame {{
                background-color: {border_color};
                border: none;
                border-top-left-radius: 8px;
                border-bottom-left-radius: 8px;
            }}
        """)

    # ------------------------------------------------------------- 动画
    def show_toast(self):
        """显示 Toast（淡入动画 + 启动自动关闭计时器）"""
        self.show()
        self.raise_()

        # 淡入动画（使用 QGraphicsOpacityEffect）
        anim = QPropertyAnimation(self._opacity_effect, b'opacity')
        anim.setDuration(250)
        anim.setStartValue(0.0)
        anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.Type.InOutCubic)
        anim.start()
        self._fade_in_anim = anim  # 保持引用防止 GC

        if self._duration > 0:
            self._auto_close_timer.start(self._duration)

    def _start_fade_out(self):
        """开始淡出动画"""
        self._auto_close_timer.stop()

        anim = QPropertyAnimation(self._opacity_effect, b'opacity')
        anim.setDuration(200)
        anim.setStartValue(self._opacity_effect.opacity())
        anim.setEndValue(0.0)
        anim.setEasingCurve(QEasingCurve.Type.InOutCubic)
        anim.finished.connect(self._on_fade_out_finished)
        anim.start()
        self._fade_out_anim = anim  # 保持引用防止 GC

    def _on_fade_out_finished(self):
        """淡出完成后关闭并通知 Manager"""
        self.hide()
        self.closed.emit(self)

    # ---------------------------------------------------------- 交互
    def _on_action_clicked(self):
        """操作按钮点击"""
        if self._action_callback:
            self._action_callback()
        self._start_fade_out()

    def enterEvent(self, a0):
        """鼠标进入时暂停自动关闭"""
        self._auto_close_timer.stop()
        super().enterEvent(a0)

    def leaveEvent(self, a0):
        """鼠标离开时重启自动关闭（缩短为 1 秒）"""
        if self._duration > 0:
            self._auto_close_timer.start(1000)
        super().leaveEvent(a0)


# ================================================================ ToastManager

class ToastManager:
    """管理多个 Toast 的位置堆叠

    每个 parent 窗口对应一个 ToastManager 实例。
    Toast 以子控件的形式定位在 parent 的右下角，从下往上堆叠。
    同时为每个 Toast 创建一层 QGraphicsDropShadowEffect 包装。
    """

    _instances: dict[int, 'ToastManager'] = {}

    def __init__(self, parent: QWidget):
        self._parent = parent
        self._toasts: list[ToastWidget] = []
        self._spacing = 10
        self._margin_bottom = 20
        self._margin_right = 20

    @staticmethod
    def get_manager(parent: QWidget) -> 'ToastManager':
        """获取或创建 parent 对应的 ToastManager"""
        pid = id(parent)
        if pid not in ToastManager._instances:
            ToastManager._instances[pid] = ToastManager(parent)
        return ToastManager._instances[pid]

    def add_toast(self, toast: ToastWidget):
        """添加一个 Toast 并更新所有位置"""
        # 为 Toast 添加阴影效果
        shadow_color = c('toast_shadow')
        shadow = QGraphicsDropShadowEffect(toast)
        shadow.setBlurRadius(16)
        shadow.setOffset(0, 4)
        shadow.setColor(_parse_shadow_color(shadow_color))
        # 注意：toast 已经有 QGraphicsOpacityEffect 作为 graphicsEffect
        # QGraphicsDropShadowEffect 只能设置给另一个 widget
        # 解决方案：给 toast 的父级或用一个包装容器
        # 这里我们给 _accent_bar 或 content_widget 设置阴影不太合适，
        # 所以直接给 toast 设置阴影层 —— 但一个 widget 只能有一个 effect。
        #
        # 最终方案：ToastWidget 上使用 QGraphicsOpacityEffect，
        # 阴影通过额外的 Shadow QFrame 实现（放在 toast 同级的下层）。
        self._shadow = shadow  # 暂存

        toast.closed.connect(self._remove_toast)
        self._toasts.append(toast)

        # 创建一个同位的阴影 QFrame
        shadow_frame = QFrame(self._parent)
        shadow_frame.setFixedWidth(324)
        shadow_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {shadow_color};
                border: none;
                border-radius: 10px;
            }}
        """)
        shadow_frame.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        shadow_frame.lower()
        toast._shadow_frame = shadow_frame

        self._reposition_all()
        toast.show_toast()

    def _remove_toast(self, toast: ToastWidget):
        """移除一个 Toast 并更新所有位置"""
        if toast in self._toasts:
            self._toasts.remove(toast)
        # 移除阴影
        if hasattr(toast, '_shadow_frame') and toast._shadow_frame:
            toast._shadow_frame.hide()
            toast._shadow_frame.deleteLater()
        toast.deleteLater()
        self._reposition_all()

        # 当没有 Toast 时清理 Manager 引用
        if not self._toasts:
            pid = id(self._parent)
            ToastManager._instances.pop(pid, None)

    def _reposition_all(self):
        """重新计算所有 Toast 的位置（从右下角向上堆叠）"""
        if not self._parent:
            return

        parent_rect = self._parent.rect()
        x = parent_rect.width() - 320 - self._margin_right

        # 从下往上堆叠
        y = parent_rect.height() - self._margin_bottom
        for toast in reversed(self._toasts):
            toast_height = toast.sizeHint().height()
            if toast_height <= 20:
                toast_height = toast.height()
            if toast_height <= 0:
                toast_height = 60
            y -= toast_height
            toast.move(x, y)
            # 同步阴影位置（偏移 2px 向右下）
            if hasattr(toast, '_shadow_frame') and toast._shadow_frame:
                toast._shadow_frame.setFixedHeight(toast_height + 4)
                toast._shadow_frame.move(x - 2, y + 2)
                toast._shadow_frame.show()
                toast._shadow_frame.lower()
                toast.raise_()
            y -= self._spacing


# ================================================================ Toast（静态入口）

class Toast:
    """轻量级 Toast 通知 - 静态调用入口

    使用方式::

        Toast.show(parent, "删除成功", Toast.SUCCESS)
        Toast.show(parent, "已删除", Toast.INFO, action_text="撤销", action_callback=undo)
    """

    # 类型常量（方便外部使用）
    SUCCESS = 'success'
    ERROR = 'error'
    INFO = 'info'
    WARNING = 'warning'

    @staticmethod
    def show(
        parent: QWidget,
        message: str,
        toast_type: str = 'info',
        duration: int = 3000,
        action_text: str = '',
        action_callback=None,
    ):
        """
        显示 Toast 通知

        Args:
            parent: 父窗口，Toast 将在其右下角显示
            message: 通知消息文本
            toast_type: 通知类型 (success / error / info / warning)
            duration: 自动关闭时间（毫秒），设为 0 则不自动关闭
            action_text: 可选操作按钮文字（如「撤销」）
            action_callback: 操作按钮点击回调
        """
        if parent is None:
            return

        manager = ToastManager.get_manager(parent)
        toast = ToastWidget(
            message=message,
            toast_type=toast_type,
            duration=duration,
            action_text=action_text,
            action_callback=action_callback,
            parent=parent,
        )
        manager.add_toast(toast)
        return toast
