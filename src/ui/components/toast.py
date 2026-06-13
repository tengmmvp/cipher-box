"""轻量级 Toast 通知组件。

支持成功、错误、信息、警告四种类型，多条通知在父窗口右下角从下向上堆叠，
各自独立的淡入淡出动画，并在鼠标悬停时暂停自动关闭。由 Toast 提供静态调用
入口，ToastManager 负责按父窗口维度复用与定位。
"""

import weakref

from PyQt6.QtCore import (
    QEasingCurve,
    QPropertyAnimation,
    Qt,
    QTimer,
    pyqtSignal,
)
from PyQt6.QtWidgets import (
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ..resources.constants import (
    BTN_CLOSE_TOAST,
    TOAST_HOVER_RESTART_MS,
    TOAST_MARGIN_BOTTOM,
    TOAST_MARGIN_RIGHT,
    TOAST_SPACING,
    TOAST_WIDTH,
)
from ..resources.icons import CLOSE, SIZE_TOAST, icon_pixmap, set_icon
from ..resources.icons import ERROR as ICON_ERROR
from ..resources.icons import INFO as ICON_INFO
from ..resources.icons import SUCCESS as ICON_SUCCESS
from ..resources.icons import WARNING as ICON_WARNING
from ..resources.theme_colors import c

_TOAST_SHADOW_WIDTH = TOAST_WIDTH + 4


class ToastWidget(QFrame):
    """单个 Toast 通知卡片。

    使用 QGraphicsOpacityEffect 实现淡入淡出，因为子控件无法使用 windowOpacity。
    阴影通过在 ToastWidget 外层套一个 ShadowContainer 实现，使透明度效果与
    阴影效果分别作用于不同的 widget，互不冲突。
    """

    closed = pyqtSignal(object)  # 通知 ToastManager 移除自身

    # 类型常量
    SUCCESS = 'success'
    ERROR = 'error'
    INFO = 'info'
    WARNING = 'warning'

    # 类型对应的图标
    _ICONS = {
        SUCCESS: ICON_SUCCESS,
        ERROR: ICON_ERROR,
        INFO: ICON_INFO,
        WARNING: ICON_WARNING,
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
        self._shadow_frame: QFrame | None = None  # 阴影层，由 ToastManager 设置
        self._action_btn: QPushButton | None = None  # 可选操作按钮，主题切换时刷新
        self._fade_in_anim = None
        self._fade_out_anim = None

        self._setup_ui(message, toast_type, action_text)
        self._apply_style(toast_type)

    # ------------------------------------------------------------------ UI
    def _setup_ui(self, message: str, toast_type: str, action_text: str):
        """构建内部布局"""
        self.setFixedWidth(TOAST_WIDTH)
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

        # 类型图标（存为属性 + 名称，主题切换时 refresh_theme 刷新烘焙色）
        self._icon_name = self._ICONS.get(toast_type, ICON_INFO)
        self._icon_label = QLabel()
        self._icon_label.setPixmap(icon_pixmap(self._icon_name, size=SIZE_TOAST))
        self._icon_label.setFixedSize(SIZE_TOAST, SIZE_TOAST)
        self._icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        top_row.addWidget(self._icon_label)

        # 消息文本（存为属性以便主题切换时刷新烘焙的 text_primary 颜色）
        self._msg_label = QLabel(message)
        self._msg_label.setWordWrap(True)
        self._msg_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self._msg_label.setStyleSheet(
            f'font-size: 13px; color: {c("text_primary")}; background: transparent; border: none;'
        )
        top_row.addWidget(self._msg_label, 1)

        # 关闭按钮
        close_btn = QPushButton()
        close_btn.setFixedSize(*BTN_CLOSE_TOAST)
        close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        close_btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        close_btn.clicked.connect(self._start_fade_out)
        set_icon(close_btn, CLOSE)
        close_btn.setObjectName('iconBtn')
        top_row.addWidget(close_btn)

        content_layout.addLayout(top_row)

        # 第二行：可选操作按钮，右对齐
        if action_text:
            self._action_btn = QPushButton(action_text)
            self._action_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            self._action_btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            self._action_btn.setStyleSheet(f"""
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
            self._action_btn.clicked.connect(self._on_action_clicked)
            action_row = QHBoxLayout()
            action_row.addStretch()
            action_row.addWidget(self._action_btn)
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

    def refresh_theme(self):
        """主题切换后重新烘焙配色：刷新背景、强调条、消息文本、操作按钮与类型图标。"""
        self._apply_style(self._toast_type)
        if getattr(self, '_msg_label', None) is not None:
            self._msg_label.setStyleSheet(
                f'font-size: 13px; color: {c("text_primary")}; background: transparent; border: none;'
            )
        if self._action_btn is not None:
            self._action_btn.setStyleSheet(f"""
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
        # 类型图标颜色烘焙进 QPixmap，主题切换时需重建刷新
        if getattr(self, '_icon_label', None) is not None:
            self._icon_label.setPixmap(icon_pixmap(self._icon_name, size=SIZE_TOAST))

    # ------------------------------------------------------------- 动画
    def show_toast(self):
        """显示 Toast，播放淡入动画并启动自动关闭计时器。"""
        self.show()
        self.raise_()

        # 启动新动画前停止旧动画，防止淡入/淡出动画重叠导致闪烁
        if self._fade_out_anim is not None:
            self._fade_out_anim.stop()

        # 淡入动画，基于 QGraphicsOpacityEffect
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

        # 启动新动画前停止旧动画，防止淡入/淡出动画重叠导致闪烁
        if self._fade_in_anim is not None:
            self._fade_in_anim.stop()

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

    def enterEvent(self, event):
        """鼠标进入时暂停自动关闭"""
        self._auto_close_timer.stop()
        super().enterEvent(event)

    def leaveEvent(self, a0):
        """鼠标离开时重启自动关闭，等待时长缩短但不超过原 duration。"""
        if self._duration > 0:
            self._auto_close_timer.start(min(self._duration, TOAST_HOVER_RESTART_MS))
        super().leaveEvent(a0)


# ================================================================ ToastManager

class ToastManager:
    """管理多个 Toast 的位置堆叠。

    每个 parent 窗口对应一个 ToastManager 实例。Toast 以子控件形式定位在
    parent 的右下角，从下向上堆叠，同时为每个 Toast 创建一层独立的阴影包装。
    """

    _instances: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()

    def __init__(self, parent: QWidget):
        self._parent = parent
        self._toasts: list[ToastWidget] = []
        self._spacing = TOAST_SPACING
        self._margin_bottom = TOAST_MARGIN_BOTTOM
        self._margin_right = TOAST_MARGIN_RIGHT

    @staticmethod
    def get_manager(parent: QWidget) -> 'ToastManager':
        """获取或创建 parent 对应的 ToastManager"""
        if parent not in ToastManager._instances:
            ToastManager._instances[parent] = ToastManager(parent)
        return ToastManager._instances[parent]

    def add_toast(self, toast: ToastWidget):
        """添加一个 Toast 并更新所有位置"""
        # 阴影效果：QGraphicsDropShadowEffect 无法叠加在 QGraphicsOpacityEffect 上，
        # 因此使用同位的 QFrame 作为阴影层，详见下方 shadow_frame。
        shadow_color = c('toast_shadow')

        toast.closed.connect(self._remove_toast)
        self._toasts.append(toast)

        # 创建一个同位的阴影 QFrame
        shadow_frame = QFrame(self._parent)
        shadow_frame.setFixedWidth(_TOAST_SHADOW_WIDTH)
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
        # 布局完成后二次校正位置：show_toast 触发布局，首次 _reposition_all 时
        # sizeHint 可能尚未稳定，延迟到事件循环空闲时重算消除堆叠跳变。
        QTimer.singleShot(0, self._reposition_all)

    def cancel_all(self):
        """取消所有活跃 Toast，清空回调并淡出，在锁定前调用此方法。"""
        for toast in list(self._toasts):
            toast._action_callback = None
            toast._start_fade_out()

    @staticmethod
    def cancel_all_for(parent: QWidget):
        """取消指定 parent 窗口的所有活跃 Toast，作为公共 API 暴露。

        替代直接访问 ``ToastManager._instances`` 私有属性的模式，
        供 MainWindow.prepare_for_lock 等外部调用方使用。
        """
        mgr = ToastManager._instances.get(parent)
        if mgr:
            mgr.cancel_all()

    @staticmethod
    def refresh_for(parent: QWidget):
        """主题切换后刷新指定 parent 窗口所有活跃 Toast 的烘焙配色。"""
        mgr = ToastManager._instances.get(parent)
        if mgr:
            mgr.refresh_active_themes()

    def refresh_active_themes(self):
        """重新烘焙所有活跃 Toast 的配色并重定位（阴影颜色随主题变化）。"""
        for toast in list(self._toasts):
            toast.refresh_theme()
            shadow = getattr(toast, '_shadow_frame', None)
            if shadow is not None:
                shadow.setStyleSheet(f"""
                    QFrame {{
                        background-color: {c('toast_shadow')};
                        border: none;
                        border-radius: 10px;
                    }}
                """)
        self._reposition_all()

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
            ToastManager._instances.pop(self._parent, None)

    def _reposition_all(self):
        """重新计算所有 Toast 的位置，从右下角向上堆叠。"""
        if not self._parent:
            return

        parent_rect = self._parent.rect()
        x = parent_rect.width() - TOAST_WIDTH - self._margin_right

        # 从下往上堆叠
        y = parent_rect.height() - self._margin_bottom
        for toast in reversed(self._toasts):
            # 高度回退链：首次布局前 sizeHint 可能返回 0，
            # 此时回退到实际 height()，最终使用保守默认值 60px。
            toast_height = toast.sizeHint().height()
            if toast_height <= 20:
                toast_height = toast.height()
            if toast_height <= 0:
                toast_height = 60
            y -= toast_height
            toast.move(x, y)
            # 同步阴影位置，向右下偏移 2px
            if hasattr(toast, '_shadow_frame') and toast._shadow_frame:
                toast._shadow_frame.setFixedHeight(toast_height + 4)
                toast._shadow_frame.move(x - 2, y + 2)
                toast._shadow_frame.show()
                toast._shadow_frame.lower()
                toast.raise_()
            y -= self._spacing


# ================================================================ Toast 静态入口

class Toast:
    """轻量级 Toast 通知的静态调用入口。

    使用方式::

        Toast.show(parent, "删除成功", Toast.SUCCESS)
        Toast.show(parent, "已删除", Toast.INFO, action_text="撤销", action_callback=undo)
    """

    # 类型常量，方便外部使用，引用自 ToastWidget 以避免重复定义
    SUCCESS = ToastWidget.SUCCESS
    ERROR = ToastWidget.ERROR
    INFO = ToastWidget.INFO
    WARNING = ToastWidget.WARNING

    @staticmethod
    def show(
        parent: QWidget,
        message: str,
        toast_type: str = 'info',
        duration: int = 3000,
        action_text: str = '',
        action_callback=None,
    ):
        """显示 Toast 通知。

        Args:
            parent: 父窗口，Toast 将在其右下角显示
            message: 通知消息文本
            toast_type: 通知类型，取值 success、error、info 或 warning
            duration: 自动关闭时间，单位毫秒，设为 0 则不自动关闭
            action_text: 可选操作按钮文字，例如「撤销」
            action_callback: 操作按钮点击回调
        """
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
