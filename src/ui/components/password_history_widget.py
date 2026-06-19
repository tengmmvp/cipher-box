"""密码历史区域组件，从 DetailPanel 拆分。

以折叠摘要形式展示密码历史，点击展开后才解密完整记录并渲染每一项的
时间、显示/隐藏切换与复制按钮。历史密码通过间接引用列表持有，闭包按索引
读取，清除时统一释放明文。
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ...utils.memory import mark_secret_discarded
from ..resources.constants import BTN_COPY, FONT_FAMILY_MONOSPACE, MAX_HISTORY_DISPLAY
from ..resources.icons import COPY, EYE, LOCK, set_icon
from ..resources.theme_colors import c

if TYPE_CHECKING:
    from ...business.managers.entry_manager import EntryManager


class PasswordHistoryWidget(QWidget):
    """密码历史折叠区组件。

    通过注入的 EntryManager 引用获取密码历史，采用延迟加载：先显示摘要，
    点击展开后才解密完整记录。
    """

    copy_requested = pyqtSignal(str)
    copy_feedback = pyqtSignal()

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._history_passwords: list[str] = []
        # 已渲染的密码 QLabel 引用：clear() 时先 setText 掩码再销毁，
        # 避免 deleteLater 异步销毁前明文驻留 Qt 对象（锁定时内存转储可读）。
        self._pwd_labels: list[QLabel] = []
        self._entry_mgr: EntryManager | None = None
        # 本组件自管的密码显示超时定时器：clear() 时停止，所有权清晰，
        # 不再依赖外层 DetailPanel 的调用顺序兜底。
        self._own_timers: list[QTimer] = []
        # 回调：获取密码可见毫秒数
        self._get_pwd_visible_ms: Callable[[], int] | None = None
        # 回调：复制并反馈
        self._copy_with_feedback: Callable[..., None] | None = None

    # ---- 公开接口 ----

    def set_callbacks(
        self,
        get_pwd_visible_ms: Callable[[], int],
        copy_with_feedback: Callable[..., None],
    ) -> None:
        """注入回调函数。

        Args:
            get_pwd_visible_ms: 无参函数，返回密码可见毫秒数
            copy_with_feedback: 复制反馈函数，接受按钮与文本两个参数
        """
        self._get_pwd_visible_ms = get_pwd_visible_ms
        self._copy_with_feedback = copy_with_feedback

    def build_stub(
        self,
        entry_id: int,
        entry_manager: EntryManager,
        content_layout: QVBoxLayout,
    ) -> None:
        """构建密码历史占位摘要，点击时才加载完整历史。

        Args:
            entry_id: 条目 ID
            entry_manager: EntryManager 实例
            content_layout: 目标布局，通常为 DetailPanel._content_layout
        """
        self._entry_mgr = entry_manager
        if not entry_manager:
            return
        count = entry_manager.password_history.get_count(entry_id)
        if not count:
            return
        btn = QPushButton(f'密码历史（{count} 条记录）— 点击展开')
        btn.setFlat(True)
        btn.setStyleSheet(f"""
            QPushButton {{
                text-align: left; color: {c("text_secondary")};
                font-size: 12px; padding: 6px 0; border: none;
            }}
            QPushButton:hover {{ color: {c("accent")}; }}
        """)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)

        def _expand(_checked: bool = False, eid: int = entry_id, button: QPushButton = btn) -> None:
            mgr = self._entry_mgr
            if not mgr:
                return
            decrypted = mgr.password_history.decrypt(
                mgr.password_history.get(eid)
            )
            if decrypted:
                content_layout.removeWidget(button)
                button.deleteLater()
                self._build_history(decrypted, content_layout)

        btn.clicked.connect(_expand)
        content_layout.addWidget(btn)

    def clear(self) -> None:
        """安全清除所有状态和密码。"""
        # 停止本组件自管的定时器，避免到期回调访问已销毁控件。
        for timer in self._own_timers:
            timer.stop()
        self._own_timers.clear()
        # 先掩码已渲染的明文 QLabel 再释放，避免 deleteLater 异步销毁前明文驻留。
        for lbl in self._pwd_labels:
            lbl.setText('••••••••')
        self._pwd_labels.clear()
        for p in self._history_passwords:
            mark_secret_discarded(p)
        self._history_passwords.clear()
        self._entry_mgr = None

    # ---- 内部方法 ----

    def _build_history(self, history: list[dict], content_layout: QVBoxLayout) -> None:
        """构建密码历史折叠区。"""
        group = QGroupBox('密码历史')
        group_layout = QVBoxLayout(group)
        group_layout.setSpacing(6)

        for record in history[:MAX_HISTORY_DISPLAY]:
            row = QHBoxLayout()
            row.setSpacing(8)

            # 时间
            time_label = QLabel(record.get('changed_at', ''))
            time_label.setFixedWidth(140)
            time_label.setStyleSheet(f'color: {c("text_muted")}; font-size: 12px;')
            row.addWidget(time_label)

            # 密码，初始隐藏
            pwd_text = record.get('password', '')
            pwd_label = QLabel('••••••••')
            pwd_label.setStyleSheet(
                f'font-family: {FONT_FAMILY_MONOSPACE}; font-size: 12px; color: {c("text_primary")};'
            )
            row.addWidget(pwd_label, 1)
            self._pwd_labels.append(pwd_label)

            # 历史密码存入间接引用列表，闭包通过索引读取，
            # clear() 时清空列表即可释放明文。
            hist_idx = len(self._history_passwords)
            self._history_passwords.append(pwd_text)

            # 显示/隐藏按钮
            show_btn = QPushButton()
            set_icon(show_btn, EYE)
            show_btn.setObjectName('iconBtn')
            show_btn.setFixedSize(*BTN_COPY)
            show_btn.setToolTip('显示/隐藏')

            # 历史密码显示超时定时器，持久且可取消
            hist_timer = QTimer(self)
            hist_timer.setSingleShot(True)
            self._own_timers.append(hist_timer)

            def _on_hist_timeout(lbl: QLabel = pwd_label, btn: QPushButton = show_btn) -> None:
                # 仅重置显示，不清空槽位：历史密码需支持显示→隐藏→再显示，
                # 与主密码字段一致；明文释放统一交给 clear() 的 mark_secret_discarded。
                lbl.setText('••••••••')
                set_icon(btn, EYE)

            hist_timer.timeout.connect(_on_hist_timeout)

            def toggle_pwd(_checked: bool = False, lbl: QLabel = pwd_label, btn: QPushButton = show_btn, idx: int = hist_idx, timer: QTimer = hist_timer) -> None:
                pwd = self._history_passwords[idx] if idx < len(self._history_passwords) else ''
                if lbl.text() == '••••••••':
                    lbl.setText(pwd)
                    set_icon(btn, LOCK)
                    if self._get_pwd_visible_ms is None:
                        return
                    timer.start(self._get_pwd_visible_ms())
                else:
                    lbl.setText('••••••••')
                    set_icon(btn, EYE)
                    timer.stop()

            show_btn.clicked.connect(toggle_pwd)
            row.addWidget(show_btn)

            # 复制按钮
            copy_btn = QPushButton()
            set_icon(copy_btn, COPY)
            copy_btn.setObjectName('iconBtn')
            copy_btn.setFixedSize(*BTN_COPY)
            copy_btn.setToolTip('复制密码')

            def do_copy(_checked: bool = False, idx: int = hist_idx, btn: QPushButton = copy_btn) -> None:
                pwd = self._history_passwords[idx] if idx < len(self._history_passwords) else ''
                if self._copy_with_feedback is None:
                    return
                self._copy_with_feedback(btn, pwd)

            copy_btn.clicked.connect(do_copy)
            copy_btn.clicked.connect(self.copy_feedback.emit)
            row.addWidget(copy_btn)

            group_layout.addLayout(row)

        content_layout.addWidget(group)
