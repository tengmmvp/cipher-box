"""密码历史区域组件 — 从 DetailPanel 拆分"""

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ..resources.constants import BTN_COPY, FONT_FAMILY_MONOSPACE, MAX_HISTORY_DISPLAY
from ..resources.icons import COPY, EYE, LOCK, set_icon
from ..resources.theme_colors import c


def zero_buffer_copy(value: str) -> None:
    """尽力零化字符串的编码副本（纵深防御）。

    WARNING: 此方法在 CPython 下**不保证**清除原始字符串内存。
    Python ``str`` 不可变，此方法仅零化 ``encode()`` 后的 bytearray 副本，
    **不影响**原始字符串对象。
    """
    if not value:
        return
    try:
        buf = bytearray(value.encode('utf-16-le'))
        for i in range(len(buf)):
            buf[i] = 0
        del buf
    except Exception:
        pass


class PasswordHistoryWidget(QWidget):
    """密码历史折叠区组件。

    通过 ``load_for_entry()`` 注入 EntryManager 引用来获取密码历史。
    延迟加载：先显示摘要，点击展开才解密。
    """

    copy_requested = pyqtSignal(str)
    copy_feedback = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._history_passwords: list[str] = []
        self._entry_mgr = None
        # 外部 _field_hide_timers 引用，通过 set_hide_timers_ref 注入
        self._field_hide_timers: list[QTimer] = []
        # 回调：获取密码可见毫秒数
        self._get_pwd_visible_ms = None
        # 回调：复制并反馈
        self._copy_with_feedback = None

    # ---- 公开接口 ----

    def set_hide_timers_ref(self, timers: list[QTimer]):
        """接收外部 _field_hide_timers 引用。"""
        self._field_hide_timers = timers

    def set_callbacks(self, get_pwd_visible_ms, copy_with_feedback):
        """注入回调函数。

        Args:
            get_pwd_visible_ms: 无参函数，返回密码可见毫秒数
            copy_with_feedback: 接受 (btn, text) 参数的复制反馈函数
        """
        self._get_pwd_visible_ms = get_pwd_visible_ms
        self._copy_with_feedback = copy_with_feedback

    def build_stub(self, entry_id: int, entry_manager, content_layout):
        """构建密码历史占位摘要，点击时才加载完整历史。

        Args:
            entry_id: 条目 ID
            entry_manager: EntryManager 实例
            content_layout: 目标布局（DetailPanel._content_layout）
        """
        self._entry_mgr = entry_manager
        if not entry_manager:
            return
        count = entry_manager.get_password_history_count(entry_id)
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

        def _expand(_checked=False, eid=entry_id, button=btn):
            mgr = self._entry_mgr
            if not mgr:
                return
            decrypted = mgr.decrypt_password_history(
                mgr.get_password_history(eid)
            )
            if decrypted:
                content_layout.removeWidget(button)
                button.deleteLater()
                self._build_history(decrypted, content_layout)

        btn.clicked.connect(_expand)
        content_layout.addWidget(btn)

    def clear(self):
        """安全清除所有状态和密码。"""
        for p in self._history_passwords:
            zero_buffer_copy(p)
        self._history_passwords.clear()
        self._entry_mgr = None

    # ---- 内部方法 ----

    def _build_history(self, history: list[dict], content_layout):
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

            # 密码（初始隐藏）
            pwd_text = record.get('password', '')
            pwd_label = QLabel('••••••••')
            pwd_label.setStyleSheet(
                f'font-family: {FONT_FAMILY_MONOSPACE}; font-size: 12px; color: {c("text_primary")};'
            )
            row.addWidget(pwd_label, 1)

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

            # 历史密码显示超时定时器（持久、可取消）
            hist_timer = QTimer(self)
            hist_timer.setSingleShot(True)
            self._field_hide_timers.append(hist_timer)

            def _on_hist_timeout(lbl=pwd_label, btn=show_btn, idx=hist_idx):
                lbl.setText('••••••••')
                set_icon(btn, EYE)
                if idx < len(self._history_passwords):
                    self._history_passwords[idx] = ''

            hist_timer.timeout.connect(_on_hist_timeout)

            def toggle_pwd(_checked=False, lbl=pwd_label, btn=show_btn, idx=hist_idx, timer=hist_timer):
                pwd = self._history_passwords[idx] if idx < len(self._history_passwords) else ''
                if lbl.text() == '••••••••':
                    lbl.setText(pwd)
                    set_icon(btn, LOCK)
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

            def do_copy(_checked=False, idx=hist_idx, btn=copy_btn):
                pwd = self._history_passwords[idx] if idx < len(self._history_passwords) else ''
                self._copy_with_feedback(btn, pwd)

            copy_btn.clicked.connect(do_copy)
            copy_btn.clicked.connect(self.copy_feedback.emit)
            row.addWidget(copy_btn)

            group_layout.addLayout(row)

        content_layout.addWidget(group)
