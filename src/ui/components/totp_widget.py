"""TOTP 验证码区域组件，从 DetailPanel 拆分。

按秒刷新并展示当前 TOTP 验证码及剩余有效期进度条，提供一键复制。
面板隐藏时暂停定时器以节省资源，重新显示时恢复刷新。
"""

import time as _time

from PyQt6.QtCore import QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ..resources.constants import BTN_TOTP_COPY, FONT_FAMILY_MONOSPACE
from ..resources.icons import COPY, set_icon_with_text
from ..resources.theme_colors import c

# TOTP 验证码刷新间隔，单位毫秒
MS_TOTP_REFRESH = 1000


class TOTPWidget(QWidget):
    """TOTP 验证码显示与刷新组件。

    通过注入的 EntryManager 引用获取 TOTP 状态。面板隐藏时自动暂停定时器，
    重新显示时恢复刷新。
    """

    copy_requested = pyqtSignal(str)
    copy_feedback = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._entry_mgr = None
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._code_label: QLabel | None = None
        self._bar: QProgressBar | None = None
        self._totp_frame: QFrame | None = None
        self._entry_id: int | None = None
        self._period: int = 30
        self._content_layout = None

    # ---- 公开接口 ----

    def start(self, entry_id: int, entry_manager, content_layout):
        """启动 TOTP 刷新。

        Args:
            entry_id: 条目 ID
            entry_manager: EntryManager 实例，用于获取 TOTP 状态
            content_layout: TOTP 区域加入的目标布局（DetailPanel._content_layout）
        """
        self._entry_mgr = entry_manager
        self._content_layout = content_layout
        self._build(entry_id)

    def stop(self):
        """停止定时器。"""
        self._timer.stop()

    def clear(self):
        """清除所有状态并销毁已构建的 TOTP 区域。"""
        self._timer.stop()
        self._entry_id = None
        self._period = 30
        self._code_label = None
        self._bar = None
        # 主动销毁已加入父级布局的 TOTP 区域，避免组件复用时累积泄漏。
        # 上层 DetailPanel._clear_layout 也会兜底清理，重复 deleteLater 安全。
        if self._totp_frame is not None:
            self._totp_frame.deleteLater()
            self._totp_frame = None

    def resume_if_active(self):
        """面板显示时若当前有条目含 TOTP 则重启定时器。"""
        if self._entry_id:
            self._timer.start(MS_TOTP_REFRESH)

    # ---- 内部方法 ----

    def _build(self, entry_id: int):
        """构建 TOTP 区域并启动刷新。"""
        if not self._entry_mgr:
            return
        state = self._entry_mgr.get_totp_state(entry_id)
        if not state:
            return
        self._entry_id = entry_id
        self._period = state['period']

        # 使用 start 注入的 content_layout（显式依赖，不再反射访问父组件私有属性）
        content_layout = self._content_layout
        if content_layout is None:
            return

        totp_frame = QFrame()
        self._totp_frame = totp_frame
        totp_frame.setStyleSheet(f"""
            QFrame {{
                background: {c("accent_light")};
                border: 1px solid {c("tag_border")};
                border-radius: 8px;
                padding: 8px;
            }}
        """)
        totp_layout = QVBoxLayout(totp_frame)
        totp_layout.setSpacing(6)

        totp_title = QLabel('验证码 (TOTP)')
        totp_title.setStyleSheet(f'font-weight: bold; font-size: 13px; color: {c("accent_text")};')
        totp_layout.addWidget(totp_title)

        code_row = QHBoxLayout()
        code_row.setSpacing(12)

        self._code_label = QLabel(state['code'])
        self._code_label.setStyleSheet(
            f'font-size: 28px; font-weight: bold; letter-spacing: 6px; '
            f'color: {c("accent_text")}; font-family: {FONT_FAMILY_MONOSPACE};'
        )
        code_row.addWidget(self._code_label)

        # 倒计时进度条
        self._bar = QProgressBar()
        self._bar.setRange(0, state['period'])
        self._bar.setValue(state['remaining'])
        self._bar.setFixedHeight(6)
        self._bar.setTextVisible(False)
        self._bar.setStyleSheet(f"""
            QProgressBar {{ background: {c("border_light")}; border: none; border-radius: 3px; }}
            QProgressBar::chunk {{ background: {c("accent")}; border-radius: 3px; }}
        """)
        code_row.addWidget(self._bar, 1)

        # 复制按钮
        copy_btn = QPushButton()
        set_icon_with_text(copy_btn, '复制', COPY)
        copy_btn.setFixedSize(*BTN_TOTP_COPY)
        copy_btn.clicked.connect(self._copy_code)
        copy_btn.clicked.connect(self.copy_feedback.emit)
        code_row.addWidget(copy_btn)

        totp_layout.addLayout(code_row)
        content_layout.addWidget(totp_frame)

        # 启动每秒一次的定时刷新
        self._timer.start(MS_TOTP_REFRESH)

    def _refresh(self):
        """刷新 TOTP 验证码，调用 generate_totp_cached 复用缓存的 period。

        _build 启动时已通过 get_totp_state 预热 EntryManager 的 secret 缓存，
        此处仅做纯 HOTP 计算，不再每秒查 DB 与 AESGCM 解密。当 key_epoch 因
        改密或锁定而变化，或条目更新、删除时缓存自动失效，下次刷新重新解密。
        """
        if not self._entry_id or not self._code_label or not self._entry_mgr:
            self._timer.stop()
            return
        code = self._entry_mgr.generate_totp_cached(self._entry_id)
        if not code:
            self._timer.stop()
            return
        self._code_label.setText(code)
        if self._bar:
            remaining = self._period - (int(_time.time()) % self._period)
            self._bar.setValue(remaining)

    def _copy_code(self):
        """复制当前 TOTP 验证码，始终取最新值。"""
        if self._code_label:
            self.copy_requested.emit(self._code_label.text())
