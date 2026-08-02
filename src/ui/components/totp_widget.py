"""TOTP 验证码区域组件。

按秒刷新并展示当前 TOTP 验证码及剩余有效期进度条，提供一键复制。
面板隐藏时暂停定时器以节省资源，重新显示时恢复刷新。
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import QObject, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
)

from ..resources.constants import BTN_TOTP_COPY, FONT_FAMILY_MONOSPACE
from ..resources.icons import COPY, set_icon_with_text
from ..resources.theme_colors import c

if TYPE_CHECKING:
    from ...business.managers.entry_manager import EntryManager

# TOTP 验证码刷新间隔，单位毫秒
MS_TOTP_REFRESH = 1000


class TOTPWidget(QObject):
    """TOTP 验证码显示与刷新组件（纯控制器，无可视自身）。

    构建的验证码控件加入外部传入的 content_layout，自身从不 show，故继承 QObject
    而非 QWidget——QTimer 等仍可以 self 为 parent。通过注入的 EntryManager 引用获取
    TOTP 状态。定时器启停由父级 DetailPanel 在 hideEvent / showEvent 中调用
    stop / resume_if_active 控制。
    """

    copy_requested = pyqtSignal(str)
    copy_feedback = pyqtSignal()

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._entry_mgr: EntryManager | None = None
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._code_label: QLabel | None = None
        self._bar: QProgressBar | None = None
        self._totp_frame: QFrame | None = None
        self._entry_id: int | None = None
        self._period: int = 30
        self._content_layout: QVBoxLayout | None = None

    # ---- 公开接口 ----

    def start(
        self,
        entry_id: int,
        entry_manager: EntryManager,
        content_layout: QVBoxLayout,
        secret: str | None = None,
    ) -> None:
        """启动 TOTP 刷新。

        Args:
            entry_id: 条目 ID
            entry_manager: EntryManager 实例，用于获取 TOTP 状态
            content_layout: TOTP 区域加入的目标布局（DetailPanel._content_layout）
            secret: 调用方已解密的 totp_secret 明文（可选，P3：避免 get_state 二次解密）
        """
        self._entry_mgr = entry_manager
        self._content_layout = content_layout
        self._build(entry_id, secret)

    def stop(self) -> None:
        self._timer.stop()

    def clear(self) -> None:
        """清除所有状态并销毁已构建的 TOTP 区域。"""
        self._timer.stop()
        # 先清空验证码明文再销毁：deleteLater 异步执行，销毁前 label 文本仍驻留
        # Qt 对象，锁定瞬间内存转储可读到。显式 setText 立即擦除可见明文。
        if self._code_label is not None:
            self._code_label.setText("")
        self._entry_id = None
        self._period = 30
        self._code_label = None
        self._bar = None
        # 主动销毁已加入父级布局的 TOTP 区域，避免组件复用时累积泄漏。
        # 上层 DetailPanel._clear_layout 也会兜底清理，重复 deleteLater 安全。
        if self._totp_frame is not None:
            self._totp_frame.deleteLater()
            self._totp_frame = None

    def resume_if_active(self) -> None:
        """面板显示时若当前有条目含 TOTP 则重启定时器。"""
        # 仅当 TOTP 区域仍存在（_code_label 非 None）时重启；_clear_content 后
        # _code_label=None，此时 start 会被 _refresh 的守卫立即 stop，产生无谓启停。
        if self._entry_id and self._code_label is not None:
            self._timer.start(MS_TOTP_REFRESH)

    # ---- 内部方法 ----

    def _build(self, entry_id: int, secret: str | None = None) -> None:
        """构建 TOTP 区域并启动刷新。secret 为调用方已解密的 totp_secret（可选）。"""
        if not self._entry_mgr:
            return
        state = self._entry_mgr.totp.get_state(entry_id, preloaded_secret=secret)
        if not state:
            return
        self._entry_id = entry_id
        self._period = state["period"]

        # 使用 start 注入的 content_layout（显式依赖，避免反射父组件私有属性）
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

        totp_title = QLabel("验证码 (TOTP)")
        totp_title.setStyleSheet(f"font-weight: bold; font-size: 13px; color: {c('accent_text')};")
        totp_layout.addWidget(totp_title)

        code_row = QHBoxLayout()
        code_row.setSpacing(12)

        self._code_label = QLabel(state["code"])
        self._code_label.setStyleSheet(
            f"font-size: 28px; font-weight: bold; letter-spacing: 6px; "
            f"color: {c('accent_text')}; font-family: {FONT_FAMILY_MONOSPACE};"
        )
        code_row.addWidget(self._code_label)

        # 倒计时进度条
        self._bar = QProgressBar()
        self._bar.setRange(0, state["period"])
        self._bar.setValue(state["remaining"])
        self._bar.setFixedHeight(6)
        self._bar.setTextVisible(False)
        self._bar.setStyleSheet(f"""
            QProgressBar {{ background: {c("border_light")}; border: none; border-radius: 3px; }}
            QProgressBar::chunk {{ background: {c("accent")}; border-radius: 3px; }}
        """)
        code_row.addWidget(self._bar, 1)

        # 复制按钮
        copy_btn = QPushButton()
        set_icon_with_text(copy_btn, "复制", COPY)
        copy_btn.setFixedSize(*BTN_TOTP_COPY)
        copy_btn.clicked.connect(self._copy_code)
        copy_btn.clicked.connect(self.copy_feedback.emit)
        code_row.addWidget(copy_btn)

        totp_layout.addLayout(code_row)
        content_layout.addWidget(totp_frame)

        # 启动每秒一次的定时刷新
        self._timer.start(MS_TOTP_REFRESH)

    def _refresh(self) -> None:
        """刷新 TOTP 验证码，调用 totp.generate_cached 复用缓存的 period。

        _build 启动时已通过 totp.get_state 预热会话内 secret 缓存，
        此处仅做纯 HOTP 计算，不再每秒查 DB 与 AESGCM 解密。当 key_epoch 因
        改密或锁定而变化，或条目更新、删除时缓存自动失效，下次刷新重新解密。
        """
        if not self._entry_id or not self._code_label or not self._entry_mgr:
            self._timer.stop()
            return
        code = self._entry_mgr.totp.generate_cached(self._entry_id)
        if not code:
            self._timer.stop()
            return
        self._code_label.setText(code)
        if self._bar is not None:
            # 经 TotpService 计算剩余秒数：其内部对 period<=0 回退默认值，消除本处
            # 独立取模的除零风险；走业务门面而非直接依赖 crypto 层。
            self._bar.setValue(self._entry_mgr.totp.remaining_seconds(self._period))

    def _copy_code(self) -> None:
        """复制当前 TOTP 验证码，始终取最新值。"""
        if self._code_label:
            self.copy_requested.emit(self._code_label.text())
