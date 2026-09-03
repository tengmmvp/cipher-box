"""密码历史区域组件。

以折叠摘要形式展示密码历史，点击展开后才解密完整记录并渲染每一项的
时间、显示/隐藏切换与复制按钮。历史密码通过间接引用字典持有，闭包按行号
读取，清除时统一释放明文。行三件套（掩码标签/显隐/复制按钮）复用 secret_field
共享工厂（MAINT-103：掩码常量与竞态守卫收敛单处），每行独立掩码定时器——
历史行可同时揭示多行，与主密码的共享单定时器模式语义不同。
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from PyQt6.QtCore import QObject, Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
)

from ...utils.memory import mark_secret_discarded
from ..resources.constants import FONT_FAMILY_MONOSPACE, MAX_HISTORY_DISPLAY, PWD_MASK
from ..resources.theme_colors import c
from .secret_field import SecretFieldEnv, make_secret_field_row
from .widgets import create_plain_text_label

if TYPE_CHECKING:
    from ...business.managers.entry_manager import EntryManager


class PasswordHistoryWidget(QObject):
    """密码历史折叠区组件（纯控制器，无可视自身）。

    构建的折叠区控件加入外部传入的 ``content_layout``，自身从不 ``show``，故继承 QObject
    而非 QWidget。通过注入的 ``EntryManager`` 引用获取密码历史，采用延迟加载：先显示
    摘要，点击展开后才解密记录。
    """

    copy_feedback = pyqtSignal()

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        # 历史密码间接引用字典（行号 → 明文），闭包按行号读取，
        # `clear()` 时清空字典即可释放明文。
        self._history_passwords: dict[int, str] = {}
        # 已渲染的密码 `QLabel` 引用：`clear()` 时先 `setText` 掩码再销毁，
        # 避免 `deleteLater` 异步销毁前明文驻留 Qt 对象（锁定时内存转储可读）。
        self._pwd_labels: list[QLabel] = []
        self._entry_mgr: EntryManager | None = None
        # 本组件自管的密码显示超时定时器（每行独立），`clear()` 时统一停止。
        self._own_timers: list[QTimer] = []
        # 回调：获取密码可见毫秒数
        self._get_pwd_visible_ms: Callable[[], int] | None = None
        # 回调：复制并反馈
        self._copy_with_feedback: Callable[[QPushButton, str], None] | None = None

    # ---- 公开接口 ----

    def set_callbacks(
        self,
        get_pwd_visible_ms: Callable[[], int],
        copy_with_feedback: Callable[[QPushButton, str], None],
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
            entry_manager: ``EntryManager`` 实例
            content_layout: 目标布局，通常为 ``DetailPanel._content_layout``
        """
        self._entry_mgr = entry_manager
        if not entry_manager:
            return
        count = entry_manager.password_history.get_count(entry_id)
        if not count:
            return
        btn = QPushButton(f"密码历史（{count} 条记录）— 点击展开")
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
            # 仅渲染 `MAX_HISTORY_DISPLAY` 条，截断后再解密，避免持 `vault_write_lock` 解密
            # 全量历史。`get` 已按 `changed_at` DESC 返回，切片取最近 N 条。
            full = mgr.password_history.get(eid)
            decrypted = mgr.password_history.decrypt(full[:MAX_HISTORY_DISPLAY])
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
        # 先掩码已渲染的明文 `QLabel` 再释放，避免 `deleteLater` 异步销毁前明文驻留。
        for lbl in self._pwd_labels:
            lbl.setText(PWD_MASK)
        self._pwd_labels.clear()
        for p in self._history_passwords.values():
            mark_secret_discarded(p)
        self._history_passwords.clear()
        self._entry_mgr = None

    # ---- 内部方法 ----

    def _make_env(self) -> SecretFieldEnv[int]:
        """按当前回调就位情况构造共享工厂环境。

        回调未注入（`set_callbacks` 前构建）时降级：``get_pwd_visible_ms`` 返回
        None 表示不启动自动掩码、``on_copy`` 为 no-op——与原手写实现的防御分支
        行为一致（揭示仍显示明文、复制无操作、不抛异常）。
        """
        get_ms = self._get_pwd_visible_ms
        copy_fn = self._copy_with_feedback
        return SecretFieldEnv(
            store=self._history_passwords,
            timers=self._own_timers,
            parent_widget=self,
            get_pwd_visible_ms=get_ms if get_ms is not None else (lambda: None),
            on_copy=copy_fn if copy_fn is not None else (lambda btn, text: None),
            on_copy_feedback=self.copy_feedback.emit,
        )

    def _build_history(self, history: list[dict[str, str]], content_layout: QVBoxLayout) -> None:
        """构建密码历史折叠区。"""
        group = QGroupBox("密码历史")
        group_layout = QVBoxLayout(group)
        group_layout.setSpacing(6)

        for record in history[:MAX_HISTORY_DISPLAY]:
            row = QHBoxLayout()
            row.setSpacing(8)

            # changed_at 时间标签经 PlainText 工厂（SEC-030）：时间戳字符串随导入
            # 数据可携带 markup 字符，字面显示与密码标签契约一致
            time_label = create_plain_text_label(record.get("changed_at", ""))
            time_label.setFixedWidth(140)
            time_label.setStyleSheet(f"color: {c('text_muted')}; font-size: 12px;")
            row.addWidget(time_label)

            # 密码行复用共享工厂（MAINT-103）：掩码/显隐/复制三件套与竞态守卫收敛
            # 单处，历史行保持每行独立定时器（可同时揭示多行）。名称标签弃用——
            # 行首位置由时间标签占据。
            pwd_text = record.get("password", "")
            hist_idx = len(self._history_passwords)
            _name, secret_row = make_secret_field_row(
                self._make_env(),
                "",
                pwd_text,
                hist_idx,
                val_label_style=(
                    f"font-family: {FONT_FAMILY_MONOSPACE}; font-size: 12px;"
                    f" color: {c('text_primary')};"
                ),
            )
            # 行内唯一 QLabel 即掩码值标签（名称标签未入布局）：持引用供 clear()
            # 时先掩码再销毁。
            pwd_label = secret_row.findChild(QLabel)
            if pwd_label is not None:
                self._pwd_labels.append(pwd_label)
            row.addWidget(secret_row, 1)

            group_layout.addLayout(row)

        content_layout.addWidget(group)
        # record dict 的 password 明文已提取到 `_history_passwords`，不再需要 dict 中的
        # 明文副本——显式 `pop` 收缩驻留面，不依赖 `_expand` 返回后的 GC 回收。
        for record in history:
            record.pop("password", None)
