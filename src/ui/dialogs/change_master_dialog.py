"""修改主密码对话框。

全量重新加密耗时较高，在后台线程执行。内置速率限制与失败锁定，校验
旧密码、新密码强度与两次一致性后才提交，完成后立即清除明文输入。
"""

from __future__ import annotations

import logging

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ...business.managers.vault_lifecycle import CHANGE_AUTH_FAILED_MESSAGE
from ...business.managers.vault_manager import VaultManager
from ...business.services.password_service import PasswordService
from ...business.services.rate_limiter import RateLimiter
from ..components.widgets import (
    WorkerBackedDialog,
    create_cancel_button,
    create_password_toggle_btn,
    finalize_worker_if_current,
    set_label_severity,
    setup_dialog_flags,
    update_strength_label,
)
from ..components.workers import BackgroundWorker
from ..resources.constants import (
    BTN_DIALOG,
    DIALOG_CHANGE_MASTER_MIN_SIZE,
    PWD_TOGGLE_AUTO_HIDE_SECONDS,
)
from ..resources.strings import DLG_TITLE_ERROR, DLG_TITLE_SUCCESS

logger = logging.getLogger(__name__)


class ChangeMasterDialog(WorkerBackedDialog):
    """主密码修改对话框，含旧密码校验与新密码强度校验。"""

    def __init__(
        self,
        vault_manager: VaultManager,
        rate_limiter: RateLimiter,
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self._vault = vault_manager
        # 限流器经组合根创建注入（ARCH-043）：有跨进程持久状态的业务安全模块，
        # 状态文件命名与哨兵登记归业务层单一事实源，UI 不再实例化。
        self._rate_limiter = rate_limiter
        self._setup_ui()

    def _clear_password_inputs(self) -> None:
        """清除全部密码输入框，缩短明文在控件中的驻留时间。"""
        self._old_pwd.clear()
        self._new_pwd.clear()
        self._confirm_pwd.clear()

    def _before_reject(self) -> None:
        # 桥接取消：设 vault 取消事件以中断重加密循环（`worker.cancel` 仅设
        # `worker` 自身标志，重加密不检查它）。重加密检测后抛异常回滚。
        if self._worker is not None and self._worker.isRunning():
            self._vault.request_cancel()

    def _after_release(self) -> None:
        # 取消时同样清除全部密码输入，与成功/失败路径一致，缩短明文驻留
        self._clear_password_inputs()

    def _setup_ui(self) -> None:
        self.setWindowTitle("修改主密码")
        self.setMinimumSize(*DIALOG_CHANGE_MASTER_MIN_SIZE)
        setup_dialog_flags(self)

        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(36, 30, 36, 30)
        # _build_* 分块构建（MAINT-094，对齐 entry_dialog 模式）：标题 → 三段密码输入 →
        # 强度/提示 → 按钮行，纯机械搬移不改控件树与行为。
        self._build_header(layout)
        self._build_old_password_field(layout)
        self._build_new_password_field(layout)
        self._build_confirm_password_field(layout)
        self._build_feedback_labels(layout)
        layout.addLayout(self._build_buttons())

    def _build_header(self, layout: QVBoxLayout) -> None:
        """构建标题与说明区。"""
        title = QLabel("修改主密码")
        title.setStyleSheet("font-size: 17px; font-weight: 600;")
        layout.addWidget(title)

        info = QLabel("修改主密码后，所有数据将使用新密码重新加密。\n请确保牢记新密码。")
        info.setObjectName("formMuted")
        info.setWordWrap(True)
        layout.addWidget(info)

    def _build_old_password_field(self, layout: QVBoxLayout) -> None:
        """构建当前主密码输入行。"""
        self._old_pwd = self._make_pwd_edit("请输入当前主密码")
        self._add_pwd_field_row(layout, "当前主密码：", self._old_pwd, "_old_toggle")

    def _build_new_password_field(self, layout: QVBoxLayout) -> None:
        """构建新主密码输入行（强度联动）。"""
        self._new_pwd = self._make_pwd_edit("请输入新主密码（至少 15 位）")
        self._new_pwd.textChanged.connect(self._on_pwd_changed)
        self._add_pwd_field_row(layout, "新主密码：", self._new_pwd, "_new_toggle")

    def _build_confirm_password_field(self, layout: QVBoxLayout) -> None:
        """构建确认新密码输入行（回车直接提交）。"""
        self._confirm_pwd = self._make_pwd_edit("请再次输入新主密码")
        self._confirm_pwd.returnPressed.connect(self._on_change)
        self._add_pwd_field_row(layout, "确认新密码：", self._confirm_pwd, "_confirm_toggle")

    def _add_pwd_field_row(
        self,
        layout: QVBoxLayout,
        label_text: str,
        edit: QLineEdit,
        toggle_attr: str,
    ) -> None:
        """把「标签 + 密码框 + 显示切换按钮」行加入布局。

        三段密码输入（当前/新/确认）行结构同构，经本 helper 组装消除三段复制
        （MAINT-094）；切换按钮经 ``setattr`` 存入 ``toggle_attr`` 指定的实例属性。
        """
        layout.addWidget(QLabel(label_text))
        field_layout = QHBoxLayout()
        field_layout.addWidget(edit)
        toggle = create_password_toggle_btn(edit, auto_hide_seconds=PWD_TOGGLE_AUTO_HIDE_SECONDS)
        setattr(self, toggle_attr, toggle)
        field_layout.addWidget(toggle)
        layout.addLayout(field_layout)

    @staticmethod
    def _make_pwd_edit(placeholder: str) -> QLineEdit:
        """构建密码输入框（密码回显模式 + 占位文案）。"""
        edit = QLineEdit()
        edit.setEchoMode(QLineEdit.EchoMode.Password)
        edit.setPlaceholderText(placeholder)
        return edit

    def _build_feedback_labels(self, layout: QVBoxLayout) -> None:
        """构建强度显示与错误提示标签。"""
        self._strength_label = QLabel("")
        self._strength_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._strength_label.setStyleSheet("font-size: 12px;")
        layout.addWidget(self._strength_label)

        self._msg_label = QLabel("")
        self._msg_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._msg_label.setObjectName("formMessage")
        set_label_severity(self._msg_label, "error")
        layout.addWidget(self._msg_label)

    def _build_buttons(self) -> QHBoxLayout:
        """构建取消与修改按钮行。"""
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        btn_layout.addWidget(create_cancel_button(self))

        self._change_btn = QPushButton("修改")
        self._change_btn.setObjectName("primaryBtn")
        self._change_btn.setFixedSize(*BTN_DIALOG)
        self._change_btn.clicked.connect(self._on_change)
        btn_layout.addWidget(self._change_btn)
        return btn_layout

    def _on_pwd_changed(self, text: str) -> None:
        update_strength_label(self._strength_label, text)

    def _on_change(self) -> None:
        # 重复提交守卫：重加密期间 `returnPressed` 仍可触发本方法（`setEnabled`
        # 只禁按钮点击），需显式拦截。
        if self._worker is not None and self._worker.isRunning():
            return
        msg = self._rate_limiter.check()
        if msg:
            self._msg_label.setText(msg)
            return

        old = self._old_pwd.text()
        new = self._new_pwd.text()
        confirm = self._confirm_pwd.text()

        if not old:
            self._msg_label.setText("请输入当前主密码")
            return
        if not new:
            self._msg_label.setText("请输入新主密码")
            return
        valid, error = PasswordService.validate_master_password(new)
        if not valid:
            self._msg_label.setText(error)
            return
        # 常量时间比较经 PasswordService.passwords_match 统一门面（SEC-031）：
        # encode('utf-8') 与 compare_digest 的配对不再由各调用点内联维护，防
        # QL-019 同型 bug（非 ASCII 密码抛 TypeError 被 Qt 槽吞掉、表单静默失败）复发。
        if not PasswordService.passwords_match(new, confirm):
            self._msg_label.setText("两次输入的新密码不一致")
            return
        if PasswordService.passwords_match(old, new):
            self._msg_label.setText("新密码不能与旧密码相同")
            return

        reply = QMessageBox.warning(
            self,
            "确认修改",
            "修改主密码将重新加密所有数据。\n此过程可能需要几秒钟。\n\n确定要继续吗？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        # 全量重新加密耗时较高，置于后台线程执行避免冻结 UI
        self._change_btn.setEnabled(False)
        set_label_severity(self._msg_label, "accent")
        self._msg_label.setText("正在重新加密所有数据...")

        self._worker = BackgroundWorker(
            lambda: self._vault.change_master_password(old, new),
            parent=self,
        )
        self._worker.finished.connect(self._on_change_done)
        self._worker.error.connect(self._on_change_error)
        self._worker.start()
        # old/new 已作为 `lambda` 闭包值捕获，清控件不影响 `worker`；启动即清空，缩短
        # 明文在控件的驻留窗口，对齐 `login_window` SEC-018 纪律。
        self._clear_password_inputs()

    def _on_change_done(self, result: tuple[bool, str]) -> None:
        if not finalize_worker_if_current(self):
            return
        self._change_btn.setEnabled(True)
        set_label_severity(self._msg_label, "error")
        success, error_msg = result
        # 无论成功与否都清除全部密码输入，缩短明文在控件中的驻留时间
        self._clear_password_inputs()
        if success:
            self._rate_limiter.record_success()
            message = "主密码已修改成功！"
            # 改密成功但 purge 失败时，error_msg 携带 warning，附加提示用户手动清理
            if error_msg:
                message += f"\n\n{error_msg}"
            QMessageBox.information(self, DLG_TITLE_SUCCESS, message)
            self.accept()
        else:
            # (False, ...) 契约下唯一语义为认证失败（ARCH-042 对齐 unlock）：一律计入
            # 速率限制；新密码策略问题与系统错误走 worker.error 异常通道（
            # _on_change_error），不惩罚用户——不再比对文案字符串，文案调整/i18n 不会
            # 使改密暴力尝试脱离限流。空文案兜底同引业务层常量（ARCH-049 收编：原第四处
            # 同值字面量，双源漂移面消除）。
            display_msg = error_msg or CHANGE_AUTH_FAILED_MESSAGE
            lock_seconds = self._rate_limiter.record_failure()
            if lock_seconds > 0:
                self._msg_label.setText(
                    f"{display_msg}。尝试次数过多，请等待 {lock_seconds} 秒后重试"
                )
            else:
                self._msg_label.setText(display_msg)

    def _on_change_error(self, error_msg: str) -> None:
        if not finalize_worker_if_current(self):
            return
        self._change_btn.setEnabled(True)
        set_label_severity(self._msg_label, "error")
        self._msg_label.setText("")
        self._clear_password_inputs()
        # `error` 信号已脱离异常上下文，`exc_info` 无堆栈；记录消息文本即可
        logger.error("主密码修改失败: %s", error_msg)
        QMessageBox.critical(self, DLG_TITLE_ERROR, error_msg)
