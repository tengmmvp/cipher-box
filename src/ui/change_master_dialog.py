"""修改主密码对话框"""

import logging

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)

from ..crypto.password_generator import PasswordGenerator
from ..ui.resources.constants import BTN_DIALOG, DIALOG_CHANGE_MASTER_MIN_SIZE, WORKER_WAIT_TIMEOUT_MS
from ..ui.resources.theme_colors import c
from ..ui.widgets import (
    RateLimiter,
    create_password_toggle_btn,
    release_worker,
    setup_dialog_flags,
    update_strength_label,
)
from ..ui.workers import BackgroundWorker

logger = logging.getLogger(__name__)


class ChangeMasterDialog(QDialog):
    """修改主密码对话框"""

    def __init__(self, vault_manager, parent=None):
        super().__init__(parent)
        self._vault = vault_manager
        self._rate_limiter = RateLimiter()
        self._worker = None
        self._setup_ui()

    def reject(self):
        """关闭对话框前取消并等待后台 worker 完成。"""
        if self._worker and self._worker.isRunning():
            self._worker.cancel()
            self._worker.wait(WORKER_WAIT_TIMEOUT_MS)
        release_worker(self)
        super().reject()

    def _setup_ui(self):
        self.setWindowTitle('修改主密码')
        self.setMinimumSize(*DIALOG_CHANGE_MASTER_MIN_SIZE)
        setup_dialog_flags(self)

        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(36, 30, 36, 30)

        # 标题
        title = QLabel('修改主密码')
        title.setStyleSheet('font-size: 16px; font-weight: bold;')
        layout.addWidget(title)

        info = QLabel('修改主密码后，所有数据将使用新密码重新加密。\n请确保牢记新密码。')
        info.setStyleSheet(f'color: {c("text_muted")}; font-size: 12px;')
        info.setWordWrap(True)
        layout.addWidget(info)

        # 旧密码
        layout.addWidget(QLabel('当前主密码：'))
        old_pwd_layout = QHBoxLayout()
        self._old_pwd = QLineEdit()
        self._old_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        self._old_pwd.setPlaceholderText('请输入当前主密码')
        old_pwd_layout.addWidget(self._old_pwd)
        self._old_toggle = create_password_toggle_btn(self._old_pwd)
        old_pwd_layout.addWidget(self._old_toggle)
        layout.addLayout(old_pwd_layout)

        # 新密码
        layout.addWidget(QLabel('新主密码：'))
        new_pwd_layout = QHBoxLayout()
        self._new_pwd = QLineEdit()
        self._new_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        self._new_pwd.setPlaceholderText('请输入新主密码（至少 12 位）')
        self._new_pwd.textChanged.connect(self._on_pwd_changed)
        new_pwd_layout.addWidget(self._new_pwd)
        self._new_toggle = create_password_toggle_btn(self._new_pwd)
        new_pwd_layout.addWidget(self._new_toggle)
        layout.addLayout(new_pwd_layout)

        # 确认新密码
        layout.addWidget(QLabel('确认新密码：'))
        confirm_pwd_layout = QHBoxLayout()
        self._confirm_pwd = QLineEdit()
        self._confirm_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        self._confirm_pwd.setPlaceholderText('请再次输入新主密码')
        self._confirm_pwd.returnPressed.connect(self._on_change)
        confirm_pwd_layout.addWidget(self._confirm_pwd)
        self._confirm_toggle = create_password_toggle_btn(self._confirm_pwd)
        confirm_pwd_layout.addWidget(self._confirm_toggle)
        layout.addLayout(confirm_pwd_layout)

        # 强度
        self._strength_label = QLabel('')
        self._strength_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._strength_label.setStyleSheet('font-size: 12px;')
        layout.addWidget(self._strength_label)

        # 提示
        self._msg_label = QLabel('')
        self._msg_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._msg_label.setStyleSheet(f'color: {c("danger")}; font-size: 12px; min-height: 18px;')
        layout.addWidget(self._msg_label)

        # 按钮
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        cancel_btn = QPushButton('取消')
        cancel_btn.setFixedSize(*BTN_DIALOG)
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)

        self._change_btn = QPushButton('修改')
        self._change_btn.setObjectName('primaryBtn')
        self._change_btn.setFixedSize(*BTN_DIALOG)
        self._change_btn.clicked.connect(self._on_change)
        btn_layout.addWidget(self._change_btn)

        layout.addLayout(btn_layout)

    def _on_pwd_changed(self, text: str):
        update_strength_label(self._strength_label, text)

    def _on_change(self):
        # L13：速率限制委托给 RateLimiter
        msg = self._rate_limiter.check()
        if msg:
            self._msg_label.setText(msg)
            return

        old = self._old_pwd.text()
        new = self._new_pwd.text()
        confirm = self._confirm_pwd.text()

        if not old:
            self._msg_label.setText('请输入当前主密码')
            return
        if not new:
            self._msg_label.setText('请输入新主密码')
            return
        valid, error = PasswordGenerator.validate_master_password(new)
        if not valid:
            self._msg_label.setText(error)
            return
        if new != confirm:
            self._msg_label.setText('两次输入的新密码不一致')
            return
        if old == new:
            self._msg_label.setText('新密码不能与旧密码相同')
            return

        # 确认操作
        reply = QMessageBox.warning(
            self, '确认修改',
            '修改主密码将重新加密所有数据。\n此过程可能需要几秒钟。\n\n确定要继续吗？',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        # 在后台线程执行重新加密，避免冻结 UI
        self._change_btn.setEnabled(False)
        self._msg_label.setStyleSheet(f'color: {c("accent")}; font-size: 12px; min-height: 18px;')
        self._msg_label.setText('正在重新加密所有数据...')

        self._worker = BackgroundWorker(
            lambda: self._vault.change_master_password(old, new),
            parent=self,
        )
        self._worker.finished.connect(self._on_change_done)
        self._worker.error.connect(self._on_change_error)
        self._worker.start()

    def _on_change_done(self, success):
        release_worker(self)
        self._change_btn.setEnabled(True)
        self._msg_label.setStyleSheet(f'color: {c("danger")}; font-size: 12px; min-height: 18px;')
        # 清除旧密码输入框，减少明文驻留内存时间。
        self._old_pwd.clear()
        if success:
            self._rate_limiter.record_success()
            QMessageBox.information(self, '成功', '主密码已修改成功！')
            self.accept()
        else:
            lock_seconds = self._rate_limiter.record_failure()
            if lock_seconds > 0:
                self._msg_label.setText(
                    f'当前主密码错误。尝试次数过多，请等待 {lock_seconds} 秒后重试'
                )
            else:
                self._msg_label.setText('当前主密码错误')

    def _on_change_error(self, error_msg: str):
        release_worker(self)
        self._change_btn.setEnabled(True)
        self._msg_label.setStyleSheet(f'color: {c("danger")}; font-size: 12px; min-height: 18px;')
        self._msg_label.setText('')
        # 清除旧密码输入框。
        self._old_pwd.clear()
        logger.error("主密码修改失败", exc_info=True)
        QMessageBox.critical(self, '错误', error_msg)
