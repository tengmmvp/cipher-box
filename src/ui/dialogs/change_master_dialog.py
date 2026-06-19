"""修改主密码对话框。

修改主密码会触发全量数据重新加密，耗时较高，在后台线程执行以避免
冻结 UI。内置速率限制与失败锁定，校验旧密码、新密码强度与两次一致性
后才提交，完成或失败后立即清除旧密码输入以缩短明文驻留时间。
"""

from __future__ import annotations

import logging
from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ...business.managers.vault_manager import AUTH_FAILED_MESSAGE, VaultManager
from ...business.services.password_service import PasswordService
from ..components.widgets import (
    RateLimiter,
    create_password_toggle_btn,
    release_worker,
    set_label_severity,
    setup_dialog_flags,
    update_strength_label,
)
from ..components.workers import BackgroundWorker, wait_worker_shutdown
from ..resources.constants import (
    BTN_DIALOG,
    DIALOG_CHANGE_MASTER_MIN_SIZE,
)

logger = logging.getLogger(__name__)


class ChangeMasterDialog(QDialog):
    """主密码修改对话框，含旧密码校验与新密码强度校验。"""

    def __init__(self, vault_manager: VaultManager, parent: QWidget | None = None):
        super().__init__(parent)
        self._vault = vault_manager
        data_dir = getattr(self._vault, 'data_dir', None)
        state_path = (
            Path(data_dir) / 'change_master_rate_limit.json'
            if isinstance(data_dir, (str, Path)) else None
        )
        self._rate_limiter = RateLimiter(state_path)
        self._worker: BackgroundWorker | None = None
        self._setup_ui()

    def reject(self) -> None:
        """关闭对话框前取消并等待后台 worker 完成，并清除密码输入。"""
        if self._worker and self._worker.isRunning():
            # 桥接取消：设 vault 取消事件以中断重加密循环（worker.cancel 仅设
            # worker 自身标志，重加密不检查它）。重加密检测后抛异常回滚。
            self._vault.request_cancel()
        wait_worker_shutdown(self._worker)
        release_worker(self)
        # 取消时同样清除全部密码输入，与成功/失败路径一致，缩短明文驻留
        self._old_pwd.clear()
        self._new_pwd.clear()
        self._confirm_pwd.clear()
        super().reject()

    def _setup_ui(self) -> None:
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
        info.setObjectName('formMuted')
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
        self._new_pwd.setPlaceholderText('请输入新主密码（至少 15 位）')
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
        self._msg_label.setObjectName('formMessage')
        set_label_severity(self._msg_label, 'error')
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

    def _on_pwd_changed(self, text: str) -> None:
        update_strength_label(self._strength_label, text)

    def _on_change(self) -> None:
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
        valid, error = PasswordService.validate_master_password(new)
        if not valid:
            self._msg_label.setText(error)
            return
        if new != confirm:
            self._msg_label.setText('两次输入的新密码不一致')
            return
        if old == new:
            self._msg_label.setText('新密码不能与旧密码相同')
            return

        reply = QMessageBox.warning(
            self, '确认修改',
            '修改主密码将重新加密所有数据。\n此过程可能需要几秒钟。\n\n确定要继续吗？',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        # 全量重新加密耗时较高，置于后台线程执行避免冻结 UI
        self._change_btn.setEnabled(False)
        set_label_severity(self._msg_label, 'accent')
        self._msg_label.setText('正在重新加密所有数据...')

        self._worker = BackgroundWorker(
            lambda: self._vault.change_master_password(old, new),
            parent=self,
        )
        self._worker.finished.connect(self._on_change_done)
        self._worker.error.connect(self._on_change_error)
        self._worker.start()

    def _on_change_done(self, result: tuple[bool, str]) -> None:
        release_worker(self)
        self._change_btn.setEnabled(True)
        set_label_severity(self._msg_label, 'error')
        success, error_msg = result
        # 无论成功与否都清除全部密码输入，缩短明文在控件中的驻留时间
        self._old_pwd.clear()
        self._new_pwd.clear()
        self._confirm_pwd.clear()
        if success:
            self._rate_limiter.record_success()
            message = '主密码已修改成功！'
            # 改密成功但 purge 失败时，error_msg 携带 warning，附加提示用户手动清理
            if error_msg:
                message += f'\n\n{error_msg}'
            QMessageBox.information(self, '成功', message)
            self.accept()
        else:
            display_msg = error_msg or AUTH_FAILED_MESSAGE
            # 仅明确的认证失败计入速率限制；新密码校验问题或系统错误不惩罚用户
            if error_msg == AUTH_FAILED_MESSAGE:
                lock_seconds = self._rate_limiter.record_failure()
            else:
                lock_seconds = 0
            if lock_seconds > 0:
                self._msg_label.setText(
                    f'{display_msg}。尝试次数过多，请等待 {lock_seconds} 秒后重试'
                )
            else:
                self._msg_label.setText(display_msg)

    def _on_change_error(self, error_msg: str) -> None:
        release_worker(self)
        self._change_btn.setEnabled(True)
        set_label_severity(self._msg_label, 'error')
        self._msg_label.setText('')
        self._old_pwd.clear()
        self._new_pwd.clear()
        self._confirm_pwd.clear()
        # error 信号已脱离异常上下文，exc_info 无堆栈；记录消息文本即可
        logger.error("主密码修改失败: %s", error_msg)
        QMessageBox.critical(self, '错误', error_msg)
