"""修改主密码对话框"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QLabel, QLineEdit,
    QPushButton, QMessageBox, QHBoxLayout,
)
from PyQt6.QtCore import Qt

from ..crypto.password_generator import PasswordGenerator
from ..ui.resources.theme_colors import c, get_strength_color
from ..ui.resources.icons import set_icon, EYE, LOCK, SIZE_BTN


class ChangeMasterDialog(QDialog):
    """修改主密码对话框"""

    def __init__(self, vault_manager, parent=None):
        super().__init__(parent)
        self._vault = vault_manager
        self._setup_ui()

    def _setup_ui(self):
        self.setWindowTitle('修改主密码')
        self.setMinimumSize(420, 420)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)

        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(36, 30, 36, 30)

        # 标题
        title = QLabel('🔑 修改主密码')
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
        self._old_toggle = QPushButton()
        self._old_toggle.setObjectName('iconBtn')
        self._old_toggle.setFixedSize(32, 32)
        set_icon(self._old_toggle, EYE)
        self._old_toggle.clicked.connect(lambda: self._toggle_pwd(self._old_pwd, self._old_toggle))
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
        self._new_toggle = QPushButton()
        self._new_toggle.setObjectName('iconBtn')
        self._new_toggle.setFixedSize(32, 32)
        set_icon(self._new_toggle, EYE)
        self._new_toggle.clicked.connect(lambda: self._toggle_pwd(self._new_pwd, self._new_toggle))
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
        self._confirm_toggle = QPushButton()
        self._confirm_toggle.setObjectName('iconBtn')
        self._confirm_toggle.setFixedSize(32, 32)
        set_icon(self._confirm_toggle, EYE)
        self._confirm_toggle.clicked.connect(lambda: self._toggle_pwd(self._confirm_pwd, self._confirm_toggle))
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
        cancel_btn.setFixedSize(90, 34)
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)

        change_btn = QPushButton('修改')
        change_btn.setObjectName('primaryBtn')
        change_btn.setFixedSize(90, 34)
        change_btn.clicked.connect(self._on_change)
        btn_layout.addWidget(change_btn)

        layout.addLayout(btn_layout)

    @staticmethod
    def _toggle_pwd(line_edit: QLineEdit, button: QPushButton):
        if line_edit.echoMode() == QLineEdit.EchoMode.Password:
            line_edit.setEchoMode(QLineEdit.EchoMode.Normal)
            set_icon(button, LOCK)
        else:
            line_edit.setEchoMode(QLineEdit.EchoMode.Password)
            set_icon(button, EYE)

    def _on_pwd_changed(self, text: str):
        if text:
            strength = PasswordGenerator.check_strength(text)
            color = get_strength_color(strength.score)
            self._strength_label.setText(f'强度：{strength.label}')
            self._strength_label.setStyleSheet(f'color: {color}; font-size: 12px;')
        else:
            self._strength_label.setText('')

    def _on_change(self):
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

        try:
            success = self._vault.change_master_password(old, new)
        except RuntimeError as e:
            QMessageBox.critical(self, '错误', str(e))
            return

        if success:
            QMessageBox.information(self, '成功', '主密码已修改成功！')
            self.accept()
        else:
            self._msg_label.setText('当前主密码错误')
