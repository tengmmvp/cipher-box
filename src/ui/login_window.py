"""登录窗口 - 首次设置主密码 / 主密码登录"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QWidget, QSpacerItem, QSizePolicy, QFrame,
)
from PyQt6.QtCore import Qt, pyqtSignal

from ..crypto.password_generator import PasswordGenerator
from ..ui.resources.theme_colors import c, get_strength_color
from ..ui.resources.icons import set_icon, icon_pixmap, EYE, LOCK, SHIELD


class LoginWindow(QDialog):
    """登录/首次设置窗口"""

    login_success = pyqtSignal()

    def __init__(self, vault_manager, parent=None):
        super().__init__(parent)
        self._vault = vault_manager
        self._is_first_time = not vault_manager.is_initialized
        self._fail_count = 0
        self._lock_until = 0.0
        self._setup_ui()

    def _setup_ui(self):
        self.setWindowTitle('CipherBox 密匣 - 登录')
        self.setFixedSize(500, 520 if self._is_first_time else 450)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(34, 30, 34, 30)
        card = QFrame()
        card.setObjectName('loginCard')
        outer.addWidget(card)
        layout = QVBoxLayout(card)
        layout.setSpacing(14)
        layout.setContentsMargins(36, 28, 36, 28)

        # 标题
        logo = QLabel()
        logo.setPixmap(icon_pixmap(SHIELD, 'accent', 44))
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(logo)

        title = QLabel('CipherBox 密匣')
        title.setObjectName('sectionLabel')
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet(f'font-size: 24px; font-weight: 700; color: {c("text_primary")};')
        layout.addWidget(title)

        product_note = QLabel('本地优先 · 端到端加密 · 数据不离开设备')
        product_note.setAlignment(Qt.AlignmentFlag.AlignCenter)
        product_note.setStyleSheet(f'color: {c("text_muted")}; font-size: 11px;')
        layout.addWidget(product_note)

        # 副标题
        if self._is_first_time:
            subtitle = QLabel('首次使用，请设置主密码')
        else:
            subtitle = QLabel('请输入主密码以解锁保险库')
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet(f'color: {c("text_muted")}; font-size: 13px;')
        layout.addWidget(subtitle)

        layout.addSpacing(10)

        # 主密码输入行
        pwd_label = QLabel('主密码：')
        pwd_label.setStyleSheet('font-weight: bold;')
        layout.addWidget(pwd_label)

        pwd_layout = QHBoxLayout()
        self._password_edit = QLineEdit()
        self._password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._password_edit.setPlaceholderText('请输入主密码')
        self._password_edit.returnPressed.connect(self._on_confirm)
        pwd_layout.addWidget(self._password_edit)

        self._toggle_pwd_btn = QPushButton()
        self._toggle_pwd_btn.setObjectName('iconBtn')
        self._toggle_pwd_btn.setFixedSize(32, 32)
        set_icon(self._toggle_pwd_btn, EYE)
        self._toggle_pwd_btn.setToolTip('显示/隐藏密码')
        self._toggle_pwd_btn.clicked.connect(self._toggle_main_password)
        pwd_layout.addWidget(self._toggle_pwd_btn)
        layout.addLayout(pwd_layout)

        # 确认密码（仅首次）
        self._confirm_container = QWidget()
        confirm_layout = QVBoxLayout(self._confirm_container)
        confirm_layout.setContentsMargins(0, 0, 0, 0)
        confirm_layout.setSpacing(6)

        confirm_label = QLabel('确认密码：')
        confirm_label.setStyleSheet('font-weight: bold;')
        confirm_layout.addWidget(confirm_label)

        confirm_pwd_layout = QHBoxLayout()
        self._confirm_edit = QLineEdit()
        self._confirm_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._confirm_edit.setPlaceholderText('请再次输入主密码')
        self._confirm_edit.returnPressed.connect(self._on_confirm)
        confirm_pwd_layout.addWidget(self._confirm_edit)

        self._toggle_confirm_btn = QPushButton()
        self._toggle_confirm_btn.setObjectName('iconBtn')
        self._toggle_confirm_btn.setFixedSize(32, 32)
        set_icon(self._toggle_confirm_btn, EYE)
        self._toggle_confirm_btn.setToolTip('显示/隐藏密码')
        self._toggle_confirm_btn.clicked.connect(self._toggle_confirm_password)
        confirm_pwd_layout.addWidget(self._toggle_confirm_btn)
        confirm_layout.addLayout(confirm_pwd_layout)

        if self._is_first_time:
            layout.addWidget(self._confirm_container)
        else:
            self._confirm_container.hide()

        # 提示信息
        self._message_label = QLabel('')
        self._message_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._message_label.setStyleSheet(f'color: {c("danger")}; font-size: 12px; min-height: 18px;')
        layout.addWidget(self._message_label)

        # 密码强度提示（首次设置时）
        self._strength_label = QLabel('')
        self._strength_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._strength_label.setStyleSheet('font-size: 12px;')
        if self._is_first_time:
            self._password_edit.textChanged.connect(self._on_password_changed)
            layout.addWidget(self._strength_label)
        else:
            self._strength_label.hide()

        layout.addSpacerItem(QSpacerItem(0, 0, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        # 按钮
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        self._confirm_btn = QPushButton('确认')
        self._confirm_btn.setObjectName('primaryBtn')
        self._confirm_btn.setFixedSize(120, 38)
        self._confirm_btn.clicked.connect(self._on_confirm)
        btn_layout.addWidget(self._confirm_btn)
        btn_layout.addStretch()

        layout.addLayout(btn_layout)

    def _toggle_main_password(self):
        if self._password_edit.echoMode() == QLineEdit.EchoMode.Password:
            self._password_edit.setEchoMode(QLineEdit.EchoMode.Normal)
            set_icon(self._toggle_pwd_btn, LOCK)
        else:
            self._password_edit.setEchoMode(QLineEdit.EchoMode.Password)
            set_icon(self._toggle_pwd_btn, EYE)

    def _toggle_confirm_password(self):
        if self._confirm_edit.echoMode() == QLineEdit.EchoMode.Password:
            self._confirm_edit.setEchoMode(QLineEdit.EchoMode.Normal)
            set_icon(self._toggle_confirm_btn, LOCK)
        else:
            self._confirm_edit.setEchoMode(QLineEdit.EchoMode.Password)
            set_icon(self._toggle_confirm_btn, EYE)

    def _on_password_changed(self, text: str):
        """密码输入变化时更新强度提示"""
        if text:
            strength = PasswordGenerator.check_strength(text)
            color = get_strength_color(strength.score)
            self._strength_label.setText(f'密码强度：{strength.label}')
            self._strength_label.setStyleSheet(f'color: {color}; font-size: 12px;')
        else:
            self._strength_label.setText('')

    def _on_confirm(self):
        """确认按钮"""
        import time

        if self._lock_until and time.monotonic() < self._lock_until:
            remaining = int(self._lock_until - time.monotonic()) + 1
            self._show_error(f'尝试次数过多，请等待 {remaining} 秒后重试')
            return
        # 锁定已过期，重置计数
        if self._lock_until and time.monotonic() >= self._lock_until:
            self._fail_count = 0
            self._lock_until = 0.0

        password = self._password_edit.text()

        if not password:
            self._show_error('请输入主密码')
            return

        if self._is_first_time:
            confirm_pwd = self._confirm_edit.text()
            if password != confirm_pwd:
                self._show_error('两次输入的密码不一致')
                return
            if len(password) < 8:
                self._show_error('主密码长度不能少于 8 个字符')
                return

            if self._vault.initialize(password):
                self._fail_count = 0
                self.login_success.emit()
                self.accept()
            else:
                self._fail_count += 1
                if self._fail_count >= 5:
                    self._lock_until = time.monotonic() + 30
                    self._show_error('尝试次数过多，请等待 30 秒后重试')
                else:
                    self._show_error('初始化失败，请重试')
        else:
            if self._vault.unlock(password):
                self._fail_count = 0
                self.login_success.emit()
                self.accept()
            else:
                self._fail_count += 1
                if self._fail_count >= 5:
                    self._lock_until = time.monotonic() + 30
                    self._show_error('尝试次数过多，请等待 30 秒后重试')
                else:
                    self._show_error('主密码错误')

    def _show_error(self, msg: str):
        self._message_label.setText(msg)
        self._message_label.setStyleSheet(f'color: {c("danger")}; font-size: 12px; min-height: 18px;')
