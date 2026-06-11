"""登录窗口 - 首次设置主密码 / 主密码登录"""

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QSpacerItem,
    QVBoxLayout,
    QWidget,
)

from ..business.password_service import PasswordService
from ..ui.resources.constants import LOGIN_HEIGHT_FIRST, LOGIN_HEIGHT_LOGIN, WORKER_WAIT_TIMEOUT_MS
from ..ui.resources.icons import EYE, LOCK, SHIELD, icon_pixmap, set_icon
from ..ui.resources.theme_colors import c
from ..ui.widgets import (
    RateLimiter,
    create_password_toggle_btn,
    release_worker,
    setup_dialog_flags,
    update_strength_label,
)
from ..ui.workers import BackgroundWorker


class LoginWindow(QDialog):
    """登录/首次设置窗口"""

    login_success = pyqtSignal()

    def __init__(self, vault_manager, parent=None):
        super().__init__(parent)
        self._vault = vault_manager
        self._is_first_time = not vault_manager.is_initialized
        self._rate_limiter = RateLimiter()
        self._worker = None
        self._setup_ui()

    def reject(self):
        """关闭前等待后台 worker 完成，避免窗口销毁后 worker 发信号。"""
        if self._worker and self._worker.isRunning():
            self._worker.cancel()
            self._worker.wait(WORKER_WAIT_TIMEOUT_MS)
        release_worker(self)
        super().reject()

    def _setup_ui(self):
        self.setWindowTitle('CipherBox - 登录')
        self.setFixedWidth(500)
        setup_dialog_flags(self)

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

        title = QLabel('CipherBox')
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
        pwd_layout.setSpacing(6)
        self._password_edit = QLineEdit()
        self._password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._password_edit.setPlaceholderText('请输入主密码')
        self._password_edit.returnPressed.connect(self._on_confirm)
        pwd_layout.addWidget(self._password_edit)

        self._toggle_pwd_btn = create_password_toggle_btn(
            self._password_edit, EYE, LOCK
        )
        pwd_layout.addWidget(self._toggle_pwd_btn)
        layout.addLayout(pwd_layout)

        # 确认密码（仅首次）
        self._confirm_container = QWidget()
        self._confirm_container.setSizePolicy(
            QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed
        )
        confirm_layout = QVBoxLayout(self._confirm_container)
        confirm_layout.setContentsMargins(0, 0, 0, 0)
        confirm_layout.setSpacing(6)

        confirm_label = QLabel('确认密码：')
        confirm_label.setStyleSheet('font-weight: bold;')
        confirm_layout.addWidget(confirm_label)

        confirm_pwd_layout = QHBoxLayout()
        confirm_pwd_layout.setSpacing(6)
        self._confirm_edit = QLineEdit()
        self._confirm_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._confirm_edit.setPlaceholderText('请再次输入主密码')
        self._confirm_edit.returnPressed.connect(self._on_confirm)
        confirm_pwd_layout.addWidget(self._confirm_edit)

        self._toggle_confirm_btn = create_password_toggle_btn(
            self._confirm_edit, EYE, LOCK
        )
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

        # 不同 DPI 和系统字体下控件高度会变化，不能使用固定高度压缩布局
        outer.activate()
        preferred_height = LOGIN_HEIGHT_FIRST if self._is_first_time else LOGIN_HEIGHT_LOGIN
        self.setFixedHeight(max(preferred_height, self.minimumSizeHint().height()))

    def _on_password_changed(self, text: str):
        """密码输入变化时更新强度提示。"""
        update_strength_label(self._strength_label, text, prefix='密码强度：')

    def _on_auth_result(self, success: bool, error_msg: str = ''):
        """处理初始化/解锁的结果。"""
        if success:
            self._rate_limiter.record_success()
            # 登录成功后立即清除密码输入框，减少明文驻留时间
            self._password_edit.clear()
            if hasattr(self, '_confirm_edit'):
                self._confirm_edit.clear()
            self.login_success.emit()
            self.accept()
        else:
            lock_seconds = self._rate_limiter.record_failure()
            if lock_seconds > 0:
                self._show_error(f'尝试次数过多，请等待 {lock_seconds} 秒后重试')
            else:
                self._show_error(error_msg or '操作失败，请重试')

    def _on_confirm(self):
        """处理确认按钮点击。"""
        msg = self._rate_limiter.check()
        if msg:
            self._show_error(msg)
            return

        # 认证进行中，禁止重复提交
        if self._worker and self._worker.isRunning():
            return

        password = self._password_edit.text()

        if not password:
            self._show_error('请输入主密码')
            return

        if self._is_first_time:
            confirm_pwd = self._confirm_edit.text()
            if password != confirm_pwd:
                self._show_error('两次输入的密码不一致')
                return
            valid, error = PasswordService.validate_master_password(password)
            if not valid:
                self._show_error(error)
                return
            action = self._vault.initialize
            error_default = '初始化失败，请重试'
        else:
            action = self._vault.unlock
            error_default = '主密码错误'

        # PBKDF2 迭代次数 600k，在后台线程执行以避免冻结 UI
        self._start_auth(action, password, error_default)

    def _start_auth(self, action, password: str, error_default: str):
        """在后台线程执行 KDF 并完成解锁或初始化。"""
        self._confirm_btn.setEnabled(False)
        self._confirm_btn.setText('正在解锁...')
        self._message_label.setText('')
        self._worker = BackgroundWorker(lambda: action(password), parent=self)
        self._worker.finished.connect(self._on_auth_done)
        self._worker.error.connect(lambda _msg: self._on_auth_error(error_default))
        self._worker.start()

    def _on_auth_done(self, result: tuple[bool, str]):
        """后台认证完成回调，result 为来自 VaultManager 的元组。"""
        release_worker(self)
        self._reset_confirm_btn()
        success, error_msg = result
        self._on_auth_result(success, error_msg)

    def _on_auth_error(self, error_default: str):
        """后台认证异常回调。"""
        release_worker(self)
        self._reset_confirm_btn()
        self._on_auth_result(False, error_default)

    def _reset_confirm_btn(self):
        self._confirm_btn.setEnabled(True)
        self._confirm_btn.setText('确认')

    def _show_error(self, msg: str):
        self._message_label.setText(msg)
        self._message_label.setStyleSheet(f'color: {c("danger")}; font-size: 12px; min-height: 18px;')
