"""登录窗口，负责首次设置主密码与日常主密码解锁。

依据是否已初始化切换首设与登录流程；Argon2id 派生在后台线程执行避免冻结 UI。
内置速率限制与失败锁定，成功后立即清除明文。
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
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

from ...business.services.password_service import PasswordService
from ...business.services.rate_limiter import RateLimiter

if TYPE_CHECKING:
    from ...business.managers.vault_manager import VaultManager
    from ...config import ConfigManager
from ..components.widgets import (
    WorkerBackedDialog,
    create_password_toggle_btn,
    finalize_worker_if_current,
    set_label_severity,
    setup_dialog_flags,
    update_strength_label,
)
from ..components.workers import BackgroundWorker
from ..resources.constants import (
    BTN_PRIMARY,
    LOGIN_HEIGHT_FIRST,
    LOGIN_HEIGHT_LOGIN,
    LOGIN_TITLE_FONT_SIZE_PX,
    LOGIN_WIDTH,
)
from ..resources.icons import EYE, LOCK, SHIELD, icon_pixmap
from ..resources.theme_colors import c


class LoginWindow(WorkerBackedDialog):
    """主密码登录或首次设置窗口。"""

    login_success = pyqtSignal()

    def __init__(
        self,
        vault_manager: VaultManager,
        config: ConfigManager | None = None,
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self._vault = vault_manager
        self._config = config
        # 命令-查询分离（ARCH-004）：is_initialized 为纯查询，先显式打开数据库（命令）
        # 再查询是否已初始化。db 文件不存在时 is_initialized 直接返回 False，无需打开。
        vault_manager.ensure_db_open()
        self._is_first_time = not vault_manager.is_initialized
        # 直接索引 data_dir（有类型 property）：缺失会在静态检查/运行时即时暴露，
        # 而非 getattr 静默退化为仅内存限流（跨会话退避与哨兵删文件检测全部失效）。
        state_path = self._vault.data_dir / "login_rate_limit.json"
        # 传入 config：把哨兵登记到签名 config，关闭「同时删除状态文件+哨兵即归零计数」的绕过
        self._rate_limiter = RateLimiter(state_path, config)
        self._setup_ui()

    def _setup_ui(self) -> None:
        self.setWindowTitle("CipherBox - 登录")
        self.setFixedWidth(LOGIN_WIDTH)
        setup_dialog_flags(self)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(34, 30, 34, 30)
        card = QFrame()
        card.setObjectName("loginCard")
        outer.addWidget(card)
        layout = QVBoxLayout(card)
        layout.setSpacing(14)
        layout.setContentsMargins(36, 28, 36, 28)

        self._build_header(layout)
        layout.addSpacing(10)
        self._build_password_row(layout)
        self._build_confirm_section(layout)
        self._build_message_labels(layout)
        layout.addSpacerItem(
            QSpacerItem(0, 0, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)
        )
        layout.addLayout(self._build_action_button())

        # 不同 DPI 与系统字体下控件高度存在差异，不能使用固定高度压缩布局，
        # 因此先激活布局再按内容提示高度与预设值取较大者固定窗口高度
        outer.activate()
        preferred_height = LOGIN_HEIGHT_FIRST if self._is_first_time else LOGIN_HEIGHT_LOGIN
        self.setFixedHeight(max(preferred_height, self.minimumSizeHint().height()))

    def _build_header(self, layout: QVBoxLayout) -> None:
        """构建 logo、标题、产品说明与副标题。"""
        logo = QLabel()
        logo.setPixmap(icon_pixmap(SHIELD, "accent", 44))
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(logo)

        title = QLabel("CipherBox")
        title.setObjectName("sectionLabel")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet(
            f"font-size: {LOGIN_TITLE_FONT_SIZE_PX}px; font-weight: 700; color: {c('text_primary')};"
        )
        layout.addWidget(title)

        product_note = QLabel("本地优先 · 端到端加密 · 数据不离开设备")
        product_note.setAlignment(Qt.AlignmentFlag.AlignCenter)
        product_note.setObjectName("formMutedSmall")
        layout.addWidget(product_note)

        if self._is_first_time:
            subtitle = QLabel("首次使用，请设置主密码")
        else:
            subtitle = QLabel("请输入主密码以解锁保险库")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setObjectName("formMutedPlain")
        layout.addWidget(subtitle)

    def _build_password_row(self, layout: QVBoxLayout) -> None:
        """构建主密码输入行。"""
        pwd_label = QLabel("主密码：")
        pwd_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(pwd_label)

        pwd_layout = QHBoxLayout()
        pwd_layout.setSpacing(6)
        self._password_edit = QLineEdit()
        self._password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._password_edit.setPlaceholderText("请输入主密码")
        self._password_edit.returnPressed.connect(self._on_confirm)
        pwd_layout.addWidget(self._password_edit)

        self._toggle_pwd_btn = create_password_toggle_btn(self._password_edit, EYE, LOCK)
        pwd_layout.addWidget(self._toggle_pwd_btn)
        layout.addLayout(pwd_layout)

    def _build_confirm_section(self, layout: QVBoxLayout) -> None:
        """构建确认密码区域，仅在首次设置时显示。"""
        self._confirm_container = QWidget()
        self._confirm_container.setSizePolicy(
            QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed
        )
        confirm_layout = QVBoxLayout(self._confirm_container)
        confirm_layout.setContentsMargins(0, 0, 0, 0)
        confirm_layout.setSpacing(6)

        confirm_label = QLabel("确认密码：")
        confirm_label.setStyleSheet("font-weight: bold;")
        confirm_layout.addWidget(confirm_label)

        confirm_pwd_layout = QHBoxLayout()
        confirm_pwd_layout.setSpacing(6)
        self._confirm_edit = QLineEdit()
        self._confirm_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._confirm_edit.setPlaceholderText("请再次输入主密码")
        self._confirm_edit.returnPressed.connect(self._on_confirm)
        confirm_pwd_layout.addWidget(self._confirm_edit)

        self._toggle_confirm_btn = create_password_toggle_btn(self._confirm_edit, EYE, LOCK)
        confirm_pwd_layout.addWidget(self._toggle_confirm_btn)
        confirm_layout.addLayout(confirm_pwd_layout)

        if self._is_first_time:
            layout.addWidget(self._confirm_container)
        else:
            self._confirm_container.hide()

    def _build_message_labels(self, layout: QVBoxLayout) -> None:
        """构建错误消息与密码强度提示（强度仅首设显示）。"""
        self._message_label = QLabel("")
        self._message_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._message_label.setObjectName("formMessage")
        set_label_severity(self._message_label, "error")
        layout.addWidget(self._message_label)

        self._strength_label = QLabel("")
        self._strength_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._strength_label.setStyleSheet("font-size: 12px;")
        if self._is_first_time:
            self._password_edit.textChanged.connect(self._on_password_changed)
            layout.addWidget(self._strength_label)
        else:
            self._strength_label.hide()

    def _build_action_button(self) -> QHBoxLayout:
        """构建确认按钮行。"""
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        self._confirm_btn = QPushButton("确认")
        self._confirm_btn.setObjectName("primaryBtn")
        self._confirm_btn.setFixedSize(*BTN_PRIMARY)
        self._confirm_btn.clicked.connect(self._on_confirm)
        btn_layout.addWidget(self._confirm_btn)
        btn_layout.addStretch()
        return btn_layout

    def _on_password_changed(self, text: str) -> None:
        """密码输入变化时更新强度提示。"""
        update_strength_label(self._strength_label, text, prefix="密码强度：")

    def _on_auth_result(
        self, success: bool, error_msg: str = "", is_auth_failure: bool = True
    ) -> None:
        """处理初始化/解锁的结果。

        is_auth_failure 为 False（系统错误）时不计入速率锁定，避免故障触发账户级锁定。
        """
        if success:
            self._rate_limiter.record_success()
            # 登录成功后立即清除密码输入框，缩短明文在内存中的驻留时间
            self._clear_password_inputs()
            self.login_success.emit()
            self.accept()
        else:
            # 失败后立即清除主密码明文，与成功路径及 change_master_dialog 的清零策略对齐；
            # 失败尝试的密码仍是用户真实密码，残留会扩大肩窥/内存 dump 暴露面。
            self._clear_password_inputs()
            if is_auth_failure:
                lock_seconds = self._rate_limiter.record_failure()
                if lock_seconds > 0:
                    self._show_error(f"尝试次数过多，请等待 {lock_seconds} 秒后重试")
                    return
            self._show_error(error_msg or "操作失败，请重试")

    def _clear_password_inputs(self) -> None:
        """清除主密码与确认密码输入框，缩短明文在控件中的驻留时间。

        _confirm_edit 无条件创建（首设显示，登录态隐藏），故无需 hasattr 守卫。
        """
        self._password_edit.clear()
        self._confirm_edit.clear()

    def _on_confirm(self) -> None:
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
            self._show_error("请输入主密码")
            return

        if self._is_first_time:
            confirm_pwd = self._confirm_edit.text()
            if password != confirm_pwd:
                self._show_error("两次输入的密码不一致")
                return
            valid, error = PasswordService.validate_master_password(password)
            if not valid:
                self._show_error(error)
                return
            action: Callable[[str], tuple[bool, str]] = self._vault.initialize
            error_default = "初始化失败，请重试"
        else:
            action = self._vault.unlock
            error_default = "主密码错误"

        # 主密码派生使用 Argon2id（内存硬化 KDF），耗时较高，需在后台线程执行避免冻结 UI
        self._start_auth(action, password, error_default)

    def _start_auth(
        self, action: Callable[[str], tuple[bool, str]], password: str, error_default: str
    ) -> None:
        """在后台线程执行 KDF 并完成解锁或初始化。"""
        self._confirm_btn.setEnabled(False)
        self._confirm_btn.setText("正在解锁...")
        self._message_label.setText("")
        self._worker = BackgroundWorker(lambda: action(password), parent=self)
        self._worker.finished.connect(self._on_auth_done)
        # worker.error 携带 str(e)，透传给 _on_auth_error 优先展示真实系统错误，无信息时回退 error_default
        self._worker.error.connect(lambda msg: self._on_auth_error(msg, error_default))
        self._worker.start()
        # SEC-LOGIN-001：password 已作为闭包传入 worker，KDF 派生期间（后台线程耗时）
        # 立即清空输入框，缩短明文在控件的驻留窗口（无需等到结果返回）。
        self._clear_password_inputs()

    def _on_auth_done(self, result: tuple[bool, str]) -> None:
        """后台认证完成回调，result 为来自 VaultManager 的元组。"""
        if not finalize_worker_if_current(self):
            return
        self._reset_confirm_btn()
        success, error_msg = result
        self._on_auth_result(success, error_msg)

    def _on_auth_error(self, error_msg: str, error_default: str) -> None:
        """后台认证异常回调（系统错误，非认证失败）。

        优先展示真实异常信息，无信息时回退 error_default。系统错误不计入速率锁定。
        """
        if not finalize_worker_if_current(self):
            return
        self._reset_confirm_btn()
        self._on_auth_result(False, error_msg or error_default, is_auth_failure=False)

    def _reset_confirm_btn(self) -> None:
        self._confirm_btn.setEnabled(True)
        self._confirm_btn.setText("确认")

    def _show_error(self, msg: str) -> None:
        self._message_label.setText(msg)
        set_label_severity(self._message_label, "error")
