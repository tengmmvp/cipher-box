"""密码生成器独立对话框。

按长度与字符集规则即时生成密码并展示强度，支持复制或经信号回填。
生成结果视为敏感数据，关闭或使用后清除以缩短明文驻留时间。
"""

from __future__ import annotations

from typing import TYPE_CHECKING, TypeVar

from PyQt6 import sip
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QSlider,
    QSpacerItem,
    QVBoxLayout,
    QWidget,
)

from ...business.services.password_service import PasswordService
from ...config import (
    CFG_DEFAULT_DIGITS,
    CFG_DEFAULT_EXCLUDE_AMBIGUOUS,
    CFG_DEFAULT_LOWERCASE,
    CFG_DEFAULT_PASSWORD_LENGTH,
    CFG_DEFAULT_SYMBOLS,
    CFG_DEFAULT_UPPERCASE,
)
from ..components.widgets import setup_dialog_flags

if TYPE_CHECKING:
    from ...config import ConfigManager
    from ..utils.clipboard import ClipboardManager
from ..resources.constants import (
    BTN_COMPACT,
    BTN_GENERATE,
    BTN_PRIMARY,
    BTN_SECONDARY,
    DIALOG_PASSWORD_GEN_MIN_SIZE,
    FONT_FAMILY_MONOSPACE,
    MS_FEEDBACK,
    PWD_GENERATE_LENGTH_DEFAULT,
)
from ..resources.icons import COPY, GENERATE, set_icon_with_text
from ..resources.theme_colors import get_strength_color

_T = TypeVar("_T")


class PasswordGeneratorDialog(QDialog):
    """独立的密码生成器对话框，可选复制或回填生成的密码。"""

    password_selected = pyqtSignal(str)

    def __init__(
        self,
        clipboard_manager: ClipboardManager | None = None,
        parent: QWidget | None = None,
        config: ConfigManager | None = None,
    ):
        super().__init__(parent)
        self._clipboard = clipboard_manager
        self._config = config
        self._copy_feedback_timer: QTimer | None = None
        self._setup_ui()
        self._generate()

    def _cfg(self, key: str, default: _T) -> _T:
        """读取配置值，config 为 None 时使用默认值。"""
        return self._config.get(key, default) if self._config else default

    def _setup_ui(self) -> None:
        self.setWindowTitle("密码生成器")
        self.setMinimumSize(*DIALOG_PASSWORD_GEN_MIN_SIZE)
        setup_dialog_flags(self)

        layout = QVBoxLayout(self)
        layout.setSpacing(14)

        # 生成的密码展示
        pwd_layout = QHBoxLayout()
        self._password_display = QLineEdit()
        self._password_display.setReadOnly(True)
        self._password_display.setStyleSheet(
            f"font-size: 16px; padding: 10px; font-family: {FONT_FAMILY_MONOSPACE};"
        )
        self._password_display.setPlaceholderText("点击「生成」按钮")
        pwd_layout.addWidget(self._password_display)

        self._copy_btn = QPushButton()
        self._copy_btn.setFixedSize(*BTN_COMPACT)
        set_icon_with_text(self._copy_btn, "复制", COPY)
        self._copy_btn.clicked.connect(self._copy_password)
        pwd_layout.addWidget(self._copy_btn)

        layout.addLayout(pwd_layout)

        # 强度显示
        self._strength_label = QLabel("")
        self._strength_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._strength_label.setStyleSheet("font-size: 14px; font-weight: 600;")
        layout.addWidget(self._strength_label)

        # 设置区域
        settings_group = QGroupBox("生成选项")
        settings_layout = QGridLayout(settings_group)
        settings_layout.setSpacing(10)

        # 长度
        settings_layout.addWidget(QLabel("密码长度："), 0, 0)
        self._length_slider = QSlider(Qt.Orientation.Horizontal)
        self._length_slider.setRange(4, 64)
        default_length = self._cfg(CFG_DEFAULT_PASSWORD_LENGTH, PWD_GENERATE_LENGTH_DEFAULT)
        self._length_slider.setValue(default_length)
        self._length_slider.valueChanged.connect(self._on_length_changed)
        settings_layout.addWidget(self._length_slider, 0, 1)

        # 标签取 setValue 钳制后的实际值（slider range [4,64]）：default_length 越界时
        # 直接用会显示与滑块不一致的错误长度（config 手改/迁移漂移时复现）。
        self._length_label = QLabel(str(self._length_slider.value()))
        self._length_label.setFixedWidth(30)
        settings_layout.addWidget(self._length_label, 0, 2)

        # 字符类型
        self._upper_check = QCheckBox("大写字母 (A-Z)")
        self._upper_check.setChecked(self._cfg(CFG_DEFAULT_UPPERCASE, True))
        settings_layout.addWidget(self._upper_check, 1, 0, 1, 3)

        self._lower_check = QCheckBox("小写字母 (a-z)")
        self._lower_check.setChecked(self._cfg(CFG_DEFAULT_LOWERCASE, True))
        settings_layout.addWidget(self._lower_check, 2, 0, 1, 3)

        self._digits_check = QCheckBox("数字 (0-9)")
        self._digits_check.setChecked(self._cfg(CFG_DEFAULT_DIGITS, True))
        settings_layout.addWidget(self._digits_check, 3, 0, 1, 3)

        self._symbols_check = QCheckBox("特殊字符 (!@#$%...)")
        self._symbols_check.setChecked(self._cfg(CFG_DEFAULT_SYMBOLS, True))
        settings_layout.addWidget(self._symbols_check, 4, 0, 1, 3)

        self._exclude_ambiguous = QCheckBox("排除模糊字符 (I, l, 1, O, 0)")
        self._exclude_ambiguous.setChecked(self._cfg(CFG_DEFAULT_EXCLUDE_AMBIGUOUS, False))
        settings_layout.addWidget(self._exclude_ambiguous, 5, 0, 1, 3)

        layout.addWidget(settings_group)

        layout.addSpacerItem(
            QSpacerItem(0, 0, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)
        )

        # 按钮
        btn_layout = QHBoxLayout()

        gen_btn = QPushButton()
        gen_btn.setObjectName("primaryBtn")
        gen_btn.setFixedSize(*BTN_GENERATE)
        set_icon_with_text(gen_btn, "生成密码", GENERATE)
        gen_btn.clicked.connect(self._generate)
        btn_layout.addWidget(gen_btn)

        use_btn = QPushButton("使用此密码")
        use_btn.setFixedSize(*BTN_PRIMARY)
        use_btn.clicked.connect(self._use_password)
        btn_layout.addWidget(use_btn)

        btn_layout.addStretch()

        close_btn = QPushButton("关闭")
        close_btn.setFixedSize(*BTN_SECONDARY)
        close_btn.clicked.connect(self.close)
        btn_layout.addWidget(close_btn)

        layout.addLayout(btn_layout)

    def _generate(self) -> None:
        uppercase = self._upper_check.isChecked()
        lowercase = self._lower_check.isChecked()
        digits = self._digits_check.isChecked()
        symbols = self._symbols_check.isChecked()
        # 至少需要一种字符集，校验文案经共享 helper 单一事实源
        ok, error = PasswordService.validate_charset_selection(
            uppercase,
            lowercase,
            digits,
            symbols,
        )
        if not ok:
            QMessageBox.warning(self, "生成规则无效", error)
            return
        password = PasswordService.generate(
            length=self._length_slider.value(),
            uppercase=uppercase,
            lowercase=lowercase,
            digits=digits,
            symbols=symbols,
            exclude_ambiguous=self._exclude_ambiguous.isChecked(),
        )
        self._password_display.setText(password)
        self._update_strength(password)

    def _update_strength(self, password: str) -> None:
        strength = PasswordService.check_strength(password)
        color = get_strength_color(strength.score)
        self._strength_label.setText(f"强度：{strength.label} ({strength.score}/4)")
        self._strength_label.setStyleSheet(f"color: {color}; font-size: 14px; font-weight: 600;")

    def _on_length_changed(self, value: int) -> None:
        self._length_label.setText(str(value))

    def _copy_password(self) -> None:
        password = self._password_display.text()
        if not password:
            return
        if self._clipboard:
            self._clipboard.copy_text(password)
            set_icon_with_text(self._copy_btn, "已复制 ✓", COPY)
        else:
            # 剪贴板管理器不可用：避免绕过自动清除机制直接写入系统剪贴板；给按钮临时
            # 文案反馈，避免用户误以为复制成功。复用反馈定时器复位为「复制」。
            set_icon_with_text(self._copy_btn, "剪贴板不可用", COPY)
        # 复用单个 QTimer（首次创建并连接，后续仅 restart），避免连续点击累积未释放的 QTimer。
        # 定时器必须以对话框为 parent（QL-032）：对话框 C++ 对象销毁时连带停止其待触发的
        # timeout，回调才不可能在对话框/按钮析构后进入。无 parent 的 QTimer 归 Python 所有，
        # 可能在对话框销毁后仍存活并触发回调，访问已 deleteLater 的按钮导致 Windows C 层
        # access violation（无法 try/except，进程直接崩溃）。
        if self._copy_feedback_timer is None:
            self._copy_feedback_timer = QTimer(self)
            self._copy_feedback_timer.setSingleShot(True)
            self._copy_feedback_timer.setInterval(MS_FEEDBACK)
            self._copy_feedback_timer.timeout.connect(self._restore_copy_label)
        self._copy_feedback_timer.start()

    def _restore_copy_label(self) -> None:
        """反馈定时器回调：把复制按钮文案复位为「复制」。

        回调触发时 ``_copy_btn`` 可能已 ``deleteLater`` 而 C++ 对象已释放，对已删
        控件调 ``set_icon_with_text`` 会触发 Windows C 层 access violation，与
        detail_panel._restore 同款 ``sip.isdeleted`` 守卫静默跳过（QL-032）。
        """
        btn = self._copy_btn
        if sip.isdeleted(btn):
            return
        set_icon_with_text(btn, "复制", COPY)

    def _use_password(self) -> None:
        password = self._password_display.text()
        if password:
            self.password_selected.emit(password)
            self._clear_sensitive()
            self.close()

    def _clear_sensitive(self) -> None:
        """关闭前清除生成的密码，减少明文在内存中的驻留时间。"""
        self._password_display.clear()
        if self._copy_feedback_timer is not None:
            # stop 后随即 deleteLater（QL-032）：仅置 None 会把已停止但仍连接复位回调的
            # 定时器孤儿化挂在对话框上——违背「复用单个 QTimer」意图（下次复制重新 new，
            # 旧对象滞留到对话框析构），也让捕获 self 的回调多活一段无意义的时间。
            self._copy_feedback_timer.stop()
            self._copy_feedback_timer.deleteLater()
            self._copy_feedback_timer = None

    def reject(self) -> None:
        """取消/关闭前清除敏感输入。

        仅重写 ``reject``（不重写 ``closeEvent``）避免双重清理：X 关闭、Esc、``close()``
        均经此单一入口。
        """
        self._clear_sensitive()
        super().reject()
