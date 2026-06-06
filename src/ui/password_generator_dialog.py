"""密码生成器对话框"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QCheckBox, QSlider, QGroupBox, QGridLayout,
    QSpacerItem, QSizePolicy, QMessageBox,
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer

from ..crypto.password_generator import PasswordGenerator
from ..ui.resources.theme_colors import get_strength_color
from ..ui.resources.icons import set_icon, set_icon_with_text, COPY, GENERATE


class PasswordGeneratorDialog(QDialog):
    """密码生成器独立对话框"""

    password_selected = pyqtSignal(str)

    def __init__(self, clipboard_manager=None, parent=None, config=None):
        super().__init__(parent)
        self._clipboard = clipboard_manager
        self._config = config
        self._setup_ui()
        self._generate()

    def _setup_ui(self):
        self.setWindowTitle('密码生成器')
        self.setMinimumSize(480, 420)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)

        layout = QVBoxLayout(self)
        layout.setSpacing(14)

        # 生成的密码展示
        pwd_layout = QHBoxLayout()
        self._password_display = QLineEdit()
        self._password_display.setReadOnly(True)
        self._password_display.setStyleSheet('font-size: 16px; padding: 10px; font-family: monospace;')
        self._password_display.setPlaceholderText('点击「生成」按钮')
        pwd_layout.addWidget(self._password_display)

        self._copy_btn = QPushButton()
        self._copy_btn.setFixedSize(80, 40)
        set_icon_with_text(self._copy_btn, '复制', COPY)
        self._copy_btn.clicked.connect(self._copy_password)
        pwd_layout.addWidget(self._copy_btn)

        layout.addLayout(pwd_layout)

        # 强度显示
        self._strength_label = QLabel('')
        self._strength_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._strength_label.setStyleSheet('font-size: 13px; font-weight: bold;')
        layout.addWidget(self._strength_label)

        # 设置区域
        settings_group = QGroupBox('生成选项')
        settings_layout = QGridLayout(settings_group)
        settings_layout.setSpacing(10)

        # 长度
        settings_layout.addWidget(QLabel('密码长度：'), 0, 0)
        self._length_slider = QSlider(Qt.Orientation.Horizontal)
        self._length_slider.setRange(4, 64)
        default_length = self._config.get('default_password_length', 16) if self._config else 16
        self._length_slider.setValue(default_length)
        self._length_slider.valueChanged.connect(self._on_length_changed)
        settings_layout.addWidget(self._length_slider, 0, 1)

        self._length_label = QLabel(str(default_length))
        self._length_label.setFixedWidth(30)
        settings_layout.addWidget(self._length_label, 0, 2)

        # 字符类型
        self._upper_check = QCheckBox('大写字母 (A-Z)')
        self._upper_check.setChecked(self._config.get('default_uppercase', True) if self._config else True)
        settings_layout.addWidget(self._upper_check, 1, 0, 1, 3)

        self._lower_check = QCheckBox('小写字母 (a-z)')
        self._lower_check.setChecked(self._config.get('default_lowercase', True) if self._config else True)
        settings_layout.addWidget(self._lower_check, 2, 0, 1, 3)

        self._digits_check = QCheckBox('数字 (0-9)')
        self._digits_check.setChecked(self._config.get('default_digits', True) if self._config else True)
        settings_layout.addWidget(self._digits_check, 3, 0, 1, 3)

        self._symbols_check = QCheckBox('特殊字符 (!@#$%...)')
        self._symbols_check.setChecked(self._config.get('default_symbols', True) if self._config else True)
        settings_layout.addWidget(self._symbols_check, 4, 0, 1, 3)

        self._exclude_ambiguous = QCheckBox('排除模糊字符 (I, l, 1, O, 0)')
        self._exclude_ambiguous.setChecked(self._config.get('default_exclude_ambiguous', False) if self._config else False)
        settings_layout.addWidget(self._exclude_ambiguous, 5, 0, 1, 3)

        layout.addWidget(settings_group)

        layout.addSpacerItem(QSpacerItem(0, 0, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        # 按钮
        btn_layout = QHBoxLayout()

        gen_btn = QPushButton()
        gen_btn.setObjectName('primaryBtn')
        gen_btn.setFixedSize(140, 38)
        set_icon_with_text(gen_btn, '生成密码', GENERATE)
        gen_btn.clicked.connect(self._generate)
        btn_layout.addWidget(gen_btn)

        use_btn = QPushButton('使用此密码')
        use_btn.setFixedSize(120, 38)
        use_btn.clicked.connect(self._use_password)
        btn_layout.addWidget(use_btn)

        btn_layout.addStretch()

        close_btn = QPushButton('关闭')
        close_btn.setFixedSize(80, 38)
        close_btn.clicked.connect(self.close)
        btn_layout.addWidget(close_btn)

        layout.addLayout(btn_layout)

    def _generate(self):
        if not any((
            self._upper_check.isChecked(), self._lower_check.isChecked(),
            self._digits_check.isChecked(), self._symbols_check.isChecked(),
        )):
            QMessageBox.warning(self, '生成规则无效', '至少需要选择一种字符类型。')
            return
        password = PasswordGenerator.generate(
            length=self._length_slider.value(),
            uppercase=self._upper_check.isChecked(),
            lowercase=self._lower_check.isChecked(),
            digits=self._digits_check.isChecked(),
            symbols=self._symbols_check.isChecked(),
            exclude_ambiguous=self._exclude_ambiguous.isChecked(),
        )
        self._password_display.setText(password)
        self._update_strength(password)

    def _update_strength(self, password: str):
        strength = PasswordGenerator.check_strength(password)
        color = get_strength_color(strength.score)
        self._strength_label.setText(f'强度：{strength.label} ({strength.score}/4)')
        self._strength_label.setStyleSheet(f'color: {color}; font-size: 13px; font-weight: bold;')

    def _on_length_changed(self, value: int):
        self._length_label.setText(str(value))

    def _copy_password(self):
        password = self._password_display.text()
        if not password:
            return
        if self._clipboard:
            self._clipboard.copy_text(password)
        else:
            from PyQt6.QtWidgets import QApplication
            clipboard = QApplication.clipboard()
            if clipboard:
                clipboard.setText(password)
        # 按钮反馈
        self._copy_btn.setText('已复制 ✓')
        QTimer.singleShot(1500, lambda: set_icon_with_text(self._copy_btn, '复制', COPY))

    def _use_password(self):
        password = self._password_display.text()
        if password:
            self.password_selected.emit(password)
            self.close()
