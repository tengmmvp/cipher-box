"""设置对话框"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLineEdit,
    QPushButton, QComboBox, QSpinBox, QCheckBox, QGroupBox,
    QFormLayout, QTabWidget, QWidget, QFileDialog, QMessageBox,
)
from PyQt6.QtCore import Qt

from ..config import ConfigManager


class SettingsDialog(QDialog):
    """设置中心"""

    def __init__(self, config: ConfigManager, parent=None):
        super().__init__(parent)
        self._config = config
        self._setup_ui()
        self._load_settings()

    def _setup_ui(self):
        self.setWindowTitle('设置')
        self.setMinimumSize(520, 480)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)

        layout = QVBoxLayout(self)

        tabs = QTabWidget()
        tabs.addTab(self._create_general_tab(), '通用')
        tabs.addTab(self._create_security_tab(), '安全')
        tabs.addTab(self._create_password_tab(), '密码生成')
        tabs.addTab(self._create_backup_tab(), '备份')
        layout.addWidget(tabs)

        # 按钮
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        reset_btn = QPushButton('恢复默认')
        reset_btn.setFixedSize(90, 34)
        reset_btn.clicked.connect(self._reset_to_defaults)
        btn_layout.addWidget(reset_btn)

        cancel_btn = QPushButton('取消')
        cancel_btn.setFixedSize(90, 34)
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)

        save_btn = QPushButton('保存')
        save_btn.setObjectName('primaryBtn')
        save_btn.setFixedSize(90, 34)
        save_btn.clicked.connect(self._save_settings)
        btn_layout.addWidget(save_btn)

        layout.addLayout(btn_layout)

    def _create_general_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # 主题
        theme_group = QGroupBox('外观')
        theme_layout = QFormLayout(theme_group)
        self._theme_combo = QComboBox()
        self._theme_combo.addItems(['浅色', '深色'])
        theme_layout.addRow('主题：', self._theme_combo)
        layout.addWidget(theme_group)

        # 系统托盘
        tray_group = QGroupBox('系统托盘')
        tray_layout = QVBoxLayout(tray_group)
        self._show_tray_check = QCheckBox('显示系统托盘图标')
        self._minimize_tray_check = QCheckBox('最小化到托盘')
        self._close_tray_check = QCheckBox('关闭时最小化到托盘而非退出')
        tray_layout.addWidget(self._show_tray_check)
        tray_layout.addWidget(self._minimize_tray_check)
        tray_layout.addWidget(self._close_tray_check)
        self._show_tray_check.toggled.connect(self._update_tray_options)
        layout.addWidget(tray_group)

        layout.addStretch()
        return widget

    def _create_security_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        lock_group = QGroupBox('自动锁定')
        lock_layout = QFormLayout(lock_group)
        self._auto_lock_spin = QSpinBox()
        self._auto_lock_spin.setRange(0, 60)
        self._auto_lock_spin.setSpecialValueText('不自动锁定')
        self._auto_lock_spin.setSuffix(' 分钟')
        lock_layout.addRow('空闲自动锁定：', self._auto_lock_spin)
        layout.addWidget(lock_group)

        clip_group = QGroupBox('剪贴板')
        clip_layout = QFormLayout(clip_group)
        self._clipboard_spin = QSpinBox()
        self._clipboard_spin.setRange(0, 300)
        self._clipboard_spin.setSuffix(' 秒')
        self._clipboard_spin.setSpecialValueText('不自动清空')
        clip_layout.addRow('复制后自动清空：', self._clipboard_spin)
        layout.addWidget(clip_group)

        pwd_group = QGroupBox('密码显示')
        pwd_layout = QFormLayout(pwd_group)
        self._pwd_visible_spin = QSpinBox()
        self._pwd_visible_spin.setRange(3, 60)
        self._pwd_visible_spin.setSuffix(' 秒')
        pwd_layout.addRow('密码显示自动隐藏：', self._pwd_visible_spin)
        layout.addWidget(pwd_group)

        layout.addStretch()
        return widget

    def _create_password_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        group = QGroupBox('默认密码生成规则')
        form = QFormLayout(group)

        self._default_length_spin = QSpinBox()
        self._default_length_spin.setRange(4, 64)
        form.addRow('默认长度：', self._default_length_spin)

        self._default_upper_check = QCheckBox('包含大写字母')
        self._default_lower_check = QCheckBox('包含小写字母')
        self._default_digits_check = QCheckBox('包含数字')
        self._default_symbols_check = QCheckBox('包含特殊字符')
        self._default_exclude_check = QCheckBox('排除模糊字符')

        form.addRow('', self._default_upper_check)
        form.addRow('', self._default_lower_check)
        form.addRow('', self._default_digits_check)
        form.addRow('', self._default_symbols_check)
        form.addRow('', self._default_exclude_check)

        layout.addWidget(group)

        # 过期提醒
        warn_group = QGroupBox('安全提醒')
        warn_layout = QFormLayout(warn_group)
        self._old_pwd_spin = QSpinBox()
        self._old_pwd_spin.setRange(30, 365)
        self._old_pwd_spin.setSuffix(' 天')
        warn_layout.addRow('密码超过此天数未修改时提醒：', self._old_pwd_spin)
        layout.addWidget(warn_group)

        layout.addStretch()
        return widget

    def _create_backup_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        group = QGroupBox('备份路径')
        path_layout = QHBoxLayout(group)
        self._backup_path_edit = QLineEdit()
        self._backup_path_edit.setPlaceholderText('默认：应用数据目录')
        path_layout.addWidget(self._backup_path_edit)

        browse_btn = QPushButton('浏览...')
        browse_btn.clicked.connect(self._browse_backup_dir)
        path_layout.addWidget(browse_btn)
        layout.addWidget(group)

        auto_group = QGroupBox('本地自动快照')
        auto_form = QFormLayout(auto_group)
        self._auto_backup_check = QCheckBox('启用自动快照')
        self._auto_backup_check.setToolTip(
            '自动快照使用当前保险库密钥，仅用于当前保险库快速回滚'
        )
        auto_form.addRow('', self._auto_backup_check)
        self._backup_interval_spin = QSpinBox()
        self._backup_interval_spin.setRange(1, 168)
        self._backup_interval_spin.setSuffix(' 小时')
        auto_form.addRow('创建间隔：', self._backup_interval_spin)
        self._backup_retention_spin = QSpinBox()
        self._backup_retention_spin.setRange(2, 50)
        self._backup_retention_spin.setSuffix(' 份')
        auto_form.addRow('保留数量：', self._backup_retention_spin)
        self._auto_backup_check.toggled.connect(self._update_backup_options)
        layout.addWidget(auto_group)

        hint = QPushButton('手动备份可跨安装恢复；自动快照仅用于当前保险库。')
        hint.setEnabled(False)
        layout.addWidget(hint)

        layout.addStretch()
        return widget

    def _browse_backup_dir(self):
        path = QFileDialog.getExistingDirectory(self, '选择备份目录')
        if path:
            self._backup_path_edit.setText(path)

    def _load_settings(self):
        theme = self._config.get('theme', 'light')
        self._theme_combo.setCurrentIndex(0 if theme == 'light' else 1)

        self._show_tray_check.setChecked(self._config.get('show_tray_icon', True))
        self._minimize_tray_check.setChecked(self._config.get('minimize_to_tray', True))
        self._close_tray_check.setChecked(self._config.get('close_to_tray', False))

        self._auto_lock_spin.setValue(self._config.get('auto_lock_minutes', 5))
        self._clipboard_spin.setValue(self._config.get('clipboard_clear_seconds', 30))
        self._pwd_visible_spin.setValue(self._config.get('password_visible_seconds', 10))

        self._default_length_spin.setValue(self._config.get('default_password_length', 16))
        self._default_upper_check.setChecked(self._config.get('default_uppercase', True))
        self._default_lower_check.setChecked(self._config.get('default_lowercase', True))
        self._default_digits_check.setChecked(self._config.get('default_digits', True))
        self._default_symbols_check.setChecked(self._config.get('default_symbols', True))
        self._default_exclude_check.setChecked(self._config.get('default_exclude_ambiguous', False))

        self._old_pwd_spin.setValue(self._config.get('old_password_warning_days', 90))
        self._backup_path_edit.setText(self._config.get('backup_directory', ''))
        self._auto_backup_check.setChecked(self._config.get('auto_backup_enabled', False))
        self._backup_interval_spin.setValue(self._config.get('auto_backup_interval_hours', 24))
        self._backup_retention_spin.setValue(self._config.get('auto_backup_retention', 10))
        self._update_tray_options(self._show_tray_check.isChecked())
        self._update_backup_options(self._auto_backup_check.isChecked())

    def _update_tray_options(self, enabled: bool):
        self._minimize_tray_check.setEnabled(enabled)
        self._close_tray_check.setEnabled(enabled)

    def _update_backup_options(self, enabled: bool):
        self._backup_interval_spin.setEnabled(enabled)
        self._backup_retention_spin.setEnabled(enabled)

    def _save_settings(self):
        if not any((
            self._default_upper_check.isChecked(),
            self._default_lower_check.isChecked(),
            self._default_digits_check.isChecked(),
            self._default_symbols_check.isChecked(),
        )):
            QMessageBox.warning(self, '生成规则无效', '至少需要选择一种密码字符类型。')
            return
        self._config.set('theme', 'light' if self._theme_combo.currentIndex() == 0 else 'dark')
        self._config.set('show_tray_icon', self._show_tray_check.isChecked())
        self._config.set('minimize_to_tray', self._minimize_tray_check.isChecked())
        self._config.set('close_to_tray', self._close_tray_check.isChecked())
        self._config.set('auto_lock_minutes', self._auto_lock_spin.value())
        self._config.set('clipboard_clear_seconds', self._clipboard_spin.value())
        self._config.set('password_visible_seconds', self._pwd_visible_spin.value())
        self._config.set('default_password_length', self._default_length_spin.value())
        self._config.set('default_uppercase', self._default_upper_check.isChecked())
        self._config.set('default_lowercase', self._default_lower_check.isChecked())
        self._config.set('default_digits', self._default_digits_check.isChecked())
        self._config.set('default_symbols', self._default_symbols_check.isChecked())
        self._config.set('default_exclude_ambiguous', self._default_exclude_check.isChecked())
        self._config.set('old_password_warning_days', self._old_pwd_spin.value())
        self._config.set('backup_directory', self._backup_path_edit.text().strip())
        self._config.set('auto_backup_enabled', self._auto_backup_check.isChecked())
        self._config.set('auto_backup_interval_hours', self._backup_interval_spin.value())
        self._config.set('auto_backup_retention', self._backup_retention_spin.value())
        self._config.save()
        self.accept()

    def _reset_to_defaults(self):
        """恢复默认设置"""
        from ..config import DEFAULT_CONFIG
        defaults = DEFAULT_CONFIG
        self._theme_combo.setCurrentIndex(0)
        self._show_tray_check.setChecked(defaults.get('show_tray_icon', True))
        self._minimize_tray_check.setChecked(defaults.get('minimize_to_tray', True))
        self._close_tray_check.setChecked(defaults.get('close_to_tray', False))
        self._auto_lock_spin.setValue(defaults.get('auto_lock_minutes', 5))
        self._clipboard_spin.setValue(defaults.get('clipboard_clear_seconds', 30))
        self._pwd_visible_spin.setValue(defaults.get('password_visible_seconds', 10))
        self._default_length_spin.setValue(defaults.get('default_password_length', 16))
        self._default_upper_check.setChecked(defaults.get('default_uppercase', True))
        self._default_lower_check.setChecked(defaults.get('default_lowercase', True))
        self._default_digits_check.setChecked(defaults.get('default_digits', True))
        self._default_symbols_check.setChecked(defaults.get('default_symbols', True))
        self._default_exclude_check.setChecked(defaults.get('default_exclude_ambiguous', False))
        self._old_pwd_spin.setValue(defaults.get('old_password_warning_days', 90))
        self._backup_path_edit.setText('')
        self._auto_backup_check.setChecked(defaults.get('auto_backup_enabled', False))
        self._backup_interval_spin.setValue(defaults.get('auto_backup_interval_hours', 24))
        self._backup_retention_spin.setValue(defaults.get('auto_backup_retention', 10))
