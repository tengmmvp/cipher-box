"""设置对话框"""

from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ...config import ConfigManager
from ..components.widgets import setup_dialog_flags
from ..resources.constants import BTN_DIALOG, DIALOG_SETTINGS_MIN_SIZE


class SettingsDialog(QDialog):
    """设置中心"""

    def __init__(self, config: ConfigManager, parent=None):
        super().__init__(parent)
        self._config = config
        self._setup_ui()
        self._load_settings()

    def _setup_ui(self):
        self.setWindowTitle('设置')
        self.setMinimumSize(*DIALOG_SETTINGS_MIN_SIZE)
        setup_dialog_flags(self)

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
        reset_btn.setFixedSize(*BTN_DIALOG)
        reset_btn.clicked.connect(self._reset_to_defaults)
        btn_layout.addWidget(reset_btn)

        cancel_btn = QPushButton('取消')
        cancel_btn.setFixedSize(*BTN_DIALOG)
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)

        save_btn = QPushButton('保存')
        save_btn.setObjectName('primaryBtn')
        save_btn.setFixedSize(*BTN_DIALOG)
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

    # (config_key, widget_attr, accessor_type, default_value)
    # accessor_type: 'combo' | 'check' | 'spin'
    _SETTINGS_MAP = [
        ('theme', '_theme_combo', 'combo', 'light'),
        ('show_tray_icon', '_show_tray_check', 'check', True),
        ('minimize_to_tray', '_minimize_tray_check', 'check', True),
        ('close_to_tray', '_close_tray_check', 'check', False),
        ('auto_lock_minutes', '_auto_lock_spin', 'spin', 5),
        ('clipboard_clear_seconds', '_clipboard_spin', 'spin', 30),
        ('password_visible_seconds', '_pwd_visible_spin', 'spin', 10),
        ('default_password_length', '_default_length_spin', 'spin', 16),
        ('default_uppercase', '_default_upper_check', 'check', True),
        ('default_lowercase', '_default_lower_check', 'check', True),
        ('default_digits', '_default_digits_check', 'check', True),
        ('default_symbols', '_default_symbols_check', 'check', True),
        ('default_exclude_ambiguous', '_default_exclude_check', 'check', False),
        ('old_password_warning_days', '_old_pwd_spin', 'spin', 90),
        ('auto_backup_enabled', '_auto_backup_check', 'check', False),
        ('auto_backup_interval_hours', '_backup_interval_spin', 'spin', 24),
        ('auto_backup_retention', '_backup_retention_spin', 'spin', 10),
    ]

    def _set_widget_value(self, widget, accessor_type: str, value):
        if accessor_type == 'combo':
            widget.setCurrentIndex(0 if value == 'light' else 1)
        elif accessor_type == 'check':
            widget.setChecked(value)
        elif accessor_type == 'spin':
            widget.setValue(value)

    def _get_widget_value(self, widget, accessor_type: str):
        if accessor_type == 'combo':
            return 'light' if widget.currentIndex() == 0 else 'dark'
        elif accessor_type == 'check':
            return widget.isChecked()
        elif accessor_type == 'spin':
            return widget.value()

    def _load_settings(self):
        for key, attr, atype, default in self._SETTINGS_MAP:
            self._set_widget_value(getattr(self, attr), atype, self._config.get(key, default))
        self._backup_path_edit.setText(self._config.get('backup_directory', ''))
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
        for key, attr, atype, _default in self._SETTINGS_MAP:
            self._config.set(key, self._get_widget_value(getattr(self, attr), atype))
        self._config.set('backup_directory', self._backup_path_edit.text().strip())
        try:
            self._config.save()
        except OSError:
            QMessageBox.critical(
                self, '保存失败',
                '无法写入配置文件，请检查磁盘空间和文件权限。',
            )
            return
        self.accept()

    def _reset_to_defaults(self):
        """恢复默认设置"""
        for _key, attr, atype, default in self._SETTINGS_MAP:
            self._set_widget_value(getattr(self, attr), atype, default)
        self._backup_path_edit.setText('')
