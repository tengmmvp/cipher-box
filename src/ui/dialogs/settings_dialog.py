"""设置对话框，按标签页组织通用、安全、密码生成与备份四类配置。

所有配置项通过 _SETTINGS_MAP 与控件属性建立映射，加载与保存统一遍历
该映射完成，新增配置只需扩展映射表。保存时执行原子写入。
"""

from __future__ import annotations

from typing import Any

from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ...business.services.password_service import PasswordService
from ...config import DEFAULT_CONFIG, ConfigManager, get_ui_int_range
from ..components.widgets import create_cancel_button, setup_dialog_flags
from ..resources.constants import BTN_DIALOG, DIALOG_SETTINGS_MIN_SIZE, THEME_DARK, THEME_LIGHT


class SettingsDialog(QDialog):
    """应用设置对话框，编辑并持久化用户偏好。"""

    def __init__(self, config: ConfigManager, parent: QWidget | None = None):
        super().__init__(parent)
        self._config = config
        self._setup_ui()
        self._load_settings()

    def _setup_ui(self) -> None:
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

        btn_layout.addWidget(create_cancel_button(self))

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
        self._auto_lock_spin.setRange(*get_ui_int_range('auto_lock_minutes'))
        self._auto_lock_spin.setSpecialValueText('不自动锁定')
        self._auto_lock_spin.setSuffix(' 分钟')
        lock_layout.addRow('空闲自动锁定：', self._auto_lock_spin)
        layout.addWidget(lock_group)

        clip_group = QGroupBox('剪贴板')
        clip_layout = QFormLayout(clip_group)
        self._clipboard_spin = QSpinBox()
        # 范围派生自 config.get_ui_int_range 单一源（下限取运行时安全下限 10）：
        # get_safe('clipboard_clear_seconds') 会将低于 10 的值钳制到 10，故 UI 不提供
        # 0 /「不自动清空」选项，避免界面值与运行时实际值脱节。
        self._clipboard_spin.setRange(*get_ui_int_range('clipboard_clear_seconds'))
        self._clipboard_spin.setSuffix(' 秒')
        clip_layout.addRow('复制后自动清空：', self._clipboard_spin)
        layout.addWidget(clip_group)

        pwd_group = QGroupBox('密码显示')
        pwd_layout = QFormLayout(pwd_group)
        self._pwd_visible_spin = QSpinBox()
        self._pwd_visible_spin.setRange(*get_ui_int_range('password_visible_seconds'))
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
        self._default_length_spin.setRange(*get_ui_int_range('default_password_length'))
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
        self._old_pwd_spin.setRange(*get_ui_int_range('old_password_warning_days'))
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
        self._backup_interval_spin.setRange(*get_ui_int_range('auto_backup_interval_hours'))
        self._backup_interval_spin.setSuffix(' 小时')
        auto_form.addRow('创建间隔：', self._backup_interval_spin)
        self._backup_retention_spin = QSpinBox()
        self._backup_retention_spin.setRange(*get_ui_int_range('auto_backup_retention'))
        self._backup_retention_spin.setSuffix(' 份')
        auto_form.addRow('保留数量：', self._backup_retention_spin)
        self._auto_backup_check.toggled.connect(self._update_backup_options)
        layout.addWidget(auto_group)

        # 用 QLabel 而非禁用的 QPushButton 承载提示文本：语义正确，避免屏幕阅读器
        # 将其识别为禁用按钮。objectName 供 QSS 控制为弱化提示色。
        hint = QLabel('手动备份可跨安装恢复；自动快照仅用于当前保险库。')
        hint.setObjectName('hintLabel')
        hint.setWordWrap(True)
        layout.addWidget(hint)

        layout.addStretch()
        return widget

    def _browse_backup_dir(self) -> None:
        path = QFileDialog.getExistingDirectory(self, '选择备份目录')
        if path:
            self._backup_path_edit.setText(path)

    # 配置项映射表，每个元素为四元组，依次是配置键、控件属性、访问类型与默认值。
    # 访问类型取值为 combo、check 或 spin，决定读写控件的方式
    # 默认值统一引用 DEFAULT_CONFIG（单一事实源），消除此处字面量与 config 双源
    # 漂移——改某项默认值只需改 config.DEFAULT_CONFIG 一处。
    _SETTINGS_MAP = [
        ('theme', '_theme_combo', 'combo', DEFAULT_CONFIG['theme']),
        ('show_tray_icon', '_show_tray_check', 'check', DEFAULT_CONFIG['show_tray_icon']),
        ('minimize_to_tray', '_minimize_tray_check', 'check', DEFAULT_CONFIG['minimize_to_tray']),
        ('close_to_tray', '_close_tray_check', 'check', DEFAULT_CONFIG['close_to_tray']),
        ('auto_lock_minutes', '_auto_lock_spin', 'spin', DEFAULT_CONFIG['auto_lock_minutes']),
        ('clipboard_clear_seconds', '_clipboard_spin', 'spin', DEFAULT_CONFIG['clipboard_clear_seconds']),
        ('password_visible_seconds', '_pwd_visible_spin', 'spin', DEFAULT_CONFIG['password_visible_seconds']),
        ('default_password_length', '_default_length_spin', 'spin', DEFAULT_CONFIG['default_password_length']),
        ('default_uppercase', '_default_upper_check', 'check', DEFAULT_CONFIG['default_uppercase']),
        ('default_lowercase', '_default_lower_check', 'check', DEFAULT_CONFIG['default_lowercase']),
        ('default_digits', '_default_digits_check', 'check', DEFAULT_CONFIG['default_digits']),
        ('default_symbols', '_default_symbols_check', 'check', DEFAULT_CONFIG['default_symbols']),
        ('default_exclude_ambiguous', '_default_exclude_check', 'check', DEFAULT_CONFIG['default_exclude_ambiguous']),
        ('old_password_warning_days', '_old_pwd_spin', 'spin', DEFAULT_CONFIG['old_password_warning_days']),
        ('auto_backup_enabled', '_auto_backup_check', 'check', DEFAULT_CONFIG['auto_backup_enabled']),
        ('auto_backup_interval_hours', '_backup_interval_spin', 'spin', DEFAULT_CONFIG['auto_backup_interval_hours']),
        ('auto_backup_retention', '_backup_retention_spin', 'spin', DEFAULT_CONFIG['auto_backup_retention']),
    ]

    def _set_widget_value(
        self,
        widget: QComboBox | QCheckBox | QSpinBox,
        accessor_type: str,
        value: Any,
    ) -> None:
        # accessor_type 与 widget 子类型在 _SETTINGS_MAP 中一一配对；isinstance 既
        # 满足类型 narrowing，又与运行时契约一致（不配对属编程错误，静默跳过）。
        if accessor_type == 'combo' and isinstance(widget, QComboBox):
            widget.setCurrentIndex(0 if value == THEME_LIGHT else 1)
        elif accessor_type == 'check' and isinstance(widget, QCheckBox):
            widget.setChecked(value)
        elif accessor_type == 'spin' and isinstance(widget, QSpinBox):
            widget.setValue(value)

    def _get_widget_value(self, widget: QComboBox | QCheckBox | QSpinBox, accessor_type: str) -> Any:
        if accessor_type == 'combo' and isinstance(widget, QComboBox):
            return THEME_LIGHT if widget.currentIndex() == 0 else THEME_DARK
        if accessor_type == 'check' and isinstance(widget, QCheckBox):
            return widget.isChecked()
        if accessor_type == 'spin' and isinstance(widget, QSpinBox):
            return widget.value()
        return None

    def _load_settings(self) -> None:
        for key, attr, atype, default in self._SETTINGS_MAP:
            self._set_widget_value(getattr(self, attr), atype, self._config.get(key, default))
        self._backup_path_edit.setText(self._config.get('backup_directory', ''))
        self._update_tray_options(self._show_tray_check.isChecked())
        self._update_backup_options(self._auto_backup_check.isChecked())

    def _update_tray_options(self, enabled: bool) -> None:
        self._minimize_tray_check.setEnabled(enabled)
        self._close_tray_check.setEnabled(enabled)

    def _update_backup_options(self, enabled: bool) -> None:
        self._backup_interval_spin.setEnabled(enabled)
        self._backup_retention_spin.setEnabled(enabled)

    def _save_settings(self) -> None:
        # 密码生成至少需要一种字符集：校验文案经共享 helper 单一源，避免漂移
        ok, error = PasswordService.validate_charset_selection(
            self._default_upper_check.isChecked(),
            self._default_lower_check.isChecked(),
            self._default_digits_check.isChecked(),
            self._default_symbols_check.isChecked(),
        )
        if not ok:
            QMessageBox.warning(self, '生成规则无效', error)
            return
        # 快照当前内存配置：save 失败时回滚，避免内存已写入新值而磁盘仍为旧值，
        # 导致用户取消后同进程后续 config.get 读到未持久化的脏值。
        snapshot: dict[str, object] = {
            key: self._config.get(key) for key, *_ in self._SETTINGS_MAP
        }
        snapshot['backup_directory'] = self._config.get('backup_directory')
        for key, attr, atype, _default in self._SETTINGS_MAP:
            self._config.set(key, self._get_widget_value(getattr(self, attr), atype))
        self._config.set('backup_directory', self._backup_path_edit.text().strip())
        try:
            self._config.save()
        except OSError:
            # save 失败：回滚内存配置到快照，保持内存与磁盘（旧值）一致。
            for key, value in snapshot.items():
                self._config.set(key, value)
            QMessageBox.critical(
                self, '保存失败',
                '无法写入配置文件，请检查磁盘空间和文件权限。',
            )
            return
        self.accept()

    def _reset_to_defaults(self) -> None:
        """将所有配置控件恢复为默认值，不立即保存。"""
        for _key, attr, atype, default in self._SETTINGS_MAP:
            self._set_widget_value(getattr(self, attr), atype, default)
        self._backup_path_edit.setText('')
