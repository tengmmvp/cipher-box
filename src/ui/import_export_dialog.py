"""导入导出对话框"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QComboBox, QProgressBar, QFileDialog, QMessageBox,
    QRadioButton, QButtonGroup, QWidget,
)
from PyQt6.QtCore import Qt, pyqtSignal

from ..ui.resources.theme_colors import c

# 格式定义
_EXPORT_FORMATS = ['JSON', 'CSV']
_IMPORT_FORMATS = ['JSON (CipherBox)', 'CSV', 'Chrome / Edge CSV', 'Bitwarden JSON', 'KeePass CSV']
_IMPORT_FILTERS = {
    'JSON (CipherBox)':  ('JSON 文件 (*.json)', 'cipherbox_import.json'),
    'CSV':               ('CSV 文件 (*.csv)', 'import.csv'),
    'Chrome / Edge CSV': ('CSV 文件 (*.csv)', 'chrome_import.csv'),
    'Bitwarden JSON':    ('JSON 文件 (*.json)', 'bitwarden_import.json'),
    'KeePass CSV':       ('CSV 文件 (*.csv)', 'keepass_import.csv'),
}


class ImportExportDialog(QDialog):
    """导入导出对话框"""

    import_completed = pyqtSignal()

    def __init__(self, import_export_manager, entry_manager, parent=None):
        super().__init__(parent)
        self._import_export = import_export_manager
        self._entry_mgr = entry_manager
        self._is_export = True
        self._setup_ui()

    def _setup_ui(self):
        self.setWindowTitle('导入 / 导出')
        self.setMinimumSize(480, 360)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)

        layout = QVBoxLayout(self)
        layout.setSpacing(14)

        # 模式选择
        mode_layout = QHBoxLayout()
        self._mode_group = QButtonGroup(self)

        export_radio = QRadioButton('导出')
        export_radio.setChecked(True)
        self._mode_group.addButton(export_radio, 0)
        mode_layout.addWidget(export_radio)

        import_radio = QRadioButton('导入')
        self._mode_group.addButton(import_radio, 1)
        mode_layout.addWidget(import_radio)

        mode_layout.addStretch()
        layout.addLayout(mode_layout)

        self._mode_group.buttonClicked.connect(self._on_mode_changed)

        # 格式选择
        format_layout = QHBoxLayout()
        format_layout.addWidget(QLabel('格式：'))
        self._format_combo = QComboBox()
        self._format_combo.addItems(_EXPORT_FORMATS)
        format_layout.addWidget(self._format_combo)
        format_layout.addStretch()
        layout.addLayout(format_layout)

        # 密码选项（仅导出）
        self._password_container = QWidget()
        pwd_layout = QHBoxLayout(self._password_container)
        pwd_layout.setContentsMargins(0, 0, 0, 0)
        self._include_pwd_check = QRadioButton('包含密码')
        self._exclude_pwd_check = QRadioButton('不包含密码')
        self._exclude_pwd_check.setChecked(True)
        pwd_layout.addWidget(self._include_pwd_check)
        pwd_layout.addWidget(self._exclude_pwd_check)
        layout.addWidget(self._password_container)

        self._duplicate_container = QWidget()
        duplicate_layout = QHBoxLayout(self._duplicate_container)
        duplicate_layout.setContentsMargins(0, 0, 0, 0)
        duplicate_layout.addWidget(QLabel('重复项：'))
        self._duplicate_combo = QComboBox()
        self._duplicate_combo.addItem('跳过已有条目', 'skip')
        self._duplicate_combo.addItem('覆盖已有条目', 'overwrite')
        self._duplicate_combo.addItem('仍然全部导入', 'import_all')
        duplicate_layout.addWidget(self._duplicate_combo, 1)
        self._duplicate_container.hide()
        layout.addWidget(self._duplicate_container)

        # 文件路径
        path_layout = QHBoxLayout()
        self._path_label = QLabel('文件：')
        path_layout.addWidget(self._path_label)

        self._path_edit = QLabel('未选择')
        self._path_edit.setStyleSheet(f'color: {c("text_muted")};')
        self._path_edit.setWordWrap(True)
        path_layout.addWidget(self._path_edit, 1)

        browse_btn = QPushButton('浏览...')
        browse_btn.clicked.connect(self._browse_file)
        path_layout.addWidget(browse_btn)

        layout.addLayout(path_layout)

        # 进度
        self._progress = QProgressBar()
        self._progress.hide()
        layout.addWidget(self._progress)

        # 状态
        self._status_label = QLabel('')
        self._status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._status_label)

        layout.addStretch()

        # 按钮
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        cancel_btn = QPushButton('取消')
        cancel_btn.setFixedSize(90, 34)
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)

        self._action_btn = QPushButton('导出')
        self._action_btn.setObjectName('primaryBtn')
        self._action_btn.setFixedSize(90, 34)
        self._action_btn.clicked.connect(self._execute)
        btn_layout.addWidget(self._action_btn)

        layout.addLayout(btn_layout)

    def _on_mode_changed(self):
        self._is_export = self._mode_group.checkedId() == 0
        self._password_container.setVisible(self._is_export)
        self._duplicate_container.setVisible(not self._is_export)
        self._action_btn.setText('导出' if self._is_export else '导入')

        # 切换格式下拉项
        self._format_combo.blockSignals(True)
        self._format_combo.clear()
        self._format_combo.addItems(
            _EXPORT_FORMATS if self._is_export else _IMPORT_FORMATS
        )
        self._format_combo.blockSignals(False)

        # 重置文件选择
        self._path_edit.setText('未选择')
        self._path_edit.setStyleSheet(f'color: {c("text_muted")};')

    def _browse_file(self):
        if self._is_export:
            fmt = self._format_combo.currentText().lower()
            path, _ = QFileDialog.getSaveFileName(
                self, '选择导出路径', f'cipherbox_export.{fmt}',
                f'{fmt.upper()} 文件 (*.{fmt})',
            )
        else:
            fmt_name = self._format_combo.currentText()
            filter_str, default_name = _IMPORT_FILTERS.get(
                fmt_name, ('密码文件 (*.json *.csv)', 'import.json')
            )
            path, _ = QFileDialog.getOpenFileName(
                self, '选择导入文件', default_name, filter_str,
            )
        if path:
            self._path_edit.setText(path)
            self._path_edit.setStyleSheet(f'color: {c("text_primary")};')

    def _execute(self):
        path = self._path_edit.text()
        if path == '未选择' or not path:
            QMessageBox.warning(self, '提示', '请先选择文件')
            return

        if self._is_export:
            self._do_export(path)
        else:
            self._do_import(path)

    def _do_export(self, path: str):
        include_pwd = self._include_pwd_check.isChecked()
        fmt = self._format_combo.currentText()

        if include_pwd:
            reply = QMessageBox.warning(
                self, '安全警告',
                '⚠️ 您选择导出包含密码的文件！\n\n'
                '导出的文件将以明文形式保存所有密码，存在严重的安全风险。\n'
                '请确保妥善保管导出文件，使用后立即删除。\n\n'
                '确定要继续吗？',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return

        try:
            entries = self._entry_mgr.get_entries_for_export(include_pwd)
            if fmt == 'JSON':
                self._import_export.export_to_json(path, entries, include_pwd)
            else:
                self._import_export.export_to_csv(path, entries, include_pwd)

            self._status_label.setText(f'✅ 成功导出 {len(entries)} 条记录')
            self._status_label.setStyleSheet(f'color: {c("success")};')
        except Exception as e:
            self._status_label.setText(f'❌ 导出失败：{e}')
            self._status_label.setStyleSheet(f'color: {c("danger")};')

    def _do_import(self, path: str):
        fmt_index = self._format_combo.currentIndex()
        duplicate_action = self._duplicate_combo.currentData() or 'skip'

        reply = QMessageBox.question(
            self, '确认导入',
            '即将导入密码数据到保险库。\n\n'
            f'重复项处理：{self._duplicate_combo.currentText()}。\n\n'
            '确定要继续吗？',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        # 准备进度条（先不显示，等回调决定）
        progress_callback = None

        def _on_progress(current: int, total: int):
            nonlocal progress_callback
            # 首次回调且超过 10 条时显示进度条
            if current == 1 and total > 10:
                self._progress.setRange(0, total)
                self._progress.setValue(0)
                self._progress.show()
            if self._progress.isVisible():
                self._progress.setValue(current)

        try:
            # 根据格式索引调用对应的导入方法
            if fmt_index == 0:  # JSON (CipherBox)
                count = self._import_export.import_from_json(
                    path, progress_callback=_on_progress,
                    duplicate_action=duplicate_action,
                )
            elif fmt_index == 1:  # CSV
                count = self._import_export.import_from_csv(
                    path, progress_callback=_on_progress,
                    duplicate_action=duplicate_action,
                )
            elif fmt_index == 2:  # Chrome / Edge CSV
                count = self._import_export.import_from_chrome_csv(
                    path, progress_callback=_on_progress,
                    duplicate_action=duplicate_action,
                )
            elif fmt_index == 3:  # Bitwarden JSON
                count = self._import_export.import_from_bitwarden_json(
                    path, progress_callback=_on_progress,
                    duplicate_action=duplicate_action,
                )
            elif fmt_index == 4:  # KeePass CSV
                count = self._import_export.import_from_keepass_csv(
                    path, progress_callback=_on_progress,
                    duplicate_action=duplicate_action,
                )
            else:
                count = 0

            self._progress.hide()
            self._status_label.setText(f'✅ 成功导入 {count} 条记录')
            self._status_label.setStyleSheet(f'color: {c("success")};')

            if count > 0:
                self.import_completed.emit()

        except Exception as e:
            self._progress.hide()
            self._status_label.setText(f'❌ 导入失败：{e}')
            self._status_label.setStyleSheet(f'color: {c("danger")};')
