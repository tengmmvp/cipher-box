"""备份恢复对话框"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QRadioButton, QButtonGroup, QFileDialog, QMessageBox, QGroupBox,
    QInputDialog, QLineEdit,
)
from PyQt6.QtCore import Qt

from ..ui.resources.theme_colors import c
from ..crypto.password_generator import PasswordGenerator


class BackupDialog(QDialog):
    """备份与恢复对话框"""

    def __init__(self, backup_manager, parent=None, config=None):
        super().__init__(parent)
        self._backup_mgr = backup_manager
        self._config = config
        self._setup_ui()

    def _setup_ui(self):
        self.setWindowTitle('备份与恢复')
        self.setMinimumSize(460, 300)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)

        layout = QVBoxLayout(self)
        layout.setSpacing(14)

        # 模式选择
        mode_group = QGroupBox('操作')
        mode_layout = QVBoxLayout(mode_group)
        self._btn_group = QButtonGroup(self)

        self._backup_radio = QRadioButton('创建加密备份')
        self._backup_radio.setChecked(True)
        self._btn_group.addButton(self._backup_radio, 0)
        mode_layout.addWidget(self._backup_radio)

        info1 = QLabel('  将保险库的全部数据加密保存到一个文件中')
        info1.setStyleSheet(f'color: {c("text_muted")}; font-size: 12px;')
        mode_layout.addWidget(info1)

        self._restore_radio = QRadioButton('从备份恢复')
        self._btn_group.addButton(self._restore_radio, 1)
        mode_layout.addWidget(self._restore_radio)

        info2 = QLabel('  ⚠️ 恢复将覆盖当前所有数据！请谨慎操作')
        info2.setStyleSheet(f'color: {c("danger")}; font-size: 12px;')
        mode_layout.addWidget(info2)

        layout.addWidget(mode_group)

        # 文件选择
        file_group = QGroupBox('文件')
        file_layout = QHBoxLayout(file_group)
        self._path_label = QLabel('未选择')
        self._path_label.setStyleSheet(f'color: {c("text_muted")};')
        self._path_label.setWordWrap(True)
        file_layout.addWidget(self._path_label, 1)

        browse_btn = QPushButton('浏览...')
        browse_btn.clicked.connect(self._browse)
        file_layout.addWidget(browse_btn)
        layout.addWidget(file_group)

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

        self._exec_btn = QPushButton('创建备份')
        self._exec_btn.setObjectName('primaryBtn')
        self._exec_btn.setFixedSize(100, 34)
        self._exec_btn.clicked.connect(self._execute)
        btn_layout.addWidget(self._exec_btn)

        layout.addLayout(btn_layout)

        self._btn_group.buttonClicked.connect(self._on_mode_changed)

    def _on_mode_changed(self):
        is_backup = self._btn_group.checkedId() == 0
        self._exec_btn.setText('创建备份' if is_backup else '恢复数据')
        self._path_label.setText('未选择')
        self._path_label.setStyleSheet(f'color: {c("text_muted")};')

    def _browse(self):
        is_backup = self._btn_group.checkedId() == 0
        if is_backup:
            initial_dir = self._config.get('backup_directory', '') if self._config else ''
            initial_path = str(__import__('pathlib').Path(initial_dir) / 'cipherbox_backup.cbox') if initial_dir else 'cipherbox_backup.cbox'
            path, _ = QFileDialog.getSaveFileName(
                self, '选择备份保存路径', initial_path,
                'CipherBox 备份 (*.cbox)',
            )
        else:
            path, _ = QFileDialog.getOpenFileName(
                self, '选择备份文件', '',
                'CipherBox 备份 (*.cbox);;所有文件 (*.*)',
            )
        if path:
            self._path_label.setText(path)
            self._path_label.setStyleSheet(f'color: {c("text_primary")};')

    def _execute(self):
        path = self._path_label.text()
        if path == '未选择' or not path:
            QMessageBox.warning(self, '提示', '请先选择文件')
            return

        is_backup = self._btn_group.checkedId() == 0

        if is_backup:
            self._do_backup(path)
        else:
            self._do_restore(path)

    def _do_backup(self, path: str):
        password, ok = QInputDialog.getText(
            self, '设置备份密码',
            '请输入独立备份密码。恢复时必须使用该密码：',
            QLineEdit.EchoMode.Password,
        )
        if not ok:
            return
        valid, error = PasswordGenerator.validate_master_password(password)
        if not valid:
            QMessageBox.warning(self, '备份密码不安全', error.replace('主密码', '备份密码'))
            return
        confirm, ok = QInputDialog.getText(
            self, '确认备份密码', '请再次输入备份密码：',
            QLineEdit.EchoMode.Password,
        )
        if not ok or confirm != password:
            QMessageBox.warning(self, '密码不一致', '两次输入的备份密码不一致。')
            return
        success, error_msg = self._backup_mgr.create_backup(path, password)
        if success:
            self._status_label.setText('✅ 备份创建成功')
            self._status_label.setStyleSheet(f'color: {c("success")};')
            QMessageBox.information(self, '成功', f'备份已保存到：\n{path}')
        else:
            self._status_label.setText('❌ 备份失败')
            self._status_label.setStyleSheet(f'color: {c("danger")};')
            msg = f'备份创建失败：{error_msg}' if error_msg else '备份创建失败，请检查文件路径和磁盘空间。'
            QMessageBox.critical(self, '错误', msg)

    def _do_restore(self, path: str):
        reply = QMessageBox.warning(
            self, '⚠️ 危险操作',
            '恢复备份将覆盖当前保险库中的所有数据！\n\n'
            '此操作不可撤销！\n\n'
            '确定要继续吗？',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            info = self._backup_mgr.inspect_backup(path)
        except (OSError, ValueError) as exc:
            QMessageBox.critical(self, '错误', str(exc))
            return
        password = None
        if info.get('password_required'):
            password, ok = QInputDialog.getText(
                self, '输入备份密码', '请输入创建该备份时设置的密码：',
                QLineEdit.EchoMode.Password,
            )
            if not ok:
                return
        success, error_msg = self._backup_mgr.restore_backup(path, password)
        if success:
            self._status_label.setText('✅ 恢复成功')
            self._status_label.setStyleSheet(f'color: {c("success")};')
            QMessageBox.information(self, '成功', '备份恢复成功！')
        else:
            self._status_label.setText('❌ 恢复失败')
            self._status_label.setStyleSheet(f'color: {c("danger")};')
            detail = f'\n\n错误信息：{error_msg}' if error_msg else ''
            QMessageBox.critical(self, '错误', f'恢复失败，请确认备份文件有效且主密码正确。{detail}')
