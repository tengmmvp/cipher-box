"""备份恢复对话框"""

from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QButtonGroup,
    QDialog,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
)

from ...business.services.password_service import PasswordService
from ..components.widgets import format_status, setup_dialog_flags
from ..components.workers import BackgroundWorker
from ..resources.constants import (
    BTN_DIALOG,
    BTN_DIALOG_WIDE,
    DIALOG_BACKUP_MIN_SIZE,
    WORKER_WAIT_TIMEOUT_MS,
)
from ..resources.theme_colors import c


class BackupDialog(QDialog):
    """备份与恢复对话框"""

    def __init__(self, backup_manager, parent=None, config=None):
        super().__init__(parent)
        self._backup_mgr = backup_manager
        self._config = config
        self._worker = None
        # 记录 worker 启动时的模式，避免 reject 时读取已切换的按钮状态
        self._worker_is_backup: bool = True
        self._selected_path: str | None = None
        self._data_changed: bool = False
        self._setup_ui()

    def _setup_ui(self):
        self.setWindowTitle('备份与恢复')
        self.setMinimumSize(*DIALOG_BACKUP_MIN_SIZE)
        setup_dialog_flags(self)

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

        info2 = QLabel('  [!] 恢复将覆盖当前所有数据！请谨慎操作')
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
        cancel_btn.setFixedSize(*BTN_DIALOG)
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)

        self._exec_btn = QPushButton('创建备份')
        self._exec_btn.setObjectName('primaryBtn')
        self._exec_btn.setFixedSize(*BTN_DIALOG_WIDE)
        self._exec_btn.clicked.connect(self._execute)
        btn_layout.addWidget(self._exec_btn)

        layout.addLayout(btn_layout)

        self._btn_group.buttonClicked.connect(self._on_mode_changed)

    def reject(self):
        """关闭对话框前等待后台 worker 完成。

        恢复操作有数据库写入副作用，不取消 worker 以确保数据一致性；
        备份创建无副作用，可安全取消。
        完成后释放 worker 引用，缩短密码闭包驻留时间。
        """
        if self._worker and self._worker.isRunning():
            if self._worker_is_backup:
                self._worker.cancel()
            self._worker.wait(WORKER_WAIT_TIMEOUT_MS)
        self._release_worker()
        super().reject()

    def _release_worker(self):
        """断开 worker 信号并释放引用，缩短密码闭包驻留时间。

        worker 的可调用对象闭包捕获了备份/恢复密码，
        操作完成或对话框关闭后立即断开信号并删除 self._worker 引用，
        使闭包随 worker 对象回收而释放。
        worker 的 parent 为 self，控件销毁时 worker 一并销毁。
        """
        worker = self._worker
        if worker is None:
            return
        try:
            worker.finished.disconnect()
            worker.error.disconnect()
        except (TypeError, RuntimeError):
            pass
        self._worker = None

    def _on_mode_changed(self):
        is_backup = self._btn_group.checkedId() == 0
        self._exec_btn.setText('创建备份' if is_backup else '恢复数据')
        self._selected_path = None
        self._path_label.setText('未选择')
        self._path_label.setStyleSheet(f'color: {c("text_muted")};')

    def _browse(self):
        is_backup = self._btn_group.checkedId() == 0
        if is_backup:
            initial_dir = self._config.get('backup_directory', '') if self._config else ''
            initial_path = str(Path(initial_dir) / 'cipherbox_backup.cbox') if initial_dir else 'cipherbox_backup.cbox'
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
            self._selected_path = path
            self._path_label.setText(path)
            self._path_label.setStyleSheet(f'color: {c("text_primary")};')

    def _execute(self):
        if not self._selected_path:
            QMessageBox.warning(self, '提示', '请先选择文件')
            return

        is_backup = self._btn_group.checkedId() == 0

        if is_backup:
            self._do_backup(self._selected_path)
        else:
            self._do_restore(self._selected_path)

    def _set_busy(self, busy: bool):
        """设置操作进行中状态：禁用/启用按钮。"""
        self._exec_btn.setEnabled(not busy)
        if busy:
            self._status_label.setText('处理中...')
            self._status_label.setStyleSheet(f'color: {c("accent")};')
        else:
            self._status_label.setText('')

    def _do_backup(self, path: str):
        password, ok = QInputDialog.getText(
            self, '设置备份密码',
            '请输入独立备份密码。恢复时必须使用该密码：',
            QLineEdit.EchoMode.Password,
        )
        if not ok:
            return
        valid, error = PasswordService.validate_master_password(password, label='备份密码')
        if not valid:
            QMessageBox.warning(self, '备份密码不安全', error)
            return
        confirm, ok = QInputDialog.getText(
            self, '确认备份密码', '请再次输入备份密码：',
            QLineEdit.EchoMode.Password,
        )
        if not ok or confirm != password:
            QMessageBox.warning(self, '密码不一致', '两次输入的备份密码不一致。')
            return
        self._set_busy(True)
        self._worker_is_backup = True
        self._worker = BackgroundWorker(
            lambda: self._backup_mgr.create_backup(path, password),
            parent=self,
        )
        self._worker.finished.connect(self._on_backup_done)
        self._worker.error.connect(self._on_backup_error)
        self._worker.start()

    def _on_backup_done(self, result):
        self._set_busy(False)
        self._release_worker()
        success, error_msg = result
        if success:
            self._data_changed = True
            self._status_label.setText(format_status(True, '备份创建成功'))
            self._status_label.setStyleSheet(f'color: {c("success")};')
            QMessageBox.information(self, '成功', f'备份已保存到：\n{self._path_label.text()}')
        else:
            self._status_label.setText(format_status(False, '备份失败'))
            self._status_label.setStyleSheet(f'color: {c("danger")};')
            msg = f'备份创建失败：{error_msg}' if error_msg else '备份创建失败，请检查文件路径和磁盘空间。'
            QMessageBox.critical(self, '错误', msg)

    def _on_backup_error(self, error_msg: str):
        self._set_busy(False)
        self._release_worker()
        self._status_label.setText(format_status(False, '备份失败'))
        self._status_label.setStyleSheet(f'color: {c("danger")};')
        QMessageBox.critical(self, '错误', f'备份创建失败：{error_msg}')

    def _do_restore(self, path: str):
        reply = QMessageBox.warning(
            self, '[!] 危险操作',
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
        # 旧版备份绑定创建时的主密码，改密后无法恢复
        if info.get('master_key_bound'):
            QMessageBox.warning(
                self, '[!] 旧版备份格式',
                '该备份使用旧版格式，绑定创建时的主密码。\n'
                '若创建该备份后修改过主密码，将无法恢复。',
            )
        password = None
        if info.get('password_required'):
            password, ok = QInputDialog.getText(
                self, '输入备份密码', '请输入创建该备份时设置的密码：',
                QLineEdit.EchoMode.Password,
            )
            if not ok:
                return
        self._set_busy(True)
        self._worker_is_backup = False
        self._worker = BackgroundWorker(
            lambda: self._backup_mgr.restore_backup(path, password),
            parent=self,
        )
        self._worker.finished.connect(self._on_restore_done)
        self._worker.error.connect(self._on_restore_error)
        self._worker.start()

    def _on_restore_done(self, result):
        self._set_busy(False)
        self._release_worker()
        success, error_msg = result
        if success:
            self._data_changed = True
            self._status_label.setText(format_status(True, '恢复成功'))
            self._status_label.setStyleSheet(f'color: {c("success")};')
            QMessageBox.information(self, '成功', '备份恢复成功！')
        else:
            self._status_label.setText(format_status(False, '恢复失败'))
            self._status_label.setStyleSheet(f'color: {c("danger")};')
            detail = f'\n\n错误信息：{error_msg}' if error_msg else ''
            QMessageBox.critical(self, '错误', f'恢复失败，请确认备份文件有效且主密码正确。{detail}')

    def _on_restore_error(self, error_msg: str):
        self._set_busy(False)
        self._release_worker()
        self._status_label.setText(format_status(False, '恢复失败'))
        self._status_label.setStyleSheet(f'color: {c("danger")};')
        QMessageBox.critical(self, '错误', f'恢复失败：{error_msg}')
