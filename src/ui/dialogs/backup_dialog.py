"""备份与恢复对话框，提供加密备份的创建与还原。

备份采用独立密码派生密钥，可跨主密码恢复。恢复前由业务层自动创建
安全快照，本对话框另提供手动清理恢复点的入口以收缩泄漏面。耗时的
备份与恢复在后台线程执行，恢复有写入副作用不可中途取消，备份可安全
取消。worker 闭包捕获备份或恢复密码，操作结束或对话框关闭后立即释放
引用以缩短密码驻留时间。
"""

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
from ..components.widgets import (
    format_status,
    release_worker,
    set_label_severity,
    setup_dialog_flags,
)
from ..components.workers import BackgroundWorker, wait_worker_shutdown
from ..resources.constants import (
    BTN_DIALOG,
    BTN_DIALOG_WIDE,
    DIALOG_BACKUP_MIN_SIZE,
)
from ..resources.theme_colors import c


class BackupDialog(QDialog):
    """备份创建与恢复的统一对话框，按模式切换操作与文案。"""

    def __init__(self, backup_manager, parent=None, config=None):
        super().__init__(parent)
        self._backup_mgr = backup_manager
        self._config = config
        self._worker = None
        # 记录 worker 启动时的模式，避免 reject 时读取已切换的按钮状态
        self._worker_is_backup: bool = True
        self._selected_path: str | None = None
        self.data_changed: bool = False
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
        info1.setObjectName('formMuted')
        mode_layout.addWidget(info1)

        self._restore_radio = QRadioButton('从备份恢复')
        self._btn_group.addButton(self._restore_radio, 1)
        mode_layout.addWidget(self._restore_radio)

        # 警告文本：去掉 ASCII [!]（屏幕阅读器会朗读该符号），改用语义化 objectName
        # 供 QSS 控制颜色；内联色下沉到 QSS 的工作并入主题重构。
        info2 = QLabel('恢复将覆盖当前所有数据！请谨慎操作')
        info2.setObjectName('warningText')
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
        self._status_label.setObjectName('formStatus')
        layout.addWidget(self._status_label)

        layout.addStretch()

        # 按钮
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        self._purge_btn = QPushButton('清理恢复点')
        self._purge_btn.setFixedSize(*BTN_DIALOG)
        self._purge_btn.clicked.connect(self._purge_restore_points)
        btn_layout.addWidget(self._purge_btn)

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

    def showEvent(self, a0):
        """对话框显示时按是否存在恢复点更新清理按钮可用性。"""
        super().showEvent(a0)
        self._update_purge_button()

    def _update_purge_button(self):
        """根据是否存在恢复前快照启用或禁用清理按钮。"""
        try:
            has_points = self._backup_mgr.count_restore_points() > 0
        except Exception:
            has_points = True  # 统计出错时保持可点，避免误锁功能
        self._purge_btn.setEnabled(has_points)

    def closeEvent(self, a0):
        # 恢复 worker 运行时拒绝关闭，避免 QThread 销毁警告与数据不一致
        if a0 is not None and self._worker and self._worker.isRunning() and not self._worker_is_backup:
            self._status_label.setText('恢复进行中，请等待完成后再关闭')
            a0.ignore()
            return
        super().closeEvent(a0)

    def reject(self):
        """关闭对话框前等待后台 worker 完成。

        恢复操作有数据库写入副作用，不取消 worker 以确保数据一致性；
        备份创建无副作用，可安全取消。
        完成后释放 worker 引用，缩短密码闭包驻留时间。
        """
        # 备份可安全取消，恢复有写入副作用仅等待完成
        wait_worker_shutdown(self._worker, cancel=self._worker_is_backup)
        release_worker(self)
        super().reject()

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
            set_label_severity(self._status_label, 'accent')
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
        release_worker(self)
        success, error_msg = result
        if success:
            self.data_changed = True
            self._status_label.setText(format_status(True, '备份创建成功'))
            set_label_severity(self._status_label, 'success')
            QMessageBox.information(self, '成功', f'备份已保存到：\n{self._path_label.text()}')
        else:
            self._status_label.setText(format_status(False, '备份失败'))
            set_label_severity(self._status_label, 'error')
            msg = f'备份创建失败：{error_msg}' if error_msg else '备份创建失败，请检查文件路径和磁盘空间。'
            QMessageBox.critical(self, '错误', msg)

    def _on_backup_error(self, error_msg: str):
        self._set_busy(False)
        release_worker(self)
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
        release_worker(self)
        success, error_msg = result
        if success:
            self.data_changed = True
            self._status_label.setText(format_status(True, '恢复成功'))
            set_label_severity(self._status_label, 'success')
            QMessageBox.information(self, '成功', '备份恢复成功！')
        else:
            self._status_label.setText(format_status(False, '恢复失败'))
            set_label_severity(self._status_label, 'error')
            detail = f'\n\n错误信息：{error_msg}' if error_msg else ''
            QMessageBox.critical(self, '错误', f'恢复失败，请确认备份文件有效且主密码正确。{detail}')

    def _on_restore_error(self, error_msg: str):
        self._set_busy(False)
        release_worker(self)
        self._status_label.setText(format_status(False, '恢复失败'))
        self._status_label.setStyleSheet(f'color: {c("danger")};')
        QMessageBox.critical(self, '错误', f'恢复失败：{error_msg}')

    def _purge_restore_points(self):
        """手动清理恢复前自动创建的安全快照，收缩已删除条目的明文泄漏面。"""
        reply = QMessageBox.question(
            self, '清理恢复点',
            '将删除所有恢复前自动创建的安全快照（pre_restore_*.cbox）。\n'
            '这些快照含恢复前的条目明文，清理可收缩泄漏面。\n\n'
            '确定继续吗？',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        count = self._backup_mgr.clear_restore_points()
        self._update_purge_button()
        if count:
            QMessageBox.information(self, '完成', f'已清理 {count} 个恢复点。')
        else:
            QMessageBox.information(self, '完成', '当前没有可清理的恢复点。')
