"""导入导出对话框，支持多格式数据的导入与导出。

导入支持 CipherBox JSON、CSV 以及 Chrome、Bitwarden、KeePass 等外部格式，
导出支持 JSON 与 CSV。耗时的导入导出在后台线程执行，避免阻塞 UI。
导入涉及数据库写入且不可中途取消，导出无副作用可安全取消。导出文件
统一加做权限收紧处理。
"""

import logging
from pathlib import Path

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QButtonGroup,
    QComboBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
    QWidget,
)

from ...utils.file_security import secure_file
from ..components.widgets import (
    format_status,
    release_worker,
    set_label_severity,
    setup_dialog_flags,
)
from ..components.workers import BackgroundWorker, wait_worker_shutdown
from ..resources.constants import (
    BTN_DIALOG,
    DIALOG_IMPORT_EXPORT_MIN_SIZE,
)
from ..resources.theme_colors import c

logger = logging.getLogger(__name__)

# 支持的导入导出格式定义
_EXPORT_FORMATS = ['JSON', 'CSV']
_IMPORT_FILTERS = {
    'JSON (CipherBox)':  ('JSON 文件 (*.json)', 'cipherbox_import.json'),
    'CSV':               ('CSV 文件 (*.csv)', 'import.csv'),
    'Chrome / Edge CSV': ('CSV 文件 (*.csv)', 'chrome_import.csv'),
    'Bitwarden JSON':    ('JSON 文件 (*.json)', 'bitwarden_import.json'),
    'KeePass CSV':       ('CSV 文件 (*.csv)', 'keepass_import.csv'),
}
_IMPORT_FORMATS = list(_IMPORT_FILTERS.keys())


class ImportExportDialog(QDialog):
    """导入与导出统一对话框，按模式切换可见选项与可用格式。"""

    import_completed = pyqtSignal()

    _IMPORT_HANDLERS = {
        'JSON (CipherBox)': 'import_from_json',
        'CSV': 'import_from_csv',
        'Chrome / Edge CSV': 'import_from_chrome_csv',
        'Bitwarden JSON': 'import_from_bitwarden_json',
        'KeePass CSV': 'import_from_keepass_csv',
    }

    def __init__(self, import_export_manager, entry_manager, parent=None):
        super().__init__(parent)
        self._import_export = import_export_manager
        self._entry_mgr = entry_manager
        self._is_export = True
        self._worker = None
        # 记录 worker 启动时的模式，避免 reject 时读取已被切换的按钮状态
        self._worker_is_export: bool = True
        self._selected_path: str | None = None
        self._setup_ui()

    def closeEvent(self, a0):
        # 导入 worker 运行时拒绝关闭，避免 QThread 销毁警告与数据不一致
        if a0 is not None and self._worker and self._worker.isRunning() and not self._worker_is_export:
            self._status_label.setText('导入进行中，请等待完成后再关闭')
            a0.ignore()
            return
        super().closeEvent(a0)

    def reject(self):
        """关闭对话框前等待后台 worker 完成。

        导入操作有数据库写入副作用，不取消 worker 以确保数据一致性；
        导出操作无副作用，可安全取消。
        """
        # 导出可安全取消，导入有写入副作用仅等待完成
        wait_worker_shutdown(self._worker, cancel=self._worker_is_export)
        release_worker(self)
        super().reject()

    def _setup_ui(self):
        self.setWindowTitle('导入 / 导出')
        self.setMinimumSize(*DIALOG_IMPORT_EXPORT_MIN_SIZE)
        setup_dialog_flags(self)

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

        # 密码选项仅在导出模式下可见
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
        self._status_label.setObjectName('formStatus')
        layout.addWidget(self._status_label)

        layout.addStretch()

        # 按钮
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        cancel_btn = QPushButton('取消')
        cancel_btn.setFixedSize(*BTN_DIALOG)
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)

        self._action_btn = QPushButton('导出')
        self._action_btn.setObjectName('primaryBtn')
        self._action_btn.setFixedSize(*BTN_DIALOG)
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
        self._selected_path = None
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
            self._selected_path = path
            self._path_edit.setText(path)
            self._path_edit.setStyleSheet(f'color: {c("text_primary")};')

    def _execute(self):
        if not self._selected_path:
            QMessageBox.warning(self, '提示', '请先选择文件')
            return

        if self._is_export:
            self._do_export(self._selected_path)
        else:
            self._do_import(self._selected_path)

    def _set_busy(self, busy: bool):
        """设置操作进行中状态。"""
        self._action_btn.setEnabled(not busy)
        if busy:
            self._status_label.setText('处理中...')
            set_label_severity(self._status_label, 'accent')
        else:
            self._status_label.setText('')

    def _do_export(self, path: str):
        include_pwd = self._include_pwd_check.isChecked()
        fmt = self._format_combo.currentText()

        if include_pwd:
            reply = QMessageBox.warning(
                self, '安全警告',
                '您选择导出包含密码的文件！\n\n'
                '导出的文件将以明文形式保存所有密码，存在严重的安全风险。\n'
                '请确保妥善保管导出文件，使用后立即删除。\n\n'
                '确定要继续吗？',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
        else:
            reply = QMessageBox.information(
                self, '安全提示',
                '导出文件包含标题、账号等敏感信息（不含密码）。\n'
                '请妥善保管导出文件，使用后及时删除。\n\n'
                '确定要继续吗？',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return

        self._set_busy(True)

        worker_holder: list[BackgroundWorker] = []

        def _export_task():
            worker = worker_holder[0]
            cancel_check = lambda: worker.is_cancelled
            entries = self._entry_mgr.get_entries_for_export(
                include_pwd, cancel_check=cancel_check,
            )
            if worker.is_cancelled:
                return 0
            if fmt == 'JSON':
                self._import_export.export_to_json(
                    path, entries, include_pwd, cancel_check=cancel_check,
                )
            else:
                self._import_export.export_to_csv(
                    path, entries, include_pwd, cancel_check=cancel_check,
                )
            return len(entries)

        self._worker_is_export = True
        self._worker = BackgroundWorker(_export_task, parent=self)
        worker_holder.append(self._worker)
        self._worker.finished.connect(self._on_export_done)
        self._worker.error.connect(self._on_export_error)
        self._worker.start()

    def _on_export_done(self, count):
        if self.sender() is not self._worker:
            return
        # 在 release_worker 前采样取消状态：取消时 export_to_json/csv 内部已清理
        # temp 文件（未 os.replace），目标文件未生成/未更新，不应报「成功导出」
        # 以免误导用户以为导出成功而留下空/损坏的明文文件。
        # 守卫 `sender() is not self._worker` 已保证 self._worker 非 None；
        # `is not None` 同时收窄类型满足静态检查。
        cancelled = self._worker is not None and self._worker.is_cancelled
        release_worker(self)
        self._set_busy(False)
        self._progress.hide()
        if cancelled:
            self._status_label.setText('导出已取消')
            set_label_severity(self._status_label, 'accent')
            return
        # 防御性加保：即使业务层已对导出文件调用 secure_file，UI 层仍
        # 再次收紧权限。使用 _selected_path 而非文本框内容判空，避免
        # 用户编辑文本框导致路径不可靠。
        path = self._selected_path
        perm_warning = False
        if path:
            try:
                secure_file(Path(path), strict=True)
            except OSError:
                logger.warning("导出文件权限设置失败: %s", path)
                perm_warning = True
        message = f'成功导出 {count} 条记录'
        if perm_warning:
            # 导出文件（可能含明文密码）权限未能收紧，明确提示用户手动限制访问
            message += '（警告：文件权限未能收紧，建议手动限制该文件访问）'
        self._status_label.setText(format_status(True, message))
        set_label_severity(self._status_label, 'success')

    def _on_export_error(self, error_msg: str):
        if self.sender() is not self._worker:
            return
        release_worker(self)
        self._set_busy(False)
        self._progress.hide()
        logger.error("导出失败: %s", error_msg)
        self._status_label.setText(format_status(False, f'导出失败：{error_msg}'))
        set_label_severity(self._status_label, 'error')

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

        self._set_busy(True)

        self._worker_is_export = False
        # 进度条初始为不确定模式，收到首个 progress 信号后切换到确定范围
        self._progress.setRange(0, 0)
        self._progress.setValue(0)
        self._progress.show()

        worker_holder: list = []

        def _import_task():
            # worker_holder 解耦：闭包经 holder[0] 访问 worker，消除对
            # self._worker 赋值时序的依赖（原读 self._worker 依赖赋值先于 start，
            # 是脆弱的隐式契约）。同时取 cancel_check 使 reject() 真正中断导入循环。
            worker = worker_holder[0] if worker_holder else None
            progress_cb = worker.emit_progress if worker is not None else None
            # is_cancelled 是 @property 返回 bool，须包成 lambda 提供 Callable[[], bool]。
            cancel_check = (lambda: worker.is_cancelled if worker is not None else False) if worker is not None else None
            fmt_name = _IMPORT_FORMATS[fmt_index] if 0 <= fmt_index < len(_IMPORT_FORMATS) else ''
            method_name = self._IMPORT_HANDLERS.get(fmt_name)
            if method_name:
                handler = getattr(self._import_export, method_name)
                return handler(
                    path,
                    progress_callback=progress_cb,
                    duplicate_action=duplicate_action,
                    cancel_check=cancel_check,
                )
            return 0

        self._worker = BackgroundWorker(_import_task, parent=self)
        worker_holder.append(self._worker)
        self._worker.progress.connect(self._on_import_progress)
        self._worker.finished.connect(self._on_import_done)
        self._worker.error.connect(self._on_import_error)
        self._worker.start()

    def _on_import_progress(self, current: int, total: int):
        """导入进度回调：切换到确定范围并更新进度条。"""
        self._progress.setRange(0, total)
        self._progress.setValue(current)

    def _on_import_done(self, count):
        if self.sender() is not self._worker:
            return
        release_worker(self)
        self._set_busy(False)
        self._progress.hide()
        self._status_label.setText(format_status(True, f'成功导入 {count} 条记录'))
        set_label_severity(self._status_label, 'success')
        if count > 0:
            self.import_completed.emit()

    def _on_import_error(self, error_msg: str):
        if self.sender() is not self._worker:
            return
        release_worker(self)
        self._set_busy(False)
        self._progress.hide()
        logger.error("导入失败: %s", error_msg)
        self._status_label.setText(format_status(False, f'导入失败：{error_msg}'))
        set_label_severity(self._status_label, 'error')
