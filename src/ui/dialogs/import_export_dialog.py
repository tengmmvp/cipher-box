"""导入导出对话框，支持多格式数据的导入与导出。

耗时操作在后台线程执行；导入有写入副作用不可取消，导出可安全取消，
导出文件统一做权限收紧。
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QButtonGroup,
    QComboBox,
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
    WorkerBackedDialog,
    create_cancel_button,
    finalize_worker_if_current,
    set_label_severity,
    setup_dialog_flags,
)
from ..components.workers import BackgroundWorker
from ..resources.constants import (
    BTN_DIALOG,
    DIALOG_IMPORT_EXPORT_MIN_SIZE,
)
from ..resources.strings import DLG_TITLE_INFO
from ..resources.theme_colors import c

if TYPE_CHECKING:
    from ...business.managers.entry_manager import EntryManager
    from ...business.managers.import_export import ImportExportManager

logger = logging.getLogger(__name__)

_EXPORT_FORMATS = ["JSON", "CSV"]
_IMPORT_FILTERS = {
    "JSON (CipherBox)": ("JSON 文件 (*.json)", "cipherbox_import.json"),
    "CSV": ("CSV 文件 (*.csv)", "import.csv"),
    "Chrome / Edge CSV": ("CSV 文件 (*.csv)", "chrome_import.csv"),
    "Bitwarden JSON": ("JSON 文件 (*.json)", "bitwarden_import.json"),
    "KeePass CSV": ("CSV 文件 (*.csv)", "keepass_import.csv"),
}
_IMPORT_FORMATS = list(_IMPORT_FILTERS.keys())
# UI 格式名 → 业务层 import_file 的 format_key（单一 dispatch 入口）。
_IMPORT_FORMAT_KEYS = {
    "JSON (CipherBox)": "json",
    "CSV": "csv",
    "Chrome / Edge CSV": "chrome_csv",
    "Bitwarden JSON": "bitwarden_json",
    "KeePass CSV": "keepass_csv",
}


class ImportExportDialog(WorkerBackedDialog):
    """导入与导出统一对话框，按模式切换可见选项与可用格式。"""

    import_completed = pyqtSignal()

    # 收窄基类声明（QLabel | None → QLabel）：_setup_ui 构造期赋值，运行时不为 None。
    _status_label: QLabel
    _browse_btn: QPushButton  # 浏览按钮，_set_busy 运行期禁用

    def __init__(
        self,
        import_export_manager: ImportExportManager,
        entry_manager: EntryManager,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._import_export = import_export_manager
        self._entry_mgr = entry_manager
        self._is_export = True
        # 记录 worker 启动时的模式，避免 reject 时读取已被切换的按钮状态
        self._worker_is_export: bool = True
        self._selected_path: str | None = None
        self._setup_ui()

    def _cancel_on_close(self) -> bool:
        # 导入有写入副作用仅等待完成不取消，导出无副作用可安全取消
        return self._worker_is_export

    def _on_close_blocked(self) -> None:
        self._status_label.setText("导入进行中，请等待完成后再关闭")

    def _set_busy(self, busy: bool) -> None:
        # 覆写基类：运行期间额外锁禁用模式/格式/重复项/密码选项/路径选择，防止用户切换
        # 模式致 UI 与已启动 worker 实际操作漂移（切到导出却看到导入结果文案）。
        super()._set_busy(busy)
        enabled = not busy
        for btn in self._mode_group.buttons():
            btn.setEnabled(enabled)
        self._format_combo.setEnabled(enabled)
        self._duplicate_combo.setEnabled(enabled)
        self._password_container.setEnabled(enabled)
        self._browse_btn.setEnabled(enabled)

    def _setup_ui(self) -> None:
        self.setWindowTitle("导入 / 导出")
        self.setMinimumSize(*DIALOG_IMPORT_EXPORT_MIN_SIZE)
        setup_dialog_flags(self)

        layout = QVBoxLayout(self)
        layout.setSpacing(14)

        # 模式选择
        mode_layout = QHBoxLayout()
        self._mode_group = QButtonGroup(self)

        export_radio = QRadioButton("导出")
        export_radio.setChecked(True)
        self._mode_group.addButton(export_radio, 0)
        mode_layout.addWidget(export_radio)

        import_radio = QRadioButton("导入")
        self._mode_group.addButton(import_radio, 1)
        mode_layout.addWidget(import_radio)

        mode_layout.addStretch()
        layout.addLayout(mode_layout)

        self._mode_group.buttonClicked.connect(self._on_mode_changed)

        # 格式选择
        format_layout = QHBoxLayout()
        format_layout.addWidget(QLabel("格式："))
        self._format_combo = QComboBox()
        self._format_combo.addItems(_EXPORT_FORMATS)
        format_layout.addWidget(self._format_combo)
        format_layout.addStretch()
        layout.addLayout(format_layout)

        # 密码选项仅在导出模式下可见
        self._password_container = QWidget()
        pwd_layout = QHBoxLayout(self._password_container)
        pwd_layout.setContentsMargins(0, 0, 0, 0)
        self._include_pwd_radio = QRadioButton("包含密码")
        self._exclude_pwd_radio = QRadioButton("不包含密码")
        self._exclude_pwd_radio.setChecked(True)
        pwd_layout.addWidget(self._include_pwd_radio)
        pwd_layout.addWidget(self._exclude_pwd_radio)
        layout.addWidget(self._password_container)

        self._duplicate_container = QWidget()
        duplicate_layout = QHBoxLayout(self._duplicate_container)
        duplicate_layout.setContentsMargins(0, 0, 0, 0)
        duplicate_layout.addWidget(QLabel("重复项："))
        self._duplicate_combo = QComboBox()
        self._duplicate_combo.addItem("跳过已有条目", "skip")
        self._duplicate_combo.addItem("覆盖已有条目", "overwrite")
        self._duplicate_combo.addItem("仍然全部导入", "import_all")
        duplicate_layout.addWidget(self._duplicate_combo, 1)
        self._duplicate_container.hide()
        layout.addWidget(self._duplicate_container)

        # 文件路径
        path_layout = QHBoxLayout()
        self._file_label = QLabel("文件：")
        path_layout.addWidget(self._file_label)

        self._path_label = QLabel("未选择")
        self._path_label.setStyleSheet(f"color: {c('text_muted')};")
        self._path_label.setWordWrap(True)
        path_layout.addWidget(self._path_label, 1)

        self._browse_btn = QPushButton("浏览...")
        self._browse_btn.clicked.connect(self._browse_file)
        path_layout.addWidget(self._browse_btn)

        layout.addLayout(path_layout)

        # 进度
        self._progress = QProgressBar()
        self._progress.hide()
        layout.addWidget(self._progress)

        # 状态
        self._status_label = QLabel("")
        self._status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status_label.setObjectName("formStatus")
        layout.addWidget(self._status_label)

        layout.addStretch()

        # 按钮
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        btn_layout.addWidget(create_cancel_button(self))

        self._action_btn = QPushButton("导出")
        self._action_btn.setObjectName("primaryBtn")
        self._action_btn.setFixedSize(*BTN_DIALOG)
        self._action_btn.clicked.connect(self._execute)
        # 经基类 _set_busy 统一禁用/启用主操作按钮
        self._primary_action_btn = self._action_btn
        btn_layout.addWidget(self._action_btn)

        layout.addLayout(btn_layout)

    def _on_mode_changed(self) -> None:
        self._is_export = self._mode_group.checkedId() == 0
        self._password_container.setVisible(self._is_export)
        self._duplicate_container.setVisible(not self._is_export)
        self._action_btn.setText("导出" if self._is_export else "导入")

        # 切换格式下拉项（_format_combo 无信号连接，clear/addItems 不触发副作用）
        self._format_combo.clear()
        self._format_combo.addItems(_EXPORT_FORMATS if self._is_export else _IMPORT_FORMATS)

        # 重置文件选择
        self._selected_path = None
        self._path_label.setText("未选择")
        self._path_label.setStyleSheet(f"color: {c('text_muted')};")

    def _browse_file(self) -> None:
        if self._is_export:
            fmt = self._format_combo.currentText().lower()
            path, _ = QFileDialog.getSaveFileName(
                self,
                "选择导出路径",
                f"cipherbox_export.{fmt}",
                f"{fmt.upper()} 文件 (*.{fmt})",
            )
        else:
            fmt_name = self._format_combo.currentText()
            filter_str, default_name = _IMPORT_FILTERS.get(
                fmt_name, ("密码文件 (*.json *.csv)", "import.json")
            )
            path, _ = QFileDialog.getOpenFileName(
                self,
                "选择导入文件",
                default_name,
                filter_str,
            )
        if path:
            self._selected_path = path
            self._path_label.setText(path)
            self._path_label.setStyleSheet(f"color: {c('text_primary')};")

    def _execute(self) -> None:
        if not self._selected_path:
            QMessageBox.warning(self, DLG_TITLE_INFO, "请先选择文件")
            return

        if self._is_export:
            self._do_export(self._selected_path)
        else:
            self._do_import(self._selected_path)

    def _do_export(self, path: str) -> None:
        """启动后台导出任务（无写入副作用，可安全取消）。

        包含密码的导出先经二次确认警告明文风险；任务内采集与写入均传 cancel_check，
        取消时业务层清理 temp 文件且不生成目标文件。
        """
        include_pwd = self._include_pwd_radio.isChecked()
        fmt = self._format_combo.currentText()

        if include_pwd:
            reply = QMessageBox.warning(
                self,
                "安全警告",
                "您选择导出包含密码的文件！\n\n"
                "导出的文件将以明文形式保存所有密码，存在严重的安全风险。\n"
                "请确保妥善保管导出文件，使用后立即删除。\n\n"
                "确定要继续吗？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
        else:
            reply = QMessageBox.information(
                self,
                "安全提示",
                "导出文件包含标题、账号等敏感信息（不含密码）。\n"
                "请妥善保管导出文件，使用后及时删除。\n\n"
                "确定要继续吗？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return

        self._set_busy(True)

        def _export_task() -> int:
            # worker 是下方赋值的自由变量，闭包延迟绑定（_export_task 在 worker.run
            # 时执行，worker 已赋值）。
            entries = self._entry_mgr.get_entries_for_export(
                include_pwd,
                cancel_check=worker.cancel_check,
            )
            if worker.is_cancelled:
                return 0
            if fmt == "JSON":
                self._import_export.export_to_json(
                    path,
                    entries,
                    include_pwd,
                    cancel_check=worker.cancel_check,
                )
            else:
                self._import_export.export_to_csv(
                    path,
                    entries,
                    include_pwd,
                    cancel_check=worker.cancel_check,
                )
            return len(entries)

        self._worker_is_export = True
        worker = BackgroundWorker(_export_task, parent=self)
        self._worker = worker
        worker.finished.connect(self._on_export_done)
        worker.error.connect(self._on_export_error)
        # cancelled 监听（M8）：export 可取消，worker 取消时 emit cancelled 而非 finished
        # （见 workers.run 逻辑），_on_export_done 不会触发；原在 finished 回调内检查
        # is_cancelled 是永不命中的死代码。改由 cancelled 信号驱动 _on_export_cancelled。
        worker.cancelled.connect(self._on_export_cancelled)
        worker.start()

    def _on_export_done(self, count: int) -> None:
        if not finalize_worker_if_current(self):
            return
        self._set_busy(False)
        self._progress.hide()
        # 防御性加保：业务层已调用 secure_file，UI 层再次收紧权限。
        # 用 _selected_path 而非文本框内容判空，避免用户编辑导致路径不可靠。
        path = self._selected_path
        perm_warning = False
        if path:
            try:
                secure_file(Path(path), strict=True)
            except OSError:
                logger.warning("导出文件权限设置失败: %s", path)
                perm_warning = True
        message = f"成功导出 {count} 条记录"
        if perm_warning:
            # 导出文件（可能含明文密码）权限未能收紧，明确提示用户手动限制访问
            message += "（警告：文件权限未能收紧，建议手动限制该文件访问）"
        self._status_label.setText(message)
        set_label_severity(self._status_label, "success")

    def _on_export_cancelled(self) -> None:
        """导出取消的 UI 处理（M8）：worker emit cancelled 而非 finished 时触发。"""
        if not finalize_worker_if_current(self):
            return
        self._set_busy(False)
        self._progress.hide()
        self._status_label.setText("导出已取消")
        set_label_severity(self._status_label, "accent")

    def _on_export_error(self, error_msg: str) -> None:
        if not finalize_worker_if_current(self):
            return
        self._set_busy(False)
        self._progress.hide()
        logger.error("导出失败: %s", error_msg)
        self._status_label.setText(f"导出失败：{error_msg}")
        set_label_severity(self._status_label, "error")

    def _do_import(self, path: str) -> None:
        """启动后台导入任务（有写入副作用，不可中途取消）。

        UI 格式名经 _IMPORT_FORMAT_KEYS 映射到业务层 format_key；重复项处理策略经
        下拉选择传入；进度经 worker.progress 信号驱动不确定→确定进度条切换。
        """
        fmt_index = self._format_combo.currentIndex()
        duplicate_action = self._duplicate_combo.currentData() or "skip"

        reply = QMessageBox.question(
            self,
            "确认导入",
            "即将导入密码数据到保险库。\n\n"
            f"重复项处理：{self._duplicate_combo.currentText()}。\n\n"
            "确定要继续吗？",
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

        def _import_task() -> int:
            # worker 是下方赋值的自由变量，闭包延迟绑定。经 _IMPORT_FORMAT_KEYS
            # 映射到 format_key，调 import_file 单一 dispatch 入口。
            fmt_name = _IMPORT_FORMATS[fmt_index] if 0 <= fmt_index < len(_IMPORT_FORMATS) else ""
            format_key = _IMPORT_FORMAT_KEYS.get(fmt_name)
            if format_key is None:
                return 0
            return self._import_export.import_file(
                path,
                format_key,
                progress_callback=worker.emit_progress,
                duplicate_action=duplicate_action,
                cancel_check=worker.cancel_check,
            )

        worker = BackgroundWorker(_import_task, parent=self)
        self._worker = worker
        worker.progress.connect(self._on_import_progress)
        worker.finished.connect(self._on_import_done)
        worker.error.connect(self._on_import_error)
        worker.start()

    def _on_import_progress(self, current: int, total: int) -> None:
        """导入进度回调：切换到确定范围并更新进度条。"""
        self._progress.setRange(0, total)
        self._progress.setValue(current)

    def _on_import_done(self, count: int) -> None:
        if not finalize_worker_if_current(self):
            return
        self._set_busy(False)
        self._progress.hide()
        self._status_label.setText(f"成功导入 {count} 条记录")
        set_label_severity(self._status_label, "success")
        if count > 0:
            self.import_completed.emit()

    def _on_import_error(self, error_msg: str) -> None:
        if not finalize_worker_if_current(self):
            return
        self._set_busy(False)
        self._progress.hide()
        logger.error("导入失败: %s", error_msg)
        self._status_label.setText(f"导入失败：{error_msg}")
        set_label_severity(self._status_label, "error")
