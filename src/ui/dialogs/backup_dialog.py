"""备份与恢复对话框，提供加密备份的创建与还原。

备份采用独立密码派生密钥可跨主密码恢复；备份可安全取消，恢复有写入
副作用不可中途取消。worker 闭包捕获密码，结束后立即释放。
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, cast

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QShowEvent
from PyQt6.QtWidgets import (
    QButtonGroup,
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
    QWidget,
)

from ...business.services.password_service import PasswordService
from ...config import CFG_BACKUP_DIRECTORY
from ...exceptions import BackupError
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
    BTN_DIALOG_WIDE,
    DIALOG_BACKUP_MIN_SIZE,
)
from ..resources.strings import DLG_TITLE_ERROR, DLG_TITLE_INFO, DLG_TITLE_SUCCESS
from ..resources.theme_colors import c

if TYPE_CHECKING:
    from ...business.managers.backup_restore import BackupRestoreManager
    from ...config import ConfigManager

logger = logging.getLogger(__name__)


class BackupDialog(WorkerBackedDialog):
    """备份创建与恢复的统一对话框，按模式切换操作与文案。"""

    # 收窄基类声明（QLabel | None → QLabel）：`_setup_ui` 构造期赋值，运行时不为 None。
    _status_label: QLabel

    def __init__(
        self,
        backup_manager: BackupRestoreManager,
        parent: QWidget | None = None,
        config: ConfigManager | None = None,
    ) -> None:
        super().__init__(parent)
        self._backup = backup_manager
        self._config = config
        # 记录 `worker` 启动时的模式，避免 `reject` 时读取已切换的按钮状态
        self._worker_is_backup: bool = True
        self._selected_path: str | None = None
        self.data_changed: bool = False
        self._setup_ui()

    def _setup_ui(self) -> None:
        self.setWindowTitle("备份与恢复")
        self.setMinimumSize(*DIALOG_BACKUP_MIN_SIZE)
        setup_dialog_flags(self)

        layout = QVBoxLayout(self)
        layout.setSpacing(14)

        # 模式选择
        mode_group = QGroupBox("操作")
        mode_layout = QVBoxLayout(mode_group)
        self._btn_group = QButtonGroup(self)

        self._backup_radio = QRadioButton("创建加密备份")
        self._backup_radio.setChecked(True)
        self._btn_group.addButton(self._backup_radio, 0)
        mode_layout.addWidget(self._backup_radio)

        info1 = QLabel("  将保险库的全部数据加密保存到一个文件中")
        info1.setObjectName("formMuted")
        mode_layout.addWidget(info1)

        self._restore_radio = QRadioButton("从备份恢复")
        self._btn_group.addButton(self._restore_radio, 1)
        mode_layout.addWidget(self._restore_radio)

        # 去掉 ASCII [!]（屏幕阅读器会朗读该符号），用语义化 `objectName` 供 QSS 控制颜色
        info2 = QLabel("恢复将覆盖当前所有数据！请谨慎操作")
        info2.setObjectName("warningText")
        info2.setStyleSheet(f"color: {c('danger')}; font-size: 12px;")
        mode_layout.addWidget(info2)

        layout.addWidget(mode_group)

        # 文件选择
        file_group = QGroupBox("文件")
        file_layout = QHBoxLayout(file_group)
        self._path_label = QLabel("未选择")
        self._path_label.setStyleSheet(f"color: {c('text_muted')};")
        self._path_label.setWordWrap(True)
        file_layout.addWidget(self._path_label, 1)

        self._browse_btn = QPushButton("浏览...")
        self._browse_btn.clicked.connect(self._browse)
        file_layout.addWidget(self._browse_btn)
        layout.addWidget(file_group)

        # 状态
        self._status_label = QLabel("")
        self._status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status_label.setObjectName("formStatus")
        layout.addWidget(self._status_label)

        layout.addStretch()

        # 按钮
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        self._purge_btn = QPushButton("清理恢复点")
        self._purge_btn.setFixedSize(*BTN_DIALOG)
        self._purge_btn.clicked.connect(self._purge_restore_points)
        btn_layout.addWidget(self._purge_btn)

        btn_layout.addWidget(create_cancel_button(self))

        self._exec_btn = QPushButton("创建备份")
        self._exec_btn.setObjectName("primaryBtn")
        self._exec_btn.setFixedSize(*BTN_DIALOG_WIDE)
        self._exec_btn.clicked.connect(self._execute)
        # 经基类 `_set_busy` 统一禁用/启用主操作按钮
        self._primary_action_btn = self._exec_btn
        btn_layout.addWidget(self._exec_btn)

        layout.addLayout(btn_layout)

        self._btn_group.buttonClicked.connect(self._on_mode_changed)

    def showEvent(self, a0: QShowEvent | None) -> None:
        """对话框显示时按是否存在恢复点更新清理按钮可用性。"""
        super().showEvent(a0)
        self._update_purge_button()

    def _update_purge_button(self) -> None:
        """根据是否存在恢复前快照启用或禁用清理按钮。"""
        try:
            has_points = self._backup.restore_points.count() > 0
        except Exception:
            # 统计出错时保持可点，避免误锁功能；记录日志保留可审计痕迹
            logger.warning("统计恢复点数失败，保持清理按钮可点", exc_info=True)
            has_points = True
        self._purge_btn.setEnabled(has_points)

    def _cancel_on_close(self) -> bool:
        # 备份可安全取消，恢复有写入副作用仅等待完成不取消
        return self._worker_is_backup

    def _on_close_blocked(self) -> None:
        self._status_label.setText("恢复进行中，请等待完成后再关闭")

    def _set_busy(self, busy: bool) -> None:
        """busy 态除主操作按钮外，额外隔离 purge/浏览/模式切换控件。

        purge 不持 `vault_write_lock`，与恢复（持锁创建 `pre_restore` 安全网快照）并发可能
        删除正在创建的回滚快照，令恢复失败后失去回滚安全网；浏览/模式切换会改进行中
        操作的路径与目标。恢复时 purge 按 `has_points` 重算启用态（而非简单反相 busy）。
        """
        super()._set_busy(busy)
        self._browse_btn.setEnabled(not busy)
        # `QButtonGroup` 无 `setEnabled`（非 `QWidget`），逐个按钮隔离模式切换
        for btn in self._btn_group.buttons():
            btn.setEnabled(not busy)
        if busy:
            self._purge_btn.setEnabled(False)
        else:
            self._update_purge_button()

    def _on_mode_changed(self) -> None:
        is_backup = self._btn_group.checkedId() == 0
        self._exec_btn.setText("创建备份" if is_backup else "恢复数据")
        self._selected_path = None
        self._path_label.setText("未选择")
        self._path_label.setStyleSheet(f"color: {c('text_muted')};")
        # 清除上一操作的残留状态文案与 severity 颜色，避免新操作起步时仍显示旧结果。
        self._status_label.setText("")
        set_label_severity(self._status_label, "accent")

    def _browse(self) -> None:
        is_backup = self._btn_group.checkedId() == 0
        backup_filter = f"CipherBox 备份 (*{self._backup.BACKUP_EXT})"
        if is_backup:
            initial_dir = self._config.get(CFG_BACKUP_DIRECTORY, "") if self._config else ""
            default_name = f"cipherbox_backup{self._backup.BACKUP_EXT}"
            initial_path = str(Path(initial_dir) / default_name) if initial_dir else default_name
            path, _ = QFileDialog.getSaveFileName(
                self,
                "选择备份保存路径",
                initial_path,
                backup_filter,
            )
        else:
            path, _ = QFileDialog.getOpenFileName(
                self,
                "选择备份文件",
                "",
                f"{backup_filter};;所有文件 (*.*)",
            )
        if path:
            self._selected_path = path
            self._path_label.setText(path)
            self._path_label.setStyleSheet(f"color: {c('text_primary')};")

    def _execute(self) -> None:
        if not self._selected_path:
            QMessageBox.warning(self, DLG_TITLE_INFO, "请先选择文件")
            return

        is_backup = self._btn_group.checkedId() == 0

        if is_backup:
            self._do_backup(self._selected_path)
        else:
            self._do_restore(self._selected_path)

    def _do_backup(self, path: str) -> None:
        """收集备份密码并启动后台创建任务（无写入副作用，可安全取消）。

        密码经独立输入与二次确认；`worker` 闭包以默认参数拷贝密码，启动后立即 `del`
        局部引用，最终释放由 `release_worker` 完成。
        """
        password, ok = QInputDialog.getText(
            self,
            "设置备份密码",
            "请输入独立备份密码。恢复时必须使用该密码：",
            QLineEdit.EchoMode.Password,
        )
        if not ok:
            return
        valid, error = PasswordService.validate_master_password(password, label="备份密码")
        if not valid:
            QMessageBox.warning(self, "备份密码不安全", error)
            return
        confirm, ok = QInputDialog.getText(
            self,
            "确认备份密码",
            "请再次输入备份密码：",
            QLineEdit.EchoMode.Password,
        )
        # 常量时间比较经 PasswordService.passwords_match 统一门面（SEC-031）：
        # encode('utf-8') 与 compare_digest 的配对不再由各调用点内联维护，防 QL-019
        # 同型 bug（非 ASCII 备份密码抛 TypeError 被 Qt 槽吞掉致加密静默失败）复发。
        if not ok or not PasswordService.passwords_match(confirm, password):
            QMessageBox.warning(self, "密码不一致", "两次输入的备份密码不一致。")
            return
        self._set_busy(True)
        self._worker_is_backup = True

        def _run(pwd: str = password) -> tuple[bool, str]:
            # `worker` 是下方赋值的自由变量，闭包延迟绑定（`_run` 在 `worker.run` 时执行）；
            # 默认参数 pwd 在定义时拷贝 password，下方 del 局部 password 不影响 `worker`。
            return self._backup.create_backup(
                path,
                pwd,
                cancel_check=worker.cancel_check,
            )

        worker = BackgroundWorker(_run, parent=self)
        self._worker = worker
        worker.finished.connect(self._on_backup_done)
        worker.error.connect(self._on_backup_error)
        worker.start()
        # 删除局部 password 仅缩短局部引用；真正释放需等 `worker` 结束由 `release_worker` 完成
        # （`_run` 默认参数已拷贝 password，del 不影响 `worker`）。
        del password

    def _on_backup_done(self, result: object) -> None:
        if not finalize_worker_if_current(self):
            return
        self._set_busy(False)
        success, error_msg = cast(tuple[bool, str], result)
        if success:
            self.data_changed = True
            self._status_label.setText("备份创建成功")
            set_label_severity(self._status_label, "success")
            QMessageBox.information(
                self, DLG_TITLE_SUCCESS, f"备份已保存到：\n{self._path_label.text()}"
            )
        else:
            self._status_label.setText("备份失败")
            set_label_severity(self._status_label, "error")
            msg = (
                f"备份创建失败：{error_msg}"
                if error_msg
                else "备份创建失败，请检查文件路径和磁盘空间。"
            )
            QMessageBox.critical(self, DLG_TITLE_ERROR, msg)

    def _on_backup_error(self, error_msg: str) -> None:
        self._report_worker_error(
            error_msg,
            status_text="备份失败",
            message=f"备份创建失败：{error_msg}",
        )

    def _do_restore(self, path: str) -> None:
        """启动后台恢复任务（有写入副作用，不可中途取消）。

        先经 `inspect_backup` 探测是否需要密码；恢复覆盖全部数据，回滚安全网快照
        （`pre_restore_*.cbox`）由 business 层在持锁事务内创建。
        """
        reply = QMessageBox.warning(
            self,
            "危险操作",
            "恢复备份将覆盖当前保险库中的所有数据！\n\n此操作不可撤销！\n\n确定要继续吗？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            info = self._backup.inspect_backup(path)
        except (OSError, BackupError) as exc:
            # 不含裸 `ValueError`：`PayloadTooLargeError` 等领域异常是 `BackupError` 子类，
            # 裸 `ValueError` 会先于 `BackupError` 吞掉它们（多重继承陷阱）。
            QMessageBox.critical(self, DLG_TITLE_ERROR, str(exc))
            return
        password = None
        if info.get("password_required"):
            password, ok = QInputDialog.getText(
                self,
                "输入备份密码",
                "请输入创建该备份时设置的密码：",
                QLineEdit.EchoMode.Password,
            )
            if not ok:
                return
        self._set_busy(True)
        self._worker_is_backup = False

        def _run(pwd: str | None = password) -> object:
            return self._backup.restore_backup(path, pwd)

        self._worker = BackgroundWorker(_run, parent=self)
        self._worker.finished.connect(self._on_restore_done)
        self._worker.error.connect(self._on_restore_error)
        self._worker.start()
        # 删除局部 password 仅缩短局部引用，与 `_do_backup` 对齐。
        del password

    def _on_restore_done(self, result: object) -> None:
        if not finalize_worker_if_current(self):
            return
        self._set_busy(False)
        success, error_msg = cast(tuple[bool, str], result)
        if success:
            self.data_changed = True
            self._status_label.setText("恢复成功")
            set_label_severity(self._status_label, "success")
            QMessageBox.information(self, DLG_TITLE_SUCCESS, "备份恢复成功！")
        else:
            self._status_label.setText("恢复失败")
            set_label_severity(self._status_label, "error")
            detail = f"\n\n错误信息：{error_msg}" if error_msg else ""
            QMessageBox.critical(
                self, DLG_TITLE_ERROR, f"恢复失败，请确认备份文件有效且主密码正确。{detail}"
            )

    def _on_restore_error(self, error_msg: str) -> None:
        self._report_worker_error(
            error_msg,
            status_text="恢复失败",
            message=f"恢复失败：{error_msg}",
        )

    def _purge_restore_points(self) -> None:
        """手动清理恢复前自动创建的安全快照，收缩已删除条目的明文泄漏面。"""
        reply = QMessageBox.question(
            self,
            "清理恢复点",
            "将删除所有恢复前自动创建的安全快照（pre_restore_*.cbox）。\n"
            "这些快照含恢复前的条目明文，清理可收缩泄漏面。\n\n"
            "确定继续吗？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        count = self._backup.restore_points.clear_all()
        self._update_purge_button()
        if count:
            QMessageBox.information(self, "完成", f"已清理 {count} 个恢复点。")
        else:
            QMessageBox.information(self, "完成", "当前没有可清理的恢复点。")
