"""限时加密共享包创建对话框。

选中条目经共享密码 AES-256-GCM 加密为 ``.cboxshare`` + 随包生成的 ``decrypt.html`` 自包含
浏览器解密器。共享密码与条目明文均不出本机；接收方凭共享密码在浏览器本地解密，无需安装
CipherBox、无需联网。后台 worker 执行加密打包，无 vault 写入副作用，可安全取消。
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import cast

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QButtonGroup,
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
    QWidget,
)

from ...business.services.password_service import PasswordService
from ...business.services.share.package import EXPIRE_NEVER, create_share_package
from ...models import Entry
from ..components.widgets import (
    WorkerBackedDialog,
    create_cancel_button,
    create_password_toggle_btn,
    finalize_worker_if_current,
    set_label_severity,
    setup_dialog_flags,
    update_strength_label,
)
from ..components.workers import BackgroundWorker
from ..resources.constants import (
    BTN_DIALOG,
    BTN_DIALOG_WIDE,
    DIALOG_SHARE_MIN_SIZE,
    PWD_TOGGLE_AUTO_HIDE_SECONDS,
)
from ..resources.icons import GENERATE, set_icon_with_text
from ..resources.strings import DLG_TITLE_INFO, DLG_TITLE_SUCCESS
from ..resources.theme_colors import c

# 过期预设：(显示名, 相对秒数)；offset=0 表示永不过期（EXPIRE_NEVER）。
_EXPIRY_OPTIONS: list[tuple[str, int]] = [
    ("1 小时", 3600),
    ("24 小时", 86400),
    ("7 天", 604800),
    ("30 天", 2592000),
    ("永不", 0),
]


def open_share_package_dialog(entry: Entry, parent: QWidget) -> None:
    """校验条目完整性并打开共享包创建对话框。

    完整性异常条目禁止分享：其部分字段无法解密，强行打包会泄漏损坏数据或致接收方
    解密失败。统一经此入口开对话框，消除各调用点（菜单/右键）的文案漂移。
    """
    if entry.integrity_error:
        QMessageBox.critical(
            parent,
            "数据完整性异常",
            f"该条目的以下字段无法解密：{entry.integrity_message}。\n\n"
            "当前无法创建共享包，请先创建备份并检查数据文件。",
        )
        return
    dialog = SharePackageDialog(entry, parent=parent)
    dialog.exec()
    dialog.deleteLater()


class SharePackageDialog(WorkerBackedDialog):
    """限时加密共享包创建对话框。"""

    # 收窄基类声明（QLabel | None → QLabel / QPushButton）：_setup_ui 构造期赋值。
    _status_label: QLabel
    _browse_btn: QPushButton
    _generate_btn: QPushButton

    def __init__(self, entry: Entry, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._entry = entry
        self._selected_dir: str | None = None
        self._setup_ui()

    def _cancel_on_close(self) -> bool:
        # 创建共享包无 vault 写入副作用，可安全取消。
        return True

    def _set_busy(self, busy: bool) -> None:
        # 覆写基类：运行期额外锁禁用密码/有效期/含密码/路径控件，防止运行中切换致
        # UI 与已启动 worker 实际参数漂移。
        super()._set_busy(busy)
        enabled = not busy
        self._browse_btn.setEnabled(enabled)
        self._generate_btn.setEnabled(enabled)
        self._pwd_edit.setEnabled(enabled)
        self._pwd_toggle.setEnabled(enabled)
        self._confirm_edit.setEnabled(enabled)
        self._expiry_combo.setEnabled(enabled)
        for btn in self._secrets_group.buttons():
            btn.setEnabled(enabled)

    def _setup_ui(self) -> None:
        self.setWindowTitle("创建共享包")
        self.setMinimumSize(*DIALOG_SHARE_MIN_SIZE)
        setup_dialog_flags(self)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        # _build_* 分块构建（MAINT-094，对齐 entry_dialog 模式）：条目预览 → 共享密码 →
        # 有效期/含密码 → 输出目录 → 状态 → 按钮行，纯机械搬移不改控件树与行为。
        layout.addWidget(self._build_preview_group())
        layout.addWidget(self._build_password_group())
        layout.addLayout(self._build_options_row())
        layout.addLayout(self._build_output_row())
        self._build_status_label(layout)
        layout.addStretch()
        layout.addLayout(self._build_buttons())

    def _build_preview_group(self) -> QGroupBox:
        """构建待共享条目预览（只读标题列表）。"""
        preview_group = QGroupBox("待共享条目")
        preview_layout = QVBoxLayout(preview_group)
        self._entry_list = QListWidget()
        self._entry_list.setSelectionMode(QListWidget.SelectionMode.NoSelection)
        self._entry_list.addItem(self._entry.title or "(无标题)")
        self._entry_list.setFixedHeight(96)
        preview_layout.addWidget(self._entry_list)
        return preview_group

    def _build_password_group(self) -> QGroupBox:
        """构建共享密码分组：输入/生成行、强度、确认与提示。"""
        pwd_group = QGroupBox("共享密码")
        pwd_layout = QVBoxLayout(pwd_group)

        pwd_row = QHBoxLayout()
        self._pwd_edit = QLineEdit()
        self._pwd_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._pwd_edit.setPlaceholderText("接收方需凭此密码解密")
        pwd_row.addWidget(self._pwd_edit, 1)
        self._pwd_toggle = create_password_toggle_btn(
            self._pwd_edit, auto_hide_seconds=PWD_TOGGLE_AUTO_HIDE_SECONDS
        )
        pwd_row.addWidget(self._pwd_toggle)
        self._generate_btn = QPushButton()
        set_icon_with_text(self._generate_btn, "生成", GENERATE)
        self._generate_btn.setFixedSize(*BTN_DIALOG)
        self._generate_btn.clicked.connect(self._generate_password)
        pwd_row.addWidget(self._generate_btn)
        pwd_layout.addLayout(pwd_row)

        self._strength_label = QLabel("")
        pwd_layout.addWidget(self._strength_label)
        self._pwd_edit.textChanged.connect(self._update_strength)

        confirm_row = QHBoxLayout()
        confirm_row.addWidget(QLabel("确认："))
        self._confirm_edit = QLineEdit()
        self._confirm_edit.setEchoMode(QLineEdit.EchoMode.Password)
        confirm_row.addWidget(self._confirm_edit, 1)
        pwd_layout.addLayout(confirm_row)

        hint = QLabel("共享密码请经独立渠道（短信/口述）发送，切勿与共享包一同发送。")
        hint.setStyleSheet(f"color: {c('warning_orange')}; font-size: 12px;")
        hint.setWordWrap(True)
        pwd_layout.addWidget(hint)
        return pwd_group

    def _build_options_row(self) -> QHBoxLayout:
        """构建有效期下拉与含密码单选行。"""
        opt_row = QHBoxLayout()
        opt_row.addWidget(QLabel("有效期："))
        self._expiry_combo = QComboBox()
        for name, _offset in _EXPIRY_OPTIONS:
            self._expiry_combo.addItem(name)
        self._expiry_combo.setCurrentIndex(1)  # 默认 24 小时
        opt_row.addWidget(self._expiry_combo)
        opt_row.addSpacing(20)
        self._secrets_group = QButtonGroup(self)
        self._include_radio = QRadioButton("含密码")
        self._include_radio.setChecked(True)
        self._exclude_radio = QRadioButton("不含密码")
        self._secrets_group.addButton(self._include_radio, 1)
        self._secrets_group.addButton(self._exclude_radio, 0)
        opt_row.addWidget(self._include_radio)
        opt_row.addWidget(self._exclude_radio)
        opt_row.addStretch()
        return opt_row

    def _build_output_row(self) -> QHBoxLayout:
        """构建输出目录选择行。"""
        dir_row = QHBoxLayout()
        dir_row.addWidget(QLabel("输出目录："))
        self._dir_label = QLabel("未选择")
        self._dir_label.setStyleSheet(f"color: {c('text_muted')};")
        self._dir_label.setWordWrap(True)
        dir_row.addWidget(self._dir_label, 1)
        self._browse_btn = QPushButton("浏览...")
        self._browse_btn.clicked.connect(self._browse_dir)
        dir_row.addWidget(self._browse_btn)
        return dir_row

    def _build_status_label(self, layout: QVBoxLayout) -> None:
        """构建居中状态标签。"""
        self._status_label = QLabel("")
        self._status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status_label.setObjectName("formStatus")
        layout.addWidget(self._status_label)

    def _build_buttons(self) -> QHBoxLayout:
        """构建取消与创建共享包按钮行。"""
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        btn_row.addWidget(create_cancel_button(self))
        self._create_btn = QPushButton("创建共享包")
        self._create_btn.setObjectName("primaryBtn")
        self._create_btn.setFixedSize(*BTN_DIALOG_WIDE)
        self._create_btn.clicked.connect(self._execute)
        # 经基类 _set_busy 统一禁用/启用主操作按钮
        self._primary_action_btn = self._create_btn
        btn_row.addWidget(self._create_btn)
        return btn_row

    def _update_strength(self, text: str) -> None:
        update_strength_label(self._strength_label, text)

    def _generate_password(self) -> None:
        pwd = PasswordService.generate(length=20)
        self._pwd_edit.setText(pwd)
        self._confirm_edit.setText(pwd)
        # 生成后显示明文供用户记录，按 auto_hide 秒数自动重新隐藏。
        self._pwd_toggle.show_password()

    def _browse_dir(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "选择共享包输出目录")
        if path:
            self._selected_dir = path
            self._dir_label.setText(path)
            self._dir_label.setStyleSheet(f"color: {c('text_primary')};")

    def _execute(self) -> None:
        password = self._pwd_edit.text()
        # 共享密码预校验与业务层 create_share_package 对齐（QL-028）：统一经
        # PasswordService.validate_master_password（≥15 字符 + 强度检查）预检，
        # 替代旧的本地 8 字符门禁——8-14 位密码过旧门禁后到 worker 才抛
        # ShareError，两端口径不一；与 backup_dialog 的预校验范式一致。
        valid, error = PasswordService.validate_master_password(password, label="共享密码")
        if not valid:
            QMessageBox.warning(self, DLG_TITLE_INFO, error)
            return
        confirm = self._confirm_edit.text()
        # 常量时间比较经 PasswordService.passwords_match 统一门面（SEC-031）：
        # encode('utf-8') 与 compare_digest 的配对不再由各调用点内联维护，防 QL-019
        # 同型 bug（非 ASCII 共享密码抛 TypeError 被槽吞掉致创建静默失败）复发。
        if not PasswordService.passwords_match(confirm, password):
            QMessageBox.warning(self, DLG_TITLE_INFO, "两次输入的共享密码不一致。")
            return
        selected_dir = self._selected_dir
        if not selected_dir:
            QMessageBox.warning(self, DLG_TITLE_INFO, "请先选择输出目录。")
            return

        include_secrets = self._include_radio.isChecked()
        expire_at = self._compute_expire_at()
        self._set_busy(True)

        def _create(pwd: str = password) -> object:
            # worker 是下方赋值的自由变量，闭包延迟绑定；默认参数 pwd 在定义时拷贝
            # password，下方 del 局部 password 不影响 worker。
            return create_share_package(
                [self._entry],
                pwd,
                include_secrets=include_secrets,
                expire_at=expire_at,
                output_dir=selected_dir,
                cancel_check=worker.cancel_check,
            )

        worker = BackgroundWorker(_create, parent=self)
        self._worker = worker
        worker.finished.connect(self._on_done)
        worker.cancelled.connect(self._on_cancelled)
        worker.error.connect(self._on_error)
        worker.start()
        del password

    def _compute_expire_at(self, *, now: int | None = None) -> int:
        _name, offset = _EXPIRY_OPTIONS[self._expiry_combo.currentIndex()]
        if offset == 0:
            return EXPIRE_NEVER
        current = now if now is not None else int(time.time())
        return current + offset

    def _on_done(self, result: object) -> None:
        if not finalize_worker_if_current(self):
            return
        self._set_busy(False)
        if result is None:
            self._status_label.setText("已取消")
            set_label_severity(self._status_label, "accent")
            return
        share_path, decrypt_path = cast(tuple[Path, Path], result)
        self._status_label.setText("共享包创建成功")
        set_label_severity(self._status_label, "success")
        QMessageBox.information(
            self,
            DLG_TITLE_SUCCESS,
            f"已生成两个文件：\n\n{share_path.name}\n{decrypt_path.name}\n\n"
            f"保存目录：{share_path.parent}\n\n"
            "请将这两个文件一起发送给接收方，并经独立渠道（短信/口述）告知共享密码。",
        )

    def _on_cancelled(self) -> None:
        if not finalize_worker_if_current(self):
            return
        self._set_busy(False)
        self._status_label.setText("已取消")
        set_label_severity(self._status_label, "accent")

    def _on_error(self, error_msg: str) -> None:
        self._report_worker_error(
            error_msg,
            status_text="创建失败",
            message=f"共享包创建失败：{error_msg}",
            log_message="共享包创建失败: %s",
        )

    def _after_release(self) -> None:
        # 关闭时清除密码输入，缩短明文驻留。
        self._pwd_edit.clear()
        self._confirm_edit.clear()
