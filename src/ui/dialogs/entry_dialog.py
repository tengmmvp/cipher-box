"""条目编辑对话框，支持 5 种条目类型、TOTP 与自定义字段。

承载新增与编辑两套流程，按条目类型动态切换可见字段。专用字段以
类型前缀存入 custom_fields，与通用自定义字段统一序列化。涉及密码、
卡号、TOTP 密钥等敏感输入，保存或关闭时统一清除以缩短明文驻留时间。
"""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import TYPE_CHECKING, TypeVar

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtGui import QIntValidator
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ...business.services.card_validation import (
    validate_card_cvv,
    validate_card_expiry,
    validate_card_number,
)
from ...business.services.entry_type_schema import (
    ENTRY_TYPE_SCHEMAS,
    SpecialFieldSpec,
    all_special_fields_by_storage,
    get_schema,
)
from ...business.services.password_service import PasswordService
from ...config import (
    CFG_DEFAULT_DIGITS,
    CFG_DEFAULT_EXCLUDE_AMBIGUOUS,
    CFG_DEFAULT_LOWERCASE,
    CFG_DEFAULT_PASSWORD_LENGTH,
    CFG_DEFAULT_SYMBOLS,
    CFG_DEFAULT_UPPERCASE,
    CFG_PASSWORD_VISIBLE_SECONDS,
)
from ...exceptions import (
    DatabaseError,
    DecryptionError,
    EntryIntegrityError,
)
from ...models import (
    ENTRY_TYPE_LOGIN,
    MAX_FIELD_NOTES,
    MAX_FIELD_PASSWORD,
    MAX_FIELD_TAGS,
    MAX_FIELD_TITLE,
    MAX_FIELD_TOTP_SECRET,
    MAX_FIELD_URL,
    MAX_FIELD_USERNAME,
    Category,
    CustomField,
    Entry,
)
from ..components.custom_fields_editor import CustomFieldsEditor
from ..components.widgets import (
    create_cancel_button,
    create_icon_button,
    create_password_toggle_btn,
    setup_dialog_flags,
    update_strength_label,
)
from ..error_messages import to_user_message
from ..resources.constants import (
    BTN_DIALOG,
    BTN_SMALL_ACTION,
    DIALOG_ENTRY_MIN_SIZE,
    MAX_TAG_DISPLAY,
    PWD_GENERATE_LENGTH_DEFAULT,
    PWD_TOGGLE_AUTO_HIDE_SECONDS,
    PWD_VISIBLE_SECONDS_DEFAULT,
    SERVER_PORT_MAX,
    SERVER_PORT_MIN,
)
from ..resources.icons import GENERATE
from ..resources.strings import (
    DLG_TITLE_ERROR,
    DLG_TITLE_INFO,
    ENTRY_TYPE_LABELS,
    entry_type_icon,
)
from ..resources.theme_colors import c

if TYPE_CHECKING:
    from ...business.managers.entry_manager import EntryManager
    from ...config import ConfigManager

logger = logging.getLogger(__name__)

_T = TypeVar("_T")


# 条目类型 schema（专用字段 / 可见字段顺序）的单一事实源在 business 层
# entry_type_schema.py，本模块经 get_schema / ENTRY_TYPE_SCHEMAS 读取。


class EntryDialog(QDialog):
    """密码条目新增与编辑对话框。

    ``entry`` 为 None 时进入新增模式，否则编辑该条目。保存成功后
    发出 ``saved`` 信号并关闭对话框。
    """

    # 备注区域高度：默认紧凑，笔记类型切换为展开以提供更大编辑空间
    _NOTES_HEIGHT_DEFAULT = 100
    _NOTES_HEIGHT_EXPANDED = 300

    saved = pyqtSignal()

    def __init__(
        self,
        entry_manager: EntryManager,
        categories: list[Category],
        all_tags: list[str] | None = None,
        entry: Entry | None = None,
        parent: QWidget | None = None,
        config: ConfigManager | None = None,
    ):
        super().__init__(parent)
        self._entry_mgr = entry_manager
        self._categories = categories
        self._all_tags = all_tags or []
        self._entry = entry
        self._config = config
        self._field_rows: dict[str, tuple[QLabel, QWidget]] = {}
        # 专用字段按控件类型分类存储：combo → _special_combos，其余（QLineEdit）→
        # _special_edits。键→类型映射由存储侧归类保证，使后续访问无需 cast。
        self._special_edits: dict[str, QLineEdit] = {}
        self._special_combos: dict[str, QComboBox] = {}

        self._setup_ui()
        if entry:
            self._load_entry(entry)

    # ------------------------------------------------------------------
    # UI 构建
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        self.setWindowTitle("编辑条目" if self._entry else "新增条目")
        self.setMinimumSize(*DIALOG_ENTRY_MIN_SIZE)
        setup_dialog_flags(self)

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setSpacing(12)

        self._build_type_selector(layout)
        layout.addLayout(self._build_form())
        layout.addWidget(self._build_totp_group())
        layout.addWidget(self._build_notes_group())
        layout.addWidget(self._build_custom_fields_group())
        layout.addLayout(self._build_buttons())

        scroll.setWidget(container)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(scroll)

        initial_type = self._entry.entry_type if self._entry else ENTRY_TYPE_LOGIN
        initial_index = self._type_combo.findData(initial_type)
        self._type_combo.blockSignals(True)
        self._type_combo.setCurrentIndex(max(0, initial_index))
        self._type_combo.blockSignals(False)
        self._current_type = initial_type
        self._apply_type_visibility(initial_type)

    def _build_type_selector(self, layout: QVBoxLayout) -> None:
        """构建类型选择行。"""
        type_row = QHBoxLayout()
        type_label = QLabel("类型：")
        type_label.setObjectName("fieldLabel")
        type_row.addWidget(type_label)

        self._type_combo = QComboBox()
        # 展示查表移 UI 层（ARCH-037）：label/icon 单一事实源在 strings.py，遍历其
        # 插入序保持原下拉顺序（models.ENTRY_TYPES 已收敛为无序类型键集合）。
        for key, label in ENTRY_TYPE_LABELS.items():
            self._type_combo.addItem(f"{entry_type_icon(key)} {label}", key)
        self._type_combo.currentIndexChanged.connect(self._on_type_changed)
        type_row.addWidget(self._type_combo, 1)
        layout.addLayout(type_row)

    def _build_form(self) -> QFormLayout:
        """构建通用字段、类型专用字段与公共尾部字段的表单。"""
        form = QFormLayout()
        form.setSpacing(10)

        # --- 通用字段 ---
        self._title_edit = QLineEdit()
        self._title_edit.setPlaceholderText("例如：GitHub 账号")
        self._title_edit.setMaxLength(MAX_FIELD_TITLE)
        self._add_field_row(form, "title", "标题 *：", self._title_edit)

        self._username_edit = QLineEdit()
        self._username_edit.setPlaceholderText("用户名或邮箱")
        self._username_edit.setMaxLength(MAX_FIELD_USERNAME)
        self._add_field_row(form, "username", "账号：", self._username_edit)

        # 密码行
        pwd_layout = QHBoxLayout()
        self._password_edit = QLineEdit()
        self._password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._password_edit.setPlaceholderText("密码")
        self._password_edit.setMaxLength(MAX_FIELD_PASSWORD)
        pwd_layout.addWidget(self._password_edit)

        self._toggle_pwd_btn = create_password_toggle_btn(
            self._password_edit,
            auto_hide_seconds=PWD_TOGGLE_AUTO_HIDE_SECONDS,
        )
        pwd_layout.addWidget(self._toggle_pwd_btn)

        gen_btn = create_icon_button(GENERATE, "生成密码")
        gen_btn.clicked.connect(self._generate_password)
        pwd_layout.addWidget(gen_btn)

        pwd_container = QWidget()
        pwd_container.setLayout(pwd_layout)
        self._add_field_row(form, "password", "密码：", pwd_container)

        # 密码强度
        self._strength_label = QLabel("")
        self._strength_label.setObjectName("formMutedSmall")
        self._add_field_row(form, "_strength", "", self._strength_label)
        self._password_edit.textChanged.connect(self._on_password_changed)

        self._url_edit = QLineEdit()
        self._url_edit.setPlaceholderText("https://")
        self._url_edit.setMaxLength(MAX_FIELD_URL)
        self._add_field_row(form, "url", "网址：", self._url_edit)

        # 类型专用字段，按 entry_type 显示或隐藏
        self._build_type_fields(form)

        # --- 公共尾部字段 ---
        self._category_combo = QComboBox()
        self._category_combo.addItem("未分类", None)
        for cat in self._categories:
            self._category_combo.addItem(f"{cat.icon_char} {cat.name}", cat.id)
        self._add_field_row(form, "category", "分类：", self._category_combo)

        self._tags_edit = QLineEdit()
        self._tags_edit.setPlaceholderText("用逗号分隔多个标签")
        self._tags_edit.setMaxLength(MAX_FIELD_TAGS)
        if self._all_tags:
            # 复用 MAX_TAG_DISPLAY：占位提示展示数量与详情面板标签上限同语义
            hint = ", ".join(self._all_tags[:MAX_TAG_DISPLAY])
            self._tags_edit.setPlaceholderText(f"常用：{hint}" if hint else "用逗号分隔多个标签")
        self._add_field_row(form, "tags", "标签：", self._tags_edit)

        self._favorite_check = QCheckBox("添加到收藏")
        self._add_field_row(form, "favorite", "", self._favorite_check)

        return form

    def _build_totp_group(self) -> QGroupBox:
        """构建两步验证 (TOTP) 区域。"""
        self._totp_group = QGroupBox("两步验证 (TOTP)")
        totp_layout = QHBoxLayout(self._totp_group)
        self._totp_edit = QLineEdit()
        self._totp_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._totp_edit.setPlaceholderText("输入 Base32 密钥或 otpauth:// URI（可选）")
        self._totp_edit.setMaxLength(MAX_FIELD_TOTP_SECRET)
        totp_layout.addWidget(self._totp_edit, 1)
        self._totp_test_btn = QPushButton("验证")
        self._totp_test_btn.setFixedSize(*BTN_SMALL_ACTION)
        self._totp_test_btn.clicked.connect(self._test_totp)
        totp_layout.addWidget(self._totp_test_btn)
        return self._totp_group

    def _build_notes_group(self) -> QGroupBox:
        """构建备注区域。"""
        notes_group = QGroupBox("备注")
        notes_layout = QVBoxLayout(notes_group)
        self._notes_edit = QTextEdit()
        self._notes_edit.setMaximumHeight(self._NOTES_HEIGHT_DEFAULT)
        self._notes_edit.setPlaceholderText("添加备注信息...")
        notes_layout.addWidget(self._notes_edit)
        return notes_group

    def _build_custom_fields_group(self) -> QGroupBox:
        """构建自定义字段区域。"""
        cf_group = QGroupBox("自定义字段")
        cf_layout = QVBoxLayout(cf_group)
        self._custom_fields_container = QVBoxLayout()
        cf_layout.addLayout(self._custom_fields_container)
        self._cf_editor = CustomFieldsEditor(self._custom_fields_container)

        add_cf_btn = QPushButton("+ 添加字段")
        add_cf_btn.setObjectName("iconBtn")
        add_cf_btn.setStyleSheet(f"text-align: left; color: {c('accent')};")
        add_cf_btn.clicked.connect(self._cf_editor.add_row)
        cf_layout.addWidget(add_cf_btn)
        return cf_group

    def _build_buttons(self) -> QHBoxLayout:
        """构建取消/保存按钮行。"""
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        btn_layout.addWidget(create_cancel_button(self))

        save_btn = QPushButton("保存")
        save_btn.setObjectName("primaryBtn")
        save_btn.setFixedSize(*BTN_DIALOG)
        save_btn.clicked.connect(self._on_save)
        btn_layout.addWidget(save_btn)

        return btn_layout

    def _build_type_fields(self, form: QFormLayout) -> None:
        """按 schema 创建专用字段并按控件类型注册到 _special_edits/_special_combos。

        字段初始隐藏，由 _apply_type_visibility 切换显隐。卡号/有效期格式化与端口
        校验等类型特有行为在控件创建后按 field_key 连接，保持 schema 纯粹。
        """
        for schema in ENTRY_TYPE_SCHEMAS.values():
            for spec in schema.special_fields:
                widget = self._create_special_widget(spec)
                self._add_field_row(form, spec.field_key, f"{spec.label}：", widget, visible=False)
                if isinstance(widget, QComboBox):
                    self._special_combos[spec.field_key] = widget
                else:
                    self._special_edits[spec.field_key] = widget
        # 卡号/有效期格式化与端口校验：类型特有行为，schema 之外的特殊连接
        self._special_edits["card_number"].textChanged.connect(self._format_card_number)
        self._special_edits["card_expiry"].textChanged.connect(self._format_card_expiry)
        self._special_edits["server_port"].setValidator(
            QIntValidator(SERVER_PORT_MIN, SERVER_PORT_MAX, self)
        )

    @staticmethod
    def _create_special_widget(spec: SpecialFieldSpec) -> QLineEdit | QComboBox:
        """按 schema 创建单个专用字段控件。"""
        if spec.kind == "combo":
            combo = QComboBox()
            combo.addItems(spec.combo_items)
            return combo
        edit = QLineEdit()
        edit.setPlaceholderText(spec.placeholder)
        if spec.sensitive:
            edit.setEchoMode(QLineEdit.EchoMode.Password)
        if spec.max_length:
            edit.setMaxLength(spec.max_length)
        return edit

    def _add_field_row(
        self, form: QFormLayout, key: str, label_text: str, widget: QWidget, visible: bool = True
    ) -> None:
        """添加一行表单字段，并按 key 记录到 _field_rows 以便后续控制显隐。"""
        label = QLabel(label_text)
        if not visible:
            label.setVisible(False)
            widget.setVisible(False)
        form.addRow(label, widget)
        self._field_rows[key] = (label, widget)

    # ------------------------------------------------------------------
    # 信用卡校验
    # ------------------------------------------------------------------

    def _validate_card_fields(self) -> bool:
        """校验信用卡字段，失败时弹出警告并返回 False。"""
        card_number = self._special_edits["card_number"].text().strip()
        card_expiry = self._special_edits["card_expiry"].text().strip()
        card_cvv = self._special_edits["card_cvv"].text().strip()

        if card_number and not validate_card_number(card_number):
            QMessageBox.warning(self, "校验失败", "卡号格式不正确，请检查后重试。")
            return False
        if card_expiry and not validate_card_expiry(card_expiry):
            QMessageBox.warning(
                self, "校验失败", "有效期格式不正确，应为 MM/YY，且月份在 01-12 之间。"
            )
            return False
        if card_cvv and not validate_card_cvv(card_cvv):
            QMessageBox.warning(self, "校验失败", "CVV 应为 3-4 位数字。")
            return False
        return True

    def _compose_server_url(self) -> str:
        """按 protocol://host[:port] 拼接服务器地址，作为该地址的唯一拼接入口。

        host 为空返回空串。供 ``_on_save`` 写入与 ``_validate_field_lengths``
        共用，防止两处拼接漂移。
        """
        host = self._special_edits["server_host"].text().strip()
        if not host:
            return ""
        port = self._special_edits["server_port"].text().strip()
        protocol = self._special_combos["server_protocol"].currentText().lower()
        return f"{protocol}://{host}" + (f":{port}" if port else "")

    def _validate_field_lengths(self, entry_type: str) -> bool:
        """校验无法在控件层硬限制的字段长度，失败时弹出警告并返回 False。

        多数单行字段已由 ``setMaxLength`` 截断。此处只覆盖：备注（QTextEdit，
        无 setMaxLength，上限 ``MAX_FIELD_NOTES``）与服务器类型拼接 url（上限
        ``MAX_FIELD_URL``）。上限与 ``Entry.from_dict`` 共用常量作为单一事实源。
        """
        notes = self._notes_edit.toPlainText().strip()
        if len(notes) > MAX_FIELD_NOTES:
            QMessageBox.warning(
                self,
                "输入有误",
                f"备注过长（最多 {MAX_FIELD_NOTES} 字符）。",
            )
            return False

        if get_schema(entry_type).composes_url:
            composed_url = self._compose_server_url()
            if composed_url and len(composed_url) > MAX_FIELD_URL:
                QMessageBox.warning(
                    self,
                    "输入有误",
                    f"网址过长（最多 {MAX_FIELD_URL} 字符）。",
                )
                return False
        return True

    @staticmethod
    def _safe_set_formatted(
        widget: QLineEdit, original: str, formatted: str, cursor_at_end: bool = False
    ) -> None:
        """写入格式化文本并尽量保留光标位置。

        调用方需先 blockSignals（textChanged 回调直接 setText 会再次引发回调）；
        此处按光标是否在末尾选择定位策略，避免格式化时光标跳变。
        """
        if formatted == original:
            return
        if cursor_at_end:
            widget.setText(formatted)
            widget.setCursorPosition(len(formatted))
        else:
            cursor_pos = widget.cursorPosition()
            offset = len(formatted) - len(original)
            widget.setText(formatted)
            widget.setCursorPosition(cursor_pos + offset)

    def _format_card_number(self, text: str) -> None:
        """卡号输入时按每 4 位插入空格分组显示。"""
        w = self._special_edits["card_number"]
        w.blockSignals(True)
        digits = text.replace(" ", "")
        formatted = " ".join(digits[i : i + 4] for i in range(0, len(digits), 4))
        self._safe_set_formatted(w, text, formatted)
        w.blockSignals(False)

    def _format_card_expiry(self, text: str) -> None:
        """有效期输入时自动补入分隔符，整理为 MM/YY 形态。"""
        w = self._special_edits["card_expiry"]
        w.blockSignals(True)
        digits = text.replace("/", "")
        if len(digits) > 2:
            formatted = digits[:2] + "/" + digits[2:4]
        else:
            formatted = digits
        self._safe_set_formatted(w, text, formatted, cursor_at_end=True)
        w.blockSignals(False)

    # ------------------------------------------------------------------
    # 类型切换
    # ------------------------------------------------------------------

    def _on_type_changed(self, index: int) -> None:
        """条目类型变更，刷新字段可见性。

        若当前类型已有用户输入，先二次确认以免静默丢弃专用字段数据。
        """
        new_type = self._type_combo.currentData() or ENTRY_TYPE_LOGIN

        if new_type == self._current_type:
            return

        # 检查当前类型的专用字段是否有用户输入（编辑/新建均检查）。
        # _current_type 恒为非空 ENTRY_TYPE_* 常量（默认 login，余从 combo 赋值）。
        old_fields = get_schema(self._current_type).visible_fields
        has_data = False
        for key in old_fields:
            # QComboBox（如协议选择）的当前选项也算用户输入，避免漏确认。
            edit = self._special_edits.get(key)
            combo = self._special_combos.get(key)
            if edit is not None:
                text = edit.text()
            elif combo is not None:
                text = combo.currentText()
            else:
                continue
            if text.strip():
                has_data = True
                break
        # 新建模式下，标题、密码、备注等通用字段已有内容时也应确认
        if not has_data and self._entry is None:
            if (
                self._title_edit.text().strip()
                or self._password_edit.text().strip()
                or self._notes_edit.toPlainText().strip()
            ):
                has_data = True

        if has_data:
            reply = QMessageBox.question(
                self,
                "切换类型",
                "切换条目类型后，当前类型的专用字段数据将不被保存。\n是否继续？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.No:
                # 恢复之前的类型
                idx = self._type_combo.findData(self._current_type)
                if idx >= 0:
                    self._type_combo.setCurrentIndex(idx)
                return

        self._current_type = new_type
        self._apply_type_visibility(new_type)

    def _apply_type_visibility(self, entry_type: str) -> None:
        """按条目类型刷新字段显隐，本身不触发类型切换确认。"""
        visible_keys = set(get_schema(entry_type).visible_fields)

        for key, (label, widget) in self._field_rows.items():
            # _strength 行跟随 password
            if key == "_strength":
                show = "password" in visible_keys
            # category / tags / favorite / 自定义字段区域始终可见，不在 _field_rows 中
            elif key in ("category", "tags", "favorite"):
                show = True
            else:
                show = key in visible_keys
            label.setVisible(show)
            widget.setVisible(show)

        # 笔记类型：经 schema.notes_expanded 标志放大备注区域，消除类型身份判断
        if get_schema(entry_type).notes_expanded:
            self._notes_edit.setMaximumHeight(self._NOTES_HEIGHT_EXPANDED)
        else:
            self._notes_edit.setMaximumHeight(self._NOTES_HEIGHT_DEFAULT)

    # ------------------------------------------------------------------
    # 数据加载
    # ------------------------------------------------------------------

    def _load_entry(self, entry: Entry) -> None:
        """将已有条目数据回填到表单。"""
        self._title_edit.setText(entry.title)
        self._username_edit.setText(entry.username)
        self._password_edit.setText(entry.password)
        self._url_edit.setText(entry.url)
        self._tags_edit.setText(entry.tags)
        self._notes_edit.setPlainText(entry.notes)
        self._favorite_check.setChecked(entry.is_favorite)

        # 类型
        idx = self._type_combo.findData(entry.entry_type)
        if idx >= 0:
            self._type_combo.blockSignals(True)
            self._type_combo.setCurrentIndex(idx)
            self._type_combo.blockSignals(False)
            self._current_type = entry.entry_type
            self._apply_type_visibility(entry.entry_type)

        # 分类
        if entry.category_id:
            idx = self._category_combo.findData(entry.category_id)
            if idx >= 0:
                self._category_combo.setCurrentIndex(idx)

        # TOTP
        if entry.totp_secret:
            self._totp_edit.setText(entry.totp_secret)

        # 按 storage_name 精确匹配恢复专用字段值，避免用户自定义字段名以
        # _card_/_id_/_server_ 开头时被误判为专用字段。
        cf_raw = entry.custom_fields
        if isinstance(cf_raw, list) and cf_raw:
            type_specific = []
            for cf in cf_raw:
                spec = all_special_fields_by_storage().get(cf.name)
                if spec is not None:
                    combo = self._special_combos.get(spec.field_key)
                    edit = self._special_edits.get(spec.field_key)
                    if combo is not None:
                        idx = combo.findText(cf.value)
                        if idx >= 0:
                            combo.setCurrentIndex(idx)
                    elif edit is not None:
                        edit.setText(cf.value)
                else:
                    type_specific.append(cf)

            # 清空旧的自定义字段行后回填通用自定义字段
            self._cf_editor.clear_rows()
            for cf in type_specific:
                self._cf_editor.add_row(cf.name, cf.value, cf.field_type)

    # ------------------------------------------------------------------
    # 密码辅助
    # ------------------------------------------------------------------

    def _cfg(self, key: str, default: _T) -> _T:
        """读取配置值，config 为 None 时使用默认值。"""
        return self._config.get(key, default) if self._config else default

    def _generate_password(self) -> None:
        length = self._cfg(CFG_DEFAULT_PASSWORD_LENGTH, PWD_GENERATE_LENGTH_DEFAULT)
        password = PasswordService.generate(
            length=length,
            uppercase=self._cfg(CFG_DEFAULT_UPPERCASE, True),
            lowercase=self._cfg(CFG_DEFAULT_LOWERCASE, True),
            digits=self._cfg(CFG_DEFAULT_DIGITS, True),
            symbols=self._cfg(CFG_DEFAULT_SYMBOLS, True),
            exclude_ambiguous=self._cfg(CFG_DEFAULT_EXCLUDE_AMBIGUOUS, False),
        )
        self._password_edit.setText(password)
        # visible_seconds 用 _cfg 而非 get_safe：「显示多久」无安全下限语义，
        # get_safe 钳制仅用于防篡改类键（auto_lock 等）。
        visible_seconds = self._cfg(CFG_PASSWORD_VISIBLE_SECONDS, PWD_VISIBLE_SECONDS_DEFAULT)
        self._toggle_pwd_btn.show_password(seconds=visible_seconds)

    def _on_password_changed(self, text: str) -> None:
        update_strength_label(self._strength_label, text, font_size="11px")

    # ------------------------------------------------------------------
    # TOTP
    # ------------------------------------------------------------------

    def _test_totp(self) -> None:
        """校验 TOTP 密钥有效性并尝试生成一次验证码。"""
        secret = self._totp_edit.text().strip()
        if not secret:
            return
        if PasswordService.validate_totp_secret(secret):
            try:
                PasswordService.generate_totp_or_raise(secret)
                QMessageBox.information(self, "验证成功", "密钥有效，已成功生成验证码。")
            except ValueError as exc:
                QMessageBox.warning(self, "验证失败", f"密钥验证出错：{exc}")
        else:
            QMessageBox.warning(self, "验证失败", "无效的 TOTP 密钥或 URI，请检查后重试。")

    # ------------------------------------------------------------------
    # 专用字段收集
    # ------------------------------------------------------------------

    def _collect_type_specific_fields(self) -> list[CustomField]:
        """按当前类型的 schema 收集专用字段为 CustomField，存储名沿用 _ 前缀。"""
        entry_type = self._type_combo.currentData() or ENTRY_TYPE_LOGIN
        fields: list[CustomField] = []
        for spec in get_schema(entry_type).special_fields:
            combo = self._special_combos.get(spec.field_key)
            if combo is not None:
                value = combo.currentText()
            else:
                value = self._special_edits[spec.field_key].text()
                # 卡号去除分组空格后存储
                if spec.field_key == "card_number":
                    value = value.replace(" ", "")
            field_type = "password" if spec.sensitive else "text"
            fields.append(CustomField(name=spec.storage_name, value=value, field_type=field_type))
        return fields

    # ------------------------------------------------------------------
    # 保存
    # ------------------------------------------------------------------

    def _collect_entry(self, entry_type: str) -> Entry:
        """收集表单控件值并构造 Entry（含专用字段拼接 url 与自定义字段合并）。

        Args:
            entry_type: 当前条目类型，由调用方经前置校验后传入。

        Returns:
            填充好的 :class:`Entry`（新建条目无 id，由调用方按编辑场景补 id）。
        """
        schema = get_schema(entry_type)
        visible = schema.visible_fields
        # 仅采集当前类型可见的通用字段，避免新增模式下类型切换后隐藏控件的残留值被
        # 持久化（如 login→card 切换后，旧 username/url 不应隐式带入不可见的新类型
        # 字段）。password/username/url 三字段统一按「编辑模式豁免 + 可见性」门控
        # （QL-029 引入密码门控，QL-033 补齐 username/url 的同款豁免）：card/identity/
        # note 的 visible_fields 不含这些字段，新增模式下残留的隐藏值不应被持久化到
        # 表单上看不见、无法清除的位置；编辑模式（self._entry 非 None）不按可见性
        # 门控——既有条目可合法持有这些字段（JSON 导入的带 username 的 card，详情
        # 面板对任何类型都显示账号/网址行），须保留隐藏控件回读的值，否则保存时被
        # 静默清空。uses_password=False 的类型（笔记）密码维持强制置空。
        if not schema.uses_password:
            password = ""
        elif self._entry is not None or "password" in visible:
            password = self._password_edit.text()
        else:
            password = ""
        username = (
            self._username_edit.text().strip()
            if self._entry is not None or "username" in visible
            else ""
        )
        url = self._url_edit.text().strip() if self._entry is not None or "url" in visible else ""

        # 由专用字段拼接 url 的类型（服务器）：username/password 已在上方统一读取。
        # host 非空时组合值优先；host 为空时保留上方门控结果——编辑模式下即隐藏
        # url 控件回读的既有值（_load_entry 无条件回填 url，导入的仅有 url 无 host
        # 的服务器条目不因编辑丢失），新增模式下为空串，两模式行为均合理。
        if schema.composes_url:
            composed = self._compose_server_url()
            if composed:
                url = composed

        # 合并专用字段 + 通用自定义字段
        all_custom = self._collect_type_specific_fields() + self._cf_editor.collect()

        return Entry(
            title=self._title_edit.text().strip(),
            username=username,
            password=password,
            url=url,
            category_id=self._category_combo.currentData(),
            tags=self._tags_edit.text().strip(),
            notes=self._notes_edit.toPlainText().strip(),
            custom_fields=all_custom,
            is_favorite=self._favorite_check.isChecked(),
            entry_type=entry_type,
            totp_secret=self._totp_edit.text().strip(),
            # 透传 integrity_error 以避免编辑保存时覆盖已损坏的加密数据，
            # 新建条目场景即 self._entry 为 None 时恒为 False。
            integrity_error=self._entry.integrity_error if self._entry else False,
            integrity_message=self._entry.integrity_message if self._entry else "",
        )

    def _handle_save_error(self, exc: Exception) -> None:
        """分流保存异常到对应的日志级别与用户文案。

        顺序敏感：领域异常（DatabaseError/DecryptionError/EntryIntegrityError）必须
        先于 ValueError 判定——DecryptionError 双继承 ValueError，若放后会被字段校验
        分支误捕为「输入有误」，掩盖领域文案。
        """
        if isinstance(exc, (DatabaseError, DecryptionError, EntryIntegrityError)):
            logger.error(
                "保存条目失败: %s: %s",
                type(exc).__name__,
                exc,
                exc_info=True,
            )
            QMessageBox.critical(self, DLG_TITLE_ERROR, to_user_message(exc))
        elif isinstance(exc, ValueError):
            # 业务层字段校验失败（纯 ValueError，非 DecryptionError）
            logger.warning("条目校验失败: %s", exc)
            QMessageBox.warning(self, "输入有误", str(exc))
        else:
            # 意外异常：与领域错误区分文案，避免经 to_user_message 归并为「用户数据问题」。
            logger.error(
                "保存条目时出现意外错误: %s: %s",
                type(exc).__name__,
                exc,
                exc_info=True,
            )
            QMessageBox.critical(
                self,
                DLG_TITLE_ERROR,
                "出现意外错误，未能保存条目。详细信息已记录到日志，请重试。",
            )

    def _on_save(self) -> None:
        title = self._title_edit.text().strip()
        if not title:
            QMessageBox.warning(self, DLG_TITLE_INFO, "请输入标题")
            return

        entry_type = self._type_combo.currentData() or ENTRY_TYPE_LOGIN

        # 专用字段额外校验（如信用卡卡号/有效期/CVV），经 schema.validate_extra 标志驱动
        if get_schema(entry_type).validate_extra:
            if not self._validate_card_fields():
                return

        # 字段长度前置校验：补充 QTextEdit 备注、服务器拼接 url 等控件层
        # 无法硬限制的字段，避免到业务层才以 ValueError 暴露。
        if not self._validate_field_lengths(entry_type):
            return

        # TOTP secret 前置校验：无效 Base32/URI 入库会致详情面板生成验证码时报错，
        # 在保存前拦截与 _test_totp 同源的校验逻辑。
        totp_secret = self._totp_edit.text().strip()
        if totp_secret and not PasswordService.validate_totp_secret(totp_secret):
            QMessageBox.warning(self, "验证失败", "无效的 TOTP 密钥或 URI，请检查后重试。")
            return

        entry = self._collect_entry(entry_type)

        try:
            if self._entry:
                entry = replace(entry, id=self._entry.id)
                self._entry_mgr.update_entry(entry)
            else:
                self._entry_mgr.add_entry(entry)
            self.saved.emit()
            # 保存成功后立即清除敏感输入框，缩短明文在内存中的驻留时间。
            self._clear_sensitive_inputs()
            self.accept()
        except Exception as exc:
            self._handle_save_error(exc)

    def _clear_sensitive_inputs(self) -> None:
        """清除所有敏感输入框中的明文。

        保存成功、取消或关闭对话框时调用。``QLineEdit.clear()`` 重置控件文本，
        消除对话结束后的残留可见密码（控件缓存、截图等）。非 CPython 密码学清除
        保证，字符串对象回收仍依赖 GC。
        """
        self._password_edit.clear()
        self._totp_edit.clear()
        # 通用字段一并清除：username/url 是核心凭据，notes/tags 可能含敏感内容，
        # 使清理范围与威胁模型一致。
        self._username_edit.clear()
        self._url_edit.clear()
        self._tags_edit.clear()
        self._notes_edit.clear()
        # 遍历 ENTRY_TYPE_SCHEMAS 全表清除专用字段：新增类型/字段自动纳入，避免
        # 硬编码 key 列表遗漏。QComboBox（如协议选择）非敏感输入，由守卫跳过。
        for schema in ENTRY_TYPE_SCHEMAS.values():
            for spec in schema.special_fields:
                edit = self._special_edits.get(spec.field_key)
                if edit is not None:
                    edit.clear()
        # 自定义字段中回显模式为 Password 的值视为敏感数据一并清除
        self._cf_editor.clear_sensitive_values()

    def reject(self) -> None:
        """取消/关闭前清除敏感输入框。

        QDialog 经 X/Esc/reject()/done(Rejected) 退出均走此入口，无需再重写
        closeEvent 重复清理。
        """
        self._clear_sensitive_inputs()
        super().reject()
