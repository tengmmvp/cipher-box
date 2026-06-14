"""条目编辑对话框，支持 5 种条目类型、TOTP 与自定义字段。

承载新增与编辑两套流程，按条目类型动态切换可见字段。专用字段以
类型前缀存入 custom_fields，与通用自定义字段统一序列化。涉及密码、
卡号、TOTP 密钥等敏感输入，保存或关闭时统一清除以缩短明文驻留时间。
"""

import logging
from dataclasses import dataclass
from typing import cast

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
from ...business.services.password_service import PasswordService
from ...models import (
    ENTRY_TYPE_CARD,
    ENTRY_TYPE_LOGIN,
    ENTRY_TYPE_NOTE,
    ENTRY_TYPE_SERVER,
    ENTRY_TYPES,
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
    create_password_toggle_btn,
    setup_dialog_flags,
    update_strength_label,
)
from ..resources.constants import (
    BTN_DIALOG,
    BTN_ICON,
    BTN_SMALL_ACTION,
    DIALOG_ENTRY_MIN_SIZE,
    PWD_GENERATE_LENGTH_DEFAULT,
    PWD_TOGGLE_AUTO_HIDE_SECONDS,
    PWD_VISIBLE_SECONDS_DEFAULT,
)
from ..resources.icons import GENERATE, set_icon
from ..resources.theme_colors import c

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _SpecialFieldSpec:
    """专用字段的 schema 定义，驱动构建/收集/加载/显隐。

    storage_name 沿用 ``_`` 前缀作为专用字段命名空间，将其与用户自定义字段
    隔离以避免字段名碰撞。加载时按 storage_name 精确匹配归属，而非按前缀
    ``startswith`` 推断，消除用户自定义字段名以 ``_card_``/``_id_``/
    ``_server_`` 开头时被误判为专用字段的风险。
    """

    field_key: str           # widget 标识与 _special_widgets 的键，如 'card_holder'
    storage_name: str        # custom_fields 中的存储名，如 '_card_holder'
    label: str               # 表单标签文案
    placeholder: str = ''
    sensitive: bool = False  # 密码型字段（EchoMode.Password + field_type='password'）
    max_length: int = 0      # 0 表示不设置 maxLength
    kind: str = 'line'       # 'line' 或 'combo'
    combo_items: tuple = ()


# 各条目类型的专用字段 schema（按显示顺序）。schema 是字段配置的单一事实来源，
# 驱动 _build_type_fields / _collect_type_specific_fields / _load_entry，
# 消除分散的前缀约定与重复的 if/elif 收集逻辑。新增类型或字段只需扩展此表。
_SPECIAL_SCHEMA: dict[str, list[_SpecialFieldSpec]] = {
    'card': [
        _SpecialFieldSpec('card_holder', '_card_holder', '持卡人', '持卡人姓名'),
        _SpecialFieldSpec('card_number', '_card_number', '卡号', '卡号', sensitive=True),
        _SpecialFieldSpec('card_expiry', '_card_expiry', '有效期', 'MM/YY', max_length=5),
        _SpecialFieldSpec('card_cvv', '_card_cvv', 'CVV', 'CVV', sensitive=True, max_length=4),
    ],
    'identity': [
        _SpecialFieldSpec('id_fullname', '_id_fullname', '姓名', '姓名'),
        _SpecialFieldSpec('id_email', '_id_email', '邮箱', '邮箱'),
        _SpecialFieldSpec('id_phone', '_id_phone', '电话', '电话'),
        _SpecialFieldSpec('id_address', '_id_address', '地址', '地址'),
    ],
    'server': [
        _SpecialFieldSpec('server_host', '_server_host', '主机', '主机地址'),
        _SpecialFieldSpec('server_port', '_server_port', '端口', '22'),
        _SpecialFieldSpec('server_protocol', '_server_protocol', '协议',
                          kind='combo', combo_items=('SSH', 'FTP', 'HTTP', 'HTTPS', '其他')),
    ],
}

# 各类型可见字段（通用 + 专用），用于切换类型时刷新显隐
_TYPE_FIELDS: dict[str, list[str]] = {
    'login':    ['title', 'username', 'password', 'url'],
    'card':     ['title', *[s.field_key for s in _SPECIAL_SCHEMA['card']]],
    'identity': ['title', *[s.field_key for s in _SPECIAL_SCHEMA['identity']]],
    'note':     ['title'],
    'server':   ['title', *[s.field_key for s in _SPECIAL_SCHEMA['server']], 'username', 'password'],
}

# 全部专用字段的 storage_name → spec 映射，加载时按 storage_name 精确匹配，
# 替代原先的前缀 startswith 推断
_ALL_SPECIAL_BY_STORAGE: dict[str, _SpecialFieldSpec] = {
    spec.storage_name: spec
    for specs in _SPECIAL_SCHEMA.values()
    for spec in specs
}


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
        entry_manager,
        categories: list[Category],
        all_tags: list[str] | None = None,
        entry: Entry | None = None,
        parent=None,
        config=None,
    ):
        super().__init__(parent)
        self._entry_mgr = entry_manager
        self._categories = categories
        self._all_tags = all_tags or []
        self._entry = entry
        self._config = config
        self._current_type = entry.entry_type if entry else ENTRY_TYPE_LOGIN
        self._field_rows: dict[str, tuple[QLabel, QWidget]] = {}
        self._special_widgets: dict[str, QWidget] = {}

        self._setup_ui()
        if entry:
            self._load_entry(entry)

    # ------------------------------------------------------------------
    # UI 构建
    # ------------------------------------------------------------------

    def _setup_ui(self):
        self.setWindowTitle('编辑条目' if self._entry else '新增条目')
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
        type_label = QLabel('类型：')
        type_label.setObjectName('fieldLabel')
        type_row.addWidget(type_label)

        self._type_combo = QComboBox()
        for key, info in ENTRY_TYPES.items():
            self._type_combo.addItem(f"{info['icon']} {info['label']}", key)
        self._type_combo.currentIndexChanged.connect(self._on_type_changed)
        type_row.addWidget(self._type_combo, 1)
        layout.addLayout(type_row)

    def _build_form(self) -> QFormLayout:
        """构建通用字段、类型专用字段与公共尾部字段的表单。"""
        form = QFormLayout()
        form.setSpacing(10)

        # --- 通用字段 ---
        self._title_edit = QLineEdit()
        self._title_edit.setPlaceholderText('例如：GitHub 账号')
        self._title_edit.setMaxLength(MAX_FIELD_TITLE)
        self._add_field_row(form, 'title', '标题 *：', self._title_edit)

        self._username_edit = QLineEdit()
        self._username_edit.setPlaceholderText('用户名或邮箱')
        self._username_edit.setMaxLength(MAX_FIELD_USERNAME)
        self._add_field_row(form, 'username', '账号：', self._username_edit)

        # 密码行
        pwd_layout = QHBoxLayout()
        self._password_edit = QLineEdit()
        self._password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._password_edit.setPlaceholderText('密码')
        self._password_edit.setMaxLength(MAX_FIELD_PASSWORD)
        pwd_layout.addWidget(self._password_edit)

        self._toggle_pwd_btn = create_password_toggle_btn(
            self._password_edit, auto_hide_seconds=PWD_TOGGLE_AUTO_HIDE_SECONDS,
        )
        pwd_layout.addWidget(self._toggle_pwd_btn)

        gen_btn = QPushButton()
        gen_btn.setObjectName('iconBtn')
        gen_btn.setFixedSize(*BTN_ICON)
        set_icon(gen_btn, GENERATE)
        gen_btn.setToolTip('生成密码')
        gen_btn.clicked.connect(self._generate_password)
        pwd_layout.addWidget(gen_btn)

        pwd_container = QWidget()
        pwd_container.setLayout(pwd_layout)
        self._add_field_row(form, 'password', '密码：', pwd_container)

        # 密码强度
        self._strength_label = QLabel('')
        self._strength_label.setObjectName('formMutedSmall')
        self._add_field_row(form, '_strength', '', self._strength_label)
        self._password_edit.textChanged.connect(self._on_password_changed)

        self._url_edit = QLineEdit()
        self._url_edit.setPlaceholderText('https://')
        self._url_edit.setMaxLength(MAX_FIELD_URL)
        self._add_field_row(form, 'url', '网址：', self._url_edit)

        # 类型专用字段，按 entry_type 显示或隐藏
        self._build_type_fields(form)

        # --- 公共尾部字段 ---
        self._category_combo = QComboBox()
        self._category_combo.addItem('未分类', None)
        for cat in self._categories:
            self._category_combo.addItem(f"{cat.icon_char} {cat.name}", cat.id)
        self._add_field_row(form, 'category', '分类：', self._category_combo)

        self._tags_edit = QLineEdit()
        self._tags_edit.setPlaceholderText('用逗号分隔多个标签')
        self._tags_edit.setMaxLength(MAX_FIELD_TAGS)
        if self._all_tags:
            hint = ', '.join(self._all_tags[:5])
            self._tags_edit.setPlaceholderText(f'常用：{hint}' if hint else '用逗号分隔多个标签')
        self._add_field_row(form, 'tags', '标签：', self._tags_edit)

        self._favorite_check = QCheckBox('添加到收藏')
        self._add_field_row(form, 'favorite', '', self._favorite_check)

        return form

    def _build_totp_group(self) -> QGroupBox:
        """构建两步验证 (TOTP) 区域。"""
        self._totp_group = QGroupBox('两步验证 (TOTP)')
        totp_layout = QHBoxLayout(self._totp_group)
        self._totp_edit = QLineEdit()
        self._totp_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._totp_edit.setPlaceholderText('输入 Base32 密钥或 otpauth:// URI（可选）')
        self._totp_edit.setMaxLength(MAX_FIELD_TOTP_SECRET)
        totp_layout.addWidget(self._totp_edit, 1)
        self._totp_test_btn = QPushButton('验证')
        self._totp_test_btn.setFixedSize(*BTN_SMALL_ACTION)
        self._totp_test_btn.clicked.connect(self._test_totp)
        totp_layout.addWidget(self._totp_test_btn)
        return self._totp_group

    def _build_notes_group(self) -> QGroupBox:
        """构建备注区域。"""
        notes_group = QGroupBox('备注')
        notes_layout = QVBoxLayout(notes_group)
        self._notes_edit = QTextEdit()
        self._notes_edit.setMaximumHeight(self._NOTES_HEIGHT_DEFAULT)
        self._notes_edit.setPlaceholderText('添加备注信息...')
        notes_layout.addWidget(self._notes_edit)
        return notes_group

    def _build_custom_fields_group(self) -> QGroupBox:
        """构建自定义字段区域。"""
        cf_group = QGroupBox('自定义字段')
        cf_layout = QVBoxLayout(cf_group)
        self._custom_fields_container = QVBoxLayout()
        cf_layout.addLayout(self._custom_fields_container)
        self._cf_editor = CustomFieldsEditor(self._custom_fields_container)

        add_cf_btn = QPushButton('+ 添加字段')
        add_cf_btn.setObjectName('iconBtn')
        add_cf_btn.setStyleSheet(f'text-align: left; color: {c("accent")};')
        add_cf_btn.clicked.connect(self._cf_editor.add_row)
        cf_layout.addWidget(add_cf_btn)
        return cf_group

    def _build_buttons(self) -> QHBoxLayout:
        """构建取消/保存按钮行。"""
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        cancel_btn = QPushButton('取消')
        cancel_btn.setFixedSize(*BTN_DIALOG)
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)

        save_btn = QPushButton('保存')
        save_btn.setObjectName('primaryBtn')
        save_btn.setFixedSize(*BTN_DIALOG)
        save_btn.clicked.connect(self._on_save)
        btn_layout.addWidget(save_btn)

        return btn_layout

    def _build_type_fields(self, form: QFormLayout):
        """按 schema 创建各条目类型的专用字段并注册到 _special_widgets。

        所有字段初始隐藏，由 _apply_type_visibility 按当前类型切换显隐。
        schema 驱动通用创建逻辑；卡号/有效期格式化与端口校验等类型特有行为
        在控件创建后按 field_key 连接，保持 schema 的纯粹性。
        """
        for specs in _SPECIAL_SCHEMA.values():
            for spec in specs:
                widget = self._create_special_widget(spec)
                self._add_field_row(form, spec.field_key, f'{spec.label}：', widget, visible=False)
                self._special_widgets[spec.field_key] = widget
        # 卡号/有效期格式化与端口校验：类型特有行为，schema 之外的特殊连接
        cast(QLineEdit, self._special_widgets['card_number']).textChanged.connect(
            self._format_card_number
        )
        cast(QLineEdit, self._special_widgets['card_expiry']).textChanged.connect(
            self._format_card_expiry
        )
        cast(QLineEdit, self._special_widgets['server_port']).setValidator(
            QIntValidator(1, 65535, self)
        )

    @staticmethod
    def _create_special_widget(spec: '_SpecialFieldSpec') -> QWidget:
        """按 schema 创建单个专用字段控件。"""
        if spec.kind == 'combo':
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

    def _add_field_row(self, form: QFormLayout, key: str, label_text: str, widget: QWidget, visible: bool = True):
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
        w = self._special_widgets
        card_number = cast(QLineEdit, w['card_number']).text().strip()
        card_expiry = cast(QLineEdit, w['card_expiry']).text().strip()
        card_cvv = cast(QLineEdit, w['card_cvv']).text().strip()

        if card_number and not validate_card_number(card_number):
            QMessageBox.warning(self, '校验失败', '卡号格式不正确，请检查后重试。')
            return False
        if card_expiry and not validate_card_expiry(card_expiry):
            QMessageBox.warning(self, '校验失败', '有效期格式不正确，应为 MM/YY，且月份在 01-12 之间。')
            return False
        if card_cvv and not validate_card_cvv(card_cvv):
            QMessageBox.warning(self, '校验失败', 'CVV 应为 3-4 位数字。')
            return False
        return True

    def _compose_server_url(self) -> str:
        """按 protocol://host[:port] 拼接服务器地址，作为单一拼接来源。

        host 为空时返回空串，避免生成无意义的 ``ssh://``。供
        ``_on_save`` 写入与 ``_validate_field_lengths`` 校验长度共用，
        防止两处拼接逻辑漂移。
        """
        host = cast(QLineEdit, self._special_widgets['server_host']).text().strip()
        if not host:
            return ''
        port = cast(QLineEdit, self._special_widgets['server_port']).text().strip()
        protocol = cast(QComboBox, self._special_widgets['server_protocol']).currentText().lower()
        return f'{protocol}://{host}' + (f':{port}' if port else '')

    def _validate_field_lengths(self, entry_type: str) -> bool:
        """校验无法在控件层硬限制的字段长度，失败时弹出警告并返回 False。

        多数单行字段已通过 ``setMaxLength`` 在输入时截断，无需在此重复检查。
        此处只覆盖两类控件层无法限制的字段：
        - 备注使用 QTextEdit，无 setMaxLength，上限为 ``MAX_FIELD_NOTES``；
        - 服务器类型由 host、port、protocol 拼接得到的 url，上限为 ``MAX_FIELD_URL``。
        校验上限与 ``src/models.py`` 的 ``Entry.from_dict`` 保持一致，使 UI
        反馈与导入校验共用同一组常量作为单一事实来源。
        """
        notes = self._notes_edit.toPlainText().strip()
        if len(notes) > MAX_FIELD_NOTES:
            QMessageBox.warning(
                self, '输入有误',
                f'备注过长（最多 {MAX_FIELD_NOTES} 字符）。',
            )
            return False

        if entry_type == ENTRY_TYPE_SERVER:
            composed_url = self._compose_server_url()
            if composed_url and len(composed_url) > MAX_FIELD_URL:
                QMessageBox.warning(
                    self, '输入有误',
                    f'网址过长（最多 {MAX_FIELD_URL} 字符）。',
                )
                return False
        return True

    @staticmethod
    def _safe_set_formatted(widget, original: str, formatted: str, cursor_at_end: bool = False):
        """阻塞信号地写入格式化文本，并尽量保留原光标位置。

        格式化回调本身由 textChanged 触发，若直接 setText 会再次引发回调，
        因此调用方需先 blockSignals；此处只负责根据光标是否在末尾选择不同
        的定位策略，避免格式化时光标跳变。
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

    def _format_card_number(self, text: str):
        """卡号输入时按每 4 位插入空格分组显示。"""
        w = self._special_widgets['card_number']
        w.blockSignals(True)
        digits = text.replace(' ', '')
        formatted = ' '.join(digits[i:i+4] for i in range(0, len(digits), 4))
        self._safe_set_formatted(w, text, formatted)
        w.blockSignals(False)

    def _format_card_expiry(self, text: str):
        """有效期输入时自动补入分隔符，整理为 MM/YY 形态。"""
        w = self._special_widgets['card_expiry']
        w.blockSignals(True)
        digits = text.replace('/', '')
        if len(digits) > 2:
            formatted = digits[:2] + '/' + digits[2:4]
        else:
            formatted = digits
        self._safe_set_formatted(w, text, formatted, cursor_at_end=True)
        w.blockSignals(False)

    # ------------------------------------------------------------------
    # 类型切换
    # ------------------------------------------------------------------

    def _on_type_changed(self, index: int):
        """条目类型变更，刷新字段可见性。

        若当前类型已有用户输入，先二次确认以免静默丢弃专用字段数据，
        用户拒绝时回退到原类型选择项。
        """
        new_type = self._type_combo.currentData() or ENTRY_TYPE_LOGIN

        if new_type == self._current_type:
            return

        # 检查当前类型的专用字段是否有用户输入数据，编辑和新建两种模式均检查
        if self._current_type:
            old_fields = _TYPE_FIELDS.get(self._current_type, [])
            has_data = False
            for key in old_fields:
                if key in self._special_widgets:
                    widget = self._special_widgets[key]
                    text = cast(QLineEdit, widget).text() if isinstance(widget, QLineEdit) else ''
                    if text.strip():
                        has_data = True
                        break
            # 新建模式下，标题、密码、备注等通用字段已有内容时也应确认
            if not has_data and self._entry is None:
                if (self._title_edit.text().strip()
                        or self._password_edit.text().strip()
                        or self._notes_edit.toPlainText().strip()):
                    has_data = True

            if has_data:
                reply = QMessageBox.question(
                    self, '切换类型',
                    '切换条目类型后，当前类型的专用字段数据将不被保存。\n是否继续？',
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

    def _apply_type_visibility(self, entry_type: str):
        """按条目类型刷新字段显隐，本身不触发类型切换确认。"""
        visible_keys = set(_TYPE_FIELDS.get(entry_type, _TYPE_FIELDS['login']))

        for key, (label, widget) in self._field_rows.items():
            # _strength 行跟随 password
            if key == '_strength':
                show = 'password' in visible_keys
            # category / tags / favorite / 自定义字段区域始终可见，不在 _field_rows 中
            elif key in ('category', 'tags', 'favorite'):
                show = True
            else:
                show = key in visible_keys
            label.setVisible(show)
            widget.setVisible(show)

        # 笔记类型：放大备注区域
        if entry_type == ENTRY_TYPE_NOTE:
            self._notes_edit.setMaximumHeight(self._NOTES_HEIGHT_EXPANDED)
        else:
            self._notes_edit.setMaximumHeight(self._NOTES_HEIGHT_DEFAULT)

    # ------------------------------------------------------------------
    # 数据加载
    # ------------------------------------------------------------------

    def _load_entry(self, entry: Entry):
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

        # 从 custom_fields 恢复专用字段值：按 storage_name 精确匹配（替代前缀 startswith），
        # 消除用户自定义字段名以 _card_/_id_/_server_ 开头时被误判为专用字段的碰撞风险。
        cf_raw = entry.custom_fields
        if isinstance(cf_raw, list) and cf_raw:
            type_specific = []
            for cf in cf_raw:
                spec = _ALL_SPECIAL_BY_STORAGE.get(cf.name)
                if spec is not None:
                    widget = self._special_widgets.get(spec.field_key)
                    if widget is not None:
                        if isinstance(widget, QComboBox):
                            idx = widget.findText(cf.value)
                            if idx >= 0:
                                widget.setCurrentIndex(idx)
                        else:
                            cast(QLineEdit, widget).setText(cf.value)
                else:
                    type_specific.append(cf)

            # 清空旧的自定义字段行后回填通用自定义字段
            self._cf_editor.clear_rows()
            for cf in type_specific:
                self._cf_editor.add_row(cf.name, cf.value, cf.field_type)

    # ------------------------------------------------------------------
    # 密码辅助
    # ------------------------------------------------------------------

    def _cfg(self, key: str, default):
        """读取配置值，config 为 None 时使用默认值。"""
        return self._config.get(key, default) if self._config else default

    def _generate_password(self):
        length = self._cfg('default_password_length', PWD_GENERATE_LENGTH_DEFAULT)
        password = PasswordService.generate(
            length=length,
            uppercase=self._cfg('default_uppercase', True),
            lowercase=self._cfg('default_lowercase', True),
            digits=self._cfg('default_digits', True),
            symbols=self._cfg('default_symbols', True),
            exclude_ambiguous=self._cfg('default_exclude_ambiguous', False),
        )
        self._password_edit.setText(password)
        # 通过按钮公共方法显示密码并按配置启动自动隐藏，替代反射式属性访问
        visible_seconds = PWD_VISIBLE_SECONDS_DEFAULT
        if self._config:
            visible_seconds = self._config.get_safe('password_visible_seconds', PWD_VISIBLE_SECONDS_DEFAULT)
        self._toggle_pwd_btn.show_password(seconds=visible_seconds)

    def _on_password_changed(self, text: str):
        update_strength_label(self._strength_label, text, font_size='11px')

    # ------------------------------------------------------------------
    # TOTP
    # ------------------------------------------------------------------

    def _test_totp(self):
        """校验 TOTP 密钥有效性并尝试生成一次验证码。"""
        secret = self._totp_edit.text().strip()
        if not secret:
            return
        if PasswordService.validate_totp_secret(secret):
            try:
                PasswordService.generate_totp_or_raise(secret)
                QMessageBox.information(self, '验证成功', '密钥有效，已成功生成验证码。')
            except ValueError as exc:
                QMessageBox.warning(self, '验证失败', f'密钥验证出错：{exc}')
        else:
            QMessageBox.warning(self, '验证失败', '无效的 TOTP 密钥或 URI，请检查后重试。')

    # ------------------------------------------------------------------
    # 专用字段收集
    # ------------------------------------------------------------------

    def _collect_type_specific_fields(self) -> list[CustomField]:
        """按当前类型的 schema 收集专用字段为 CustomField，存储名沿用 _ 前缀。"""
        entry_type = self._type_combo.currentData() or ENTRY_TYPE_LOGIN
        fields: list[CustomField] = []
        for spec in _SPECIAL_SCHEMA.get(entry_type, []):
            widget = self._special_widgets[spec.field_key]
            if isinstance(widget, QComboBox):
                value = widget.currentText()
            else:
                value = cast(QLineEdit, widget).text()
                # 卡号去除分组空格后存储
                if spec.field_key == 'card_number':
                    value = value.replace(' ', '')
            field_type = 'password' if spec.sensitive else 'text'
            fields.append(CustomField(name=spec.storage_name, value=value, field_type=field_type))
        return fields

    # ------------------------------------------------------------------
    # 保存
    # ------------------------------------------------------------------

    def _on_save(self):
        title = self._title_edit.text().strip()
        if not title:
            QMessageBox.warning(self, '提示', '请输入标题')
            return

        entry_type = self._type_combo.currentData() or ENTRY_TYPE_LOGIN

        # 信用卡类型需额外校验卡号、有效期与 CVV
        if entry_type == ENTRY_TYPE_CARD:
            if not self._validate_card_fields():
                return

        # 字段长度前置校验。QLineEdit 已通过 setMaxLength 限制多数字段，
        # 此处补充对 QTextEdit 备注、服务器拼接 url 等无法在控件层硬限制
        # 的字段做即时提示，避免到达业务层后才以 ValueError 形式暴露。
        if not self._validate_field_lengths(entry_type):
            return

        # 笔记类型不使用密码字段，强制置空避免保存无意义数据
        password = self._password_edit.text() if entry_type != ENTRY_TYPE_NOTE else ''
        username = self._username_edit.text().strip()
        url = self._url_edit.text().strip()

        # 服务器类型由 host 与 port 拼接出 url；username/password 已在上方统一读取
        if entry_type == ENTRY_TYPE_SERVER:
            composed = self._compose_server_url()
            if composed:
                url = composed

        # 合并专用字段 + 通用自定义字段
        all_custom = self._collect_type_specific_fields() + self._cf_editor.collect()

        entry = Entry(
            title=title,
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
            integrity_message=self._entry.integrity_message if self._entry else '',
        )

        try:
            if self._entry:
                entry.id = self._entry.id
                self._entry_mgr.update_entry(entry)
            else:
                self._entry_mgr.add_entry(entry)
            self.saved.emit()
            # 保存成功后立即清除敏感输入框，缩短明文在内存中的驻留时间。
            self._clear_sensitive_inputs()
            self.accept()
        except ValueError as exc:
            # 业务层字段校验失败，提示用户修改后重试
            logger.warning("条目校验失败: %s", exc)
            QMessageBox.warning(self, '输入有误', str(exc))
        except Exception as exc:
            logger.error("保存条目失败: %s", type(exc).__name__, exc_info=True)
            QMessageBox.critical(self, '错误', '保存失败，请重试')

    def _clear_sensitive_inputs(self):
        """清除所有敏感输入框中的明文。

        在保存成功、用户取消或关闭对话框时调用。QLineEdit.clear() 会重置
        控件文本，主要消除对话结束后的残留可见密码风险，涉及控件缓存与
        截图等场景。注意这并非 CPython 下的密码学清除保证，字符串对象的
        回收仍依赖 GC。
        """
        self._password_edit.clear()
        self._totp_edit.clear()
        # 通用字段：username/url 对 login/server 类型是核心凭据，notes 可能含敏感
        # 备注，tags 可能含敏感标识。关闭对话框时一并清除，使清理范围与威胁模型一致
        # （避免清了 CVV 却残留同等敏感的 username）。
        self._username_edit.clear()
        self._url_edit.clear()
        self._tags_edit.clear()
        self._notes_edit.clear()
        # 专用字段统一清除：遍历 _SPECIAL_SCHEMA 全表，覆盖 card_*（卡号/CVV 等）、
        # id_*（PII）以及 server_host 等所有专用字段。新增类型或字段时自动纳入清除
        # 范围，避免硬编码 key 列表遗漏导致的安全回归。QComboBox（如协议选择）非
        # 敏感输入，由 isinstance(QLineEdit) 守卫跳过。
        for specs in _SPECIAL_SCHEMA.values():
            for spec in specs:
                widget = self._special_widgets.get(spec.field_key)
                if isinstance(widget, QLineEdit):
                    widget.clear()
        # 自定义字段中回显模式为 Password 的值视为敏感数据一并清除
        self._cf_editor.clear_sensitive_values()

    def reject(self):
        """取消/关闭前清除敏感输入框。"""
        self._clear_sensitive_inputs()
        super().reject()

    def closeEvent(self, a0):
        """窗口关闭前清除敏感输入框。"""
        self._clear_sensitive_inputs()
        super().closeEvent(a0)
