"""条目编辑对话框，支持 5 种条目类型、TOTP 与自定义字段。

承载新增与编辑两套流程，按条目类型动态切换可见字段。专用字段以
类型前缀存入 custom_fields，与通用自定义字段统一序列化。涉及密码、
卡号、TOTP 密钥等敏感输入，保存或关闭时统一清除以缩短明文驻留时间。
"""

import logging
import re
from typing import cast

from PyQt6.QtCore import pyqtSignal
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

from ...business.services.password_service import PasswordService
from ...models import (
    ENTRY_TYPE_CARD,
    ENTRY_TYPE_IDENTITY,
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
from ..components.widgets import (
    create_password_toggle_btn,
    setup_dialog_flags,
    update_strength_label,
)
from ..resources.constants import (
    BTN_COPY,
    BTN_DIALOG,
    BTN_ICON,
    BTN_SMALL_ACTION,
    DIALOG_ENTRY_MIN_SIZE,
    PWD_GENERATE_LENGTH_DEFAULT,
    PWD_TOGGLE_AUTO_HIDE_SECONDS,
    PWD_VISIBLE_SECONDS_DEFAULT,
)
from ..resources.icons import CLOSE, GENERATE, LOCK, set_icon
from ..resources.theme_colors import c

logger = logging.getLogger(__name__)


# 各条目类型对应可见字段的映射，用于切换类型时刷新显隐
_TYPE_FIELDS = {
    'login':    ['title', 'username', 'password', 'url'],
    'card':     ['title', 'card_holder', 'card_number', 'card_expiry', 'card_cvv'],
    'identity': ['title', 'id_fullname', 'id_email', 'id_phone', 'id_address'],
    'note':     ['title'],
    'server':   ['title', 'server_host', 'server_port', 'server_protocol', 'username', 'password'],
}

# 专用字段在 custom_fields 中存储时携带的名称前缀，用于加载时区分归属类型
_SPECIAL_FIELD_PREFIXES = {
    '_card_': 'card',
    '_id_': 'identity',
    '_server_': 'server',
}


# ------------------------------------------------------------------
# 信用卡校验，作为模块级函数以便复用与单元测试
# ------------------------------------------------------------------

def validate_card_number(number: str) -> bool:
    """使用 Luhn 算法校验信用卡号是否合法。"""
    number = number.replace(' ', '').replace('-', '')
    if not number.isdigit() or len(number) < 13:
        return False
    total = 0
    for i, ch in enumerate(reversed(number)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def validate_card_expiry(expiry: str) -> bool:
    """校验有效期是否为 MM/YY 格式且月份在 1 至 12 之间。"""
    if not re.match(r'^\d{2}/\d{2}$', expiry):
        return False
    month = int(expiry[:2])
    return 1 <= month <= 12


def validate_card_cvv(cvv: str) -> bool:
    """校验 CVV 是否为 3 至 4 位数字。"""
    return cvv.isdigit() and 3 <= len(cvv) <= 4


class EntryDialog(QDialog):
    """密码条目新增与编辑对话框。

    ``entry`` 为 None 时进入新增模式，否则编辑该条目。保存成功后
    发出 ``saved`` 信号并关闭对话框。
    """

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
        self._custom_fields: list[CustomField] = []
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

        # ===== 类型选择 =====
        type_row = QHBoxLayout()
        type_label = QLabel('类型：')
        type_label.setStyleSheet(f'font-weight: bold; color: {c("text_secondary")};')
        type_row.addWidget(type_label)

        self._type_combo = QComboBox()
        for key, info in ENTRY_TYPES.items():
            self._type_combo.addItem(f"{info['icon']} {info['label']}", key)
        self._type_combo.currentIndexChanged.connect(self._on_type_changed)
        type_row.addWidget(self._type_combo, 1)
        layout.addLayout(type_row)

        # ===== 表单区域 =====
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
        self._strength_label.setStyleSheet(f'font-size: 11px; color: {c("text_muted")};')
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

        layout.addLayout(form)

        # ===== TOTP 区域 =====
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
        layout.addWidget(self._totp_group)

        # ===== 备注 =====
        notes_group = QGroupBox('备注')
        notes_layout = QVBoxLayout(notes_group)
        self._notes_edit = QTextEdit()
        self._notes_edit.setMaximumHeight(100)
        self._notes_edit.setPlaceholderText('添加备注信息...')
        notes_layout.addWidget(self._notes_edit)
        layout.addWidget(notes_group)

        # ===== 自定义字段 =====
        cf_group = QGroupBox('自定义字段')
        cf_layout = QVBoxLayout(cf_group)
        self._custom_fields_container = QVBoxLayout()
        self._custom_field_rows: list[tuple] = []  # 各元素依次为字段名、类型、值编辑框与所在行的四元组
        cf_layout.addLayout(self._custom_fields_container)

        add_cf_btn = QPushButton('+ 添加字段')
        add_cf_btn.setObjectName('iconBtn')
        add_cf_btn.setStyleSheet(f'text-align: left; color: {c("accent")};')
        add_cf_btn.clicked.connect(self._add_custom_field_row)
        cf_layout.addWidget(add_cf_btn)
        layout.addWidget(cf_group)

        # ===== 按钮 =====
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

        layout.addLayout(btn_layout)

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

    def _build_type_fields(self, form: QFormLayout):
        """创建各条目类型的专用字段并注册到 _special_widgets。

        所有字段初始为隐藏，由 _apply_type_visibility 按当前类型切换显隐。
        """
        # --- 卡片专用字段 ---
        card_holder = QLineEdit()
        card_holder.setPlaceholderText('持卡人姓名')
        self._add_field_row(form, 'card_holder', '持卡人：', card_holder, visible=False)
        self._special_widgets['card_holder'] = card_holder

        card_number = QLineEdit()
        card_number.setEchoMode(QLineEdit.EchoMode.Password)
        card_number.setPlaceholderText('卡号')
        self._add_field_row(form, 'card_number', '卡号：', card_number, visible=False)
        self._special_widgets['card_number'] = card_number
        card_number.textChanged.connect(self._format_card_number)

        card_expiry = QLineEdit()
        card_expiry.setPlaceholderText('MM/YY')
        card_expiry.setMaxLength(5)
        self._add_field_row(form, 'card_expiry', '有效期：', card_expiry, visible=False)
        self._special_widgets['card_expiry'] = card_expiry
        card_expiry.textChanged.connect(self._format_card_expiry)

        card_cvv = QLineEdit()
        card_cvv.setEchoMode(QLineEdit.EchoMode.Password)
        card_cvv.setPlaceholderText('CVV')
        card_cvv.setMaxLength(4)
        self._add_field_row(form, 'card_cvv', 'CVV：', card_cvv, visible=False)
        self._special_widgets['card_cvv'] = card_cvv

        # --- 身份专用字段 ---
        id_fullname = QLineEdit()
        id_fullname.setPlaceholderText('姓名')
        self._add_field_row(form, 'id_fullname', '姓名：', id_fullname, visible=False)
        self._special_widgets['id_fullname'] = id_fullname

        id_email = QLineEdit()
        id_email.setPlaceholderText('邮箱')
        self._add_field_row(form, 'id_email', '邮箱：', id_email, visible=False)
        self._special_widgets['id_email'] = id_email

        id_phone = QLineEdit()
        id_phone.setPlaceholderText('电话')
        self._add_field_row(form, 'id_phone', '电话：', id_phone, visible=False)
        self._special_widgets['id_phone'] = id_phone

        id_address = QLineEdit()
        id_address.setPlaceholderText('地址')
        self._add_field_row(form, 'id_address', '地址：', id_address, visible=False)
        self._special_widgets['id_address'] = id_address

        # --- 服务器专用字段 ---
        server_host = QLineEdit()
        server_host.setPlaceholderText('主机地址')
        self._add_field_row(form, 'server_host', '主机：', server_host, visible=False)
        self._special_widgets['server_host'] = server_host

        server_port = QLineEdit()
        server_port.setPlaceholderText('22')
        self._add_field_row(form, 'server_port', '端口：', server_port, visible=False)
        self._special_widgets['server_port'] = server_port

        server_protocol = QComboBox()
        server_protocol.addItems(['SSH', 'FTP', 'HTTP', 'HTTPS', '其他'])
        self._add_field_row(form, 'server_protocol', '协议：', server_protocol, visible=False)
        self._special_widgets['server_protocol'] = server_protocol

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
        """校验信用卡字段，失败时弹出警告并返回 False"""
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
            host = cast(QLineEdit, self._special_widgets['server_host']).text().strip()
            port = cast(QLineEdit, self._special_widgets['server_port']).text().strip()
            protocol = cast(QComboBox, self._special_widgets['server_protocol']).currentText().lower()
            if host:
                composed_url = f'{protocol}://{host}' + (f':{port}' if port else '')
                if len(composed_url) > MAX_FIELD_URL:
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
            self._notes_edit.setMaximumHeight(300)
        else:
            self._notes_edit.setMaximumHeight(100)

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

        # 从 custom_fields 恢复专用字段值
        cf_raw = entry.custom_fields
        if isinstance(cf_raw, list) and cf_raw:
            type_specific = []
            for cf in cf_raw:
                matched = False
                for prefix in _SPECIAL_FIELD_PREFIXES:
                    if cf.name.startswith(prefix):
                        field_key = cf.name[1:]  # 去掉前导下划线，例如 _card_holder 得到 card_holder
                        w = self._special_widgets.get(field_key)
                        if w:
                            if isinstance(w, QComboBox):
                                idx = w.findText(cf.value)
                                if idx >= 0:
                                    w.setCurrentIndex(idx)
                            else:
                                cast(QLineEdit, w).setText(cf.value)
                        matched = True
                        break
                if not matched:
                    type_specific.append(cf)

            # 清空旧的自定义字段行
            while self._custom_fields_container.count():
                item = self._custom_fields_container.takeAt(0)
                if item is None:
                    continue
                sub = item.layout()
                if sub is not None:
                    while sub.count():
                        w = sub.takeAt(0)
                        if w is not None:
                            widget = w.widget()
                            if widget is not None:
                                widget.deleteLater()
                    self._custom_fields_container.removeItem(sub)
                    sub.deleteLater()
            self._custom_field_rows.clear()

            # 剩余的作为通用自定义字段
            for cf in type_specific:
                self._add_custom_field_row(cf.name, cf.value, cf.field_type)

    # ------------------------------------------------------------------
    # 密码辅助
    # ------------------------------------------------------------------

    def _generate_password(self):
        length = PWD_GENERATE_LENGTH_DEFAULT
        if self._config:
            length = self._config.get('default_password_length', PWD_GENERATE_LENGTH_DEFAULT)
        password = PasswordService.generate(
            length=length,
            uppercase=self._config.get('default_uppercase', True) if self._config else True,
            lowercase=self._config.get('default_lowercase', True) if self._config else True,
            digits=self._config.get('default_digits', True) if self._config else True,
            symbols=self._config.get('default_symbols', True) if self._config else True,
            exclude_ambiguous=self._config.get('default_exclude_ambiguous', False) if self._config else False,
        )
        self._password_edit.setText(password)
        self._password_edit.setEchoMode(QLineEdit.EchoMode.Normal)
        set_icon(self._toggle_pwd_btn, LOCK)
        # 按钮内置自动隐藏定时器通过 Qt 动态属性暴露，此处取出并按配置启动
        timer = self._toggle_pwd_btn.property('autoHideTimer')
        if timer is not None:
            visible_seconds = PWD_VISIBLE_SECONDS_DEFAULT
            if self._config:
                visible_seconds = self._config.get('password_visible_seconds', PWD_VISIBLE_SECONDS_DEFAULT)
            timer.start(visible_seconds * 1000)

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
    # 自定义字段
    # ------------------------------------------------------------------

    def _add_custom_field_row(self, name: str = '', value: str = '', field_type: str = 'text'):
        """新增一行自定义字段，并绑定类型切换时切换回显模式。"""
        row_layout = QHBoxLayout()
        name_edit = QLineEdit(name)
        name_edit.setPlaceholderText('字段名')
        name_edit.setFixedWidth(120)
        row_layout.addWidget(name_edit)

        type_combo = QComboBox()
        type_combo.addItems(['文本', '密码', '网址', '邮箱'])
        type_combo.setCurrentIndex({'text': 0, 'password': 1, 'url': 2, 'email': 3}.get(field_type, 0))
        type_combo.setFixedWidth(64)
        type_combo.setToolTip('字段类型')
        row_layout.addWidget(type_combo)

        value_edit = QLineEdit(value)
        value_edit.setPlaceholderText('字段值')
        if field_type == 'password':
            value_edit.setEchoMode(QLineEdit.EchoMode.Password)
        type_combo.currentIndexChanged.connect(
            lambda idx, ve=value_edit: ve.setEchoMode(
                QLineEdit.EchoMode.Password if idx == 1 else QLineEdit.EchoMode.Normal
            )
        )
        row_layout.addWidget(value_edit)

        del_btn = QPushButton()
        del_btn.setObjectName('iconBtn')
        del_btn.setFixedSize(*BTN_COPY)
        set_icon(del_btn, CLOSE, 'danger')
        del_btn.clicked.connect(lambda: self._remove_custom_field_row(row_layout))
        row_layout.addWidget(del_btn)

        self._custom_fields_container.addLayout(row_layout)
        self._custom_field_rows.append((name_edit, type_combo, value_edit, row_layout))

    def _remove_custom_field_row(self, layout: QHBoxLayout):
        """按 layout 引用定位并移除一行自定义字段。"""
        # 按 layout 引用直接匹配移除，避免依据索引错位
        self._custom_field_rows = [
            row for row in self._custom_field_rows if row[3] is not layout
        ]
        while layout.count():
            item = layout.takeAt(0)
            if item is not None:
                w = item.widget()
                if w is not None:
                    w.deleteLater()
        self._custom_fields_container.removeItem(layout)

    def _collect_custom_fields(self) -> list[CustomField]:
        """收集用户填写的通用自定义字段，忽略名称为空者。"""
        fields = []
        type_map = {0: 'text', 1: 'password', 2: 'url', 3: 'email'}
        for name_edit, type_combo, value_edit, _layout in self._custom_field_rows:
            if name_edit.text().strip():
                ft = type_map.get(type_combo.currentIndex(), 'text')
                fields.append(CustomField(
                    name=name_edit.text().strip(),
                    value=value_edit.text(),
                    field_type=ft,
                ))
        return fields

    # ------------------------------------------------------------------
    # 专用字段收集
    # ------------------------------------------------------------------

    def _collect_type_specific_fields(self) -> list[CustomField]:
        """将当前类型的专用字段收集为 CustomField，名称带类型前缀。"""
        fields: list[CustomField] = []
        entry_type = self._type_combo.currentData() or ENTRY_TYPE_LOGIN

        if entry_type == ENTRY_TYPE_CARD:
            w = self._special_widgets
            fields.append(CustomField(name='_card_holder', value=cast(QLineEdit, w['card_holder']).text()))
            raw_number = cast(QLineEdit, w['card_number']).text().replace(' ', '')
            fields.append(CustomField(name='_card_number', value=raw_number, field_type='password'))
            fields.append(CustomField(name='_card_expiry', value=cast(QLineEdit, w['card_expiry']).text()))
            fields.append(CustomField(name='_card_cvv', value=cast(QLineEdit, w['card_cvv']).text(), field_type='password'))

        elif entry_type == ENTRY_TYPE_IDENTITY:
            w = self._special_widgets
            fields.append(CustomField(name='_id_fullname', value=cast(QLineEdit, w['id_fullname']).text()))
            fields.append(CustomField(name='_id_email', value=cast(QLineEdit, w['id_email']).text()))
            fields.append(CustomField(name='_id_phone', value=cast(QLineEdit, w['id_phone']).text()))
            fields.append(CustomField(name='_id_address', value=cast(QLineEdit, w['id_address']).text()))

        elif entry_type == ENTRY_TYPE_SERVER:
            w = self._special_widgets
            fields.append(CustomField(name='_server_host', value=cast(QLineEdit, w['server_host']).text()))
            fields.append(CustomField(name='_server_port', value=cast(QLineEdit, w['server_port']).text()))
            protocol = cast(QComboBox, w['server_protocol']).currentText()
            fields.append(CustomField(name='_server_protocol', value=protocol))

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

        # 服务器类型由 host 与 port 拼接出 url
        if entry_type == ENTRY_TYPE_SERVER:
            host = cast(QLineEdit, self._special_widgets['server_host']).text().strip()
            port = cast(QLineEdit, self._special_widgets['server_port']).text().strip()
            protocol = cast(QComboBox, self._special_widgets['server_protocol']).currentText().lower()
            if host:
                url = f'{protocol}://{host}' + (f':{port}' if port else '')
            username = self._username_edit.text().strip()
            password = self._password_edit.text()

        # 合并专用字段 + 通用自定义字段
        all_custom = self._collect_type_specific_fields() + self._collect_custom_fields()

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
        # 信用卡敏感字段，覆盖持卡人、卡号、有效期与 CVV
        for key in ('card_holder', 'card_number', 'card_expiry', 'card_cvv'):
            widget = self._special_widgets.get(key)
            if isinstance(widget, QLineEdit):
                widget.clear()
        # 身份信息 PII 字段
        for key in ('id_fullname', 'id_email', 'id_phone', 'id_address'):
            widget = self._special_widgets.get(key)
            if isinstance(widget, QLineEdit):
                widget.clear()
        # 自定义字段中回显模式为 Password 的值视为敏感数据一并清除
        for _name_edit, _type_combo, value_edit, _layout in self._custom_field_rows:
            if value_edit.echoMode() == QLineEdit.EchoMode.Password:
                value_edit.clear()

    def reject(self):
        """取消/关闭前清除敏感输入框。"""
        self._clear_sensitive_inputs()
        super().reject()

    def closeEvent(self, a0):
        """窗口关闭前清除敏感输入框。"""
        self._clear_sensitive_inputs()
        super().closeEvent(a0)
