"""条目编辑对话框 - 支持 5 种条目类型、TOTP、标签自动补全"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTextEdit, QComboBox, QCheckBox, QWidget,
    QFormLayout, QGroupBox, QScrollArea, QMessageBox,
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer

from ..database.models import Category, CustomField, Entry
from ..database.models import ENTRY_TYPES, ENTRY_TYPE_LOGIN, ENTRY_TYPE_NOTE, ENTRY_TYPE_SERVER, ENTRY_TYPE_CARD, ENTRY_TYPE_IDENTITY
from ..crypto.password_generator import PasswordGenerator
from ..crypto.totp import TOTPGenerator
from ..ui.resources.theme_colors import c
from ..ui.resources.icons import set_icon, EYE, EYE_SLASH, LOCK, GENERATE, CLOSE, SIZE_BTN


# 各类型可见字段映射
_TYPE_FIELDS = {
    'login':    ['title', 'username', 'password', 'url'],
    'card':     ['title', 'card_holder', 'card_number', 'card_expiry', 'card_cvv'],
    'identity': ['title', 'id_fullname', 'id_email', 'id_phone', 'id_address'],
    'note':     ['title'],
    'server':   ['title', 'server_host', 'server_port', 'server_protocol', 'username', 'password'],
}

# 专用字段名前缀 -> 类型映射
_SPECIAL_FIELD_PREFIXES = {
    '_card_': 'card',
    '_id_': 'identity',
    '_server_': 'server',
}


class EntryDialog(QDialog):
    """密码条目编辑对话框"""

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

        # 密码生成后自动隐藏定时器
        self._pwd_auto_hide_timer = QTimer(self)
        self._pwd_auto_hide_timer.setSingleShot(True)
        self._pwd_auto_hide_timer.timeout.connect(self._auto_hide_pwd_field)

        self._setup_ui()
        if entry:
            self._load_entry(entry)

    # ------------------------------------------------------------------
    # UI 构建
    # ------------------------------------------------------------------

    def _setup_ui(self):
        self.setWindowTitle('编辑条目' if self._entry else '新增条目')
        self.setMinimumSize(560, 620)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)

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
        self._add_field_row(form, 'title', '标题 *：', self._title_edit)

        self._username_edit = QLineEdit()
        self._username_edit.setPlaceholderText('用户名或邮箱')
        self._add_field_row(form, 'username', '账号：', self._username_edit)

        # 密码行
        pwd_layout = QHBoxLayout()
        self._password_edit = QLineEdit()
        self._password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._password_edit.setPlaceholderText('密码')
        pwd_layout.addWidget(self._password_edit)

        self._toggle_pwd_btn = QPushButton()
        self._toggle_pwd_btn.setObjectName('iconBtn')
        self._toggle_pwd_btn.setFixedSize(32, 32)
        set_icon(self._toggle_pwd_btn, EYE)
        self._toggle_pwd_btn.clicked.connect(self._toggle_password)
        pwd_layout.addWidget(self._toggle_pwd_btn)

        gen_btn = QPushButton()
        gen_btn.setObjectName('iconBtn')
        gen_btn.setFixedSize(32, 32)
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
        self._add_field_row(form, 'url', '网址：', self._url_edit)

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

        # --- 公共尾部字段 ---
        self._category_combo = QComboBox()
        self._category_combo.addItem('未分类', None)
        for cat in self._categories:
            self._category_combo.addItem(f"{cat.icon_char} {cat.name}", cat.id)
        self._add_field_row(form, 'category', '分类：', self._category_combo)

        self._tags_edit = QLineEdit()
        self._tags_edit.setPlaceholderText('用逗号分隔多个标签')
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
        self._totp_edit.setPlaceholderText('输入 Base32 密钥或 otpauth:// URI（可选）')
        totp_layout.addWidget(self._totp_edit, 1)
        self._totp_test_btn = QPushButton('验证')
        self._totp_test_btn.setFixedSize(60, 28)
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
        cancel_btn.setFixedSize(90, 34)
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)

        save_btn = QPushButton('保存')
        save_btn.setObjectName('primaryBtn')
        save_btn.setFixedSize(90, 34)
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

    def _add_field_row(self, form: QFormLayout, key: str, label_text: str, widget: QWidget, visible: bool = True):
        """添加一行表单字段，同时记录到 _field_rows 字典中以便按 key 控制显隐"""
        label = QLabel(label_text)
        if not visible:
            label.setVisible(False)
            widget.setVisible(False)
        form.addRow(label, widget)
        self._field_rows[key] = (label, widget)

    # ------------------------------------------------------------------
    # 信用卡校验
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_card_number(number: str) -> bool:
        """Luhn 算法验证信用卡号"""
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

    @staticmethod
    def _validate_card_expiry(expiry: str) -> bool:
        """验证 MM/YY 格式"""
        import re
        if not re.match(r'^\d{2}/\d{2}$', expiry):
            return False
        month = int(expiry[:2])
        return 1 <= month <= 12

    @staticmethod
    def _validate_card_cvv(cvv: str) -> bool:
        """CVV 必须为 3-4 位数字"""
        return cvv.isdigit() and 3 <= len(cvv) <= 4

    def _validate_card_fields(self) -> bool:
        """校验信用卡字段，失败时弹出警告并返回 False"""
        w = self._special_widgets
        card_number = w['card_number'].text().strip()
        card_expiry = w['card_expiry'].text().strip()
        card_cvv = w['card_cvv'].text().strip()

        if card_number and not self._validate_card_number(card_number):
            QMessageBox.warning(self, '校验失败', '卡号格式不正确，请检查后重试。')
            return False
        if card_expiry and not self._validate_card_expiry(card_expiry):
            QMessageBox.warning(self, '校验失败', '有效期格式不正确，应为 MM/YY，且月份在 01-12 之间。')
            return False
        if card_cvv and not self._validate_card_cvv(card_cvv):
            QMessageBox.warning(self, '校验失败', 'CVV 应为 3-4 位数字。')
            return False
        return True

    def _format_card_number(self, text: str):
        """卡号输入时自动每 4 位加空格"""
        w = self._special_widgets['card_number']
        w.blockSignals(True)
        digits = text.replace(' ', '')
        if digits and len(digits) % 5 == 0 and not text.endswith(' '):
            # 用户正在输入，自动在每4位后插入空格
            pass
        formatted = ' '.join(digits[i:i+4] for i in range(0, len(digits), 4))
        if formatted != text:
            # 保留光标位置
            cursor_pos = w.cursorPosition()
            offset = len(formatted) - len(text)
            w.setText(formatted)
            w.setCursorPosition(cursor_pos + offset)
        w.blockSignals(False)

    def _format_card_expiry(self, text: str):
        """有效期输入时自动插入 / 分隔符"""
        w = self._special_widgets['card_expiry']
        w.blockSignals(True)
        digits = text.replace('/', '')
        if len(digits) > 2:
            formatted = digits[:2] + '/' + digits[2:4]
        else:
            formatted = digits
        if formatted != text:
            cursor_pos = w.cursorPosition()
            w.setText(formatted)
            w.setCursorPosition(len(formatted))
        w.blockSignals(False)

    # ------------------------------------------------------------------
    # 类型切换
    # ------------------------------------------------------------------

    def _on_type_changed(self, index: int):
        """条目类型变更，更新字段可见性"""
        new_type = self._type_combo.currentData() or ENTRY_TYPE_LOGIN

        if new_type == self._current_type:
            return

        # 编辑模式下检查是否有未保存的专用字段数据
        if self._entry is not None and self._current_type:
            old_fields = _TYPE_FIELDS.get(self._current_type, [])
            has_data = False
            for key in old_fields:
                if key in self._special_widgets:
                    widget = self._special_widgets[key]
                    text = widget.text() if hasattr(widget, 'text') else ''
                    if text.strip():
                        has_data = True
                        break

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
        """按条目类型刷新字段显隐，不触发类型切换确认。"""
        visible_keys = set(_TYPE_FIELDS.get(entry_type, _TYPE_FIELDS['login']))

        for key, (label, widget) in self._field_rows.items():
            # _strength 行跟随 password
            if key == '_strength':
                show = 'password' in visible_keys
            # category / tags / favorite / 自定义字段区域始终可见（不在 _field_rows 中）
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
        """加载条目数据到表单"""
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
        if entry.custom_fields:
            type_specific = []
            for cf in entry.custom_fields:
                matched = False
                for prefix in _SPECIAL_FIELD_PREFIXES:
                    if cf.name.startswith(prefix):
                        field_key = cf.name[1:]  # e.g. '_card_holder' -> 'card_holder'
                        w = self._special_widgets.get(field_key)
                        if w:
                            if isinstance(w, QComboBox):
                                idx = w.findText(cf.value)
                                if idx >= 0:
                                    w.setCurrentIndex(idx)
                            else:
                                w.setText(cf.value)
                        matched = True
                        break
                if not matched:
                    type_specific.append(cf)

            # 剩余的作为通用自定义字段
            for cf in type_specific:
                self._add_custom_field_row(cf.name, cf.value, cf.field_type)

    # ------------------------------------------------------------------
    # 密码辅助
    # ------------------------------------------------------------------

    def _toggle_password(self):
        if self._password_edit.echoMode() == QLineEdit.EchoMode.Password:
            self._password_edit.setEchoMode(QLineEdit.EchoMode.Normal)
            set_icon(self._toggle_pwd_btn, LOCK)
        else:
            self._password_edit.setEchoMode(QLineEdit.EchoMode.Password)
            set_icon(self._toggle_pwd_btn, EYE)
            self._pwd_auto_hide_timer.stop()

    def _auto_hide_pwd_field(self):
        self._password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        set_icon(self._toggle_pwd_btn, EYE)

    def _generate_password(self):
        length = 16
        if self._config:
            length = self._config.get('default_password_length', 16)
        password = PasswordGenerator.generate(
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
        visible_seconds = 10
        if self._config:
            visible_seconds = self._config.get('password_visible_seconds', 10)
        self._pwd_auto_hide_timer.start(visible_seconds * 1000)

    def _on_password_changed(self, text: str):
        if text:
            strength = PasswordGenerator.check_strength(text)
            from ..ui.resources.theme_colors import get_strength_color
            color = get_strength_color(strength.score)
            self._strength_label.setText(f'强度：{strength.label}')
            self._strength_label.setStyleSheet(f'color: {color}; font-size: 11px;')
        else:
            self._strength_label.setText('')

    # ------------------------------------------------------------------
    # TOTP
    # ------------------------------------------------------------------

    def _test_totp(self):
        """测试 TOTP 密钥有效性"""
        secret = self._totp_edit.text().strip()
        if not secret:
            return
        if TOTPGenerator.validate_secret(secret):
            code = TOTPGenerator.generate(secret)
            QMessageBox.information(self, '验证成功', f'密钥有效\n当前验证码：{code}')
        else:
            QMessageBox.warning(self, '验证失败', '无效的 TOTP 密钥或 URI，请检查后重试。')

    # ------------------------------------------------------------------
    # 自定义字段
    # ------------------------------------------------------------------

    def _add_custom_field_row(self, name: str = '', value: str = '', field_type: str = 'text'):
        """添加自定义字段行"""
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
        del_btn.setFixedSize(28, 28)
        set_icon(del_btn, CLOSE, 'danger')
        del_btn.clicked.connect(lambda: self._remove_custom_field_row(row_layout))
        row_layout.addWidget(del_btn)

        self._custom_fields_container.addLayout(row_layout)

    def _remove_custom_field_row(self, layout: QHBoxLayout):
        """移除自定义字段行"""
        while layout.count():
            item = layout.takeAt(0)
            w = item.widget() if item else None
            if w:
                w.deleteLater()
        self._custom_fields_container.removeItem(layout)

    def _collect_custom_fields(self) -> list[CustomField]:
        """收集自定义字段"""
        fields = []
        type_map = {0: 'text', 1: 'password', 2: 'url', 3: 'email'}
        for i in range(self._custom_fields_container.count()):
            row = self._custom_fields_container.itemAt(i)
            if row and isinstance(row, QHBoxLayout):
                name_edit = None
                value_edit = None
                type_combo = None
                for j in range(row.count()):
                    item = row.itemAt(j)
                    if item and item.widget():
                        widget = item.widget()
                        if isinstance(widget, QComboBox):
                            type_combo = widget
                        elif isinstance(widget, QLineEdit):
                            if name_edit is None:
                                name_edit = widget
                            else:
                                value_edit = widget
                if name_edit and value_edit and name_edit.text().strip():
                    ft = type_map.get(type_combo.currentIndex(), 'text') if type_combo else 'text'
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
        """将当前类型的专用字段收集为 CustomField（name 带类型前缀）"""
        fields: list[CustomField] = []
        entry_type = self._type_combo.currentData() or ENTRY_TYPE_LOGIN

        if entry_type == ENTRY_TYPE_CARD:
            w = self._special_widgets
            fields.append(CustomField(name='_card_holder', value=w['card_holder'].text()))
            raw_number = w['card_number'].text().replace(' ', '')
            fields.append(CustomField(name='_card_number', value=raw_number, field_type='password'))
            fields.append(CustomField(name='_card_expiry', value=w['card_expiry'].text()))
            fields.append(CustomField(name='_card_cvv', value=w['card_cvv'].text(), field_type='password'))

        elif entry_type == ENTRY_TYPE_IDENTITY:
            w = self._special_widgets
            fields.append(CustomField(name='_id_fullname', value=w['id_fullname'].text()))
            fields.append(CustomField(name='_id_email', value=w['id_email'].text()))
            fields.append(CustomField(name='_id_phone', value=w['id_phone'].text()))
            fields.append(CustomField(name='_id_address', value=w['id_address'].text()))

        elif entry_type == ENTRY_TYPE_SERVER:
            w = self._special_widgets
            fields.append(CustomField(name='_server_host', value=w['server_host'].text()))
            fields.append(CustomField(name='_server_port', value=w['server_port'].text()))
            protocol = w['server_protocol'].currentText()
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

        # 信用卡类型校验
        if entry_type == ENTRY_TYPE_CARD:
            if not self._validate_card_fields():
                return

        # 笔记类型的 password 置空
        password = self._password_edit.text() if entry_type != ENTRY_TYPE_NOTE else ''
        username = self._username_edit.text().strip()
        url = self._url_edit.text().strip()

        # 服务器类型：用 host+port 构造 url
        if entry_type == ENTRY_TYPE_SERVER:
            host = self._special_widgets['server_host'].text().strip()
            port = self._special_widgets['server_port'].text().strip()
            protocol = self._special_widgets['server_protocol'].currentText().lower()
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
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, '错误', f'保存失败：{e}')
