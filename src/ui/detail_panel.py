"""详情面板 - 展示密码条目详细信息（重构版）"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QGroupBox, QFormLayout, QScrollArea, QProgressBar, QFrame,
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer

from ..database.models import Entry
from ..crypto.password_generator import PasswordGenerator
from ..crypto.totp import TOTPGenerator
from ..ui.resources.theme_colors import c, get_strength_color
from ..ui.resources.icons import (
    set_icon, set_icon_with_text, EYE, LOCK, COPY, CHECK, EDIT, DELETE,
    STAR, STAR_OUTLINE, SIZE_BTN, SIZE_SMALL,
)


class DetailPanel(QWidget):
    """密码条目详情面板"""

    edit_requested = pyqtSignal(int)
    delete_requested = pyqtSignal(int)
    favorite_toggled = pyqtSignal(int)
    copy_feedback = pyqtSignal()

    def __init__(self, clipboard_manager, entry_manager=None, config=None, parent=None):
        super().__init__(parent)
        self.setObjectName('detailPanel')
        self._clipboard = clipboard_manager
        self._entry_mgr = entry_manager
        self._config = config
        self._current_entry: Entry | None = None
        self._pwd_hide_timer = QTimer(self)
        self._pwd_hide_timer.setSingleShot(True)
        self._pwd_hide_timer.timeout.connect(self._auto_hide_password)
        self._pwd_label_ref = None
        self._show_btn_ref = None
        self._totp_timer = QTimer(self)
        self._totp_timer.timeout.connect(self._refresh_totp)
        self._totp_code_label = None
        self._totp_bar = None
        self._totp_secret = ''
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # 顶部工具栏
        toolbar = QHBoxLayout()
        toolbar.setContentsMargins(16, 12, 16, 8)

        self._title_label = QLabel('选择一个条目查看详情')
        self._title_label.setObjectName('sectionLabel')
        self._title_label.setStyleSheet(
            f'font-size: 16px; font-weight: bold; color: {c("text_primary")};'
        )
        self._title_label.setWordWrap(True)
        toolbar.addWidget(self._title_label)

        toolbar.addStretch()

        self._fav_btn = QPushButton()
        set_icon(self._fav_btn, STAR_OUTLINE)
        self._fav_btn.setObjectName('iconBtn')
        self._fav_btn.setFixedSize(32, 32)
        self._fav_btn.setToolTip('收藏')
        self._fav_btn.hide()
        toolbar.addWidget(self._fav_btn)

        self._edit_btn = QPushButton()
        set_icon(self._edit_btn, EDIT)
        self._edit_btn.setObjectName('iconBtn')
        self._edit_btn.setFixedSize(32, 32)
        self._edit_btn.setToolTip('编辑')
        self._edit_btn.hide()
        toolbar.addWidget(self._edit_btn)

        self._delete_btn = QPushButton()
        set_icon(self._delete_btn, DELETE)
        self._delete_btn.setObjectName('iconBtn')
        self._delete_btn.setFixedSize(32, 32)
        self._delete_btn.setToolTip('删除')
        self._delete_btn.hide()
        toolbar.addWidget(self._delete_btn)

        layout.addLayout(toolbar)

        # 分隔线
        self._divider = QFrame()
        self._divider.setFixedHeight(1)
        self._divider.setStyleSheet(f'background: {c("divider")};')
        layout.addWidget(self._divider)

        # 滚动内容
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        self._content = QWidget()
        self._content_layout = QVBoxLayout(self._content)
        self._content_layout.setContentsMargins(20, 16, 20, 16)
        self._content_layout.setSpacing(10)

        # 空状态
        self._empty_label = QLabel('📋\n\n从列表中选择一个条目\n以查看详细信息')
        self._empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty_label.setStyleSheet(f'color: {c("text_muted")}; font-size: 14px;')
        self._content_layout.addWidget(self._empty_label)

        scroll.setWidget(self._content)
        layout.addWidget(scroll)

    def show_entry(self, entry: Entry):
        """显示条目详情"""
        self._current_entry = entry
        self._pwd_hide_timer.stop()
        self._totp_timer.stop()
        self._clear_content()

        # 更新标题
        self._title_label.setText(f'{entry.type_icon} {entry.title}')
        self._edit_btn.setVisible(not entry.is_deleted)
        self._delete_btn.setVisible(not entry.is_deleted)
        self._fav_btn.setVisible(not entry.is_deleted)
        if not entry.is_deleted:
            set_icon(self._fav_btn, STAR if entry.is_favorite else STAR_OUTLINE)
        # 连接信号
        try:
            self._edit_btn.clicked.disconnect()
        except TypeError:
            pass
        self._edit_btn.clicked.connect(lambda: self.edit_requested.emit(entry.id))
        try:
            self._delete_btn.clicked.disconnect()
        except TypeError:
            pass
        self._delete_btn.clicked.connect(lambda: self.delete_requested.emit(entry.id))
        try:
            self._fav_btn.clicked.disconnect()
        except TypeError:
            pass
        self._fav_btn.clicked.connect(lambda: self.favorite_toggled.emit(entry.id))

        # ===== 头部信息区：分类 + 标签 =====
        header_info = QHBoxLayout()
        header_info.setSpacing(8)

        if entry.category_name:
            cat_tag = QLabel(f'  {entry.category_name}  ')
            cat_tag.setStyleSheet(
                f'background: {c("tag_bg")}; color: {c("tag_text")}; '
                f'border: 1px solid {c("tag_border")}; border-radius: 10px; '
                f'font-size: 11px; padding: 2px 8px;'
            )
            header_info.addWidget(cat_tag)

        if entry.entry_type and entry.entry_type != 'login':
            type_tag = QLabel(f'  {entry.type_label}  ')
            type_tag.setStyleSheet(
                f'background: {c("accent_light")}; color: {c("accent_text")}; '
                f'border-radius: 10px; font-size: 11px; padding: 2px 8px;'
            )
            header_info.addWidget(type_tag)

        for tag in entry.get_tag_list()[:5]:
            tag_label = QLabel(f'  {tag}  ')
            tag_label.setStyleSheet(
                f'background: {c("tag_bg")}; color: {c("tag_text")}; '
                f'border: 1px solid {c("tag_border")}; border-radius: 10px; '
                f'font-size: 11px; padding: 2px 6px;'
            )
            header_info.addWidget(tag_label)

        header_info.addStretch()
        self._content_layout.addLayout(header_info)

        if entry.integrity_error:
            warning = QLabel(
                f'部分数据无法解密：{entry.integrity_message}。为保护原始数据，已禁用编辑。'
            )
            warning.setWordWrap(True)
            warning.setStyleSheet(
                f'background: {c("danger_light")}; color: {c("danger")}; '
                f'border: 1px solid {c("danger")}; border-radius: 6px; padding: 10px;'
            )
            self._content_layout.addWidget(warning)
            self._edit_btn.hide()

        # ===== 核心信息区 =====
        core_form = QFormLayout()
        core_form.setSpacing(10)
        core_form.setHorizontalSpacing(16)

        # 账号
        if entry.username:
            core_form.addRow(*self._make_row('账号', entry.username, True))

        # 密码
        if entry.password:
            core_form.addRow(*self._make_password_row(entry.password))

        # 网址
        if entry.url:
            url_label = QLabel(f'<a href="{entry.url}" style="color: {c("link")}; text-decoration:none;">{entry.url}</a>')
            url_label.setWordWrap(True)
            url_label.setTextFormat(Qt.TextFormat.RichText)
            url_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
            url_label.setOpenExternalLinks(True)
            core_form.addRow('网址：', url_label)

        self._content_layout.addLayout(core_form)

        # ===== 密码强度进度条 =====
        if entry.password:
            strength = PasswordGenerator.check_strength(entry.password)
            strength_color = get_strength_color(strength.score)

            strength_row = QHBoxLayout()
            strength_row.setSpacing(8)

            strength_label_title = QLabel('强度：')
            strength_label_title.setStyleSheet(f'font-weight: bold; color: {c("text_secondary")};')
            strength_row.addWidget(strength_label_title)

            bar = QProgressBar()
            bar.setRange(0, 4)
            bar.setValue(strength.score)
            bar.setFixedHeight(8)
            bar.setTextVisible(False)
            bar.setStyleSheet(f"""
                QProgressBar {{ background: {c("progress_bg")}; border: none; border-radius: 4px; }}
                QProgressBar::chunk {{ background: {strength_color}; border-radius: 4px; }}
            """)
            strength_row.addWidget(bar, 1)

            strength_text = QLabel(f'{strength.label} ({strength.score}/4)')
            strength_text.setStyleSheet(f'color: {strength_color}; font-weight: bold; font-size: 12px;')
            strength_row.addWidget(strength_text)

            self._content_layout.addLayout(strength_row)

        # ===== TOTP 区域 =====
        if entry.has_totp:
            self._build_totp_section(entry.totp_secret)

        # ===== 密码历史 =====
        if entry.id and self._entry_mgr:
            history = self._entry_mgr.get_password_history(entry.id)
            if history:
                decrypted_history = self._entry_mgr.decrypt_password_history(history)
                if decrypted_history:
                    self._build_password_history(decrypted_history)

        # ===== 时间 =====
        meta_form = QFormLayout()
        meta_form.setSpacing(4)
        meta_form_label_style = f'color: {c("text_muted")}; font-size: 12px;'
        if entry.created_at:
            meta_form.addRow(
                QLabel('创建：'),
                QLabel(self._format_time(entry.created_at))
            )
        if entry.updated_at:
            meta_form.addRow(
                QLabel('更新：'),
                QLabel(self._format_time(entry.updated_at))
            )
        if entry.password and entry.password_changed_at:
            meta_form.addRow(
                QLabel('密码更新：'),
                QLabel(self._format_time(entry.password_changed_at))
            )
        for i in range(meta_form.count()):
            item = meta_form.itemAt(i)
            if item and item.widget():
                item.widget().setStyleSheet(meta_form_label_style)
        if meta_form.count() > 0:
            self._content_layout.addLayout(meta_form)

        # ===== 备注 =====
        if entry.notes:
            notes_group = QGroupBox('备注')
            notes_layout = QVBoxLayout(notes_group)
            notes_label = QLabel(entry.notes)
            notes_label.setWordWrap(True)
            notes_label.setStyleSheet(f'color: {c("text_primary")}; font-size: 13px;')
            notes_layout.addWidget(notes_label)
            self._content_layout.addWidget(notes_group)

        # ===== 自定义字段 =====
        if entry.custom_fields:
            cf_group = QGroupBox('自定义字段')
            cf_layout = QFormLayout(cf_group)
            cf_layout.setSpacing(6)
            labels = {
                '_card_holder': '持卡人', '_card_number': '卡号',
                '_card_expiry': '有效期', '_card_cvv': 'CVV',
                '_id_fullname': '姓名', '_id_email': '邮箱',
                '_id_phone': '电话', '_id_address': '地址',
                '_server_host': '主机', '_server_port': '端口',
                '_server_protocol': '协议',
            }
            for cf in entry.custom_fields:
                if not cf.value:
                    continue
                icon = {'password': '🔒', 'url': '🌐', 'email': '📧'}.get(cf.field_type, '📝')
                label = labels.get(cf.name, cf.name)
                if cf.field_type == 'password':
                    cf_layout.addRow(*self._make_secret_row(f'{icon} {label}', cf.value))
                else:
                    cf_layout.addRow(*self._make_row(f'{icon} {label}', cf.value, True))
            self._content_layout.addWidget(cf_group)

        self._content_layout.addStretch()

    def _build_totp_section(self, secret: str):
        """构建 TOTP 验证码区域"""
        self._totp_secret = secret

        totp_frame = QFrame()
        totp_frame.setStyleSheet(f"""
            QFrame {{
                background: {c("accent_light")};
                border: 1px solid {c("tag_border")};
                border-radius: 8px;
                padding: 8px;
            }}
        """)
        totp_layout = QVBoxLayout(totp_frame)
        totp_layout.setSpacing(6)

        totp_title = QLabel('🔐 验证码 (TOTP)')
        totp_title.setStyleSheet(f'font-weight: bold; font-size: 13px; color: {c("accent_text")};')
        totp_layout.addWidget(totp_title)

        code_row = QHBoxLayout()
        code_row.setSpacing(12)

        code = TOTPGenerator.generate(secret)
        self._totp_code_label = QLabel(code)
        self._totp_code_label.setStyleSheet(
            f'font-size: 28px; font-weight: bold; letter-spacing: 6px; '
            f'color: {c("accent_text")}; font-family: monospace;'
        )
        code_row.addWidget(self._totp_code_label)

        # 倒计时进度条
        remaining = TOTPGenerator.get_remaining_seconds(secret=secret)
        self._totp_bar = QProgressBar()
        self._totp_bar.setRange(0, TOTPGenerator.get_period(secret))
        self._totp_bar.setValue(remaining)
        self._totp_bar.setFixedHeight(6)
        self._totp_bar.setTextVisible(False)
        self._totp_bar.setStyleSheet(f"""
            QProgressBar {{ background: {c("border_light")}; border: none; border-radius: 3px; }}
            QProgressBar::chunk {{ background: {c("accent")}; border-radius: 3px; }}
        """)
        code_row.addWidget(self._totp_bar, 1)

        # 复制按钮
        copy_btn = QPushButton()
        set_icon_with_text(copy_btn, '复制', COPY)
        copy_btn.setFixedSize(72, 30)
        copy_btn.clicked.connect(self._copy_totp_code)
        copy_btn.clicked.connect(self.copy_feedback.emit)
        code_row.addWidget(copy_btn)

        totp_layout.addLayout(code_row)
        self._content_layout.addWidget(totp_frame)

        # 启动定时刷新（每秒）
        self._totp_timer.start(1000)

    def _refresh_totp(self):
        """刷新 TOTP 验证码"""
        if not self._totp_secret or not self._totp_code_label:
            self._totp_timer.stop()
            return
        code = TOTPGenerator.generate(self._totp_secret)
        self._totp_code_label.setText(code)
        remaining = TOTPGenerator.get_remaining_seconds(secret=self._totp_secret)
        if self._totp_bar:
            self._totp_bar.setValue(remaining)

    def _copy_totp_code(self):
        """复制当前 TOTP 验证码（始终取最新值）"""
        if self._totp_code_label:
            self._copy(self._totp_code_label.text())

    def _build_password_history(self, history: list[dict]):
        """构建密码历史折叠区"""
        group = QGroupBox('🕐 密码历史')
        group_layout = QVBoxLayout(group)
        group_layout.setSpacing(6)

        for record in history[:5]:
            row = QHBoxLayout()
            row.setSpacing(8)

            # 时间
            time_label = QLabel(record.get('changed_at', ''))
            time_label.setFixedWidth(140)
            time_label.setStyleSheet(f'color: {c("text_muted")}; font-size: 12px;')
            row.addWidget(time_label)

            # 密码（初始隐藏）
            pwd_text = record.get('password', '')
            pwd_label = QLabel('••••••••')
            pwd_label.setStyleSheet(
                f'font-family: monospace; font-size: 12px; color: {c("text_primary")};'
            )
            row.addWidget(pwd_label, 1)

            # 显示/隐藏按钮
            show_btn = QPushButton()
            set_icon(show_btn, EYE)
            show_btn.setObjectName('iconBtn')
            show_btn.setFixedSize(24, 24)
            show_btn.setToolTip('显示/隐藏')

            def toggle_pwd(_checked=False, lbl=pwd_label, btn=show_btn, text=pwd_text):
                if lbl.text() == '••••••••':
                    lbl.setText(text)
                    set_icon(btn, LOCK)
                else:
                    lbl.setText('••••••••')
                    set_icon(btn, EYE)

            show_btn.clicked.connect(toggle_pwd)
            row.addWidget(show_btn)

            # 复制按钮
            copy_btn = QPushButton()
            set_icon(copy_btn, COPY)
            copy_btn.setObjectName('iconBtn')
            copy_btn.setFixedSize(24, 24)
            copy_btn.setToolTip('复制密码')

            def do_copy(_checked=False, text=pwd_text, btn=copy_btn):
                self._copy(text)
                set_icon(btn, CHECK, 'success')
                QTimer.singleShot(1500, lambda: set_icon(btn, COPY))

            copy_btn.clicked.connect(do_copy)
            copy_btn.clicked.connect(self.copy_feedback.emit)
            row.addWidget(copy_btn)

            group_layout.addLayout(row)

        self._content_layout.addWidget(group)

    def _make_row(self, label: str, value: str, copyable: bool) -> tuple[QLabel, QWidget]:
        """创建带复制按钮的行"""
        name_label = QLabel(f'{label}：')
        name_label.setStyleSheet(f'font-weight: bold; color: {c("text_secondary")};')

        row_widget = QWidget()
        row_layout = QHBoxLayout(row_widget)
        row_layout.setContentsMargins(0, 0, 0, 0)

        val_label = QLabel(value)
        val_label.setWordWrap(True)
        val_label.setStyleSheet(f'color: {c("text_primary")};')
        row_layout.addWidget(val_label, 1)

        if copyable and value:
            copy_btn = QPushButton()
            set_icon(copy_btn, COPY)
            copy_btn.setObjectName('iconBtn')
            copy_btn.setFixedSize(28, 28)
            copy_btn.setToolTip('复制')

            def do_copy(_checked=False, v=value, btn=copy_btn):
                self._copy(v)
                set_icon(btn, CHECK, 'success')
                QTimer.singleShot(1500, lambda: set_icon(btn, COPY))

            copy_btn.clicked.connect(do_copy)
            row_layout.addWidget(copy_btn)

        return name_label, row_widget

    def _make_password_row(self, password: str) -> tuple[QLabel, QWidget]:
        """创建密码行"""
        name_label = QLabel('密码：')
        name_label.setStyleSheet(f'font-weight: bold; color: {c("text_secondary")};')

        row_widget = QWidget()
        row_layout = QHBoxLayout(row_widget)
        row_layout.setContentsMargins(0, 0, 0, 0)

        pwd_label = QLabel('••••••••')
        pwd_label.setStyleSheet(
            f'font-family: monospace; font-size: 13px; color: {c("text_primary")};'
        )
        row_layout.addWidget(pwd_label, 1)

        show_btn = QPushButton()
        set_icon(show_btn, EYE)
        show_btn.setObjectName('iconBtn')
        show_btn.setFixedSize(28, 28)
        show_btn.setToolTip('显示/隐藏')

        self._pwd_label_ref = pwd_label
        self._show_btn_ref = show_btn
        self._current_password = password

        def toggle():
            if pwd_label.text() == '••••••••':
                pwd_label.setText(password)
                set_icon(show_btn, LOCK)
                self._pwd_hide_timer.start(self._get_pwd_visible_ms())
            else:
                pwd_label.setText('••••••••')
                set_icon(show_btn, EYE)
                self._pwd_hide_timer.stop()

        show_btn.clicked.connect(toggle)
        row_layout.addWidget(show_btn)

        copy_btn = QPushButton()
        set_icon(copy_btn, COPY)
        copy_btn.setObjectName('iconBtn')
        copy_btn.setFixedSize(28, 28)
        copy_btn.setToolTip('复制密码')

        def do_copy_pwd(_checked=False, btn=copy_btn):
            self._copy(password)
            set_icon(btn, CHECK, 'success')
            QTimer.singleShot(1500, lambda: set_icon(btn, COPY))

        copy_btn.clicked.connect(do_copy_pwd)
        copy_btn.clicked.connect(self.copy_feedback.emit)
        row_layout.addWidget(copy_btn)

        return name_label, row_widget

    def _make_secret_row(self, label: str, value: str) -> tuple[QLabel, QWidget]:
        """创建独立的敏感字段行，默认隐藏且支持复制。"""
        name_label = QLabel(f'{label}：')
        name_label.setStyleSheet(f'font-weight: bold; color: {c("text_secondary")};')
        row_widget = QWidget()
        row_layout = QHBoxLayout(row_widget)
        row_layout.setContentsMargins(0, 0, 0, 0)
        value_label = QLabel('••••••••')
        value_label.setStyleSheet(
            f'font-family: monospace; color: {c("text_primary")};'
        )
        row_layout.addWidget(value_label, 1)
        show_btn = QPushButton()
        set_icon(show_btn, EYE)
        show_btn.setObjectName('iconBtn')
        show_btn.setFixedSize(28, 28)

        def toggle():
            visible = value_label.text() == '••••••••'
            value_label.setText(value if visible else '••••••••')
            set_icon(show_btn, LOCK if visible else EYE)
            if visible:
                QTimer.singleShot(
                    self._get_pwd_visible_ms(),
                    lambda: (value_label.setText('••••••••'), set_icon(show_btn, EYE)),
                )

        show_btn.clicked.connect(toggle)
        row_layout.addWidget(show_btn)
        copy_btn = QPushButton()
        set_icon(copy_btn, COPY)
        copy_btn.setObjectName('iconBtn')
        copy_btn.setFixedSize(28, 28)
        copy_btn.clicked.connect(lambda: self._copy(value))
        copy_btn.clicked.connect(self.copy_feedback.emit)
        row_layout.addWidget(copy_btn)
        return name_label, row_widget

    def _get_pwd_visible_ms(self) -> int:
        """获取密码显示自动隐藏的毫秒数"""
        seconds = 10
        if self._config:
            seconds = self._config.get('password_visible_seconds', 10)
        return seconds * 1000

    def _auto_hide_password(self):
        """自动隐藏密码"""
        if self._pwd_label_ref and self._show_btn_ref:
            self._pwd_label_ref.setText('••••••••')
            set_icon(self._show_btn_ref, EYE)

    def _copy(self, text: str):
        """复制文本"""
        self._clipboard.copy_text(text)

    def _clear_content(self):
        """清除详情面板内容"""
        self._totp_timer.stop()
        self._totp_code_label = None
        self._totp_bar = None
        self._totp_secret = ''
        self._pwd_label_ref = None
        self._show_btn_ref = None
        self._clear_layout(self._content_layout)

    @staticmethod
    def _clear_layout(layout):
        """递归清除布局中的所有子项"""
        while layout.count():
            item = layout.takeAt(0)
            if item is None:
                continue
            sub_layout = item.layout()
            sub_widget = item.widget()
            if sub_layout:
                DetailPanel._clear_layout(sub_layout)
            elif sub_widget:
                sub_widget.hide()
                sub_widget.deleteLater()

    def hideEvent(self, a0):
        """面板隐藏时停止 TOTP 定时器以节省资源"""
        super().hideEvent(a0)
        if hasattr(self, '_totp_timer') and self._totp_timer.isActive():
            self._totp_timer.stop()

    def showEvent(self, a0):
        """面板显示时如果当前有条目含 TOTP 则重启定时器"""
        super().showEvent(a0)
        if (
            hasattr(self, '_totp_timer')
            and hasattr(self, '_totp_secret')
            and self._totp_secret
            and hasattr(self, '_current_entry')
            and self._current_entry
            and self._current_entry.has_totp
        ):
            self._totp_timer.start(1000)

    def show_empty(self):
        """显示空状态"""
        self._clear_content()
        self._current_entry = None
        self._pwd_hide_timer.stop()
        self._totp_timer.stop()
        self._title_label.setText('选择一个条目查看详情')
        self._edit_btn.hide()
        self._delete_btn.hide()
        self._fav_btn.hide()
        self._empty_label = QLabel('📋\n\n从列表中选择一个条目\n以查看详细信息')
        self._empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty_label.setStyleSheet(f'color: {c("text_muted")}; font-size: 14px;')
        self._content_layout.addWidget(self._empty_label)

    def refresh_theme(self):
        """刷新在构造时写入的主题相关内联样式。"""
        self._title_label.setStyleSheet(
            f'font-size: 16px; font-weight: bold; color: {c("text_primary")};'
        )
        self._divider.setStyleSheet(f'background: {c("divider")};')

    @staticmethod
    def _format_time(iso_str: str) -> str:
        """格式化时间显示"""
        try:
            return iso_str[:19].replace('T', ' ')
        except (ValueError, IndexError):
            return iso_str
