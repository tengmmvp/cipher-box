"""详情面板 - 展示密码条目详细信息（重构版）"""

from datetime import datetime
from html import escape
from urllib.parse import urlparse
import time as _time

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ..database.models import Entry
from ..ui.resources.constants import (
    BTN_COPY,
    BTN_ICON,
    BTN_TOTP_COPY,
    FONT_FAMILY_MONOSPACE,
    MAX_HISTORY_DISPLAY,
    MAX_TAG_DISPLAY,
    MS_FEEDBACK,
    MS_TOTP_REFRESH,
    PWD_VISIBLE_SECONDS_DEFAULT,
)
from ..ui.resources.icons import (
    CHECK,
    COPY,
    DELETE,
    EDIT,
    EYE,
    LOCK,
    SIZE_BTN,
    SIZE_SMALL,
    STAR,
    STAR_OUTLINE,
    set_icon,
    set_icon_with_text,
)
from ..ui.resources.theme_colors import c, get_strength_color
from .widgets import clear_layout

# 密码强度标签映射（模块级常量，避免每次 show_entry 重建）
_STRENGTH_LABELS = {0: '非常弱', 1: '弱', 2: '一般', 3: '强', 4: '非常强'}


class DetailPanel(QWidget):
    """密码条目详情面板

    安全说明（CPython 限制）：
    - 明文密码作为 Python str 存储在 self._current_password 和闭包中。
    - Python 字符串不可变，_secure_wipe 无法覆写原始对象内存。
    - _clear_content 通过置空引用和 del 缩短敏感数据驻留时间。
    - 对于主密码（main_password=True），_toggle 闭包从 self._current_password
      读取而非直接捕获值，使得 _clear_content 清空后闭包也看到空值。
    """

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
        self._signal_connections = []
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
        self._totp_entry_id: int | None = None  # 4A：通过 EntryManager 获取 TOTP 状态
        self._totp_period: int = 30  # 缓存 TOTP 周期，避免刷新时重复调用 get_totp_state
        self._current_password = ''
        # 间接引用存储：敏感字段值通过字典引用，_clear_content 时一并清空，
        # 避免闭包直接捕获明文导致密码驻留内存。
        self._secret_values: dict[str, str] = {}
        self._history_passwords: list[str] = []
        # 普通字段明文值间接引用：闭包通过 row_id 从字典读取而非直接捕获明文，
        # _clear_content 时一并清空，缩短敏感数据驻留内存时间。
        self._plain_values: dict[int, str] = {}
        self._plain_row_counter: int = 0
        # H5/H7：非主密码敏感字段与历史密码的自动掩码定时器（持久、可取消），
        # 替代不可取消的 QTimer.singleShot。_clear_content 时统一 stop 并清空。
        self._field_hide_timers: list[QTimer] = []
        # 复制反馈定时器（可取消），替代不可取消的 QTimer.singleShot，
        # 避免控件销毁后回调访问已删对象。
        self._copy_feedback_timers: list[QTimer] = []
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
        self._fav_btn.setFixedSize(*BTN_ICON)
        self._fav_btn.setToolTip('收藏')
        self._fav_btn.hide()
        toolbar.addWidget(self._fav_btn)

        self._edit_btn = QPushButton()
        set_icon(self._edit_btn, EDIT)
        self._edit_btn.setObjectName('iconBtn')
        self._edit_btn.setFixedSize(*BTN_ICON)
        self._edit_btn.setToolTip('编辑')
        self._edit_btn.hide()
        toolbar.addWidget(self._edit_btn)

        self._delete_btn = QPushButton()
        set_icon(self._delete_btn, DELETE)
        self._delete_btn.setObjectName('iconBtn')
        self._delete_btn.setFixedSize(*BTN_ICON)
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
        self._empty_label = QLabel('请从列表中选择一个条目\n以查看详细信息')
        self._empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty_label.setStyleSheet(f'color: {c("text_muted")}; font-size: 14px;')
        self._content_layout.addWidget(self._empty_label)

        scroll.setWidget(self._content)
        layout.addWidget(scroll)

    @property
    def current_entry(self):
        """当前展示的条目（只读访问）。"""
        return self._current_entry

    def show_entry(self, entry: Entry, *, force: bool = False):
        """显示条目详情

        Args:
            entry: 要显示的条目
            force: 强制重建（主题切换时需要刷新内联样式）
        """
        # 同条目无变化时跳过重建
        if (not force
                and self._current_entry is not None
                and self._current_entry.id == entry.id
                and self._current_entry.updated_at == entry.updated_at):
            return
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
        # 清理旧信号连接
        for signal, slot in self._signal_connections:
            try:
                signal.disconnect(slot)
            except TypeError:
                pass
        self._signal_connections.clear()

        # 建立新连接（闭包只捕获 entry.id，避免持有 entry 引用）
        eid = entry.id
        self._signal_connections = [
            (self._edit_btn.clicked, lambda: self.edit_requested.emit(eid)),
            (self._delete_btn.clicked, lambda: self.delete_requested.emit(eid)),
            (self._fav_btn.clicked, lambda: self.favorite_toggled.emit(eid)),
        ]
        for signal, slot in self._signal_connections:
            signal.connect(slot)

        self._content_layout.addLayout(self._build_tags_section(entry))

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
            core_form.addRow(*self._make_field_row('账号', entry.username, copyable=True))

        # 密码
        if entry.password:
            core_form.addRow(*self._make_field_row('密码', entry.password, secret=True, main_password=True))

        # 网址
        if entry.url:
            parsed_url = urlparse(entry.url)
            safe_url = parsed_url.scheme.lower() in ('http', 'https')
            escaped_url = escape(entry.url, quote=True)
            if safe_url:
                text = f'<a href="{escaped_url}" style="color: {c("link")}; text-decoration:none;">{escaped_url}</a>'
            else:
                text = escaped_url
            url_label = QLabel(text)
            url_label.setWordWrap(True)
            url_label.setTextFormat(Qt.TextFormat.RichText)
            if safe_url:
                url_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
                url_label.setOpenExternalLinks(True)
            core_form.addRow('网址：', url_label)

        self._content_layout.addLayout(core_form)

        if entry.password:
            self._build_strength_bar(entry)

        # ===== TOTP 区域 =====
        if entry.has_totp and entry.id:
            self._build_totp_section(entry.id)

        # ===== 密码历史（延迟加载：仅显示摘要，点击展开才解密） =====
        if entry.id and self._entry_mgr:
            self._build_password_history_stub(entry.id)

        self._build_meta_section(entry)

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
            self._build_custom_fields_section(entry)

        self._content_layout.addStretch()

    def _build_tags_section(self, entry: Entry) -> QHBoxLayout:
        """构建分类、类型和标签区域"""
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

        for tag in entry.get_tag_list()[:MAX_TAG_DISPLAY]:
            tag_label = QLabel(f'  {tag}  ')
            tag_label.setStyleSheet(
                f'background: {c("tag_bg")}; color: {c("tag_text")}; '
                f'border: 1px solid {c("tag_border")}; border-radius: 10px; '
                f'font-size: 11px; padding: 2px 6px;'
            )
            header_info.addWidget(tag_label)

        header_info.addStretch()
        return header_info

    def _build_strength_bar(self, entry: Entry):
        """构建密码强度进度条"""
        score = entry.password_strength
        strength_color = get_strength_color(score)

        strength_row = QHBoxLayout()
        strength_row.setSpacing(8)

        strength_label_title = QLabel('强度：')
        strength_label_title.setStyleSheet(f'font-weight: bold; color: {c("text_secondary")};')
        strength_row.addWidget(strength_label_title)

        bar = QProgressBar()
        bar.setRange(0, 4)
        bar.setValue(score)
        bar.setFixedHeight(8)
        bar.setTextVisible(False)
        bar.setStyleSheet(f"""
            QProgressBar {{ background: {c("progress_bg")}; border: none; border-radius: 4px; }}
            QProgressBar::chunk {{ background: {strength_color}; border-radius: 4px; }}
        """)
        strength_row.addWidget(bar, 1)

        strength_text = QLabel(f'{_STRENGTH_LABELS.get(score, "未知")} ({score}/4)')
        strength_text.setStyleSheet(f'color: {strength_color}; font-weight: bold; font-size: 12px;')
        strength_row.addWidget(strength_text)

        self._content_layout.addLayout(strength_row)

    def _build_meta_section(self, entry: Entry):
        """构建时间元数据区域"""
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

    def _build_custom_fields_section(self, entry: Entry):
        """构建自定义字段区域"""
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
            icon = {'password': '[PWD]', 'url': '[URL]', 'email': '[MAIL]'}.get(cf.field_type, '[TXT]')
            label = labels.get(cf.name, cf.name)
            if cf.field_type == 'password':
                cf_layout.addRow(*self._make_field_row(f'{icon} {label}', cf.value, secret=True))
            else:
                cf_layout.addRow(*self._make_field_row(f'{icon} {label}', cf.value, copyable=True))
        self._content_layout.addWidget(cf_group)

    def _build_totp_section(self, entry_id: int):
        """构建 TOTP 验证码区域。

        4A 架构迁移：接收 entry_id 而非明文 secret，通过 EntryManager
        获取 TOTP 状态（code/remaining/period），UI 层不直接调用 crypto。
        """
        if not self._entry_mgr:
            return
        state = self._entry_mgr.get_totp_state(entry_id)
        if not state:
            return
        self._totp_entry_id = entry_id
        self._totp_period = state['period']  # 缓存周期供刷新使用

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

        totp_title = QLabel('验证码 (TOTP)')
        totp_title.setStyleSheet(f'font-weight: bold; font-size: 13px; color: {c("accent_text")};')
        totp_layout.addWidget(totp_title)

        code_row = QHBoxLayout()
        code_row.setSpacing(12)

        self._totp_code_label = QLabel(state['code'])
        self._totp_code_label.setStyleSheet(
            f'font-size: 28px; font-weight: bold; letter-spacing: 6px; '
            f'color: {c("accent_text")}; font-family: {FONT_FAMILY_MONOSPACE};'
        )
        code_row.addWidget(self._totp_code_label)

        # 倒计时进度条
        self._totp_bar = QProgressBar()
        self._totp_bar.setRange(0, state['period'])
        self._totp_bar.setValue(state['remaining'])
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
        copy_btn.setFixedSize(*BTN_TOTP_COPY)
        copy_btn.clicked.connect(self._copy_totp_code)
        copy_btn.clicked.connect(self.copy_feedback.emit)
        code_row.addWidget(copy_btn)

        totp_layout.addLayout(code_row)
        self._content_layout.addWidget(totp_frame)

        # 启动定时刷新（每秒）
        self._totp_timer.start(MS_TOTP_REFRESH)

    def _refresh_totp(self):
        """刷新 TOTP 验证码（仅调用 generate_totp，复用缓存的 period）。"""
        if not self._totp_entry_id or not self._totp_code_label or not self._entry_mgr:
            self._totp_timer.stop()
            return
        code = self._entry_mgr.generate_totp(self._totp_entry_id)
        if not code:
            self._totp_timer.stop()
            return
        self._totp_code_label.setText(code)
        if self._totp_bar:
            remaining = self._totp_period - (int(_time.time()) % self._totp_period)
            self._totp_bar.setValue(remaining)

    def _copy_totp_code(self):
        """复制当前 TOTP 验证码（始终取最新值）"""
        if self._totp_code_label:
            self._copy(self._totp_code_label.text())

    def _build_password_history_stub(self, entry_id: int):
        """构建密码历史占位摘要，点击时才加载完整历史"""
        count = self._entry_mgr.get_password_history_count(entry_id)
        if not count:
            return
        btn = QPushButton(f'密码历史（{count} 条记录）— 点击展开')
        btn.setFlat(True)
        btn.setStyleSheet(f"""
            QPushButton {{
                text-align: left; color: {c("text_secondary")};
                font-size: 12px; padding: 6px 0; border: none;
            }}
            QPushButton:hover {{ color: {c("accent")}; }}
        """)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)

        def _expand(_checked=False, eid=entry_id, button=btn):
            decrypted = self._entry_mgr.decrypt_password_history(
                self._entry_mgr.get_password_history(eid)
            )
            if decrypted:
                self._content_layout.removeWidget(button)
                button.deleteLater()
                self._build_password_history(decrypted)

        btn.clicked.connect(_expand)
        self._content_layout.addWidget(btn)

    def _build_password_history(self, history: list[dict]):
        """构建密码历史折叠区"""
        group = QGroupBox('密码历史')
        group_layout = QVBoxLayout(group)
        group_layout.setSpacing(6)

        for record in history[:MAX_HISTORY_DISPLAY]:
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
                f'font-family: {FONT_FAMILY_MONOSPACE}; font-size: 12px; color: {c("text_primary")};'
            )
            row.addWidget(pwd_label, 1)

            # 历史密码存入间接引用列表，闭包通过索引读取，
            # _clear_content 时清空列表即可释放明文。
            hist_idx = len(self._history_passwords)
            self._history_passwords.append(pwd_text)

            # 显示/隐藏按钮
            show_btn = QPushButton()
            set_icon(show_btn, EYE)
            show_btn.setObjectName('iconBtn')
            show_btn.setFixedSize(*BTN_COPY)
            show_btn.setToolTip('显示/隐藏')

            # H7：历史密码显示超时定时器（持久、可取消）。复用主密码可见时长，
            # 到时自动重新掩码并清空该条历史密码的明文副本，缩短敏感数据驻留。
            # _clear_content 时统一 stop 并清空，避免切换条目/锁定后误触发。
            hist_timer = QTimer(self)
            hist_timer.setSingleShot(True)
            self._field_hide_timers.append(hist_timer)

            def _on_hist_timeout(lbl=pwd_label, btn=show_btn, idx=hist_idx):
                lbl.setText('••••••••')
                set_icon(btn, EYE)
                if idx < len(self._history_passwords):
                    self._history_passwords[idx] = ''

            hist_timer.timeout.connect(_on_hist_timeout)

            def toggle_pwd(_checked=False, lbl=pwd_label, btn=show_btn, idx=hist_idx, timer=hist_timer):
                pwd = self._history_passwords[idx] if idx < len(self._history_passwords) else ''
                if lbl.text() == '••••••••':
                    lbl.setText(pwd)
                    set_icon(btn, LOCK)
                    timer.start(self._get_pwd_visible_ms())
                else:
                    lbl.setText('••••••••')
                    set_icon(btn, EYE)
                    timer.stop()

            show_btn.clicked.connect(toggle_pwd)
            row.addWidget(show_btn)

            # 复制按钮
            copy_btn = QPushButton()
            set_icon(copy_btn, COPY)
            copy_btn.setObjectName('iconBtn')
            copy_btn.setFixedSize(*BTN_COPY)
            copy_btn.setToolTip('复制密码')

            def do_copy(_checked=False, idx=hist_idx, btn=copy_btn):
                pwd = self._history_passwords[idx] if idx < len(self._history_passwords) else ''
                self._copy(pwd)
                set_icon(btn, CHECK, 'success')
                timer = QTimer(self)
                timer.setSingleShot(True)
                self._copy_feedback_timers.append(timer)

                def _restore(btn=btn, t=timer):
                    set_icon(btn, COPY)
                    if t in self._copy_feedback_timers:
                        self._copy_feedback_timers.remove(t)

                timer.timeout.connect(_restore)
                timer.start(MS_FEEDBACK)

            copy_btn.clicked.connect(do_copy)
            copy_btn.clicked.connect(self.copy_feedback.emit)
            row.addWidget(copy_btn)

            group_layout.addLayout(row)

        self._content_layout.addWidget(group)

    def _make_field_row(
        self, label: str, value: str,
        *, secret: bool = False, copyable: bool = False, main_password: bool = False,
    ) -> tuple[QLabel, QWidget]:
        """创建字段行（统一入口，分发到具体方法）。

        Args:
            label: 字段名称
            value: 字段值
            secret: 敏感字段，默认掩码显示，支持显示/隐藏切换
            copyable: 是否显示复制按钮（secret=True 时隐含可复制）
            main_password: 仅用于主密码字段，追踪引用并使用全局自动隐藏定时器
        """
        if secret:
            return self._make_secret_field_row(label, value, main_password=main_password)
        return self._make_plain_field_row(label, value, copyable=copyable)

    def _make_plain_field_row(
        self, label: str, value: str, *, copyable: bool = False,
    ) -> tuple[QLabel, QWidget]:
        """创建普通字段行（明文显示 + 可选复制按钮）。"""
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
            # 将明文存入间接引用字典，闭包通过 row_id 读取，
            # _clear_content 时一并清空，避免闭包直接捕获明文。
            row_id = self._plain_row_counter
            self._plain_row_counter += 1
            self._plain_values[row_id] = value

            copy_btn = QPushButton()
            set_icon(copy_btn, COPY)
            copy_btn.setObjectName('iconBtn')
            copy_btn.setFixedSize(*BTN_COPY)
            copy_btn.setToolTip('复制')

            def _copy_value(_checked=False, rid=row_id, btn=copy_btn):
                v = self._plain_values.get(rid, '')
                self._copy(v)
                set_icon(btn, CHECK, 'success')
                timer = QTimer(self)
                timer.setSingleShot(True)
                self._copy_feedback_timers.append(timer)

                def _restore(btn=btn, t=timer):
                    set_icon(btn, COPY)
                    if t in self._copy_feedback_timers:
                        self._copy_feedback_timers.remove(t)

                timer.timeout.connect(_restore)
                timer.start(MS_FEEDBACK)

            copy_btn.clicked.connect(_copy_value)
            row_layout.addWidget(copy_btn)

        return name_label, row_widget

    def _make_secret_field_row(
        self, label: str, value: str, *, main_password: bool = False,
    ) -> tuple[QLabel, QWidget]:
        """创建敏感字段行（默认掩码 + 显示/隐藏 + 复制按钮）。

        Args:
            label: 字段名称
            value: 字段值
            main_password: 仅用于主密码字段，追踪引用并使用全局自动隐藏定时器
        """
        name_label = QLabel(f'{label}：')
        name_label.setStyleSheet(f'font-weight: bold; color: {c("text_secondary")};')

        row_widget = QWidget()
        row_layout = QHBoxLayout(row_widget)
        row_layout.setContentsMargins(0, 0, 0, 0)

        val_label = QLabel('••••••••')
        val_label.setStyleSheet(
            f'font-family: {FONT_FAMILY_MONOSPACE}; font-size: 13px; color: {c("text_primary")};'
        )
        row_layout.addWidget(val_label, 1)

        show_btn = QPushButton()
        set_icon(show_btn, EYE)
        show_btn.setObjectName('iconBtn')
        show_btn.setFixedSize(*BTN_COPY)
        show_btn.setToolTip('显示/隐藏')

        if main_password:
            self._pwd_label_ref = val_label
            self._show_btn_ref = show_btn
            self._current_password = value
            field_timer = None
        else:
            # 非主密码的敏感字段存入间接引用字典，
            # 闭包从字典读取而非直接捕获值，_clear_content 可清除。
            self._secret_values[label] = value
            # H5：持久单次定时器（可取消），替代不可取消的 QTimer.singleShot。
            # _clear_content 时 stop 并清空，避免切换条目/锁定后定时器仍触发
            # 对已销毁控件操作。
            field_timer = QTimer(self)
            field_timer.setSingleShot(True)
            field_timer.timeout.connect(
                lambda lbl=val_label, btn=show_btn: (
                    lbl.setText('••••••••'), set_icon(btn, EYE),
                )
            )
            self._field_hide_timers.append(field_timer)

        def _toggle(_checked=False, lbl=val_label, btn=show_btn,
                    is_main=main_password, key=label, timer=field_timer):
            # 所有敏感字段均通过间接引用读取（主密码用
            # self._current_password，其他用 self._secret_values），
            # 使得 _clear_content 清空后闭包也看到空值。
            pwd = self._current_password if is_main else self._secret_values.get(key, '')
            if lbl.text() == '••••••••':
                lbl.setText(pwd)
                set_icon(btn, LOCK)
                if is_main:
                    self._pwd_hide_timer.start(self._get_pwd_visible_ms())
                elif timer is not None:
                    timer.start(self._get_pwd_visible_ms())
            else:
                lbl.setText('••••••••')
                set_icon(btn, EYE)
                if is_main:
                    self._pwd_hide_timer.stop()
                elif timer is not None:
                    timer.stop()

        show_btn.clicked.connect(_toggle)
        row_layout.addWidget(show_btn)

        copy_btn = QPushButton()
        set_icon(copy_btn, COPY)
        copy_btn.setObjectName('iconBtn')
        copy_btn.setFixedSize(*BTN_COPY)
        copy_btn.setToolTip('复制密码')

        def _copy_secret(_checked=False, is_main=main_password, key=label, btn=copy_btn):
            # 复制时也从间接引用读取，避免闭包捕获明文。
            pwd = self._current_password if is_main else self._secret_values.get(key, '')
            self._copy(pwd)
            set_icon(btn, CHECK, 'success')
            timer = QTimer(self)
            timer.setSingleShot(True)
            self._copy_feedback_timers.append(timer)

            def _restore(btn=btn, t=timer):
                set_icon(btn, COPY)
                if t in self._copy_feedback_timers:
                    self._copy_feedback_timers.remove(t)

            timer.timeout.connect(_restore)
            timer.start(MS_FEEDBACK)

        copy_btn.clicked.connect(_copy_secret)
        copy_btn.clicked.connect(self.copy_feedback.emit)
        row_layout.addWidget(copy_btn)

        return name_label, row_widget

    def _get_pwd_visible_ms(self) -> int:
        """获取密码显示自动隐藏的毫秒数"""
        seconds = PWD_VISIBLE_SECONDS_DEFAULT
        if self._config:
            seconds = self._config.get('password_visible_seconds', PWD_VISIBLE_SECONDS_DEFAULT)
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
        """清除详情面板内容，安全擦除敏感数据。"""
        # 停止所有自动掩码定时器，避免清除后对已销毁控件触发回调
        # （H5/H7：非主密码字段与历史密码定时器在 _clear_layout 后控件即销毁）。
        self._totp_timer.stop()
        self._pwd_hide_timer.stop()
        for timer in self._field_hide_timers:
            timer.stop()
        self._field_hide_timers.clear()
        # 取消所有复制反馈定时器，避免控件销毁后回调访问已删对象。
        for timer in self._copy_feedback_timers:
            timer.stop()
        self._copy_feedback_timers.clear()
        # 安全擦除普通字段间接引用中的明文值
        for k in list(self._plain_values):
            self._secure_wipe(self._plain_values[k])
        self._plain_values.clear()
        self._plain_row_counter = 0
        # 4A：不再存储明文 TOTP secret，只需重置 entry_id 和缓存
        self._totp_entry_id = None
        self._totp_period = 30
        self._totp_code_label = None
        self._totp_bar = None
        self._secure_wipe(self._current_password)
        self._current_password = ''
        self._pwd_label_ref = None
        self._show_btn_ref = None
        # 安全擦除间接引用中的敏感值
        for k in list(self._secret_values):
            self._secure_wipe(self._secret_values[k])
        self._secret_values.clear()
        for p in self._history_passwords:
            self._secure_wipe(p)
        self._history_passwords.clear()
        self._clear_layout(self._content_layout)
        # _clear_layout 通过 deleteLater 销毁所有子控件，将引用置空
        # 以便 refresh_theme 用 is not None 检查控件存活状态。
        self._empty_label = None

    @staticmethod
    def _secure_wipe(value: str) -> None:
        """安全擦除字符串：用零覆盖编码副本后立即释放。

        WARNING: 此方法在 CPython 下**不保证**清除原始字符串内存。
        Python ``str`` 不可变，此方法仅零化 ``encode()`` 后的 bytearray 副本，
        **不影响**原始字符串对象。保留此方法作为纵深防御惯例，但维护者不应依赖其
        安全性保证。

        真正的安全清理依赖 ``_clear_content()`` 置空所有引用
       （``self._current_password``、``self._secret_values``、
        ``self._history_passwords``）以触发 GC，以及闭包通过间接引用
        （``self._current_password`` 等 dict/list）读取而非直接捕获值，
        使得清空引用后闭包即返回空值。
        """
        if not value:
            return
        try:
            buf = bytearray(value.encode('utf-16-le'))
            for i in range(len(buf)):
                buf[i] = 0
            del buf
        except Exception:
            pass

    @staticmethod
    def _clear_layout(layout):
        clear_layout(layout)

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
            and self._totp_entry_id
            and hasattr(self, '_current_entry')
            and self._current_entry
            and self._current_entry.has_totp
        ):
            self._totp_timer.start(MS_TOTP_REFRESH)

    def show_empty(self):
        """显示空状态"""
        self._clear_content()
        self._current_entry = None
        self._title_label.setText('选择一个条目查看详情')
        self._edit_btn.hide()
        self._delete_btn.hide()
        self._fav_btn.hide()
        self._empty_label = QLabel('请从列表中选择一个条目\n以查看详细信息')
        self._empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty_label.setStyleSheet(f'color: {c("text_muted")}; font-size: 14px;')
        self._content_layout.addWidget(self._empty_label)

    def secure_clear(self):
        """安全清除所有敏感数据和信号连接（锁定时由主窗口调用）。"""
        for signal, slot in self._signal_connections:
            try:
                signal.disconnect(slot)
            except TypeError:
                pass
        self._signal_connections.clear()
        self.show_empty()

    def refresh_theme(self):
        """刷新在构造时写入的主题相关内联样式。"""
        self._title_label.setStyleSheet(
            f'font-size: 16px; font-weight: bold; color: {c("text_primary")};'
        )
        self._divider.setStyleSheet(f'background: {c("divider")};')
        # _empty_label 在 _clear_content 后置为 None，
        # 仅在控件仍存在时刷新。
        if self._empty_label is not None:
            self._empty_label.setStyleSheet(f'color: {c("text_muted")}; font-size: 14px;')

    @staticmethod
    def _format_time(iso_str: str) -> str:
        """格式化时间显示。

        用 ``datetime.fromisoformat`` 解析 ISO-8601 时间戳并规范化输出；
        解析失败时原样返回（兼容非标准或历史格式），不再依赖字符串切片。
        """
        if not iso_str:
            return iso_str
        try:
            dt = datetime.fromisoformat(iso_str)
        except ValueError:
            return iso_str
        return dt.strftime('%Y-%m-%d %H:%M:%S')
