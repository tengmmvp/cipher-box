"""详情面板 - 展示密码条目详细信息"""

import logging
from html import escape
from urllib.parse import urlparse

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

from ...models import Entry
from ...utils.format import format_datetime
from ..resources.constants import (
    BTN_COPY,
    BTN_ICON,
    FONT_FAMILY_MONOSPACE,
    MAX_TAG_DISPLAY,
    MS_FEEDBACK,
    PWD_VISIBLE_SECONDS_DEFAULT,
)
from ..resources.icons import (
    CHECK,
    COPY,
    DELETE,
    EDIT,
    EYE,
    LOCK,
    STAR,
    STAR_OUTLINE,
    set_icon,
)
from ..resources.theme_colors import c, get_strength_color
from .custom_fields_renderer import CustomFieldsRenderer
from .password_history_widget import PasswordHistoryWidget
from .totp_widget import TOTPWidget
from .widgets import clear_layout

logger = logging.getLogger(__name__)

# 密码强度标签映射，模块级常量避免每次 show_entry 重建
_STRENGTH_LABELS = {0: '非常弱', 1: '弱', 2: '一般', 3: '强', 4: '非常强'}


def zero_buffer_copy(value: str) -> None:
    """尽力零化字符串的编码副本（纵深防御）。

    WARNING: 此方法在 CPython 下**不保证**清除原始字符串内存。
    Python ``str`` 不可变，此方法仅零化 ``encode()`` 后的 bytearray 副本，
    **不影响**原始字符串对象。真正的安全清理依赖 ``_clear_content()``
    置空所有引用以触发 GC。

    方法名 ``zero_buffer_copy``（而非 _secure_wipe）如实反映了其能力。
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
        self._current_password = ''
        # 主条目非主密码敏感字段的间接引用字典（自定义字段由 renderer 管理）
        self._secret_values_main: dict[str, str] = {}
        # 非主密码敏感字段与历史密码的自动掩码定时器（持久、可取消），
        # 替代不可取消的 QTimer.singleShot。_clear_content 时统一 stop 并清空。
        self._field_hide_timers: list[QTimer] = []
        # 复制反馈定时器（可取消），替代不可取消的 QTimer.singleShot，
        # 避免控件销毁后回调访问已删对象。上限 20 防止极端情况下泄漏。
        self._copy_feedback_timers: set[QTimer] = set()
        self._COPY_FEEDBACK_TIMERS_MAX = 20

        # ---- 子组件 ----
        self._totp_widget = TOTPWidget(self)
        self._totp_widget.copy_requested.connect(self._copy)
        self._totp_widget.copy_feedback.connect(self.copy_feedback.emit)

        self._history_widget = PasswordHistoryWidget(self)
        self._history_widget.set_hide_timers_ref(self._field_hide_timers)
        self._history_widget.set_callbacks(
            get_pwd_visible_ms=self._get_pwd_visible_ms,
            copy_with_feedback=self._copy_with_feedback,
        )
        self._history_widget.copy_feedback.connect(self.copy_feedback.emit)

        self._fields_renderer = CustomFieldsRenderer(
            copy_callback=self._copy_with_feedback,
            copy_feedback_callback=self.copy_feedback.emit,
            hide_timer_callback=self._get_pwd_visible_ms,
        )

        self._setup_ui()

    def _add_copy_feedback_timer(self, timer: QTimer):
        """注册复制反馈定时器，超出上限时回收最旧的。"""
        if len(self._copy_feedback_timers) >= self._COPY_FEEDBACK_TIMERS_MAX:
            oldest = next(iter(self._copy_feedback_timers))
            oldest.stop()
            self._copy_feedback_timers.discard(oldest)
        self._copy_feedback_timers.add(timer)

    def _copy_with_feedback(self, btn: QPushButton, text: str):
        """复制文本到剪贴板并显示图标反馈，定时恢复为复制图标。"""
        self._copy(text)
        set_icon(btn, CHECK, 'success')
        timer = QTimer(self)
        timer.setSingleShot(True)
        self._add_copy_feedback_timer(timer)

        def _restore(btn=btn, t=timer):
            set_icon(btn, COPY)
            self._copy_feedback_timers.discard(t)

        timer.timeout.connect(_restore)
        timer.start(MS_FEEDBACK)

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
        """当前展示的条目，只读访问。"""
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
        logger.debug("显示条目详情: id=%d title=%r", entry.id, entry.title)
        self._current_entry = entry
        self._pwd_hide_timer.stop()
        self._totp_widget.stop()
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
            self._totp_widget.start(entry.id, self._entry_mgr)

        # ===== 密码历史（延迟加载：仅显示摘要，点击展开才解密） =====
        if entry.id and self._entry_mgr:
            self._history_widget.build_stub(entry.id, self._entry_mgr, self._content_layout)

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
            cf_timers = self._fields_renderer.render(entry, self._content_layout, self)
            self._field_hide_timers.extend(cf_timers)

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
                QLabel(format_datetime(entry.created_at))
            )
        if entry.updated_at:
            meta_form.addRow(
                QLabel('更新：'),
                QLabel(format_datetime(entry.updated_at))
            )
        if entry.password and entry.password_changed_at:
            meta_form.addRow(
                QLabel('密码更新：'),
                QLabel(format_datetime(entry.password_changed_at))
            )
        for i in range(meta_form.count()):
            item = meta_form.itemAt(i)
            if item:
                w = item.widget()
                if w:
                    w.setStyleSheet(meta_form_label_style)
        if meta_form.count() > 0:
            self._content_layout.addLayout(meta_form)

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
            copy_btn = QPushButton()
            set_icon(copy_btn, COPY)
            copy_btn.setObjectName('iconBtn')
            copy_btn.setFixedSize(*BTN_COPY)
            copy_btn.setToolTip('复制')

            # 使用闭包捕获当前值（主条目字段不需要间接引用，生命周期与面板同步）
            def _copy_value(_checked=False, v=value, btn=copy_btn):
                self._copy_with_feedback(btn, v)

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
            # 非主密码的敏感字段 — 使用独立的间接引用字典
            self._secret_values_main[label] = value
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
            pwd = self._current_password if is_main else self._secret_values_main.get(key, '')
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
            pwd = self._current_password if is_main else self._secret_values_main.get(key, '')
            self._copy_with_feedback(btn, pwd)

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
        # 停止所有自动掩码定时器，避免清除后对已销毁控件触发回调。
        self._totp_widget.stop()
        self._pwd_hide_timer.stop()
        for timer in self._field_hide_timers:
            timer.stop()
        self._field_hide_timers.clear()
        # 取消所有复制反馈定时器，避免控件销毁后回调访问已删对象。
        for timer in self._copy_feedback_timers:
            timer.stop()
        self._copy_feedback_timers.clear()
        # 安全擦除主条目字段间接引用中的敏感值
        for k in list(self._secret_values_main):
            zero_buffer_copy(self._secret_values_main[k])
        self._secret_values_main.clear()
        # 清除子组件状态
        self._totp_widget.clear()
        self._history_widget.clear()
        self._fields_renderer.clear()
        zero_buffer_copy(self._current_password)
        self._current_password = ''
        self._pwd_label_ref = None
        self._show_btn_ref = None
        self._clear_layout(self._content_layout)
        logger.debug("详情面板内容已清除")
        # _clear_layout 通过 deleteLater 销毁所有子控件，将引用置空
        # 以便 refresh_theme 用 is not None 检查控件存活状态。
        self._empty_label = None

    @staticmethod
    def _clear_layout(layout):
        clear_layout(layout)

    def hideEvent(self, a0):
        """面板隐藏时停止 TOTP 定时器以节省资源"""
        super().hideEvent(a0)
        if hasattr(self, '_totp_widget'):
            self._totp_widget.stop()

    def showEvent(self, a0):
        """面板显示时如果当前有条目含 TOTP 则重启定时器"""
        super().showEvent(a0)
        if (
            hasattr(self, '_totp_widget')
            and hasattr(self, '_current_entry')
            and self._current_entry
            and self._current_entry.has_totp
        ):
            self._totp_widget.resume_if_active()

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
        """安全清除所有敏感数据和信号连接，由主窗口在锁定时调用。"""
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
