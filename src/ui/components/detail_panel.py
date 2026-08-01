"""密码条目详情面板。

负责单条条目的全量展示，包括核心字段、密码强度、TOTP、密码历史、
自定义字段与元数据。面板内置敏感字段显示/隐藏、复制反馈与自动掩码
机制，并在锁定前由主窗口调用 secure_clear 安全擦除内存中的明文。
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from collections.abc import Callable
from html import escape
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, urlparse

from PyQt6 import sip
from PyQt6.QtCore import Qt, QTimer, pyqtBoundSignal, pyqtSignal
from PyQt6.QtGui import QHideEvent, QShowEvent
from PyQt6.QtWidgets import (
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLayout,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ...config import CFG_PASSWORD_VISIBLE_SECONDS
from ...models import ENTRY_TYPE_LOGIN, Entry, Sensitive
from ...utils.format import format_datetime
from ...utils.memory import mark_secret_discarded

if TYPE_CHECKING:
    from ...business.managers.entry_manager import EntryManager
    from ...config import ConfigManager
    from ..utils.clipboard import ClipboardManager
from ..resources.constants import (
    BTN_COPY,
    MAX_TAG_DISPLAY,
    MS_FEEDBACK,
    PWD_MASK,
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
from .secret_field import SecretFieldEnv, make_secret_field_row
from .totp_widget import TOTPWidget
from .widgets import clear_layout, create_icon_button, disconnect_all

logger = logging.getLogger(__name__)

# 密码强度标签映射，模块级常量避免每次 show_entry 重建
_STRENGTH_LABELS = {0: "非常弱", 1: "弱", 2: "一般", 3: "强", 4: "非常强"}


class DetailPanel(QWidget):
    """密码条目详情面板。

    安全说明，受 CPython 运行时限制：
    - 明文密码以 Python str 形式存储在 self._current_password 及闭包中。
    - Python 字符串不可变，mark_secret_discarded 无法覆写原始对象内存。
    - _clear_content 通过置空引用缩短敏感数据的驻留时间。
    - 对主密码字段，_toggle 闭包从 self._current_password 读取而非直接
      捕获值，使 _clear_content 清空后闭包同样读到空值。
    """

    edit_requested = pyqtSignal(int)
    delete_requested = pyqtSignal(int)
    favorite_toggled = pyqtSignal(int)
    copy_feedback = pyqtSignal()

    # 复制反馈定时器上限：可取消定时器替代 QTimer.singleShot，控件销毁前需逐个
    # stop，上限防止极端情况下的定时器泄漏。
    _COPY_FEEDBACK_TIMERS_MAX = 20

    def __init__(
        self,
        clipboard_manager: ClipboardManager,
        entry_manager: EntryManager | None = None,
        config: ConfigManager | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("detailPanel")
        self._clipboard = clipboard_manager
        self._entry_mgr = entry_manager
        self._config = config
        self._signal_connections: list[tuple[pyqtBoundSignal, Callable[..., Any]]] = []
        self._current_entry: Entry | None = None
        self._pwd_hide_timer = QTimer(self)
        self._pwd_hide_timer.setSingleShot(True)
        self._pwd_hide_timer.timeout.connect(self._auto_hide_password)
        self._pwd_label_ref: QLabel | None = None
        self._show_btn_ref: QPushButton | None = None
        self._current_password = ""
        # 主条目中非主密码敏感字段的间接引用字典，自定义字段由 renderer 管理
        self._secret_values_main: dict[str, str] = {}
        # 非主密码敏感字段与自定义字段的自动掩码定时器，持久且可取消，
        # 便于 _clear_content 统一停止并清空（历史密码定时器由 PasswordHistoryWidget 自管）。
        self._field_hide_timers: list[QTimer] = []
        # 复制反馈定时器，可取消，避免控件销毁后回调访问已删对象；上限 20 防泄漏。
        self._copy_feedback_timers: OrderedDict[QTimer, QPushButton] = OrderedDict()

        # ---- 子组件 ----
        self._totp_widget = TOTPWidget(self)
        self._totp_widget.copy_requested.connect(self._copy)
        self._totp_widget.copy_feedback.connect(self.copy_feedback.emit)

        self._history_widget = PasswordHistoryWidget(self)
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

    def _add_copy_feedback_timer(self, timer: QTimer, btn: QPushButton) -> None:
        """注册复制反馈定时器，超出上限时回收最旧的（FIFO）并恢复其按钮图标。"""
        if len(self._copy_feedback_timers) >= self._COPY_FEEDBACK_TIMERS_MAX:
            # FIFO 回收最旧：其 _restore 回调因 stop() 不再触发，须主动恢复按钮图标，
            # 否则按钮永久停留 CHECK。sip 守卫防止 btn 已 deleteLater。
            oldest, oldest_btn = self._copy_feedback_timers.popitem(last=False)
            oldest.stop()
            oldest.deleteLater()
            if oldest_btn is not None and not sip.isdeleted(oldest_btn):
                set_icon(oldest_btn, COPY)
        self._copy_feedback_timers[timer] = btn

    def _copy_with_feedback(self, btn: QPushButton, text: str) -> None:
        """复制文本到剪贴板并显示图标反馈，定时恢复为复制图标。"""
        self._copy(text)
        set_icon(btn, CHECK, "success")
        timer = QTimer(self)
        timer.setSingleShot(True)
        self._add_copy_feedback_timer(timer, btn)

        def _restore(btn: QPushButton = btn, t: QTimer = timer) -> None:
            # 定时器回调触发时 btn 可能已 deleteLater 但事件循环未处理，
            # 守卫避免对已释放 C++ 对象调用 set_icon 抛 RuntimeError。
            if sip.isdeleted(btn):
                self._copy_feedback_timers.pop(t, None)
                return
            set_icon(btn, COPY)
            self._copy_feedback_timers.pop(t, None)
            t.deleteLater()

        timer.timeout.connect(_restore)
        timer.start(MS_FEEDBACK)

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # 顶部工具栏
        toolbar = QHBoxLayout()
        toolbar.setContentsMargins(16, 12, 16, 8)

        self._title_label = QLabel("选择一个条目查看详情")
        self._title_label.setObjectName("detailTitle")
        self._title_label.setWordWrap(True)
        toolbar.addWidget(self._title_label)

        toolbar.addStretch()

        self._fav_btn = create_icon_button(STAR_OUTLINE, "收藏", visible=False)
        self._edit_btn = create_icon_button(EDIT, "编辑", visible=False)
        self._delete_btn = create_icon_button(DELETE, "删除", visible=False)
        toolbar.addWidget(self._fav_btn)
        toolbar.addWidget(self._edit_btn)
        toolbar.addWidget(self._delete_btn)

        layout.addLayout(toolbar)

        self._divider = QFrame()
        self._divider.setFixedHeight(1)
        self._divider.setObjectName("detailDivider")
        layout.addWidget(self._divider)

        # 滚动内容
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        self._content = QWidget()
        self._content_layout = QVBoxLayout(self._content)
        self._content_layout.setContentsMargins(20, 16, 20, 16)
        self._content_layout.setSpacing(10)

        self._empty_label = QLabel("请从列表中选择一个条目\n以查看详细信息")
        self._empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty_label.setObjectName("detailEmpty")
        self._content_layout.addWidget(self._empty_label)

        scroll.setWidget(self._content)
        layout.addWidget(scroll)

    @property
    def current_entry(self) -> Entry | None:
        """当前展示的条目，只读访问。"""
        return self._current_entry

    def show_entry(self, entry: Entry, *, force: bool = False) -> None:
        """显示条目详情。

        Args:
            entry: 要显示的条目
            force: 强制重建，主题切换时需要刷新内联样式
        """
        if (
            not force
            and self._current_entry is not None
            and self._current_entry.id == entry.id
            and self._current_entry.updated_at == entry.updated_at
        ):
            return
        logger.debug("显示条目详情: id=%d", entry.id)
        self._prepare_display(entry)
        self._update_header_and_actions(entry)
        self._content_layout.addLayout(self._build_tags_section(entry))
        self._render_integrity_warning(entry)
        self._render_core_form(entry)
        self._render_totp_and_history(entry)
        self._build_meta_section(entry)
        self._render_notes(entry)
        self._render_custom_fields(entry)
        self._content_layout.addStretch()

    def _prepare_display(self, entry: Entry) -> None:
        """切换条目：驱逐上一条目的 TOTP 明文缓存，重置控件并清空内容区。"""
        if self._current_entry is not None and self._current_entry.id != entry.id:
            self._evict_current_totp()
        self._current_entry = entry
        self._pwd_hide_timer.stop()
        self._totp_widget.stop()
        self._clear_content()
        if self._empty_label is not None:
            self._empty_label.hide()

    def _update_header_and_actions(self, entry: Entry) -> None:
        """更新标题与操作按钮可见性，清理并重连按钮信号。

        闭包仅捕获 ``entry.id``，避免信号槽持有整个 entry 引用阻碍 GC。
        """
        self._title_label.setText(f"{entry.type_icon} {entry.title}")
        self._edit_btn.setVisible(not entry.is_deleted)
        self._delete_btn.setVisible(not entry.is_deleted)
        self._fav_btn.setVisible(not entry.is_deleted)
        if not entry.is_deleted:
            set_icon(self._fav_btn, STAR if entry.is_favorite else STAR_OUTLINE)
        disconnect_all(self._signal_connections)
        self._signal_connections.clear()
        eid = entry.id
        self._signal_connections = [
            (self._edit_btn.clicked, lambda: self.edit_requested.emit(eid)),
            (self._delete_btn.clicked, lambda: self.delete_requested.emit(eid)),
            (self._fav_btn.clicked, lambda: self.favorite_toggled.emit(eid)),
        ]
        for signal, slot in self._signal_connections:
            signal.connect(slot)

    def _render_integrity_warning(self, entry: Entry) -> None:
        """完整性错误时显示告警并隐藏编辑按钮，防止覆盖已损坏的加密数据。"""
        if not entry.integrity_error:
            return
        warning = QLabel(
            f"部分数据无法解密：{entry.integrity_message}。为保护原始数据，已禁用编辑。"
        )
        warning.setWordWrap(True)
        warning.setObjectName("detailWarning")
        self._content_layout.addWidget(warning)
        self._edit_btn.hide()

    def _render_core_form(self, entry: Entry) -> None:
        """渲染核心信息区（账号/密码/网址）及密码强度条。"""
        core_form = QFormLayout()
        core_form.setSpacing(10)
        core_form.setHorizontalSpacing(16)
        if entry.username:
            core_form.addRow(*self._make_field_row("账号", entry.username, copyable=True))
        if entry.password:
            core_form.addRow(
                *self._make_field_row("密码", entry.password, secret=True, main_password=True)
            )
        if entry.url:
            core_form.addRow("网址：", self._build_url_label(entry.url))
        self._content_layout.addLayout(core_form)
        if entry.password:
            self._build_strength_bar(entry)

    def _build_url_label(self, url: str) -> QLabel:
        """构建网址标签：http(s) 渲染为可点击链接，其余 scheme 纯文本防注入。

        href 用 quote 编码以容忍空格/中文等字符，避免 RichText 解析器在
        ``<a href="...">`` 内被特殊字符截断；safe 白名单保留 URL 结构字符，
        显示文本用转义后的原文。
        """
        parsed_url = urlparse(url)
        safe_url = parsed_url.scheme.lower() in ("http", "https")
        escaped_url = escape(url, quote=True)
        if safe_url:
            href = quote(url, safe="/:?&=#%+")
            text = (
                f'<a href="{escape(href, quote=True)}" '
                f'style="color: {c("link")}; text-decoration:none;">{escaped_url}</a>'
            )
        else:
            text = escaped_url
        url_label = QLabel(text)
        url_label.setWordWrap(True)
        url_label.setTextFormat(Qt.TextFormat.RichText)
        if safe_url:
            url_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
            url_label.setOpenExternalLinks(True)
        return url_label

    def _render_totp_and_history(self, entry: Entry) -> None:
        """启动 TOTP 显示与密码历史延迟加载 stub。"""
        if entry.has_totp and entry.id and self._entry_mgr is not None:
            self._totp_widget.start(
                entry.id,
                self._entry_mgr,
                self._content_layout,
                entry.totp_secret,
            )
        if entry.id and self._entry_mgr:
            self._history_widget.build_stub(entry.id, self._entry_mgr, self._content_layout)

    def _render_notes(self, entry: Entry) -> None:
        if not entry.notes:
            return
        notes_group = QGroupBox("备注")
        notes_layout = QVBoxLayout(notes_group)
        notes_label = QLabel(entry.notes)
        notes_label.setWordWrap(True)
        notes_label.setObjectName("notesValue")
        notes_layout.addWidget(notes_label)
        self._content_layout.addWidget(notes_group)

    def _render_custom_fields(self, entry: Entry) -> None:
        if not entry.custom_fields:
            return
        cf_timers = self._fields_renderer.render(entry, self._content_layout, self)
        self._field_hide_timers.extend(cf_timers)

    def _build_tags_section(self, entry: Entry) -> QHBoxLayout:
        """构建分类、类型和标签区域。"""
        header_info = QHBoxLayout()
        header_info.setSpacing(8)

        if entry.category_name:
            cat_tag = QLabel(f"  {entry.category_name}  ")
            cat_tag.setObjectName("tag")
            header_info.addWidget(cat_tag)

        if entry.entry_type and entry.entry_type != ENTRY_TYPE_LOGIN:
            type_tag = QLabel(f"  {entry.type_label}  ")
            type_tag.setObjectName("typeTag")
            header_info.addWidget(type_tag)

        for tag in entry.get_tag_list()[:MAX_TAG_DISPLAY]:
            tag_label = QLabel(f"  {tag}  ")
            tag_label.setObjectName("tag")
            header_info.addWidget(tag_label)

        header_info.addStretch()
        return header_info

    def _build_strength_bar(self, entry: Entry) -> None:
        score = entry.password_strength
        strength_color = get_strength_color(score)

        strength_row = QHBoxLayout()
        strength_row.setSpacing(8)

        strength_label_title = QLabel("强度：")
        strength_label_title.setObjectName("fieldLabel")
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

        strength_text = QLabel(f"{_STRENGTH_LABELS.get(score, '未知')} ({score}/4)")
        strength_text.setStyleSheet(f"color: {strength_color}; font-weight: bold; font-size: 12px;")
        strength_row.addWidget(strength_text)

        self._content_layout.addLayout(strength_row)

    def _build_meta_section(self, entry: Entry) -> None:
        """构建时间元数据区域。"""
        meta_form = QFormLayout()
        meta_form.setSpacing(4)
        if entry.created_at:
            meta_form.addRow(QLabel("创建："), QLabel(format_datetime(entry.created_at)))
        if entry.updated_at:
            meta_form.addRow(QLabel("更新："), QLabel(format_datetime(entry.updated_at)))
        if entry.password and entry.password_changed_at:
            meta_form.addRow(
                QLabel("密码更新："), QLabel(format_datetime(entry.password_changed_at))
            )
        for i in range(meta_form.count()):
            item = meta_form.itemAt(i)
            if item:
                w = item.widget()
                if w:
                    w.setObjectName("metaLabel")
        if meta_form.count() > 0:
            self._content_layout.addLayout(meta_form)

    def _make_field_row(
        self,
        label: str,
        value: str,
        *,
        secret: bool = False,
        copyable: bool = False,
        main_password: bool = False,
    ) -> tuple[QLabel, QWidget]:
        """创建字段行的统一入口，根据是否敏感分发到具体方法。

        Args:
            label: 字段名称
            value: 字段值
            secret: 敏感字段，默认掩码显示，支持显示/隐藏切换
            copyable: 是否显示复制按钮，secret=True 时隐含可复制
            main_password: 仅用于主密码字段，追踪引用并使用全局自动隐藏定时器
        """
        # Sensitive 标记值自动以密码框渲染，防止调用方忘传 secret=True
        if secret or isinstance(value, Sensitive):
            return self._make_secret_field_row(label, value, main_password=main_password)
        return self._make_plain_field_row(label, value, copyable=copyable)

    def _make_plain_field_row(
        self,
        label: str,
        value: str,
        *,
        copyable: bool = False,
    ) -> tuple[QLabel, QWidget]:
        """创建普通字段行，明文显示并可选附带复制按钮。"""
        name_label = QLabel(f"{label}：")
        name_label.setObjectName("fieldLabel")

        row_widget = QWidget()
        row_layout = QHBoxLayout(row_widget)
        row_layout.setContentsMargins(0, 0, 0, 0)

        val_label = QLabel(value)
        val_label.setWordWrap(True)
        val_label.setObjectName("fieldValue")
        row_layout.addWidget(val_label, 1)

        if copyable and value:
            copy_btn = QPushButton()
            set_icon(copy_btn, COPY)
            copy_btn.setObjectName("iconBtn")
            copy_btn.setFixedSize(*BTN_COPY)
            copy_btn.setToolTip("复制")

            # 使用闭包捕获当前值，主条目字段无需间接引用，其生命周期与面板同步
            def _copy_value(
                _checked: bool = False, v: str = value, btn: QPushButton = copy_btn
            ) -> None:
                if sip.isdeleted(btn):
                    return
                self._copy_with_feedback(btn, v)

            copy_btn.clicked.connect(_copy_value)
            # 与敏感字段复制按钮一致：复制后发 copy_feedback，经主窗口在状态栏提示。
            copy_btn.clicked.connect(self.copy_feedback.emit)
            row_layout.addWidget(copy_btn)

        return name_label, row_widget

    def _make_secret_field_row(
        self,
        label: str,
        value: str,
        *,
        main_password: bool = False,
    ) -> tuple[QLabel, QWidget]:
        """创建敏感字段行，默认掩码，附带显示/隐藏与复制按钮。

        Args:
            label: 字段名称
            value: 字段值
            main_password: 仅用于主密码字段，追踪引用并使用全局自动隐藏定时器
        """
        if not main_password:
            # 非主密码敏感字段复用共享构建逻辑（与 CustomFieldsRenderer 一致），
            # 明文按 label 键存入 _secret_values_main，切换/锁定时统一清零。
            return make_secret_field_row(
                SecretFieldEnv(
                    store=self._secret_values_main,
                    timers=self._field_hide_timers,
                    parent_widget=self,
                    get_pwd_visible_ms=self._get_pwd_visible_ms,
                    on_copy=self._copy_with_feedback,
                    on_copy_feedback=self.copy_feedback.emit,
                ),
                label,
                value,
                store_key=label,
            )
        # 主密码字段：使用全局 _pwd_hide_timer 与 _current_password 独立引用，
        # 不复用共享逻辑（共享逻辑为每行使用独立 QTimer）。
        name_label = QLabel(f"{label}：")
        name_label.setObjectName("fieldLabel")

        row_widget = QWidget()
        row_layout = QHBoxLayout(row_widget)
        row_layout.setContentsMargins(0, 0, 0, 0)

        val_label = QLabel(PWD_MASK)
        val_label.setObjectName("secretValue")
        row_layout.addWidget(val_label, 1)

        show_btn = QPushButton()
        set_icon(show_btn, EYE)
        show_btn.setObjectName("iconBtn")
        show_btn.setFixedSize(*BTN_COPY)
        show_btn.setToolTip("显示/隐藏")

        self._pwd_label_ref = val_label
        self._show_btn_ref = show_btn
        self._current_password = value

        def _toggle(
            _checked: bool = False, lbl: QLabel = val_label, btn: QPushButton = show_btn
        ) -> None:
            # _clear_content 经 deleteLater 异步销毁控件；销毁窗口期内若仍有挂起的
            # clicked 事件触发闭包，操作已删除的 C++ 对象会抛 RuntimeError。守卫
            # 避免该竞态，与 _signal_connections 在 secure_clear 时显式断开的设计互补。
            if sip.isdeleted(lbl) or sip.isdeleted(btn):
                return
            pwd = self._current_password
            if lbl.text() == PWD_MASK:
                lbl.setText(pwd)
                set_icon(btn, LOCK)
                self._pwd_hide_timer.start(self._get_pwd_visible_ms())
            else:
                lbl.setText(PWD_MASK)
                set_icon(btn, EYE)
                self._pwd_hide_timer.stop()

        show_btn.clicked.connect(_toggle)
        row_layout.addWidget(show_btn)

        copy_btn = QPushButton()
        set_icon(copy_btn, COPY)
        copy_btn.setObjectName("iconBtn")
        copy_btn.setFixedSize(*BTN_COPY)
        copy_btn.setToolTip("复制密码")

        def _copy_secret(_checked: bool = False, btn: QPushButton = copy_btn) -> None:
            if sip.isdeleted(btn):
                return
            self._copy_with_feedback(btn, self._current_password)

        copy_btn.clicked.connect(_copy_secret)
        copy_btn.clicked.connect(self.copy_feedback.emit)
        row_layout.addWidget(copy_btn)

        return name_label, row_widget

    def _get_pwd_visible_ms(self) -> int:
        """获取密码显示自动隐藏的毫秒数。"""
        seconds: int = PWD_VISIBLE_SECONDS_DEFAULT
        if self._config:
            seconds = int(
                self._config.get_safe(CFG_PASSWORD_VISIBLE_SECONDS, PWD_VISIBLE_SECONDS_DEFAULT)
            )
        return seconds * 1000

    def _auto_hide_password(self) -> None:
        if self._pwd_label_ref and self._show_btn_ref:
            self._pwd_label_ref.setText(PWD_MASK)
            set_icon(self._show_btn_ref, EYE)

    def _copy(self, text: str) -> None:
        self._clipboard.copy_text(text)

    def _evict_current_totp(self) -> None:
        """清理当前条目的 TOTP secret 明文缓存（委托 EntryManager）。

        切换条目或清空详情时调用，避免离开条目后 TOTP secret（双因子凭证）
        长期驻留缓存——泄露可独立生成验证码绕过 2FA。锁定/改密由缓存层整体
        失效兜底，此处覆盖「保险库仍解锁但用户已离开该条目」的窗口。
        """
        prev = self._current_entry
        if (
            self._entry_mgr is not None
            and prev is not None
            and prev.id is not None
            and prev.has_totp
        ):
            self._entry_mgr.totp.evict(prev.id)

    def _clear_content(self) -> None:
        """清除详情面板内容，安全擦除敏感数据。"""
        # 停止所有自动掩码定时器，避免清除后对已销毁控件触发回调。
        self._totp_widget.stop()
        self._pwd_hide_timer.stop()
        for timer in self._field_hide_timers:
            timer.stop()
            timer.deleteLater()
        self._field_hide_timers.clear()
        # 取消所有复制反馈定时器，避免控件销毁后回调访问已删对象。
        for timer in self._copy_feedback_timers:
            timer.stop()
            timer.deleteLater()
        self._copy_feedback_timers.clear()
        # 安全擦除主条目字段间接引用中的敏感值
        for k in list(self._secret_values_main):
            mark_secret_discarded(self._secret_values_main[k])
        self._secret_values_main.clear()
        # 清除子组件状态
        self._totp_widget.clear()
        self._history_widget.clear()
        self._fields_renderer.clear()
        mark_secret_discarded(self._current_password)
        self._current_password = ""
        # 先清空主密码 label 明文再置空引用，避免 deleteLater 异步销毁前明文驻留。
        if self._pwd_label_ref is not None:
            self._pwd_label_ref.setText(PWD_MASK)
        self._pwd_label_ref = None
        self._show_btn_ref = None
        # _empty_label 为构造时一次创建的常驻控件，从布局中取出避免被
        # _clear_layout 的 deleteLater 销毁，从而 show_empty 可直接复用。
        if self._empty_label is not None:
            self._content_layout.removeWidget(self._empty_label)
            self._empty_label.hide()
        self._clear_layout(self._content_layout)
        logger.debug("详情面板内容已清除")

    @staticmethod
    def _clear_layout(layout: QLayout) -> None:
        clear_layout(layout)

    def hideEvent(self, a0: QHideEvent | None) -> None:
        """面板隐藏时停止 TOTP 定时器以节省资源。"""
        super().hideEvent(a0)
        if hasattr(self, "_totp_widget"):
            self._totp_widget.stop()

    def showEvent(self, a0: QShowEvent | None) -> None:
        """面板显示时如果当前有条目含 TOTP 则重启定时器。"""
        super().showEvent(a0)
        if (
            hasattr(self, "_totp_widget")
            and hasattr(self, "_current_entry")
            and self._current_entry
            and self._current_entry.has_totp
        ):
            self._totp_widget.resume_if_active()

    def show_empty(self) -> None:
        self._evict_current_totp()
        self._clear_content()
        self._current_entry = None
        self._title_label.setText("选择一个条目查看详情")
        self._edit_btn.hide()
        self._delete_btn.hide()
        self._fav_btn.hide()
        # 复用构造时创建的常驻 _empty_label，仅更新文本并显示，
        # 避免每次 show_empty 频繁 new QLabel + deleteLater 累积。
        self._empty_label.setText("请从列表中选择一个条目\n以查看详细信息")
        self._content_layout.addWidget(self._empty_label)
        self._empty_label.show()

    def secure_clear(self) -> None:
        """安全清除所有敏感数据和信号连接，由主窗口在锁定时调用。"""
        disconnect_all(self._signal_connections)
        self._signal_connections.clear()
        self.show_empty()
