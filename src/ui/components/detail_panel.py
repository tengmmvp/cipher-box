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
    PWD_VISIBLE_SECONDS_DEFAULT,
)
from ..resources.icons import (
    CHECK,
    COPY,
    DELETE,
    EDIT,
    SHARE,
    STAR,
    STAR_OUTLINE,
    set_icon,
)
from ..resources.radius import RADIUS_TINY
from ..resources.strings import entry_type_icon, entry_type_label
from ..resources.theme_colors import c, get_strength_color
from .custom_fields_renderer import CustomFieldsRenderer
from .password_history_widget import PasswordHistoryWidget
from .secret_field import SecretFieldEnv, SharedHideTimer, make_secret_field_row
from .totp_widget import TOTPWidget
from .widgets import clear_layout, create_icon_button, create_plain_text_label, disconnect_all

logger = logging.getLogger(__name__)

# 密码强度标签映射，模块级常量避免每次 `show_entry` 重建
_STRENGTH_LABELS = {0: "非常弱", 1: "弱", 2: "一般", 3: "强", 4: "非常强"}


class DetailPanel(QWidget):
    """密码条目详情面板。

    安全说明，受 CPython 运行时限制：
    - 敏感字段明文（含主密码）以 Python `str` 形式存储在间接引用字典
      `self._secret_values_main` 及字段行闭包中（MAINT-103：主密码原独立的
      `self._current_password` 引用收编入同一字典）。
    - Python 字符串不可变，`mark_secret_discarded` 无法覆写原始对象内存。
    - `_clear_content` 通过清空间接引用字典缩短敏感数据的驻留时间；字段行
      闭包经字典读取，清空后闭包读到空值。
    - 主密码字段行经 `SharedHideTimer` 共享单定时器自动掩码（同屏单显式），
      切换条目/锁定时经 `stop()` 先掩码当前显式行再停止计时。
    """

    edit_requested = pyqtSignal(int)
    delete_requested = pyqtSignal(int)
    share_requested = pyqtSignal(int)
    favorite_toggled = pyqtSignal(int)
    copy_feedback = pyqtSignal()

    # 复制反馈定时器上限：可取消定时器替代 `QTimer.singleShot`，控件销毁前需逐个
    # `stop`，上限防止极端情况下的定时器泄漏。
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
        # 当前展示条目的数据世代（SEC-054）：与 _current_entry 同刻记录，经
        # current_data_epoch property 只读透出，force 重建（主题切换持旧条目重显）
        # 时由调用方回传 show_entry 复用——entry 的敏感字段解密于该世代，
        # TOTP 预热写入据此复查。
        self._current_data_epoch: str | None = None
        # 主密码字段的共享单定时器显隐协调器（MAINT-103）：全局一个 QTimer、
        # 同屏单显式，替代原 _pwd_hide_timer + _pwd_label_ref/_show_btn_ref 专属
        # 实现；切换条目/锁定时经 stop() 掩码当前显式行并停止计时。
        self._pwd_hide = SharedHideTimer(self)
        # 主条目敏感字段（含主密码，按标签名键控）的间接引用字典，自定义字段由
        # `renderer` 管理
        self._secret_values_main: dict[str, str] = {}
        # 非主密码敏感字段与自定义字段的自动掩码定时器，持久且可取消，
        # 便于 `_clear_content` 统一停止并清空（历史密码定时器由 `PasswordHistoryWidget` 自管）。
        self._field_hide_timers: list[QTimer] = []
        # 复制反馈定时器，可取消，避免控件销毁后回调访问已删对象；超上限 FIFO 回收防泄漏。
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
            # FIFO 回收最旧：其 `_restore` 回调因 `stop()` 不再触发，须主动恢复按钮图标，
            # 否则按钮永久停留 `CHECK`。`sip.isdeleted` 守卫防止 `btn` 已 `deleteLater`。
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
            # 定时器回调触发时 `btn` 可能已 `deleteLater` 但事件循环未处理，
            # 守卫避免对已释放 C++ 对象调用 `set_icon` 抛 `RuntimeError`。
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

        # 标题承载条目 title（用户/导入数据），PlainText 防富文本注入（SEC-030）
        self._title_label = create_plain_text_label(
            "选择一个条目查看详情", "detailTitle", word_wrap=True
        )
        toolbar.addWidget(self._title_label)

        toolbar.addStretch()

        self._fav_btn = create_icon_button(STAR_OUTLINE, "收藏", visible=False)
        self._edit_btn = create_icon_button(EDIT, "编辑", visible=False)
        self._share_btn = create_icon_button(SHARE, "创建共享包", visible=False)
        self._delete_btn = create_icon_button(DELETE, "删除", visible=False)
        toolbar.addWidget(self._fav_btn)
        toolbar.addWidget(self._edit_btn)
        toolbar.addWidget(self._share_btn)
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

    @property
    def holds_secret_values(self) -> bool:
        """主条目敏感字段间接引用字典是否仍持有明文（测试观察用，MAINT-095）。

        锁定清理守护据此断言敏感明文已随 ``_secret_values_main`` 清空（MAINT-103：
        主密码原独立的 ``_current_password`` 引用已收编入该字典）；只暴露布尔而非
        字典本体，观察面本身不扩散明文。
        """
        return bool(self._secret_values_main)

    @property
    def current_data_epoch(self) -> str | None:
        """当前展示条目的数据世代（SEC-054），只读访问。

        供 force 重建的调用方（主题切换持旧条目重显）回传 ``show_entry`` 的
        ``data_epoch``——面板不再内置「未传时另行快照 key_epoch」的回退分支：
        该最弱分支（现时快照）恰是新调用方漏传时的默认落点，SEC-054 关闭的
        「旧世代 TOTP secret 植入新世代缓存」窗口会对其重开，故 ``data_epoch``
        改为必传、由类型系统强制调用方显式抉择（主路径传 ``get_entry_with_epoch``
        带出的世代，force 重建传本 property 复用的记录世代）。
        """
        return self._current_data_epoch

    def show_entry(
        self,
        entry: Entry,
        *,
        force: bool = False,
        data_epoch: str | None,
    ) -> None:
        """显示条目详情。

        Args:
            entry: 要显示的条目
            force: 强制重建，主题切换时需要刷新内联样式
            data_epoch: **必传**。entry 敏感字段的解密世代（SEC-054 窗口闭合）：
                主路径由 entry_actions_controller 经 ``get_entry_with_epoch`` 从
                读锁内带出，「解密后→预热前」窗口内发生恢复轮换时旧世代 secret
                被 TOTP 预热守卫拒收；force 重建同一条目时传
                ``self.current_data_epoch`` 复用初次展示记录的世代。无默认值是
                有意的：回退「现时快照 key_epoch」的最弱分支曾是漏传调用方的
                静默默认落点（SEC-054 关闭的窗口对其重开），类型系统强制显式抉择。
        """
        if (
            not force
            and self._current_entry is not None
            and self._current_entry.id == entry.id
            and self._current_entry.updated_at == entry.updated_at
        ):
            return
        logger.debug("显示条目详情: id=%d", entry.id)
        # 世代由调用方显式传入并随条目同刻记录（SEC-054）；「未传时现时快照
        # key_epoch」的最弱分支已随必传签名删除（见 current_data_epoch 说明）。
        self._current_data_epoch = data_epoch
        self._prepare_display(entry)
        self._update_header_and_actions(entry)
        self._content_layout.addLayout(self._build_tags_section(entry))
        self._render_integrity_warning(entry)
        self._render_core_form(entry)
        self._render_totp_and_history(entry, data_epoch=data_epoch)
        self._build_meta_section(entry)
        self._render_notes(entry)
        self._render_custom_fields(entry)
        self._content_layout.addStretch()

    def _prepare_display(self, entry: Entry) -> None:
        """切换条目：驱逐上一条目的 TOTP 明文缓存，重置控件并清空内容区。"""
        if self._current_entry is not None and self._current_entry.id != entry.id:
            self._evict_current_totp()
        self._current_entry = entry
        # stop() 顺带掩码当前显式主密码行（若有）：共享单定时器模式下 label 引用
        # 由协调器持有，_clear_content 不再单独掩码（MAINT-103）。
        self._pwd_hide.stop()
        self._totp_widget.stop()
        self._clear_content()
        if self._empty_label is not None:
            self._empty_label.hide()

    def _update_header_and_actions(self, entry: Entry) -> None:
        """更新标题与操作按钮可见性，清理并重连按钮信号。

        闭包仅捕获 ``entry.id``，避免信号槽持有整个 entry 引用阻碍 GC。
        """
        # 类型图标占位符经 UI 展示查表（ARCH-037）：models.ENTRY_TYPES 已收敛为
        # 纯类型键集合，展示元数据单一事实源在 ui/resources/strings.py。
        self._title_label.setText(f"{entry_type_icon(entry.entry_type)} {entry.title}")
        self._edit_btn.setVisible(not entry.is_deleted)
        self._share_btn.setVisible(not entry.is_deleted)
        self._delete_btn.setVisible(not entry.is_deleted)
        self._fav_btn.setVisible(not entry.is_deleted)
        if not entry.is_deleted:
            set_icon(self._fav_btn, STAR if entry.is_favorite else STAR_OUTLINE)
        disconnect_all(self._signal_connections)
        self._signal_connections.clear()
        eid = entry.id
        self._signal_connections = [
            (self._edit_btn.clicked, lambda: self.edit_requested.emit(eid)),
            (self._share_btn.clicked, lambda: self.share_requested.emit(eid)),
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
        self._share_btn.hide()

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

    def _render_totp_and_history(self, entry: Entry, *, data_epoch: str | None) -> None:
        """启动 TOTP 显示与密码历史延迟加载 stub。

        data_epoch 为 show_entry 收到的数据世代（SEC-054，调用方必传），随
        preloaded secret 透传给 TOTP 预热写入做世代复查。
        """
        if entry.has_totp and entry.id and self._entry_mgr is not None:
            self._totp_widget.start(
                entry.id,
                self._entry_mgr,
                self._content_layout,
                entry.totp_secret,
                data_epoch,
            )
        if entry.id and self._entry_mgr:
            self._history_widget.build_stub(entry.id, self._entry_mgr, self._content_layout)

    def _render_notes(self, entry: Entry) -> None:
        """渲染备注区，无备注时跳过。"""
        if not entry.notes:
            return
        notes_group = QGroupBox("备注")
        notes_layout = QVBoxLayout(notes_group)
        # 备注为用户/导入数据，PlainText 按字面显示 `<b>` 等标记（SEC-030）
        notes_label = create_plain_text_label(entry.notes, "notesValue", word_wrap=True)
        notes_layout.addWidget(notes_label)
        self._content_layout.addWidget(notes_group)

    def _render_custom_fields(self, entry: Entry) -> None:
        """渲染自定义字段区，无字段时跳过；返回的掩码定时器交由面板统一持有。"""
        if not entry.custom_fields:
            return
        cf_timers = self._fields_renderer.render(entry, self._content_layout, self)
        self._field_hide_timers.extend(cf_timers)

    def _build_tags_section(self, entry: Entry) -> QHBoxLayout:
        """构建分类、类型和标签区域。"""
        header_info = QHBoxLayout()
        header_info.setSpacing(8)

        if entry.category_name:
            # 分类名与标签均为用户/导入数据，PlainText 标签（SEC-030）
            cat_tag = create_plain_text_label(f"  {entry.category_name}  ", "tag")
            header_info.addWidget(cat_tag)

        if entry.entry_type and entry.entry_type != ENTRY_TYPE_LOGIN:
            # SEC-030 复核：文案为 strings 查表的固定类型标签（非用户数据），保持 QLabel
            type_tag = QLabel(f"  {entry_type_label(entry.entry_type)}  ")
            type_tag.setObjectName("typeTag")
            header_info.addWidget(type_tag)

        for tag in entry.get_tag_list()[:MAX_TAG_DISPLAY]:
            tag_label = create_plain_text_label(f"  {tag}  ", "tag")
            header_info.addWidget(tag_label)

        header_info.addStretch()
        return header_info

    def _build_strength_bar(self, entry: Entry) -> None:
        """构建密码强度条：进度条 + 分值文本，颜色按强度区间映射。"""
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
            QProgressBar {{ background: {c("progress_bg")}; border: none; border-radius: {RADIUS_TINY}px; }}
            QProgressBar::chunk {{ background: {strength_color}; border-radius: {RADIUS_TINY}px; }}
        """)
        strength_row.addWidget(bar, 1)

        strength_text = QLabel(f"{_STRENGTH_LABELS.get(score, '未知')} ({score}/4)")
        strength_text.setStyleSheet(f"color: {strength_color}; font-weight: 600; font-size: 12px;")
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

        # 字段值（如 username）为用户/导入数据，PlainText（SEC-030）
        val_label = create_plain_text_label(value, "fieldValue", word_wrap=True)
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

        全部经共享工厂构建（MAINT-103：主密码原内联手写三件套收编），明文按
        label 键存入 _secret_values_main，切换/锁定时统一清零。

        Args:
            label: 字段名称
            value: 字段值
            main_password: 仅用于主密码字段——注入共享单定时器（同屏单显式、
                切换条目时经 ``_pwd_hide.stop()`` 掩码收缩明文驻留）；其余敏感
                字段每行独立 QTimer，可同时揭示多行
        """
        return make_secret_field_row(
            SecretFieldEnv(
                store=self._secret_values_main,
                timers=self._field_hide_timers,
                parent_widget=self,
                get_pwd_visible_ms=self._get_pwd_visible_ms,
                on_copy=self._copy_with_feedback,
                on_copy_feedback=self.copy_feedback.emit,
                # 共享单定时器模式仅主密码行注入（None 走每行独立定时器默认模式）
                shared_hide=self._pwd_hide if main_password else None,
            ),
            label,
            value,
            store_key=label,
        )

    def _get_pwd_visible_ms(self) -> int:
        """获取密码显示自动隐藏的毫秒数。"""
        seconds: int = PWD_VISIBLE_SECONDS_DEFAULT
        if self._config:
            seconds = int(
                self._config.get_safe(CFG_PASSWORD_VISIBLE_SECONDS, PWD_VISIBLE_SECONDS_DEFAULT)
            )
        return seconds * 1000

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
        # 停止所有自动掩码定时器，避免清除后对已销毁控件触发回调。主密码的共享
        # 单定时器经 stop() 顺带掩码当前显式行（MAINT-103：label 引用由协调器
        # 持有，此处无需单独掩码），deleteLater 异步销毁前明文已收缩。
        self._totp_widget.stop()
        self._pwd_hide.stop()
        for timer in self._field_hide_timers:
            timer.stop()
            timer.deleteLater()
        self._field_hide_timers.clear()
        # 取消所有复制反馈定时器，避免控件销毁后回调访问已删对象。
        for timer in self._copy_feedback_timers:
            timer.stop()
            timer.deleteLater()
        self._copy_feedback_timers.clear()
        # 安全擦除主条目字段间接引用中的敏感值（含主密码，清空后字段行闭包读到空值）
        for k in list(self._secret_values_main):
            mark_secret_discarded(self._secret_values_main[k])
        self._secret_values_main.clear()
        # 清除子组件状态
        self._totp_widget.clear()
        self._history_widget.clear()
        self._fields_renderer.clear()
        # `_empty_label` 为构造时一次创建的常驻控件，从布局中取出避免被
        # `_clear_layout` 的 `deleteLater` 销毁，从而 `show_empty` 可直接复用。
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
        """切回空状态：驱逐当前条目 TOTP、安全清除内容并隐藏操作按钮。"""
        self._evict_current_totp()
        self._clear_content()
        self._current_entry = None
        # 世代随条目一同清空（SEC-054）：空状态无「当前条目的解密世代」可言，
        # 残留旧值会在下一次 show_entry 的 force 复用判定前形成无主状态。
        self._current_data_epoch = None
        self._title_label.setText("选择一个条目查看详情")
        self._edit_btn.hide()
        self._share_btn.hide()
        self._delete_btn.hide()
        self._fav_btn.hide()
        # 复用构造时创建的常驻 `_empty_label`，仅更新文本并显示，
        # 避免每次 `show_empty` 频繁 new `QLabel` + `deleteLater` 累积。
        self._empty_label.setText("请从列表中选择一个条目\n以查看详细信息")
        self._content_layout.addWidget(self._empty_label)
        self._empty_label.show()

    def secure_clear(self) -> None:
        """安全清除所有敏感数据和信号连接，由主窗口在锁定时调用。"""
        disconnect_all(self._signal_connections)
        self._signal_connections.clear()
        self.show_empty()
