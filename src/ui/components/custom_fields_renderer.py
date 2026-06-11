"""自定义字段渲染器 — 从 DetailPanel 拆分（纯工具类，非 QWidget）"""

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import (
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QWidget,
)

from ..resources.constants import BTN_COPY, FONT_FAMILY_MONOSPACE
from ..resources.icons import COPY, EYE, LOCK, set_icon
from ..resources.theme_colors import c


def zero_buffer_copy(value: str) -> None:
    """尽力零化字符串的编码副本（纵深防御）。

    WARNING: 此方法在 CPython 下**不保证**清除原始字符串内存。
    Python ``str`` 不可变，此方法仅零化 ``encode()`` 后的 bytearray 副本，
    **不影响**原始字符串对象。
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


class CustomFieldsRenderer:
    """自定义字段渲染器。

    纯工具类，不继承 QWidget。通过 ``render()`` 渲染所有自定义字段
    到目标布局，返回需要管理的 QTimer 列表。
    """

    def __init__(self, copy_callback, copy_feedback_callback, hide_timer_callback):
        """初始化渲染器。

        Args:
            copy_callback: 复制反馈回调，签名 (btn: QPushButton, text: str) -> None
            copy_feedback_callback: 复制反馈通知回调，签名 () -> None
            hide_timer_callback: 密码可见时长回调，签名 () -> int（毫秒）
        """
        self._copy_callback = copy_callback
        self._copy_feedback_callback = copy_feedback_callback
        self._get_pwd_visible_ms = hide_timer_callback
        self._secret_values: dict[str, str] = {}
        self._plain_values: dict[int, str] = {}
        self._plain_row_counter: int = 0

    # ---- 公开接口 ----

    def render(self, entry, layout, parent_widget) -> list[QTimer]:
        """渲染所有自定义字段。

        Args:
            entry: Entry 实例
            layout: 目标布局（DetailPanel._content_layout）
            parent_widget: 父控件，用于 QTimer 的父对象管理

        Returns:
            需要外部管理的 QTimer 列表（字段自动掩码定时器）。
        """
        timers: list[QTimer] = []
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
        custom_fields = entry.custom_fields
        if not isinstance(custom_fields, list):
            return timers
        entry.assert_decrypted()
        for cf in custom_fields:
            if not cf.value:
                continue
            icon = {'password': '[PWD]', 'url': '[URL]', 'email': '[MAIL]'}.get(cf.field_type, '[TXT]')
            label = labels.get(cf.name, cf.name)
            if cf.field_type == 'password':
                row = self._make_secret_field_row(f'{icon} {label}', cf.value, timers, parent_widget)
            else:
                row = self._make_plain_field_row(f'{icon} {label}', cf.value)
            cf_layout.addRow(*row)
        layout.addWidget(cf_group)
        return timers

    def clear(self):
        """安全清除所有值。"""
        for k in list(self._plain_values):
            zero_buffer_copy(self._plain_values[k])
        self._plain_values.clear()
        self._plain_row_counter = 0
        for k in list(self._secret_values):
            zero_buffer_copy(self._secret_values[k])
        self._secret_values.clear()

    # ---- 内部方法 ----

    def _make_plain_field_row(
        self, label: str, value: str, *, copyable: bool = True,
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
            # 将明文存入间接引用字典，闭包通过 row_id 读取
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
                self._copy_callback(btn, v)

            copy_btn.clicked.connect(_copy_value)
            row_layout.addWidget(copy_btn)

        return name_label, row_widget

    def _make_secret_field_row(
        self, label: str, value: str, timers: list[QTimer], parent_widget,
    ) -> tuple[QLabel, QWidget]:
        """创建敏感字段行（默认掩码 + 显示/隐藏 + 复制按钮）。"""
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

        # 敏感字段存入间接引用字典，闭包从字典读取而非直接捕获值
        self._secret_values[label] = value
        # 持久单次定时器（可取消）
        field_timer = QTimer(parent_widget)
        field_timer.setSingleShot(True)
        field_timer.timeout.connect(
            lambda lbl=val_label, btn=show_btn: (
                lbl.setText('••••••••'), set_icon(btn, EYE),
            )
        )
        timers.append(field_timer)

        def _toggle(_checked=False, lbl=val_label, btn=show_btn, key=label, timer=field_timer):
            pwd = self._secret_values.get(key, '')
            if lbl.text() == '••••••••':
                lbl.setText(pwd)
                set_icon(btn, LOCK)
                if timer is not None:
                    timer.start(self._get_pwd_visible_ms())
            else:
                lbl.setText('••••••••')
                set_icon(btn, EYE)
                if timer is not None:
                    timer.stop()

        show_btn.clicked.connect(_toggle)
        row_layout.addWidget(show_btn)

        copy_btn = QPushButton()
        set_icon(copy_btn, COPY)
        copy_btn.setObjectName('iconBtn')
        copy_btn.setFixedSize(*BTN_COPY)
        copy_btn.setToolTip('复制密码')

        def _copy_secret(_checked=False, key=label, btn=copy_btn):
            pwd = self._secret_values.get(key, '')
            self._copy_callback(btn, pwd)

        copy_btn.clicked.connect(_copy_secret)
        copy_btn.clicked.connect(self._copy_feedback_callback)
        row_layout.addWidget(copy_btn)

        return name_label, row_widget
