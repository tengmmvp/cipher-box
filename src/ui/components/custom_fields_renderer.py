"""自定义字段渲染器，从 DetailPanel 拆分。

纯工具类，不继承 QWidget，负责将条目的自定义字段渲染到目标布局，
并管理敏感字段的间接引用与自动掩码定时器。返回的定时器列表由
DetailPanel 统一持有，以便在清除内容时一并停止。
"""

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import (
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QWidget,
)

from ...utils.memory import mark_secret_discarded
from ..resources.constants import BTN_COPY, FONT_FAMILY_MONOSPACE
from ..resources.icons import COPY, set_icon
from ..resources.theme_colors import c
from .secret_field import make_secret_field_row

# 模板字段名 → 显示标签，避免每次 render 重建字典
_TEMPLATE_FIELD_LABELS = {
    '_card_holder': '持卡人', '_card_number': '卡号',
    '_card_expiry': '有效期', '_card_cvv': 'CVV',
    '_id_fullname': '姓名', '_id_email': '邮箱',
    '_id_phone': '电话', '_id_address': '地址',
    '_server_host': '主机', '_server_port': '端口',
    '_server_protocol': '协议',
}


class CustomFieldsRenderer:
    """自定义字段渲染器。

    纯工具类，不继承 QWidget。通过 ``render()`` 渲染所有自定义字段
    到目标布局，返回需要管理的 QTimer 列表。
    """

    def __init__(self, copy_callback, copy_feedback_callback, hide_timer_callback):
        """初始化渲染器。

        Args:
            copy_callback: 复制反馈回调，接收按钮与文本两个参数，无返回值。
            copy_feedback_callback: 复制反馈通知回调，无参数无返回值。
            hide_timer_callback: 密码可见时长回调，无参数返回毫秒数。
        """
        self._copy_callback = copy_callback
        self._copy_feedback_callback = copy_feedback_callback
        self._get_pwd_visible_ms = hide_timer_callback
        self._secret_values: dict[int, str] = {}
        self._plain_values: dict[int, str] = {}
        self._plain_row_counter: int = 0
        self._secret_row_counter: int = 0

    # ---- 公开接口 ----

    def render(self, entry, layout, parent_widget) -> list[QTimer]:
        """渲染所有自定义字段。

        Args:
            entry: Entry 实例
            layout: 目标布局，通常为 DetailPanel._content_layout
            parent_widget: 父控件，用于 QTimer 的父对象管理

        Returns:
            需要外部管理的 QTimer 列表，即字段自动掩码定时器。
        """
        timers: list[QTimer] = []
        cf_group = QGroupBox('自定义字段')
        cf_layout = QFormLayout(cf_group)
        cf_layout.setSpacing(6)
        custom_fields = entry.custom_fields
        if not isinstance(custom_fields, list):
            return timers
        entry.assert_decrypted()
        for cf in custom_fields:
            if not cf.value:
                continue
            icon = {'password': '[PWD]', 'url': '[URL]', 'email': '[MAIL]'}.get(cf.field_type, '[TXT]')
            label = _TEMPLATE_FIELD_LABELS.get(cf.name, cf.name)
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
            mark_secret_discarded(self._plain_values[k])
        self._plain_values.clear()
        self._plain_row_counter = 0
        for k in list(self._secret_values):
            mark_secret_discarded(self._secret_values[k])
        self._secret_values.clear()
        self._secret_row_counter = 0

    # ---- 内部方法 ----

    def _make_plain_field_row(
        self, label: str, value: str, *, copyable: bool = True,
    ) -> tuple[QLabel, QWidget]:
        """创建普通字段行，明文显示并可选附带复制按钮。"""
        name_label = QLabel(f'{label}：')
        name_label.setObjectName('fieldLabel')

        row_widget = QWidget()
        row_layout = QHBoxLayout(row_widget)
        row_layout.setContentsMargins(0, 0, 0, 0)

        val_label = QLabel(value)
        val_label.setWordWrap(True)
        val_label.setObjectName('fieldValue')
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
        """创建敏感字段行，默认掩码，附带显示/隐藏与复制按钮。

        复用共享构建逻辑，明文按行索引（row_id）存入间接引用字典避免重名键覆盖。
        """
        row_id = self._secret_row_counter
        self._secret_row_counter += 1
        return make_secret_field_row(
            label, value,
            store=self._secret_values,
            store_key=row_id,
            timers=timers,
            parent_widget=parent_widget,
            get_pwd_visible_ms=self._get_pwd_visible_ms,
            on_copy=self._copy_callback,
            on_copy_feedback=self._copy_feedback_callback,
            name_label_style=f'font-weight: bold; color: {c("text_secondary")};',
            val_label_style=(
                f'font-family: {FONT_FAMILY_MONOSPACE}; font-size: 13px;'
                f' color: {c("text_primary")};'
            ),
        )
