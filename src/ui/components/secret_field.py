"""敏感字段行的共享构建逻辑。

DetailPanel 的非主密码字段与 CustomFieldsRenderer 的自定义字段共用此模块，
消除两处重复的掩码标签、显示/隐藏按钮、复制按钮与间接引用闭包逻辑。

DetailPanel 的主密码字段因使用全局自动隐藏定时器（``_pwd_hide_timer``）与
独立引用（``_current_password``），保留其专属实现，不复用此模块。
"""

from __future__ import annotations

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QWidget

from ..resources.constants import BTN_COPY
from ..resources.icons import COPY, EYE, LOCK, set_icon


def make_secret_field_row(
    label_text: str,
    value: str,
    *,
    store: dict,
    store_key,
    timers: list[QTimer],
    parent_widget,
    get_pwd_visible_ms,
    on_copy,
    on_copy_feedback,
    name_label_style: str = '',
    val_label_style: str = '',
) -> tuple[QLabel, QWidget]:
    """构建一个敏感字段行：掩码标签 + 显示/隐藏按钮 + 复制按钮。

    明文经 ``store[store_key]`` 间接引用，闭包不直接捕获 value，便于调用方
    在切换条目或锁定时统一 ``mark_secret_discarded`` 清零。自动掩码 QTimer 追加到
    ``timers``，由调用方持有以便统一停止。

    Args:
        label_text: 字段显示名称。
        value: 字段明文值。
        store: 间接引用字典，调用方负责清零。
        store_key: ``store`` 中存储 value 的键，调用方保证唯一。
        timers: 接收本行自动掩码 QTimer 的列表。
        parent_widget: QTimer 的父对象。
        get_pwd_visible_ms: 返回显示毫秒数的零参回调。
        on_copy: 复制回调 ``(btn, value) -> None``。
        on_copy_feedback: 复制成功后的反馈回调 ``-> None``。
        name_label_style: 名称标签内联样式；为空则用 objectName ``fieldLabel`` 走 QSS。
        val_label_style: 值标签内联样式；为空则用 objectName ``secretValue`` 走 QSS。
    """
    name_label = QLabel(f'{label_text}：')
    if name_label_style:
        name_label.setStyleSheet(name_label_style)
    else:
        name_label.setObjectName('fieldLabel')

    row_widget = QWidget()
    row_layout = QHBoxLayout(row_widget)
    row_layout.setContentsMargins(0, 0, 0, 0)

    val_label = QLabel('••••••••')
    if val_label_style:
        val_label.setStyleSheet(val_label_style)
    else:
        val_label.setObjectName('secretValue')
    row_layout.addWidget(val_label, 1)

    show_btn = QPushButton()
    set_icon(show_btn, EYE)
    show_btn.setObjectName('iconBtn')
    show_btn.setFixedSize(*BTN_COPY)
    show_btn.setToolTip('显示/隐藏')

    store[store_key] = value
    field_timer = QTimer(parent_widget)
    field_timer.setSingleShot(True)
    field_timer.timeout.connect(
        lambda lbl=val_label, btn=show_btn: (
            lbl.setText('••••••••'), set_icon(btn, EYE),
        )
    )
    timers.append(field_timer)

    def _toggle(_checked=False, lbl=val_label, btn=show_btn, key=store_key, timer=field_timer):
        pwd = store.get(key, '')
        if lbl.text() == '••••••••':
            lbl.setText(pwd)
            set_icon(btn, LOCK)
            timer.start(get_pwd_visible_ms())
        else:
            lbl.setText('••••••••')
            set_icon(btn, EYE)
            timer.stop()

    show_btn.clicked.connect(_toggle)
    row_layout.addWidget(show_btn)

    copy_btn = QPushButton()
    set_icon(copy_btn, COPY)
    copy_btn.setObjectName('iconBtn')
    copy_btn.setFixedSize(*BTN_COPY)
    copy_btn.setToolTip('复制密码')

    def _copy_secret(_checked=False, key=store_key, btn=copy_btn):
        on_copy(btn, store.get(key, ''))

    copy_btn.clicked.connect(_copy_secret)
    copy_btn.clicked.connect(on_copy_feedback)
    row_layout.addWidget(copy_btn)

    return name_label, row_widget
