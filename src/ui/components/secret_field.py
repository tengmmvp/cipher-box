"""敏感字段行的共享构建逻辑。

DetailPanel 的非主密码字段与 CustomFieldsRenderer 的自定义字段共用此模块，
消除两处重复的掩码标签、显示/隐藏按钮、复制按钮与间接引用闭包逻辑。

DetailPanel 的主密码字段因使用全局自动隐藏定时器（``_pwd_hide_timer``）与
独立引用（``_current_password``），保留其专属实现，不复用此模块。
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Generic, TypeVar

from PyQt6 import sip
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QWidget

from ..resources.constants import BTN_COPY, PWD_MASK
from ..resources.icons import COPY, EYE, LOCK, set_icon
from .widgets import create_plain_text_label

_StoreKey = TypeVar("_StoreKey")


@dataclass(frozen=True)
class SecretFieldEnv(Generic[_StoreKey]):
    """敏感字段行构建的共享环境（间接引用字典/定时器列表/回调）。

    聚合 6 个跨字段不变的依赖为单一参数，收敛 ``make_secret_field_row`` 的 11 参
    签名。``store`` / ``timers`` 由调用方持有以便锁定或切换条目时统一清零与停止。
    泛型 ``_StoreKey`` 使 ``store`` 键类型与 ``store_key`` 参数保持一致
    （detail_panel 用 str 标签名，custom_fields_renderer 用 int 行号）。
    """

    store: dict[_StoreKey, str]
    timers: list[QTimer]
    parent_widget: QWidget
    get_pwd_visible_ms: Callable[[], int]
    on_copy: Callable[[QPushButton, str], None]
    on_copy_feedback: Callable[[], None]


def make_secret_field_row(
    env: SecretFieldEnv[_StoreKey],
    label_text: str,
    value: str,
    store_key: _StoreKey,
    *,
    name_label_style: str = "",
    val_label_style: str = "",
) -> tuple[QLabel, QWidget]:
    """构建一个敏感字段行：掩码标签 + 显示/隐藏按钮 + 复制按钮。

    明文经 ``env.store[store_key]`` 间接引用，闭包不直接捕获 value，便于调用方
    在切换条目或锁定时统一 ``mark_secret_discarded`` 清零。自动掩码 QTimer 追加到
    ``env.timers``，由调用方持有以便统一停止。

    Args:
        env: 跨字段共享的环境（间接引用字典、定时器列表、回调）。
        label_text: 字段显示名称。
        value: 字段明文值。
        store_key: ``env.store`` 中存储 value 的键，调用方保证唯一。
        name_label_style: 名称标签内联样式；为空则用 objectName ``fieldLabel`` 走 QSS。
        val_label_style: 值标签内联样式；为空则用 objectName ``secretValue`` 走 QSS。
    """
    # name/val 均可能承载用户数据（自定义字段名 / 揭示的敏感值），PlainText
    # 保证 `<` 开头的值按字面显示、与复制内容一致（SEC-030）。
    name_label = create_plain_text_label(f"{label_text}：")
    if name_label_style:
        name_label.setStyleSheet(name_label_style)
    else:
        name_label.setObjectName("fieldLabel")

    row_widget = QWidget()
    row_layout = QHBoxLayout(row_widget)
    row_layout.setContentsMargins(0, 0, 0, 0)

    val_label = create_plain_text_label(PWD_MASK)
    if val_label_style:
        val_label.setStyleSheet(val_label_style)
    else:
        val_label.setObjectName("secretValue")
    row_layout.addWidget(val_label, 1)

    show_btn = QPushButton()
    set_icon(show_btn, EYE)
    show_btn.setObjectName("iconBtn")
    show_btn.setFixedSize(*BTN_COPY)
    show_btn.setToolTip("显示/隐藏")

    env.store[store_key] = value
    field_timer = QTimer(env.parent_widget)
    field_timer.setSingleShot(True)

    def _auto_mask(lbl: QLabel = val_label, btn: QPushButton = show_btn) -> None:
        lbl.setText(PWD_MASK)
        set_icon(btn, EYE)

    field_timer.timeout.connect(_auto_mask)
    env.timers.append(field_timer)

    def _toggle(
        _checked: bool = False,
        lbl: QLabel = val_label,
        btn: QPushButton = show_btn,
        key: _StoreKey = store_key,
        timer: QTimer = field_timer,
    ) -> None:
        # 控件可能已被 `deleteLater`，异步回调（定时器/点击）触发时用 `sip.isdeleted` 守卫，避免访问已销毁控件抛 `RuntimeError`
        if sip.isdeleted(lbl) or sip.isdeleted(btn):
            return
        pwd = env.store.get(key, "")
        if lbl.text() == PWD_MASK:
            lbl.setText(pwd)
            set_icon(btn, LOCK)
            timer.start(env.get_pwd_visible_ms())
        else:
            lbl.setText(PWD_MASK)
            set_icon(btn, EYE)
            timer.stop()

    show_btn.clicked.connect(_toggle)
    row_layout.addWidget(show_btn)

    copy_btn = QPushButton()
    set_icon(copy_btn, COPY)
    copy_btn.setObjectName("iconBtn")
    copy_btn.setFixedSize(*BTN_COPY)
    copy_btn.setToolTip("复制密码")

    def _copy_secret(
        _checked: bool = False, key: _StoreKey = store_key, btn: QPushButton = copy_btn
    ) -> None:
        env.on_copy(btn, env.store.get(key, ""))

    copy_btn.clicked.connect(_copy_secret)
    copy_btn.clicked.connect(env.on_copy_feedback)
    row_layout.addWidget(copy_btn)

    return name_label, row_widget
