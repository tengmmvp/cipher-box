"""自定义字段渲染器。

纯工具类，不继承 QWidget，负责将条目的自定义字段渲染到目标布局，
并管理敏感字段的间接引用与自动掩码定时器。返回的定时器列表由
DetailPanel 统一持有，以便在清除内容时一并停止。
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import (
    QFormLayout,
    QGroupBox,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ...business.services.entry_type_schema import all_special_fields_by_storage
from ..resources.constants import FONT_FAMILY_MONOSPACE
from ..resources.theme_colors import c
from .secret_field import (
    PlainFieldEnv,
    RowValueStore,
    SecretFieldEnv,
    make_plain_field_row,
    make_secret_field_row,
)

if TYPE_CHECKING:
    from ...models import Entry

# 模板字段名 → 显示标签，从 entry_type_schema 单一事实源派生，避免平行定义。
_TEMPLATE_FIELD_LABELS = {
    spec.storage_name: spec.label for spec in all_special_fields_by_storage().values()
}

# 字段类型 → 前缀图标标签，供 render 行内显示字段类型徽记。
_FIELD_TYPE_ICONS: dict[str, str] = {
    "password": "[PWD]",
    "url": "[URL]",
    "email": "[MAIL]",
}
_FIELD_TYPE_ICON_DEFAULT = "[TXT]"


class CustomFieldsRenderer:
    """自定义字段渲染器。

    纯工具类，不继承 QWidget。通过 ``render()`` 渲染所有自定义字段
    到目标布局，返回需要管理的 QTimer 列表。
    """

    def __init__(
        self,
        copy_callback: Callable[[QPushButton, str], None],
        copy_feedback_callback: Callable[[], None],
        hide_timer_callback: Callable[[], int],
    ):
        """初始化渲染器。

        Args:
            copy_callback: 复制反馈回调，接收按钮与文本两个参数，无返回值。
            copy_feedback_callback: 复制反馈通知回调，无参数无返回值。
            hide_timer_callback: 密码可见时长回调，无参数返回毫秒数。
        """
        self._copy_callback = copy_callback
        self._copy_feedback_callback = copy_feedback_callback
        self._get_pwd_visible_ms = hide_timer_callback
        # 间接引用明文 holder（MAINT-115）：敏感/普通自定义字段各一份，行号分配
        # 与 mark_secret_discarded 清零由共享 RowValueStore 收口（原与 detail_panel
        # 逐字重复的「dict + 计数器 + 清理块」三件套）。
        self._secret_rows = RowValueStore()
        self._plain_rows = RowValueStore()

    # ---- 公开接口 ----

    def render(
        self,
        entry: Entry,
        layout: QVBoxLayout,
        parent_widget: QWidget,
    ) -> list[QTimer]:
        """渲染所有自定义字段。

        Args:
            entry: Entry 实例
            layout: 目标布局，通常为 DetailPanel._content_layout
            parent_widget: 父控件，用于 QTimer 的父对象管理

        Returns:
            需要外部管理的 QTimer 列表，即字段自动掩码定时器。
        """
        timers: list[QTimer] = []
        custom_fields = entry.custom_fields
        if not isinstance(custom_fields, list):
            return timers
        entry.assert_decrypted()
        # 先收集待渲染行再决定是否挂载分组（QL-030）：值全为空的字段逐行跳过后，
        # 不应残留只有标题的空「自定义字段」分组；有行时才创建分组并 addWidget。
        # timers 由行构建过程追加，与是否挂载分组无关，返回语义不变。
        rows: list[tuple[QLabel, QWidget]] = []
        for cf in custom_fields:
            if not cf.value:
                continue
            icon = _FIELD_TYPE_ICONS.get(cf.field_type, _FIELD_TYPE_ICON_DEFAULT)
            label = _TEMPLATE_FIELD_LABELS.get(cf.name, cf.name)
            if cf.field_type == "password":
                row = self._make_secret_field_row(
                    f"{icon} {label}", cf.value, timers, parent_widget
                )
            else:
                row = self._make_plain_field_row(f"{icon} {label}", cf.value)
            rows.append(row)
        if rows:
            cf_group = QGroupBox("自定义字段")
            cf_layout = QFormLayout(cf_group)
            cf_layout.setSpacing(6)
            for row in rows:
                cf_layout.addRow(*row)
            layout.addWidget(cf_group)
        return timers

    def clear(self) -> None:
        """安全清除所有值（mark_secret_discarded 清零 + 行号复位，MAINT-115 holder 收口）。"""
        self._plain_rows.clear()
        self._secret_rows.clear()

    # ---- 内部方法 ----

    def _make_plain_field_row(
        self,
        label: str,
        value: str,
        *,
        copyable: bool = True,
    ) -> tuple[QLabel, QWidget]:
        """创建普通字段行，明文显示并可选附带复制按钮。

        共享工厂薄委托（MAINT-113）：行构造与复制闭包的 ``sip.isdeleted`` 竞态
        守卫收敛在 ``secret_field.make_plain_field_row`` 单一事实源（原内联实现
        缺失守卫——按钮销毁窗口期内挂起 ``clicked`` 投递直达复制反馈图标写入）。
        行号分配与清零经共享 holder（MAINT-115）。
        """
        return make_plain_field_row(
            PlainFieldEnv(store=self._plain_rows.store, on_copy=self._copy_callback),
            label,
            value,
            self._plain_rows.next_key(),
            copyable=copyable,
        )

    def _make_secret_field_row(
        self,
        label: str,
        value: str,
        timers: list[QTimer],
        parent_widget: QWidget,
    ) -> tuple[QLabel, QWidget]:
        """创建敏感字段行，默认掩码，附带显示/隐藏与复制按钮。

        复用共享构建逻辑，明文按行号键存入间接引用 holder 避免重名键覆盖
        （行号分配与清零经共享 holder，MAINT-115）。
        """
        return make_secret_field_row(
            SecretFieldEnv(
                store=self._secret_rows.store,
                timers=timers,
                parent_widget=parent_widget,
                get_pwd_visible_ms=self._get_pwd_visible_ms,
                on_copy=self._copy_callback,
                on_copy_feedback=self._copy_feedback_callback,
            ),
            label,
            value,
            store_key=self._secret_rows.next_key(),
            name_label_style=f"font-weight: 600; color: {c('text_secondary')};",
            val_label_style=(
                f"font-family: {FONT_FAMILY_MONOSPACE}; font-size: 13px;"
                f" color: {c('text_primary')};"
            ),
        )
