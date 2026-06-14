"""自定义字段动态编辑器，从 EntryDialog 拆分。

管理自定义字段行的增删与收集，每行包含字段名、类型与值。
EntryDialog 通过组合持有其实例，将自定义字段的 UI 状态与逻辑
从近 900 行的对话框中分离，降低单类职责负载。
"""

from PyQt6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)

from ...models import CustomField
from ..resources.constants import BTN_COPY
from ..resources.icons import CLOSE, set_icon


class CustomFieldsEditor:
    """自定义字段的动态增删、收集与清理。

    持有字段行布局容器与行记录，提供新增、删除、清空、收集与敏感值清除。
    每行的类型下拉框切换时自动调整值输入框的回显模式。
    """

    # 字段类型到下拉框索引的映射，与下拉框 addItem 顺序一致
    _TYPE_INDEX_MAP = {'text': 0, 'password': 1, 'url': 2, 'email': 3}
    _INDEX_TYPE_MAP = {0: 'text', 1: 'password', 2: 'url', 3: 'email'}

    def __init__(self, container_layout: QVBoxLayout):
        self._container = container_layout
        # 各元素依次为字段名、类型、值编辑框与所在行布局的四元组
        self._rows: list[tuple[QLineEdit, QComboBox, QLineEdit, QHBoxLayout]] = []

    def add_row(self, name: str = '', value: str = '', field_type: str = 'text') -> None:
        """新增一行自定义字段，并绑定类型切换时切换回显模式。"""
        row_layout = QHBoxLayout()
        name_edit = QLineEdit(name)
        name_edit.setPlaceholderText('字段名')
        name_edit.setFixedWidth(120)
        row_layout.addWidget(name_edit)

        type_combo = QComboBox()
        type_combo.addItems(['文本', '密码', '网址', '邮箱'])
        type_combo.setCurrentIndex(self._TYPE_INDEX_MAP.get(field_type, 0))
        type_combo.setFixedWidth(64)
        type_combo.setToolTip('字段类型')
        row_layout.addWidget(type_combo)

        value_edit = QLineEdit(value)
        value_edit.setPlaceholderText('字段值')
        if field_type == 'password':
            value_edit.setEchoMode(QLineEdit.EchoMode.Password)
        type_combo.currentIndexChanged.connect(
            lambda idx, ve=value_edit, tmap=self._INDEX_TYPE_MAP: ve.setEchoMode(
                QLineEdit.EchoMode.Password
                if tmap.get(idx) == 'password'
                else QLineEdit.EchoMode.Normal
            )
        )
        row_layout.addWidget(value_edit)

        del_btn = QPushButton()
        del_btn.setObjectName('iconBtn')
        del_btn.setFixedSize(*BTN_COPY)
        set_icon(del_btn, CLOSE, 'danger')
        del_btn.clicked.connect(lambda: self.remove_row(row_layout))
        row_layout.addWidget(del_btn)

        self._container.addLayout(row_layout)
        self._rows.append((name_edit, type_combo, value_edit, row_layout))

    def remove_row(self, layout: QHBoxLayout) -> None:
        """按 layout 引用定位并移除一行自定义字段。"""
        # 按 layout 引用直接匹配移除，避免依据索引错位
        self._rows = [row for row in self._rows if row[3] is not layout]
        while layout.count():
            item = layout.takeAt(0)
            if item is not None:
                widget = item.widget()
                if widget is not None:
                    widget.deleteLater()
        self._container.removeItem(layout)
        layout.deleteLater()

    def clear_rows(self) -> None:
        """清空所有自定义字段行，供加载已有条目时重建。"""
        while self._rows:
            _name, _type, _value, layout = self._rows.pop()
            while layout.count():
                item = layout.takeAt(0)
                if item is not None:
                    widget = item.widget()
                    if widget is not None:
                        widget.deleteLater()
            self._container.removeItem(layout)
            layout.deleteLater()

    def collect(self) -> list[CustomField]:
        """收集用户填写的自定义字段，忽略名称为空者。"""
        fields = []
        for name_edit, type_combo, value_edit, _layout in self._rows:
            if name_edit.text().strip():
                field_type = self._INDEX_TYPE_MAP.get(type_combo.currentIndex(), 'text')
                fields.append(CustomField(
                    name=name_edit.text().strip(),
                    value=value_edit.text(),
                    field_type=field_type,
                ))
        return fields

    def clear_sensitive_values(self) -> None:
        """清除所有自定义字段的值，缩短明文在控件中的驻留时间。

        自定义字段值可能含密码、密钥、URL、邮箱、CVV 等各类敏感凭据，
        统一清除避免仅清密码型而残留同等敏感的 url/email 等。
        """
        for _name_edit, _type_combo, value_edit, _layout in self._rows:
            value_edit.clear()
