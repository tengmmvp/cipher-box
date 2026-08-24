"""CustomFieldsEditor 测试 — 自定义字段行的增删、类型切换与收集。

覆盖 ``custom_fields_editor.py`` 的动态行管理：添加行（含初始值回填与类型
下拉框定位）、删除行（按 layout 引用精准移除）、类型切换联动值框回显模式
（password 掩码/其余明文）、``collect`` 忽略空名行并返回正确结构、
``clear_rows`` / ``clear_sensitive_values`` 的清空语义。
"""

from PyQt6.QtWidgets import QComboBox, QLineEdit, QPushButton, QVBoxLayout, QWidget

from src.ui.components.custom_fields_editor import CustomFieldsEditor


def _make_editor(qapp) -> tuple[CustomFieldsEditor, QWidget, QVBoxLayout]:
    parent = QWidget()
    layout = QVBoxLayout(parent)
    editor = CustomFieldsEditor(layout)
    parent.show()
    return editor, parent, layout


def _row_widgets(editor: CustomFieldsEditor, idx: int):
    name_edit, type_combo, value_edit, row_layout = editor._rows[idx]
    return name_edit, type_combo, value_edit, row_layout


def _delete_button(row_layout) -> QPushButton:
    widget = row_layout.itemAt(row_layout.count() - 1).widget()
    assert isinstance(widget, QPushButton)
    return widget


class TestAddRow:
    """add_row：控件创建、初始值回填与类型回显模式。"""

    def test_add_default_row_creates_widgets(self, qapp):
        """默认添加一行：字段名/类型/值三个编辑控件 + 删除按钮，加入容器布局。"""
        editor, _parent, layout = _make_editor(qapp)

        editor.add_row()

        assert len(editor._rows) == 1
        assert layout.count() == 1
        name_edit, type_combo, value_edit, _row = _row_widgets(editor, 0)
        assert isinstance(name_edit, QLineEdit)
        assert isinstance(type_combo, QComboBox)
        assert isinstance(value_edit, QLineEdit)
        assert name_edit.text() == ""
        assert value_edit.text() == ""
        assert type_combo.count() == 4  # text/password/url/email

    def test_add_row_backfills_initial_values(self, qapp):
        """初始值回填：名称、值与类型按入参定位（加载已有条目重建场景）。"""
        editor, _parent, _layout = _make_editor(qapp)

        editor.add_row(name="API 密钥", value="sk-123", field_type="password")

        name_edit, type_combo, value_edit, _row = _row_widgets(editor, 0)
        assert name_edit.text() == "API 密钥"
        assert value_edit.text() == "sk-123"
        # password 类型定位到对应下拉索引且值框为掩码回显
        assert type_combo.currentText() == "密码"
        assert value_edit.echoMode() == QLineEdit.EchoMode.Password

    def test_non_password_type_echoes_plaintext(self, qapp):
        """text/url/email 类型值框明文回显。"""
        editor, _parent, _layout = _make_editor(qapp)

        for field_type in ("text", "url", "email"):
            editor.add_row(value="v", field_type=field_type)

        for idx in range(3):
            _name, _combo, value_edit, _row = _row_widgets(editor, idx)
            assert value_edit.echoMode() == QLineEdit.EchoMode.Normal

    def test_unknown_type_falls_back_to_text(self, qapp):
        """未定义类型回退到首个类型（text），不抛异常。"""
        editor, _parent, _layout = _make_editor(qapp)

        editor.add_row(field_type="bogus")

        _name, type_combo, _value, _row = _row_widgets(editor, 0)
        assert type_combo.currentIndex() == 0
        assert type_combo.currentText() == "文本"

    def test_name_length_capped_at_model_limit(self, qapp):
        """字段名输入框 maxLength 与模型层 MAX_CUSTOM_FIELD_NAME 对齐（前端截断）。"""
        from src.models import MAX_CUSTOM_FIELD_NAME

        editor, _parent, _layout = _make_editor(qapp)
        editor.add_row()
        name_edit, _combo, _value, _row = _row_widgets(editor, 0)

        assert name_edit.maxLength() == MAX_CUSTOM_FIELD_NAME


class TestTypeSwitch:
    """类型下拉框切换联动值框回显模式。"""

    def test_switch_to_password_masks_value(self, qapp):
        """切到密码类型：值框切换为掩码回显。"""
        editor, _parent, _layout = _make_editor(qapp)
        editor.add_row(value="plain")
        _name, type_combo, value_edit, _row = _row_widgets(editor, 0)

        type_combo.setCurrentText("密码")  # 经真实 currentIndexChanged 信号驱动

        assert value_edit.echoMode() == QLineEdit.EchoMode.Password

    def test_switch_back_to_text_unmasks_value(self, qapp):
        """密码行切回文本：值框恢复明文回显。"""
        editor, _parent, _layout = _make_editor(qapp)
        editor.add_row(value="secret", field_type="password")
        _name, type_combo, value_edit, _row = _row_widgets(editor, 0)
        assert value_edit.echoMode() == QLineEdit.EchoMode.Password

        type_combo.setCurrentText("文本")

        assert value_edit.echoMode() == QLineEdit.EchoMode.Normal


class TestRemoveRow:
    """remove_row：按 layout 引用移除行。"""

    def test_delete_button_removes_only_that_row(self, qapp):
        """点击某行删除按钮：仅该行被移除，其余行保持。"""
        editor, _parent, layout = _make_editor(qapp)
        editor.add_row(name="first")
        editor.add_row(name="second")
        editor.add_row(name="third")

        _delete_button(_row_widgets(editor, 1)[3]).click()

        assert len(editor._rows) == 2
        assert layout.count() == 2
        remaining_names = [_row_widgets(editor, i)[0].text() for i in range(2)]
        assert remaining_names == ["first", "third"]

    def test_remove_row_by_layout_reference(self, qapp):
        """remove_row 按 layout 引用移除指定行（防索引错位）。"""
        editor, _parent, _layout = _make_editor(qapp)
        editor.add_row(name="a")
        editor.add_row(name="b")

        editor.remove_row(_row_widgets(editor, 0)[3])

        assert len(editor._rows) == 1
        assert _row_widgets(editor, 0)[0].text() == "b"

    def test_clear_rows_empties_all_rows(self, qapp):
        """clear_rows 清空全部行（加载已有条目时重建场景）。"""
        editor, _parent, layout = _make_editor(qapp)
        editor.add_row(name="a")
        editor.add_row(name="b")
        editor.add_row(name="c")

        editor.clear_rows()

        assert editor._rows == []
        assert layout.count() == 0


class TestCollect:
    """collect：结构收集与空名行跳过。"""

    def test_collect_returns_custom_field_structure(self, qapp):
        """收集返回 CustomField 列表：名称去首尾空白、值与类型取当前控件值。"""
        from src.models import CustomField

        editor, _parent, _layout = _make_editor(qapp)
        editor.add_row(name="  服务器  ", value="web-01", field_type="text")
        editor.add_row(name="密钥", value="sk-9", field_type="password")
        editor.add_row(name="邮箱", value="a@b.c", field_type="email")

        fields = editor.collect()

        assert fields == [
            CustomField(name="服务器", value="web-01", field_type="text"),
            CustomField(name="密钥", value="sk-9", field_type="password"),
            CustomField(name="邮箱", value="a@b.c", field_type="email"),
        ]

    def test_collect_skips_empty_and_blank_names(self, qapp):
        """空名与纯空白名行被跳过（不产出空名 CustomField）。"""
        editor, _parent, _layout = _make_editor(qapp)
        editor.add_row(name="", value="ignored-1")
        editor.add_row(name="   ", value="ignored-2")
        editor.add_row(name="有效", value="kept")

        fields = editor.collect()

        assert len(fields) == 1
        assert fields[0].name == "有效"
        assert fields[0].value == "kept"

    def test_collect_reflects_edited_values(self, qapp):
        """收集取编辑后的最新值（用户修改字段名/值后保存）。"""
        editor, _parent, _layout = _make_editor(qapp)
        editor.add_row(name="旧名", value="旧值")

        name_edit, _combo, value_edit, _row = _row_widgets(editor, 0)
        name_edit.setText("新名")
        value_edit.setText("新值")

        fields = editor.collect()
        assert fields[0].name == "新名"
        assert fields[0].value == "新值"

    def test_collect_empty_editor_returns_empty_list(self, qapp):
        """无任何行时返回空列表。"""
        editor, _parent, _layout = _make_editor(qapp)
        assert editor.collect() == []


class TestClearSensitiveValues:
    """clear_sensitive_values：统一清除各类字段值（含 url/email 等同等敏感值）。"""

    def test_clears_values_keeps_names(self, qapp):
        """清除所有值框内容，字段名与类型保留（仅收缩明文驻留，不销毁行）。"""
        editor, _parent, _layout = _make_editor(qapp)
        editor.add_row(name="密码", value="p@ss", field_type="password")
        editor.add_row(name="网址", value="https://x", field_type="url")

        editor.clear_sensitive_values()

        for idx in range(2):
            name_edit, _combo, value_edit, _row = _row_widgets(editor, idx)
            assert value_edit.text() == ""
            assert name_edit.text() != ""  # 名称不清
        assert len(editor._rows) == 2  # 行仍在，可继续编辑
