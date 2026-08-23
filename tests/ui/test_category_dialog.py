"""CategoryDialog 接线测试：新建/编辑双模式、名称校验与保存回调。

守护「控件值→``EntryManager.categories`` 写入参数」接线：空名前置拦截、合法名新建
（``add_category`` 参数与 ``saved`` 信号）、编辑模式初始回填与改名 ``update_category``
（id 保留）、业务层拒绝（``EntryError``）经 ``to_user_message`` 呈现为 critical 且不
发 ``saved`` 信号。

长度上限说明：名称输入框 ``setMaxLength(MAX_CATEGORY_NAME)``（QL-031）在对话框层
截断超长输入，新增/编辑两路径共享 models 单一事实源上限（manager 不查长度，
``MAX_CATEGORY_NAME`` 此前仅在 ``Category.from_dict``/导入路径生效）。超长名拒收
用例以 mock 模拟业务层 ``EntryError`` 拒绝，守护「拒绝结果→用户可见错误」的接线
不回退为静默成功。

``QMessageBox.warning/critical`` 经 monkeypatch 捕获，避免真实模态阻塞。
"""

from unittest.mock import MagicMock

import pytest
from PyQt6.QtWidgets import QDialog

from src.exceptions import EntryError
from src.models import MAX_CATEGORY_NAME, Category
from src.ui.dialogs.category_dialog import ICON_CANDIDATES, PRESET_COLORS


def _recorder(cap: dict, key: str):
    """返回一个 mock：仅记录 QMessageBox.warning/critical 的调用参数。"""

    def _fn(*args, **kwargs):
        cap.setdefault(key, []).append(args)
        return None

    return _fn


@pytest.fixture
def patched_msgbox(monkeypatch):
    """捕获 QMessageBox.warning / critical，避免模态对话框阻塞测试。"""
    cap: dict = {}
    monkeypatch.setattr(
        "src.ui.dialogs.category_dialog.QMessageBox.warning",
        _recorder(cap, "warning"),
    )
    monkeypatch.setattr(
        "src.ui.dialogs.category_dialog.QMessageBox.critical",
        _recorder(cap, "critical"),
    )
    return cap


def _connect_saved_recorder(dlg) -> list[bool]:
    """记录无参 saved 信号发射次数（lambda 适配零参 append）。"""
    fired: list[bool] = []
    dlg.saved.connect(lambda: fired.append(True))
    return fired


def _make_dialog(mgr, category: Category | None = None):
    from src.ui.dialogs.category_dialog import CategoryDialog

    return CategoryDialog(mgr, category=category)


def _existing_category() -> Category:
    """编辑模式测试用的既有分类。"""
    return Category(id=7, name="社交账号", icon_char="[SOC]", color="#2196F3", sort_order=2)


class TestNewMode:
    """新增模式：空名拦截、合法名保存、业务层拒绝的错误呈现。"""

    def test_empty_name_rejected(self, qapp, patched_msgbox):
        """空名（含纯空白）被拒：弹警告、不写业务层、不发 saved。"""
        mgr = MagicMock()
        dlg = _make_dialog(mgr)
        fired = _connect_saved_recorder(dlg)
        dlg._name_edit.setText("   ")

        dlg._on_save()

        assert patched_msgbox["warning"]
        mgr.categories.add_category.assert_not_called()
        assert fired == []

    def test_valid_name_calls_add_category_and_accepts(self, qapp, patched_msgbox):
        """合法名：add_category 收到名称/图标/颜色，发 saved 并 accept。"""
        mgr = MagicMock()
        dlg = _make_dialog(mgr)
        assert dlg.windowTitle() == "新增分类"
        fired = _connect_saved_recorder(dlg)
        dlg._name_edit.setText("工作账号")

        dlg._on_save()

        mgr.categories.add_category.assert_called_once()
        cat = mgr.categories.add_category.call_args.args[0]
        assert cat.name == "工作账号"
        assert cat.icon_char in ICON_CANDIDATES
        assert cat.color in PRESET_COLORS
        assert fired == [True]
        assert dlg.result() == QDialog.DialogCode.Accepted

    def test_overlong_name_truncated_by_max_length(self, qapp):
        """超长输入（> MAX_CATEGORY_NAME）在输入框层即被截断，不会以超长名直达业务层（QL-031）。"""
        dlg = _make_dialog(MagicMock())
        dlg._name_edit.setText("超" * (MAX_CATEGORY_NAME + 10))
        assert len(dlg._name_edit.text()) == MAX_CATEGORY_NAME

    def test_boundary_length_name_preserved_and_saved(self, qapp):
        """恰在上限的名称完整保留并可保存：截断门禁不误伤合法边界输入。"""
        mgr = MagicMock()
        dlg = _make_dialog(mgr)
        name = "界" * MAX_CATEGORY_NAME
        dlg._name_edit.setText(name)
        assert dlg._name_edit.text() == name

        dlg._on_save()

        mgr.categories.add_category.assert_called_once()
        assert mgr.categories.add_category.call_args.args[0].name == name
        assert dlg.result() == QDialog.DialogCode.Accepted

    def test_normal_length_name_not_truncated(self, qapp):
        """远小于上限的正常名称不受截断影响。"""
        dlg = _make_dialog(MagicMock())
        dlg._name_edit.setText("工作账号")
        assert dlg._name_edit.text() == "工作账号"

    def test_overlong_name_rejected_by_manager_surfaces_critical(self, qapp, patched_msgbox):
        """超长名输入先被 maxLength 截断（QL-031）；manager 侧 EntryError（查重等
        等价拒绝路径）仍呈现 critical 且不发 saved，不回退为静默成功。"""
        mgr = MagicMock()
        mgr.categories.add_category.side_effect = EntryError(
            f"分类名称过长（最多 {MAX_CATEGORY_NAME} 字符）"
        )
        dlg = _make_dialog(mgr)
        fired = _connect_saved_recorder(dlg)
        dlg._name_edit.setText("超" * (MAX_CATEGORY_NAME + 1))

        dlg._on_save()

        mgr.categories.add_category.assert_called_once()
        assert patched_msgbox["critical"]
        text = " ".join(str(arg) for arg in patched_msgbox["critical"][0])
        assert "分类名称过长" in text
        assert fired == []
        assert dlg.result() != QDialog.DialogCode.Accepted


class TestEditMode:
    """编辑模式：初始回填与改名保存。"""

    def test_edit_mode_prefills_form(self, qapp):
        """编辑模式回填名称/图标/颜色，标题切换为「编辑分类」。"""
        dlg = _make_dialog(MagicMock(), category=_existing_category())

        assert dlg.windowTitle() == "编辑分类"
        assert dlg._name_edit.text() == "社交账号"
        assert dlg._icon_combo.currentText() == "[SOC]"
        assert dlg._selected_color == "#2196F3"

    def test_rename_calls_update_category_preserving_id(self, qapp, patched_msgbox):
        """改名保存：update_category 收到新名与保留的 id/图标/颜色，发 saved。"""
        mgr = MagicMock()
        dlg = _make_dialog(mgr, category=_existing_category())
        fired = _connect_saved_recorder(dlg)
        dlg._name_edit.setText("社交账号-新")

        dlg._on_save()

        mgr.categories.update_category.assert_called_once()
        cat = mgr.categories.update_category.call_args.args[0]
        assert cat.id == 7, "编辑保存须保留原分类 id"
        assert cat.name == "社交账号-新"
        assert cat.icon_char == "[SOC]"
        assert cat.color == "#2196F3"
        mgr.categories.add_category.assert_not_called()
        assert fired == [True]
        assert dlg.result() == QDialog.DialogCode.Accepted
