"""EntryActionsController 右键菜单与复制动作测试。

覆盖 ``test_entry_actions_controller`` 之外的菜单/复制/分类调度路径：

- ``_build_active_entry_menu``：不同形态条目（登录含 TOTP / 卡片收藏 / 笔记无
  TOTP）的菜单项集合与「动作→处理函数」dispatch 映射；
- 回收站条目菜单（``_show_deleted_entry_menu``）：恢复 / 永久删除调用的
  manager 方法与刷新回调；
- ``_copy_username/_copy_password/_copy_totp``：面板缓存命中分支（PERF-005 复用
  面板已解密明文，不调 manager）vs 未命中分支（延迟解密经 manager）；
- 分类 CRUD 调度：add/edit 对话框装配与 saved→refresh 接线、删除分类确认。

范式沿用 ``test_entry_actions_controller``：MagicMock view/manager + 探针 deps，
``QMenu.exec`` 经类级 monkeypatch 捕获菜单并按文案返回选中项，避免真实模态。
"""

# 测试大量用 MagicMock 注入依赖，抑制其属性访问的静态类型告警
# pyright: reportAttributeAccessIssue=false

from unittest.mock import MagicMock

from PyQt6.QtCore import QPoint
from PyQt6.QtWidgets import QMainWindow, QMenu, QMessageBox

from src.models import Category, Entry
from src.ui.controllers.entry_actions_controller import (
    EntryActionsController,
    EntryActionsDeps,
    EntryActionsView,
)

_CTRL_MODULE = "src.ui.controllers.entry_actions_controller"


def _make_deps(calls: dict[str, list]) -> EntryActionsDeps:
    """构造 EntryActionsDeps，refresh_* 用探针记录调用。"""

    def _probe(name: str):
        calls[name] = []

        def _cb(*args: object) -> None:
            calls[name].append(args)

        return _cb

    return EntryActionsDeps(
        refresh_after_entry_change=_probe("refresh_after_entry_change"),
        refresh_entries_only=_probe("refresh_entries_only"),
        refresh_categories=_probe("refresh_categories"),
        get_dialog_options=lambda: ([], []),
    )


def _make_controller():
    """构造 controller + 探针 dict + detail_panel mock。"""
    calls: dict[str, list] = {}
    detail_panel = MagicMock()
    ctrl = EntryActionsController(
        MagicMock(),
        MagicMock(),
        MagicMock(),
        detail_panel,
        MagicMock(),
        _make_deps(calls),
    )
    return ctrl, calls, detail_panel


def _setup(ctrl: EntryActionsController) -> None:
    """在全新 QMainWindow + mock view 上 setup。"""
    view = EntryActionsView(
        entry_list=MagicMock(),
        category_list=MagicMock(),
        status_bar=MagicMock(),
        add_entry_btn=MagicMock(),
        add_category_btn=MagicMock(),
    )
    ctrl.setup(QMainWindow(), view)


def _menu_texts(menu: QMenu) -> list[str]:
    """菜单项文案列表（过滤分隔符的空文案）。"""
    return [a.text() for a in menu.actions() if a.text()]


def _action_by_text(menu: QMenu, text: str):
    """按文案取菜单动作，找不到时断言失败。"""
    for act in menu.actions():
        if act.text() == text:
            return act
    raise AssertionError(f"菜单中不存在动作：{text}（实际：{_menu_texts(menu)}）")


def _patch_menu_exec(monkeypatch, choose: str) -> dict:
    """类级 patch QMenu.exec：捕获菜单文案并按文案返回选中项。"""

    captured: dict = {}

    def _fake_exec(menu, *args, **kwargs):
        captured["texts"] = _menu_texts(menu)
        for act in menu.actions():
            if act.text() == choose:
                return act
        return None

    monkeypatch.setattr(QMenu, "exec", _fake_exec)
    return captured


class TestActiveEntryMenuItems:
    """_build_active_entry_menu：不同形态条目的菜单项集合。"""

    def test_login_entry_with_totp_menu_items(self, qapp):
        """登录条目（含 TOTP）：含复制验证码 + 收藏（未收藏态）。"""
        ctrl, _, _ = _make_controller()
        _setup(ctrl)
        summary = Entry(
            id=1, title="GitHub", username="alice", entry_type="login", totp_present=True
        )

        menu, handlers = ctrl._build_active_entry_menu(summary)

        assert _menu_texts(menu) == [
            "复制账号",
            "复制密码",
            "复制验证码",
            "编辑",
            "收藏",
            "创建共享包",
            "删除",
        ]
        # 每个动作都有对应的处理函数（含 TOTP 项）
        assert len(handlers) == 7

    def test_card_entry_without_totp_favorite_menu_items(self, qapp):
        """卡片条目（无 TOTP、已收藏）：无复制验证码，收藏项为「取消收藏」。"""
        ctrl, _, _ = _make_controller()
        _setup(ctrl)
        summary = Entry(id=2, title="Visa 卡", entry_type="card", is_favorite=True)

        menu, handlers = ctrl._build_active_entry_menu(summary)

        assert _menu_texts(menu) == [
            "复制账号",
            "复制密码",
            "编辑",
            "取消收藏",
            "创建共享包",
            "删除",
        ]
        assert len(handlers) == 6

    def test_note_entry_without_totp_or_favorite(self, qapp):
        """笔记条目（无 TOTP、未收藏）同样保底基础菜单项。"""
        ctrl, _, _ = _make_controller()
        _setup(ctrl)
        summary = Entry(id=3, title="wifi 备注", entry_type="note")

        menu, handlers = ctrl._build_active_entry_menu(summary)

        assert _menu_texts(menu) == [
            "复制账号",
            "复制密码",
            "编辑",
            "收藏",
            "创建共享包",
            "删除",
        ]
        assert len(handlers) == 6

    def test_entry_without_id_returns_empty_menu(self, qapp):
        """id 为 None 的防御分支返回空菜单（类型收窄防御，不抛异常）。"""
        ctrl, _, _ = _make_controller()
        _setup(ctrl)
        summary = Entry(id=None, title="无 id")

        menu, handlers = ctrl._build_active_entry_menu(summary)

        assert _menu_texts(menu) == []
        assert handlers == {}

    def test_handlers_dispatch_to_expected_actions(self, qapp, monkeypatch):
        """菜单 dispatch：复制/编辑/删除动作的处理函数绑定到对应方法与 entry_id。"""
        ctrl, _, _ = _make_controller()
        _setup(ctrl)
        monkeypatch.setattr(f"{_CTRL_MODULE}.Toast.show", MagicMock())
        ctrl._copy_password = MagicMock()
        ctrl._copy_username = MagicMock()
        ctrl.edit_entry = MagicMock()
        ctrl.delete_entry = MagicMock()
        summary = Entry(id=42, title="dispatch", totp_present=True)

        menu, handlers = ctrl._build_active_entry_menu(summary)
        handlers[_action_by_text(menu, "复制密码")]()
        handlers[_action_by_text(menu, "复制账号")]()
        handlers[_action_by_text(menu, "编辑")]()
        handlers[_action_by_text(menu, "删除")]()
        handlers[_action_by_text(menu, "复制验证码")]()

        ctrl._copy_password.assert_called_once_with(42)
        ctrl._copy_username.assert_called_once_with(42)
        ctrl.edit_entry.assert_called_once_with(42)
        ctrl.delete_entry.assert_called_once_with(42)
        # 复制验证码绑定真实 _copy_totp（未 mock），经 totp 子服务按 entry_id 生成
        ctrl._entry_mgr.totp.generate.assert_called_once_with(42)


class TestDeletedEntryMenu:
    """回收站条目右键菜单：恢复 / 永久删除 dispatch。"""

    def test_deleted_menu_items_and_restore(self, qapp, monkeypatch):
        """已删除条目菜单为 恢复/永久删除；选「恢复」调 restore_entry 并全量刷新。"""
        ctrl, calls, _ = _make_controller()
        _setup(ctrl)
        captured = _patch_menu_exec(monkeypatch, "恢复")
        monkeypatch.setattr(f"{_CTRL_MODULE}.Toast.show", MagicMock())
        deleted = Entry(id=9, title="已删条目", is_deleted=True)

        ctrl._show_deleted_entry_menu(deleted, QPoint(0, 0))

        assert captured["texts"] == ["恢复", "永久删除"]
        ctrl._entry_mgr.restore_entry.assert_called_once_with(9)
        assert calls["refresh_after_entry_change"] == [()]

    def test_deleted_menu_permanent_delete_confirmed(self, qapp, monkeypatch):
        """选「永久删除」并确认 → permanent_delete_entry + 全量刷新。"""
        ctrl, calls, _ = _make_controller()
        _setup(ctrl)
        _patch_menu_exec(monkeypatch, "永久删除")
        monkeypatch.setattr(
            f"{_CTRL_MODULE}.QMessageBox.warning",
            lambda *a, **k: QMessageBox.StandardButton.Yes,
        )
        monkeypatch.setattr(f"{_CTRL_MODULE}.Toast.show", MagicMock())
        deleted = Entry(id=9, title="已删条目", is_deleted=True)

        ctrl._show_deleted_entry_menu(deleted, QPoint(0, 0))

        ctrl._entry_mgr.permanent_delete_entry.assert_called_once_with(9)
        assert calls["refresh_after_entry_change"] == [()]

    def test_deleted_menu_permanent_delete_declined(self, qapp, monkeypatch):
        """永久删除选「否」→ 不删除、不刷新。"""
        ctrl, calls, _ = _make_controller()
        _setup(ctrl)
        _patch_menu_exec(monkeypatch, "永久删除")
        monkeypatch.setattr(
            f"{_CTRL_MODULE}.QMessageBox.warning",
            lambda *a, **k: QMessageBox.StandardButton.No,
        )
        deleted = Entry(id=9, title="已删条目", is_deleted=True)

        ctrl._show_deleted_entry_menu(deleted, QPoint(0, 0))

        ctrl._entry_mgr.permanent_delete_entry.assert_not_called()
        assert calls["refresh_after_entry_change"] == []

    def test_restore_failure_shows_error_no_refresh(self, qapp, monkeypatch):
        """恢复抛异常 → 仅 Toast 错误，不触发刷新。"""
        ctrl, calls, _ = _make_controller()
        _setup(ctrl)
        _patch_menu_exec(monkeypatch, "恢复")
        monkeypatch.setattr(f"{_CTRL_MODULE}.Toast.show", MagicMock())
        ctrl._entry_mgr.restore_entry.side_effect = RuntimeError("db busy")
        deleted = Entry(id=9, title="已删条目", is_deleted=True)

        ctrl._show_deleted_entry_menu(deleted, QPoint(0, 0))

        assert calls["refresh_after_entry_change"] == []

    def test_deleted_menu_locked_skips(self, qapp, monkeypatch):
        """锁定态经 @require_unlocked 跳过回收站菜单（不访问已清零密钥）。"""
        ctrl, _, _ = _make_controller()
        _setup(ctrl)
        ctrl.set_locked(True)
        captured = _patch_menu_exec(monkeypatch, "恢复")
        deleted = Entry(id=9, title="已删条目", is_deleted=True)

        ctrl._show_deleted_entry_menu(deleted, QPoint(0, 0))

        assert captured == {}  # 菜单未构建
        ctrl._entry_mgr.restore_entry.assert_not_called()


class TestCopyActions:
    """_copy_username/_copy_password/_copy_totp：面板缓存命中 vs 未命中。"""

    def test_copy_password_panel_cache_hit_skips_manager(self, qapp, monkeypatch):
        """PERF-005：右键当前详情条目时复用面板已解密明文，不调 get_entry。"""
        ctrl, _, detail_panel = _make_controller()
        _setup(ctrl)
        monkeypatch.setattr(f"{_CTRL_MODULE}.Toast.show", MagicMock())
        detail_panel.current_entry = Entry(id=5, title="当前", password="panel-pwd")

        ctrl._copy_password(5)

        ctrl._clipboard.copy_text.assert_called_once_with("panel-pwd")
        ctrl._entry_mgr.get_entry.assert_not_called()  # 跳过重复全量解密
        detail_panel.copy_feedback.emit.assert_called_once()  # 触发复制反馈

    def test_copy_password_cache_miss_falls_back_to_manager(self, qapp, monkeypatch):
        """面板显示的是其他条目 → 回退延迟解密（get_entry），不发复制反馈。"""
        ctrl, _, detail_panel = _make_controller()
        _setup(ctrl)
        monkeypatch.setattr(f"{_CTRL_MODULE}.Toast.show", MagicMock())
        detail_panel.current_entry = Entry(id=99, title="其他", password="other-pwd")
        ctrl._entry_mgr.get_entry.return_value = Entry(id=5, title="目标", password="mgr-pwd")

        ctrl._copy_password(5)

        ctrl._entry_mgr.get_entry.assert_called_once_with(5)
        ctrl._clipboard.copy_text.assert_called_once_with("mgr-pwd")
        detail_panel.copy_feedback.emit.assert_not_called()

    def test_copy_password_no_panel_selection_falls_back(self, qapp, monkeypatch):
        """面板无选中（current_entry=None）→ 走 manager 延迟解密。"""
        ctrl, _, detail_panel = _make_controller()
        _setup(ctrl)
        monkeypatch.setattr(f"{_CTRL_MODULE}.Toast.show", MagicMock())
        detail_panel.current_entry = None
        ctrl._entry_mgr.get_entry.return_value = Entry(id=5, title="目标", password="mgr-pwd")

        ctrl._copy_password(5)

        ctrl._entry_mgr.get_entry.assert_called_once_with(5)
        ctrl._clipboard.copy_text.assert_called_once_with("mgr-pwd")

    def test_copy_password_empty_password_not_copied(self, qapp, monkeypatch):
        """解密出的密码为空串时不写入剪贴板（不覆盖剪贴板为空内容）。"""
        ctrl, _, detail_panel = _make_controller()
        _setup(ctrl)
        monkeypatch.setattr(f"{_CTRL_MODULE}.Toast.show", MagicMock())
        detail_panel.current_entry = Entry(id=5, title="空密码", password="")

        ctrl._copy_password(5)

        ctrl._clipboard.copy_text.assert_not_called()

    def test_copy_username_always_decrypts_via_manager(self, qapp, monkeypatch):
        """复制账号无面板缓存分支，始终经 get_entry 延迟解密。"""
        ctrl, _, detail_panel = _make_controller()
        _setup(ctrl)
        monkeypatch.setattr(f"{_CTRL_MODULE}.Toast.show", MagicMock())
        detail_panel.current_entry = Entry(id=5, title="当前", username="panel-user")
        ctrl._entry_mgr.get_entry.return_value = Entry(id=5, title="当前", username="mgr-user")

        ctrl._copy_username(5)

        ctrl._entry_mgr.get_entry.assert_called_once_with(5)
        ctrl._clipboard.copy_text.assert_called_once_with("mgr-user")

    def test_copy_totp_copies_generated_code(self, qapp, monkeypatch):
        """复制验证码：TOTP 服务生成验证码后写入剪贴板（UI 不接触 secret）。"""
        ctrl, _, _ = _make_controller()
        _setup(ctrl)
        monkeypatch.setattr(f"{_CTRL_MODULE}.Toast.show", MagicMock())
        ctrl._entry_mgr.totp.generate.return_value = "123456"

        ctrl._copy_totp(7)

        ctrl._entry_mgr.totp.generate.assert_called_once_with(7)
        ctrl._clipboard.copy_text.assert_called_once_with("123456")

    def test_copy_totp_generation_failure_no_copy(self, qapp, monkeypatch):
        """TOTP 生成失败（空码）不写剪贴板，Toast 错误提示。"""
        ctrl, _, _ = _make_controller()
        _setup(ctrl)
        monkeypatch.setattr(f"{_CTRL_MODULE}.Toast.show", MagicMock())
        ctrl._entry_mgr.totp.generate.return_value = ""

        ctrl._copy_totp(7)

        ctrl._clipboard.copy_text.assert_not_called()


class TestCategoryCrudDispatch:
    """分类 CRUD 调度：对话框装配、saved→refresh 接线与删除确认。"""

    def test_add_category_connects_saved_to_refresh_categories(self, qapp, monkeypatch):
        """新增分类：CategoryDialog 打开且 saved 信号连 refresh_categories。"""
        ctrl, calls, _ = _make_controller()
        _setup(ctrl)
        mock_dialog = MagicMock()
        monkeypatch.setattr(f"{_CTRL_MODULE}.CategoryDialog", mock_dialog)

        ctrl.add_category()

        mock_dialog.assert_called_once()
        mock_dialog.return_value.saved.connect.assert_called_once_with(
            ctrl._deps.refresh_categories
        )

    def test_edit_category_passes_existing_category(self, qapp, monkeypatch):
        """编辑分类：查到的 category 传入对话框，saved 连 refresh_categories。"""
        ctrl, calls, _ = _make_controller()
        _setup(ctrl)
        category = Category(id=3, name="工作")
        ctrl._entry_mgr.categories.get_category.return_value = category
        mock_dialog = MagicMock()
        monkeypatch.setattr(f"{_CTRL_MODULE}.CategoryDialog", mock_dialog)

        ctrl._edit_category(3)

        ctrl._entry_mgr.categories.get_category.assert_called_once_with(3)
        assert mock_dialog.call_args.kwargs.get("category") is category
        mock_dialog.return_value.saved.connect.assert_called_once_with(
            ctrl._deps.refresh_categories
        )

    def test_edit_category_missing_silently_returns(self, qapp, monkeypatch):
        """分类已被他处删除（查询为空）→ 静默返回，不打开对话框。"""
        ctrl, _, _ = _make_controller()
        _setup(ctrl)
        ctrl._entry_mgr.categories.get_category.return_value = None
        mock_dialog = MagicMock()
        monkeypatch.setattr(f"{_CTRL_MODULE}.CategoryDialog", mock_dialog)

        ctrl._edit_category(3)

        mock_dialog.assert_not_called()

    def test_delete_category_confirmed_deletes_and_refreshes(self, qapp, monkeypatch):
        """确认删除分类 → sidebar_ctrl.delete_category + 全量条目刷新。"""
        ctrl, calls, _ = _make_controller()
        _setup(ctrl)
        ctrl._sidebar_ctrl.build_delete_message.return_value = ("确定删除「工作」？", True, "工作")
        monkeypatch.setattr(
            f"{_CTRL_MODULE}.QMessageBox.question",
            lambda *a, **k: QMessageBox.StandardButton.Yes,
        )
        monkeypatch.setattr(f"{_CTRL_MODULE}.Toast.show", MagicMock())

        ctrl._delete_category(3)

        ctrl._sidebar_ctrl.delete_category.assert_called_once_with(3)
        assert calls["refresh_after_entry_change"] == [()]

    def test_delete_category_declined_keeps_category(self, qapp, monkeypatch):
        """取消删除 → 不调用删除、不刷新。"""
        ctrl, calls, _ = _make_controller()
        _setup(ctrl)
        ctrl._sidebar_ctrl.build_delete_message.return_value = ("确定删除「工作」？", False, "工作")
        monkeypatch.setattr(
            f"{_CTRL_MODULE}.QMessageBox.question",
            lambda *a, **k: QMessageBox.StandardButton.No,
        )

        ctrl._delete_category(3)

        ctrl._sidebar_ctrl.delete_category.assert_not_called()
        assert calls["refresh_after_entry_change"] == []

    def test_delete_category_failure_shows_error_no_refresh(self, qapp, monkeypatch):
        """删除抛异常 → 仅 Toast 错误，不触发刷新。"""
        ctrl, calls, _ = _make_controller()
        _setup(ctrl)
        ctrl._sidebar_ctrl.build_delete_message.return_value = ("确定删除「工作」？", False, "工作")
        monkeypatch.setattr(
            f"{_CTRL_MODULE}.QMessageBox.question",
            lambda *a, **k: QMessageBox.StandardButton.Yes,
        )
        monkeypatch.setattr(f"{_CTRL_MODULE}.Toast.show", MagicMock())
        ctrl._sidebar_ctrl.delete_category.side_effect = RuntimeError("db locked")

        ctrl._delete_category(3)

        assert calls["refresh_after_entry_change"] == []
