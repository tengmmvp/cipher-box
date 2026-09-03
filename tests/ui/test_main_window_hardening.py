"""MainWindow 锁定清理与交互回归（自 test_product_hardening 按主题拆出）。

覆盖锁定前 UI 明文清理（详情面板/剪贴板/打开中的编辑对话框）、改密成功触发
强制快照、深色主题防抖选条目渲染、标签筛选端到端。经 make_vault_env 建真实
保险库 + build_business_context 组装 MainWindow（与 app.py 构造链同构）。

观察面纪律（MAINT-095）：面板当前条目/敏感值驻留走 DetailPanel 公开观察
property（current_entry / holds_secret_values）；标题标签文本渲染无公开面，
保留 ``_title_label`` 单点白盒观测（豁免于观察 property 判据；豁免类别与
数量口径见 docs/audit_codes.md 的 MAINT-095 豁免台账，本文件属台账 B 类）。
"""

from collections.abc import Callable
from typing import cast

from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication

from src.business.composition import build_business_context
from src.models import Entry
from src.ui.dialogs.entry_dialog import EntryDialog
from src.ui.windows.main_window import MainWindow
from tests.helpers import make_entry_manager

_APP = QApplication.instance() or QApplication([])


def test_lock_preparation_clears_decrypted_ui_and_clipboard(make_vault_env):
    """锁定前清理清空 UI 解密数据与剪贴板残留。"""
    env = make_vault_env(master_password="MasterPassword!2026")
    config = env.config
    vault = env.vault
    manager = env.entry_mgr
    manager.add_entry(Entry(title="Secret", password="VisibleSecret!2026"))
    window = MainWindow(build_business_context(config, vault))
    assert window._entry_model.rowCount() == 1
    window._clipboard.copy_text("VisibleSecret!2026")

    window.prepare_for_lock()
    vault.lock()

    assert window._entry_model.rowCount() == 0
    # 经 DetailPanel 公开观察面断言（MAINT-095）：当前条目引用与敏感明文间接
    # 引用字典均已清空（MAINT-103 收编后主密码不再有独立的 _current_password）
    assert window._detail_panel.current_entry is None
    assert not window._detail_panel.holds_secret_values
    clipboard = QApplication.clipboard()
    assert clipboard is not None
    assert clipboard.text() != "VisibleSecret!2026"
    window.close()


def test_change_master_success_triggers_force_backup(monkeypatch, make_vault_env):
    """改密成功触发强制快照（force=True）。

    回归守护 P0：``show_change_master`` 应委托 ``AutoBackupController.trigger_check``。
    """
    from src.ui.components.toast import Toast
    from src.ui.dialogs.change_master_dialog import ChangeMasterDialog

    env = make_vault_env(master_password="MasterPassword!2026")
    config = env.config
    vault = env.vault
    make_entry_manager(vault).add_entry(Entry(title="t", password="p"))
    # MenuSlots.refresh_all_data 在 MainWindow 构造时捕获 list_refresh.refresh_all_data
    # 的绑定方法；实例级 monkeypatch 不影响已持有 bound method，故构造前打类级桩。
    from src.ui.controllers.list_refresh_controller import ListRefreshController

    monkeypatch.setattr(ListRefreshController, "refresh_all_data", lambda self: None)
    window = MainWindow(build_business_context(config, vault))
    try:
        # mock 改密对话框直接返回 Accepted，跳过真实改密 UI 与 Argon2id 派生
        monkeypatch.setattr(
            ChangeMasterDialog,
            "exec",
            lambda self: ChangeMasterDialog.DialogCode.Accepted,
        )
        # 屏蔽改密成功路径的 UI 副作用，聚焦 trigger_check 调用断言
        monkeypatch.setattr(Toast, "show", lambda *args, **kwargs: None)
        monkeypatch.setattr(window._detail_panel, "show_empty", lambda: None)
        called: list[bool] = []
        monkeypatch.setattr(
            window._auto_backup,
            "trigger_check",
            lambda force=False: called.append(force),
        )

        window._menu.show_change_master()

        assert called == [True]
    finally:
        window.close()


def test_lock_closes_and_scrubs_open_entry_dialog(make_vault_env):
    """锁定关闭已打开的条目编辑对话框并擦除其中明文字段。"""
    env = make_vault_env(master_password="MasterPassword!2026")
    config = env.config
    vault = env.vault
    manager = env.entry_mgr
    entry_id = manager.add_entry(Entry(title="Secret", password="DialogSecret!2026"))
    window = MainWindow(build_business_context(config, vault))
    window.show()
    dialog = EntryDialog(
        manager,
        manager.categories.get_categories(),
        entry=manager.get_entry(entry_id),
        parent=window,
        config=config,
    )
    dialog.show()
    _APP.processEvents()

    window.prepare_for_lock()
    vault.lock()
    _APP.processEvents()

    assert not dialog.isVisible()
    assert dialog._password_edit.text() == ""
    window.close()


def test_selecting_first_entry_opens_detail_panel_without_crash(make_vault_env):
    """深色主题下选中首条目经防抖触发详情面板渲染不崩溃。"""
    env = make_vault_env(master_password="MasterPassword!2026")
    config = env.config
    config.set("theme", "dark")
    vault = env.vault
    manager = env.entry_mgr
    entry_id = manager.add_entry(Entry(title="Selectable", password="Strong!2026Password"))
    window = MainWindow(build_business_context(config, vault))
    window._entry_list.setCurrentIndex(window._entry_model.index(0))
    # 等待 150ms 选择防抖定时器触发并处理事件
    # PyQt6 QtTest.pyi 将 qWait 误标为实例方法，首个形参为 self，
    # 导致 pyright 把位置实参绑定到 self 而报 ms 缺失；此处将 qWait
    # cast 为接受单一 int 的可调用对象，消除类型误差，运行时行为不变。
    cast(Callable[[int], None], QTest.qWait)(150)
    _APP.processEvents()
    # 经 DetailPanel 公开观察面断言（MAINT-095）：防抖回调把选中条目送入面板
    current_entry = window._detail_panel.current_entry
    assert current_entry is not None
    assert current_entry.id == entry_id
    # 标题标签真实渲染了该条目标题（文本渲染无公开面，保留单点白盒观测）
    assert window._detail_panel._title_label.text().endswith("Selectable")
    window.close()


def test_main_window_filters_entries_by_tag(make_vault_env):
    """MainWindow 按标签筛选条目（端到端验证标签过滤管线）。"""
    env = make_vault_env(master_password="MasterPassword!2026")
    config = env.config
    vault = env.vault
    manager = env.entry_mgr
    manager.add_entry(Entry(title="Work", tags="工作,重要"))
    manager.add_entry(Entry(title="Personal", tags="个人"))
    window = MainWindow(build_business_context(config, vault))
    index = window._tag_combo.findData("工作")
    assert index >= 0
    window._tag_combo.setCurrentIndex(index)
    _APP.processEvents()
    assert window._entry_model.rowCount() == 1
    first_entry = window._entry_model.data(window._entry_model.index(0), 256)
    assert first_entry is not None
    assert first_entry.title == "Work"
    window.close()
