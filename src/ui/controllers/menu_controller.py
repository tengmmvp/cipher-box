"""MainWindow 菜单与对话框调度控制器。

普通类（非 QObject）：``__init__`` 注入 manager 与跨 controller 回调
（``MenuSlots`` frozen dataclass），``setup(parent, search_edit)`` 构建
菜单栏/快捷键。跨 controller 协作一律走 ``MenuSlots`` 回调，pyright 在
装配点逐字段校验每个回调的绑定方法名。
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction, QKeySequence, QShortcut
from PyQt6.QtWidgets import QLineEdit, QMainWindow, QMenu, QMessageBox

from ..dialogs.about_dialog import AboutDialog
from ..dialogs.backup_dialog import BackupDialog
from ..dialogs.change_master_dialog import ChangeMasterDialog
from ..dialogs.import_export_dialog import ImportExportDialog
from ..dialogs.password_generator_dialog import PasswordGeneratorDialog
from ..dialogs.security_dashboard import SecurityDashboard
from ..dialogs.settings_dialog import SettingsDialog
from ..resources.icons import (
    CLOSE,
    FOLDER,
    GENERATE,
    HELP,
    KEY,
    LOCK_SOLID,
    PLUS,
    SETTINGS,
    SHIELD,
    SHORTCUT,
    UPLOAD,
    icon,
)

if TYPE_CHECKING:
    from ...business.managers.backup_restore import BackupRestoreManager
    from ...business.managers.entry_manager import EntryManager
    from ...business.managers.import_export import ImportExportManager
    from ...business.managers.vault_manager import VaultManager
    from ...business.services.security_analyzer import SecurityAnalyzer
    from ...config import ConfigManager
    from ..components.detail_panel import DetailPanel
    from ..utils.clipboard import ClipboardManager
    from .auto_backup_controller import AutoBackupController

logger = logging.getLogger(__name__)

# 菜单项类型：（标签，快捷键|None，图标名，触发回调）。供 _setup_menubar 规格表使用。
_MenuItem = tuple[str, str | None, str, Callable[..., object]]

# 快捷键定义：每个条目由按键序列和显示描述组成，供 setup_shortcuts 与 show_shortcuts 共享。
_SHORTCUT_DISPLAY = [
    ("Ctrl+N", "新增条目"),
    ("Ctrl+E", "编辑选中条目"),
    ("Ctrl+F", "搜索"),
    ("Ctrl+G", "密码生成器"),
    ("Ctrl+L", "锁定保险库"),
    ("Ctrl+,", "偏好设置"),
    ("Ctrl+Q", "退出"),
    ("Delete", "删除选中条目"),
    ("Escape", "清空搜索/取消选择"),
]


@dataclass(frozen=True)
class MenuSlots:
    """菜单/快捷键触发的跨 controller 回调，由 MainWindow 装配（绑定 EntryActions/
    ListRefresh/host 方法）。

    每个字段即一条显式契约，pyright 在装配点校验绑定方法存在且签名匹配。
    """

    add_entry: Callable[[], None]
    edit_entry: Callable[[int], None]
    edit_selected_entry: Callable[[], None]
    delete_selected_entry: Callable[[], None]
    on_password_selected: Callable[[str], None]
    clear_search: Callable[[], None]
    refresh_all_data: Callable[[], None]
    apply_theme: Callable[[], None]
    apply_runtime_settings: Callable[[], None]
    lock: Callable[[], None]


@dataclass(frozen=True)
class MenuDeps:
    """MenuController 依赖的 manager / controller / 控件引用（装配期注入）。

    聚合 9 个依赖为单一参数，对齐既有 ``ListRefreshView`` / ``EntryActionsDeps``
    范式，收敛 MenuController.__init__ 的 10 参签名。frozen 防装配后意外突变。
    """

    config: ConfigManager
    vault: VaultManager
    entry_mgr: EntryManager
    security: SecurityAnalyzer
    import_export: ImportExportManager
    backup: BackupRestoreManager
    clipboard: ClipboardManager
    detail_panel: DetailPanel
    auto_backup: AutoBackupController


class MenuController:
    """菜单栏、全局快捷键与对话框调度。

    ``_show_from_tray`` 操纵窗口可见性、查找 LoginWindow 并读锁定态，属窗口编排，
    保留在 MainWindow。
    """

    _parent: QMainWindow
    _search_edit: QLineEdit

    def __init__(self, deps: MenuDeps, slots: MenuSlots) -> None:
        self._config = deps.config
        self._vault = deps.vault
        self._entry_mgr = deps.entry_mgr
        self._security = deps.security
        self._import_export = deps.import_export
        self._backup = deps.backup
        self._clipboard = deps.clipboard
        self._detail_panel = deps.detail_panel
        self._auto_backup = deps.auto_backup
        self._slots = slots
        self._shortcuts: list[QShortcut] = []

    def setup(self, parent: QMainWindow, search_edit: QLineEdit) -> None:
        """构建菜单栏与快捷键。须在 MainWindow 控件创建后调用。

        parent 用于 QAction/QShortcut 的 Qt 父关系（析构自动断开信号）与 menuBar()/
        close()；search_edit 供 Ctrl+F 聚焦。
        """
        self._parent = parent
        self._search_edit = search_edit
        self._setup_menubar()
        self._setup_shortcuts()

    # ----- 菜单栏 -----

    def _setup_menubar(self) -> None:
        """构建菜单栏（数据驱动：规格表遍历创建 QAction，消除重复堆叠）。

        每项 ``(标签, 快捷键|None, 图标名, 触发回调)``；``None`` 占位表示分隔符。
        ``update_menu_icons`` 按 ``QAction.data()`` 存储的图标名重建，与规格表的
        图标名列对齐。
        """
        parent = self._parent
        menubar = parent.menuBar()
        if menubar is None:
            return
        slots = self._slots
        spec: list[tuple[str, list[_MenuItem | None]]] = [
            (
                "文件",
                [
                    ("新增条目", "Ctrl+N", PLUS, slots.add_entry),
                    None,
                    ("导入 / 导出", None, UPLOAD, self.show_import_export),
                    ("备份与恢复", None, FOLDER, self.show_backup),
                    None,
                    ("锁定保险库", "Ctrl+L", LOCK_SOLID, slots.lock),
                    ("退出", "Ctrl+Q", CLOSE, parent.close),
                ],
            ),
            (
                "工具",
                [
                    ("密码生成器", None, GENERATE, self.show_password_generator),
                    ("安全仪表盘", None, SHIELD, self.show_security_dashboard),
                ],
            ),
            (
                "设置",
                [
                    ("偏好设置", None, SETTINGS, self.show_settings),
                    ("修改主密码", None, KEY, self.show_change_master),
                ],
            ),
            (
                "帮助",
                [
                    ("快捷键", None, SHORTCUT, self.show_shortcuts),
                    None,
                    ("关于 CipherBox", None, HELP, self.show_about),
                ],
            ),
        ]
        for menu_title, items in spec:
            menu = menubar.addMenu(menu_title)
            if menu is None:
                return
            for item in items:
                if item is None:
                    menu.addSeparator()
                    continue
                self._add_menu_action(menu, item)

    def _add_menu_action(self, menu: QMenu, item: _MenuItem) -> None:
        """据规格表条目创建并注册一个 QAction（图标名同时存入 data 供主题刷新重建）。"""
        label, shortcut, icon_name, slot = item
        action = QAction(label, self._parent)
        if shortcut:
            action.setShortcut(shortcut)
        action.setIcon(icon(icon_name))
        action.setData(icon_name)
        action.triggered.connect(slot)
        menu.addAction(action)

    # ----- 快捷键 -----

    def _setup_shortcuts(self) -> None:
        parent = self._parent
        search_edit = self._search_edit
        shortcuts = [
            ("Ctrl+F", lambda: search_edit.setFocus()),
            ("Ctrl+E", self._slots.edit_selected_entry),
            ("Ctrl+G", self.show_password_generator),
            ("Ctrl+,", self.show_settings),
            ("Delete", self._slots.delete_selected_entry),
            ("Escape", self._slots.clear_search),
        ]
        # 保留引用防止 GC 回收：虽然 Qt parent=parent 持有引用，
        # 但显式保存更安全，避免 PyPy 等非引用计数实现的回收风险
        self._shortcuts = []
        for key, callback in shortcuts:
            shortcut = QShortcut(QKeySequence(key), parent)
            shortcut.activated.connect(callback)
            self._shortcuts.append(shortcut)

    def update_menu_icons(self) -> None:
        """刷新菜单栏图标，主题切换时颜色需要更新。

        按 ``QAction.data()`` 存储的 icon name 重建，而非 ``action.text()`` 反查——
        后者在菜单文案变更（如国际化）时会让图标丢失。
        """
        parent = self._parent
        if parent is None:
            return
        menubar = parent.menuBar()
        if menubar is None:
            return
        for menu in menubar.findChildren(QMenu):
            for action in menu.actions():
                icon_name = action.data()
                if icon_name:
                    action.setIcon(icon(icon_name))

    # ----- 对话框 -----

    def show_password_generator(self) -> None:
        """打开密码生成器；选中的密码经 ``on_password_selected`` 回调处理。"""
        dialog = PasswordGeneratorDialog(self._clipboard, self._parent, config=self._config)
        dialog.password_selected.connect(self._slots.on_password_selected)
        dialog.exec()
        dialog.deleteLater()

    def show_settings(self) -> None:
        """打开设置对话框；接受后应用主题与运行时设置（剪贴板/托盘/自动锁定等）。"""
        dialog = SettingsDialog(self._config, self._parent)
        accepted = dialog.exec() == SettingsDialog.DialogCode.Accepted
        dialog.deleteLater()
        if accepted:
            self._slots.apply_theme()
            self._slots.apply_runtime_settings()

    def show_import_export(self) -> None:
        """打开导入/导出对话框；导入完成后全量刷新（条目/分类/标签整体替换）。"""
        dialog = ImportExportDialog(
            self._import_export,
            self._entry_mgr,
            self._parent,
        )
        dialog.import_completed.connect(self._slots.refresh_all_data)
        dialog.exec()
        dialog.deleteLater()

    def show_backup(self) -> None:
        """打开备份/恢复对话框；仅在实际发生备份/恢复时全量刷新并清空详情面板。"""
        dialog = BackupDialog(self._backup, self._parent, config=self._config)
        dialog.exec()
        data_changed = dialog.data_changed
        dialog.deleteLater()
        if data_changed:
            self._slots.refresh_all_data()
            self._detail_panel.show_empty()

    def show_change_master(self) -> None:
        """打开修改主密码对话框；成功后全量刷新并触发强制改密快照。

        快照 ``force=True`` 绕过自动备份开关——即使用户已禁用自动备份，改密前的
        可回滚点仍须保留。Toast 文案不谎称「已创建」（异步可能被并发跳过或失败）。
        """
        dialog = ChangeMasterDialog(self._vault, self._config, self._parent)
        result = dialog.exec()
        dialog.deleteLater()
        if result == ChangeMasterDialog.DialogCode.Accepted:
            self._slots.refresh_all_data()
            self._detail_panel.show_empty()
            self._auto_backup.trigger_check(force=True)
            from ..components.toast import Toast
            from ..resources.constants import MS_TOAST_DEFAULT

            Toast.show(
                self._parent,
                "正在创建改密快照，完成后可在「备份与恢复」中查看或恢复",
                Toast.INFO,
                duration=MS_TOAST_DEFAULT,
            )
            logger.info("改密成功，已触发强制快照")

    def show_about(self) -> None:
        dialog = AboutDialog(self._parent)
        dialog.exec()
        dialog.deleteLater()

    def show_security_dashboard(self) -> None:
        """打开安全仪表盘；exec 返回后同步处理 pending 修复条目（M14）。

        替代原 ``singleShot(0)`` 延迟 emit——dialog 随即 ``deleteLater``，延迟回调
        访问已销毁 dialog 的信号会崩溃，故同步打开编辑对话框为单层模态。
        """
        dialog = SecurityDashboard(
            self._security,
            self._entry_mgr,
            self._config,
            self._parent,
        )
        dialog.exec()
        pending_fix_id = dialog.pending_fix_id
        dialog.deleteLater()
        if pending_fix_id is not None:
            self._slots.edit_entry(pending_fix_id)

    def show_shortcuts(self) -> None:
        rows = "".join(
            f'<tr><td>{key}</td><td style="padding-left:12px">{desc}</td></tr>'
            for key, desc in _SHORTCUT_DISPLAY
        )
        text = f"<table>{rows}</table>"
        msg = QMessageBox(self._parent)
        msg.setWindowTitle("快捷键")
        msg.setTextFormat(Qt.TextFormat.RichText)
        msg.setText(text)
        msg.exec()
        msg.deleteLater()
