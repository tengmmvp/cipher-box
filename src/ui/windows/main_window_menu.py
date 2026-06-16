"""MainWindow 菜单与对话框 Mixin

从 main_window.py 提取的菜单栏构建、快捷键注册及各类对话框展示方法。

继承 QMainWindow 以支持 Pyright 静态分析，运行时由 MainWindow 通过
多重继承统一初始化，Mixin 自身不定义 ``__init__``。
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction, QKeySequence, QShortcut
from PyQt6.QtWidgets import QApplication, QMainWindow, QMessageBox

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

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from PyQt6.QtCore import QTimer, pyqtSignal
    from PyQt6.QtWidgets import QLineEdit

    from ...business.managers.backup_restore import BackupRestoreManager
    from ...business.managers.entry_manager import EntryManager
    from ...business.managers.import_export import ImportExportManager
    from ...business.managers.vault_manager import VaultManager
    from ...business.services.security_analyzer import SecurityAnalyzer
    from ...config import ConfigManager
    from ...utils.clipboard import ClipboardManager
    from ..components.detail_panel import DetailPanel

# 快捷键定义：每个条目由按键序列和显示描述组成，供 _setup_shortcuts 与 _show_shortcuts 共享。
_SHORTCUT_DISPLAY = [
    ('Ctrl+N', '新增条目'),
    ('Ctrl+E', '编辑选中条目'),
    ('Ctrl+F', '搜索'),
    ('Ctrl+G', '密码生成器'),
    ('Ctrl+L', '锁定保险库'),
    ('Ctrl+,', '偏好设置'),
    ('Ctrl+Q', '退出'),
    ('Delete', '删除选中条目'),
    ('Escape', '清空搜索/取消选择'),
]


class _MainWindowMenuMixin(QMainWindow):
    """菜单栏、快捷键及对话框方法。

    仅与 MainWindow 组合使用，以下属性由宿主 MainWindow 提供，
    此处声明类型注解供静态分析使用。
    """

    if TYPE_CHECKING:
        _config: ConfigManager
        _vault: VaultManager
        _entry_mgr: EntryManager
        _security: SecurityAnalyzer
        _import_export: ImportExportManager
        _backup: BackupRestoreManager
        _clipboard: ClipboardManager
        _detail_panel: DetailPanel
        _locked_ui: bool
        _status_timer: QTimer
        _shortcuts: list[QShortcut]
        _search_edit: QLineEdit
        lock_requested: pyqtSignal

        def _add_entry(self) -> None: ...
        def _edit_entry(self, entry_id: int) -> None: ...
        def _edit_selected_entry(self) -> None: ...
        def _delete_selected_entry(self) -> None: ...
        def _clear_search(self) -> None: ...
        def _on_password_selected(self, password: str) -> None: ...
        def _refresh_all_data(self) -> None: ...
        def _refresh_after_entry_change(self) -> None: ...
        def _apply_theme(self) -> None: ...
        def _apply_runtime_settings(self) -> None: ...
        def _run_backup_async(self, force: bool = False) -> None: ...

    # ----- 菜单栏 -----

    def _setup_menubar(self):
        menubar = self.menuBar()
        if menubar is None:
            return

        # 文件菜单
        file_menu = menubar.addMenu('文件')
        if file_menu is None:
            return

        add_act = QAction('新增条目', self)
        add_act.setShortcut('Ctrl+N')
        add_act.setIcon(icon(PLUS))
        add_act.setData(PLUS)
        add_act.triggered.connect(self._add_entry)
        file_menu.addAction(add_act)

        file_menu.addSeparator()

        import_act = QAction('导入 / 导出', self)
        import_act.setIcon(icon(UPLOAD))
        import_act.setData(UPLOAD)
        import_act.triggered.connect(self._show_import_export)
        file_menu.addAction(import_act)

        backup_act = QAction('备份与恢复', self)
        backup_act.setIcon(icon(FOLDER))
        backup_act.setData(FOLDER)
        backup_act.triggered.connect(self._show_backup)
        file_menu.addAction(backup_act)

        file_menu.addSeparator()

        lock_act = QAction('锁定保险库', self)
        lock_act.setShortcut('Ctrl+L')
        lock_act.setIcon(icon(LOCK_SOLID))
        lock_act.setData(LOCK_SOLID)
        lock_act.triggered.connect(lambda: self.lock_requested.emit())
        file_menu.addAction(lock_act)

        quit_act = QAction('退出', self)
        quit_act.setShortcut('Ctrl+Q')
        quit_act.setIcon(icon(CLOSE))
        quit_act.setData(CLOSE)
        quit_act.triggered.connect(self.close)
        file_menu.addAction(quit_act)

        # 工具菜单
        tools_menu = menubar.addMenu('工具')
        if tools_menu is None:
            return

        gen_act = QAction('密码生成器', self)
        gen_act.setIcon(icon(GENERATE))
        gen_act.setData(GENERATE)
        gen_act.triggered.connect(self._show_password_generator)
        tools_menu.addAction(gen_act)

        security_act = QAction('安全仪表盘', self)
        security_act.setIcon(icon(SHIELD))
        security_act.setData(SHIELD)
        security_act.triggered.connect(self._show_security_dashboard)
        tools_menu.addAction(security_act)

        # 设置菜单
        settings_menu = menubar.addMenu('设置')
        if settings_menu is None:
            return

        prefs_act = QAction('偏好设置', self)
        prefs_act.setIcon(icon(SETTINGS))
        prefs_act.setData(SETTINGS)
        prefs_act.triggered.connect(self._show_settings)
        settings_menu.addAction(prefs_act)

        change_pwd_act = QAction('修改主密码', self)
        change_pwd_act.setIcon(icon(KEY))
        change_pwd_act.setData(KEY)
        change_pwd_act.triggered.connect(self._show_change_master)
        settings_menu.addAction(change_pwd_act)

        # 帮助菜单
        help_menu = menubar.addMenu('帮助')
        if help_menu is None:
            return

        shortcuts_act = QAction('快捷键', self)
        shortcuts_act.setIcon(icon(SHORTCUT))
        shortcuts_act.setData(SHORTCUT)
        shortcuts_act.triggered.connect(self._show_shortcuts)
        help_menu.addAction(shortcuts_act)

        help_menu.addSeparator()

        about_act = QAction('关于 CipherBox', self)
        about_act.setIcon(icon(HELP))
        about_act.setData(HELP)
        about_act.triggered.connect(self._show_about)
        help_menu.addAction(about_act)

    # ----- 快捷键 -----

    def _setup_shortcuts(self):
        """注册全局快捷键。"""
        shortcuts = [
            ('Ctrl+F', lambda: self._search_edit.setFocus()),
            ('Ctrl+E', self._edit_selected_entry),
            ('Ctrl+G', self._show_password_generator),
            ('Ctrl+,', self._show_settings),
            ('Delete', self._delete_selected_entry),
            ('Escape', self._clear_search),
        ]
        # 保留引用防止 GC 回收：虽然 Qt parent=self 持有引用，
        # 但显式保存更安全，避免 PyPy 等非引用计数实现的回收风险
        self._shortcuts: list[QShortcut] = []
        for key, callback in shortcuts:
            shortcut = QShortcut(QKeySequence(key), self)
            shortcut.activated.connect(callback)
            self._shortcuts.append(shortcut)

    def _update_menu_icons(self):
        """刷新菜单栏图标，主题切换时颜色需要更新。

        按 ``QAction.data()`` 存储的 icon name 重建，而非 ``action.text()`` 反查——
        后者在菜单文案变更（如国际化）时会让图标丢失。
        """
        from PyQt6.QtWidgets import QMenu

        menubar = self.menuBar()
        if menubar is None:
            return
        for menu in menubar.findChildren(QMenu):
            for action in menu.actions():
                icon_name = action.data()
                if icon_name:
                    action.setIcon(icon(icon_name))

    # ----- 对话框 -----

    def _show_password_generator(self):
        dialog = PasswordGeneratorDialog(self._clipboard, self, config=self._config)
        dialog.password_selected.connect(self._on_password_selected)
        dialog.exec()

    def _show_settings(self):
        dialog = SettingsDialog(self._config, self)
        if dialog.exec() == SettingsDialog.DialogCode.Accepted:
            self._apply_theme()
            self._apply_runtime_settings()

    def _show_import_export(self):
        dialog = ImportExportDialog(self._import_export, self._entry_mgr, self)
        dialog.import_completed.connect(self._refresh_all_data)
        dialog.exec()

    def _show_backup(self):
        dialog = BackupDialog(self._backup, self, config=self._config)
        dialog.exec()
        # 仅在对话框实际执行了备份/恢复操作时才全量刷新
        if dialog.data_changed:
            self._refresh_all_data()
            self._detail_panel.show_empty()

    def _show_change_master(self):
        dialog = ChangeMasterDialog(self._vault, self)
        result = dialog.exec()
        if result == ChangeMasterDialog.DialogCode.Accepted:
            self._refresh_all_data()
            self._detail_panel.show_empty()
            # 改密后强制创建当前保险库快照（force=True 绕过自动备份开关）。
            # 即使用户已禁用自动备份，改密快照仍会创建以保留改密前的可回滚点；
            # 显式 Toast 告知，避免用户误以为禁用自动备份后没有任何快照产生。
            self._run_backup_async(force=True)
            from ..components.toast import Toast
            from ..resources.constants import MS_TOAST_DEFAULT
            # 备份异步进行，文案不谎称"已创建"（force=True 绕过开关，可能被并发跳过
            # 或后台失败）。完成后用户可在「备份与恢复」查看。
            Toast.show(
                self, '正在创建改密快照，完成后可在「备份与恢复」中查看或恢复',
                Toast.INFO, duration=MS_TOAST_DEFAULT,
            )
            logger.info("改密成功，已触发强制快照")

    def _show_about(self):
        dialog = AboutDialog(self)
        dialog.exec()

    def _show_security_dashboard(self):
        dialog = SecurityDashboard(self._security, self._entry_mgr, self._config, self)
        # fix_requested 经仪表盘 singleShot(0) 延迟 emit 触发 _edit_entry；
        # 实际刷新由 _edit_entry 内部连接的 EntryDialog.saved 信号驱动，
        # 此处不再依赖仪表盘 Accepted 状态刷新，消除时序耦合。
        dialog.fix_requested.connect(self._edit_entry)
        dialog.exec()

    def _show_shortcuts(self):
        rows = ''.join(
            f'<tr><td>{key}</td><td style="padding-left:12px">{desc}</td></tr>'
            for key, desc in _SHORTCUT_DISPLAY
        )
        text = f'<table>{rows}</table>'
        msg = QMessageBox(self)
        msg.setWindowTitle('快捷键')
        msg.setTextFormat(Qt.TextFormat.RichText)
        msg.setText(text)
        msg.exec()

    def _show_from_tray(self):
        if not self._vault.is_unlocked or self._locked_ui:
            # 锁定时主窗口已隐藏，激活登录窗（由 app 创建并显示）供用户解锁
            from ..dialogs.login_window import LoginWindow
            for widget in QApplication.topLevelWidgets():
                if isinstance(widget, LoginWindow):
                    widget.showNormal()
                    widget.activateWindow()
                    widget.raise_()
                    return
            # 找不到登录窗（异常状态：app 应已显示登录窗）：记录告警，
            # 避免用户点击托盘无反应且无任何反馈
            logger.warning("托盘请求显示但未找到登录窗口")
            return
        self.showNormal()
        self.activateWindow()
        # 从托盘恢复后刷新状态栏摘要：close_to_tray 清了详情面板与 worker，
        # 状态栏可能停留在隐藏前的陈旧文本，重启定时器触发刷新。
        self._status_timer.start()
