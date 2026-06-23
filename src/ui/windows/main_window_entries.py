"""MainWindow 条目 CRUD、分类管理与右键菜单 Mixin。

从 main_window_filters.py 拆分（控制单文件规模）：条目增删改、收藏切换、
条目/分类右键菜单、分类 CRUD、复制反馈与密码生成器回调等「数据操作」方法。
搜索/排序/过滤刷新方法保留在 main_window_filters.py。两组方法经 MainWindow
多重继承共享同一 self，跨组调用（如 ``_delete_entry → _refresh_after_entry_change``）
经 self 解析，与拆分前行为完全一致。

继承 QMainWindow 以支持 Pyright 静态分析，运行时由 MainWindow 多重继承统一
初始化，Mixin 自身不定义 ``__init__``。
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from PyQt6.QtCore import QModelIndex, QPoint, Qt
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import QMainWindow, QMenu, QMessageBox

from ..components.toast import Toast
from ..dialogs.category_dialog import CategoryDialog
from ..dialogs.entry_dialog import EntryDialog
from ..resources.constants import MS_TOAST_DEFAULT, MS_TOAST_LONG, MS_TOAST_SHORT
from ..resources.icons import CLOSE, COPY, DELETE, EDIT, REFRESH, STAR, STAR_OUTLINE, icon
from .main_window_mixin_base import _require_unlocked

if TYPE_CHECKING:
    from PyQt6.QtCore import QTimer
    from PyQt6.QtWidgets import QLineEdit, QListView, QListWidget, QStatusBar

    from ...business.managers.entry_manager import EntryManager
    from ...config import ConfigManager
    from ...models import Category, Entry
    from ..components.detail_panel import DetailPanel
    from ..controllers.sidebar_controller import SidebarController as _SidebarController
    from ..utils.clipboard import ClipboardManager


class _MainWindowEntriesMixin(QMainWindow):
    """条目 CRUD、分类管理与右键菜单方法。

    仅与 MainWindow 组合使用，以下属性由宿主 MainWindow 提供，此处声明类型
    注解供静态分析（与 ``_MainWindowFiltersMixin`` 声明一致，多重继承下同类型
    重复声明无冲突）。与 filters Mixin 共享同一 MainWindow 实例，跨 Mixin 方法
    调用经 self 解析。
    """

    # 宿主 MainWindow 提供的实例属性类型注解
    _config: ConfigManager
    _entry_mgr: EntryManager
    _clipboard: ClipboardManager
    _detail_panel: DetailPanel
    _sidebar_ctrl: _SidebarController
    _status_bar: QStatusBar
    _entry_list: QListView
    _search_edit: QLineEdit
    _category_list: QListWidget
    _select_timer: QTimer
    _pending_selection: int | None
    _locked_ui: bool
    _cached_categories: list[Category]
    _cached_tag_names: list[str]

    if TYPE_CHECKING:
        # 跨 Mixin 方法：由 _MainWindowFiltersMixin 提供，运行时经 MainWindow
        # 多重继承解析。此处仅声明签名供静态分析，避免 Entries Mixin 单独
        # 看不到这些方法时报「属性未知」。
        def _refresh_after_entry_change(self) -> None: ...
        def _refresh_entries_only(self) -> None: ...
        def _refresh_categories(self) -> None: ...

    # ======== 条目选择 ========

    def _on_entry_selected(self, current: QModelIndex, _previous: QModelIndex) -> None:
        if current.isValid():
            self._pending_selection = current.row()
            self._select_timer.start()

    def _do_select_entry(self) -> None:
        """防抖后的条目选择：执行解密并显示。

        校验 pending_selection 仍是列表当前选中项：后台刷新可能在防抖窗口内
        重建列表，使该条目被删除或替换，此时不应再用其 id 解密显示，避免
        详情面板与列表当前选中不一致。
        """
        current_row = self._pending_selection
        # 取值后立即重置，避免 timer 再次触发时复用过期引用
        self._pending_selection = None
        if self._locked_ui:
            return
        if current_row is None:
            return
        # 后台刷新可能已重建列表，确认 pending 行仍是当前选中行；
        # 失败说明选中已改变，清空详情面板避免残留与列表不一致的旧条目
        idx = self._entry_list.currentIndex()
        if idx.row() != current_row:
            self._detail_panel.show_empty()
            return
        summary = idx.data(Qt.ItemDataRole.UserRole)
        if summary:
            entry = self._entry_mgr.get_entry(summary.id)
            if entry:
                self._detail_panel.show_entry(entry)

    # ======== 条目右键菜单 ========

    def _on_entry_context_menu(self, pos: QPoint) -> None:
        """条目右键菜单 — 路由到已删除/活跃条目子菜单。"""
        index = self._entry_list.indexAt(pos)
        if not index.isValid():
            return

        summary = index.data(Qt.ItemDataRole.UserRole)
        if not summary:
            return
        if summary.is_deleted:
            self._show_deleted_entry_menu(summary, pos)
        else:
            self._show_active_entry_menu(summary, pos)

    def _show_deleted_entry_menu(self, entry: Entry, pos: QPoint) -> None:
        """回收站条目右键菜单。"""
        # 列表条目必来自 DB，id 非 None；守卫后 entry_id 收窄为 int 供下游调用。
        if entry.id is None:
            return
        entry_id = entry.id
        menu = QMenu(self)
        restore_act = QAction('恢复', self)
        restore_act.setIcon(icon(REFRESH))
        menu.addAction(restore_act)
        delete_act = QAction('永久删除', self)
        delete_act.setIcon(icon(CLOSE, 'danger'))
        menu.addAction(delete_act)

        chosen = menu.exec(self._entry_list.mapToGlobal(pos))

        if chosen == restore_act:
            self._entry_mgr.restore_entry(entry_id)
            self._refresh_after_entry_change()
            Toast.show(self, f'已恢复「{entry.title}」', Toast.SUCCESS)
        elif chosen == delete_act:
            reply = QMessageBox.warning(
                self, '永久删除',
                f'确定要永久删除「{entry.title}」吗？\n此操作不可撤销！',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.Yes:
                self._entry_mgr.permanent_delete_entry(entry_id)
                self._refresh_after_entry_change()

    def _show_active_entry_menu(self, summary: Entry, pos: QPoint) -> None:
        """活跃条目右键菜单 — dict dispatch，复制操作延迟解密。"""
        # 列表条目必来自 DB，id 非 None；守卫后由 _build_active_entry_menu 收窄为 int。
        if summary.id is None:
            return
        menu, handlers = self._build_active_entry_menu(summary)
        chosen = menu.exec(self._entry_list.mapToGlobal(pos))
        if chosen is None:
            return
        handler = handlers.get(chosen)
        if handler is not None:
            handler()

    def _build_active_entry_menu(
        self, summary: Entry,
    ) -> tuple[QMenu, dict[QAction, Callable[[], None]]]:
        """构造活跃条目右键菜单及其「动作→处理函数」映射。

        dict dispatch 替代 if/elif 链；复制类处理延迟解密（菜单打开期间可能触发
        自动锁定，处理函数内守卫 ``_locked_ui`` 避免锁定态访问已清零密钥）。
        """
        entry_id = summary.id
        if entry_id is None:  # 调用方 _show_active_entry_menu 已守卫，此处为类型收窄防御
            return QMenu(self), {}
        menu = QMenu(self)

        copy_user_act = QAction('复制账号', self)
        copy_user_act.setIcon(icon(COPY))
        menu.addAction(copy_user_act)
        copy_pwd_act = QAction('复制密码', self)
        copy_pwd_act.setIcon(icon(COPY))
        menu.addAction(copy_pwd_act)

        # TOTP 验证码：仅当条目配置了 TOTP 密钥时显示
        copy_totp_act: QAction | None = None
        if summary.has_totp:
            copy_totp_act = QAction('复制验证码', self)
            copy_totp_act.setIcon(icon(COPY))
            menu.addAction(copy_totp_act)

        menu.addSeparator()
        edit_act = QAction('编辑', self)
        edit_act.setIcon(icon(EDIT))
        menu.addAction(edit_act)
        if summary.is_favorite:
            fav_act = QAction('取消收藏', self)
            fav_act.setIcon(icon(STAR_OUTLINE))
        else:
            fav_act = QAction('收藏', self)
            fav_act.setIcon(icon(STAR))
        menu.addAction(fav_act)
        menu.addSeparator()
        del_act = QAction('删除', self)
        del_act.setIcon(icon(DELETE))
        menu.addAction(del_act)

        def _toggle_favorite() -> None:
            self._entry_mgr.toggle_favorite(entry_id)
            self._refresh_entries_only()

        handlers: dict[QAction, Callable[[], None]] = {
            copy_user_act: lambda: self._menu_copy_username(entry_id),
            copy_pwd_act: lambda: self._menu_copy_password(entry_id),
            edit_act: lambda: self._edit_entry(entry_id),
            fav_act: _toggle_favorite,
            del_act: lambda: self._delete_entry(entry_id),
        }
        if copy_totp_act is not None:
            handlers[copy_totp_act] = lambda: self._menu_copy_totp(entry_id)
        return menu, handlers

    @_require_unlocked
    def _menu_copy_username(self, entry_id: int) -> None:
        """延迟解密并复制条目账号；锁定态守卫避免访问已清零密钥。"""
        entry = self._entry_mgr.get_entry(entry_id)
        if entry and entry.username:
            self._clipboard.copy_text(entry.username)
            Toast.show(self, '已复制账号', Toast.SUCCESS, duration=MS_TOAST_SHORT)

    @_require_unlocked
    def _menu_copy_password(self, entry_id: int) -> None:
        """延迟解密并复制条目密码；仅当右键的是当前详情条目时触发复制反馈。"""
        entry = self._entry_mgr.get_entry(entry_id)
        if entry and entry.password:
            self._clipboard.copy_text(entry.password)
            current = self._detail_panel.current_entry
            if current is not None and current.id == entry_id:
                self._detail_panel.copy_feedback.emit()
            Toast.show(self, '已复制密码', Toast.SUCCESS, duration=MS_TOAST_SHORT)

    @_require_unlocked
    def _menu_copy_totp(self, entry_id: int) -> None:
        """生成并复制 TOTP 验证码；UI 层不接触明文 TOTP secret。"""
        code = self._entry_mgr.totp.generate(entry_id)
        if code:
            self._clipboard.copy_text(code)
            Toast.show(self, '验证码已复制', Toast.SUCCESS, duration=MS_TOAST_SHORT)
        else:
            Toast.show(self, '验证码生成失败，请检查密钥', Toast.ERROR, duration=MS_TOAST_DEFAULT)

    def _on_category_context_menu(self, pos: QPoint) -> None:
        """分类右键菜单。"""
        item = self._category_list.itemAt(pos)
        if not item:
            return
        cat_id = item.data(Qt.ItemDataRole.UserRole)
        if cat_id is None:
            return

        menu = QMenu(self)
        edit_act = menu.addAction('编辑分类')
        if edit_act is None:
            return
        edit_act.setIcon(icon(EDIT))
        delete_act = menu.addAction('删除分类')
        if delete_act is None:
            return
        delete_act.setIcon(icon(DELETE))
        action = menu.exec(self._category_list.mapToGlobal(pos))

        if action == edit_act:
            self._edit_category(cat_id)
        elif action == delete_act:
            self._delete_category(cat_id)

    # ========== 条目 CRUD ==========

    def _add_entry(self) -> None:
        categories = self._cached_categories or self._entry_mgr.categories.get_categories()
        tag_names = self._cached_tag_names
        dialog = EntryDialog(self._entry_mgr, categories, tag_names, parent=self, config=self._config)
        dialog.saved.connect(self._refresh_after_entry_change)
        dialog.exec()

    @_require_unlocked
    def _edit_entry(self, entry_id: int) -> None:
        # 延迟回调（仪表盘 singleShot fix_requested）可能在锁定后触发，
        # @_require_unlocked 守卫避免锁定态访问已清零密钥导致崩溃
        entry = self._entry_mgr.get_entry(entry_id)
        if not entry:
            return
        if entry.integrity_error:
            QMessageBox.critical(
                self,
                '数据完整性异常',
                f'该条目的以下字段无法解密：{entry.integrity_message}。\n\n'
                '为避免覆盖原始密文，当前禁止编辑。请先创建备份并检查数据文件。',
            )
            return
        categories = self._cached_categories or self._entry_mgr.categories.get_categories()
        tag_names = self._cached_tag_names
        dialog = EntryDialog(self._entry_mgr, categories, tag_names, entry=entry, parent=self, config=self._config)
        dialog.saved.connect(self._refresh_after_entry_change)
        dialog.exec()

    def _edit_selected_entry(self) -> None:
        """快捷键：编辑当前选中条目。"""
        idx = self._entry_list.currentIndex()
        if idx.isValid():
            entry = idx.data(Qt.ItemDataRole.UserRole)
            if entry:
                self._edit_entry(entry.id)

    @_require_unlocked
    def _delete_entry(self, entry_id: int) -> None:
        entry = self._entry_mgr.get_entry(entry_id)
        if not entry:
            return
        reply = QMessageBox.question(
            self, '确认删除',
            f'确定要删除「{entry.title}」吗？\n条目将移入回收站。',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self._entry_mgr.delete_entry(entry_id)
            self._detail_panel.show_empty()
            entry_title = entry.title

            def undo() -> None:
                # 撤销 Toast 存活期间可能已锁定，守卫避免锁定态崩溃
                if self._locked_ui:
                    return
                # 校验条目仍在回收站：撤销 Toast 存活期间条目可能已被永久删除
                current = self._entry_mgr.get_entry(entry_id)
                if current is None or not current.is_deleted:
                    Toast.show(self, '该条目已被永久删除，无法撤销', Toast.ERROR)
                    return
                self._entry_mgr.restore_entry(entry_id)
                self._refresh_after_entry_change()
                Toast.show(self, f'已恢复「{entry_title}」', Toast.SUCCESS)

            self._refresh_after_entry_change()
            Toast.show(self, f'已移入回收站', Toast.INFO, duration=MS_TOAST_LONG,
                       action_text='撤销', action_callback=undo)

    def _delete_selected_entry(self) -> None:
        """快捷键：删除当前选中条目。"""
        idx = self._entry_list.currentIndex()
        if idx.isValid():
            entry = idx.data(Qt.ItemDataRole.UserRole)
            if entry and not entry.is_deleted:
                self._delete_entry(entry.id)

    def _toggle_favorite(self, entry_id: int) -> None:
        self._entry_mgr.toggle_favorite(entry_id)
        self._refresh_entries_only()

    def _on_copy_feedback(self) -> None:
        self._status_bar.showMessage('已复制到剪贴板', MS_TOAST_DEFAULT)

    # ========== 分类管理 ==========

    def _add_category(self) -> None:
        dialog = CategoryDialog(self._entry_mgr, parent=self)
        dialog.saved.connect(self._refresh_categories)
        dialog.exec()

    def _edit_category(self, category_id: int) -> None:
        category = self._entry_mgr.categories.get_category(category_id)
        if not category:
            return
        dialog = CategoryDialog(self._entry_mgr, category=category, parent=self)
        dialog.saved.connect(self._refresh_categories)
        dialog.exec()

    def _delete_category(self, category_id: int) -> None:
        msg, _has_entries, cat_name = self._sidebar_ctrl.build_delete_message(category_id)
        if not msg:
            return
        reply = QMessageBox.question(
            self, '删除分类', msg,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self._sidebar_ctrl.delete_category(category_id)
            self._refresh_after_entry_change()
            Toast.show(self, f'已删除分类「{cat_name}」', Toast.SUCCESS)

    # ========== 密码生成器回调 ==========

    def _on_password_selected(self, password: str) -> None:
        """密码生成器独立打开时，选中密码后复制到剪贴板。"""
        self._clipboard.copy_text(password)
        Toast.show(self, '密码已复制到剪贴板', Toast.SUCCESS)
