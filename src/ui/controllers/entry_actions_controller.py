"""MainWindow 条目 CRUD、分类管理与右键菜单控制器。

普通类（非 QObject）：``__init__`` 注入 manager 与跨 controller 回调
（``EntryActionsDeps``），``setup(parent, view)`` 接收 QObject 父与冻结
dataclass view-handle（``EntryActionsView``），创建选择防抖定时器并连接控件信号。
跨 controller 协作一律走 ``EntryActionsDeps`` 回调，pyright 在装配点逐字段校验每个
回调的绑定方法名。锁定态守卫经 ``set_locked()`` / ``prepare_for_lock()`` 广播，
由 ``_locked_guard`` 统一承载。
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from PyQt6.QtCore import QModelIndex, QPoint, Qt, QTimer
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import QMainWindow, QMenu, QMessageBox

from ..components.toast import Toast
from ..dialogs.category_dialog import CategoryDialog
from ..dialogs.entry_dialog import EntryDialog
from ..dialogs.share_package_dialog import open_share_package_dialog
from ..error_messages import to_user_message
from ..resources.constants import (
    MS_ENTRY_SELECT_DEBOUNCE,
    MS_TOAST_DEFAULT,
    MS_TOAST_LONG,
    MS_TOAST_SHORT,
)
from ..resources.icons import CLOSE, COPY, DELETE, EDIT, REFRESH, SHARE, STAR, STAR_OUTLINE, icon
from ._locked_guard import require_unlocked

if TYPE_CHECKING:
    from PyQt6.QtWidgets import QListView, QListWidget, QPushButton, QStatusBar

    from ...business.managers.entry_manager import EntryManager
    from ...config import ConfigManager
    from ...models import Category, Entry
    from ..components.detail_panel import DetailPanel
    from ..controllers.sidebar_controller import SidebarController
    from ..utils.clipboard import ClipboardManager

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EntryActionsView:
    """EntryActionsController 操作的列表控件引用（由 MainWindow 装配）。

    控件仍是 MainWindow 的 host 属性（``test_product_hardening`` 等直接访问
    ``window._entry_list`` / ``window._category_list``），controller 经此冻结 dataclass
    取引用，不持有 host 自身以避免环依赖。
    """

    entry_list: QListView
    category_list: QListWidget
    status_bar: QStatusBar
    add_entry_btn: QPushButton
    add_category_btn: QPushButton


@dataclass(frozen=True)
class EntryActionsDeps:
    """跨 controller 回调，由 MainWindow 装配（绑定 ListRefresh/host 方法）。

    refresh_* 三入口对应不同刷新粒度（全量 / 仅条目 / 分类），均绑定 ListRefreshController
    方法；get_dialog_options 绑 host 缓存读取，供新增/编辑对话框预填分类与标签自动补全。
    """

    refresh_after_entry_change: Callable[[], None]
    refresh_entries_only: Callable[[], None]
    refresh_categories: Callable[[], None]
    get_dialog_options: Callable[[], tuple[list[Category], list[str]]]


class EntryActionsController:
    """条目 CRUD、分类管理与右键菜单。

    选择防抖定时器与 pending 选择态由本控制器持有；锁定态经 ``_locked``
    守卫，host 在 prepare_for_lock / refresh_after_unlock 经 ``set_locked`` 广播。
    """

    _parent: QMainWindow
    _view: EntryActionsView

    def __init__(
        self,
        config: ConfigManager,
        entry_mgr: EntryManager,
        clipboard: ClipboardManager,
        detail_panel: DetailPanel,
        sidebar_ctrl: SidebarController,
        deps: EntryActionsDeps,
    ) -> None:
        self._config = config
        self._entry_mgr = entry_mgr
        self._clipboard = clipboard
        self._detail_panel = detail_panel
        self._sidebar_ctrl = sidebar_ctrl
        self._deps = deps
        self._locked = False
        self._select_timer: QTimer | None = None
        self._pending_selection: int | None = None

    def setup(self, parent: QMainWindow, view: EntryActionsView) -> None:
        """创建选择防抖定时器并连接控件信号。须在 MainWindow 控件创建后调用。

        parent 作 QWidget 父（QMenu/QAction/QTimer 的 Qt 父关系，析构自动断开信号）
        与 Toast/对话框的父窗口；view 提供列表控件与新增按钮引用。
        """
        self._parent = parent
        self._view = view

        # 选择防抖定时器：快速导航时不触发逐条解密
        self._select_timer = QTimer(parent)
        self._select_timer.setSingleShot(True)
        self._select_timer.setInterval(MS_ENTRY_SELECT_DEBOUNCE)
        self._select_timer.timeout.connect(self.do_select_entry)

        # 详情面板信号 → 条目编辑/删除/收藏/复制反馈
        self._detail_panel.edit_requested.connect(self.edit_entry)
        self._detail_panel.share_requested.connect(self.share_entry)
        self._detail_panel.delete_requested.connect(self.delete_entry)
        self._detail_panel.favorite_toggled.connect(self.toggle_favorite)
        self._detail_panel.copy_feedback.connect(self.on_copy_feedback)

        # 条目列表信号
        entry_list = view.entry_list
        selection_model = entry_list.selectionModel()
        if selection_model is not None:
            selection_model.currentChanged.connect(self.on_entry_selected)
        entry_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        entry_list.customContextMenuRequested.connect(self.on_entry_context_menu)
        view.add_entry_btn.clicked.connect(self.add_entry)

        # 分类列表信号
        category_list = view.category_list
        category_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        category_list.customContextMenuRequested.connect(self.on_category_context_menu)
        view.add_category_btn.clicked.connect(self.add_category)

    # ======== 锁定态与生命周期 ========

    def set_locked(self, locked: bool) -> None:
        """host 经 refresh_after_unlock(False) 广播解锁态（锁定态由 prepare_for_lock 设）。"""
        self._locked = locked

    def prepare_for_lock(self) -> None:
        """锁定前置：标记锁定态并清选择 pending，防止锁定后防抖回调访问已清零密钥。

        定时器停止由 host ``_stop_ui_timers`` 统一调度（收敛所有 UI 定时器停点），
        此处不重复，避免与 ``_stop_ui_timers`` 双重停止语义混淆。
        """
        self._locked = True
        self._pending_selection = None

    def stop_timers(self) -> None:
        """停止选择防抖定时器（host ``_stop_ui_timers`` 调用）。"""
        if self._select_timer is not None:
            self._select_timer.stop()

    def cancel_pending_selection(self) -> None:
        """清选择 pending（隐藏到托盘等路径调用，不改变锁定态）。"""
        self._pending_selection = None

    # ======== 条目选择 ========

    def on_entry_selected(self, current: QModelIndex, _previous: QModelIndex) -> None:
        if current.isValid():
            self._pending_selection = current.row()
            if self._select_timer is not None:
                self._select_timer.start()

    def do_select_entry(self) -> None:
        """防抖后的条目选择：执行解密并显示。

        校验 pending_selection 仍是列表当前选中项：后台刷新可能在防抖窗口内
        重建列表，使该条目被删除或替换，此时不应再用其 id 解密显示，避免
        详情面板与列表当前选中不一致。
        """
        current_row = self._pending_selection
        # 取值后立即重置，避免 timer 再次触发时复用过期引用
        self._pending_selection = None
        if self._locked:
            return
        if current_row is None:
            return
        # 后台刷新可能已重建列表，确认 pending 行仍是当前选中行；
        # 失败说明选中已改变，清空详情面板避免残留与列表不一致的旧条目
        idx = self._view.entry_list.currentIndex()
        if idx.row() != current_row:
            self._detail_panel.show_empty()
            return
        summary = idx.data(Qt.ItemDataRole.UserRole)
        if summary:
            # 短路（PERF-003）：详情面板已显示同一条目（id + updated_at 未变）时跳过重复
            # get_entry 全量解密（含 password/totp），避免重复选中同一条目的解密开销。
            current = self._detail_panel.current_entry
            if (
                current is not None
                and current.id == summary.id
                and current.updated_at == summary.updated_at
            ):
                return
            entry = self._entry_mgr.get_entry(summary.id)
            if entry:
                self._detail_panel.show_entry(entry)

    # ======== 条目右键菜单 ========

    def on_entry_context_menu(self, pos: QPoint) -> None:
        """条目右键菜单 — 路由到已删除/活跃条目子菜单。"""
        index = self._view.entry_list.indexAt(pos)
        if not index.isValid():
            return

        summary = index.data(Qt.ItemDataRole.UserRole)
        if not summary:
            return
        if summary.is_deleted:
            self._show_deleted_entry_menu(summary, pos)
        else:
            self._show_active_entry_menu(summary, pos)

    @require_unlocked
    def _show_deleted_entry_menu(self, entry: Entry, pos: QPoint) -> None:
        """回收站条目右键菜单。"""
        # 列表条目必来自 DB，id 非 None；守卫后 entry_id 收窄为 int 供下游调用。
        if entry.id is None:
            return
        entry_id = entry.id
        parent = self._parent
        menu = QMenu(parent)
        restore_act = QAction("恢复", parent)
        restore_act.setIcon(icon(REFRESH))
        menu.addAction(restore_act)
        delete_act = QAction("永久删除", parent)
        delete_act.setIcon(icon(CLOSE, "danger"))
        menu.addAction(delete_act)

        chosen = menu.exec(self._view.entry_list.mapToGlobal(pos))

        if chosen == restore_act:
            try:
                self._entry_mgr.restore_entry(entry_id)
                self._deps.refresh_after_entry_change()
            except Exception as exc:
                logger.error("恢复条目失败: %s", exc, exc_info=True)
                Toast.show(parent, to_user_message(exc), Toast.ERROR, duration=MS_TOAST_DEFAULT)
                return
            Toast.show(parent, f"已恢复「{entry.title}」", Toast.SUCCESS)
        elif chosen == delete_act:
            reply = QMessageBox.warning(
                parent,
                "永久删除",
                f"确定要永久删除「{entry.title}」吗？\n此操作不可撤销！",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.Yes:
                try:
                    self._entry_mgr.permanent_delete_entry(entry_id)
                    self._deps.refresh_after_entry_change()
                except Exception as exc:
                    logger.error("永久删除条目失败: %s", exc, exc_info=True)
                    Toast.show(parent, to_user_message(exc), Toast.ERROR, duration=MS_TOAST_DEFAULT)

    def _show_active_entry_menu(self, summary: Entry, pos: QPoint) -> None:
        """活跃条目右键菜单 — dict dispatch，复制操作延迟解密。"""
        # 列表条目必来自 DB，id 非 None；守卫后由 _build_active_entry_menu 收窄为 int。
        if summary.id is None:
            return
        menu, handlers = self._build_active_entry_menu(summary)
        chosen = menu.exec(self._view.entry_list.mapToGlobal(pos))
        if chosen is None:
            return
        handler = handlers.get(chosen)
        if handler is not None:
            handler()

    def _build_active_entry_menu(
        self,
        summary: Entry,
    ) -> tuple[QMenu, dict[QAction, Callable[[], None]]]:
        """构造活跃条目右键菜单及其「动作→处理函数」映射。

        dict dispatch 替代 if/elif 链；复制类处理延迟解密，处理函数内经
        ``@require_unlocked`` 守卫避免锁定态访问已清零密钥。
        """
        entry_id = summary.id
        parent = self._parent
        if entry_id is None:  # 调用方 _show_active_entry_menu 已守卫，此处为类型收窄防御
            return QMenu(parent), {}
        menu = QMenu(parent)

        copy_user_act = QAction("复制账号", parent)
        copy_user_act.setIcon(icon(COPY))
        menu.addAction(copy_user_act)
        copy_pwd_act = QAction("复制密码", parent)
        copy_pwd_act.setIcon(icon(COPY))
        menu.addAction(copy_pwd_act)

        # TOTP 验证码：仅当条目配置了 TOTP 密钥时显示
        copy_totp_act: QAction | None = None
        if summary.has_totp:
            copy_totp_act = QAction("复制验证码", parent)
            copy_totp_act.setIcon(icon(COPY))
            menu.addAction(copy_totp_act)

        menu.addSeparator()
        edit_act = QAction("编辑", parent)
        edit_act.setIcon(icon(EDIT))
        menu.addAction(edit_act)
        if summary.is_favorite:
            fav_act = QAction("取消收藏", parent)
            fav_act.setIcon(icon(STAR_OUTLINE))
        else:
            fav_act = QAction("收藏", parent)
            fav_act.setIcon(icon(STAR))
        menu.addAction(fav_act)
        menu.addSeparator()
        share_act = QAction("创建共享包", parent)
        share_act.setIcon(icon(SHARE))
        menu.addAction(share_act)
        menu.addSeparator()
        del_act = QAction("删除", parent)
        del_act.setIcon(icon(DELETE))
        menu.addAction(del_act)

        handlers: dict[QAction, Callable[[], None]] = {
            copy_user_act: lambda: self._copy_username(entry_id),
            copy_pwd_act: lambda: self._copy_password(entry_id),
            edit_act: lambda: self.edit_entry(entry_id),
            fav_act: lambda: self.toggle_favorite(entry_id),
            share_act: lambda: self.share_entry(entry_id),
            del_act: lambda: self.delete_entry(entry_id),
        }
        if copy_totp_act is not None:
            handlers[copy_totp_act] = lambda: self._copy_totp(entry_id)
        return menu, handlers

    @require_unlocked
    def _copy_username(self, entry_id: int) -> None:
        """延迟解密并复制条目账号；锁定态守卫避免访问已清零密钥。"""
        entry = self._entry_mgr.get_entry(entry_id)
        if entry and entry.username:
            self._clipboard.copy_text(entry.username)
            Toast.show(self._parent, "已复制账号", Toast.SUCCESS, duration=MS_TOAST_SHORT)

    @require_unlocked
    def _copy_password(self, entry_id: int) -> None:
        """延迟解密并复制条目密码；仅当右键的是当前详情条目时触发复制反馈。"""
        # 复用面板已解密明文（PERF-005）：右键复制密码的常是当前详情条目，直接取其已解密
        # password 跳过重复 get_entry 全量解密；非当前条目回退延迟解密。
        current = self._detail_panel.current_entry
        entry = (
            current
            if current is not None and current.id == entry_id
            else self._entry_mgr.get_entry(entry_id)
        )
        if entry and entry.password:
            self._clipboard.copy_text(entry.password)
            if current is not None and current.id == entry_id:
                self._detail_panel.copy_feedback.emit()
            Toast.show(self._parent, "已复制密码", Toast.SUCCESS, duration=MS_TOAST_SHORT)

    @require_unlocked
    def _copy_totp(self, entry_id: int) -> None:
        """生成并复制 TOTP 验证码；UI 层不接触明文 TOTP secret。"""
        code = self._entry_mgr.totp.generate(entry_id)
        if code:
            self._clipboard.copy_text(code)
            Toast.show(self._parent, "验证码已复制", Toast.SUCCESS, duration=MS_TOAST_SHORT)
        else:
            Toast.show(
                self._parent, "验证码生成失败，请检查密钥", Toast.ERROR, duration=MS_TOAST_DEFAULT
            )

    def on_category_context_menu(self, pos: QPoint) -> None:
        """分类右键菜单。"""
        item = self._view.category_list.itemAt(pos)
        if not item:
            return
        cat_id = item.data(Qt.ItemDataRole.UserRole)
        if cat_id is None:
            return

        parent = self._parent
        menu = QMenu(parent)
        edit_act = menu.addAction("编辑分类")
        if edit_act is None:
            return
        edit_act.setIcon(icon(EDIT))
        delete_act = menu.addAction("删除分类")
        if delete_act is None:
            return
        delete_act.setIcon(icon(DELETE))
        action = menu.exec(self._view.category_list.mapToGlobal(pos))

        if action == edit_act:
            self._edit_category(cat_id)
        elif action == delete_act:
            self._delete_category(cat_id)

    # ========== 条目 CRUD ==========

    def _resolve_dialog_options(self) -> tuple[list[Category], list[str]]:
        """获取新增/编辑对话框预填的分类与标签，分类为空时回退全量查询（QL-009）。"""
        categories, tag_names = self._deps.get_dialog_options()
        if not categories:
            categories = self._entry_mgr.categories.get_categories()
        return categories, tag_names

    @require_unlocked
    def add_entry(self) -> None:
        """打开新增条目对话框；保存后触发全量刷新（新增可能引入新分类/标签）。"""
        categories, tag_names = self._resolve_dialog_options()
        parent = self._parent
        dialog = EntryDialog(
            self._entry_mgr, categories, tag_names, parent=parent, config=self._config
        )
        dialog.saved.connect(self._deps.refresh_after_entry_change)
        dialog.exec()
        dialog.deleteLater()

    @require_unlocked
    def edit_entry(self, entry_id: int) -> None:
        """打开编辑对话框；完整性异常条目禁止编辑以防覆盖原始密文。

        仪表盘修复回调（exec 返回后同步调用）可能在锁定后触发，
        ``@require_unlocked`` 守卫避免锁定态访问已清零密钥导致崩溃。
        """
        entry = self._entry_mgr.get_entry(entry_id)
        if not entry:
            return
        if entry.integrity_error:
            QMessageBox.critical(
                self._parent,
                "数据完整性异常",
                f"该条目的以下字段无法解密：{entry.integrity_message}。\n\n"
                "为避免覆盖原始密文，当前禁止编辑。请先创建备份并检查数据文件。",
            )
            return
        categories, tag_names = self._resolve_dialog_options()
        parent = self._parent
        dialog = EntryDialog(
            self._entry_mgr, categories, tag_names, entry=entry, parent=parent, config=self._config
        )
        dialog.saved.connect(self._deps.refresh_after_entry_change)
        dialog.exec()
        dialog.deleteLater()

    def edit_selected_entry(self) -> None:
        idx = self._view.entry_list.currentIndex()
        if idx.isValid():
            entry = idx.data(Qt.ItemDataRole.UserRole)
            if entry:
                self.edit_entry(entry.id)

    @require_unlocked
    def delete_entry(self, entry_id: int) -> None:
        """软删除条目（移入回收站），提供带撤销 Toast 的可恢复路径。

        撤销回调带锁定态守卫，并校验条目仍在回收站——撤销 Toast 存活期间条目
        可能已被永久删除或保险库已锁定。
        """
        entry = self._entry_mgr.get_entry(entry_id)
        if not entry:
            return
        parent = self._parent
        reply = QMessageBox.question(
            parent,
            "确认删除",
            f"确定要删除「{entry.title}」吗？\n条目将移入回收站。",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            try:
                self._entry_mgr.delete_entry(entry_id)
            except Exception as exc:
                logger.error("删除条目失败: %s", exc, exc_info=True)
                Toast.show(parent, to_user_message(exc), Toast.ERROR, duration=MS_TOAST_DEFAULT)
                return
            self._detail_panel.show_empty()
            entry_title = entry.title

            def undo() -> None:
                # 撤销 Toast 存活期间可能已锁定，守卫避免锁定态崩溃
                if self._locked:
                    return
                # 校验条目仍在回收站：撤销 Toast 存活期间条目可能已被永久删除
                current = self._entry_mgr.get_entry(entry_id)
                if current is None or not current.is_deleted:
                    Toast.show(parent, "该条目已被永久删除，无法撤销", Toast.ERROR)
                    return
                self._entry_mgr.restore_entry(entry_id)
                self._deps.refresh_after_entry_change()
                Toast.show(parent, f"已恢复「{entry_title}」", Toast.SUCCESS)

            self._deps.refresh_after_entry_change()
            Toast.show(
                parent,
                "已移入回收站",
                Toast.INFO,
                duration=MS_TOAST_LONG,
                action_text="撤销",
                action_callback=undo,
            )

    def delete_selected_entry(self) -> None:
        idx = self._view.entry_list.currentIndex()
        if idx.isValid():
            entry = idx.data(Qt.ItemDataRole.UserRole)
            if entry and not entry.is_deleted:
                self.delete_entry(entry.id)

    @require_unlocked
    def toggle_favorite(self, entry_id: int) -> None:
        """切换收藏标志；仅需刷新条目列表（分类/标签/安全摘要不变）。"""
        try:
            self._entry_mgr.toggle_favorite(entry_id)
        except Exception as exc:
            logger.error("切换收藏失败: %s", exc, exc_info=True)
            Toast.show(self._parent, to_user_message(exc), Toast.ERROR, duration=MS_TOAST_DEFAULT)
            return
        self._deps.refresh_entries_only()

    @require_unlocked
    def share_entry(self, entry_id: int) -> None:
        """打开共享包创建对话框；完整性异常条目禁止分享以防泄漏损坏数据。"""
        entry = self._entry_mgr.get_entry(entry_id)
        if not entry:
            return
        open_share_package_dialog(entry, self._parent)

    def on_copy_feedback(self) -> None:
        self._view.status_bar.showMessage("已复制到剪贴板", MS_TOAST_DEFAULT)

    # ========== 分类管理 ==========

    @require_unlocked
    def add_category(self) -> None:
        """打开新增分类对话框；保存后仅刷新分类（条目归属不变）。"""
        parent = self._parent
        dialog = CategoryDialog(self._entry_mgr, parent=parent)
        dialog.saved.connect(self._deps.refresh_categories)
        dialog.exec()
        dialog.deleteLater()

    @require_unlocked
    def _edit_category(self, category_id: int) -> None:
        """打开编辑分类对话框；分类不存在时（已被他处删除）静默返回。"""
        category = self._entry_mgr.categories.get_category(category_id)
        if not category:
            return
        parent = self._parent
        dialog = CategoryDialog(self._entry_mgr, category=category, parent=parent)
        dialog.saved.connect(self._deps.refresh_categories)
        dialog.exec()
        dialog.deleteLater()

    @require_unlocked
    def _delete_category(self, category_id: int) -> None:
        """删除分类；其下条目保留但取消归属，故刷新走全量条目路径。"""
        msg, _has_entries, cat_name = self._sidebar_ctrl.build_delete_message(category_id)
        if not msg:
            return
        parent = self._parent
        reply = QMessageBox.question(
            parent,
            "删除分类",
            msg,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            try:
                self._sidebar_ctrl.delete_category(category_id)
                self._deps.refresh_after_entry_change()
            except Exception as exc:
                logger.error("删除分类失败: %s", exc, exc_info=True)
                Toast.show(parent, to_user_message(exc), Toast.ERROR, duration=MS_TOAST_DEFAULT)
                return
            Toast.show(parent, f"已删除分类「{cat_name}」", Toast.SUCCESS)

    # ========== 密码生成器回调 ==========

    def on_password_selected(self, password: str) -> None:
        """密码生成器独立打开时，选中密码后复制到剪贴板。"""
        self._clipboard.copy_text(password)
        Toast.show(self._parent, "密码已复制到剪贴板", Toast.SUCCESS)
