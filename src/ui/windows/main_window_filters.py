"""MainWindow 筛选、排序、数据刷新与条目操作 Mixin

从 main_window.py 提取的排序配置、过滤器数据获取、列表刷新、
条目 CRUD、分类管理、右键菜单及搜索事件处理方法。

继承 QMainWindow 以支持 Pyright 静态分析，运行时由 MainWindow 通过
多重继承统一初始化，Mixin 自身不定义 ``__init__``。
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from PyQt6.QtCore import QModelIndex, Qt
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import QListWidgetItem, QMainWindow, QMenu, QMessageBox

from ..components.empty_state_widget import EmptyStateWidget
from ..components.toast import Toast
from ..components.workers import BackgroundWorker
from ..dialogs.category_dialog import CategoryDialog
from ..dialogs.entry_dialog import EntryDialog
from ..resources.constants import (
    ASYNC_SEARCH_THRESHOLD,
    MS_TOAST_DEFAULT,
    MS_TOAST_LONG,
    MS_TOAST_SHORT,
)
from ..resources.icons import (
    CLOSE,
    COPY,
    DELETE,
    EDIT,
    EMPTY_FOLDER,
    EMPTY_GENERIC,
    EMPTY_SEARCH,
    EMPTY_SUCCESS,
    EMPTY_TRASH,
    EMPTY_VAULT,
    FOLDER,
    REFRESH,
    STAR,
    STAR_OUTLINE,
    icon,
)

if TYPE_CHECKING:
    from PyQt6.QtCore import QTimer
    from PyQt6.QtWidgets import (
        QComboBox,
        QLabel,
        QLineEdit,
        QListView,
        QListWidget,
        QStackedWidget,
        QStatusBar,
    )

    from ...business.managers.entry_manager import EntryManager
    from ...business.services.security_analyzer import SecurityAnalyzer
    from ...config import ConfigManager
    from ...utils.clipboard import ClipboardManager
    from ..components.detail_panel import DetailPanel
    from ..components.entry_list_widget import EntryListModel
    from ..controllers.entry_list_controller import EntryListController as _EntryListController
    from ..controllers.sidebar_controller import SidebarController as _SidebarController

logger = logging.getLogger(__name__)

# 搜索结果渲染上限：超大库下避免一次性渲染过多条目卡死 UI
_MAX_SEARCH_RESULTS_DISPLAY = 1000


class _MainWindowFiltersMixin(QMainWindow):
    """排序、筛选、数据刷新、条目 CRUD 及相关事件处理方法。

    仅与 MainWindow 组合使用，以下属性由宿主 MainWindow 提供，
    此处声明类型注解供静态分析使用。由于使用 ``from __future__ import annotations``，
    运行时注解不求值，不存在循环导入风险。
    """

    # 宿主 MainWindow 提供的实例属性类型注解
    _config: ConfigManager
    _entry_mgr: EntryManager
    _security: SecurityAnalyzer
    _clipboard: ClipboardManager
    _detail_panel: DetailPanel
    _entry_list_ctrl: _EntryListController
    _sidebar_ctrl: _SidebarController
    _status_bar: QStatusBar
    _warning_label: QLabel
    _stats_label: QLabel
    _status_timer: QTimer
    _entry_change_timer: QTimer
    _search_timer: QTimer
    _select_timer: QTimer
    _search_edit: QLineEdit
    _entry_list: QListView
    _entry_model: EntryListModel
    _category_list: QListWidget
    _tag_combo: QComboBox
    _sort_combo: QComboBox
    _filter_list: QListWidget
    _list_stack: QStackedWidget
    _list_title: QLabel
    _count_label: QLabel
    _current_filter: str
    _current_category_id: int | None
    _current_search: str
    _current_tag: str
    _pending_selection: int | None
    _cached_categories: list
    _cached_tag_names: list[str]
    _cached_total_entries: int
    _status_worker: BackgroundWorker | None
    _entry_worker: BackgroundWorker | None
    _entry_workers: set[BackgroundWorker]
    _entry_refresh_generation: int
    _locked_ui: bool
    _last_refresh_filter: str | None

    # ========== 排序 ==========

    def _get_sort_config(self) -> tuple[str, str]:
        """获取当前排序字段和方向。"""
        return self._entry_list_ctrl.get_sort_config(self._sort_combo.currentIndex())

    def _on_sort_changed(self):
        """排序选项变更。仅更新内存配置，持久化由 closeEvent 统一完成，
        避免快速翻动排序选项时每次触发 fsync 阻塞主线程。"""
        field, order = self._get_sort_config()
        self._config.set('sort_field', field)
        self._config.set('sort_order', order)
        self._refresh_entries()

    def _sort_entries(self, entries: list) -> list:
        """对条目列表排序。"""
        return self._entry_list_ctrl.sort_entries(entries, self._sort_combo.currentIndex())

    # ========== 数据操作 ==========

    def _refresh_categories(self):
        selected_category_id = self._current_category_id
        self._category_list.blockSignals(True)
        self._category_list.clear()

        all_item = QListWidgetItem('全部分类')
        all_item.setData(Qt.ItemDataRole.UserRole, None)
        all_item.setIcon(icon(FOLDER))
        self._category_list.addItem(all_item)

        categories = self._sidebar_ctrl.get_categories()
        category_counts = self._sidebar_ctrl.get_category_entry_counts()
        for cat in categories:
            if cat.id is None:
                continue
            label = self._sidebar_ctrl.build_category_label(cat, category_counts.get(cat.id, 0))
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, cat.id)
            self._category_list.addItem(item)

        target_row = 0
        if selected_category_id is not None:
            for row in range(self._category_list.count()):
                selected_item = self._category_list.item(row)
                if selected_item and selected_item.data(Qt.ItemDataRole.UserRole) == selected_category_id:
                    target_row = row
                    break
            else:
                self._current_category_id = None
        self._category_list.setCurrentRow(target_row)
        self._category_list.blockSignals(False)
        self._cached_categories = categories

    def _refresh_tag_filter(self):
        from ..resources.constants import MAX_TAG_AUTOCOMPLETE

        current = self._current_tag
        self._tag_combo.blockSignals(True)
        self._tag_combo.clear()
        self._tag_combo.addItem('全部标签', '')
        all_tags = self._sidebar_ctrl.get_all_tags()
        for tag, count in all_tags:
            self._tag_combo.addItem(f'{tag}  ·  {count}', tag)
        index = self._tag_combo.findData(current)
        self._tag_combo.setCurrentIndex(index if index >= 0 else 0)
        if index < 0:
            self._current_tag = ''
        self._tag_combo.blockSignals(False)
        self._cached_tag_names = [t[0] for t in all_tags[:MAX_TAG_AUTOCOMPLETE]]

    # ======== 过滤器数据获取：委托给 EntryListController ========

    def _fetch_for_filter(
        self,
        filter_key: str,
        *,
        category_id: int | None = None,
        search: str | None = None,
        cancel_check=None,
        use_current_state: bool = True,
    ) -> tuple[list, str]:
        """按过滤器键获取数据，参数绑定基于当前 UI 状态。

        过滤器→方法的映射复用 EntryListController.get_fetcher，避免在控制器
        与本 Mixin 两处维护相同的键集合。各 fetcher 所需的当前分类、搜索等
        参数在此按 filter_key 统一绑定。
        """
        effective_search = self._current_search if use_current_state else (search or '')
        effective_category = self._current_category_id if use_current_state else category_id
        fetcher = self._entry_list_ctrl.get_fetcher(filter_key)
        if filter_key == 'all':
            return fetcher(effective_category, effective_search, cancel_check)
        if filter_key in ('favorite', 'recent', 'trash'):
            return fetcher(effective_search, cancel_check)
        return fetcher()  # weak、duplicate 无参数

    def _current_category_name(self) -> str:
        """返回当前选中分类的名称，无选中分类时返回空字符串。"""
        if self._current_category_id is None:
            return ''
        for category in self._cached_categories:
            if category.id == self._current_category_id:
                return category.name
        return ''

    def _refresh_entries(self):
        # 重建列表前取消待执行的选中防抖，避免对已失效的 pending_selection
        # 操作，与 prepare_for_lock 一致
        self._select_timer.stop()
        self._pending_selection = None
        # 记录滚动位置和当前选中行，重建后恢复，提升列表刷新体验。
        # 仅在当前过滤器未变时恢复同一数据集的刷新；切换过滤器后数据集不同，不应恢复旧位置
        saved_filter = self._last_refresh_filter
        current_filter = self._current_filter
        should_restore_position = (saved_filter == current_filter)
        self._last_refresh_filter = current_filter
        scrollbar = self._entry_list.verticalScrollBar()
        saved_scroll = (
            scrollbar.value() if should_restore_position and scrollbar is not None else 0
        )
        saved_row = self._entry_list.currentIndex().row() if should_restore_position else -1

        # 异步刷新条件：条目数超阈值时移入后台线程，避免主线程全量解密卡顿。
        # all/favorite/trash 无论是否搜索都需全量解密，大库下须异步；recent 仅在
        # 有搜索时全量解密（无搜索走 SQL LIMIT，本身很快）；weak/duplicate 来自
        # 缓存安全摘要，无需异步。原先要求「有搜索」才异步，导致无搜索时大库
        # 切换分类/收藏在主线程同步解密卡顿。
        filter_key = self._current_filter
        needs_async = (
            filter_key in ('all', 'favorite', 'trash')
            or (filter_key == 'recent' and self._current_search)
        )
        if (
            needs_async
            and self._entry_mgr.get_entry_count(include_deleted=True)
            >= ASYNC_SEARCH_THRESHOLD
        ):
            self._start_async_entry_refresh(
                current_filter,
                self._current_category_id,
                self._current_search,
                should_restore_position,
                saved_scroll,
                saved_row,
            )
            return

        if self._entry_worker is not None:
            self._entry_worker.cancel()
            self._entry_worker = None
        entries, title = self._fetch_for_filter(self._current_filter)
        self._apply_entry_results(
            entries, title, should_restore_position, saved_scroll, saved_row,
        )

    def _start_async_entry_refresh(
        self,
        filter_key: str,
        category_id: int | None,
        search: str,
        should_restore_position: bool,
        saved_scroll: int,
        saved_row: int,
    ) -> None:
        if self._entry_worker is not None:
            self._entry_worker.cancel()
        self._entry_refresh_generation += 1
        generation = self._entry_refresh_generation
        holder: list[BackgroundWorker] = []

        def _fetch():
            worker = holder[0]
            return self._fetch_for_filter(
                filter_key,
                category_id=category_id,
                search=search,
                cancel_check=lambda: worker.is_cancelled,
                use_current_state=False,
            )

        worker = BackgroundWorker(_fetch, parent=self)
        holder.append(worker)
        self._entry_worker = worker
        self._entry_workers.add(worker)
        self._count_label.setText('加载中...')

        def _release() -> None:
            self._entry_workers.discard(worker)
            if self._entry_worker is worker:
                self._entry_worker = None

        def _done(result) -> None:
            if (
                self._locked_ui
                or generation != self._entry_refresh_generation
                or self._current_filter != filter_key
                or self._current_category_id != category_id
                or self._current_search != search
            ):
                _release()
                return
            entries, title = result
            _release()
            self._apply_entry_results(
                entries, title, should_restore_position, saved_scroll, saved_row,
            )

        worker.finished.connect(_done)
        worker.error.connect(lambda _message: _release())
        worker.cancelled.connect(_release)
        worker.start()

    def _apply_entry_results(
        self,
        entries: list,
        title: str,
        should_restore_position: bool,
        saved_scroll: int,
        saved_row: int,
    ) -> None:
        # 分类筛选下显示分类名作为标题，而非 fetcher 默认的「全部条目」
        if self._current_category_id is not None:
            title = self._current_category_name() or title
        self._list_title.setText(title)

        if self._current_search and self._current_filter in ('weak', 'duplicate'):
            entries = self._entry_list_ctrl.filter_by_search(entries, self._current_search)

        if self._current_tag:
            entries = self._entry_list_ctrl.filter_by_tag(entries, self._current_tag)

        # 排序：弱密码/重复/近期使用默认顺序
        if self._current_filter in ('all', 'favorite', 'trash'):
            entries = self._sort_entries(entries)

        # 搜索结果防御性上限：超大库下避免渲染过多条目卡死 UI
        original_count = len(entries)
        truncated = (
            bool(self._current_search)
            and original_count > _MAX_SEARCH_RESULTS_DISPLAY
        )
        if truncated:
            entries = entries[:_MAX_SEARCH_RESULTS_DISPLAY]

        # Model/View：一次替换全部数据，QListView 按需经 delegate 绘制，
        # 不再为每条创建常驻 QListWidgetItem，降低大库刷新开销与内存占用。
        self._entry_model.set_entries(entries)

        # 恢复滚动位置和选中行，仅在过滤器未变时恢复，避免切换后跳到旧位置
        if should_restore_position and not self._current_search and 0 <= saved_row < self._entry_model.rowCount():
            self._entry_list.setCurrentIndex(self._entry_model.index(saved_row))
        if should_restore_position:
            scrollbar = self._entry_list.verticalScrollBar()
            if scrollbar is not None:
                scrollbar.setValue(saved_scroll)

        if truncated:
            self._count_label.setText(f'前 {len(entries)} 项（共 {original_count} 项）')
        else:
            self._count_label.setText(f'{len(entries)} 项')

        if entries:
            self._list_stack.setCurrentWidget(self._entry_list)
        else:
            self._show_empty_state()

    def _show_empty_state(self):
        """根据当前场景显示不同的空状态提示。"""
        # 清除旧的空状态 widget，即索引 1 及之后的所有 widget
        while self._list_stack.count() > 1:
            old = self._list_stack.widget(1)
            if old is None:
                break
            self._list_stack.removeWidget(old)
            old.deleteLater()

        icon, title, subtitle, action_text, slot = self._resolve_empty_state()
        empty = EmptyStateWidget(
            icon_name=icon, title=title, subtitle=subtitle, action_text=action_text,
        )
        if slot is not None:
            empty.action_clicked.connect(slot)
        self._list_stack.addWidget(empty)
        self._list_stack.setCurrentWidget(empty)

    def _resolve_empty_state(self):
        """按优先级解析当前空状态配置。

        返回由图标、标题、副标题、操作按钮文案、操作回调槽位组成的五元组。
        将 7 种空态场景的文案与图标配置集中于此；EmptyStateWidget 的构造与信号
        连接统一在 _show_empty_state 一处完成，新增或修改空态文案只需调整本表。
        """
        if self._current_search:
            return (EMPTY_SEARCH, '没有找到匹配的条目', '尝试不同的搜索关键词', '清除搜索', self._clear_search)
        if self._current_filter == 'trash':
            return (EMPTY_TRASH, '回收站是空的', '删除的条目会出现在这里', '', None)
        if self._current_filter == 'weak':
            # 缓存未就绪时显示"分析中"，避免空列表被误读为"无弱密码"
            if self._security.get_cached_report(
                self._config.get('old_password_warning_days')
            ) is None:
                return (EMPTY_GENERIC, '正在分析密码强度...', '请稍候', '', None)
            return (EMPTY_SUCCESS, '没有发现弱密码', '所有密码强度良好', '', None)
        if self._current_filter == 'duplicate':
            if self._security.get_cached_report(
                self._config.get('old_password_warning_days')
            ) is None:
                return (EMPTY_GENERIC, '正在分析重复密码...', '请稍候', '', None)
            return (EMPTY_SUCCESS, '没有重复密码', '所有密码都是唯一的', '', None)
        if self._current_filter == 'recent':
            return (EMPTY_SUCCESS, '没有近期更新', '最近没有修改过条目', '', None)
        if self._current_category_id is not None:
            return (EMPTY_FOLDER, '该分类下暂无条目', '新增或编辑条目时可选择该分类', '', None)
        # 仅此分支需要总数，惰性查询避免其他空态场景的无谓 DB 访问
        total_entries = getattr(self, '_cached_total_entries', -1)
        if total_entries < 0:
            total_entries = self._entry_mgr.get_entry_count()
            self._cached_total_entries = total_entries
        if total_entries == 0:
            return (EMPTY_VAULT, '还没有密码条目', '点击工具栏「新增」按钮开始添加', '新增条目', self._add_entry)
        return (EMPTY_GENERIC, '暂无条目', '', '', None)

    def _update_status_bar(self):
        days = self._config.get('old_password_warning_days')
        # 快速路径：缓存命中时直接更新 UI
        cached = self._security.get_cached_report(days)
        if cached is not None:
            self._apply_status_summary(cached)
            return
        # 缓存未命中：显示占位文本，异步执行分析
        self._status_bar.showMessage('安全分析中...')
        if self._status_worker and self._status_worker.isRunning():
            return
        worker = BackgroundWorker(
            lambda: self._security.get_or_compute_report(days),
            parent=self,
        )
        self._status_worker = worker

        def _on_finished(summary):
            # 锁定后或非当前 worker 的延迟回调均不应用，避免访问已清零状态
            if self._locked_ui or self._status_worker is not worker:
                return
            self._apply_status_summary(summary)
            # worker 已结束，释放引用，与 _on_error 一致，避免 _status_worker
            # 长期指向已结束 worker 而破坏生命周期不变量。
            if self._status_worker is worker:
                self._status_worker = None

        worker.finished.connect(_on_finished)
        # worker 线程抛异常时更新状态栏，避免永远卡在"安全分析中..."无反馈
        def _on_error(_msg):
            if self._locked_ui or self._status_worker is not worker:
                return
            self._status_bar.showMessage('安全分析暂时不可用')
            if self._status_worker is worker:
                self._status_worker = None
        worker.error.connect(_on_error)
        worker.start()

    def _apply_status_summary(self, summary: dict):
        try:
            total = summary['total']
            self._stats_label.setText(f'共 {total} 项')
            parts = [f'总计 {total} 条']
            if summary['weak_count'] > 0:
                parts.append(f'弱密码 {summary["weak_count"]}')
            if summary['duplicate_count'] > 0:
                parts.append(f'重复 {summary["duplicate_count"]}')
            self._status_bar.showMessage('  |  '.join(parts))
            # 密码过期警告：复用实例属性，避免 findChild
            if summary.get('old', 0) > 0:
                old_count = summary['old']
                self._warning_label.setText(f'  {old_count} 个密码已过期  ')
                self._warning_label.show()
                if self._warning_label.parent() is not self._status_bar:
                    self._status_bar.addPermanentWidget(self._warning_label)
            else:
                self._warning_label.hide()
        except (ValueError, RuntimeError):
            logger.debug("状态栏安全分析失败", exc_info=True)
            self._status_bar.showMessage('安全分析暂时不可用')

    # ========== 事件处理 ==========

    def _invalidate_security_cache(self):
        self._security.invalidate_cache()

    def _refresh_all_data(self):
        """全量刷新：分类 + 标签 + 条目 + 安全摘要。

        用于数据发生重大变更的场景，如导入、备份恢复、修改主密码。
        """
        self._invalidate_security_cache()
        # 失效空态总数缓存与滚动位置恢复标记：数据整体替换后应重算
        self._cached_total_entries = -1
        self._last_refresh_filter = None
        self._refresh_categories()
        self._refresh_tag_filter()
        self._refresh_entries()
        self._status_timer.start()

    def _refresh_after_entry_change(self):
        """条目变更后请求刷新，通过防抖合并多次快速操作。"""
        self._entry_change_timer.start()

    def _do_refresh_after_entry_change(self):
        """执行条目变更后的全量刷新，由防抖定时器触发。

        分类和标签看似总与上次相同，但编辑/删除操作可能改变分类下的条目计数、
        移除某条目使用的最后一个标签等。防抖定时器以 100ms 间隔已合并快速连续操作，
        三次轻量查询即分类、计数和标签的开销可接受。
        对于确定不改变分类/标签的操作如切换收藏，使用 _refresh_entries_only。
        """
        # 安全缓存失效已通过 EntryManager 回调自动完成，此处无需再调用
        self._cached_total_entries = -1
        # 失效滚动位置恢复标记：条目增删后列表已变，不应恢复旧滚动位置
        self._last_refresh_filter = None
        self._refresh_categories()
        self._refresh_tag_filter()
        self._refresh_entries()
        self._status_timer.start()

    def _refresh_entries_only(self):
        """仅刷新条目列表和状态栏，不刷新分类/标签/安全摘要。

        用于轻量操作如切换收藏，此时分类和标签不会改变。
        """
        self._refresh_entries()
        self._status_timer.start()

    def _on_search_input(self, _text: str):
        self._search_timer.start()

    def _on_tag_changed(self):
        if self._locked_ui:
            return
        self._current_tag = self._tag_combo.currentData() or ''
        self._refresh_entries()

    def _do_search(self):
        if self._locked_ui:
            return
        self._current_search = self._search_edit.text().strip()
        self._refresh_entries()

    def _on_filter_changed(self, current, _previous):
        if self._locked_ui:
            return
        if current:
            self._current_filter = current.data(Qt.ItemDataRole.UserRole)
            self._current_category_id = None
            # 切换过滤器使总数缓存失效，避免空库文案误判（EMPTY_VAULT/EMPTY_GENERIC）
            self._cached_total_entries = -1
            self._category_list.blockSignals(True)
            self._category_list.setCurrentRow(-1)
            self._category_list.blockSignals(False)
            self._refresh_entries()

    def _on_category_changed(self, current, _previous):
        if self._locked_ui:
            return
        if current:
            self._current_category_id = current.data(Qt.ItemDataRole.UserRole)
            self._current_filter = 'all'
            self._cached_total_entries = -1
            self._filter_list.blockSignals(True)
            self._filter_list.setCurrentRow(0)
            self._filter_list.blockSignals(False)
            # 列表标题由 _refresh_entries 根据 _current_category_id 统一设置，
            # 避免此处设置的分类名随后被 fetcher 返回的标题覆盖
            self._refresh_entries()

    def _on_entry_selected(self, current, _previous):
        if current.isValid():
            self._pending_selection = current.row()
            self._select_timer.start()

    def _do_select_entry(self):
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

    def _on_entry_context_menu(self, pos):
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

    def _show_deleted_entry_menu(self, entry, pos):
        """回收站条目右键菜单。"""
        menu = QMenu(self)
        restore_act = QAction('恢复', self)
        restore_act.setIcon(icon(REFRESH))
        menu.addAction(restore_act)
        delete_act = QAction('永久删除', self)
        delete_act.setIcon(icon(CLOSE, 'danger'))
        menu.addAction(delete_act)

        chosen = menu.exec(self._entry_list.mapToGlobal(pos))

        if chosen == restore_act:
            self._entry_mgr.restore_entry(entry.id)
            self._refresh_after_entry_change()
            Toast.show(self, f'已恢复「{entry.title}」', Toast.SUCCESS)
        elif chosen == delete_act:
            reply = QMessageBox.warning(
                self, '永久删除',
                f'确定要永久删除「{entry.title}」吗？\n此操作不可撤销！',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.Yes:
                self._entry_mgr.permanent_delete_entry(entry.id)
                self._refresh_after_entry_change()

    def _show_active_entry_menu(self, summary, pos):
        """活跃条目右键菜单 — dict dispatch，复制操作延迟解密。"""
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
            menu.addAction(fav_act)
        else:
            fav_act = QAction('收藏', self)
            fav_act.setIcon(icon(STAR))
            menu.addAction(fav_act)
        menu.addSeparator()
        del_act = QAction('删除', self)
        del_act.setIcon(icon(DELETE))
        menu.addAction(del_act)

        chosen = menu.exec(self._entry_list.mapToGlobal(pos))
        if chosen is None:
            return

        # 延迟解密：复制操作按需加载完整条目。菜单打开期间可能触发自动锁定，
        # 闭包内守卫避免锁定态访问已清零密钥
        def _copy_user():
            if self._locked_ui:
                return
            e = self._entry_mgr.get_entry(summary.id)
            if e and e.username:
                self._clipboard.copy_text(e.username)
                Toast.show(self, '已复制账号', Toast.SUCCESS, duration=MS_TOAST_SHORT)

        def _copy_pwd():
            if self._locked_ui:
                return
            e = self._entry_mgr.get_entry(summary.id)
            if e and e.password:
                self._clipboard.copy_text(e.password)
                # 仅当右键的是当前详情面板显示的条目时，才触发其复制按钮反馈
                current = self._detail_panel.current_entry
                if current is not None and current.id == summary.id:
                    self._detail_panel.copy_feedback.emit()
                Toast.show(self, '已复制密码', Toast.SUCCESS, duration=MS_TOAST_SHORT)

        def _copy_totp():
            if self._locked_ui:
                return
            # 通过 EntryManager 生成验证码，UI 层不接触明文 TOTP secret
            code = self._entry_mgr.generate_totp(summary.id)
            if code:
                self._clipboard.copy_text(code)
                Toast.show(self, '验证码已复制', Toast.SUCCESS, duration=MS_TOAST_SHORT)
            else:
                Toast.show(self, '验证码生成失败，请检查密钥', Toast.ERROR, duration=MS_TOAST_DEFAULT)

        # dict dispatch 替代 if/elif 链
        def _toggle_favorite() -> None:
            self._entry_mgr.toggle_favorite(summary.id)
            self._refresh_entries_only()

        handlers: dict = {
            copy_user_act: _copy_user,
            copy_pwd_act: _copy_pwd,
            edit_act: lambda: self._edit_entry(summary.id),
            fav_act: _toggle_favorite,
            del_act: lambda: self._delete_entry(summary.id),
        }
        if copy_totp_act:
            handlers[copy_totp_act] = _copy_totp

        handler = handlers.get(chosen)
        if handler:
            handler()

    def _on_category_context_menu(self, pos):
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

    # ========== 操作方法 ==========

    def _add_entry(self):
        categories = self._cached_categories or self._entry_mgr.get_categories()
        tag_names = self._cached_tag_names
        dialog = EntryDialog(self._entry_mgr, categories, tag_names, parent=self, config=self._config)
        dialog.saved.connect(self._refresh_after_entry_change)
        dialog.exec()

    def _edit_entry(self, entry_id: int):
        # 延迟回调（仪表盘 singleShot fix_requested）可能在锁定后触发，
        # 守卫避免锁定态访问已清零密钥导致崩溃
        if self._locked_ui:
            return
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
        categories = self._cached_categories or self._entry_mgr.get_categories()
        tag_names = self._cached_tag_names
        dialog = EntryDialog(self._entry_mgr, categories, tag_names, entry=entry, parent=self, config=self._config)
        dialog.saved.connect(self._refresh_after_entry_change)
        dialog.exec()

    def _edit_selected_entry(self):
        """快捷键：编辑当前选中条目。"""
        idx = self._entry_list.currentIndex()
        if idx.isValid():
            entry = idx.data(Qt.ItemDataRole.UserRole)
            if entry:
                self._edit_entry(entry.id)

    def _delete_entry(self, entry_id: int):
        if self._locked_ui:
            return
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

            def undo():
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

    def _delete_selected_entry(self):
        """快捷键：删除当前选中条目。"""
        idx = self._entry_list.currentIndex()
        if idx.isValid():
            entry = idx.data(Qt.ItemDataRole.UserRole)
            if entry and not entry.is_deleted:
                self._delete_entry(entry.id)

    def _toggle_favorite(self, entry_id: int):
        self._entry_mgr.toggle_favorite(entry_id)
        self._refresh_entries_only()

    def _on_copy_feedback(self):
        self._status_bar.showMessage('已复制到剪贴板', MS_TOAST_DEFAULT)

    def _clear_search(self):
        """快捷键：清空搜索。"""
        if self._search_edit.text():
            self._search_edit.clear()
        else:
            self._entry_list.setCurrentIndex(QModelIndex())
            self._detail_panel.show_empty()

    # ========== 分类管理 ==========

    def _add_category(self):
        dialog = CategoryDialog(self._entry_mgr, parent=self)
        dialog.saved.connect(self._refresh_categories)
        dialog.exec()

    def _edit_category(self, category_id: int):
        category = self._entry_mgr.get_category(category_id)
        if not category:
            return
        dialog = CategoryDialog(self._entry_mgr, category=category, parent=self)
        dialog.saved.connect(self._refresh_categories)
        dialog.exec()

    def _delete_category(self, category_id: int):
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

    def _on_password_selected(self, password: str):
        """密码生成器独立打开时，选中密码后复制到剪贴板。"""
        self._clipboard.copy_text(password)
        Toast.show(self, '密码已复制到剪贴板', Toast.SUCCESS)
