"""CipherBox 主窗口。

编排侧边栏、条目列表与详情面板，集成快捷键、排序、Toast 通知、分类管理、
标签筛选、撤销删除、主题刷新、自动锁定与备份、安全仪表盘等功能。通过
_MainWindowEntriesMixin / _MainWindowFiltersMixin / _MainWindowMenuMixin 多重继承
拆分方法实现职责分离，三组方法经 MainWindow 多重继承共享同一 self（共享工具
``_require_unlocked`` 见 ``main_window_mixin_base``）。
"""

import logging
from typing import cast

from PyQt6.QtCore import (
    QEvent,
    QObject,
    Qt,
    QTimer,
    pyqtSignal,
)
from PyQt6.QtGui import QCloseEvent, QKeyEvent, QShowEvent
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListView,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from ...business.composition import BusinessContext
from ...config import DEFAULT_THEME, MAX_WINDOW_GEOMETRY_BYTES
from ..components.detail_panel import DetailPanel
from ..components.entry_list_widget import EntryItemDelegate, EntryListModel
from ..components.tray_icon import TrayIcon
from ..components.widgets import disconnect_all
from ..components.workers import BackgroundWorker, wait_worker_shutdown
from ..controllers.auto_backup_controller import AutoBackupController
from ..controllers.auto_lock_controller import AutoLockController
from ..controllers.entry_list_controller import EntryListController
from ..controllers.sidebar_controller import SidebarController
from ..resources.constants import (
    CLIPBOARD_CLEAR_SECONDS_DEFAULT,
    FILTER_MAX_HEIGHT,
    MS_ENTRY_CHANGE_DEBOUNCE,
    MS_ENTRY_SELECT_DEBOUNCE,
    MS_SEARCH_DEBOUNCE,
    MS_STATUS_BAR_DEBOUNCE,
    SIDEBAR_WIDTH,
    SORT_OPTIONS,
    SPLITTER_SIZES,
    WINDOW_DEFAULT_SIZE,
    WINDOW_MIN_SIZE,
)
from ..resources.icons import (
    PLUS,
    SEARCH,
    SHIELD,
    icon,
    icon_pixmap,
    set_icon_with_text,
)
from ..resources.styles import get_style
from ..utils.clipboard import ClipboardManager
from .main_window_entries import _MainWindowEntriesMixin
from .main_window_filters import _MainWindowFiltersMixin
from .main_window_menu import _MainWindowMenuMixin

logger = logging.getLogger(__name__)

class MainWindow(_MainWindowEntriesMixin, _MainWindowFiltersMixin, _MainWindowMenuMixin, QMainWindow):
    """CipherBox 主窗口。"""

    lock_requested = pyqtSignal()

    def __init__(self, ctx: BusinessContext) -> None:
        super().__init__()
        self._config = ctx.config
        self._vault = ctx.vault
        self._cache = ctx.cache
        self._change_bus = ctx.change_bus
        self._entry_mgr = ctx.entry_mgr
        self._security = ctx.security
        self._import_export = ctx.import_export
        self._backup = ctx.backup
        self._create_ui_controllers()
        self._current_filter = 'all'
        self._current_category_id = None
        self._current_search = ''
        self._current_tag = ''
        self._tray: TrayIcon | None = None
        self._locked_ui = False
        # 首次解锁标志：MainWindow 构造紧跟 app.py 的 refresh_after_unlock（show 前），
        # 而构造期 __init__/_setup_ui 已刷新 categories/tags/entries，故首次解锁跳过
        # 重复刷新，避免构造期 worker 与本次 worker 双重全量解密（W1+W2）。
        self._first_unlock = True

        self._status_timer = QTimer(self)
        self._status_timer.setSingleShot(True)
        self._status_timer.setInterval(MS_STATUS_BAR_DEBOUNCE)
        self._status_timer.timeout.connect(self._update_status_bar)
        self._status_worker: BackgroundWorker | None = None
        # _entry_worker：当前活跃的条目刷新 worker（最新启动）；_entry_workers：所有
        # 运行中 worker（含历史未结束的）。二者经 _start_async_entry_refresh 的 add 与
        # release 回调同步维护——add 时同时置活跃与加入集合，release 时同时移除。
        # cancel 路径只置空活跃（worker 异步结束后由 release 回调清集合），shutdown
        # 清整个集合。两变量语义不同故保留双跟踪，非冗余。
        self._entry_worker: BackgroundWorker | None = None
        self._entry_workers: set[BackgroundWorker] = set()
        self._entry_refresh_generation = 0
        # 标签下拉异步刷新：get_all_tags() 在缓存失效时需全量解密全部条目 tags，
        # 大库下移入后台。_tag_worker 跟踪最新标签 worker（取消重叠），标签 worker
        # 同样加入 _entry_workers 以复用 _shutdown_workers / closeEvent 的取消。
        self._tag_worker: BackgroundWorker | None = None
        self._tag_refresh_generation = 0
        self._cached_categories = []
        self._cached_tag_names = []
        self._cached_total_entries = -1
        # 上次刷新的过滤器键，用于判断滚动位置是否应恢复（仅同一过滤器刷新
        # 时恢复）。显式初始化，避免依赖 filters.py 的 getattr 兜底。
        self._last_refresh_filter: str | None = None

        # 条目变更防抖定时器，用于合并短时间内连续的刷新请求
        self._entry_change_timer = QTimer(self)
        self._entry_change_timer.setSingleShot(True)
        self._entry_change_timer.setInterval(MS_ENTRY_CHANGE_DEBOUNCE)
        self._entry_change_timer.timeout.connect(self._do_refresh_after_entry_change)

        # 条目选择防抖定时器，快速导航时不触发逐条解密
        self._select_timer = QTimer(self)
        self._select_timer.setSingleShot(True)
        self._select_timer.setInterval(MS_ENTRY_SELECT_DEBOUNCE)
        self._select_timer.timeout.connect(self._do_select_entry)
        self._pending_selection: int | None = None

        self._setup_ui()
        self._setup_menubar()
        self._setup_shortcuts()
        self._setup_tray()
        self._setup_auto_lock()
        self._setup_auto_backup()
        app = QApplication.instance()
        if app:
            app.installEventFilter(self)
        self._refresh_entries()

    def _create_ui_controllers(self) -> None:
        """组装依赖 Qt 线程亲和性或 UI 配置的控制器。

        纯 Python business manager 由 BusinessContext 注入（见 composition.py）；
        此处仅创建 QObject 控制器（AutoLock/AutoBackup/Clipboard）与依赖 UI 配置的
        控制器（EntryList/Sidebar），它们有线程亲和性或需 config，不适合放入
        frozen dataclass。跨 manager 连线（锁定/变更回调）已在 build_business_context
        完成。
        """
        self._entry_list_ctrl = EntryListController(
            self._entry_mgr, self._security, self._config,
        )
        self._sidebar_ctrl = SidebarController(self._entry_mgr, self._config)
        self._auto_backup = AutoBackupController(self._vault, self._backup, self._config)
        self._auto_lock = AutoLockController(self._vault, self._config, self.lock_requested.emit)
        self._clipboard = ClipboardManager(
            self._config.get_safe('clipboard_clear_seconds', CLIPBOARD_CLEAR_SECONDS_DEFAULT)
        )

    def _setup_ui(self) -> None:
        self.setWindowTitle('CipherBox')
        self.setMinimumSize(*WINDOW_MIN_SIZE)
        self.resize(*WINDOW_DEFAULT_SIZE)

        theme = self._config.get('theme', DEFAULT_THEME)
        self.setStyleSheet(get_style(theme))
        self._current_theme: str = theme

        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        self._splitter = QSplitter(Qt.Orientation.Horizontal)
        self._splitter.setHandleWidth(1)

        # === 左侧：侧边栏 ===
        self._build_sidebar()

        # === 中间：条目列表 ===
        self._build_entry_list()

        # === 右侧：详情面板 ===
        self._detail_panel = DetailPanel(self._clipboard, entry_manager=self._entry_mgr, config=self._config)
        self._splitter.addWidget(self._detail_panel)

        # 设置分割比例
        saved_sizes = self._config.get('splitter_sizes')
        if saved_sizes and len(saved_sizes) == 3:
            self._splitter.setSizes(saved_sizes)
        else:
            self._splitter.setSizes(SPLITTER_SIZES)

        main_layout.addWidget(self._splitter)

        # 恢复窗口位置
        saved_geo = self._config.get('window_geometry')
        if saved_geo:
            try:
                geo_bytes = bytes.fromhex(saved_geo)
                # 上限与 config._is_valid 共用 MAX_WINDOW_GEOMETRY_BYTES 单一常量，
                # 消除校验端与消费端各自硬编码导致合法 geometry 被静默丢弃。
                if len(geo_bytes) <= MAX_WINDOW_GEOMETRY_BYTES:
                    self.restoreGeometry(geo_bytes)
            except (ValueError, RuntimeError):
                logger.debug("窗口几何位置恢复失败，已忽略", exc_info=True)

        # 连接详情面板信号
        self._detail_panel.edit_requested.connect(self._edit_entry)
        self._detail_panel.delete_requested.connect(self._delete_entry)
        self._detail_panel.favorite_toggled.connect(self._toggle_favorite)
        self._detail_panel.copy_feedback.connect(self._on_copy_feedback)

        # 状态栏
        self._status_bar = QStatusBar()
        self._warning_label = QLabel()
        self._warning_label.setObjectName('warningText')
        self.setStatusBar(self._status_bar)
        self._update_status_bar()

    def _build_sidebar(self) -> None:
        self._sidebar = QWidget()
        self._sidebar.setObjectName('sidebar')
        self._sidebar.setFixedWidth(SIDEBAR_WIDTH)
        sidebar_layout = QVBoxLayout(self._sidebar)
        sidebar_layout.setContentsMargins(12, 14, 12, 12)
        sidebar_layout.setSpacing(6)

        brand_row = QHBoxLayout()
        self._brand_icon = QLabel()
        self._brand_icon.setPixmap(icon_pixmap(SHIELD, 'accent', 24))
        self._brand_icon.setFixedSize(28, 28)
        brand_row.addWidget(self._brand_icon)
        brand_text = QVBoxLayout()
        brand_text.setSpacing(0)
        self._brand_title = QLabel('CipherBox')
        self._brand_title.setObjectName('sidebarBrandTitle')
        self._brand_subtitle = QLabel('本地加密保险库')
        self._brand_subtitle.setObjectName('sidebarBrandSubtitle')
        brand_text.addWidget(self._brand_title)
        brand_text.addWidget(self._brand_subtitle)
        brand_row.addLayout(brand_text, 1)
        sidebar_layout.addLayout(brand_row)
        sidebar_layout.addSpacing(8)

        # 搜索框
        self._search_edit = QLineEdit()
        self._search_edit.setPlaceholderText('搜索标题、账号或标签')
        self._search_edit.setClearButtonEnabled(True)
        self._search_edit.addAction(icon(SEARCH), QLineEdit.ActionPosition.LeadingPosition)
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(MS_SEARCH_DEBOUNCE)
        self._search_timer.timeout.connect(self._do_search)
        self._search_edit.textChanged.connect(self._on_search_input)
        sidebar_layout.addWidget(self._search_edit)

        self._tag_combo = QComboBox()
        self._tag_combo.setToolTip('按标签筛选条目')
        self._tag_combo.currentIndexChanged.connect(self._on_tag_changed)
        sidebar_layout.addWidget(self._tag_combo)
        self._refresh_tag_filter()

        # 筛选标签
        self._filter_label = QLabel('筛选')
        self._filter_label.setObjectName('sidebarSectionLabel')
        sidebar_layout.addWidget(self._filter_label)

        # 筛选项列表
        self._filter_list = QListWidget()
        self._filter_list.setMaximumHeight(FILTER_MAX_HEIGHT)
        self._build_filter_list()
        self._filter_list.currentItemChanged.connect(self._on_filter_changed)
        sidebar_layout.addWidget(self._filter_list)

        # 筛选区域分割线
        self._separator1 = QLabel()
        self._separator1.setFixedHeight(1)
        self._separator1.setObjectName('sidebarSeparator')
        sidebar_layout.addWidget(self._separator1)

        # 分类标签
        cat_header = QHBoxLayout()
        self._cat_label = QLabel('分类')
        self._cat_label.setObjectName('sidebarSectionLabel')
        cat_header.addWidget(self._cat_label)
        cat_header.addStretch()
        add_cat_btn = QPushButton('+')
        add_cat_btn.setObjectName('iconBtn')
        add_cat_btn.setFixedSize(22, 22)
        add_cat_btn.setToolTip('管理分类')
        add_cat_btn.setStyleSheet('font-size: 14px;')
        add_cat_btn.clicked.connect(self._add_category)
        cat_header.addWidget(add_cat_btn)
        sidebar_layout.addLayout(cat_header)

        # 分类列表
        self._category_list = QListWidget()
        self._category_list.currentItemChanged.connect(self._on_category_changed)
        self._category_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._category_list.customContextMenuRequested.connect(self._on_category_context_menu)
        self._refresh_categories()
        sidebar_layout.addWidget(self._category_list)

        # 分类区域分割线
        self._separator2 = QLabel()
        self._separator2.setFixedHeight(1)
        self._separator2.setObjectName('sidebarSeparator')
        sidebar_layout.addWidget(self._separator2)

        sidebar_layout.addStretch()

        # 排序控件
        self._sort_label = QLabel('排序')
        self._sort_label.setObjectName('sidebarSectionLabel')
        sidebar_layout.addWidget(self._sort_label)

        self._sort_combo = QComboBox()
        for label, _, _ in SORT_OPTIONS:
            self._sort_combo.addItem(label)
        sort_field = self._config.get('sort_field', 'updated_at')
        sort_order = self._config.get('sort_order', 'desc')
        sort_idx = next(
            (i for i, (_, f, o) in enumerate(SORT_OPTIONS) if f == sort_field and o == sort_order),
            0,
        )
        self._sort_combo.setCurrentIndex(sort_idx)
        self._sort_combo.currentIndexChanged.connect(self._on_sort_changed)
        sidebar_layout.addWidget(self._sort_combo)

        # 统计
        self._stats_label = QLabel('')
        self._stats_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._stats_label.setObjectName('sidebarStatsLabel')
        sidebar_layout.addWidget(self._stats_label)

        self._splitter.addWidget(self._sidebar)

    def _build_filter_list(self) -> None:
        """重建侧边栏筛选项列表，主题切换时需要重建图标。"""
        from ..resources.icons import (
            FILTER_ALL,
            FILTER_DUPLICATE,
            FILTER_FAVORITE,
            FILTER_RECENT,
            FILTER_TRASH,
            FILTER_WEAK,
        )

        current_row = self._filter_list.currentRow()
        self._filter_list.blockSignals(True)
        self._filter_list.clear()
        filters = [
            ('全部', 'all', FILTER_ALL),
            ('收藏', 'favorite', FILTER_FAVORITE),
            ('弱密码', 'weak', FILTER_WEAK),
            ('重复密码', 'duplicate', FILTER_DUPLICATE),
            ('近期更新', 'recent', FILTER_RECENT),
            ('回收站', 'trash', FILTER_TRASH),
        ]
        for text, key, icon_name in filters:
            item = QListWidgetItem(text)
            item.setData(Qt.ItemDataRole.UserRole, key)
            item.setIcon(icon(icon_name))
            self._filter_list.addItem(item)
        if current_row >= 0:
            self._filter_list.setCurrentRow(current_row)
        else:
            self._filter_list.setCurrentRow(0)
        self._filter_list.blockSignals(False)

    def _build_entry_list(self) -> None:
        list_container = QWidget()
        list_container.setObjectName('listPane')
        list_layout = QVBoxLayout(list_container)
        list_layout.setContentsMargins(0, 0, 0, 0)
        list_layout.setSpacing(0)

        # 列表标题栏
        list_header = QHBoxLayout()
        list_header.setContentsMargins(12, 8, 12, 4)

        self._list_title = QLabel('全部条目')
        self._list_title.setObjectName('sidebarListTitle')
        list_header.addWidget(self._list_title)

        list_header.addStretch()

        self._count_label = QLabel('0 项')
        self._count_label.setObjectName('sidebarCountLabel')
        list_header.addWidget(self._count_label)

        list_layout.addLayout(list_header)

        # 条目列表，使用 QStackedWidget 切换列表和空状态
        self._list_stack = QStackedWidget()

        # Model/View：QListView + EntryListModel 替代 QListWidget，
        # set_entries 一次替换数据，视图按需经 delegate 绘制，消除逐项 item 创建。
        self._entry_list = QListView()
        self._entry_list.setObjectName('entryList')
        self._entry_model = EntryListModel(self._entry_list)
        self._entry_list.setModel(self._entry_model)
        self._entry_delegate = EntryItemDelegate(self._entry_list)
        self._entry_list.setItemDelegate(self._entry_delegate)
        self._entry_list.setUniformItemSizes(True)
        self._entry_list.setAlternatingRowColors(True)
        # QListView 无 currentItemChanged，改用 selectionModel 的 currentChanged
        selection_model = self._entry_list.selectionModel()
        if selection_model is not None:
            selection_model.currentChanged.connect(self._on_entry_selected)
        self._entry_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._entry_list.customContextMenuRequested.connect(self._on_entry_context_menu)
        self._list_stack.addWidget(self._entry_list)

        list_layout.addWidget(self._list_stack, 1)

        # 添加按钮
        add_bar = QHBoxLayout()
        add_bar.setContentsMargins(8, 4, 8, 8)
        add_btn = QPushButton()
        add_btn.setObjectName('primaryBtn')
        set_icon_with_text(add_btn, '新增条目', PLUS, 'text_on_accent')
        add_btn.clicked.connect(self._add_entry)
        add_bar.addWidget(add_btn)
        list_layout.addLayout(add_bar)

        self._splitter.addWidget(list_container)

    def _setup_tray(self) -> None:
        if not self._config.get('show_tray_icon', True):
            return
        # 与 _apply_runtime_settings 的 disable 分支对称：若已存在旧托盘实例
        # （如运行期设置变更或重建路径调用此方法），先清理避免孤儿 QSystemTrayIcon
        # 残留并占用任务栏图标槽位。deleteLater 由 Qt 事件循环安全回收。
        if self._tray is not None:
            self._tray.hide()
            self._tray.deleteLater()
            self._tray = None
        # 先断开旧连接，避免禁用→重启用托盘时 _on_lock_tray 重复连接
        disconnect_all([(self.lock_requested, self._on_lock_tray)])
        self._tray = TrayIcon(self)
        self._tray.show_window.connect(self._show_from_tray)
        self._tray.lock_vault.connect(lambda: self.lock_requested.emit())
        self._tray.quit_app.connect(self._quit_app)
        self._tray.show()
        self.lock_requested.connect(self._on_lock_tray)

    def _setup_auto_lock(self) -> None:
        self._auto_lock.setup(self)

    def showEvent(self, event: QShowEvent | None) -> None:  # pyright: ignore[reportIncompatibleMethodOverride]
        super().showEvent(event)
        # WTS 注册须在窗口 show 后（HWND 有效）；__init__ 时未 show 会触发 C 层
        # access violation。注册逻辑由 AutoLockController 负责（内部幂等，仅首次显示时注册）。
        self._auto_lock.setup_session_notification(self)

    def _setup_auto_backup(self) -> None:
        # 定时器创建与 worker 生命周期由 AutoBackupController 管理；不在此启动
        # （vault 未解锁时空转），由 refresh_after_unlock 在解锁后启动。
        self._auto_backup.setup(self)

    def eventFilter(self, watched: QObject | None, event: QEvent | None) -> bool:  # pyright: ignore[reportIncompatibleMethodOverride]
        """捕获整个应用的用户活动，重置自动锁定计时器。

        排除修饰键即 Shift/Ctrl/Alt/Meta，仅有意义的按键才重置。
        仅对按键、鼠标点击、滚轮与触摸开始重置；不包含 MouseMove，
        因为鼠标静止悬停时系统仍会持续产生移动事件，纳入它会使
        超时锁定被无限推迟，违背密码管理器的安全预期。
        此过滤器替代了 keyPressEvent/mousePressEvent 的双重功能。
        """
        if event is not None and event.type() == QEvent.Type.KeyPress:
            key_event = cast(QKeyEvent, event)
            if key_event.key() not in (
                Qt.Key.Key_Shift, Qt.Key.Key_Control,
                Qt.Key.Key_Alt, Qt.Key.Key_Meta,
            ):
                self._auto_lock.reset_timer()
        elif event is not None and event.type() in (
            QEvent.Type.MouseButtonPress,
            QEvent.Type.Wheel,
            QEvent.Type.TouchBegin,
        ):
            self._auto_lock.reset_timer()
        return super().eventFilter(watched, event)

    def _apply_runtime_settings(self) -> None:
        """立即应用无需重启的安全和托盘设置。"""
        self._clipboard.clear_seconds = self._config.get_safe('clipboard_clear_seconds', CLIPBOARD_CLEAR_SECONDS_DEFAULT)
        self._auto_lock.reset_timer()
        self._auto_backup.trigger_check()
        should_show = self._config.get('show_tray_icon', True)
        if should_show and self._tray is None:
            self._setup_tray()
        elif not should_show and self._tray is not None:
            self._tray.hide()
            self._tray.deleteLater()
            self._tray = None

    def _shutdown_workers(self) -> None:
        """取消并等待所有后台 worker 结束，避免 QThread running 析构崩溃。

        统一 status/backup 两类 worker 的关闭：取消（设置协作取消标志）并等待
        其退出，超时则记 error（见 ``wait_worker_shutdown``）。锁定、退出、隐藏到
        托盘前调用，确保这些路径不再持有密钥或对已锁定 vault 发信号、继续解密条目。
        """
        wait_worker_shutdown(self._status_worker)
        self._status_worker = None
        self._auto_backup.shutdown()
        for worker in tuple(self._entry_workers):
            wait_worker_shutdown(worker)
        self._entry_workers.clear()
        self._entry_worker = None
        self._tag_worker = None

    def _quit_app(self) -> None:
        # 托盘退出：与 closeEvent 退出分支清理对齐——先移除事件过滤器，防止
        # 已销毁对象仍被 QApplication 引用、排队的原生消息派发到已删闭包。
        app = QApplication.instance()
        if app:
            app.removeEventFilter(self)
        # 移除会话锁屏原生事件过滤器（与 removeEventFilter 对称），解除
        # QApplication 对其闭包（绑定 lock_requested）的引用。
        self._auto_lock.remove_session_filter()
        # 等待后台 worker 退出（避免 QThread running 析构崩溃），清剪贴板明文，
        # 再关闭 vault
        self._shutdown_workers()
        self._clipboard.clear_now()
        self._vault.close()
        if self._tray:
            self._tray.hide()
        QApplication.quit()

    # ========== 主题刷新 ==========

    def _apply_theme(self) -> None:
        """应用当前主题，用于设置切换后刷新。"""
        theme = self._config.get('theme', DEFAULT_THEME)
        if theme != self._current_theme:
            self._current_theme = theme
            style = get_style(theme)
            app = QApplication.instance()
            if isinstance(app, QApplication):
                app.setStyleSheet(style)  # pyright: ignore[reportAttributeAccessIssue]
            # 重建侧边栏筛选图标，因为颜色已烘焙到 QIcon 中需要重建
            self._build_filter_list()
            # 刷新菜单栏图标
            self._update_menu_icons()
            self._brand_icon.setPixmap(icon_pixmap(SHIELD, 'accent', 24))
            if self._tray:
                self._tray.set_locked(False)
            # 主题切换时数据未变，只需强制重绘列表控件
            self._entry_delegate.clear_color_cache()
            self._entry_list.update()
            # 分类列表的 FOLDER 图标颜色已烘焙到 QIcon，update() 不会刷新，
            # 需重建分类列表以用新主题颜色重新生成图标。
            self._refresh_categories()
            # 空状态 EmptyStateWidget 的颜色在创建时烘焙，主题切换时需重建刷新
            if self._list_stack.currentWidget() is not self._entry_list:
                self._show_empty_state()
            # 刷新详情面板：force=True 强制重建以刷新内联样式
            # 仅在详情面板已有内容时刷新，避免主题切换意外恢复用户已取消选择的条目
            current_entry = self._detail_panel.current_entry
            if current_entry:
                self._detail_panel.show_entry(current_entry, force=True)
            else:
                self._detail_panel.show_empty()
            # 刷新活跃 Toast 的烘焙配色（背景/文本/按钮颜色随主题变化）
            from ..components.toast import ToastManager
            ToastManager.refresh_for(self)

    # ========== 窗口事件 ==========

    def _stop_ui_timers(self) -> None:
        """停止所有 UI 去抖定时器（搜索/选择/条目变更/状态栏）。

        收敛锁定、隐藏到托盘等状态转换路径的定时器停止集合为单一调用，避免新增
        定时器时遗漏某个——``_status_timer`` 曾在 ``_secure_hide_to_tray`` 漏停，
        致托盘态 pending 触发仍启动全量解密的安全分析 worker。
        """
        self._search_timer.stop()
        self._select_timer.stop()
        self._entry_change_timer.stop()
        self._status_timer.stop()

    def _secure_hide_to_tray(self) -> None:
        """隐藏到托盘前的安全清理：清详情面板明文、清剪贴板、停 worker 与定时器。

        close_to_tray 与 minimize_to_tray 共用：保持 vault 解锁与列表模型，
        但清除瞬时明文（详情面板、剪贴板）并停止后台解密 worker，避免隐藏到
        托盘后仍持有密钥/明文。_lock_timer 仍运行，托盘态空闲超时会自动锁定。
        """
        self._detail_panel.show_empty()
        self._clipboard.clear_now()
        self._stop_ui_timers()
        self._pending_selection = None
        from ..components.toast import ToastManager
        ToastManager.cancel_all_for(self)
        self._shutdown_workers()

    def closeEvent(self, a0: QCloseEvent | None) -> None:
        if a0 is None:
            return
        try:
            geo = self.saveGeometry()
            self._config.set('window_geometry', geo.data().hex())
            sizes = self._splitter.sizes()
            self._config.set('splitter_sizes', list(sizes))
            field, order = self._get_sort_config()
            self._config.set('sort_field', field)
            self._config.set('sort_order', order)
            self._config.save()
        except (OSError, ValueError, TypeError):
            logger.debug("保存窗口状态失败", exc_info=True)

        if self._config.get('close_to_tray', False) and self._tray:
            # 隐藏到托盘（非退出、非锁定）：安全清理后隐藏。保持 vault 解锁、
            # 列表模型与备份/状态定时器；_lock_timer 仍运行，托盘态空闲超时会
            # 自动锁定（安全设计）。从托盘恢复时窗口立即可用；详情面板已清空，
            # 恢复后由用户重新选择条目。
            self._secure_hide_to_tray()
            a0.ignore()
            self.hide()
        else:
            # 完全退出：移除事件过滤器，防止已销毁对象仍被 QApplication 引用。
            app = QApplication.instance()
            if app:
                app.removeEventFilter(self)
            # 移除会话锁屏原生事件过滤器（与 removeEventFilter 对称），解除
            # QApplication 对其闭包（绑定 lock_requested）的引用。
            self._auto_lock.remove_session_filter()
            # 统一用 _shutdown_workers 取消并等待后台 worker 结束，
            # 与 prepare_for_lock 的关闭模式一致，确保退出前 worker 不再持有密钥。
            self._shutdown_workers()
            # 完全退出时清除剪贴板中的明文密码，防止应用关闭后残留
            self._clipboard.clear_now()
            self._vault.close()
            if self._tray:
                self._tray.hide()
            a0.accept()

    def changeEvent(self, a0: QEvent | None) -> None:
        if a0 is None:
            return
        if a0.type() == a0.Type.WindowStateChange:
            if self.windowState() & Qt.WindowState.WindowMinimized:
                if self._config.get('minimize_to_tray', True) and self._tray:
                    # 最小化到托盘同样视为「离开交互」，执行与 close_to_tray 一致
                    # 的安全清理，避免最小化比关闭更不安全（详情明文、剪贴板明文、
                    # 后台解密 worker 继续运行）。hide 延迟到下一事件循环避免
                    # 在 changeEvent 内直接 hide 的 Qt 重入问题。
                    self._secure_hide_to_tray()
                    QTimer.singleShot(0, self.hide)
        super().changeEvent(a0)

    def refresh_after_unlock(self) -> None:
        """解锁后刷新界面。"""
        self._locked_ui = False
        if self._first_unlock:
            # 首次解锁紧跟构造：__init__/_setup_ui 已刷新 categories/tags/entries，
            # 跳过重复全量加载（否则构造期 worker 与本处 worker 双重解密）。
            self._first_unlock = False
        else:
            self._refresh_categories()
            self._refresh_tag_filter()
            self._refresh_entries()
        self._detail_panel.show_empty()
        self._auto_lock.reset_timer()
        # 解锁后刷新状态栏安全摘要，避免停留在锁定前的陈旧或空白状态
        self._status_timer.start()
        # 重启自动备份定时器：prepare_for_lock 已停止它，解锁后须恢复，
        # 否则任意一次锁定→解锁后本地自动快照将永久失效。
        self._auto_backup.start_timer()
        self._auto_backup.schedule_initial_check()
        if self._tray:
            self._tray.set_locked(False)

    def emergency_clear_clipboard(self) -> None:
        """紧急清空剪贴板，供 app 层崩溃/退出兜底经公共 API 调用。

        避免崩溃兜底路径直接 getattr 访问 ``_clipboard`` 私有属性——重命名该属性时
        getattr 返回 None 会无声错过清理，而崩溃兜底恰是最不应静默失效的安全路径。
        """
        clipboard = getattr(self, '_clipboard', None)
        if clipboard is not None:
            try:
                clipboard.clear_now()
            except Exception:
                # 崩溃兜底路径清空的是可能残留的明文密码，属最严重的安全事件；
                # 用 error 级确保生产默认 INFO 输出仍可见，便于发现静默失效。
                logger.error("崩溃兜底紧急清空剪贴板失败，明文可能残留", exc_info=True)

    def emergency_cancel_workers(self, *, wait_timeout_ms: float = 0.0) -> None:
        """紧急取消后台 worker，供 app 层 aboutToQuit 等不阻塞退出路径。

        与 ``_shutdown_workers`` 的区别：默认仅取消不等待（避免阻塞退出）；
        ``wait_timeout_ms > 0`` 时取消后等待该超时（aboutToQuit 用短超时，让持密钥
        解密的 worker 退出协作循环后再 lock 清零，收缩「已锁定」后明文残留窗口；
        超时放弃不阻塞退出）。遍历 ``_entry_workers`` 全集快照（含并发 entry worker），
        而非仅 ``_entry_worker`` 单引用（最后一个），避免漏 cancel 并发 worker 残留
        持密钥继续解密、与 lock() 清零竞态。
        """
        self._auto_backup.cancel()
        workers = (self._status_worker, *tuple(self._entry_workers))
        for worker in workers:
            if worker is None:
                continue
            try:
                worker.cancel()
            except RuntimeError:
                pass
        if wait_timeout_ms > 0:
            for worker in workers:
                if worker is None:
                    continue
                try:
                    worker.wait(int(wait_timeout_ms))
                except RuntimeError:
                    pass

    def prepare_for_lock(self) -> None:
        """在清除主密钥前销毁界面和剪贴板中的明文副本。

        清理顺序原则：先立即收敛主窗口自身的明文/密钥/可见性（列表模型、详情面板、
        剪贴板、定时器、缓存、后台 worker），**再**关闭对话框——后者经
        ``wait_worker_shutdown`` 可能阻塞主线程等待后台写入完成（恢复/导入 worker
        不可中断）。若先等对话框，恢复/导入进行中触发锁定会使主密钥与明文 UI 在
        用户「已请求锁定」后仍持续可见数秒至数十秒；先清主窗口可把暴露面收敛到
        对话框自身的敏感控件（由各对话框 reject 路径清零）。
        """
        self._locked_ui = True
        self._auto_lock.stop_timer()
        # 清除活跃 Toast 的回调，防止锁定后撤销操作触发异常。
        from ..components.toast import ToastManager
        ToastManager.cancel_all_for(self)
        # —— 先立即清空主窗口敏感 UI 与状态（均不阻塞）——
        self._current_search = ''
        self._search_edit.blockSignals(True)
        self._search_edit.clear()
        self._search_edit.blockSignals(False)
        self._stop_ui_timers()
        self._pending_selection = None
        # 清空条目列表，移除对 Entry 对象的引用
        self._entry_model.set_entries([])
        # 安全清除详情面板中的敏感数据和信号连接
        self._detail_panel.secure_clear()
        # 清除剪贴板中的明文
        self._clipboard.clear_now()
        # 停止后台定时器
        self._auto_backup.stop_timer()
        # 取消后台 worker（状态分析/备份/列表刷新），避免锁定后仍运行、对已锁定
        # vault 发信号或继续解密条目
        self._shutdown_workers()
        # 清除缓存
        self._invalidate_security_cache()
        # 清空 username 明文缓存。epoch 失效会在下次访问时触发，
        # 此处显式调用以立即释放，避免锁定到进程退出的残留窗口
        self._entry_mgr.invalidate_caches()
        # —— 最后关闭对话框：reject 经 wait_worker_shutdown 可能阻塞等待后台 worker ——
        # 各对话框 reject 调用自身的 _clear_sensitive_inputs 清零敏感控件并等待后台
        # worker 退出；置于末尾使主窗口明文先行清除，对话框等待期间的暴露仅限其自身。
        if QApplication.instance():
            for widget in list(QApplication.topLevelWidgets()):
                if widget is self or not isinstance(widget, QDialog):
                    continue
                widget.reject()
        self._count_label.setText('0 项')
        self._status_bar.clearMessage()
        # 托盘锁定状态由 lock_requested 信号驱动（_setup_tray 连接 _on_lock_tray），
        # 此处不再显式调用，避免与信号链重复触发

    def _on_lock_tray(self) -> None:
        """锁定时更新托盘图标状态。"""
        if self._tray:
            self._tray.set_locked(True)
