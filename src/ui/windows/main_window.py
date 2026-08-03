"""CipherBox 主窗口。

编排侧边栏、条目列表与详情面板，集成快捷键、排序、Toast、分类管理、标签筛选、
撤销删除、主题刷新、自动锁定与备份、安全仪表盘等。职责经组合化 controller 分离：
MenuController（菜单/对话框调度）、EntryActionsController（条目 CRUD/分类/右键菜单）、
ListRefreshController（筛选/排序/列表刷新/状态栏/worker），经冻结 dataclass 回调协作；
host 仅保留控件创建、生命周期编排（锁定/关闭/托盘/主题/事件过滤）与 ``_locked_ui``
状态广播。
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
from PyQt6.QtGui import QAction, QCloseEvent, QKeyEvent, QShowEvent
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
from ...config import (
    CFG_CLIPBOARD_CLEAR_SECONDS,
    CFG_CLOSE_TO_TRAY,
    CFG_MINIMIZE_TO_TRAY,
    CFG_SHOW_TRAY_ICON,
    CFG_SORT_FIELD,
    CFG_SORT_ORDER,
    CFG_SPLITTER_SIZES,
    CFG_THEME,
    CFG_WINDOW_GEOMETRY,
    DEFAULT_THEME,
    MAX_WINDOW_GEOMETRY_BYTES,
)
from ...models import Category
from ..components.detail_panel import DetailPanel
from ..components.entry_list_widget import EntryItemDelegate, EntryListModel
from ..components.toast import ToastManager
from ..components.tray_icon import TrayIcon
from ..components.widgets import disconnect_all
from ..controllers.auto_backup_controller import AutoBackupController
from ..controllers.auto_lock_controller import AutoLockController
from ..controllers.entry_actions_controller import (
    EntryActionsController,
    EntryActionsDeps,
    EntryActionsView,
)
from ..controllers.entry_list_controller import EntryListController
from ..controllers.list_refresh_controller import (
    ListRefreshController,
    ListRefreshDeps,
    ListRefreshView,
)
from ..controllers.menu_controller import MenuController, MenuDeps, MenuSlots
from ..controllers.sidebar_controller import SidebarController
from ..dialogs.login_window import LoginWindow
from ..resources.constants import (
    CLIPBOARD_CLEAR_SECONDS_DEFAULT,
    FILTER_MAX_HEIGHT,
    SIDEBAR_ICON_SIZE,
    SIDEBAR_ICON_SIZE_SMALL,
    SIDEBAR_WIDTH,
    SORT_OPTIONS,
    SPLITTER_SIZES,
    WINDOW_DEFAULT_SIZE,
    WINDOW_MIN_SIZE,
)
from ..resources.icons import (
    FILTER_ALL,
    FILTER_DUPLICATE,
    FILTER_FAVORITE,
    FILTER_RECENT,
    FILTER_TRASH,
    FILTER_WEAK,
    PLUS,
    SEARCH,
    SHIELD,
    icon,
    icon_pixmap,
    set_icon_with_text,
)
from ..resources.styles import get_style
from ..resources.theme_colors import set_theme
from ..utils.clipboard import ClipboardManager

logger = logging.getLogger(__name__)


class MainWindow(QMainWindow):
    """CipherBox 主窗口，UI 层中心编排器。

    经 ``BusinessContext`` 注入业务层 manager；自身仅装配依赖 Qt 线程亲和性的
    控制器与子组件，把菜单调度、条目 CRUD、列表刷新等委托给组合化 controller。
    职责划分与控制器协作细节见模块 docstring。
    """

    lock_requested = pyqtSignal()

    def __init__(self, ctx: BusinessContext) -> None:
        super().__init__()
        # 保留 ctx 引用供 MenuController 等控制器聚合注入业务 manager。
        self._ctx = ctx
        self._config = ctx.config
        self._vault = ctx.vault
        self._entry_mgr = ctx.entry_mgr
        self._security = ctx.security
        self._import_export = ctx.import_export
        self._backup = ctx.backup
        # 显式标注类型，使 mypy 能解析 helper 外的引用点（如 self._menu.setup）。
        self._menu: MenuController
        self._list_refresh: ListRefreshController
        self._entry_actions: EntryActionsController
        self._create_ui_controllers()
        self._tray: TrayIcon | None = None
        self._locked_ui = False
        # 首次解锁跳过刷新：构造期 setup 已加载，避免重复 worker 双重全量解密。
        self._first_unlock = True

        self._setup_ui()
        # 顺序保证依赖：list_refresh（建立缓存）→ entry_actions（deps 读其缓存/方法）
        # → menu（slots 绑 entry_actions）。list_refresh 空态 on_add_entry 经 lambda
        # 延迟绑定 entry_actions.add_entry（运行时 entry_actions 已就绪）。
        self._create_list_refresh_controller()
        self._create_entry_actions_controller()
        self._list_refresh.setup(self, self._list_refresh_view())
        self._entry_actions.setup(self, self._entry_actions_view())
        self._create_menu_controller()
        self._menu.setup(self, self._search_edit)
        self._setup_tray()
        self._setup_auto_lock()
        self._setup_auto_backup()
        app = QApplication.instance()
        if app:
            app.installEventFilter(self)

    def _create_ui_controllers(self) -> None:
        """组装依赖 Qt 线程亲和性或 UI 配置的控制器。

        BusinessContext 注入纯 Python business manager；此处仅创建有线程亲和性或
        需 config 的 QObject 控制器（AutoLock/AutoBackup/Clipboard/EntryList/Sidebar），
        不适合放入 frozen dataclass。
        """
        self._entry_list_ctrl = EntryListController(
            self._entry_mgr,
            self._security,
            self._config,
        )
        self._sidebar_ctrl = SidebarController(self._entry_mgr)
        self._auto_backup = AutoBackupController(self._vault, self._backup, self._config)
        self._auto_lock = AutoLockController(self._vault, self._config, self.lock_requested.emit)
        self._clipboard = ClipboardManager(
            self._config.get_safe(CFG_CLIPBOARD_CLEAR_SECONDS, CLIPBOARD_CLEAR_SECONDS_DEFAULT)
        )

    def _create_menu_controller(self) -> None:
        """组装菜单控制器（需在 _setup_ui 与各 controller 创建后）。

        条目操作回调绑 entry_actions，clear_search/refresh 绑 list_refresh，
        apply_*/lock 绑 host 方法。
        """
        self._menu = MenuController(
            MenuDeps(
                ctx=self._ctx,
                clipboard=self._clipboard,
                detail_panel=self._detail_panel,
                auto_backup=self._auto_backup,
            ),
            MenuSlots(
                add_entry=self._entry_actions.add_entry,
                edit_entry=self._entry_actions.edit_entry,
                edit_selected_entry=self._entry_actions.edit_selected_entry,
                delete_selected_entry=self._entry_actions.delete_selected_entry,
                on_password_selected=self._entry_actions.on_password_selected,
                clear_search=self._list_refresh.clear_search,
                refresh_all_data=self._list_refresh.refresh_all_data,
                apply_theme=self._apply_theme,
                apply_runtime_settings=self._apply_runtime_settings,
                lock=self.lock_requested.emit,
            ),
        )

    def _create_list_refresh_controller(self) -> None:
        """组装列表刷新控制器（须在 _setup_ui 与 entry_actions 之前，依赖控件）。

        EntryActionsDeps 的 refresh_* 绑本控制器方法；空态 on_add_entry 经 lambda
        延迟绑定 entry_actions.add_entry（运行时已就绪）。
        """
        self._list_refresh = ListRefreshController(
            self._config,
            self._entry_mgr,
            self._security,
            self._entry_list_ctrl,
            self._sidebar_ctrl,
            ListRefreshDeps(on_add_entry=lambda: self._entry_actions.add_entry()),
        )

    def _list_refresh_view(self) -> ListRefreshView:
        """收集 ListRefreshController.setup 所需的控件引用（控件仍是 host 属性）。"""
        return ListRefreshView(
            search_edit=self._search_edit,
            entry_list=self._entry_list,
            entry_model=self._entry_model,
            category_list=self._category_list,
            tag_combo=self._tag_combo,
            sort_combo=self._sort_combo,
            filter_list=self._filter_list,
            list_stack=self._list_stack,
            list_title=self._list_title,
            count_label=self._count_label,
            status_bar=self._status_bar,
            warning_label=self._warning_label,
            stats_label=self._stats_label,
            detail_panel=self._detail_panel,
        )

    def _create_entry_actions_controller(self) -> None:
        """组装条目操作控制器（须在 _setup_ui 与 list_refresh 之后，依赖控件）。

        refresh_* 绑 list_refresh 方法；get_dialog_options 转发 list_refresh 缓存，
        供新增/编辑对话框预填分类与标签。
        """
        self._entry_actions = EntryActionsController(
            self._config,
            self._entry_mgr,
            self._clipboard,
            self._detail_panel,
            self._sidebar_ctrl,
            EntryActionsDeps(
                refresh_after_entry_change=self._list_refresh.refresh_after_entry_change,
                refresh_entries_only=self._list_refresh.refresh_entries_only,
                refresh_categories=self._list_refresh.refresh_categories,
                get_dialog_options=self._get_dialog_options,
            ),
        )

    def _entry_actions_view(self) -> EntryActionsView:
        """收集 EntryActionsController.setup 所需的控件引用（控件仍是 host 属性）。"""
        return EntryActionsView(
            entry_list=self._entry_list,
            category_list=self._category_list,
            status_bar=self._status_bar,
            add_entry_btn=self._add_entry_btn,
            add_category_btn=self._add_category_btn,
        )

    def _get_dialog_options(self) -> tuple[list[Category], list[str]]:
        """供 EntryActionsController 新增/编辑对话框读取分类缓存与标签自动补全。"""
        return self._list_refresh.cached_categories, self._list_refresh.cached_tag_names

    def _show_from_tray(self) -> None:
        """托盘「显示窗口」回调：锁定态激活登录窗，解锁态显示主窗并刷新状态栏。"""
        if not self._vault.is_unlocked or self._locked_ui:
            for widget in QApplication.topLevelWidgets():
                if isinstance(widget, LoginWindow):
                    widget.showNormal()
                    widget.activateWindow()
                    widget.raise_()
                    return
            logger.warning("托盘请求显示但未找到登录窗口")
            return
        self.showNormal()
        self.activateWindow()
        # 从托盘恢复后状态栏可能停留在隐藏前的陈旧文本，重启定时器刷新。
        self._list_refresh.start_status_timer()

    def _setup_ui(self) -> None:
        self.setWindowTitle("CipherBox")
        self.setMinimumSize(*WINDOW_MIN_SIZE)
        self.resize(*WINDOW_DEFAULT_SIZE)

        theme = self._config.get(CFG_THEME, DEFAULT_THEME)
        # 显式激活主题，使运行时 c() 解析的颜色与样式表一致（ARCH-008）。
        # 样式表统一经 app 级应用（app.py 启动时 setStyleSheet），不在窗口级重复设置——
        # 否则 _apply_theme 仅更 app 级时，主窗口子树会停留旧主题 QSS（widget 自身样式表
        # 优先于 app 级），与运行时图标新主题割裂。
        set_theme(theme)
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
        self._detail_panel = DetailPanel(
            self._clipboard, entry_manager=self._entry_mgr, config=self._config
        )
        self._splitter.addWidget(self._detail_panel)

        # 分割比例：优先恢复用户上次保存值，缺失或非法（非 3 段）则回退默认
        saved_sizes = self._config.get(CFG_SPLITTER_SIZES)
        if saved_sizes and len(saved_sizes) == 3:
            self._splitter.setSizes(saved_sizes)
        else:
            self._splitter.setSizes(SPLITTER_SIZES)

        main_layout.addWidget(self._splitter)

        # 恢复窗口位置
        saved_geo = self._config.get(CFG_WINDOW_GEOMETRY)
        if saved_geo:
            try:
                geo_bytes = bytes.fromhex(saved_geo)
                # 与 config._is_valid 共用 MAX_WINDOW_GEOMETRY_BYTES，消除两端硬编码分歧。
                if len(geo_bytes) <= MAX_WINDOW_GEOMETRY_BYTES:
                    self.restoreGeometry(geo_bytes)
            except (ValueError, RuntimeError):
                logger.debug("窗口几何位置恢复失败，已忽略", exc_info=True)

        # 状态栏
        self._status_bar = QStatusBar()
        self._warning_label = QLabel()
        self._warning_label.setObjectName("warningText")
        self.setStatusBar(self._status_bar)

    def _build_sidebar(self) -> None:
        """构建侧边栏容器并按区段装配（品牌/筛选/分类/排序统计）。"""
        self._sidebar = QWidget()
        self._sidebar.setObjectName("sidebar")
        self._sidebar.setFixedWidth(SIDEBAR_WIDTH)
        sidebar_layout = QVBoxLayout(self._sidebar)
        sidebar_layout.setContentsMargins(12, 14, 12, 12)
        sidebar_layout.setSpacing(6)

        self._build_sidebar_brand(sidebar_layout)
        self._build_sidebar_filters(sidebar_layout)
        self._build_sidebar_categories(sidebar_layout)
        self._build_sidebar_sort_stats(sidebar_layout)

        self._splitter.addWidget(self._sidebar)

    def _build_sidebar_brand(self, sidebar_layout: QVBoxLayout) -> None:
        """品牌区：图标 + 标题/副标题。"""
        brand_row = QHBoxLayout()
        self._brand_icon = QLabel()
        self._brand_icon.setPixmap(icon_pixmap(SHIELD, "accent", 24))
        self._brand_icon.setFixedSize(*SIDEBAR_ICON_SIZE)
        brand_row.addWidget(self._brand_icon)
        brand_text = QVBoxLayout()
        brand_text.setSpacing(0)
        self._brand_title = QLabel("CipherBox")
        self._brand_title.setObjectName("sidebarBrandTitle")
        self._brand_subtitle = QLabel("本地加密保险库")
        self._brand_subtitle.setObjectName("sidebarBrandSubtitle")
        brand_text.addWidget(self._brand_title)
        brand_text.addWidget(self._brand_subtitle)
        brand_row.addLayout(brand_text, 1)
        sidebar_layout.addLayout(brand_row)
        sidebar_layout.addSpacing(8)

    def _build_sidebar_filters(self, sidebar_layout: QVBoxLayout) -> None:
        """筛选区：搜索框 + 标签下拉 + 筛选项列表 + 分割线。"""
        self._search_edit = QLineEdit()
        self._search_edit.setPlaceholderText("搜索标题、账号或标签")
        self._search_edit.setClearButtonEnabled(True)
        # 存引用供主题切换刷新：addAction 返回的 QAction 图标颜色烘焙到 QIcon，
        # setStyleSheet 全局刷新不重建已烘焙图标，须在 _apply_theme 显式 setIcon。
        # addAction stub 标注 QAction | None，构造期正常返回 QAction，None 分支由主题
        # 刷新处的 is not None 守卫兜底。
        self._search_action: QAction | None = self._search_edit.addAction(
            icon(SEARCH), QLineEdit.ActionPosition.LeadingPosition
        )
        sidebar_layout.addWidget(self._search_edit)

        self._tag_combo = QComboBox()
        self._tag_combo.setToolTip("按标签筛选条目")
        sidebar_layout.addWidget(self._tag_combo)

        self._filter_label = QLabel("筛选")
        self._filter_label.setObjectName("sidebarSectionLabel")
        sidebar_layout.addWidget(self._filter_label)

        self._filter_list = QListWidget()
        self._filter_list.setMaximumHeight(FILTER_MAX_HEIGHT)
        self._build_filter_list()
        sidebar_layout.addWidget(self._filter_list)

        self._separator1 = QLabel()
        self._separator1.setFixedHeight(1)
        self._separator1.setObjectName("sidebarSeparator")
        sidebar_layout.addWidget(self._separator1)

    def _build_sidebar_categories(self, sidebar_layout: QVBoxLayout) -> None:
        """分类区：分类标题（含管理按钮）+ 分类列表 + 分割线。"""
        cat_header = QHBoxLayout()
        self._cat_label = QLabel("分类")
        self._cat_label.setObjectName("sidebarSectionLabel")
        cat_header.addWidget(self._cat_label)
        cat_header.addStretch()
        self._add_category_btn = QPushButton("+")
        self._add_category_btn.setObjectName("iconBtn")
        self._add_category_btn.setFixedSize(*SIDEBAR_ICON_SIZE_SMALL)
        self._add_category_btn.setToolTip("管理分类")
        cat_header.addWidget(self._add_category_btn)
        sidebar_layout.addLayout(cat_header)

        self._category_list = QListWidget()
        sidebar_layout.addWidget(self._category_list)

        self._separator2 = QLabel()
        self._separator2.setFixedHeight(1)
        self._separator2.setObjectName("sidebarSeparator")
        sidebar_layout.addWidget(self._separator2)

    def _build_sidebar_sort_stats(self, sidebar_layout: QVBoxLayout) -> None:
        """排序与统计区：弹簧 + 排序下拉（恢复持久索引）+ 统计标签。"""
        sidebar_layout.addStretch()

        self._sort_label = QLabel("排序")
        self._sort_label.setObjectName("sidebarSectionLabel")
        sidebar_layout.addWidget(self._sort_label)

        self._sort_combo = QComboBox()
        for label, _, _ in SORT_OPTIONS:
            self._sort_combo.addItem(label)
        sort_field = self._config.get(CFG_SORT_FIELD, "updated_at")
        sort_order = self._config.get(CFG_SORT_ORDER, "desc")
        sort_idx = next(
            (i for i, (_, f, o) in enumerate(SORT_OPTIONS) if f == sort_field and o == sort_order),
            0,
        )
        self._sort_combo.setCurrentIndex(sort_idx)
        sidebar_layout.addWidget(self._sort_combo)

        self._stats_label = QLabel("")
        self._stats_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._stats_label.setObjectName("sidebarStatsLabel")
        sidebar_layout.addWidget(self._stats_label)

    def _build_filter_list(self) -> None:
        """重建侧边栏筛选项列表，主题切换时需要重建图标。"""
        current_row = self._filter_list.currentRow()
        self._filter_list.blockSignals(True)
        self._filter_list.clear()
        filters = [
            ("全部", "all", FILTER_ALL),
            ("收藏", "favorite", FILTER_FAVORITE),
            ("弱密码", "weak", FILTER_WEAK),
            ("重复密码", "duplicate", FILTER_DUPLICATE),
            ("近期更新", "recent", FILTER_RECENT),
            ("回收站", "trash", FILTER_TRASH),
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
        """构建中间条目列表区：标题/计数栏、Model/View 列表（含空态切换）与新增按钮。"""
        list_container = QWidget()
        list_container.setObjectName("listPane")
        list_layout = QVBoxLayout(list_container)
        list_layout.setContentsMargins(0, 0, 0, 0)
        list_layout.setSpacing(0)

        # 列表标题栏
        list_header = QHBoxLayout()
        list_header.setContentsMargins(12, 8, 12, 4)

        self._list_title = QLabel("全部条目")
        self._list_title.setObjectName("sidebarListTitle")
        list_header.addWidget(self._list_title)

        list_header.addStretch()

        self._count_label = QLabel("0 项")
        self._count_label.setObjectName("sidebarCountLabel")
        list_header.addWidget(self._count_label)

        list_layout.addLayout(list_header)

        # 条目列表，使用 QStackedWidget 切换列表和空状态
        self._list_stack = QStackedWidget()

        # Model/View：set_entries 一次替换数据，delegate 按需绘制，消除逐项 item 创建。
        self._entry_list = QListView()
        self._entry_list.setObjectName("entryList")
        self._entry_model = EntryListModel(self._entry_list)
        self._entry_list.setModel(self._entry_model)
        self._entry_delegate = EntryItemDelegate(self._entry_list)
        self._entry_list.setItemDelegate(self._entry_delegate)
        self._entry_list.setUniformItemSizes(True)
        self._entry_list.setAlternatingRowColors(True)
        self._list_stack.addWidget(self._entry_list)

        list_layout.addWidget(self._list_stack, 1)

        # 添加按钮
        add_bar = QHBoxLayout()
        add_bar.setContentsMargins(8, 4, 8, 8)
        self._add_entry_btn = QPushButton()
        self._add_entry_btn.setObjectName("primaryBtn")
        set_icon_with_text(self._add_entry_btn, "新增条目", PLUS, "text_on_accent")
        add_bar.addWidget(self._add_entry_btn)
        list_layout.addLayout(add_bar)

        self._splitter.addWidget(list_container)

    def _setup_tray(self) -> None:
        """创建托盘图标并连接其菜单信号；旧实例先清理避免占用任务栏槽位。

        ``disconnect_all`` 断开旧 ``lock_requested`` 连接，防止禁用→重启用托盘时
        ``_on_lock_tray`` 重复连接导致锁定事件多次触发。
        """
        if not self._config.get(CFG_SHOW_TRAY_ICON, True):
            return
        # 旧实例先 hide + deleteLater（Qt 事件循环安全回收）。
        if self._tray is not None:
            self._tray.hide()
            self._tray.deleteLater()
            self._tray = None
        disconnect_all([(self.lock_requested, self._on_lock_tray)])
        self._tray = TrayIcon(self)
        self._tray.show_window.connect(self._show_from_tray)
        self._tray.lock_vault.connect(self.lock_requested.emit)
        self._tray.quit_app.connect(self._quit_app)
        self._tray.show()
        self.lock_requested.connect(self._on_lock_tray)

    def _setup_auto_lock(self) -> None:
        self._auto_lock.setup(self)

    def showEvent(self, event: QShowEvent | None) -> None:  # pyright: ignore[reportIncompatibleMethodOverride]
        super().showEvent(event)
        # WTS 注册须在窗口 show 后（HWND 有效）；__init__ 时未 show 会触发 C 层
        # access violation。注册由 AutoLockController 负责（内部幂等）。
        self._auto_lock.setup_session_notification(self)

    def _setup_auto_backup(self) -> None:
        # 仅创建定时器；vault 未解锁前不启动，由 refresh_after_unlock 在解锁后启动。
        self._auto_backup.setup(self)

    def eventFilter(self, watched: QObject | None, event: QEvent | None) -> bool:  # pyright: ignore[reportIncompatibleMethodOverride]
        """捕获用户活动重置自动锁定计时器。

        排除修饰键；仅按键/鼠标点击/滚轮/触摸开始重置。不含 MouseMove——鼠标
        静止悬停时系统仍持续产生移动事件，纳入它会使超时锁定被无限推迟。
        """
        if event is not None and event.type() == QEvent.Type.KeyPress:
            key_event = cast(QKeyEvent, event)
            if key_event.key() not in (
                Qt.Key.Key_Shift,
                Qt.Key.Key_Control,
                Qt.Key.Key_Alt,
                Qt.Key.Key_Meta,
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
        self._clipboard.clear_seconds = self._config.get_safe(
            CFG_CLIPBOARD_CLEAR_SECONDS, CLIPBOARD_CLEAR_SECONDS_DEFAULT
        )
        self._auto_lock.reset_timer()
        self._auto_backup.trigger_check()
        should_show = self._config.get(CFG_SHOW_TRAY_ICON, True)
        if should_show and self._tray is None:
            self._setup_tray()
        elif not should_show and self._tray is not None:
            self._tray.hide()
            self._tray.deleteLater()
            self._tray = None

    def _shutdown_workers(self) -> None:
        """取消并等待所有后台 worker 结束，避免 QThread running 析构崩溃。

        锁定、退出、隐藏到托盘前调用，确保这些路径不再持有密钥或对已锁定 vault
        发信号、继续解密条目。
        """
        self._list_refresh.shutdown()
        self._auto_backup.shutdown()

    def _persist_window_state(self) -> None:
        """持久化窗口几何/分割比例/排序偏好到 config。

        ``closeEvent`` 与 ``_quit_app``（托盘退出经 ``QApplication.quit`` 不触发
        ``closeEvent``）共用，避免经托盘退出丢失窗口配置——原 ``_quit_app`` 漏存，
        每次托盘退出后窗口大小/侧栏比例/排序偏好回退默认值。
        """
        try:
            geo = self.saveGeometry()
            self._config.set(CFG_WINDOW_GEOMETRY, geo.data().hex())
            sizes = self._splitter.sizes()
            self._config.set(CFG_SPLITTER_SIZES, list(sizes))
            field, order = self._list_refresh.get_sort_config()
            self._config.set(CFG_SORT_FIELD, field)
            self._config.set(CFG_SORT_ORDER, order)
            self._config.save()
        except (OSError, ValueError, TypeError):
            logger.debug("保存窗口状态失败", exc_info=True)

    def _perform_exit_cleanup(self) -> None:
        """完全退出的共用清理序列（_quit_app 与 closeEvent 退出分支共用）。

        收敛两处曾各自维护的重复步骤，避免漂移：移除事件过滤器、解除会话锁屏
        过滤器引用、等待后台 worker、reject 模态对话框、清剪贴板明文、关闭 vault、
        隐藏托盘。窗口状态持久化与退出动作（QApplication.quit / event.accept）
        由各调用方自行处理——_persist_window_state 须在调用本方法前完成。
        """
        # 移除事件过滤器，防止已销毁对象仍被 QApplication 引用。
        app = QApplication.instance()
        if app:
            app.removeEventFilter(self)
        # 解除 QApplication 对会话锁屏过滤器闭包（绑定 lock_requested）的引用。
        self._auto_lock.remove_session_filter()
        # 等待后台 worker 退出，清剪贴板明文，再关闭 vault。
        self._shutdown_workers()
        # reject 模态对话框：托盘菜单是原生菜单不受 application-modal 阻拦，故可达；
        # 须在 vault.close 前 reject 使其 worker 退出，否则 vault 关闭撕裂共享
        # sqlite 事务 + QThread running 析构崩溃（ARCH-009）。
        for widget in list(QApplication.topLevelWidgets()):
            if widget is self or not isinstance(widget, QDialog):
                continue
            widget.reject()
        self._clipboard.clear_now()
        self._vault.close()
        if self._tray:
            self._tray.hide()

    def _quit_app(self) -> None:
        # 持久化窗口状态：QApplication.quit() 不触发 closeEvent，须显式保存。
        self._persist_window_state()
        self._perform_exit_cleanup()
        QApplication.quit()

    # ========== 主题刷新 ==========

    def _apply_theme(self) -> None:
        """应用当前主题，用于设置切换后刷新。"""
        theme = self._config.get(CFG_THEME, DEFAULT_THEME)
        if theme != self._current_theme:
            self._current_theme = theme
            # 显式激活主题，使运行时 c() 解析的颜色与样式表一致（ARCH-008）
            set_theme(theme)
            style = get_style(theme)
            app = QApplication.instance()
            if isinstance(app, QApplication):
                app.setStyleSheet(style)  # pyright: ignore[reportAttributeAccessIssue]
            # 颜色烘焙到 QIcon，需重建筛选/分类列表与菜单图标
            self._build_filter_list()
            self._menu.update_menu_icons()
            self._brand_icon.setPixmap(icon_pixmap(SHIELD, "accent", 24))
            # _add_entry_btn 与搜索框 leading action 的图标颜色烘焙到 QIcon，
            # setStyleSheet 全局刷新不重建已烘焙图标，须显式重设。
            set_icon_with_text(self._add_entry_btn, "新增条目", PLUS, "text_on_accent")
            if self._search_action is not None:
                self._search_action.setIcon(icon(SEARCH))
            if self._tray:
                self._tray.set_locked(False)
            # 数据未变，强制重绘列表控件即可
            self._entry_delegate.clear_color_cache()
            self._entry_list.update()
            # FOLDER 图标与空态 EmptyStateWidget 颜色烘焙到 QIcon/对象，update()
            # 不刷新，需重建。统一委托 list_refresh。
            self._list_refresh.rebuild_for_theme()
            # 仅在有内容时 force 刷新详情面板，避免恢复用户已取消选择的条目
            current_entry = self._detail_panel.current_entry
            if current_entry:
                self._detail_panel.show_entry(current_entry, force=True)
            else:
                self._detail_panel.show_empty()
            # 刷新活跃 Toast 的烘焙配色
            ToastManager.refresh_for(self)

    # ========== 窗口事件 ==========

    def _stop_ui_timers(self) -> None:
        """停止所有 UI 去抖定时器（搜索/选择/条目变更/状态栏）。

        收敛状态转换路径的定时器停止为单一调用，避免新增时遗漏——``_status_timer``
        曾在 ``_secure_hide_to_tray`` 漏停，致托盘态 pending 触发仍启动全量解密 worker。
        """
        self._list_refresh.stop_timers()
        self._entry_actions.stop_timers()

    def _secure_hide_to_tray(self) -> None:
        """隐藏到托盘前的安全清理：清详情面板明文、剪贴板，停 worker 与定时器。

        close_to_tray 与 minimize_to_tray 共用：保持 vault 解锁与列表模型，但清除
        瞬时明文并停止后台解密 worker；_lock_timer 仍运行，托盘态空闲超时自动锁定。
        """
        self._detail_panel.show_empty()
        self._clipboard.clear_now()
        self._stop_ui_timers()
        self._entry_actions.cancel_pending_selection()
        ToastManager.cancel_all_for(self)
        self._shutdown_workers()

    def closeEvent(self, a0: QCloseEvent | None) -> None:
        """关闭前持久化窗口状态；按 ``close_to_tray`` 设置分流隐藏到托盘或完全退出。"""
        if a0 is None:
            return
        self._persist_window_state()

        if self._config.get(CFG_CLOSE_TO_TRAY, False) and self._tray:
            # 隐藏到托盘（非退出、非锁定）：安全清理后隐藏。保持 vault 解锁、列表模型
            # 与定时器；_lock_timer 仍运行，托盘态空闲超时自动锁定。恢复后详情面板
            # 已清空，由用户重新选择条目。
            self._secure_hide_to_tray()
            a0.ignore()
            self.hide()
        else:
            # 完全退出：共用清理序列（与 _quit_app 对齐），event.accept 退出。
            self._perform_exit_cleanup()
            a0.accept()

    def changeEvent(self, a0: QEvent | None) -> None:
        """最小化时按 ``minimize_to_tray`` 设置执行与关闭一致的安全清理后隐藏到托盘。"""
        if a0 is None:
            return
        if a0.type() == a0.Type.WindowStateChange:
            if self.windowState() & Qt.WindowState.WindowMinimized:
                if self._config.get(CFG_MINIMIZE_TO_TRAY, True) and self._tray:
                    # 最小化同样视为「离开交互」，执行与 close_to_tray 一致的安全清理，
                    # 避免最小化比关闭更不安全。hide 延迟到下一事件循环避免 changeEvent
                    # 内直接 hide 的 Qt 重入问题。
                    self._secure_hide_to_tray()
                    QTimer.singleShot(0, self.hide)
        super().changeEvent(a0)

    def refresh_after_unlock(self) -> None:
        """解锁后刷新界面。"""
        self._locked_ui = False
        self._entry_actions.set_locked(False)
        self._list_refresh.set_locked(False)
        if self._first_unlock:
            # 首次解锁紧跟构造：setup 已加载，跳过重复全量加载避免双重解密 worker。
            self._first_unlock = False
        else:
            self._list_refresh.refresh_after_unlock()
        self._detail_panel.show_empty()
        self._auto_lock.reset_timer()
        # 解锁后刷新状态栏安全摘要，避免停留在锁定前的陈旧或空白状态
        self._list_refresh.start_status_timer()
        # prepare_for_lock 已停止自动备份定时器，解锁后须恢复，否则锁定→解锁后失效。
        self._auto_backup.start_timer()
        self._auto_backup.schedule_initial_check()
        if self._tray:
            self._tray.set_locked(False)

    def emergency_clear_clipboard(self) -> None:
        """紧急清空剪贴板，供 app 层崩溃/退出兜底经公共 API 调用。

        公共 API 而非直接 getattr 私有属性——重命名时 getattr 返回 None 会无声错过清理，
        崩溃兜底恰是最不应静默失效的安全路径。
        """
        clipboard = getattr(self, "_clipboard", None)
        if clipboard is not None:
            try:
                clipboard.clear_now()
            except Exception:
                # 崩溃兜底清空的是可能残留的明文，用 error 级确保生产 INFO 可见。
                logger.error("崩溃兜底紧急清空剪贴板失败，明文可能残留", exc_info=True)

    def emergency_cancel_workers(self, *, wait_timeout_ms: float = 0.0) -> None:
        """紧急取消后台 worker，供 app 层 aboutToQuit 等不阻塞退出路径。

        与 ``_shutdown_workers`` 区别：默认仅取消不等待（避免阻塞退出）；``wait_timeout_ms
        > 0`` 时取消后等待该超时（aboutToQuit 用短超时让持密钥 worker 退出后再 lock 清零，
        收缩「已锁定」后明文残留窗口，超时放弃不阻塞）。
        """
        self._auto_backup.cancel()
        self._list_refresh.cancel_all_workers()
        if wait_timeout_ms > 0:
            self._list_refresh.wait_workers(int(wait_timeout_ms))

    def prepare_for_lock(self) -> None:
        """在清除主密钥前销毁界面和剪贴板中的明文副本。

        清理顺序：先立即收敛主窗口自身的明文/密钥/可见性（列表模型、详情面板、
        剪贴板、定时器、缓存、worker），**再**关闭对话框——后者经
        ``wait_worker_shutdown`` 可能阻塞等待后台写入（恢复/导入 worker 不可中断）。
        先清主窗口可把暴露面收敛到对话框自身的敏感控件（由其 reject 路径清零）。
        """
        self._locked_ui = True
        self._entry_actions.prepare_for_lock()
        self._auto_lock.stop_timer()
        # 清除活跃 Toast 回调，防止锁定后撤销操作触发异常。
        ToastManager.cancel_all_for(self)
        # —— 先立即清空主窗口敏感 UI 与状态（均不阻塞）——
        # list_refresh.prepare_for_lock 收敛搜索清空、安全缓存失效与 username 缓存清理
        self._list_refresh.prepare_for_lock()
        self._stop_ui_timers()
        self._entry_model.set_entries([])
        self._detail_panel.secure_clear()
        self._clipboard.clear_now()
        self._auto_backup.stop_timer()
        # 取消并等待后台 worker，避免锁定后对已锁定 vault 发信号或继续解密
        self._shutdown_workers()
        # —— 最后关闭对话框：reject 经 wait_worker_shutdown 可能阻塞等待后台 worker ——
        if QApplication.instance():
            for widget in list(QApplication.topLevelWidgets()):
                if widget is self or not isinstance(widget, QDialog):
                    continue
                widget.reject()
        self._count_label.setText("0 项")
        self._status_bar.clearMessage()
        # 托盘锁定状态由 lock_requested 信号驱动，此处不显式调用避免重复触发

    def _on_lock_tray(self) -> None:
        """锁定时更新托盘图标状态。"""
        if self._tray:
            self._tray.set_locked(True)
