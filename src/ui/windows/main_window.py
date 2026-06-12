"""CipherBox 主窗口。

编排侧边栏、条目列表与详情面板，集成快捷键、排序、Toast 通知、分类管理、
标签筛选、撤销删除、主题刷新、自动锁定与备份、安全仪表盘等功能。通过
_MainWindowFiltersMixin 与 _MainWindowMenuMixin 多重继承拆分方法实现职责分离。
"""

import logging

from PyQt6.QtCore import QEvent, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QCloseEvent
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QStatusBar,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ...business.managers.backup_restore import BackupRestoreManager
from ...business.managers.entry_manager import EntryManager
from ...business.managers.import_export import ImportExportManager
from ...business.managers.vault_manager import VaultManager
from ...business.services.security_analyzer import SecurityAnalyzer
from ...config import ConfigManager
from ...utils.clipboard import ClipboardManager
from ..components.detail_panel import DetailPanel
from ..components.entry_list_widget import EntryItemDelegate
from ..components.tray_icon import TrayIcon
from ..components.workers import BackgroundWorker
from ..controllers.entry_list_controller import EntryListController
from ..controllers.sidebar_controller import SidebarController
from ..resources.constants import (
    CLIPBOARD_CLEAR_SECONDS_DEFAULT,
    FILTER_MAX_HEIGHT,
    MS_AUTO_BACKUP_CHECK,
    MS_ENTRY_CHANGE_DEBOUNCE,
    MS_ENTRY_SELECT_DEBOUNCE,
    MS_INITIAL_BACKUP_DELAY,
    MS_SEARCH_DEBOUNCE,
    MS_STATUS_BAR_DEBOUNCE,
    SIDEBAR_WIDTH,
    SORT_OPTIONS,
    SPLITTER_SIZES,
    WINDOW_DEFAULT_SIZE,
    WINDOW_MIN_SIZE,
    WORKER_WAIT_TIMEOUT_MS,
)
from ..resources.icons import (
    PLUS,
    SEARCH,
    SHIELD,
    SIZE_SIDEBAR,
    icon,
    icon_pixmap,
    set_icon_with_text,
)
from ..resources.styles import get_style
from ..resources.theme_colors import c
from .main_window_filters import _MainWindowFiltersMixin
from .main_window_menu import _MainWindowMenuMixin

logger = logging.getLogger(__name__)

# 排序选项来自共享常量，作为单一事实来源
_SORT_OPTIONS = SORT_OPTIONS

_SIDEBAR_INLINE_STYLES = [
    ('_sidebar',        'background: {sidebar_bg}'),
    ('_filter_label',   'font-weight: bold; color: {text_secondary}; font-size: 12px; margin-top: 4px'),
    ('_separator1',     'background: {divider}; margin: 6px 0px'),
    ('_cat_label',      'font-weight: bold; color: {text_secondary}; font-size: 12px; margin-top: 4px'),
    ('_separator2',     'background: {divider}; margin: 6px 0px'),
    ('_sort_label',     'font-weight: bold; color: {text_secondary}; font-size: 12px; margin-top: 4px'),
    ('_stats_label',    'color: {text_secondary}; font-size: 11px; margin-top: 4px'),
    ('_list_title',     'font-weight: bold; font-size: 14px; color: {text_primary}'),
    ('_count_label',    'color: {text_secondary}; font-size: 12px'),
    ('_brand_title',    'font-size: 15px; font-weight: 700; color: {text_primary}'),
    ('_brand_subtitle', 'font-size: 10px; color: {text_muted}'),
]


class MainWindow(_MainWindowFiltersMixin, _MainWindowMenuMixin, QMainWindow):
    """CipherBox 主窗口"""

    lock_requested = pyqtSignal()

    def __init__(self, config: ConfigManager, vault: VaultManager):
        super().__init__()
        self._config = config
        self._vault = vault
        self._create_managers()
        self._register_callbacks()
        self._current_filter = 'all'
        self._current_category_id = None
        self._current_search = ''
        self._current_tag = ''
        self._tray: TrayIcon | None = None
        self._locked_ui = False

        self._status_timer = QTimer(self)
        self._status_timer.setSingleShot(True)
        self._status_timer.setInterval(MS_STATUS_BAR_DEBOUNCE)
        self._status_timer.timeout.connect(self._update_status_bar)
        self._status_worker: BackgroundWorker | None = None
        self._backup_worker: BackgroundWorker | None = None
        self._cached_categories = []
        self._cached_tag_names = []
        self._cached_total_entries = -1

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
        self._pending_selection: QListWidgetItem | None = None

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

    def _create_managers(self):
        """组装业务层管理器与控制器。

        将依赖组装从 __init__ 提取，使构造函数聚焦于初始化顺序编排，
        管理器的创建与连线集中于此便于审计与调整。
        """
        self._entry_mgr = EntryManager(self._vault)
        self._security = SecurityAnalyzer(self._vault, entry_manager=self._entry_mgr)
        self._entry_list_ctrl = EntryListController(
            self._entry_mgr, self._security, self._config,
        )
        self._sidebar_ctrl = SidebarController(self._entry_mgr, self._config)
        self._import_export = ImportExportManager(self._entry_mgr)
        self._backup = BackupRestoreManager(self._vault)
        self._clipboard = ClipboardManager(
            self._config.get_safe('clipboard_clear_seconds', CLIPBOARD_CLEAR_SECONDS_DEFAULT)
        )

    def _register_callbacks(self):
        """注册锁定与条目变更回调，事件驱动地失效相关缓存。"""
        # 注册锁定回调，确保 lock() 时自动清除 entry 缓存
        self._vault.register_on_lock(self._entry_mgr.invalidate_caches)
        # 条目变更时自动失效安全分析缓存，通过事件驱动取代手动调用
        self._entry_mgr.register_on_change(self._security.invalidate_cache)

    def _setup_ui(self):
        self.setWindowTitle('CipherBox')
        self.setMinimumSize(*WINDOW_MIN_SIZE)
        self.resize(*WINDOW_DEFAULT_SIZE)

        theme = self._config.get('theme', 'light')
        self.setStyleSheet(get_style(theme))
        self._current_theme = theme

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
                if len(geo_bytes) <= 64:
                    self.restoreGeometry(geo_bytes)
            except (ValueError, RuntimeError):
                pass

        # 连接详情面板信号
        self._detail_panel.edit_requested.connect(self._edit_entry)
        self._detail_panel.delete_requested.connect(self._delete_entry)
        self._detail_panel.favorite_toggled.connect(self._toggle_favorite)
        self._detail_panel.copy_feedback.connect(self._on_copy_feedback)

        # 状态栏
        self._status_bar = QStatusBar()
        self._warning_label = QLabel()
        self._warning_label.setStyleSheet(f'color: {c("warning")}; font-size: 12px;')
        self.setStatusBar(self._status_bar)
        self._update_status_bar()

    def _apply_sidebar_inline_styles(self):
        """统一刷新侧边栏控件的内联样式，主题切换时调用。"""
        for attr, tmpl in _SIDEBAR_INLINE_STYLES:
            widget = getattr(self, attr, None)
            if widget is not None:
                widget.setStyleSheet(tmpl.format(
                    sidebar_bg=c('sidebar_bg'), text_secondary=c('text_secondary'),
                    divider=c('divider'), text_primary=c('text_primary'),
                    text_muted=c('text_muted'),
                ))

    def _build_sidebar(self):
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
        self._brand_subtitle = QLabel('本地加密保险库')
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
        sidebar_layout.addWidget(self._separator1)

        # 分类标签
        cat_header = QHBoxLayout()
        self._cat_label = QLabel('分类')
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
        sidebar_layout.addWidget(self._separator2)

        sidebar_layout.addStretch()

        # 排序控件
        self._sort_label = QLabel('排序')
        sidebar_layout.addWidget(self._sort_label)

        self._sort_combo = QComboBox()
        for label, _, _ in _SORT_OPTIONS:
            self._sort_combo.addItem(label)
        sort_field = self._config.get('sort_field', 'updated_at')
        sort_order = self._config.get('sort_order', 'desc')
        sort_idx = next(
            (i for i, (_, f, o) in enumerate(_SORT_OPTIONS) if f == sort_field and o == sort_order),
            0,
        )
        self._sort_combo.setCurrentIndex(sort_idx)
        self._sort_combo.currentIndexChanged.connect(self._on_sort_changed)
        sidebar_layout.addWidget(self._sort_combo)

        # 统计
        self._stats_label = QLabel('')
        self._stats_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sidebar_layout.addWidget(self._stats_label)

        self._splitter.addWidget(self._sidebar)
        self._apply_sidebar_inline_styles()

    def _build_filter_list(self):
        """重建侧边栏筛选项列表，主题切换时需要重建图标"""
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
            item.setIcon(icon(icon_name, size=SIZE_SIDEBAR))
            self._filter_list.addItem(item)
        if current_row >= 0:
            self._filter_list.setCurrentRow(current_row)
        else:
            self._filter_list.setCurrentRow(0)
        self._filter_list.blockSignals(False)

    def _build_entry_list(self):
        list_container = QWidget()
        list_container.setObjectName('listPane')
        list_layout = QVBoxLayout(list_container)
        list_layout.setContentsMargins(0, 0, 0, 0)
        list_layout.setSpacing(0)

        # 列表标题栏
        list_header = QHBoxLayout()
        list_header.setContentsMargins(12, 8, 12, 4)

        self._list_title = QLabel('全部条目')
        list_header.addWidget(self._list_title)

        list_header.addStretch()

        self._count_label = QLabel('0 项')
        list_header.addWidget(self._count_label)

        list_layout.addLayout(list_header)

        # 条目列表，使用 QStackedWidget 切换列表和空状态
        self._list_stack = QStackedWidget()

        self._entry_list = QListWidget()
        self._entry_delegate = EntryItemDelegate(self._entry_list)
        self._entry_list.setItemDelegate(self._entry_delegate)
        self._entry_list.setUniformItemSizes(True)
        self._entry_list.setAlternatingRowColors(True)
        self._entry_list.currentItemChanged.connect(self._on_entry_selected)
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

    def _setup_tray(self):
        if not self._config.get('show_tray_icon', True):
            return
        # 先断开旧连接，避免禁用→重启用托盘时 _on_lock_tray 重复连接
        try:
            self.lock_requested.disconnect(self._on_lock_tray)
        except TypeError:
            pass
        self._tray = TrayIcon(self)
        self._tray.show_window.connect(self._show_from_tray)
        self._tray.lock_vault.connect(lambda: self.lock_requested.emit())
        self._tray.quit_app.connect(self._quit_app)
        self._tray.show()
        self.lock_requested.connect(self._on_lock_tray)

    def _setup_auto_lock(self):
        self._lock_timer = QTimer(self)
        self._lock_timer.setSingleShot(True)
        self._lock_timer.timeout.connect(lambda: self.lock_requested.emit())
        self._reset_lock_timer()

    def _setup_auto_backup(self):
        self._backup_timer = QTimer(self)
        self._backup_timer.setInterval(MS_AUTO_BACKUP_CHECK)
        self._backup_timer.timeout.connect(self._maybe_auto_backup)
        self._backup_timer.start()
        QTimer.singleShot(MS_INITIAL_BACKUP_DELAY, self._maybe_auto_backup)

    def _maybe_auto_backup(self, force: bool = False):
        """按设置创建当前保险库的本地快速快照，后台执行以避免阻塞 UI。"""
        if not self._vault.is_unlocked:
            return
        self._run_backup_async(force=force)

    def _run_backup_async(self, force: bool = False):
        """异步执行自动备份。

        始终在 BackgroundWorker 中运行：maybe_auto_backup 在间隔到期时会执行
        全量解密 + PBKDF2 + 加密，同步执行会阻塞 UI 主线程数秒。
        """
        if not self._vault.is_unlocked:
            return
        # 上一个备份仍在运行则跳过，避免覆盖引用导致孤儿线程在锁定后访问已清零密钥
        if self._backup_worker is not None and self._backup_worker.isRunning():
            return

        def _task():
            return self._backup.maybe_auto_backup(self._config, force=force)

        worker = BackgroundWorker(_task, parent=self)
        worker.error.connect(lambda msg: logger.warning("自动快照失败: %s", msg))
        self._backup_worker = worker
        worker.start()

    def _reset_lock_timer(self):
        minutes = self._config.get_safe('auto_lock_minutes', 5)
        if not self._vault.is_unlocked or minutes <= 0:
            self._lock_timer.stop()
            return
        self._lock_timer.start(minutes * 60 * 1000)

    def eventFilter(self, watched, event):  # pyright: ignore[reportIncompatibleMethodOverride]
        """捕获整个应用的用户活动，重置自动锁定计时器。

        排除修饰键即 Shift/Ctrl/Alt/Meta，仅有意义的按键才重置。
        仅对按键、鼠标点击、滚轮与触摸开始重置；不包含 MouseMove，
        因为鼠标静止悬停时系统仍会持续产生移动事件，纳入它会使
        超时锁定被无限推迟，违背密码管理器的安全预期。
        此过滤器替代了 keyPressEvent/mousePressEvent 的双重功能。
        """
        if event.type() == QEvent.Type.KeyPress:
            if event.key() not in (
                Qt.Key.Key_Shift, Qt.Key.Key_Control,
                Qt.Key.Key_Alt, Qt.Key.Key_Meta,
            ):
                self._reset_lock_timer()
        elif event.type() in (
            QEvent.Type.MouseButtonPress,
            QEvent.Type.Wheel,
            QEvent.Type.TouchBegin,
        ):
            self._reset_lock_timer()
        return super().eventFilter(watched, event)

    def _apply_runtime_settings(self):
        """立即应用无需重启的安全和托盘设置。"""
        self._clipboard.clear_seconds = self._config.get_safe('clipboard_clear_seconds', CLIPBOARD_CLEAR_SECONDS_DEFAULT)
        self._reset_lock_timer()
        self._maybe_auto_backup()
        should_show = self._config.get('show_tray_icon', True)
        if should_show and self._tray is None:
            self._setup_tray()
        elif not should_show and self._tray is not None:
            self._tray.hide()
            self._tray.deleteLater()
            self._tray = None

    def _quit_app(self):
        self._vault.close()
        if self._tray:
            self._tray.hide()
        QApplication.quit()

    # ========== 主题刷新 ==========

    def _apply_theme(self):
        """应用当前主题，用于设置切换后刷新"""
        theme = self._config.get('theme', 'light')
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
            # 刷新侧边栏内联样式，颜色值已烘焙因此需要重设
            self._apply_sidebar_inline_styles()
            self._warning_label.setStyleSheet(f'color: {c("warning")}; font-size: 12px;')
            self._brand_icon.setPixmap(icon_pixmap(SHIELD, 'accent', 24))
            self._detail_panel.refresh_theme()
            if self._tray:
                self._tray.set_locked(False)
            # 主题切换时数据未变，只需强制重绘列表控件
            self._entry_delegate.clear_color_cache()
            self._entry_list.update()
            self._category_list.update()
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

    # ========== 窗口事件 ==========

    def closeEvent(self, a0: QCloseEvent | None):
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

        # 移除事件过滤器，防止已销毁对象仍被 QApplication 引用。
        app = QApplication.instance()
        if app:
            app.removeEventFilter(self)

        if self._config.get('close_to_tray', False) and self._tray:
            self._clipboard.clear_now()
            a0.ignore()
            self.hide()
        else:
            # 退出前取消后台 worker，先 cancel 两者再分别 wait 以并行等待
            if self._status_worker and self._status_worker.isRunning():
                self._status_worker.cancel()
            if self._backup_worker and self._backup_worker.isRunning():
                self._backup_worker.cancel()
            if self._status_worker and self._status_worker.isRunning():
                self._status_worker.wait(WORKER_WAIT_TIMEOUT_MS)
            if self._backup_worker and self._backup_worker.isRunning():
                self._backup_worker.wait(WORKER_WAIT_TIMEOUT_MS)
            # 完全退出时清除剪贴板中的明文密码，防止应用关闭后残留
            self._clipboard.clear_now()
            self._vault.close()
            if self._tray:
                self._tray.hide()
            a0.accept()

    def changeEvent(self, a0: QEvent | None):
        if a0 is None:
            return
        if a0.type() == a0.Type.WindowStateChange:
            if self.windowState() & Qt.WindowState.WindowMinimized:
                if self._config.get('minimize_to_tray', True) and self._tray:
                    QTimer.singleShot(0, self.hide)
        super().changeEvent(a0)

    def refresh_after_unlock(self):
        """解锁后刷新界面"""
        self._locked_ui = False
        self._refresh_categories()
        self._refresh_tag_filter()
        self._refresh_entries()
        self._detail_panel.show_empty()
        self._reset_lock_timer()
        # 解锁后刷新状态栏安全摘要，避免停留在锁定前的陈旧或空白状态
        self._status_timer.start()
        if self._tray:
            self._tray.set_locked(False)

    def prepare_for_lock(self):
        """在清除主密钥前销毁界面和剪贴板中的明文副本。"""
        self._locked_ui = True
        self._lock_timer.stop()
        # 清除活跃 Toast 的回调，防止锁定后撤销操作触发异常。
        from ..components.toast import ToastManager
        ToastManager.cancel_all_for(self)
        # 关闭所有打开的对话框，清除其中的输入内容
        if QApplication.instance():
            for widget in list(QApplication.topLevelWidgets()):
                if widget is self or not isinstance(widget, QDialog):
                    continue
                for line_edit in widget.findChildren(QLineEdit):
                    line_edit.clear()
                for text_edit in widget.findChildren(QTextEdit):
                    text_edit.clear()
                widget.reject()
        # 重置搜索状态
        self._current_search = ''
        self._search_edit.blockSignals(True)
        self._search_edit.clear()
        self._search_edit.blockSignals(False)
        self._search_timer.stop()
        self._select_timer.stop()
        self._pending_selection = None
        # 清空条目列表，移除对 Entry 对象的引用
        self._entry_list.clear()
        # 安全清除详情面板中的敏感数据和信号连接
        self._detail_panel.secure_clear()
        # 清除剪贴板中的明文
        self._clipboard.clear_now()
        # 停止后台定时器
        self._backup_timer.stop()
        self._status_timer.stop()
        # 取消后台状态分析 worker，避免锁定后仍运行或对已锁定 vault 发信号
        if self._status_worker and self._status_worker.isRunning():
            self._status_worker.cancel()
            self._status_worker.wait(WORKER_WAIT_TIMEOUT_MS)
        self._status_worker = None
        # 取消异步备份 worker，防止锁定后继续解密条目
        if self._backup_worker and self._backup_worker.isRunning():
            self._backup_worker.cancel()
            self._backup_worker.wait(WORKER_WAIT_TIMEOUT_MS)
            self._backup_worker = None
        # 清除缓存
        self._invalidate_security_cache()
        # 清空 username 明文缓存。epoch 失效会在下次访问时触发，
        # 此处显式调用以立即释放，避免锁定到进程退出的残留窗口
        self._entry_mgr.invalidate_caches()
        self._count_label.setText('0 项')
        self._status_bar.clearMessage()
        self._on_lock_tray()

    def _on_lock_tray(self):
        """锁定时更新托盘图标状态"""
        if self._tray:
            self._tray.set_locked(True)
