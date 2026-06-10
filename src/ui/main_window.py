"""主窗口 - CipherBox 主界面

集成：快捷键、排序、Toast 通知、分类管理、标签筛选、撤销删除、主题刷新、安全仪表盘
"""

import logging

from PyQt6.QtCore import QEvent, QSize, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QAction, QCloseEvent, QKeySequence, QShortcut
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
    QMenu,
    QMessageBox,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QStatusBar,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ..business.backup_restore import BackupRestoreManager
from ..business.crypto_utils import matches_tag
from ..business.entry_manager import EntryManager
from ..business.import_export import ImportExportManager
from ..business.security_analyzer import SecurityAnalyzer
from ..business.vault_manager import VaultManager
from ..config import ConfigManager
from ..utils.clipboard import ClipboardManager
from .about_dialog import AboutDialog
from .backup_dialog import BackupDialog
from .category_dialog import CategoryDialog
from .change_master_dialog import ChangeMasterDialog
from .detail_panel import DetailPanel
from .empty_state_widget import EmptyStateWidget
from .entry_dialog import EntryDialog
from .entry_list_widget import EntryItemDelegate
from .import_export_dialog import ImportExportDialog
from .password_generator_dialog import PasswordGeneratorDialog
from .resources.constants import (
    CLIPBOARD_CLEAR_SECONDS_DEFAULT,
    FILTER_MAX_HEIGHT,
    MAX_TAG_AUTOCOMPLETE,
    MS_AUTO_BACKUP_CHECK,
    MS_ENTRY_CHANGE_DEBOUNCE,
    MS_ENTRY_SELECT_DEBOUNCE,
    MS_INITIAL_BACKUP_DELAY,
    MS_SEARCH_DEBOUNCE,
    MS_STATUS_BAR_DEBOUNCE,
    MS_TOAST_DEFAULT,
    MS_TOAST_LONG,
    MS_TOAST_SHORT,
    RECENT_ENTRY_LIMIT,
    SIDEBAR_WIDTH,
    SPLITTER_SIZES,
    WINDOW_DEFAULT_SIZE,
    WINDOW_MIN_SIZE,
    WORKER_WAIT_TIMEOUT_MS,
)
from .resources.icons import (
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
    FILTER_ALL,
    FILTER_DUPLICATE,
    FILTER_FAVORITE,
    FILTER_RECENT,
    FILTER_TRASH,
    FILTER_WEAK,
    FOLDER,
    GENERATE,
    HELP,
    KEY,
    LOCK_SOLID,
    PLUS,
    REFRESH,
    SEARCH,
    SETTINGS,
    SHIELD,
    SHORTCUT,
    SIZE_MENU,
    SIZE_SIDEBAR,
    STAR,
    STAR_OUTLINE,
    UPLOAD,
    icon,
    icon_pixmap,
    set_icon_with_text,
)
from .resources.styles import get_style
from .resources.theme_colors import c
from .security_dashboard import SecurityDashboard
from .settings_dialog import SettingsDialog
from .toast import Toast
from .tray_icon import TrayIcon
from .workers import BackgroundWorker

logger = logging.getLogger(__name__)

# 排序选项：(显示名称, 字段, 排序方向)
_SORT_OPTIONS = [
    ('更新时间 ↓', 'updated_at', 'desc'),
    ('更新时间 ↑', 'updated_at', 'asc'),
    ('标题 A→Z', 'title', 'asc'),
    ('标题 Z→A', 'title', 'desc'),
    ('强度 高→低', 'password_strength', 'desc'),
    ('强度 低→高', 'password_strength', 'asc'),
    ('创建时间 ↓', 'created_at', 'desc'),
    ('创建时间 ↑', 'created_at', 'asc'),
]

# 快捷键定义：(按键序列, 显示描述) — _setup_shortcuts 和 _show_shortcuts 共享此数据源。
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


class MainWindow(QMainWindow):
    """CipherBox 主窗口"""

    lock_requested = pyqtSignal()

    def __init__(self, config: ConfigManager, vault: VaultManager):
        super().__init__()
        self._config = config
        self._vault = vault
        self._entry_mgr = EntryManager(vault)
        self._security = SecurityAnalyzer(vault, entry_manager=self._entry_mgr)
        self._import_export = ImportExportManager(self._entry_mgr)
        self._backup = BackupRestoreManager(vault)
        self._clipboard = ClipboardManager(config.get_safe('clipboard_clear_seconds', CLIPBOARD_CLEAR_SECONDS_DEFAULT))
        # SEC-08：注册锁定回调，确保 lock() 时自动清除 entry 缓存
        self._vault.register_on_lock(self._entry_mgr.invalidate_caches)
        # A-06：条目变更时自动失效安全分析缓存（事件驱动，取代手动调用）
        self._entry_mgr.register_on_change(self._security.invalidate_cache)
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
        self._cached_categories = []
        self._cached_tag_names = []
        self._cached_total_entries = -1

        # 条目变更防抖定时器（合并短时间内连续的刷新请求）
        self._entry_change_timer = QTimer(self)
        self._entry_change_timer.setSingleShot(True)
        self._entry_change_timer.setInterval(MS_ENTRY_CHANGE_DEBOUNCE)
        self._entry_change_timer.timeout.connect(self._do_refresh_after_entry_change)

        # 条目选择防抖定时器（快速导航时不触发逐条解密）
        self._select_timer = QTimer(self)
        self._select_timer.setSingleShot(True)
        self._select_timer.setInterval(MS_ENTRY_SELECT_DEBOUNCE)
        self._select_timer.timeout.connect(self._do_select_entry)
        self._pending_selection = None

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
                if len(geo_bytes) <= 256:
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
        """统一刷新侧边栏控件的内联样式（主题切换时调用）。"""
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
        """重建侧边栏筛选项列表（主题切换时需要重建图标）"""
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

    def _update_menu_icons(self):
        """刷新菜单栏图标（主题切换时颜色需要更新）"""
        menubar = self.menuBar()
        if menubar is None:
            return
        icon_map = {
            '新增条目': (PLUS, None),
            '导入 / 导出': (UPLOAD, None),
            '备份与恢复': (FOLDER, None),
            '锁定保险库': (LOCK_SOLID, None),
            '退出': (CLOSE, None),
            '密码生成器': (GENERATE, None),
            '安全仪表盘': (SHIELD, None),
            '偏好设置': (SETTINGS, None),
            '修改主密码': (KEY, None),
            '快捷键': (SHORTCUT, None),
            '关于 CipherBox': (HELP, None),
        }
        for menu in menubar.findChildren(QMenu):
            for action in menu.actions():
                text = action.text()
                if text in icon_map:
                    icon_name, color_key = icon_map[text]
                    action.setIcon(icon(icon_name, color_key, size=SIZE_MENU))

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

        # 条目列表（QStackedWidget 切换列表/空状态）
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
        add_act.setIcon(icon(PLUS, size=SIZE_MENU))
        add_act.triggered.connect(self._add_entry)
        file_menu.addAction(add_act)

        file_menu.addSeparator()

        import_act = QAction('导入 / 导出', self)
        import_act.setIcon(icon(UPLOAD, size=SIZE_MENU))
        import_act.triggered.connect(self._show_import_export)
        file_menu.addAction(import_act)

        backup_act = QAction('备份与恢复', self)
        backup_act.setIcon(icon(FOLDER, size=SIZE_MENU))
        backup_act.triggered.connect(self._show_backup)
        file_menu.addAction(backup_act)

        file_menu.addSeparator()

        lock_act = QAction('锁定保险库', self)
        lock_act.setShortcut('Ctrl+L')
        lock_act.setIcon(icon(LOCK_SOLID, size=SIZE_MENU))
        lock_act.triggered.connect(lambda: self.lock_requested.emit())
        file_menu.addAction(lock_act)

        quit_act = QAction('退出', self)
        quit_act.setShortcut('Ctrl+Q')
        quit_act.setIcon(icon(CLOSE, size=SIZE_MENU))
        quit_act.triggered.connect(self.close)
        file_menu.addAction(quit_act)

        # 工具菜单
        tools_menu = menubar.addMenu('工具')
        if tools_menu is None:
            return

        gen_act = QAction('密码生成器', self)
        gen_act.setIcon(icon(GENERATE, size=SIZE_MENU))
        gen_act.triggered.connect(self._show_password_generator)
        tools_menu.addAction(gen_act)

        security_act = QAction('安全仪表盘', self)
        security_act.setIcon(icon(SHIELD, size=SIZE_MENU))
        security_act.triggered.connect(self._show_security_dashboard)
        tools_menu.addAction(security_act)

        # 设置菜单
        settings_menu = menubar.addMenu('设置')
        if settings_menu is None:
            return

        prefs_act = QAction('偏好设置', self)
        prefs_act.setIcon(icon(SETTINGS, size=SIZE_MENU))
        prefs_act.triggered.connect(self._show_settings)
        settings_menu.addAction(prefs_act)

        change_pwd_act = QAction('修改主密码', self)
        change_pwd_act.setIcon(icon(KEY, size=SIZE_MENU))
        change_pwd_act.triggered.connect(self._show_change_master)
        settings_menu.addAction(change_pwd_act)

        # 帮助菜单
        help_menu = menubar.addMenu('帮助')
        if help_menu is None:
            return

        shortcuts_act = QAction('快捷键', self)
        shortcuts_act.setIcon(icon(SHORTCUT, size=SIZE_MENU))
        shortcuts_act.triggered.connect(self._show_shortcuts)
        help_menu.addAction(shortcuts_act)

        help_menu.addSeparator()

        about_act = QAction('关于 CipherBox', self)
        about_act.setIcon(icon(HELP, size=SIZE_MENU))
        about_act.triggered.connect(self._show_about)
        help_menu.addAction(about_act)

    def _setup_shortcuts(self):
        """注册全局快捷键"""
        shortcuts = [
            ('Ctrl+F', lambda: self._search_edit.setFocus()),
            ('Ctrl+E', self._edit_selected_entry),
            ('Ctrl+G', self._show_password_generator),
            ('Ctrl+,', self._show_settings),
            ('Delete', self._delete_selected_entry),
            ('Escape', self._clear_search),
        ]
        for key, callback in shortcuts:
            shortcut = QShortcut(QKeySequence(key), self)
            shortcut.activated.connect(callback)

    def _setup_tray(self):
        if not self._config.get('show_tray_icon', True):
            return
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
        """按设置创建当前保险库的本地快速快照。"""
        if not self._vault.is_unlocked:
            return
        success, error = self._backup.maybe_auto_backup(self._config, force=force)
        if not success:
            Toast.show(self, f'自动快照失败：{error}', Toast.ERROR, duration=MS_TOAST_LONG)

    def _run_backup_async(self, force: bool = False):
        """异步执行自动备份（force=True 时在 BackgroundWorker 中运行）。"""
        if not self._vault.is_unlocked:
            return
        if not force:
            # 非 force 路径：仅检查配置，几乎无 I/O，可同步执行
            self._backup.maybe_auto_backup(self._config, force=False)
            return

        def _task():
            return self._backup.maybe_auto_backup(self._config, force=True)

        worker = BackgroundWorker(_task, parent=self)
        worker.error.connect(lambda msg: logger.warning("自动快照失败: %s", msg))
        worker.start()

    def _reset_lock_timer(self):
        minutes = self._config.get('auto_lock_minutes', 5)
        if not self._vault.is_unlocked or minutes <= 0:
            self._lock_timer.stop()
            return
        self._lock_timer.start(minutes * 60 * 1000)

    def eventFilter(self, watched, event):  # pyright: ignore[reportIncompatibleMethodOverride]
        """捕获整个应用的用户活动，重置自动锁定计时器。

        排除修饰键（Shift/Ctrl/Alt/Meta），仅有意义的按键才重置。
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

    # ========== 排序 ==========

    def _get_sort_config(self) -> tuple[str, str]:
        """获取当前排序字段和方向"""
        idx = self._sort_combo.currentIndex()
        if 0 <= idx < len(_SORT_OPTIONS):
            _, field, order = _SORT_OPTIONS[idx]
            return field, order
        return 'updated_at', 'desc'

    def _on_sort_changed(self):
        """排序选项变更"""
        field, order = self._get_sort_config()
        self._config.set('sort_field', field)
        self._config.set('sort_order', order)
        self._config.save()
        self._refresh_entries()

    def _sort_entries(self, entries: list) -> list:
        """对条目列表排序"""
        field, order = self._get_sort_config()

        def sort_key(e):
            if field == 'title':
                return (e.title or '').lower()
            elif field == 'password_strength':
                return e.password_strength
            elif field == 'created_at':
                return e.created_at or ''
            else:  # updated_at
                return e.updated_at or ''

        reverse = (order == 'desc')
        return sorted(entries, key=sort_key, reverse=reverse)

    # ========== 数据操作 ==========

    def _refresh_categories(self):
        selected_category_id = self._current_category_id
        self._category_list.blockSignals(True)
        self._category_list.clear()

        all_item = QListWidgetItem('全部分类')
        all_item.setData(Qt.ItemDataRole.UserRole, None)
        all_item.setIcon(icon(FOLDER, size=SIZE_SIDEBAR))
        self._category_list.addItem(all_item)

        categories = self._entry_mgr.get_categories()
        category_counts = self._entry_mgr.get_category_entry_counts()
        for cat in categories:
            if cat.id is None:
                continue
            count = category_counts.get(cat.id, 0)
            label = f'{cat.icon_char} {cat.name} ({count})' if count > 0 else f'{cat.icon_char} {cat.name}'
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, cat.id)
            self._category_list.addItem(item)

        target_row = 0
        if selected_category_id is not None:
            for row in range(self._category_list.count()):
                item = self._category_list.item(row)
                if item and item.data(Qt.ItemDataRole.UserRole) == selected_category_id:
                    target_row = row
                    break
            else:
                self._current_category_id = None
        self._category_list.setCurrentRow(target_row)
        self._category_list.blockSignals(False)
        self._cached_categories = categories

    def _refresh_tag_filter(self):
        current = self._current_tag
        self._tag_combo.blockSignals(True)
        self._tag_combo.clear()
        self._tag_combo.addItem('全部标签', '')
        all_tags = self._entry_mgr.get_all_tags()
        for tag, count in all_tags:
            self._tag_combo.addItem(f'{tag}  ·  {count}', tag)
        index = self._tag_combo.findData(current)
        self._tag_combo.setCurrentIndex(index if index >= 0 else 0)
        if index < 0:
            self._current_tag = ''
        self._tag_combo.blockSignals(False)
        self._cached_tag_names = [t[0] for t in all_tags[:MAX_TAG_AUTOCOMPLETE]]

    # ---------- 过滤器数据获取（各过滤器独立方法） ----------

    def _fetch_all(self) -> tuple[list, str]:
        return self._entry_mgr.get_entry_summaries(
            category_id=self._current_category_id,
            search=self._current_search,
        ), '全部条目'

    def _fetch_favorite(self) -> tuple[list, str]:
        return self._entry_mgr.get_entry_summaries(favorite_only=True, search=self._current_search), '收藏'

    def _fetch_weak(self) -> tuple[list, str]:
        summary = self._get_security_summary()
        return (summary or {}).get('weak_entries', []), '弱密码（全部分类）'

    def _fetch_duplicate(self) -> tuple[list, str]:
        summary = self._get_security_summary()
        groups = (summary or {}).get('duplicate_groups', [])
        return [e for group in groups for e in group], '重复密码（全部分类）'

    def _fetch_recent(self) -> tuple[list, str]:
        entries = self._entry_mgr.get_entry_summaries(
            search=self._current_search, limit=RECENT_ENTRY_LIMIT,
        )
        entries.sort(key=lambda e: e.updated_at or '', reverse=True)
        return entries, '近期更新'

    def _fetch_trash(self) -> tuple[list, str]:
        return self._entry_mgr.get_entry_summaries(deleted_only=True, search=self._current_search), '回收站'

    def _get_fetcher(self, filter_key: str):
        """获取过滤器对应的数据获取方法"""
        fetchers = {
            'all': self._fetch_all,
            'favorite': self._fetch_favorite,
            'weak': self._fetch_weak,
            'duplicate': self._fetch_duplicate,
            'recent': self._fetch_recent,
            'trash': self._fetch_trash,
        }
        return fetchers.get(filter_key, self._fetch_all)

    def _refresh_entries(self):
        # H6：重建列表前取消待执行的选中防抖，避免对已失效的 pending_selection
        # 操作（与 prepare_for_lock 一致）
        self._select_timer.stop()
        self._pending_selection = None
        # M-P3：记录滚动位置和当前选中行，重建后恢复（提升列表刷新体验）
        # 仅在当前过滤器未变时恢复（同一数据集的刷新），切换过滤器后数据集不同不应恢复旧位置
        saved_filter = getattr(self, '_last_refresh_filter', None)
        current_filter = self._current_filter
        should_restore_position = (saved_filter == current_filter)
        self._last_refresh_filter = current_filter
        saved_scroll = self._entry_list.verticalScrollBar().value() if should_restore_position else 0  # pyright: ignore[reportOptionalMemberAccess]
        saved_row = self._entry_list.currentRow() if should_restore_position else -1
        self._entry_list.clear()

        entries, title = self._get_fetcher(self._current_filter)()
        self._list_title.setText(title)

        if self._current_search and self._current_filter in ('weak', 'duplicate'):
            entries = [e for e in entries if self._entry_mgr.matches_search(e, self._current_search)]

        if self._current_tag:
            entries = [e for e in entries if matches_tag(e, self._current_tag)]

        # 排序（弱密码/重复/近期使用默认顺序）
        if self._current_filter in ('all', 'favorite', 'trash'):
            entries = self._sort_entries(entries)

        for entry in entries:
            item = QListWidgetItem(self._entry_list)
            item.setSizeHint(QSize(0, EntryItemDelegate.ROW_HEIGHT))
            item.setData(Qt.ItemDataRole.UserRole, entry)

        # M-P3：恢复滚动位置和选中行（仅在过滤器未变时恢复，避免切换后跳到旧位置）
        if should_restore_position and not self._current_search and 0 <= saved_row < self._entry_list.count():
            self._entry_list.setCurrentRow(saved_row)
        if should_restore_position:
            self._entry_list.verticalScrollBar().setValue(saved_scroll)  # pyright: ignore[reportOptionalMemberAccess]

        self._count_label.setText(f'{len(entries)} 项')

        if entries:
            self._list_stack.setCurrentWidget(self._entry_list)
        else:
            self._show_empty_state()

    def _show_loading_state(self, message: str = '加载中...', subtitle: str = ''):
        """显示加载状态（用于异步操作进行中）"""
        while self._list_stack.count() > 1:
            old = self._list_stack.widget(1)  # pyright: ignore[reportOptionalMemberAccess]
            self._list_stack.removeWidget(old)
            old.deleteLater()  # pyright: ignore[reportOptionalMemberAccess]
        loading = EmptyStateWidget(
            icon_name=EMPTY_GENERIC,
            title=message,
            subtitle=subtitle,
        )
        self._list_stack.addWidget(loading)
        self._list_stack.setCurrentWidget(loading)

    def _show_empty_state(self):
        """根据当前场景显示不同的空状态提示"""
        # 清除旧的空状态 widget（索引 1 及之后）
        while self._list_stack.count() > 1:
            old = self._list_stack.widget(1)
            if old is None:
                break
            self._list_stack.removeWidget(old)
            old.deleteLater()

        total_entries = getattr(self, '_cached_total_entries', -1)
        if total_entries < 0:
            total_entries = self._entry_mgr.get_entry_count()
        empty = None

        if self._current_search:
            # 搜索无结果
            empty = EmptyStateWidget(
                icon_name=EMPTY_SEARCH,
                title='没有找到匹配的条目',
                subtitle='尝试不同的搜索关键词',
                action_text='清除搜索',
            )
            empty.action_clicked.connect(self._clear_search)
        elif self._current_filter == 'trash':
            # 回收站为空
            empty = EmptyStateWidget(
                icon_name=EMPTY_TRASH,
                title='回收站是空的',
                subtitle='删除的条目会出现在这里',
            )
        elif self._current_filter == 'weak':
            # 无弱密码
            empty = EmptyStateWidget(
                icon_name=EMPTY_SUCCESS,
                title='没有发现弱密码',
                subtitle='所有密码强度良好',
            )
        elif self._current_filter == 'duplicate':
            # 无重复密码
            empty = EmptyStateWidget(
                icon_name=EMPTY_SUCCESS,
                title='没有重复密码',
                subtitle='所有密码都是唯一的',
            )
        elif self._current_filter == 'recent':
            # 无近期更新
            empty = EmptyStateWidget(
                icon_name=EMPTY_SUCCESS,
                title='没有近期更新',
                subtitle='最近没有修改过条目',
            )
        elif self._current_category_id is not None:
            # 分类为空
            empty = EmptyStateWidget(
                icon_name=EMPTY_FOLDER,
                title='该分类下暂无条目',
                subtitle='新增或编辑条目时可选择该分类',
            )
        elif total_entries == 0:
            # 新用户
            empty = EmptyStateWidget(
                icon_name=EMPTY_VAULT,
                title='还没有密码条目',
                subtitle='点击工具栏「新增」按钮开始添加',
                action_text='新增条目',
            )
            empty.action_clicked.connect(self._add_entry)
        else:
            # 其他场景：通用空状态
            empty = EmptyStateWidget(
                icon_name=EMPTY_GENERIC,
                title='暂无条目',
            )

        self._list_stack.addWidget(empty)
        self._list_stack.setCurrentWidget(empty)

    def _update_status_bar(self):
        days = self._config.get('old_password_warning_days', 90)
        # 快速路径：缓存命中时直接更新 UI
        cached = self._security.get_cached_report(days)
        if cached is not None:
            self._apply_status_summary(cached)
            return
        # 缓存未命中：显示占位文本，异步执行分析
        self._status_bar.showMessage('安全分析中...')
        if self._status_worker and self._status_worker.isRunning():
            return
        # 断开旧 worker 的信号，防止重复连接导致信号泄漏
        if self._status_worker:
            try:
                self._status_worker.finished.disconnect(self._on_status_analyzed)
                self._status_worker.error.disconnect()
            except (TypeError, RuntimeError):
                pass
        self._status_worker = BackgroundWorker(
            lambda: self._security.get_or_compute_report(days),
            parent=self,
        )
        self._status_worker.finished.connect(self._on_status_analyzed)
        self._status_worker.error.connect(lambda _: None)
        self._status_worker.start()

    def _on_status_analyzed(self, summary):
        self._apply_status_summary(summary)

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
            # 密码过期警告（复用实例属性，避免 findChild）
            if summary.get('old', 0) > 0:
                old_count = summary['old']
                self._warning_label.setText(f'  [!] {old_count} 个密码已过期  ')
                self._warning_label.show()
                if self._warning_label.parent() is not self._status_bar:
                    self._status_bar.addPermanentWidget(self._warning_label)
            else:
                self._warning_label.hide()
        except (ValueError, RuntimeError):
            logger.debug("状态栏安全分析失败", exc_info=True)
            self._status_bar.showMessage('安全分析暂时不可用')

    def _get_security_summary(self) -> dict | None:
        """返回缓存的安全分析结果，不触发同步计算。

        当缓存未就绪时返回 None，调用方应处理此情况（显示空列表）。
        首次计算由 _update_status_bar 的定时器在后台触发。
        """
        return self._security.get_cached_report(
            self._config.get('old_password_warning_days', 90)
        )

    # ========== 事件处理 ==========

    def _invalidate_security_cache(self):
        self._security.invalidate_cache()

    def _refresh_all_data(self):
        """全量刷新：分类 + 标签 + 条目 + 安全摘要。

        用于数据发生重大变更的场景（导入、备份恢复、修改主密码）。
        """
        self._invalidate_security_cache()
        self._refresh_categories()
        self._refresh_tag_filter()
        self._refresh_entries()
        self._status_timer.start()

    def _refresh_after_entry_change(self):
        """条目变更后请求刷新（防抖合并）。"""
        self._entry_change_timer.start()

    def _do_refresh_after_entry_change(self):
        """执行条目变更后的全量刷新（由防抖定时器触发）。"""
        # A-06：安全缓存失效已通过 EntryManager 回调自动完成，此处无需再调用
        self._cached_total_entries = -1
        self._refresh_categories()
        self._refresh_tag_filter()
        self._refresh_entries()
        self._status_timer.start()

    def _refresh_entries_only(self):
        """仅刷新条目列表和状态栏（不刷新分类/标签/安全摘要）。

        用于轻量操作如切换收藏，分类和标签不会改变。
        """
        self._refresh_entries()
        self._status_timer.start()

    def _on_search_input(self, _text: str):
        self._search_timer.start()

    def _on_tag_changed(self):
        self._current_tag = self._tag_combo.currentData() or ''
        self._refresh_entries()

    def _do_search(self):
        self._current_search = self._search_edit.text().strip()
        self._refresh_entries()

    def _on_filter_changed(self, current, _previous):
        if current:
            self._current_filter = current.data(Qt.ItemDataRole.UserRole)
            self._current_category_id = None
            self._category_list.blockSignals(True)
            self._category_list.setCurrentRow(-1)
            self._category_list.blockSignals(False)
            self._refresh_entries()

    def _on_category_changed(self, current, _previous):
        if current:
            self._current_category_id = current.data(Qt.ItemDataRole.UserRole)
            self._current_filter = 'all'
            self._filter_list.blockSignals(True)
            self._filter_list.setCurrentRow(0)
            self._filter_list.blockSignals(False)

            cat_name = current.text()
            self._list_title.setText(cat_name)
            self._refresh_entries()

    def _on_entry_selected(self, current, _previous):
        if current:
            self._pending_selection = current
            self._select_timer.start()

    def _do_select_entry(self):
        """防抖后的条目选择：执行解密并显示"""
        current = self._pending_selection
        # H6：取值后立即重置，避免 timer 再次触发时复用过期引用
        self._pending_selection = None
        if current:
            summary = current.data(Qt.ItemDataRole.UserRole)
            if summary:
                entry = self._entry_mgr.get_entry(summary.id)
                if entry:
                    self._detail_panel.show_entry(entry)

    # ------------------------------------------------------------------
    # 条目右键菜单
    # ------------------------------------------------------------------

    def _on_entry_context_menu(self, pos):
        """条目右键菜单 — 路由到已删除/活跃条目子菜单"""
        item = self._entry_list.itemAt(pos)
        if not item:
            return

        summary = item.data(Qt.ItemDataRole.UserRole)
        if summary.is_deleted:
            self._show_deleted_entry_menu(summary, pos)
        else:
            self._show_active_entry_menu(summary, pos)

    def _show_deleted_entry_menu(self, entry, pos):
        """回收站条目右键菜单"""
        menu = QMenu(self)
        restore_act = QAction('恢复', self)
        restore_act.setIcon(icon(REFRESH, size=SIZE_MENU))
        menu.addAction(restore_act)
        delete_act = QAction('永久删除', self)
        delete_act.setIcon(icon(CLOSE, 'danger', size=SIZE_MENU))
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
        """活跃条目右键菜单 — dict dispatch，复制操作延迟解密"""
        menu = QMenu(self)

        copy_user_act = QAction('复制账号', self)
        copy_user_act.setIcon(icon(COPY, size=SIZE_MENU))
        menu.addAction(copy_user_act)
        copy_pwd_act = QAction('复制密码', self)
        copy_pwd_act.setIcon(icon(COPY, size=SIZE_MENU))
        menu.addAction(copy_pwd_act)

        # TOTP 验证码（仅当条目配置了 TOTP 密钥时显示）
        copy_totp_act: QAction | None = None
        if summary.has_totp:
            copy_totp_act = QAction('复制验证码', self)
            copy_totp_act.setIcon(icon(COPY, size=SIZE_MENU))
            menu.addAction(copy_totp_act)

        menu.addSeparator()
        edit_act = QAction('编辑', self)
        edit_act.setIcon(icon(EDIT, size=SIZE_MENU))
        menu.addAction(edit_act)
        if summary.is_favorite:
            fav_act = QAction('取消收藏', self)
            fav_act.setIcon(icon(STAR_OUTLINE, size=SIZE_MENU))
            menu.addAction(fav_act)
        else:
            fav_act = QAction('收藏', self)
            fav_act.setIcon(icon(STAR, size=SIZE_MENU))
            menu.addAction(fav_act)
        menu.addSeparator()
        del_act = QAction('删除', self)
        del_act.setIcon(icon(DELETE, size=SIZE_MENU))
        menu.addAction(del_act)

        chosen = menu.exec(self._entry_list.mapToGlobal(pos))
        if chosen is None:
            return

        # 延迟解密：复制操作按需加载完整条目
        def _copy_user():
            e = self._entry_mgr.get_entry(summary.id)
            if e and e.username:
                self._clipboard.copy_text(e.username)
                Toast.show(self, '已复制账号', Toast.SUCCESS, duration=MS_TOAST_SHORT)

        def _copy_pwd():
            e = self._entry_mgr.get_entry(summary.id)
            if e and e.password:
                self._clipboard.copy_text(e.password)
                self._detail_panel.copy_feedback.emit()
                Toast.show(self, '已复制密码', Toast.SUCCESS, duration=MS_TOAST_SHORT)

        def _copy_totp():
            # 4A：通过 EntryManager 生成验证码，UI 层不接触明文 TOTP secret
            code = self._entry_mgr.generate_totp(summary.id)
            if code:
                self._clipboard.copy_text(code)
                Toast.show(self, '验证码已复制', Toast.SUCCESS, duration=MS_TOAST_SHORT)
            else:
                Toast.show(self, '验证码生成失败，请检查密钥', Toast.ERROR, duration=MS_TOAST_DEFAULT)

        # dict dispatch 替代 if/elif 链
        handlers: dict = {
            copy_user_act: _copy_user,
            copy_pwd_act: _copy_pwd,
            edit_act: lambda: self._edit_entry(summary.id),
            fav_act: lambda: (self._entry_mgr.toggle_favorite(summary.id),
                              self._refresh_entries_only()),
            del_act: lambda: self._delete_entry(summary.id),
        }
        if copy_totp_act:
            handlers[copy_totp_act] = _copy_totp

        handler = handlers.get(chosen)
        if handler:
            handler()

    def _on_category_context_menu(self, pos):
        """分类右键菜单"""
        item = self._category_list.itemAt(pos)
        if not item:
            return
        cat_id = item.data(Qt.ItemDataRole.UserRole)
        if cat_id is None:
            return

        menu = QMenu(self)
        edit_act = menu.addAction('编辑分类')
        if edit_act is None: return
        edit_act.setIcon(icon(EDIT, size=SIZE_MENU))
        delete_act = menu.addAction('删除分类')
        if delete_act is None: return
        delete_act.setIcon(icon(DELETE, size=SIZE_MENU))
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
        """快捷键：编辑当前选中条目"""
        current = self._entry_list.currentItem()
        if current:
            entry = current.data(Qt.ItemDataRole.UserRole)
            if entry:
                self._edit_entry(entry.id)

    def _delete_entry(self, entry_id: int):
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
                self._entry_mgr.restore_entry(entry_id)
                self._refresh_after_entry_change()
                Toast.show(self, f'已恢复「{entry_title}」', Toast.SUCCESS)

            self._refresh_after_entry_change()
            Toast.show(self, f'已移入回收站', Toast.INFO, duration=MS_TOAST_LONG,
                       action_text='撤销', action_callback=undo)

    def _delete_selected_entry(self):
        """快捷键：删除当前选中条目"""
        current = self._entry_list.currentItem()
        if current:
            entry = current.data(Qt.ItemDataRole.UserRole)
            if entry and not entry.is_deleted:
                self._delete_entry(entry.id)

    def _toggle_favorite(self, entry_id: int):
        self._entry_mgr.toggle_favorite(entry_id)
        self._refresh_entries_only()

    def _on_copy_feedback(self):
        self._status_bar.showMessage('已复制到剪贴板', MS_TOAST_DEFAULT)

    def _clear_search(self):
        """快捷键：清空搜索"""
        if self._search_edit.text():
            self._search_edit.clear()
        else:
            self._entry_list.setCurrentRow(-1)
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
        category = self._entry_mgr.get_category(category_id)
        if not category:
            return
        count = self._entry_mgr.get_category_entry_count(category_id)
        msg = f'确定要删除分类「{category.name}」吗？'
        if count > 0:
            msg += f'\n\n该分类下有 {count} 个条目，删除后将取消分类归属。'
        reply = QMessageBox.question(
            self, '删除分类', msg,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self._entry_mgr.delete_category(category_id)
            self._refresh_after_entry_change()
            Toast.show(self, f'已删除分类「{category.name}」', Toast.SUCCESS)

    # ========== 对话框 ==========

    def _show_password_generator(self):
        dialog = PasswordGeneratorDialog(self._clipboard, self, config=self._config)
        dialog.password_selected.connect(self._on_password_selected)
        dialog.exec()

    def _on_password_selected(self, password: str):
        """密码生成器独立打开时，选中密码后复制到剪贴板"""
        self._clipboard.copy_text(password)
        Toast.show(self, '密码已复制到剪贴板', Toast.SUCCESS)

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
        # 对话框内可能执行了恢复操作（覆盖数据），无论结果都完整刷新
        self._refresh_all_data()
        self._detail_panel.show_empty()

    def _show_change_master(self):
        dialog = ChangeMasterDialog(self._vault, self)
        result = dialog.exec()
        if result == ChangeMasterDialog.DialogCode.Accepted:
            self._refresh_all_data()
            self._detail_panel.show_empty()
            self._run_backup_async(force=True)

    def _show_about(self):
        dialog = AboutDialog(self)
        dialog.exec()

    def _show_security_dashboard(self):
        dialog = SecurityDashboard(self._security, self._entry_mgr, self._config, self)
        dialog.fix_requested.connect(self._edit_entry)
        result = dialog.exec()
        # 仅在用户实际执行了修复操作时刷新（Accepted 且 fix_requested 至少触发一次）
        if result == QDialog.DialogCode.Accepted:
            self._refresh_after_entry_change()

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
            return
        self.showNormal()
        self.activateWindow()

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
        """应用当前主题（用于设置切换后刷新）"""
        theme = self._config.get('theme', 'light')
        if theme != self._current_theme:
            self._current_theme = theme
            style = get_style(theme)
            app = QApplication.instance()
            if isinstance(app, QApplication):
                app.setStyleSheet(style)  # pyright: ignore[reportAttributeAccessIssue]
            # 重建侧边栏筛选图标（颜色烘焙到 QIcon，需重建）
            self._build_filter_list()
            # 刷新菜单栏图标
            self._update_menu_icons()
            # 刷新侧边栏内联样式（颜色值已烘焙，需重设）
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
            # H1：退出前取消后台状态分析 worker
            if self._status_worker and self._status_worker.isRunning():
                self._status_worker.cancel()
                self._status_worker.wait(WORKER_WAIT_TIMEOUT_MS)
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
        if self._tray:
            self._tray.set_locked(False)

    def prepare_for_lock(self):
        """在清除主密钥前销毁界面和剪贴板中的明文副本。"""
        self._locked_ui = True
        self._lock_timer.stop()
        # S1：清除活跃 Toast 的回调，防止锁定后撤销操作触发异常。
        # ToastManager 以 self 为 key 存储在弱引用字典中。
        from .toast import ToastManager
        mgr = ToastManager._instances.get(self)
        if mgr:
            mgr.cancel_all()
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
        # 清空条目列表（移除对 Entry 对象的引用）
        self._entry_list.clear()
        # 安全清除详情面板中的敏感数据和信号连接
        self._detail_panel.secure_clear()
        # 清除剪贴板中的明文
        self._clipboard.clear_now()
        # 停止后台定时器
        self._backup_timer.stop()
        self._status_timer.stop()
        # H1：取消后台状态分析 worker，避免锁定后仍运行或对已锁定 vault 发信号
        if self._status_worker and self._status_worker.isRunning():
            self._status_worker.cancel()
            self._status_worker.wait(WORKER_WAIT_TIMEOUT_MS)
        # 清除缓存
        self._invalidate_security_cache()
        # M-P1：清空 username 明文缓存（epoch 失效会在下次访问时触发，
        # 此处显式调用以立即释放，避免锁定到进程退出的残留窗口）
        self._entry_mgr.invalidate_caches()
        self._count_label.setText('0 项')
        self._status_bar.clearMessage()
        self._on_lock_tray()

    def _on_lock_tray(self):
        """锁定时更新托盘图标状态"""
        if self._tray:
            self._tray.set_locked(True)
