"""主窗口 - CipherBox 主界面

集成：快捷键、排序、Toast 通知、分类管理、标签筛选、撤销删除、主题刷新、安全仪表盘
"""

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QLineEdit, QListWidget, QListWidgetItem,
    QSplitter, QMenu, QMessageBox, QStatusBar, QStackedWidget,
    QComboBox, QApplication,
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QEvent
from PyQt6.QtGui import QAction, QShortcut, QKeySequence
from datetime import datetime, timedelta
from pathlib import Path

from ..config import ConfigManager
from ..business.vault_manager import VaultManager
from ..business.entry_manager import EntryManager
from ..business.security_analyzer import SecurityAnalyzer
from ..business.import_export import ImportExportManager
from ..business.backup_restore import BackupRestoreManager
from ..utils.clipboard import ClipboardManager

from .detail_panel import DetailPanel
from .entry_dialog import EntryDialog
from .password_generator_dialog import PasswordGeneratorDialog
from .settings_dialog import SettingsDialog
from .import_export_dialog import ImportExportDialog
from .backup_dialog import BackupDialog
from .change_master_dialog import ChangeMasterDialog
from .about_dialog import AboutDialog
from .tray_icon import TrayIcon
from .entry_list_widget import EntryItemWidget
from .empty_state_widget import EmptyStateWidget
from .toast import Toast
from .category_dialog import CategoryDialog
from .security_dashboard import SecurityDashboard
from .resources.styles import get_style
from .resources.theme_colors import c, get_strength_color
from .resources.icons import (
    icon, set_icon, set_icon_with_text, icon_pixmap,
    PLUS, EDIT, DELETE, COPY, REFRESH, CLOSE, STAR, STAR_OUTLINE,
    GENERATE, SHIELD, KEY, LOCK_SOLID, SETTINGS, HELP, SHORTCUT,
    UNDO, FOLDER, SEARCH, UPLOAD, DOWNLOAD,
    SIZE_MENU, SIZE_SIDEBAR,
    FILTER_ALL, FILTER_FAVORITE, FILTER_WEAK, FILTER_DUPLICATE,
    FILTER_RECENT, FILTER_TRASH,
    EMPTY_SEARCH, EMPTY_TRASH, EMPTY_SUCCESS, EMPTY_FOLDER, EMPTY_VAULT, EMPTY_GENERIC,
)


class MainWindow(QMainWindow):
    """CipherBox 主窗口"""

    lock_requested = pyqtSignal()

    def __init__(self, config: ConfigManager, vault: VaultManager):
        super().__init__()
        self._config = config
        self._vault = vault
        self._entry_mgr = EntryManager(vault)
        self._security = SecurityAnalyzer(vault)
        self._import_export = ImportExportManager(self._entry_mgr)
        self._backup = BackupRestoreManager(vault)
        self._clipboard = ClipboardManager(config.get('clipboard_clear_seconds', 30))
        self._current_filter = 'all'
        self._current_category_id = None
        self._current_search = ''
        self._current_tag = ''
        self._tray: TrayIcon | None = None
        self._security_cache = None
        self._security_cache_time = 0
        self._locked_ui = False

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
        self.setMinimumSize(980, 640)
        self.resize(1180, 760)

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
            self._splitter.setSizes([200, 380, 420])

        main_layout.addWidget(self._splitter)

        # 恢复窗口位置
        saved_geo = self._config.get('window_geometry')
        if saved_geo:
            try:
                self.restoreGeometry(bytes.fromhex(saved_geo))
            except Exception:
                pass

        # 连接详情面板信号
        self._detail_panel.edit_requested.connect(self._edit_entry)
        self._detail_panel.delete_requested.connect(self._delete_entry)
        self._detail_panel.favorite_toggled.connect(self._toggle_favorite)
        self._detail_panel.copy_feedback.connect(self._on_copy_feedback)

        # 状态栏
        self._status_bar = QStatusBar()
        self.setStatusBar(self._status_bar)
        self._update_status_bar()

    def _build_sidebar(self):
        self._sidebar = QWidget()
        self._sidebar.setObjectName('sidebar')
        self._sidebar.setFixedWidth(220)
        self._sidebar.setStyleSheet(f'background: {c("sidebar_bg")};')
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
        self._brand_title.setStyleSheet(f'font-size: 15px; font-weight: 700; color: {c("text_primary")};')
        self._brand_subtitle = QLabel('本地加密保险库')
        self._brand_subtitle.setStyleSheet(f'font-size: 10px; color: {c("text_muted")};')
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
        self._search_timer.setInterval(300)
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
        self._filter_label.setStyleSheet(f'font-weight: bold; color: {c("text_secondary")}; font-size: 12px; margin-top: 4px;')
        sidebar_layout.addWidget(self._filter_label)

        # 筛选项列表
        self._filter_list = QListWidget()
        self._filter_list.setMaximumHeight(240)
        self._build_filter_list()
        self._filter_list.currentItemChanged.connect(self._on_filter_changed)
        sidebar_layout.addWidget(self._filter_list)

        # 筛选区域分割线
        self._separator1 = QLabel()
        self._separator1.setFixedHeight(1)
        self._separator1.setStyleSheet(f'background: {c("divider")}; margin: 6px 0px;')
        sidebar_layout.addWidget(self._separator1)

        # 分类标签
        cat_header = QHBoxLayout()
        self._cat_label = QLabel('分类')
        self._cat_label.setStyleSheet(f'font-weight: bold; color: {c("text_secondary")}; font-size: 12px; margin-top: 4px;')
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
        self._separator2.setStyleSheet(f'background: {c("divider")}; margin: 6px 0px;')
        sidebar_layout.addWidget(self._separator2)

        sidebar_layout.addStretch()

        # 排序控件
        self._sort_label = QLabel('排序')
        self._sort_label.setStyleSheet(f'font-weight: bold; color: {c("text_secondary")}; font-size: 12px; margin-top: 4px;')
        sidebar_layout.addWidget(self._sort_label)

        self._sort_combo = QComboBox()
        self._sort_combo.addItems(['更新时间 ↓', '更新时间 ↑', '标题 A→Z', '标题 Z→A', '强度 高→低', '强度 低→高', '创建时间 ↓', '创建时间 ↑'])
        sort_field = self._config.get('sort_field', 'updated_at')
        sort_order = self._config.get('sort_order', 'desc')
        sort_idx = {
            ('updated_at', 'desc'): 0, ('updated_at', 'asc'): 1,
            ('title', 'asc'): 2, ('title', 'desc'): 3,
            ('password_strength', 'desc'): 4, ('password_strength', 'asc'): 5,
            ('created_at', 'desc'): 6, ('created_at', 'asc'): 7,
        }.get((sort_field, sort_order), 0)
        self._sort_combo.setCurrentIndex(sort_idx)
        self._sort_combo.currentIndexChanged.connect(self._on_sort_changed)
        sidebar_layout.addWidget(self._sort_combo)

        # 统计
        self._stats_label = QLabel('')
        self._stats_label.setStyleSheet(f'color: {c("text_secondary")}; font-size: 11px; margin-top: 4px;')
        self._stats_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sidebar_layout.addWidget(self._stats_label)

        self._splitter.addWidget(self._sidebar)

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
        self._list_title.setStyleSheet(f'font-weight: bold; font-size: 14px; color: {c("text_primary")};')
        list_header.addWidget(self._list_title)

        list_header.addStretch()

        self._count_label = QLabel('0 项')
        self._count_label.setStyleSheet(f'color: {c("text_secondary")}; font-size: 12px;')
        list_header.addWidget(self._count_label)

        list_layout.addLayout(list_header)

        # 条目列表（QStackedWidget 切换列表/空状态）
        self._list_stack = QStackedWidget()

        self._entry_list = QListWidget()
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

        # 文件菜单
        file_menu = menubar.addMenu('文件')

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
        minutes = self._config.get('auto_lock_minutes', 5)
        self._lock_timer = QTimer(self)
        self._lock_timer.setSingleShot(True)
        self._lock_timer.timeout.connect(lambda: self.lock_requested.emit())
        self._reset_lock_timer()

    def _setup_auto_backup(self):
        self._backup_timer = QTimer(self)
        self._backup_timer.setInterval(10 * 60 * 1000)
        self._backup_timer.timeout.connect(self._maybe_auto_backup)
        self._backup_timer.start()
        QTimer.singleShot(1500, self._maybe_auto_backup)

    def _maybe_auto_backup(self, force: bool = False):
        """按设置创建当前保险库的本地快速快照。"""
        if not self._vault.is_unlocked or not self._config.get('auto_backup_enabled', False):
            return
        interval = self._config.get('auto_backup_interval_hours', 24)
        last_text = self._config.get('last_auto_backup_at', '')
        if not force and last_text:
            try:
                elapsed = datetime.now() - datetime.fromisoformat(last_text)
                if elapsed < timedelta(hours=interval):
                    return
            except ValueError:
                pass
        backup_dir = self._config.get('backup_directory', '')
        directory = Path(backup_dir) if backup_dir else self._config.data_dir / 'backups'
        directory.mkdir(parents=True, exist_ok=True)
        filename = f'cipherbox_snapshot_{datetime.now():%Y%m%d_%H%M%S}.cbox'
        success, error = self._backup.create_backup(str(directory / filename))
        if not success:
            Toast.show(self, f'自动快照失败：{error}', Toast.ERROR, duration=5000)
            return
        self._config.set('last_auto_backup_at', datetime.now().isoformat())
        self._config.save()
        retention = self._config.get('auto_backup_retention', 10)
        snapshots = sorted(directory.glob('cipherbox_snapshot_*.cbox'), reverse=True)
        for old_file in snapshots[retention:]:
            try:
                old_file.unlink()
            except OSError:
                pass

    def _reset_lock_timer(self):
        minutes = self._config.get('auto_lock_minutes', 5)
        if not self._vault.is_unlocked or minutes <= 0:
            self._lock_timer.stop()
            return
        self._lock_timer.start(minutes * 60 * 1000)

    def eventFilter(self, watched, event):
        """捕获整个应用的用户活动，而不仅是主窗口空白区域。"""
        if event.type() in (
            QEvent.Type.KeyPress,
            QEvent.Type.MouseButtonPress,
            QEvent.Type.Wheel,
            QEvent.Type.TouchBegin,
        ):
            self._reset_lock_timer()
        return super().eventFilter(watched, event)

    def keyPressEvent(self, a0):
        self._reset_lock_timer()
        super().keyPressEvent(a0)

    def mousePressEvent(self, a0):
        self._reset_lock_timer()
        super().mousePressEvent(a0)

    # ========== 排序 ==========

    def _get_sort_config(self) -> tuple[str, str]:
        """获取当前排序字段和方向"""
        idx = self._sort_combo.currentIndex()
        configs = [
            ('updated_at', 'desc'), ('updated_at', 'asc'),
            ('title', 'asc'), ('title', 'desc'),
            ('password_strength', 'desc'), ('password_strength', 'asc'),
            ('created_at', 'desc'), ('created_at', 'asc'),
        ]
        return configs[idx] if idx < len(configs) else ('updated_at', 'desc')

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
                return e.title.lower()
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
        for cat in categories:
            count = self._vault.db.get_category_entry_count(cat.id)
            label = f'{cat.icon_char} {cat.name} ({count})' if count > 0 else f'{cat.icon_char} {cat.name}'
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, cat.id)
            self._category_list.addItem(item)

        target_row = 0
        if selected_category_id is not None:
            for row in range(self._category_list.count()):
                item = self._category_list.item(row)
                if item.data(Qt.ItemDataRole.UserRole) == selected_category_id:
                    target_row = row
                    break
            else:
                self._current_category_id = None
        self._category_list.setCurrentRow(target_row)
        self._category_list.blockSignals(False)

    def _refresh_tag_filter(self):
        current = self._current_tag
        self._tag_combo.blockSignals(True)
        self._tag_combo.clear()
        self._tag_combo.addItem('全部标签', '')
        for tag, count in self._entry_mgr.get_all_tags():
            self._tag_combo.addItem(f'{tag}  ·  {count}', tag)
        index = self._tag_combo.findData(current)
        self._tag_combo.setCurrentIndex(index if index >= 0 else 0)
        if index < 0:
            self._current_tag = ''
        self._tag_combo.blockSignals(False)

    def _refresh_entries(self):
        self._entry_list.clear()

        entries = []

        if self._current_filter == 'all':
            entries = self._entry_mgr.get_entries(
                category_id=self._current_category_id,
                search=self._current_search,
            )
            self._list_title.setText('全部条目')
        elif self._current_filter == 'favorite':
            entries = self._entry_mgr.get_entries(favorite_only=True, search=self._current_search)
            self._list_title.setText('收藏')
        elif self._current_filter == 'weak':
            entries = self._security.find_weak_passwords()
            self._list_title.setText('弱密码')
        elif self._current_filter == 'duplicate':
            groups = self._security.find_duplicate_passwords()
            entries = [e for group in groups for e in group]
            self._list_title.setText('重复密码')
        elif self._current_filter == 'recent':
            entries = self._entry_mgr.get_entries(search=self._current_search)
            entries.sort(key=lambda e: e.updated_at, reverse=True)
            entries = entries[:20]
            self._list_title.setText('近期更新')
        elif self._current_filter == 'trash':
            entries = self._entry_mgr.get_entries(deleted_only=True, search=self._current_search)
            self._list_title.setText('回收站')
        else:
            entries = self._entry_mgr.get_entries(search=self._current_search)

        if self._current_search and self._current_filter in ('weak', 'duplicate'):
            keyword = self._current_search.lower()
            entries = [
                entry for entry in entries
                if keyword in entry.title.lower()
                or keyword in entry.username.lower()
                or keyword in entry.url.lower()
                or keyword in entry.tags.lower()
            ]

        if self._current_tag:
            entries = [
                entry for entry in entries
                if self._current_tag in entry.get_tag_list()
            ]

        # 排序（弱密码/重复/近期使用默认顺序）
        if self._current_filter in ('all', 'favorite', 'trash'):
            entries = self._sort_entries(entries)

        for entry in entries:
            item = QListWidgetItem(self._entry_list)
            widget = EntryItemWidget(entry, highlight=self._current_search)
            item.setSizeHint(widget.sizeHint())
            self._entry_list.setItemWidget(item, widget)
            item.setData(Qt.ItemDataRole.UserRole, entry)

        self._count_label.setText(f'{len(entries)} 项')

        if entries:
            self._list_stack.setCurrentWidget(self._entry_list)
        else:
            self._show_empty_state()

    def _show_empty_state(self):
        """根据当前场景显示不同的空状态提示"""
        # 清除旧的空状态 widget（索引 1 及之后）
        while self._list_stack.count() > 1:
            old = self._list_stack.widget(1)
            self._list_stack.removeWidget(old)
            old.deleteLater()

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
        try:
            import time
            now = time.time()
            # 30 秒缓存
            if self._security_cache is not None and (now - self._security_cache_time) < 30:
                summary = self._security_cache
            else:
                summary = self._security.full_analysis(
                    self._config.get('old_password_warning_days', 90)
                )
                self._security_cache = summary
                self._security_cache_time = now

            total = summary['total']
            self._stats_label.setText(f'共 {total} 项')
            parts = [f'总计 {total} 条']
            if summary['weak'] > 0:
                parts.append(f'弱密码 {summary["weak"]}')
            if summary['duplicate_count'] > 0:
                parts.append(f'重复 {summary["duplicate_count"]}')
            self._status_bar.showMessage('  |  '.join(parts))
            # 密码过期警告
            if summary.get('old', 0) > 0:
                old_count = summary['old']
                warning_label = QLabel(f'  ⚠ {old_count} 个密码已过期  ')
                warning_label.setStyleSheet('color: #D4A017; font-size: 12px;')
                # 移除旧警告标签（避免重复添加）
                old_warn = self._status_bar.findChild(QLabel)
                if old_warn:
                    self._status_bar.removeWidget(old_warn)
                    old_warn.deleteLater()
                self._status_bar.addPermanentWidget(warning_label)
            else:
                # 无过期密码时清除警告标签
                old_warn = self._status_bar.findChild(QLabel)
                if old_warn:
                    self._status_bar.removeWidget(old_warn)
                    old_warn.deleteLater()
        except Exception:
            pass

    # ========== 事件处理 ==========

    def _invalidate_security_cache(self):
        self._security_cache = None
        self._security_cache_time = 0

    def _refresh_all_data(self):
        """统一刷新条目、分类计数和安全摘要。"""
        self._invalidate_security_cache()
        self._refresh_categories()
        self._refresh_tag_filter()
        self._refresh_entries()
        self._update_status_bar()

    def _on_search_input(self, text: str):
        self._search_timer.start()

    def _on_tag_changed(self):
        self._current_tag = self._tag_combo.currentData() or ''
        self._refresh_entries()

    def _do_search(self):
        self._current_search = self._search_edit.text().strip()
        self._refresh_entries()

    def _on_filter_changed(self, current, previous):
        if current:
            self._current_filter = current.data(Qt.ItemDataRole.UserRole)
            self._current_category_id = None
            self._category_list.blockSignals(True)
            self._category_list.setCurrentRow(-1)
            self._category_list.blockSignals(False)
            self._refresh_entries()

    def _on_category_changed(self, current, previous):
        if current:
            self._current_category_id = current.data(Qt.ItemDataRole.UserRole)
            self._current_filter = 'all'
            self._filter_list.blockSignals(True)
            self._filter_list.setCurrentRow(0)
            self._filter_list.blockSignals(False)

            cat_name = current.text()
            self._list_title.setText(cat_name)
            self._refresh_entries()

    def _on_entry_selected(self, current, previous):
        # 取消前一项选中态
        if previous is not None:
            prev_widget = self._entry_list.itemWidget(previous)
            if prev_widget and hasattr(prev_widget, 'set_selected'):
                prev_widget.set_selected(False)

        if current:
            # 设置当前项选中态
            cur_widget = self._entry_list.itemWidget(current)
            if cur_widget and hasattr(cur_widget, 'set_selected'):
                cur_widget.set_selected(True)

            entry = current.data(Qt.ItemDataRole.UserRole)
            if entry:
                self._detail_panel.show_entry(entry)

    def _on_entry_context_menu(self, pos):
        item = self._entry_list.itemAt(pos)
        if not item:
            return

        entry = item.data(Qt.ItemDataRole.UserRole)
        menu = QMenu(self)

        if entry.is_deleted:
            restore_act = menu.addAction('恢复')
            restore_act.setIcon(icon(REFRESH, size=SIZE_MENU))
            delete_act = menu.addAction('永久删除')
            delete_act.setIcon(icon(CLOSE, 'danger', size=SIZE_MENU))
            action = menu.exec(self._entry_list.mapToGlobal(pos))

            if action == restore_act:
                self._entry_mgr.restore_entry(entry.id)
                self._refresh_all_data()
                Toast.show(self, f'已恢复「{entry.title}」', Toast.SUCCESS)
            elif action == delete_act:
                reply = QMessageBox.warning(
                    self, '永久删除',
                    f'确定要永久删除「{entry.title}」吗？\n此操作不可撤销！',
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                )
                if reply == QMessageBox.StandardButton.Yes:
                    self._entry_mgr.permanent_delete_entry(entry.id)
                    self._refresh_all_data()
        else:
            copy_user_act = menu.addAction('复制账号')
            copy_user_act.setIcon(icon(COPY, size=SIZE_MENU))
            copy_pwd_act = menu.addAction('复制密码')
            copy_pwd_act.setIcon(icon(COPY, size=SIZE_MENU))
            # TOTP 验证码（仅当条目配置了 TOTP 密钥时显示）
            copy_totp_act = None
            if entry.totp_secret:
                copy_totp_act = menu.addAction('复制验证码')
                copy_totp_act.setIcon(icon(COPY, size=SIZE_MENU))
            menu.addSeparator()
            edit_act = menu.addAction('编辑')
            edit_act.setIcon(icon(EDIT, size=SIZE_MENU))
            if entry.is_favorite:
                fav_act = menu.addAction('取消收藏')
                fav_act.setIcon(icon(STAR_OUTLINE, size=SIZE_MENU))
            else:
                fav_act = menu.addAction('收藏')
                fav_act.setIcon(icon(STAR, size=SIZE_MENU))
            menu.addSeparator()
            del_act = menu.addAction('删除')
            del_act.setIcon(icon(DELETE, size=SIZE_MENU))

            action = menu.exec(self._entry_list.mapToGlobal(pos))

            if action == copy_user_act:
                self._clipboard.copy_text(entry.username)
                Toast.show(self, '已复制账号', Toast.SUCCESS, duration=2000)
            elif action == copy_pwd_act:
                self._clipboard.copy_text(entry.password)
                Toast.show(self, '已复制密码', Toast.SUCCESS, duration=2000)
            elif copy_totp_act and action == copy_totp_act:
                from ..crypto.totp import TOTPGenerator
                code = TOTPGenerator.generate(entry.totp_secret)
                if code:
                    self._clipboard.copy_text(code)
                    Toast.show(self, f'验证码 {code} 已复制', Toast.SUCCESS, duration=3000)
                else:
                    Toast.show(self, '验证码生成失败，请检查密钥', Toast.ERROR, duration=3000)
            elif action == edit_act:
                self._edit_entry(entry.id)
            elif action == fav_act:
                self._entry_mgr.toggle_favorite(entry.id)
                self._refresh_all_data()
            elif action == del_act:
                self._delete_entry(entry.id)

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
        edit_act.setIcon(icon(EDIT, size=SIZE_MENU))
        delete_act = menu.addAction('删除分类')
        delete_act.setIcon(icon(DELETE, size=SIZE_MENU))
        action = menu.exec(self._category_list.mapToGlobal(pos))

        if action == edit_act:
            self._edit_category(cat_id)
        elif action == delete_act:
            self._delete_category(cat_id)

    # ========== 操作方法 ==========

    def _add_entry(self):
        categories = self._entry_mgr.get_categories()
        all_tags = self._entry_mgr.get_all_tags()
        tag_names = [t[0] for t in all_tags[:20]]
        dialog = EntryDialog(self._entry_mgr, categories, tag_names, parent=self, config=self._config)
        dialog.saved.connect(self._refresh_all_data)
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
        categories = self._entry_mgr.get_categories()
        all_tags = self._entry_mgr.get_all_tags()
        tag_names = [t[0] for t in all_tags[:20]]
        dialog = EntryDialog(self._entry_mgr, categories, tag_names, entry=entry, parent=self, config=self._config)
        dialog.saved.connect(self._refresh_all_data)
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
                self._refresh_all_data()
                Toast.show(self, f'已恢复「{entry_title}」', Toast.SUCCESS)

            self._refresh_all_data()
            Toast.show(self, f'已移入回收站', Toast.INFO, duration=5000,
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
        self._refresh_all_data()
        entry = self._entry_mgr.get_entry(entry_id)
        if entry:
            self._detail_panel.show_entry(entry)

    def _on_copy_feedback(self):
        self._status_bar.showMessage('已复制到剪贴板', 3000)

    def _clear_search(self):
        """快捷键：清空搜索"""
        if self._search_edit.text():
            self._search_edit.clear()
        else:
            self._entry_list.setCurrentRow(-1)
            self._detail_panel.show_empty()

    # ========== 分类管理 ==========

    def _add_category(self):
        dialog = CategoryDialog(self._vault.db, parent=self)
        dialog.saved.connect(self._refresh_categories)
        dialog.exec()

    def _edit_category(self, category_id: int):
        category = self._vault.db.get_category(category_id)
        if not category:
            return
        dialog = CategoryDialog(self._vault.db, category=category, parent=self)
        dialog.saved.connect(self._refresh_categories)
        dialog.exec()

    def _delete_category(self, category_id: int):
        category = self._vault.db.get_category(category_id)
        if not category:
            return
        count = self._vault.db.get_category_entry_count(category_id)
        msg = f'确定要删除分类「{category.name}」吗？'
        if count > 0:
            msg += f'\n\n该分类下有 {count} 个条目，删除后将取消分类归属。'
        reply = QMessageBox.question(
            self, '删除分类', msg,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self._vault.db.delete_category(category_id)
            self._refresh_all_data()
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
            self._maybe_auto_backup(force=True)

    def _show_about(self):
        dialog = AboutDialog(self)
        dialog.exec()

    def _show_security_dashboard(self):
        dialog = SecurityDashboard(self._security, self._entry_mgr, self._config, self)
        dialog.fix_requested.connect(self._edit_entry)
        dialog.exec()
        self._refresh_all_data()

    def _show_shortcuts(self):
        QMessageBox.information(self, '快捷键', (
            '⌨️ 快捷键列表\n\n'
            'Ctrl+N      新增条目\n'
            'Ctrl+E      编辑选中条目\n'
            'Ctrl+F      搜索\n'
            'Ctrl+G      密码生成器\n'
            'Ctrl+L      锁定保险库\n'
            'Ctrl+,      偏好设置\n'
            'Ctrl+Q      退出\n'
            'Delete      删除选中条目\n'
            'Escape      清空搜索/取消选择'
        ))

    def _show_from_tray(self):
        if not self._vault.is_unlocked or self._locked_ui:
            return
        self.showNormal()
        self.activateWindow()

    def _apply_runtime_settings(self):
        """立即应用无需重启的安全和托盘设置。"""
        self._clipboard.clear_seconds = self._config.get('clipboard_clear_seconds', 30)
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
        from PyQt6.QtWidgets import QApplication
        QApplication.quit()

    # ========== 主题刷新 ==========

    def _apply_theme(self):
        """应用当前主题（用于设置切换后刷新）"""
        theme = self._config.get('theme', 'light')
        if theme != self._current_theme:
            self._current_theme = theme
            style = get_style(theme)
            app = QApplication.instance()
            if app:
                app.setStyleSheet(style)
            self.setStyleSheet(style)
            # 重建侧边栏筛选图标（颜色烘焙到 QIcon，需重建）
            self._build_filter_list()
            # 刷新菜单栏图标
            self._update_menu_icons()
            # 刷新侧边栏内联样式（颜色值已烘焙，需重设）
            self._sidebar.setStyleSheet(f'background: {c("sidebar_bg")};')
            self._filter_label.setStyleSheet(f'font-weight: bold; color: {c("text_secondary")}; font-size: 12px; margin-top: 4px;')
            self._separator1.setStyleSheet(f'background: {c("divider")}; margin: 6px 0px;')
            self._cat_label.setStyleSheet(f'font-weight: bold; color: {c("text_secondary")}; font-size: 12px; margin-top: 4px;')
            self._separator2.setStyleSheet(f'background: {c("divider")}; margin: 6px 0px;')
            self._sort_label.setStyleSheet(f'font-weight: bold; color: {c("text_secondary")}; font-size: 12px; margin-top: 4px;')
            self._stats_label.setStyleSheet(f'color: {c("text_secondary")}; font-size: 11px; margin-top: 4px;')
            # 刷新列表区域内联样式
            self._list_title.setStyleSheet(f'font-weight: bold; font-size: 14px; color: {c("text_primary")};')
            self._count_label.setStyleSheet(f'color: {c("text_secondary")}; font-size: 12px;')
            self._brand_icon.setPixmap(icon_pixmap(SHIELD, 'accent', 24))
            self._brand_title.setStyleSheet(f'font-size: 15px; font-weight: 700; color: {c("text_primary")};')
            self._brand_subtitle.setStyleSheet(f'font-size: 10px; color: {c("text_muted")};')
            self._detail_panel.refresh_theme()
            if self._tray:
                self._tray.set_locked(False)
            # 刷新所有子组件的颜色
            self._refresh_entries()
            self._refresh_categories()
            # 刷新详情面板：如有选中条目则重新显示，否则显示空状态
            current = self._entry_list.currentItem()
            if current:
                entry = current.data(Qt.ItemDataRole.UserRole)
                if entry:
                    self._detail_panel.show_entry(entry)
                else:
                    self._detail_panel.show_empty()
            else:
                self._detail_panel.show_empty()

    # ========== 窗口事件 ==========

    def closeEvent(self, a0):
        try:
            geo = self.saveGeometry()
            self._config.set('window_geometry', geo.data().hex())
            if hasattr(self, '_splitter'):
                sizes = self._splitter.sizes()
                self._config.set('splitter_sizes', list(sizes))
            field, order = self._get_sort_config()
            self._config.set('sort_field', field)
            self._config.set('sort_order', order)
            self._config.save()
        except Exception:
            pass

        if self._config.get('close_to_tray', False) and self._tray:
            a0.ignore()
            self.hide()
        else:
            self._vault.close()
            if self._tray:
                self._tray.hide()
            a0.accept()

    def changeEvent(self, a0):
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
        self._current_search = ''
        self._search_edit.blockSignals(True)
        self._search_edit.clear()
        self._search_edit.blockSignals(False)
        self._search_timer.stop()
        self._entry_list.clear()
        self._detail_panel.show_empty()
        self._clipboard.clear_now()
        self._invalidate_security_cache()
        self._count_label.setText('0 项')
        self._status_bar.clearMessage()
        self._on_lock_tray()

    def _on_lock_tray(self):
        """锁定时更新托盘图标状态"""
        if self._tray:
            self._tray.set_locked(True)
