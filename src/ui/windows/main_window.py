"""CipherBox 主窗口。

编排侧边栏、条目列表与详情面板，集成快捷键、排序、Toast 通知、分类管理、
标签筛选、撤销删除、主题刷新、自动锁定与备份、安全仪表盘等功能。通过
_MainWindowFiltersMixin 与 _MainWindowMenuMixin 多重继承拆分方法实现职责分离。
"""

import logging
import sys

from PyQt6.QtCore import QAbstractNativeEventFilter, QEvent, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QCloseEvent
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
from ..components.entry_list_widget import EntryItemDelegate, EntryListModel
from ..components.tray_icon import TrayIcon
from ..components.workers import BackgroundWorker, wait_worker_shutdown
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
from .main_window_filters import _MainWindowFiltersMixin
from .main_window_menu import _MainWindowMenuMixin

logger = logging.getLogger(__name__)

# Windows 会话锁屏通知消息常量。系统锁屏（Win+L）时立即锁定保险库（1Password/
# Bitwarden 等行业惯例），而非等应用内 QTimer 到期。非 Windows 平台不注册
# （nativeEvent 中以 sys.platform 短路），降级为仅超时锁定。
_WM_WTSSESSION_CHANGE = 0x02B1
_WTS_SESSION_LOCK = 0x7


class _SessionLockFilter(QAbstractNativeEventFilter):
    """Windows 会话锁屏事件过滤器，捕获 WM_WTSSESSION_CHANGE 触发保险库锁定。

    用 QAbstractNativeEventFilter 挂载 QApplication，而非重写 MainWindow.nativeEvent：
    后者在 MainWindow 多继承（FiltersMixin/MenuMixin/QMainWindow）MRO 下会触发
    C 层 access violation；独立过滤器规避该问题，是 Qt 推荐的原生消息拦截方式。
    """

    def __init__(self, on_lock):
        super().__init__()
        self._on_lock = on_lock

    def nativeEventFilter(self, eventType, message):  # pyright: ignore[reportIncompatibleMethodOverride]
        try:
            if bytes(eventType) == b'windows_generic_MSG':  # pyright: ignore[reportArgumentType]
                from ctypes import wintypes
                msg = wintypes.MSG.from_address(int(message))  # pyright: ignore[reportArgumentType]
                if msg.message == _WM_WTSSESSION_CHANGE and msg.wParam == _WTS_SESSION_LOCK:
                    self._on_lock()
        except Exception:
            logger.debug("会话锁屏过滤器处理消息失败", exc_info=True)
        return False, 0

# 排序选项来自共享常量，作为单一事实来源
_SORT_OPTIONS = SORT_OPTIONS


class MainWindow(_MainWindowFiltersMixin, _MainWindowMenuMixin, QMainWindow):
    """CipherBox 主窗口。"""

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
        self._entry_worker: BackgroundWorker | None = None
        self._entry_workers: set[BackgroundWorker] = set()
        self._entry_refresh_generation = 0
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
                # 上限 512 字节留足余量：Qt saveGeometry 通常 40-60 字节，未来版本
                # 可能增长；原 64 偏紧，Qt 升级后可能丢弃合法 geometry。
                if len(geo_bytes) <= 512:
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
        self._warning_label.setObjectName('warningText')
        self.setStatusBar(self._status_bar)
        self._update_status_bar()

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
        self._stats_label.setObjectName('sidebarStatsLabel')
        sidebar_layout.addWidget(self._stats_label)

        self._splitter.addWidget(self._sidebar)

    def _build_filter_list(self):
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

    def _setup_tray(self):
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

    def showEvent(self, event):  # pyright: ignore[reportIncompatibleMethodOverride]
        super().showEvent(event)
        # WTS 注册须在窗口 show 后（HWND 有效）；__init__ 时未 show 会触发 C 层
        # access violation。showEvent 守卫使注册仅在实际显示时发生。测试环境
        # （pytest）_setup_session_notification 直接跳过，不安装过滤器。
        if not getattr(self, '_wts_setup_attempted', False):
            self._wts_setup_attempted = True
            self._setup_session_notification()

    def _setup_session_notification(self) -> None:
        """注册 Windows 会话锁屏通知，系统锁屏时立即触发保险库锁定。

        仅 Windows 平台启用；注册失败（如远程会话、权限受限、wtsapi32 不可用）
        静默降级为仅 QTimer 超时锁定，不影响其他功能。winId 须在窗口创建后调用，
        故置于 __init__ 的 _setup_ui 之后。
        """
        self._wts_registered = False
        # 仅 Windows 交互会话注册。测试环境（pytest 驱动 QApplication）的窗口未进入
        # 真实消息循环，WTSRegisterSessionNotification 会触发 C 层 access violation
        # （无法 try/except 捕获）；真实交互运行时窗口进入消息循环，WTS 正常工作。
        if sys.platform != 'win32' or 'pytest' in sys.modules:
            return
        try:
            import ctypes
            from ctypes import wintypes
            # 显式声明 argtypes/restype：HWND 是指针类型，64 位下默认 c_int 推断会使
            # HWND 传参截断，触发 access violation（C 层崩溃，try/except 无法捕获）。
            wts = ctypes.windll.wtsapi32
            wts.WTSRegisterSessionNotification.argtypes = [
                wintypes.HWND, wintypes.DWORD,
            ]
            wts.WTSRegisterSessionNotification.restype = wintypes.BOOL
            hwnd = int(self.winId())
            # NOTIFY_FOR_THIS_SESSION = 0：仅当前会话的锁屏/解锁通知
            if wts.WTSRegisterSessionNotification(hwnd, 0):
                self._wts_registered = True
                self._session_filter = _SessionLockFilter(self.lock_requested.emit)
                app = QApplication.instance()
                if app is not None:
                    app.installNativeEventFilter(self._session_filter)
            else:
                logger.debug("WTSRegisterSessionNotification 返回 0，会话锁屏联动降级")
        except Exception:
            logger.debug("WTS 会话通知注册失败，降级为仅 QTimer 超时锁定", exc_info=True)

    def _setup_auto_backup(self):
        # 仅创建定时器，不启动：__init__ 时 vault 尚未解锁，启动会使首次
        # singleShot 在未解锁状态空转。定时器与首次延迟检查统一由
        # refresh_after_unlock 在解锁后启动。
        self._backup_timer = QTimer(self)
        self._backup_timer.setInterval(MS_AUTO_BACKUP_CHECK)
        self._backup_timer.timeout.connect(self._maybe_auto_backup)

    def _maybe_auto_backup(self, force: bool = False):
        """按设置创建当前保险库的本地快速快照，后台执行以避免阻塞 UI。"""
        if not self._vault.is_unlocked:
            return
        # 未启用自动备份时直接返回，避免每 10 分钟空转一个 worker 线程。
        # force=True 表示设置变更后立即触发，绕过开关以兑现用户意图。
        if not force and not self._config.get_safe('auto_backup_enabled', False):
            return
        self._run_backup_async(force=force)

    def _run_backup_async(self, force: bool = False):
        """异步执行自动备份。

        始终在 BackgroundWorker 中运行：maybe_auto_backup 在间隔到期时会执行
        全量解密 + 备份密钥 Argon2id 派生 + 加密，同步执行会阻塞 UI 主线程数秒。
        """
        if not self._vault.is_unlocked:
            return
        # 上一个备份仍在运行则跳过，避免覆盖引用导致孤儿线程在锁定后访问已清零密钥
        if self._backup_worker is not None and self._backup_worker.isRunning():
            return

        # cancel_check 经显式容器引用 worker，避免闭包延迟绑定局部变量 worker：
        # _task 在 worker 构造前定义，若直接引用 worker 则依赖「start 后 worker 已
        # 赋值」的隐式执行顺序，未来把 start 内联进构造会触发 NameError。容器在
        # start 前赋值，使依赖显式且与执行顺序解耦。
        worker_holder: list[BackgroundWorker] = []

        def _task():
            # 接入 worker 的协作取消探针：锁定/隐藏到托盘时 wait_worker_shutdown
            # 设置取消标志，maybe_auto_backup 的全量解密循环据此及时退出，
            # 避免锁定后继续持密钥解密并推迟密钥清零。
            return self._backup.maybe_auto_backup(
                self._config, force=force,
                cancel_check=lambda: worker_holder[0].is_cancelled,
            )

        def _on_backup_error(msg):
            # 守卫：仅当当前备份 worker 仍是本 worker 时记录，避免被后续备份替换后
            # 旧 worker 的延迟错误信号触发误导性日志（与 _status_worker 守卫对齐）。
            if self._backup_worker is worker_holder[0]:
                logger.warning("自动快照失败: %s", msg)

        worker = BackgroundWorker(_task, parent=self)
        worker_holder.append(worker)
        worker.error.connect(_on_backup_error)
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

    def _shutdown_workers(self) -> None:
        """取消并等待所有后台 worker 结束，避免 QThread running 析构崩溃。

        统一 status/backup 两类 worker 的关闭：取消（设置协作取消标志）并等待
        其退出，超时则记 error（见 ``wait_worker_shutdown``）。锁定、退出、隐藏到
        托盘前调用，确保这些路径不再持有密钥或对已锁定 vault 发信号、继续解密条目。
        """
        wait_worker_shutdown(self._status_worker)
        self._status_worker = None
        wait_worker_shutdown(self._backup_worker)
        self._backup_worker = None
        for worker in tuple(self._entry_workers):
            wait_worker_shutdown(worker)
        self._entry_workers.clear()
        self._entry_worker = None

    def _quit_app(self):
        # 托盘退出：与 closeEvent 退出分支清理对齐——先移除事件过滤器，防止
        # 已销毁对象仍被 QApplication 引用、排队的原生消息派发到已删闭包。
        app = QApplication.instance()
        if app:
            app.removeEventFilter(self)
            session_filter = getattr(self, '_session_filter', None)
            if session_filter is not None:
                app.removeNativeEventFilter(session_filter)
        # 等待后台 worker 退出（避免 QThread running 析构崩溃），清剪贴板明文，
        # 再关闭 vault
        self._shutdown_workers()
        self._clipboard.clear_now()
        self._vault.close()
        if self._tray:
            self._tray.hide()
        QApplication.quit()

    # ========== 主题刷新 ==========

    def _apply_theme(self):
        """应用当前主题，用于设置切换后刷新。"""
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

        if self._config.get('close_to_tray', False) and self._tray:
            # 隐藏到托盘（非退出、非锁定）：清理详情面板瞬时明文并停选择定时器，
            # 等待后台 worker 退出避免隐藏后继续持密钥解密（业务层已支持协作取消，
            # wait 通常短暂）。保持 vault 解锁、列表模型与备份/状态定时器；
            # _lock_timer 仍运行，托盘态空闲超时会自动锁定（安全设计）。
            # 从托盘恢复时窗口立即可用；详情面板已清空，恢复后由用户重新选择条目。
            self._detail_panel.show_empty()
            self._clipboard.clear_now()
            self._select_timer.stop()
            self._entry_change_timer.stop()
            # 搜索防抖定时器也需停止：隐藏后 300ms 触发 _do_search 会无谓地
            # 全量解密刷新已隐藏的列表，与 prepare_for_lock 的清理集对齐。
            self._search_timer.stop()
            self._pending_selection = None
            from ..components.toast import ToastManager
            ToastManager.cancel_all_for(self)
            self._shutdown_workers()
            a0.ignore()
            self.hide()
        else:
            # 完全退出：移除事件过滤器，防止已销毁对象仍被 QApplication 引用。
            app = QApplication.instance()
            if app:
                app.removeEventFilter(self)
                # 移除会话锁屏原生事件过滤器，与 removeEventFilter(self) 对称：
                # 完全退出时解除 QApplication 对 _session_filter 的引用，避免其闭包
                # （绑定 lock_requested）在窗口销毁后仍被原生消息派发调用。
                # _session_filter 仅 Windows 实际显示时才安装，未注册时为缺失属性。
                session_filter = getattr(self, '_session_filter', None)
                if session_filter is not None:
                    app.removeNativeEventFilter(session_filter)
            # 统一用 _shutdown_workers 取消并等待后台 worker 结束，
            # 与 prepare_for_lock 的关闭模式一致，确保退出前 worker 不再持有密钥。
            self._shutdown_workers()
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
        """解锁后刷新界面。"""
        self._locked_ui = False
        self._refresh_categories()
        self._refresh_tag_filter()
        self._refresh_entries()
        self._detail_panel.show_empty()
        self._reset_lock_timer()
        # 解锁后刷新状态栏安全摘要，避免停留在锁定前的陈旧或空白状态
        self._status_timer.start()
        # 重启自动备份定时器：prepare_for_lock 已停止它，解锁后须恢复，
        # 否则任意一次锁定→解锁后本地自动快照将永久失效。
        self._backup_timer.start()
        # 解锁后延迟首次备份检查，与解锁刷新错峰避免争用主线程
        QTimer.singleShot(MS_INITIAL_BACKUP_DELAY, self._maybe_auto_backup)
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
                logger.debug("紧急剪贴板清理失败", exc_info=True)

    def emergency_cancel_workers(self) -> None:
        """紧急取消后台 worker（不等待），供 app 层 aboutToQuit 等不阻塞退出路径。

        与 ``_shutdown_workers`` 的区别：仅取消不等待，避免阻塞退出；worker 收到
        取消标志后尽快退出协作循环，缩短持密钥解密的残留窗口。
        """
        for worker in (
            getattr(self, '_backup_worker', None),
            getattr(self, '_status_worker', None),
            getattr(self, '_entry_worker', None),
        ):
            if worker is not None:
                try:
                    worker.cancel()
                except RuntimeError:
                    pass

    def prepare_for_lock(self):
        """在清除主密钥前销毁界面和剪贴板中的明文副本。"""
        self._locked_ui = True
        self._lock_timer.stop()
        # 清除活跃 Toast 的回调，防止锁定后撤销操作触发异常。
        from ..components.toast import ToastManager
        ToastManager.cancel_all_for(self)
        # 关闭所有打开的对话框：直接走对话框自身的 reject()——各对话框 reject 调用
        # 自己的 _clear_sensitive_inputs 清零敏感控件，且 wait_worker_shutdown 等待
        # 后台 worker 退出。原先 findChildren(QLineEdit/QTextEdit).clear() 旁路既无法
        # 等待 worker，也抓不到未来新增的非 LineEdit 敏感控件，与各对话框的清零双轨
        # 易漂移，故移除，单一清零路径交由对话框自身负责。
        if QApplication.instance():
            for widget in list(QApplication.topLevelWidgets()):
                if widget is self or not isinstance(widget, QDialog):
                    continue
                widget.reject()
        # 重置搜索状态
        self._current_search = ''
        self._search_edit.blockSignals(True)
        self._search_edit.clear()
        self._search_edit.blockSignals(False)
        self._search_timer.stop()
        self._select_timer.stop()
        self._entry_change_timer.stop()
        self._pending_selection = None
        # 清空条目列表，移除对 Entry 对象的引用
        self._entry_model.set_entries([])
        # 安全清除详情面板中的敏感数据和信号连接
        self._detail_panel.secure_clear()
        # 清除剪贴板中的明文
        self._clipboard.clear_now()
        # 停止后台定时器
        self._backup_timer.stop()
        self._status_timer.stop()
        # 取消后台 worker（状态分析/备份/列表刷新），避免锁定后仍运行、对已锁定
        # vault 发信号或继续解密条目
        self._shutdown_workers()
        # 清除缓存
        self._invalidate_security_cache()
        # 清空 username 明文缓存。epoch 失效会在下次访问时触发，
        # 此处显式调用以立即释放，避免锁定到进程退出的残留窗口
        self._entry_mgr.invalidate_caches()
        self._count_label.setText('0 项')
        self._status_bar.clearMessage()
        # 托盘锁定状态由 lock_requested 信号驱动（_setup_tray 连接 _on_lock_tray），
        # 此处不再显式调用，避免与信号链重复触发

    def _on_lock_tray(self):
        """锁定时更新托盘图标状态。"""
        if self._tray:
            self._tray.set_locked(True)
