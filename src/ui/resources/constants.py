"""UI 层共享常量 — 按钮尺寸、动画时长、显示限制等。"""

from ...business.managers.entry_manager import DEFAULT_RECENT_SUMMARIES_LIMIT
from ...config import (
    CFG_CLIPBOARD_CLEAR_SECONDS,
    CFG_DEFAULT_PASSWORD_LENGTH,
    CFG_PASSWORD_VISIBLE_SECONDS,
    DEFAULT_CONFIG,
    DEFAULT_THEME,
)

# 密码可见秒数等默认值从 config.DEFAULT_CONFIG 派生为单一事实源，避免双源漂移；
# 其余为本模块独有 UI 常量。

# ---------- 按钮尺寸 ----------
BTN_DIALOG = (90, 34)  # 对话框主操作按钮
BTN_DIALOG_WIDE = (100, 34)  # 宽对话框按钮，适配中文文本
BTN_PRIMARY = (120, 38)  # 主要操作按钮，如登录、使用密码等
BTN_GENERATE = (140, 38)  # 密码生成器主按钮
BTN_SECONDARY = (80, 38)  # 次要按钮，如关闭等
BTN_ACTION = (140, 36)  # 空状态操作按钮
BTN_COMPACT = (80, 40)  # 紧凑功能按钮，如密码生成器复制
BTN_SMALL_ACTION = (60, 28)  # 小型操作按钮，如 TOTP 验证等
BTN_FIX = (56, 28)  # 安全仪表盘修复按钮
BTN_ICON = (32, 32)  # 图标按钮，如眼睛、锁等
BTN_COPY = (28, 28)  # 复制按钮
BTN_TOTP_COPY = (72, 30)  # TOTP 复制按钮
BTN_CLOSE_TOAST = (20, 20)  # Toast 关闭按钮

# ---------- 动画与反馈时长，单位毫秒 ----------
MS_FEEDBACK = 1500  # 复制按钮反馈持续时间
MS_TOAST_SHORT = 2000  # 短 Toast 显示
MS_TOAST_DEFAULT = 3000  # 默认 Toast 显示
MS_TOAST_LONG = 5000  # 长 Toast 显示，用于需用户注意的消息
PWD_VISIBLE_SECONDS_DEFAULT: int = int(DEFAULT_CONFIG[CFG_PASSWORD_VISIBLE_SECONDS])
CLIPBOARD_CLEAR_SECONDS_DEFAULT: int = int(DEFAULT_CONFIG[CFG_CLIPBOARD_CLEAR_SECONDS])
WORKER_WAIT_TIMEOUT_MS = 3000  # 后台 Worker 等待超时（可取消操作）
# 不可中断操作（恢复/导入，_cancel_on_close=False）的关闭等待超时。大库逐条 AES-GCM
# 加密可能远超可取消操作的 3s，用更长超时避免 worker 仍在运行时对话框析构触发
# QThread: Destroyed 崩溃（自动锁定/退出经 reject 绕过 closeEvent 守卫）。
WORKER_WAIT_TIMEOUT_IRREVERSIBLE_MS = 120000
ABOUT_TO_QUIT_WAIT_TIMEOUT_MS = 400  # aboutToQuit 短超时等待 worker 退出（不阻塞退出）
MS_SEARCH_DEBOUNCE = 300  # 搜索输入防抖间隔
MS_AUTO_BACKUP_CHECK = 10 * 60 * 1000  # 自动备份检查间隔
MS_STATUS_BAR_DEBOUNCE = 100  # 状态栏安全分析防抖间隔
MS_ENTRY_SELECT_DEBOUNCE = 80  # 条目选择防抖间隔
MS_ENTRY_CHANGE_DEBOUNCE = 100  # 条目变更防抖间隔
MS_INITIAL_BACKUP_DELAY = 1500  # 启动后首次备份检查延迟

# ---------- 显示限制 ----------
MAX_HISTORY_DISPLAY = 5  # 详情面板最多显示密码历史条数
MAX_TAG_DISPLAY = 5  # 详情面板最多显示标签数
MAX_TAG_AUTOCOMPLETE = 20  # 标签自动补全最大数量
# 「近期更新」筛选最多显示条目数（ARCH-034）：引用业务层
# get_recent_summaries 的默认 limit 作单一事实源（UI→business 合法），原本地同值
# 20 双源声明在业务侧调整时会静默漂移，使 UI 截断与 SQL LIMIT 失配。
RECENT_ENTRY_LIMIT = DEFAULT_RECENT_SUMMARIES_LIMIT
MAX_SEARCH_RESULTS_DISPLAY = 1000  # 搜索结果渲染上限：超大库下避免一次性渲染过多条目卡死 UI
ASYNC_SEARCH_THRESHOLD = 50  # 超过该条目数时列表/搜索移入后台线程
# 阈值由 100 下调至 50（PERF-012）：冷缓存下 50-100 条目的全量摘要解密（每条 4 字段
# AES-GCM + base64 + 缓存填充）在主线程已达数十毫秒临界卡顿，下调使中小库也走已有
# 异步路径避免冻结 UI；极小库（< 50）仍同步以省去后台线程与「加载中」闪烁。

# ---------- 窗口尺寸 ----------
WINDOW_MIN_SIZE = (980, 640)
WINDOW_DEFAULT_SIZE = (1180, 760)
SIDEBAR_WIDTH = 220
SIDEBAR_ICON_SIZE = (28, 28)  # 侧边栏品牌图标尺寸
SIDEBAR_ICON_SIZE_SMALL = (22, 22)  # 侧边栏小号图标按钮尺寸（如「管理分类」+ 按钮）
FILTER_MAX_HEIGHT = 240
SPLITTER_SIZES = [200, 380, 420]

# ---------- 对话框最小尺寸 ----------
DIALOG_BACKUP_MIN_SIZE = (460, 300)
DIALOG_IMPORT_EXPORT_MIN_SIZE = (480, 360)
DIALOG_CHANGE_MASTER_MIN_SIZE = (420, 420)
DIALOG_ENTRY_MIN_SIZE = (560, 620)
DIALOG_PASSWORD_GEN_MIN_SIZE = (480, 420)
DIALOG_SECURITY_DASHBOARD_MIN_SIZE = (680, 580)
DIALOG_SETTINGS_MIN_SIZE = (520, 480)
DIALOG_CATEGORY_MIN_SIZE = (420, 420)
DIALOG_SHARE_MIN_SIZE = (520, 560)
DIALOG_ABOUT_MIN_SIZE = (400, 340)

# ---------- Toast 布局 ----------
TOAST_WIDTH = 320  # Toast 通知宽度，单位像素
TOAST_SPACING = 10
TOAST_MARGIN_BOTTOM = 20
TOAST_MARGIN_RIGHT = 20
TOAST_HOVER_RESTART_MS = 1000

# ---------- 登录窗口 ----------
LOGIN_WIDTH = 500  # 登录窗口固定宽度
LOGIN_HEIGHT_FIRST = 520
LOGIN_HEIGHT_LOGIN = 450
LOGIN_TITLE_FONT_SIZE_PX = 26  # 登录窗口标题字号（QSS 内联，单位 px）


# ---------- 字体 ----------
# 主字体 Inter（打包随应用分发，启动经 font_loader 注册到 QFontDatabase）。加载失败或
# 缺失字形（如中文）时回退系统字体：Windows Microsoft YaHei UI、macOS PingFang SC、
# Linux Noto Sans CJK SC，最终系统无衬线。
FONT_FAMILY_PRIMARY = "Inter"
FONT_FAMILY_DISPLAY = "Inter"
# QFont 不支持 CSS 字体栈，此处列出回退顺序供 QFont 构造使用。
FONT_FAMILY_FALLBACKS = [
    "Microsoft YaHei UI",
    "PingFang SC",
    "Noto Sans CJK SC",
    "SimHei",
    "sans-serif",
]

# CSS/QSS 字体栈，供 QSS 样式表 font-family 属性使用
FONT_FAMILY_CSS = (
    '"Inter", "Microsoft YaHei UI", "PingFang SC", "Noto Sans CJK SC", "Segoe UI", sans-serif'
)

# ---------- 密码相关默认值 ----------
PWD_TOGGLE_AUTO_HIDE_SECONDS = 30  # 密码切换按钮自动隐藏秒数
PWD_GENERATE_LENGTH_DEFAULT: int = int(
    DEFAULT_CONFIG[CFG_DEFAULT_PASSWORD_LENGTH]
)  # 默认生成密码长度（单一事实源）
PWD_MASK = "••••••••"  # 密码字段掩码（显隐切换/比较的单一事实源，跨 detail_panel / password_history_widget / secret_field 复用）

# ---------- 等宽字体，用于 QSS 样式表 ----------
FONT_FAMILY_MONOSPACE = "Consolas, Courier New, monospace"

# ---------- 排序选项 ----------
# 每项由显示名称、字段、排序方向组成，供 main_window 和 ListRefreshController 共享
SORT_OPTIONS = [
    ("更新时间 ↓", "updated_at", "desc"),
    ("更新时间 ↑", "updated_at", "asc"),
    ("标题 A→Z", "title", "asc"),
    ("标题 Z→A", "title", "desc"),
    ("强度 高→低", "password_strength", "desc"),
    ("强度 低→高", "password_strength", "asc"),
    ("创建时间 ↓", "created_at", "desc"),
    ("创建时间 ↑", "created_at", "asc"),
]

# ---------- 条目字段校验 ----------
# 服务器端口校验范围（QIntValidator 边界），TCP/UDP 合法区间 1-65535，0 不接受。
SERVER_PORT_MIN = 1
SERVER_PORT_MAX = 65535

# ---------- 主题标识 ----------
# 主题字符串单例：'light'/'dark' 字面量归 config 所有。THEME_LIGHT 直接派生自
# config.DEFAULT_THEME（ARCH-035），消除「同值双源」漂移；THEME_DARK 无 config 侧
# 常量（DEFAULT_THEME 恒为 light），保留字面量。
THEME_LIGHT = DEFAULT_THEME
THEME_DARK = "dark"
