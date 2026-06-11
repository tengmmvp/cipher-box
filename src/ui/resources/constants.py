"""UI 层共享常量 — 按钮尺寸、动画时长、显示限制等。"""

# ---------- 按钮尺寸 ----------
BTN_DIALOG = (90, 34)       # 对话框主操作按钮
BTN_DIALOG_WIDE = (100, 34)  # 宽对话框按钮（中文文本）
BTN_PRIMARY = (120, 38)     # 主要操作按钮（登录、使用密码等）
BTN_GENERATE = (140, 38)    # 密码生成器主按钮
BTN_SECONDARY = (80, 38)    # 次要按钮（关闭等）
BTN_ACTION = (140, 36)      # 空状态操作按钮
BTN_COMPACT = (80, 40)      # 紧凑功能按钮（密码生成器复制）
BTN_SMALL_ACTION = (60, 28) # 小型操作按钮（TOTP 验证等）
BTN_FIX = (56, 28)          # 安全仪表盘修复按钮
BTN_ICON = (32, 32)         # 图标按钮（眼睛、锁等）
BTN_COPY = (28, 28)         # 复制按钮
BTN_TOTP_COPY = (72, 30)    # TOTP 复制按钮
BTN_CLOSE_TOAST = (20, 20)  # Toast 关闭按钮

# ---------- 动画与反馈时长（毫秒）----------
MS_FEEDBACK = 1500          # 复制按钮反馈持续时间
MS_TOAST_SHORT = 2000       # 短 Toast 显示
MS_TOAST_DEFAULT = 3000     # 默认 Toast 显示
MS_TOAST_LONG = 5000        # 长 Toast 显示（需用户注意的消息）
PWD_VISIBLE_SECONDS_DEFAULT = 10  # 密码可见默认秒数
CLIPBOARD_CLEAR_SECONDS_DEFAULT = 30  # 剪贴板自动清除默认秒数
WORKER_WAIT_TIMEOUT_MS = 3000     # 后台 Worker 等待超时（毫秒）
MS_SEARCH_DEBOUNCE = 300    # 搜索输入防抖间隔
MS_AUTO_BACKUP_CHECK = 10 * 60 * 1000  # 自动备份检查间隔
MS_STATUS_BAR_DEBOUNCE = 100  # 状态栏安全分析防抖间隔（毫秒）
MS_ENTRY_SELECT_DEBOUNCE = 80  # 条目选择防抖间隔
MS_ENTRY_CHANGE_DEBOUNCE = 100  # 条目变更防抖间隔

# ---------- 显示限制 ----------
MAX_HISTORY_DISPLAY = 5     # 详情面板最多显示密码历史条数
MAX_TAG_DISPLAY = 5         # 详情面板最多显示标签数
MAX_TAG_AUTOCOMPLETE = 20   # 标签自动补全最大数量
RECENT_ENTRY_LIMIT = 20     # 「近期更新」筛选最多显示条目数

# ---------- 窗口尺寸 ----------
WINDOW_MIN_SIZE = (980, 640)
WINDOW_DEFAULT_SIZE = (1180, 760)
SIDEBAR_WIDTH = 220
FILTER_MAX_HEIGHT = 240
SPLITTER_SIZES = [200, 380, 420]
MS_INITIAL_BACKUP_DELAY = 1500

# ---------- 对话框最小尺寸 ----------
DIALOG_BACKUP_MIN_SIZE = (460, 300)
DIALOG_IMPORT_EXPORT_MIN_SIZE = (480, 360)
DIALOG_CHANGE_MASTER_MIN_SIZE = (420, 420)
DIALOG_ENTRY_MIN_SIZE = (560, 620)
DIALOG_PASSWORD_GEN_MIN_SIZE = (480, 420)
DIALOG_SECURITY_DASHBOARD_MIN_SIZE = (680, 580)
DIALOG_SETTINGS_MIN_SIZE = (520, 480)
DIALOG_CATEGORY_MIN_SIZE = (420, 420)
DIALOG_ABOUT_MIN_SIZE = (400, 340)

# ---------- Toast 布局 ----------
TOAST_WIDTH = 320  # Toast 通知宽度（像素）
TOAST_SPACING = 10
TOAST_MARGIN_BOTTOM = 20
TOAST_MARGIN_RIGHT = 20
TOAST_HOVER_RESTART_MS = 1000

# ---------- 登录窗口 ----------
LOGIN_HEIGHT_FIRST = 520
LOGIN_HEIGHT_LOGIN = 450

# ---------- 安全评分惩罚权重 ----------
HEALTH_PENALTY_WEAK = 15
HEALTH_PENALTY_DUPLICATE = 10
HEALTH_PENALTY_OLD = 5

# ---------- 字体 ----------
# 字体栈：Windows 优先 Microsoft YaHei，macOS 回退 PingFang SC，
# Linux 回退 Noto Sans CJK SC，最终回退系统无衬线字体。
FONT_FAMILY_PRIMARY = 'Microsoft YaHei UI'
FONT_FAMILY_DISPLAY = 'Microsoft YaHei'
# QFont 不支持 CSS 字体栈，此处列出回退顺序供 QFont 构造使用。
FONT_FAMILY_FALLBACKS = ['PingFang SC', 'Noto Sans CJK SC', 'SimHei', 'sans-serif']

# CSS/QSS 字体栈（用于 QSS 样式表 font-family 属性）
FONT_FAMILY_CSS = '"Microsoft YaHei", "PingFang SC", "Noto Sans CJK SC", "Segoe UI", sans-serif'

# ---------- 密码相关默认值 ----------
PWD_TOGGLE_AUTO_HIDE_SECONDS = 30    # 密码切换按钮自动隐藏秒数
PWD_GENERATE_LENGTH_DEFAULT = 16     # 默认生成密码长度

# ---------- 字体（CSS/QSS） ----------
FONT_FAMILY_MONOSPACE = 'Consolas, Courier New, monospace'

# ---------- 排序选项 ----------
# (显示名称, 字段, 排序方向) — main_window 和 main_window_filters 共享
SORT_OPTIONS = [
    ('更新时间 ↓', 'updated_at', 'desc'),
    ('更新时间 ↑', 'updated_at', 'asc'),
    ('标题 A→Z', 'title', 'asc'),
    ('标题 Z→A', 'title', 'desc'),
    ('强度 高→低', 'password_strength', 'desc'),
    ('强度 低→高', 'password_strength', 'asc'),
    ('创建时间 ↓', 'created_at', 'desc'),
    ('创建时间 ↑', 'created_at', 'asc'),
]
