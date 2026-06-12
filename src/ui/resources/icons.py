"""统一图标管理模块 — 基于 QtAwesome 的语义化图标系统

使用方式：
    from .resources.icons import icon, set_icon, EYE, COPY
    set_icon(btn, EYE)                    # 设置按钮图标，并自动清除文字
    act.setIcon(icon(COPY, size=SIZE_MENU))  # 菜单项图标
"""

import qtawesome as qta
from PyQt6.QtCore import QSize, Qt
from PyQt6.QtGui import QColor, QFont, QIcon, QPainter, QPixmap

from .theme_colors import c

# ============================================================
# 预设尺寸
# ============================================================
SIZE_BTN = 16       # 标准按钮图标
SIZE_MENU = 14      # 菜单项图标
SIZE_SIDEBAR = 14   # 侧边栏列表项
SIZE_EMPTY = 48     # 空状态大图标
SIZE_TOAST = 18     # Toast 通知图标

# ============================================================
# 图标名常量
# ============================================================

# --- 密码显示/隐藏 ---
EYE = 'eye'
LOCK = 'lock'

# --- 操作 ---
COPY = 'copy'
CHECK = 'check'
EDIT = 'edit'
DELETE = 'delete'
PLUS = 'plus'
CLOSE = 'close'
REFRESH = 'refresh'
GENERATE = 'generate'

# --- 收藏 ---
STAR = 'star'
STAR_OUTLINE = 'star_outline'

# --- 状态 ---
SUCCESS = 'success'
ERROR = 'error'
WARNING = 'warning'
INFO = 'info'

# --- 导航/分类 ---
SEARCH = 'search'
FOLDER = 'folder'
KEY = 'key'
SHIELD = 'shield'
LOCK_SOLID = 'lock_solid'
SETTINGS = 'settings'

# --- 侧边栏筛选项 ---
FILTER_ALL = 'filter_all'
FILTER_FAVORITE = 'filter_favorite'
FILTER_WEAK = 'filter_weak'
FILTER_DUPLICATE = 'filter_duplicate'
FILTER_RECENT = 'filter_recent'
FILTER_TRASH = 'filter_trash'

# --- 空状态 ---
EMPTY_SEARCH = 'empty_search'
EMPTY_TRASH = 'empty_trash'
EMPTY_SUCCESS = 'empty_success'
EMPTY_FOLDER = 'empty_folder'
EMPTY_VAULT = 'empty_vault'
EMPTY_GENERIC = 'empty_generic'

# --- 其他 ---
UPLOAD = 'upload'
HELP = 'help'
SHORTCUT = 'shortcut'

# ============================================================
# 图标映射表：常量映射到 qtawesome 字形名与默认颜色键组成的二元组
# ============================================================

_ICON_MAP: dict[str, tuple[str, str]] = {
    # 密码显示/隐藏
    EYE:         ('fa6s.eye',              'text_secondary'),
    LOCK:        ('fa6s.lock',             'text_secondary'),

    # 操作
    COPY:        ('fa6s.copy',             'text_secondary'),
    CHECK:       ('fa6s.check',            'success'),
    EDIT:        ('fa6s.pen-to-square',    'text_secondary'),
    DELETE:      ('fa6s.trash-can',        'text_secondary'),
    PLUS:        ('fa6s.plus',             'accent'),
    CLOSE:       ('fa6s.xmark',            'text_muted'),
    REFRESH:     ('fa6s.rotate-left',      'text_secondary'),
    GENERATE:    ('fa6s.dice',             'accent'),

    # 收藏
    STAR:        ('fa6s.star',             'warning'),
    STAR_OUTLINE:('mdi6.star-outline',     'text_muted'),

    # 状态
    SUCCESS:     ('fa6s.circle-check',     'success'),
    ERROR:       ('fa6s.circle-xmark',     'danger'),
    WARNING:     ('fa6s.triangle-exclamation', 'warning_orange'),
    INFO:        ('fa6s.circle-info',      'accent'),

    # 导航
    SEARCH:      ('fa6s.magnifying-glass', 'text_muted'),
    FOLDER:      ('fa6s.folder',           'text_secondary'),
    KEY:         ('fa6s.key',              'accent'),
    SHIELD:      ('fa6s.shield-halved',    'accent'),
    LOCK_SOLID:  ('fa6s.lock',             'accent'),
    SETTINGS:    ('fa6s.gear',             'text_secondary'),

    # 侧边栏筛选项
    FILTER_ALL:      ('fa6s.clipboard-list',         'text_secondary'),
    FILTER_FAVORITE: ('fa6s.star',                   'warning'),
    FILTER_WEAK:     ('fa6s.triangle-exclamation',   'warning_orange'),
    FILTER_DUPLICATE:('fa6s.repeat',                 'text_secondary'),
    FILTER_RECENT:   ('fa6s.clock-rotate-left',      'text_secondary'),
    FILTER_TRASH:    ('fa6s.trash-can',               'text_secondary'),

    # 空状态
    EMPTY_SEARCH:  ('fa6s.magnifying-glass', 'text_muted'),
    EMPTY_TRASH:   ('fa6s.trash-can',        'text_muted'),
    EMPTY_SUCCESS: ('fa6s.circle-check',     'success'),
    EMPTY_FOLDER:  ('fa6s.folder-open',      'text_muted'),
    EMPTY_VAULT:   ('fa6s.shield-halved',    'accent'),
    EMPTY_GENERIC: ('fa6s.clipboard',        'text_muted'),

    # 其他
    UPLOAD:       ('fa6s.upload',               'accent'),
    HELP:         ('fa6s.circle-question',      'text_secondary'),
    SHORTCUT:     ('fa6s.keyboard',             'text_secondary'),
}

# ============================================================
# 核心 API
# ============================================================


def _make_icon(name: str, color_key: str | None = None) -> QIcon:
    """内部：创建 QIcon 实例。

    颜色在创建时烘焙到 QIcon 中，主题颜色通过 c() 获取。
    主题切换时需重建所有图标，重建入口包括 _build_filter_list、_update_menu_icons 等，
    遗漏重建的图标将保留旧主题颜色。
    """
    glyph, default_color_key = _ICON_MAP[name]
    ck = color_key or default_color_key
    color = c(ck)
    return qta.icon(glyph, color=color)


def icon(name: str, color_key: str | None = None, size: int = SIZE_BTN) -> QIcon:  # noqa: ARG001
    """获取着色后的 QIcon。

    Note:
        ``size`` 参数暂未使用，QIcon 渲染尺寸由目标 widget 的 iconSize 决定。
        保留此参数以便未来支持固定尺寸输出。
    """
    return _make_icon(name, color_key)


def icon_pixmap(name: str, color_key: str | None = None, size: int = SIZE_BTN) -> QPixmap:
    """获取 QPixmap，用于 QLabel 等无法直接设置 QIcon 的控件。"""
    qicon = _make_icon(name, color_key)
    return qicon.pixmap(QSize(size, size))


def set_icon(widget, name: str, color_key: str | None = None, size: int = SIZE_BTN):
    """给 QPushButton 设置图标并自动清除文字。"""
    qicon = _make_icon(name, color_key)
    widget.setIcon(qicon)
    widget.setIconSize(QSize(size, size))
    widget.setText('')
    widget.setAccessibleName(name.replace('_', ' '))


def set_icon_with_text(widget, text: str, name: str, color_key: str | None = None, size: int = SIZE_BTN):
    """给 QPushButton 同时设置图标和文字。"""
    qicon = _make_icon(name, color_key)
    widget.setIcon(qicon)
    widget.setIconSize(QSize(size, size))
    widget.setText(text)
    widget.setAccessibleName(text)


def draw_logo_pixmap(
    size: int = 64,
    bg_color: str | None = None,
    text: str = 'C',
    text_color: str | None = None,
    font_size: int | None = None,
) -> QPixmap:
    """绘制 CipherBox Logo 的 QPixmap。

    Args:
        size: 画布尺寸，正方形
        bg_color: 背景色，默认使用主题 brand 色
        text: 显示文字
        text_color: 文字颜色，默认使用 text_on_accent
        font_size: 字体大小，默认按 size 自动计算
    """
    from .constants import FONT_FAMILY_PRIMARY

    if bg_color is None:
        bg_color = c('brand')
    if text_color is None:
        text_color = c('text_on_accent')
    if font_size is None:
        font_size = max(12, size // 2 - 4) if len(text) <= 1 else max(8, size // 3)

    margin = max(1, size // 16)
    rect_size = size - 2 * margin
    radius = max(2, size // 5)

    pixmap = QPixmap(size, size)
    pixmap.fill(QColor(0, 0, 0, 0))
    p = QPainter(pixmap)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setBrush(QColor(bg_color))
    p.setPen(Qt.PenStyle.NoPen)
    p.drawRoundedRect(margin, margin, rect_size, rect_size, radius, radius)
    p.setPen(QColor(text_color))
    p.setFont(QFont(FONT_FAMILY_PRIMARY, font_size, QFont.Weight.Bold))
    p.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, text)
    p.end()
    return pixmap
