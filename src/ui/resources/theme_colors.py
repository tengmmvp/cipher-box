"""主题颜色系统 — 定义浅色/深色配色 token，供 styles 与运行时 c() 取色。

单例契约：模块级可变状态追踪当前主题（_current_theme/_current_colors），
set_theme() 必须在任何 c() 调用之前执行（由 styles.get_style 或
MainWindow._apply_theme 触发）。线程安全：PyQt6 单线程 UI，所有 c() 调用
均在主线程，无需同步；后台线程不应直接调用 c()。
"""

import logging

logger = logging.getLogger(__name__)

LIGHT_COLORS = {
    # 基础色
    'bg_primary': '#f7f9fb',
    'bg_secondary': '#eef2f5',
    'bg_tertiary': '#e4e9ee',
    'bg_input': '#ffffff',
    'bg_card': '#ffffff',
    'bg_card_hover': '#f3f7f7',
    'text_primary': '#17212b',
    'text_secondary': '#52616f',
    'text_muted': '#8794a1',
    'text_placeholder': '#999999',
    'text_on_accent': '#ffffff',
    'border': '#cbd5de',
    'border_light': '#e2e8ee',
    'divider': '#e2e8ee',
    # 强调色
    'accent': '#0f766e',
    'accent_hover': '#0b5f59',
    'accent_light': '#dff5f1',
    'accent_text': '#0b655e',
    # 按钮色
    'btn_bg': '#ffffff',
    'btn_hover': '#f0f5f5',
    'btn_pressed': '#e3eceb',
    'danger': '#e74c3c',
    'danger_hover': '#c0392b',
    'danger_light': '#fde8e8',
    'success': '#27ae60',
    'success_light': '#e8f8ef',
    'warning': '#f1c40f',
    'warning_orange': '#e67e22',
    'warning_light': '#fef9e7',
    # 链接
    'link': '#0f766e',
    # 密码强度
    'strength_0': '#e74c3c',
    'strength_1': '#e67e22',
    'strength_2': '#f1c40f',
    'strength_3': '#27ae60',
    'strength_4': '#27ae60',
    # 滚动条
    'scrollbar_bg': '#f5f5f5',
    'scrollbar_handle': '#c0c0c0',
    'scrollbar_handle_hover': '#a0a0a0',
    # 选中/悬停
    'item_selected_bg': '#dff5f1',
    'item_selected_text': '#0b655e',
    'item_hover_bg': '#edf6f4',
    # 菜单
    'menu_bg': '#ffffff',
    'menu_item_hover': '#dff5f1',
    'menu_separator': '#e0e0e0',
    # 进度条
    'progress_bg': '#e0e0e0',
    'progress_fill': '#0f766e',
    # 提示
    'tooltip_bg': '#333333',
    'tooltip_text': '#ffffff',
    'tooltip_border': '#555555',
    # Toast
    'toast_bg': '#ffffff',
    'toast_border': '#e0e0e0',
    'toast_shadow': 'rgba(0,0,0,0.12)',
    'toast_success_bg': '#e8f8ef',
    'toast_success_border': '#27ae60',
    'toast_error_bg': '#fde8e8',
    'toast_error_border': '#e74c3c',
    'toast_info_bg': '#dff5f1',
    'toast_info_border': '#0f766e',
    'toast_warning_bg': '#fef9e7',
    'toast_warning_border': '#f1c40f',
    # 徽章
    'badge_bg': '#dff5f1',
    'badge_text': '#0b655e',
    # 标签
    'tag_bg': '#e8f7f4',
    'tag_text': '#0b655e',
    'tag_border': '#b8e1da',
    # 侧边栏
    'sidebar_bg': '#f0f4f6',
    'sidebar_active_indicator': '#0f766e',
    'sidebar_count_bg': '#e0e0e0',
    'sidebar_count_text': '#666666',
    # 品牌
    'brand': '#0f766e',
    # 图标按钮
    'icon_btn_hover': 'rgba(128,128,128,0.1)',
}

DARK_COLORS = {
    # 基础色
    'bg_primary': '#0f1724',
    'bg_secondary': '#151f2e',
    'bg_tertiary': '#223044',
    'bg_input': '#182436',
    'bg_card': '#172334',
    'bg_card_hover': '#1c2b3f',
    'text_primary': '#e7edf3',
    'text_secondary': '#aab7c4',
    'text_muted': '#718096',
    'text_placeholder': '#718096',
    'text_on_accent': '#062b28',
    'border': '#35445a',
    'border_light': '#253348',
    'divider': '#253348',
    # 强调色
    'accent': '#5eead4',
    'accent_hover': '#7cf2df',
    'accent_light': '#183b3a',
    'accent_text': '#72ead8',
    # 按钮色
    'btn_bg': '#1b293c',
    'btn_hover': '#25364c',
    'btn_pressed': '#30445d',
    'danger': '#f38ba8',
    'danger_hover': '#eba0ac',
    'danger_light': '#3a2a30',
    'success': '#a6e3a1',
    'success_light': '#2a3a2e',
    'warning': '#f9e2af',
    'warning_orange': '#fab387',
    'warning_light': '#3a3520',
    # 链接
    'link': '#72ead8',
    # 密码强度
    'strength_0': '#f38ba8',
    'strength_1': '#fab387',
    'strength_2': '#f9e2af',
    'strength_3': '#a6e3a1',
    'strength_4': '#a6e3a1',
    # 滚动条
    'scrollbar_bg': '#1e1e2e',
    'scrollbar_handle': '#45475a',
    'scrollbar_handle_hover': '#585b70',
    # 选中/悬停
    'item_selected_bg': '#183b3a',
    'item_selected_text': '#72ead8',
    'item_hover_bg': '#1b2d3c',
    # 菜单
    'menu_bg': '#313244',
    'menu_item_hover': '#45475a',
    'menu_separator': '#45475a',
    # 进度条
    'progress_bg': '#45475a',
    'progress_fill': '#5eead4',
    # 提示
    'tooltip_bg': '#313244',
    'tooltip_text': '#cdd6f4',
    'tooltip_border': '#45475a',
    # Toast
    'toast_bg': '#313244',
    'toast_border': '#45475a',
    'toast_shadow': 'rgba(0,0,0,0.3)',
    'toast_success_bg': '#2a3a2e',
    'toast_success_border': '#a6e3a1',
    'toast_error_bg': '#3a2a30',
    'toast_error_border': '#f38ba8',
    'toast_info_bg': '#262637',
    'toast_info_border': '#89b4fa',
    'toast_warning_bg': '#3a3520',
    'toast_warning_border': '#f9e2af',
    # 徽章
    'badge_bg': '#313244',
    'badge_text': '#89b4fa',
    # 标签
    'tag_bg': '#313244',
    'tag_text': '#89b4fa',
    'tag_border': '#45475a',
    # 侧边栏
    'sidebar_bg': '#181825',
    'sidebar_active_indicator': '#89b4fa',
    'sidebar_count_bg': '#45475a',
    'sidebar_count_text': '#a6adc8',
    # 品牌
    'brand': '#5eead4',
    # 图标按钮
    'icon_btn_hover': 'rgba(200,200,200,0.15)',
}

# 加载即校验浅色/深色 key 集合一致，遗漏主题立即报错（早失败）。
# 用显式 raise 而非 assert：python -O 会剔除 assert 致校验失效。
if set(LIGHT_COLORS) != set(DARK_COLORS):
    raise RuntimeError('浅色/深色主题颜色 key 不一致')

# 模块初始主题须与 config.DEFAULT_THEME 一致：本模块为零上层依赖的纯色板不
# import config，故以注释声明该一致性约定。
_current_theme = 'light'
_current_colors = dict(LIGHT_COLORS)


def get_colors(theme: str = '') -> dict[str, str]:
    """获取指定主题的颜色字典。"""
    if theme == 'dark':
        return dict(DARK_COLORS)
    return dict(LIGHT_COLORS)


def set_theme(theme: str) -> None:
    """设置当前主题。"""
    global _current_theme, _current_colors
    _current_theme = theme
    _current_colors = dict(DARK_COLORS) if theme == 'dark' else dict(LIGHT_COLORS)


def c(key: str) -> str:
    """获取当前主题的颜色值。

    未知 key 记录告警并回退中性灰色 '#888888'，便于开发期发现拼写错误，
    同时避免运行期 raise 中断绘制。
    """
    color = _current_colors.get(key)
    if color is None:
        logger.warning("未知颜色 key：%s，回退中性灰", key)
        return '#888888'
    return color


def get_strength_color(score: int) -> str:
    """获取密码强度对应的颜色。"""
    return c(f'strength_{min(score, 4)}')
