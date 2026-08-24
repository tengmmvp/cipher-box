"""主题颜色系统 — 定义浅色/深色配色 token，供 styles 与运行时 c() 取色。

单例契约：模块级可变状态追踪当前主题（_current_theme/_current_colors），
set_theme() 必须在任何 c() 调用之前执行（由 styles.get_style 或
MainWindow._apply_theme 触发）。线程安全：PyQt6 单线程 UI，所有 c() 调用
均在主线程，无需同步；后台线程不应直接调用 c()。
"""

import logging

from ...config import DEFAULT_THEME

logger = logging.getLogger(__name__)

LIGHT_COLORS = {
    # 基础色（near-white 画布）
    "bg_primary": "#fbfbfd",
    "bg_secondary": "#f5f5f7",
    "bg_input": "#ffffff",
    "bg_card": "#ffffff",
    "bg_card_hover": "#f5f5f7",
    "text_primary": "#1d1d1f",
    "text_secondary": "#6e6e73",
    "text_muted": "#86868b",
    "text_on_accent": "#ffffff",
    "border": "#d2d2d7",
    "border_light": "#e5e5e7",
    "divider": "#e5e5e7",
    # 强调色（Apple Blue 单蓝点缀）
    "accent": "#0071e3",
    "accent_hover": "#0058b9",
    "accent_light": "#e8f1fb",
    "accent_text": "#0058b9",
    # 按钮色
    "btn_bg": "#ffffff",
    "btn_hover": "#f5f5f7",
    "btn_pressed": "#e5e5e7",
    # 状态色（Apple iOS 系统色）
    "danger": "#ff3b30",
    "danger_light": "#ffe1e1",
    "success": "#34c759",
    "warning": "#ffcc00",
    "warning_orange": "#ff9500",
    # 链接
    "link": "#0071e3",
    # 密码强度（红→橙→黄→绿→绿）
    "strength_0": "#ff3b30",
    "strength_1": "#ff9500",
    "strength_2": "#ffcc00",
    "strength_3": "#34c759",
    "strength_4": "#34c759",
    # 滚动条（iOS systemGray）
    "scrollbar_bg": "#f5f5f7",
    "scrollbar_handle": "#c7c7cc",
    "scrollbar_handle_hover": "#aeaeb2",
    # 选中/悬停（蓝 8% 选中）
    "item_selected_bg": "#e8f1fb",
    "item_selected_text": "#0071e3",
    "item_hover_bg": "#f5f5f7",
    # 菜单（iOS 实色蓝选中）
    "menu_bg": "#ffffff",
    "menu_item_hover": "#0071e3",
    "menu_separator": "#e5e5e7",
    # 进度条
    "progress_bg": "#e5e5e7",
    "progress_fill": "#0071e3",
    # 提示
    "tooltip_bg": "#1d1d1f",
    "tooltip_text": "#ffffff",
    "tooltip_border": "#3a3a3c",
    # Toast（白底 + 左侧彩色竖条，去阴影）
    "toast_bg": "#ffffff",
    "toast_border": "#d2d2d7",
    "toast_shadow": "transparent",
    "toast_success_bg": "#ffffff",
    "toast_success_border": "#34c759",
    "toast_error_bg": "#ffffff",
    "toast_error_border": "#ff3b30",
    "toast_info_bg": "#ffffff",
    "toast_info_border": "#0071e3",
    "toast_warning_bg": "#ffffff",
    "toast_warning_border": "#ff9500",
    # 标签
    "tag_bg": "#e8f1fb",
    "tag_text": "#0071e3",
    "tag_border": "#c7dcf6",
    # 侧边栏
    "sidebar_bg": "#f5f5f7",
    # 品牌
    "brand": "#0071e3",
    # 图标按钮（iOS tap highlight）
    "icon_btn_hover": "rgba(0,0,0,0.06)",
}

DARK_COLORS = {
    # 基础色（Apple 深色，纯黑 OLED + elevated surfaces）
    "bg_primary": "#000000",
    "bg_secondary": "#1c1c1e",
    "bg_input": "#1c1c1e",
    "bg_card": "#1c1c1e",
    "bg_card_hover": "#2c2c2e",
    "text_primary": "#f5f5f7",
    "text_secondary": "#aeaeb2",
    "text_muted": "#636366",
    "text_on_accent": "#ffffff",
    "border": "#38383a",
    "border_light": "#2c2c2e",
    "divider": "#2c2c2e",
    # 强调色（iOS systemBlue dark）
    "accent": "#0a84ff",
    "accent_hover": "#409cff",
    "accent_light": "#0a2540",
    "accent_text": "#409cff",
    # 按钮色
    "btn_bg": "#1c1c1e",
    "btn_hover": "#2c2c2e",
    "btn_pressed": "#3a3a3c",
    # 状态色（iOS 系统色 dark）
    "danger": "#ff453a",
    "danger_light": "#3a1812",
    "success": "#30d158",
    "warning": "#ffd60a",
    "warning_orange": "#ff9f0a",
    # 链接
    "link": "#0a84ff",
    # 密码强度
    "strength_0": "#ff453a",
    "strength_1": "#ff9f0a",
    "strength_2": "#ffd60a",
    "strength_3": "#30d158",
    "strength_4": "#30d158",
    # 滚动条（iOS systemGray dark）
    "scrollbar_bg": "#1c1c1e",
    "scrollbar_handle": "#48484a",
    "scrollbar_handle_hover": "#636366",
    # 选中/悬停
    "item_selected_bg": "#0a2540",
    "item_selected_text": "#0a84ff",
    "item_hover_bg": "#2c2c2e",
    # 菜单
    "menu_bg": "#1c1c1e",
    "menu_item_hover": "#0a84ff",
    "menu_separator": "#38383a",
    # 进度条
    "progress_bg": "#2c2c2e",
    "progress_fill": "#0a84ff",
    # 提示
    "tooltip_bg": "#1d1d1f",
    "tooltip_text": "#f5f5f7",
    "tooltip_border": "#48484a",
    # Toast（暗卡片 + 彩色边/竖条，去阴影）
    "toast_bg": "#1c1c1e",
    "toast_border": "#38383a",
    "toast_shadow": "transparent",
    "toast_success_bg": "#1c1c1e",
    "toast_success_border": "#30d158",
    "toast_error_bg": "#1c1c1e",
    "toast_error_border": "#ff453a",
    "toast_info_bg": "#1c1c1e",
    "toast_info_border": "#0a84ff",
    "toast_warning_bg": "#1c1c1e",
    "toast_warning_border": "#ff9f0a",
    # 标签
    "tag_bg": "#0a2540",
    "tag_text": "#0a84ff",
    "tag_border": "#0a3a6e",
    # 侧边栏（贴底纯黑）
    "sidebar_bg": "#000000",
    # 品牌
    "brand": "#0a84ff",
    # 图标按钮（iOS tap highlight dark）
    "icon_btn_hover": "rgba(255,255,255,0.08)",
}

# 加载即校验浅色/深色 key 集合一致，遗漏主题立即报错（早失败）。
# 用显式 raise 而非 assert：python -O 会剔除 assert 致校验失效。
if set(LIGHT_COLORS) != set(DARK_COLORS):
    raise RuntimeError("浅色/深色主题颜色 key 不一致")

# 模块初始主题直接派生自 config.DEFAULT_THEME（ARCH-035）：色板 token 本身仍是
# 零依赖纯数据，仅初值经单一事实源对齐，消除「同值双源注释约定」的漂移风险
# （constants.py 的 THEME_LIGHT 派生同源）。import 方向 UI→config 合法（分层：
# UI 可依赖共享层），config 不反向依赖 UI，无循环。
_current_theme = DEFAULT_THEME
_current_colors = dict(LIGHT_COLORS)


def get_colors(theme: str = "") -> dict[str, str]:
    """获取指定主题的颜色字典。"""
    if theme == "dark":
        return dict(DARK_COLORS)
    return dict(LIGHT_COLORS)


def set_theme(theme: str) -> None:
    """设置当前主题。"""
    global _current_theme, _current_colors
    _current_theme = theme
    _current_colors = dict(DARK_COLORS) if theme == "dark" else dict(LIGHT_COLORS)


def c(key: str) -> str:
    """获取当前主题的颜色值。

    未知 key 记录告警并回退中性灰色 '#888888'，便于开发期发现拼写错误，
    同时避免运行期 raise 中断绘制。
    """
    color = _current_colors.get(key)
    if color is None:
        logger.warning("未知颜色 key：%s，回退中性灰", key)
        return "#888888"
    return color


def get_strength_color(score: int) -> str:
    """获取密码强度对应的颜色。"""
    return c(f"strength_{min(score, 4)}")
