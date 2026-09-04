"""主题默认值单一事实源一致性测试（ARCH-035）。

历史三处独立声明 'light' 字面量（config.DEFAULT_THEME / constants.THEME_LIGHT /
theme_colors._current_theme 模块初值），靠注释约定同值，任一处改动即静默漂移
（如默认主题切 dark 时 theme_colors 初值仍解析浅色）。现统一派生自
``config.DEFAULT_THEME``，本文件守护三处恒等不被回归为字面量双源。
"""

import importlib

import src.config as config
import src.ui.resources.theme_colors as theme_colors
from src.ui.resources.constants import THEME_DARK, THEME_LIGHT


def test_theme_light_derives_from_default_theme():
    """constants.THEME_LIGHT 与 config.DEFAULT_THEME 恒等（派生而非巧合同值）。"""
    assert THEME_LIGHT == config.DEFAULT_THEME


def test_theme_dark_derives_from_config_constant():
    """constants.THEME_DARK 与 config.THEME_DARK 恒等（派生而非巧合同值，MAINT-123）。"""
    assert THEME_DARK == config.THEME_DARK


def test_theme_colors_initial_theme_derives_from_default_theme():
    """theme_colors 模块初值与 config.DEFAULT_THEME 恒等。

    经 importlib.reload 重取模块级初值：同进程其他测试可能已 set_theme 改动
    运行态 ``_current_theme``，直接断言会被污染；reload 后恢复原运行态，不影响
    后续依赖主题状态的测试。theme_colors 为纯色板数据模块（reload 无 Qt 副作用）。
    """
    saved_theme = theme_colors._current_theme
    saved_colors = theme_colors._current_colors
    try:
        reloaded = importlib.reload(theme_colors)
        assert reloaded._current_theme == config.DEFAULT_THEME
    finally:
        # 还原 reload 前的运行态（若先前测试已 set_theme("dark")）
        theme_colors._current_theme = saved_theme
        theme_colors._current_colors = saved_colors


def test_three_theme_defaults_all_identical():
    """三处主题默认值整体恒等：config.DEFAULT_THEME == THEME_LIGHT == 模块初值。"""
    saved_theme = theme_colors._current_theme
    saved_colors = theme_colors._current_colors
    try:
        reloaded = importlib.reload(theme_colors)
        assert config.DEFAULT_THEME == THEME_LIGHT == reloaded._current_theme
    finally:
        theme_colors._current_theme = saved_theme
        theme_colors._current_colors = saved_colors


def test_get_colors_and_set_theme_derive_dark_branch_from_config_constant(monkeypatch):
    """get_colors/set_theme 的 dark 判据派生自 config.THEME_DARK（MAINT-123 补正）。

    monkeypatch 改名常量后 reload：真派生的实现随新值解析深色；字面量 ``"dark"``
    实现仍认旧值——以此区分派生与巧合同值。
    """
    monkeypatch.setattr(config, "THEME_DARK", "drk")
    saved_theme = theme_colors._current_theme
    saved_colors = theme_colors._current_colors
    try:
        reloaded = importlib.reload(theme_colors)
        assert reloaded.get_colors("drk") == theme_colors.DARK_COLORS
        assert reloaded.get_colors(config.DEFAULT_THEME) == theme_colors.LIGHT_COLORS
        reloaded.set_theme("drk")
        assert reloaded._current_theme == "drk"
        assert reloaded._current_colors == theme_colors.DARK_COLORS
    finally:
        monkeypatch.undo()
        importlib.reload(theme_colors)
        theme_colors._current_theme = saved_theme
        theme_colors._current_colors = saved_colors
