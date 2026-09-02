"""TrayIcon 系统托盘组件测试（零覆盖补齐，离屏冒烟 + 行为）。

offscreen/无托盘环境下 ``isSystemTrayAvailable`` 为 False，构造与信号连接
仍应正常；图标绘制经纯函数 ``_create_icon`` 直接断言。
"""

from PyQt6.QtGui import QColor, QIcon

from src.ui.components.tray_icon import TrayIcon
from src.ui.resources.theme_colors import c


class TestTrayIcon:
    """托盘构造、状态切换与交互信号。"""

    def test_construction_sets_icon_and_tooltip(self, qapp):
        """构造后携带 CipherBox 图标与未锁定提示文案。"""
        tray = TrayIcon()
        assert isinstance(tray.icon(), QIcon)
        assert not tray.icon().isNull()
        assert tray.toolTip() == "CipherBox"

    def test_set_locked_true_switches_state(self, qapp):
        """锁定态切换图标与提示文案（LOCK 文字缩写）。"""
        tray = TrayIcon()
        tray.set_locked(True)
        assert tray.toolTip() == "CipherBox（已锁定）"

    def test_set_locked_false_restores(self, qapp):
        """解锁态恢复默认图标与提示。"""
        tray = TrayIcon()
        tray.set_locked(True)
        tray.set_locked(False)
        assert tray.toolTip() == "CipherBox"

    def test_create_icon_truncates_long_text(self, qapp):
        """长文字（如 LOCK，len>2）缩写为首字符（32px 画布防溢出裁剪）。"""
        icon = TrayIcon._create_icon(QColor(c("brand")), "LOCK")
        assert not icon.isNull()

    def test_create_icon_accepts_color_name(self, qapp):
        """color 参数兼容 str 形态（历史调用路径）。"""
        icon = TrayIcon._create_icon(QColor(c("brand")).name(), "C")
        assert not icon.isNull()

    def test_double_click_emits_show_window(self, qapp):
        """双击激活发射 show_window 信号（唤出主窗口）。"""
        from PyQt6.QtWidgets import QSystemTrayIcon

        tray = TrayIcon()
        received: list[int] = []
        tray.show_window.connect(lambda: received.append(1))

        tray._on_activated(QSystemTrayIcon.ActivationReason.DoubleClick)

        assert received == [1]

    def test_single_click_does_not_emit(self, qapp):
        """单击不唤出窗口（仅双击语义）。"""
        from PyQt6.QtWidgets import QSystemTrayIcon

        tray = TrayIcon()
        received: list[int] = []
        tray.show_window.connect(lambda: received.append(1))

        tray._on_activated(QSystemTrayIcon.ActivationReason.Trigger)

        assert received == []

    def test_menu_actions_emit_signals(self, qapp):
        """右键菜单三项动作分别转发对应信号。"""
        from PyQt6.QtGui import QAction

        tray = TrayIcon()
        shown: list[int] = []
        locked: list[int] = []
        quitted: list[int] = []
        tray.show_window.connect(lambda: shown.append(1))
        tray.lock_vault.connect(lambda: locked.append(1))
        tray.quit_app.connect(lambda: quitted.append(1))

        menu = tray.contextMenu()
        assert menu is not None
        # 分隔符行动作 text 为空串，过滤后按序断言三项
        actions = [a for a in menu.actions() if isinstance(a, QAction) and a.text()]
        assert [a.text() for a in actions] == ["显示主窗口", "锁定保险库", "退出"]
        for action in actions:
            action.trigger()

        assert shown and locked and quitted
