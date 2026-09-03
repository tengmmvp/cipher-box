"""TrayIcon 系统托盘组件测试（零覆盖补齐，离屏冒烟 + 行为）。

offscreen/无托盘环境下 ``isSystemTrayAvailable`` 为 False，构造与信号连接
仍应正常；图标绘制经纯函数 ``_create_icon`` 直接断言（QImage 逐像素比对——
offscreen 下 devicePixelRatio 恒 1，pixmap→image 对比确定性成立）。
"""

from PyQt6.QtGui import QColor, QIcon

from src.ui.components.tray_icon import TrayIcon
from src.ui.resources.theme_colors import c


def _icon_image(icon: QIcon):
    """取 QIcon 的 32px QImage（同尺寸采样，供逐像素比对）。"""
    return icon.pixmap(32, 32).toImage()


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
        unlocked_image = _icon_image(tray.icon())
        tray.set_locked(True)
        assert tray.toolTip() == "CipherBox（已锁定）"
        # 图标真实切换：与解锁态像素不同，且等于 LOCK（灰底 L）规格图标。
        # 期望值经 _create_icon 重建的半镜像独立性论证（QL-076）：期望侧的
        # 颜色（text_muted）与文字（LOCK）由本测试独立选定，与 set_locked 的
        # 实现来源不同——若 set_locked 改用其它颜色/文字，等值断言失败；已知
        # 局限是 _create_icon 的绘制格式整体变化（尺寸/绘制库）时两侧同步漂移，
        # 该风险由前两个不等/tooltip 断言（不经 _create_icon）独立兜底。
        locked_image = _icon_image(tray.icon())
        assert locked_image != unlocked_image
        assert locked_image == _icon_image(TrayIcon._create_icon(QColor(c("text_muted")), "LOCK"))
        # 差分断言：锁定图标确按 text_muted（而非 brand 或其它）着色——与
        # brand 色同文字产物不同，证明颜色真实参与且不是恒等比较
        assert locked_image != _icon_image(TrayIcon._create_icon(QColor(c("brand")), "LOCK"))

    def test_set_locked_false_restores(self, qapp):
        """解锁态恢复默认图标与提示。"""
        tray = TrayIcon()
        unlocked_image = _icon_image(tray.icon())
        tray.set_locked(True)
        tray.set_locked(False)
        assert tray.toolTip() == "CipherBox"
        # 图标恢复：与锁定态不同、与初始解锁态逐像素一致
        restored_image = _icon_image(tray.icon())
        assert restored_image == unlocked_image
        assert restored_image != _icon_image(TrayIcon._create_icon(QColor(c("text_muted")), "LOCK"))

    def test_create_icon_truncates_long_text(self, qapp):
        """长文字（如 LOCK，len>2）缩写为首字符（32px 画布防溢出裁剪）。"""
        color = QColor(c("brand"))
        icon = TrayIcon._create_icon(color, "LOCK")
        assert not icon.isNull()
        # 截断行为断言：LOCK 与其首字符 L 产物逐像素一致（未截断则 4 字符溢出裁剪
        # 且字号分支不同，像素必不相同）
        assert _icon_image(icon) == _icon_image(TrayIcon._create_icon(color, "L"))
        # 对照：与双字符（走 12px 字号分支）产物确有差异，证明对比非恒真
        assert _icon_image(icon) != _icon_image(TrayIcon._create_icon(color, "CL"))

    def test_create_icon_accepts_color_name(self, qapp):
        """color 参数兼容 str 形态（历史调用路径）。"""
        icon = TrayIcon._create_icon(QColor(c("brand")).name(), "C")
        assert not icon.isNull()
        # str 与 QColor 入参产物一致（历史路径等价性）。两侧同经 _create_icon
        # 是本断言的目的本身（等价性契约，QL-076 独立性论证）：被测对象就是
        # 「同一函数对两种入参形态的归一」，不存在不经该函数的独立期望构造。
        assert _icon_image(icon) == _icon_image(TrayIcon._create_icon(QColor(c("brand")), "C"))

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
        # 逐项配对：每个菜单动作只转发自己的信号，不串发其它信号
        show_action, lock_action, quit_action = actions
        show_action.trigger()
        assert shown == [1] and locked == [] and quitted == []
        lock_action.trigger()
        assert locked == [1] and quitted == []
        quit_action.trigger()
        assert quitted == [1]
        assert shown == [1] and locked == [1]
