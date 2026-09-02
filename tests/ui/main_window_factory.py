"""MainWindow 测试工厂：真实构造 + stub BusinessContext（深链耦合收敛）。

此前 ``test_main_window_lifecycle`` 等用 ``MainWindow.__new__(MainWindow)`` 绕过
构造器后手工布线 10+ 私有属性——半初始化对象上任何未手工布线的属性都缺失，
MainWindow 新增依赖时测试只能靠 AttributeError 兜底发现。本工厂经真实构造链
（与 app.py 的 ``MainWindow(build_business_context(...))`` 同构）产出完整初始化
的窗口：config 用真实测试实例，vault/entry_mgr/security 等业务成员用**预配置的
MagicMock**（空库返回值），使构造期的列表/分类/状态栏初始填充可在无真实数据下
运行。测试再按需把个别协作方覆写为记录探针（实例属性赋值天然遮蔽真实属性），
不再从零布线。
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock

from src.business.composition import BusinessContext

if TYPE_CHECKING:
    from src.ui.windows.main_window import MainWindow


def make_stub_business_context(data_dir: Path) -> BusinessContext:
    """构造各业务成员为预配置 mock 的 BusinessContext（config 用真实测试实例）。

    mock 返回值面向 MainWindow 构造期的初始填充（列表/分类/标签/状态栏）与空态
    路径：条目计数 0（同步刷新分支）、分类/标签空集合、安全计数全 0（状态栏同步
    渲染，不拉起真实分析 worker）。
    """
    from tests.helpers import make_test_config

    config = make_test_config(data_dir)
    entry_mgr = MagicMock(name="entry_mgr")
    entry_mgr.get_entry_count.return_value = 0
    entry_mgr.get_entry_summaries.return_value = []
    entry_mgr.get_all_tags.return_value = []
    entry_mgr.categories.get_categories.return_value = []
    entry_mgr.categories.get_category_entry_counts.return_value = {}
    security = MagicMock(name="security")
    security.get_cached_counts.return_value = MagicMock(
        total=0, weak_count=0, duplicate_count=0, old=0
    )
    return BusinessContext(
        config=config,
        vault=MagicMock(name="vault"),
        entry_mgr=entry_mgr,
        security=security,
        import_export=MagicMock(name="import_export"),
        backup=MagicMock(name="backup"),
        change_master_rate_limiter=MagicMock(name="change_master_rate_limiter"),
    )


def make_main_window(
    data_dir: Path, *, show_tray: bool = False
) -> tuple[MainWindow, BusinessContext]:
    """真实构造的 MainWindow（stub BusinessContext 注入），返回 (window, ctx)。

    Args:
        data_dir: 测试数据目录（真实 config 落盘位置）。
        show_tray: 是否启用托盘图标（默认 False——生命周期测试通常把 ``_tray``
            覆写为探针，构造期无需真实 TrayIcon）。
    """
    from src.ui.windows.main_window import MainWindow

    ctx = make_stub_business_context(data_dir)
    if not show_tray:
        ctx.config.set("show_tray_icon", False)
    return MainWindow(ctx), ctx
