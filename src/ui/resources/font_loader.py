"""打包字体加载 — 启动时将 Inter 注册到 QFontDatabase。

Inter 以 variable font 形式打包，启动经 :func:`load_bundled_fonts` 注册后，
``QFont("Inter")`` 与 QSS ``font-family: "Inter"`` 可用，``setWeight`` / ``font-weight``
经 variable axis 精确生效。加载失败不阻塞启动——字体栈回退系统字体
（Microsoft YaHei UI / PingFang SC / Noto Sans CJK SC）。

调用时机：必须在 ``QApplication`` 创建之后、任何 ``QWidget`` 构造之前
（``CipherBoxApp.__init__`` 内 ``configure_logging`` 之后），否则首屏字面仍是回退字体。
"""

import logging
from importlib.resources import files

from PyQt6.QtGui import QFontDatabase

logger = logging.getLogger(__name__)

# 打包字体文件名；variable font 单文件覆盖全部 weight。
_BUNDLED_FONTS: tuple[str, ...] = ("Inter-Variable.ttf",)


def load_bundled_fonts() -> list[str]:
    """加载打包字体，返回成功注册的 family 列表（供诊断日志）。

    用 ``files(__package__) / "fonts"`` 相对定位字体包：随本模块位置自动跟随，对包重命名
    健壮。单文件加载失败记 ``warning`` 并继续，绝不抛出——字体缺失应回退系统字体而非阻断启动。
    """
    added: list[str] = []
    assert __package__ is not None  # 包内模块恒非 None；收窄 pyright 的 str|None 推断
    for name in _BUNDLED_FONTS:
        try:
            font_path = files(__package__) / "fonts" / name
            font_id = QFontDatabase.addApplicationFont(str(font_path))
        except Exception:
            logger.warning("加载打包字体失败：%s", name, exc_info=True)
            continue
        if font_id == -1:
            logger.warning("打包字体无法注册到 QFontDatabase：%s", name)
            continue
        added.extend(QFontDatabase.applicationFontFamilies(font_id))
    if added:
        logger.info("已加载打包字体：%s", ", ".join(added))
    return added
