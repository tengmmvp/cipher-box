"""font_loader 打包字体加载测试。

验证 Inter 变量字体启动注册成功，且字体缺失时记 warning 不阻塞启动（回退系统字体）。
需 QApplication（addApplicationFont 要求），经 ``qapp`` fixture 提供。
"""

from src.ui.resources import font_loader
from src.ui.resources.font_loader import load_bundled_fonts


def test_load_bundled_fonts_registers_inter(qapp):
    """Inter 变量字体随包分发，加载后注册到 QFontDatabase。"""
    families = load_bundled_fonts()
    assert families  # 非空
    assert any("Inter" in f for f in families)


def test_load_bundled_fonts_swallows_missing_font(qapp, monkeypatch):
    """字体文件缺失时不抛异常（回退系统字体，不阻断启动）。"""
    monkeypatch.setattr(font_loader, "_BUNDLED_FONTS", ("NonExistent.ttf",))
    families = load_bundled_fonts()
    assert families == []  # 无可注册 family，但不抛


def test_load_bundled_fonts_swallows_resource_error(qapp, monkeypatch):
    """资源定位/读取抛异常时（frozen/zipimport 边界）不阻塞启动，吞异常回退系统字体。

    启动关键路径用 ``except Exception`` 强兜底：任何意外异常（非仅文件缺失）都回退
    系统字体而非崩溃，故此处用 OSError 模拟覆盖 except 分支。
    """

    def raising_files(_pkg):
        raise OSError("simulated resource error")

    monkeypatch.setattr(font_loader, "files", raising_files)
    families = load_bundled_fonts()
    assert families == []  # 吞异常，回退空（系统字体）
