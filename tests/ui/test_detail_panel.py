"""``DetailPanel._build_url_label`` 的 scheme 白名单与注入防护测试。

覆盖 ``src/ui/components/detail_panel.py::_build_url_label``：
- http/https 渲染为可点击 ``<a href=...>`` 链接（RichText + 外链交互）。
- javascript:/file:/data: 等非白名单 scheme 渲染为纯文本（无链接），防止 XSS。
- URL 含 ``<>"'`` 等特殊字符时经 ``html.escape`` 转义，不破坏 ``<a>`` 标签结构、
  不注入 markup。

``_build_url_label`` 不读实例状态，经 ``DetailPanel.__new__`` 裸实例直接调用，
避免完整 ``__init__`` 的控件树装配开销。``QLabel`` 构造需 QApplication，用 conftest
的 ``qapp`` fixture。
"""

import pytest
from PyQt6.QtCore import Qt

from src.ui.components.detail_panel import DetailPanel


def _make_panel() -> DetailPanel:
    """构造跳过 __init__ 的 DetailPanel 裸实例（_build_url_label 不依赖实例状态）。"""
    return DetailPanel.__new__(DetailPanel)


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "https://example.com/path?q=1",
        "HTTPS://EXAMPLE.COM",  # 大写 scheme 也应识别（.lower() 归一化）
    ],
)
def test_http_https_url_renders_as_link(qapp, url):
    """http/https scheme 渲染含 ``<a href=`` 的可点击链接。"""
    label = _make_panel()._build_url_label(url)

    text = label.text()
    assert "<a href=" in text
    assert label.textFormat() == Qt.TextFormat.RichText
    # 安全文档启用外链交互（TextBrowserInteraction + setOpenExternalLinks）
    assert label.textInteractionFlags() == Qt.TextInteractionFlag.TextBrowserInteraction
    assert label.openExternalLinks() is True


@pytest.mark.parametrize(
    "url",
    [
        "javascript:alert(1)",  # XSS 经典向量
        "file:///etc/passwd",  # 本地文件读取
        "data:text/html,<script>",  # data URI
        "vbscript:msgbox(1)",  # 另一种脚本 scheme
    ],
)
def test_non_http_scheme_renders_as_plain_text_without_link(qapp, url):
    """非白名单 scheme 渲染纯文本，无 ``<a>`` 链接，防脚本/文件 scheme 注入。"""
    label = _make_panel()._build_url_label(url)

    text = label.text()
    assert "<a " not in text
    assert "href=" not in text
    # 仍为 RichText（统一格式），但内容是转义后的纯文本
    assert label.textFormat() == Qt.TextFormat.RichText
    # 非安全 scheme 不启用外链交互
    assert label.openExternalLinks() is False


def test_url_with_special_chars_is_escaped_not_breaking_tag(qapp):
    """含 ``<>"'`` 的 URL 经转义，不破坏 ``<a>`` 标签结构、不注入 markup。

    href 用 ``urllib.parse.quote`` 编码（保留 URL 结构字符），显示文本用
    ``html.escape(quote=True)`` 转义——双重保护：href 内的特殊字符被 quote 处理，
    显示文本中的 ``<`` 变 ``&lt;``，杜绝标签逃逸。
    """
    url = 'https://example.com/<script>alert("x")</script>'
    label = _make_panel()._build_url_label(url)

    text = label.text()
    # 渲染为链接
    assert text.count("<a ") == 1
    assert text.count("</a>") == 1
    # 原始 ``<script>`` 不得作为 markup 出现（已转义为 &lt;script&gt;）
    assert "<script>" not in text
    assert "&lt;script&gt;" in text
    # 恰好一个 <a 开标签（无注入额外标签）
    assert text.startswith("<a href=")


def test_empty_scheme_url_treated_as_plain_text(qapp):
    """无 scheme（裸域名/相对路径）的 URL 不渲染为链接。

    urlparse 对 'example.com' 解析得 scheme=''，不在白名单 → 纯文本。
    """
    label = _make_panel()._build_url_label("example.com/path")

    assert "<a " not in label.text()


def test_link_contains_href_and_styled(qapp):
    """http 链接含 href 属性与内联样式（颜色取自主题 link token）。"""
    label = _make_panel()._build_url_label("https://example.com")

    text = label.text()
    assert 'href="https://example.com"' in text
    assert "text-decoration:none" in text
