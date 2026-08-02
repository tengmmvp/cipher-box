"""URL scheme 卫生清洗：拦截危险 scheme（javascript:/data:/file: 等）。

纯函数，无状态。供导入路径（数据卫生纵深防御）与共享包打包路径（解密器 XSS
渲染限制之外的二次防御）共用，消除两路径各自内联清洗逻辑的重复。

url 的真正安全边界在各渲染层（主 App ``detail_panel._build_url_label`` 与共享包
``decrypter_template.html`` 的 ``field()`` 均仅 http/https 渲染为可点击链接）。
本模块确保数据层产出的 url 统一不含危险 scheme，防未来新增「打开/复制 url」
功能时某路径数据漏网。
"""

import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# url scheme 白名单：保留常见安全 scheme，拒绝 javascript:/data:/file:/vbscript:
# 等被渲染层误用为可点击链接致钓鱼/协议注入的 scheme。空 scheme（裸域名）允许通过。
URL_SCHEME_ALLOWLIST = frozenset(
    {
        "http",
        "https",
        "ftp",
        "ftps",
        "ssh",
        "sftp",
        "telnet",
        "mailto",
    }
)


def sanitize_url_scheme(url: str) -> str:
    """校验 url scheme，非白名单 scheme 清空。

    非安全必需——url 的真正安全边界在各渲染层。此处为「数据卫生」的一致性纵深
    防御：使导入与共享打包产出的 url 统一不含危险 scheme。空 scheme（裸域名）允许
    通过，UI 点击时按默认 http 处理。
    """
    if not url:
        return url
    scheme = urlparse(url).scheme.lower()
    if scheme and scheme not in URL_SCHEME_ALLOWLIST:
        logger.warning("URL 含非白名单 scheme：%s，已清空该字段", scheme)
        return ""
    return url


__all__ = ["URL_SCHEME_ALLOWLIST", "sanitize_url_scheme"]
