"""导入/外流数据卫生清洗：URL scheme 白名单与表格公式注入转义。

纯函数，无状态。供导入路径（数据卫生纵深防御）、导出路径（CSV 注入防护）与
共享包打包路径（解密器 XSS 渲染限制之外的二次防御）共用，消除各路径内联清洗
逻辑的重复。

url 的真正安全边界在各渲染层（主 App ``detail_panel._build_url_label`` 与共享包
``decrypter_template.html`` 的 ``field()`` 均仅 http/https 渲染为可点击链接）。
本模块确保数据层产出的 url 统一不含危险 scheme，防未来新增「打开/复制 url」
功能时某路径数据漏网。

``sanitize_formula_prefix`` 原为 import_export 的模块级私有函数（SEC-008 入库
边界清洗），ARCH-038 导出策略拆分后 exporters 亦需复用，manager↔exporters 直接
互引会成环，故下沉本 services 层（与 sanitize_url_scheme 同属「外流数据卫生」）。
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


def sanitize_formula_prefix(value: str) -> str:
    """转义 CSV/表格公式注入危险前缀（= +/-/@/制表符），供入库与导出共享。

    把清洗点前移到入库边界（SEC-008）：导入阶段统一对受影响文本字段转义，使后续
    剪贴板复制、JSON 导出等外流路径无需各自防护即可避免表格软件公式执行。导出
    路径（exporters.base.csv_safe）复用同一逻辑作为纵深防御（覆盖非导入来源、如
    用户手建的危险前缀条目）。
    """
    if value.startswith(("=", "+", "-", "@", "\t")):
        return "'" + value
    return value


__all__ = ["URL_SCHEME_ALLOWLIST", "sanitize_formula_prefix", "sanitize_url_scheme"]
