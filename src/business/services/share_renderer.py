"""限时加密共享包解密器 HTML 渲染。

读取模板与 hash-wasm 的 argon2 UMD bundle（含内嵌 WASM），将 JS 内嵌
decrypter_template.html，生成接收方零安装、零联网的自包含浏览器解密器。资源缺失
（开发期未就绪或打包配置遗漏）时抛 :class:`ShareError`，使缺失在生成共享包时显性
失败而非静默产出坏文件。

hash-wasm（MIT, (c) Dani Biro）的 argon2 实现把 WASM 以 base64 内嵌 UMD bundle，故
无独立 .wasm 文件——内嵌 ``hash-wasm-argon2.js`` 即含运行所需全部代码，浏览器经
``hashwasm.argon2id({...})`` 调用（全局名 ``hashwasm``）。
"""

import logging
from importlib.resources import files

from ...exceptions import ShareError
from .share_header_codec import SHARE_VERSION

logger = logging.getLogger(__name__)

# 资源包路径：hash-wasm-argon2.js 与 decrypter_template.html 所在包（经 pyproject
# package-data 分发；packages.find 仅收集 .py，非 Python 资源须显式声明）。
_RESOURCE_PACKAGE = "src.business.services.share_resources"


def _read_resource_text(name: str) -> str:
    """读取资源文本，缺失时抛 ShareError。"""
    try:
        return (files(_RESOURCE_PACKAGE) / name).read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError) as exc:
        raise ShareError(f"解密器资源缺失：{name}") from exc


def render_decrypter() -> str:
    """渲染自包含解密器 HTML：模板占位替换为 hash-wasm argon2 JS、asmcrypto JS 与版本号。"""
    template = _read_resource_text("decrypter_template.html")
    argon2_js = _read_resource_text("hash-wasm-argon2.js")
    asmcrypto_js = _read_resource_text("asmcrypto.js")
    return (
        template.replace("{{HASH_WASM_JS}}", argon2_js)
        .replace("{{ASMCRYPTO_JS}}", asmcrypto_js)
        .replace("{{VERSION}}", str(SHARE_VERSION))
    )


__all__ = ["render_decrypter"]
