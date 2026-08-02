"""限时加密共享包解密器 HTML 渲染。

读取模板与 hash-wasm 的 argon2 UMD bundle（含内嵌 WASM），将 JS 内嵌
decrypter_template.html，生成接收方零安装、零联网的自包含浏览器解密器。资源缺失
（开发期未就绪或打包配置遗漏）时抛 :class:`ShareError`，使缺失在生成共享包时显性
失败而非静默产出坏文件。

hash-wasm（MIT, (c) Dani Biro）的 argon2 实现把 WASM 以 base64 内嵌 UMD bundle，故
无独立 .wasm 文件——内嵌 ``hash-wasm-argon2.js`` 即含运行所需全部代码，浏览器经
``hashwasm.argon2id({...})`` 调用（全局名 ``hashwasm``）。

asmcrypto.js（MIT, (c) Ágoston Pör）选用理据：解密器在 ``file://`` 协议下打开时浏览器
禁用 ``crypto.subtle``（WebCrypto 要求安全上下文），故以 asmcrypto 的纯 JS AES-256-GCM
实现替代 WebCrypto，使 ``decrypt.html`` 双击即用、无需联网或本地服务。
"""

import logging
from importlib.resources import files

from ...exceptions import ShareError
from .share_header_codec import SHARE_VERSION

logger = logging.getLogger(__name__)


def _read_resource_text(name: str) -> str:
    """读取资源文本，缺失时抛 ShareError。

    用 ``files(__package__) / "share_resources"`` 相对定位资源包：随本模块位置自动跟随，
    对包重命名健壮（绝对包名字符串会在重命名后运行期才暴雷）。资源经 pyproject package-data
    分发（packages.find 仅收集 .py，非 Python 资源须显式声明）。
    """
    try:
        assert __package__ is not None  # 包内模块恒非 None；收窄 pyright 的 str|None 推断
        return (files(__package__) / "share_resources" / name).read_text(encoding="utf-8")
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
