"""share_renderer 解密器 HTML 渲染冒烟测试。

验证 ``render_decrypter`` 真实读取模板与 JS 资源并完成占位符替换——无 ``{{}}`` 残留，
含 hash-wasm argon2 / asmcrypto / 版本号。覆盖 Python 渲染器与 ``decrypter_template.html``
之间的隐式契约，防模板占位符名漂移（如 ``{{HASH_WASM_JS}}`` 误改为 ``{{HASH_WASM}}``）
致用户首次创建共享包时才暴雷。
"""

from src.business.services.share_header_codec import SHARE_VERSION
from src.business.services.share_renderer import render_decrypter


def test_render_decrypter_replaces_all_placeholders():
    """render_decrypter 真实渲染：占位符全替换，无 {{}} 残留。"""
    html = render_decrypter()
    assert "{{HASH_WASM_JS}}" not in html
    assert "{{ASMCRYPTO_JS}}" not in html
    assert "{{VERSION}}" not in html
    assert "{{" not in html  # 无任何残留占位符


def test_render_decrypter_embeds_libs_and_version():
    """渲染产物含 hash-wasm argon2、asmcrypto 与版本号字样。"""
    html = render_decrypter()
    assert "argon2" in html.lower()
    assert "asmCrypto" in html
    assert str(SHARE_VERSION) in html
