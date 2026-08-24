"""share_renderer 解密器 HTML 渲染冒烟测试。

验证 ``render_decrypter`` 真实读取模板与 JS 资源并完成占位符替换——无 ``{{}}`` 残留，
含 hash-wasm argon2 / asmcrypto / 版本号。覆盖 Python 渲染器与 ``decrypter_template.html``
之间的隐式契约，防模板占位符名漂移（如 ``{{HASH_WASM_JS}}`` 误改为 ``{{HASH_WASM}}``）
致用户首次创建共享包时才暴雷。
"""

from src.business.services.share.header_codec import SHARE_VERSION
from src.business.services.share.renderer import render_decrypter


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


def test_placeholder_in_bundle_not_replaced_second_pass(monkeypatch):
    """第三方 bundle 含 ``{{...}}`` 字面量时不被二次替换（QL-051）。

    原实现按序多次 str.replace：{{ASMCRYPTO_JS}}/{{VERSION}} 在 HASH_WASM_JS 注入
    之后替换，若 bundle 恰含同形字面量会被当作模板占位符改写。单遍 re.sub 只扫
    模板原文，注入内容不参与后续匹配。
    """
    from src.business.services.share import renderer

    template = "<html>{{HASH_WASM_JS}}|{{ASMCRYPTO_JS}}|v{{VERSION}}</html>"
    # argon2 bundle 内嵌另外两个占位名的字面量（模拟 minified 代码碰撞场景）
    argon2_js = "libA[\"{{ASMCRYPTO_JS}}\"]='{{VERSION}}';"
    asmcrypto_js = "libB();"
    resources = {
        "decrypter_template.html": template,
        "hash-wasm-argon2.js": argon2_js,
        "asmcrypto.js": asmcrypto_js,
    }
    monkeypatch.setattr(renderer, "_read_resource_text", lambda name: resources[name])

    html = render_decrypter()

    # 模板占位符全部按预期替换
    assert argon2_js in html and "libB();" in html
    assert f"v{SHARE_VERSION}</html>" in html
    # bundle 内的字面量原样保留，未被 {{ASMCRYPTO_JS}}/{{VERSION}} 轮次改写
    assert '"{{ASMCRYPTO_JS}}"' in html
    assert "'{{VERSION}}'" in html
