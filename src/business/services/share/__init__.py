"""限时加密共享包子包。

承载 .cboxshare 二进制头编解码/密钥派生、AES-256-GCM 加密打包、共享包文件命名约定、
自包含浏览器解密器 HTML 渲染及其非 Python 资源（hash-wasm-argon2.js / asmcrypto.js /
decrypter_template.html）等模块，经子包内分组以与 ``managers/importers/`` 子包模式对齐。
"""
