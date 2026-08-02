"""限时加密共享包解密器资源包。

承载非 Python 资源（hash-wasm-argon2.js + asmcrypto.js + decrypter_template.html），
经 importlib.resources 读取。需 pyproject ``package-data`` 配置随包分发——仅声明为包
（本 ``__init__.py``）不足以包含非 .py 资源。hash-wasm-argon2.js 为 hash-wasm
（MIT, (c) Dani Biro）的 argon2 UMD bundle，WASM 以 base64 内嵌，无独立 .wasm 文件；
asmcrypto.js（MIT, (c) Ágoston Pör）提供纯 JS AES-256-GCM，替代 file:// 下不可用的
WebCrypto（crypto.subtle 需安全上下文）。
"""
