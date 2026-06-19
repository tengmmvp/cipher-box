"""UI 层专用工具（依赖 PyQt6）。

与跨层共享的 ``src/utils/`` 区分：此处模块依赖 PyQt6 等 UI 框架，仅 UI 层使用，
不放入 ``src/utils/`` 以保持共享层零上层依赖约定（Data/Crypto 层可安全引用 utils）。
"""
