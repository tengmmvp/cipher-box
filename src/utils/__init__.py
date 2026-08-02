"""共享工具层 — 跨 UI/Business/Data 三层复用的零上层依赖基础设施。

包含文件最小权限控制（``file_security``：跨平台 ACL/原子写入/安全覆写删除/DPAPI）、
安全内存操作（``memory``）、统一时间戳与本地格式化（``format``）、批量安全删除
（``purge_files``）。本层不依赖 PyQt6（依赖 Qt 的 UI 工具归 ``src/ui/utils/``），
保持共享层可被任意上层引用。
"""
