"""共享工具层 — 跨 UI/Business/Data 三层复用的零上层依赖基础设施。

文件安全域按关注域分模块（MAINT-117）：``_platform``（平台判定常量）、``win_acl``
（Windows SID 解析与 ACL 收紧 ctypes 链）、``path_validation``（validate_file_path
路径安全校验）、``file_security``（文件权限加固/安全覆写删除/原子写入）、``dpapi``
（Windows DPAPI 封装）；另有安全内存操作（``memory``）、统一时间戳与本地格式化
（``format``）、批量安全删除（``purge_files``）、常量时间 MAC/签名比较
（``secure_compare``）。本层不依赖 PyQt6（依赖 Qt 的
UI 工具归 ``src/ui/utils/``），保持共享层可被任意上层引用。
"""
