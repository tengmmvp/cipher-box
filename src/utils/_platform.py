"""utils 子包共享的平台判定常量（MAINT-117 拆分自 file_security）。

file_security 按关注域拆为 win_acl/path_validation/file_security/dpapi 后，
四个子模块均需平台判定；常量集中本模块定义一次、各模块 ``from ._platform
import IS_WINDOWS`` 引入同一对象，保持「单一常量、统一引用」纪律（在任一消费
模块重复定义会造成多源漂移面）。测试对某模块打桩平台语义时，monkeypatch 该模块
自身的 ``IS_WINDOWS`` 绑定——import 引入的名字在各消费模块命名空间独立绑定，
patch 仅影响目标模块，不污染其它消费方。
"""

import sys

# 平台判定单一常量（MAINT-012）：统一引用，避免 os.name=='nt' 与 sys.platform=='win32' 混用致跨平台漂移。
IS_WINDOWS = sys.platform == "win32"
