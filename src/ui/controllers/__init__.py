"""组合化 controller 子包：将主窗口的数据到控件映射与生命周期逻辑拆分到普通类。

每个 controller 为普通类（非 QObject）：``__init__`` 注入 manager 与跨 controller
回调（冻结 dataclass），``setup(parent, view)`` 接收 QObject 父与冻结 dataclass
view-handle 后连接控件信号。跨 controller 协作一律经冻结 dataclass 回调，pyright
在 host 装配点逐字段校验绑定方法名与签名。

锁定态守卫统一承载于 ``_locked_guard`` 的 ``require_unlocked`` 装饰器——锁定后主密钥
已清零，被装饰方法访问 entry_mgr/totp/clipboard 会崩溃或读到无效数据，集中守卫消除
多处 ``if self._locked: return`` 的重复。``MenuController`` 不经此守卫：其菜单入口经
主窗口锁定态直接禁用/隐藏隔离。
"""
