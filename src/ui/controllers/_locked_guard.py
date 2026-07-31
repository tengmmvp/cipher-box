"""组合化控制器的锁定态守卫（项目唯一锁定态守卫）。

读组合化 controller 自有的 ``_locked`` 属性，由 host 经 ``set_locked()`` /
``prepare_for_lock()`` 广播。原 MainWindow Mixin 的 ``_require_unlocked``（读宿主
``_locked_ui``）已随三个 Mixin 全部迁为组合化 controller 而删除，本模块统一承载
MenuController / EntryActionsController / ListRefreshController 的锁定态守卫。
"""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import Any


def require_unlocked(method: Callable[..., None]) -> Callable[..., None]:
    """装饰方法：controller 锁定态（``_locked=True``）时跳过执行。

    锁定后主密钥已清零，被装饰方法访问 entry_mgr/totp/clipboard 会崩溃或读到
    无效数据。集中守卫消除多处 ``if self._locked: return`` 的重复。被装饰方法
    均为 Qt 槽或操作回调、返回 None，故守卫特化为 ``Callable[..., None]``——锁定态
    ``return None`` 与正常态调用均得 None，签名诚实，无需 ``type: ignore`` 压制
    返回类型。对 Qt 信号连接透明（PyQt6 信号连接不严格检查槽签名，wrapper 经
    ``*args`` 透传信号参数）。
    """

    @wraps(method)
    def wrapper(self: Any, *args: Any, **kwargs: Any) -> None:
        if self._locked:
            return None
        method(self, *args, **kwargs)

    return wrapper
