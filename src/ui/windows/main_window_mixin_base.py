"""MainWindow Mixin 共享工具。

从 main_window_filters 提取 ``_require_unlocked`` 守卫装饰器，供 filters 与
entries 两个 Mixin 平级 import，消除 entries → filters 的兄弟 Mixin 私有依赖
（二者本应平级，各自从本模块取共享工具，互不构成隐式前置依赖）。
"""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import Any, TypeVar

_F = TypeVar('_F')


def _require_unlocked(method: Callable[..., _F]) -> Callable[..., _F]:
    """装饰方法：锁定态（``_locked_ui=True``）时跳过执行。

    锁定后主密钥已清零，被装饰方法访问 entry_mgr/totp/clipboard 会崩溃或读到
    无效数据。集中守卫消除多处 ``if self._locked_ui: return`` 的重复。锁定态
    返回 None——被装饰方法均为 Qt 槽或操作回调，无返回值或调用方不依赖锁定态
    的返回值，与原内联守卫语义一致；对 Qt 信号连接透明（PyQt6 信号连接不严格
    检查槽签名，wrapper 经 ``*args`` 透传信号参数）。
    """
    @wraps(method)
    def wrapper(self: Any, *args: Any, **kwargs: Any) -> _F:
        if self._locked_ui:
            return None  # type: ignore[return-value]
        return method(self, *args, **kwargs)
    return wrapper
