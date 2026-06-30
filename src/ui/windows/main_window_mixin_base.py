"""MainWindow Mixin 共享工具。

从 main_window_filters 提取 ``_require_unlocked`` 守卫装饰器，供 filters 与
entries 两个 Mixin 平级 import，消除 entries → filters 的兄弟 Mixin 私有依赖
（二者本应平级，各自从本模块取共享工具，互不构成隐式前置依赖）。

跨 Mixin 方法契约清单（单一参考）：
MainWindow 经多重继承组合 ``_MainWindowEntriesMixin`` 与 ``_MainWindowFiltersMixin``，
二者经 ``self`` 跨调用对方方法。mypy 不跨 Mixin 验证这些调用（多重继承运行时解析），
故各消费方 Mixin 在 ``TYPE_CHECKING`` 下声明 stub 供局部静态分析。此清单集中记录全部
跨 Mixin 方法，作为重命名时的单一参考——重命名提供方后须同步更新消费方 stub，
否则运行时才会 ``AttributeError``（mypy 不跨 Mixin 拦截）：

  - 提供方 ``_MainWindowEntriesMixin`` → 消费方 ``_MainWindowFiltersMixin``：
    ``_add_entry``（空态「新增条目」按钮回调）
  - 提供方 ``_MainWindowFiltersMixin`` → 消费方 ``_MainWindowEntriesMixin``：
    ``_refresh_after_entry_change``（条目增删改后经防抖触发全量刷新）、
    ``_refresh_entries_only``（切换收藏等仅刷条目列表）、
    ``_refresh_categories``（分类变更后刷分类列表）

收敛取舍：filters→entries 仅 ``_add_entry`` 一个入口（空态回调），已最小；entries→filters
三个 refresh 入口对应不同刷新粒度（全量 / 仅条目 / 分类），合并会损失精细刷新能力
（如切换收藏的轻量刷新），故保留。新增跨 Mixin 方法须在此清单与消费方
``TYPE_CHECKING`` stub 同步登记。
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
