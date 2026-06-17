"""数据库层共享装饰器和工具函数。

将 ``_db_operation`` / ``_db_write`` 从 db_manager.py 提取到独立模块，
避免 Repository 与 DatabaseManager 之间的循环导入。
"""

import functools
import logging
from typing import Any, Callable, ParamSpec, TypeVar

from ..exceptions import DatabaseError

logger = logging.getLogger(__name__)

_P = ParamSpec('_P')
_R = TypeVar('_R')


def _db_operation(method: Callable[_P, _R]) -> Callable[_P, _R]:
    """数据库读操作装饰器：获取 RLock 并校验连接状态。

    用于不修改数据的查询方法。要求被装饰的实例拥有 ``_conn`` 和 ``_lock`` 属性。

    使用 ``ParamSpec`` 透传被装饰方法的参数与返回类型，使 Pyright strict 下
    调用方仍能推断被装饰方法的精确签名（避免装饰器吞掉返回类型退化为 Any）。
    """
    @functools.wraps(method)
    def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        # 被装饰的是实例方法，args[0] 为 self（EntryRepository / CategoryRepository /
        # DatabaseManager）。以 Any 访问其 _conn/_lock，类型安全由被装饰类自身保证。
        instance: Any = args[0]
        if instance._conn is None:
            raise DatabaseError("数据库未连接")
        with instance._lock:
            return method(*args, **kwargs)
    return wrapper


def _db_write(method: Callable[_P, _R]) -> Callable[_P, _R]:
    """数据库写操作装饰器：获取 RLock、校验连接状态、并执行写入前校验。

    相较 ``_db_operation`` 额外调用 ``self._guard_write()``，阻止过期密钥
    会话继续写库。通过装饰器自动执行写入前校验，使写保护成为不可遗忘的
    默认，而非依赖每个写方法内部手动调用 ``self._guard_write()``——后者
    分散在十余处，新增写方法时一旦遗漏即静默绕过护栏。

    要求被装饰的实例拥有 ``_conn``、``_lock`` 与 ``_guard_write`` 属性/方法。
    """
    @functools.wraps(method)
    def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        instance: Any = args[0]
        if instance._conn is None:
            raise DatabaseError("数据库未连接")
        with instance._lock:
            instance._guard_write()
            return method(*args, **kwargs)
    return wrapper
