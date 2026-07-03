"""数据库层共享装饰器和工具函数。

将 ``_db_operation`` / ``_db_write`` 从 db_manager.py 提取到独立模块，
避免 Repository 与 DatabaseManager 之间的循环导入。
"""

import functools
import logging
import sqlite3
import threading
from collections.abc import Callable
from typing import Concatenate, ParamSpec, Protocol, TypeVar, runtime_checkable

from ..exceptions import DatabaseError

logger = logging.getLogger(__name__)

_P = ParamSpec('_P')
_R = TypeVar('_R')


@runtime_checkable
class _DbOperationHost(Protocol):
    """_db_operation/_db_write 装饰器所需宿主接口。

    DatabaseManager 与各 Repository 均满足：以 Protocol 替代 ``args[0]: Any``，配合
    Concatenate 让被装饰方法的 self 经 TypeVar bound 收敛到本协议，恢复静态检查
    （原先被装饰方法的 self 退化为 Any，_conn/_lock 访问无类型校验）。只读 property
    声明使 DatabaseManager 的实例属性与 Repository 的 property 转发均能满足。
    """

    @property
    def _conn(self) -> sqlite3.Connection | None: ...

    @property
    def _lock(self) -> threading.RLock: ...


class _DbWriteHost(_DbOperationHost, Protocol):
    """写操作宿主额外要求 _guard_write 与事务状态查询。

    ``in_transaction`` 用于 ``_db_write`` 的失败回滚契约：仅在未处显式事务时
    回滚 standalone 写的隐式事务，避免对显式事务内的嵌套写双重 rollback。
    """

    def _guard_write(self) -> None: ...

    @property
    def in_transaction(self) -> bool: ...


_H = TypeVar('_H', bound='_DbOperationHost')
_HW = TypeVar('_HW', bound='_DbWriteHost')


def _db_operation(method: Callable[Concatenate[_H, _P], _R]) -> Callable[Concatenate[_H, _P], _R]:
    """数据库读操作装饰器：获取 RLock 并校验连接状态。

    用于不修改数据的查询方法。要求被装饰的实例满足 ``_DbOperationHost``（_conn/_lock）。
    经 Concatenate + TypeVar bound 透传 self 类型，使 Pyright strict 下调用方仍能推断
    被装饰方法的精确签名（避免装饰器吞掉返回类型退化为 Any）。
    """
    @functools.wraps(method)
    def wrapper(self: _H, *args: _P.args, **kwargs: _P.kwargs) -> _R:
        if self._conn is None:
            raise DatabaseError("数据库未连接")
        with self._lock:
            return method(self, *args, **kwargs)
    return wrapper


def _db_write(method: Callable[Concatenate[_HW, _P], _R]) -> Callable[Concatenate[_HW, _P], _R]:
    """数据库写操作装饰器：获取 RLock、校验连接状态、并执行写入前校验。

    相较 ``_db_operation`` 额外调用 ``self._guard_write()``，阻止过期密钥会话继续
    写库。通过装饰器自动执行写入前校验，使写保护成为不可遗忘的默认，而非依赖每个
    写方法内部手动调用——后者分散在十余处，新增写方法时一旦遗漏即静默绕过护栏。

    失败回滚契约：被装饰的 standalone 写方法依赖 sqlite3 默认 ``isolation_level``
    的隐式事务（首条 DML 自动开事务，末尾 ``_auto_commit`` 收尾）。若方法抛异常，
    ``_auto_commit`` 不执行，隐式事务保持开启而 ``_transaction_depth`` 仍为 0，
    此后显式 ``transaction()`` 的 ``BEGIN TRANSACTION`` 会抛
    *"cannot start a transaction within a transaction"*。故 standalone 写失败时
    必须回滚隐式事务；显式事务内的嵌套写不在此回滚（由 ``transaction()`` 上下文
    统一回滚，避免双重 rollback 干扰外层事务）。

    要求被装饰的实例满足 ``_DbWriteHost``（_conn/_lock/_guard_write/in_transaction）。
    """
    @functools.wraps(method)
    def wrapper(self: _HW, *args: _P.args, **kwargs: _P.kwargs) -> _R:
        if self._conn is None:
            raise DatabaseError("数据库未连接")
        with self._lock:
            self._guard_write()
            try:
                return method(self, *args, **kwargs)
            except Exception:
                if not self.in_transaction:
                    conn = self._conn
                    if conn is not None:
                        try:
                            conn.rollback()
                        except sqlite3.Error:
                            logger.warning("写失败后回滚隐式事务失败", exc_info=True)
                raise
    return wrapper
