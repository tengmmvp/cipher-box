"""``_db_write`` 装饰器的失败回滚契约测试。

覆盖 ``src/database/_decorators.py`` 的 standalone 写失败回滚分支：

- ``in_transaction=False`` 时（standalone 隐式事务）调用 ``conn.rollback()`` 收尾，
  此后显式 ``BEGIN TRANSACTION`` 不再报 *"cannot start a transaction within a
  transaction"*。
- ``in_transaction=True`` 时（外层显式事务内的嵌套写）**不**在本方法 rollback，
  避免对 ``transaction()`` 上下文管理的显式事务双重 rollback。
- 两种路径均原样再抛原异常。

复用 ``tests/database/test_repository_boundaries.py`` 的真 SQLite 模式：宿主持
真实 ``sqlite3.Connection``（经 ``_CountingConn`` 代理拦截 rollback 计数），使
rollback 的效果可被直接观测（事务态翻转 + ``BEGIN`` 可重入）。
"""

import sqlite3
import threading

import pytest

from src.database._decorators import _db_write


class _StandaloneError(RuntimeError):
    """被装饰方法抛出的标记异常，断言「原异常再抛」时靠类型同一性区分。"""


class _CountingConn:
    """``sqlite3.Connection`` 的最小代理：拦截 ``rollback`` 计数，其余委托真实连接。

    sqlite3.Connection 的 ``rollback`` 属性只读，无法直接 monkeypatch；以代理包裹
    真实连接，既保留真实事务语义（``execute`` 触发的隐式事务、``in_transaction``
    翻转），又能观测装饰器是否调用了 rollback。
    """

    def __init__(self, real: sqlite3.Connection) -> None:
        self._real = real
        self.rollback_calls = 0

    def rollback(self) -> None:
        self.rollback_calls += 1
        self._real.rollback()

    def execute(self, sql: str, *args, **kwargs):
        return self._real.execute(sql, *args, **kwargs)

    def executemany(self, sql: str, *args, **kwargs):
        return self._real.executemany(sql, *args, **kwargs)

    @property
    def in_transaction(self) -> bool:
        return self._real.in_transaction

    @property
    def isolation_level(self) -> str | None:
        return self._real.isolation_level

    def close(self) -> None:
        self._real.close()


class _WriteHost:
    """满足 ``_DbWriteHost`` Protocol 的最小宿主。

    ``_conn`` 经代理持真实 ``sqlite3.Connection``（:memory:），使 rollback 真正翻转
    事务态；``in_transaction`` 由测试按场景注入，模拟 standalone 写（False）与显式
    事务内嵌套写（True）。设 ``_conn_real=None`` 模拟断连。
    """

    def __init__(self, conn: _CountingConn, *, in_transaction: bool) -> None:
        self._conn_real: _CountingConn | None = conn
        self._in_transaction = in_transaction
        self._lock_real = threading.RLock()
        self.guard_write_calls = 0

    @property
    def _conn(self) -> _CountingConn | None:
        return self._conn_real

    @property
    def _lock(self) -> threading.RLock:
        return self._lock_real

    @property
    def in_transaction(self) -> bool:
        return self._in_transaction

    def _guard_write(self) -> None:
        self.guard_write_calls += 1

    @_db_write
    def failing_write(self) -> None:
        """执行一条 DML 开启隐式事务后抛标记异常。

        CREATE TABLE / INSERT 经 sqlite3 默认 isolation_level 自动 BEGIN；抛异常时
        ``_auto_commit`` 未执行，隐式事务保持开启，正是 ``_db_write`` 回滚契约
        要处理的场景。
        """
        self._conn.execute("CREATE TABLE IF NOT EXISTS demo(x INTEGER)")
        self._conn.execute("INSERT INTO demo(x) VALUES(1)")
        raise _StandaloneError("standalone write failed")


@pytest.fixture
def conn():
    """内存 SQLite 连接（经代理包裹），事务态可直接经 ``conn.in_transaction`` 观测。"""
    proxy = _CountingConn(sqlite3.connect(":memory:"))
    yield proxy
    proxy.close()


class TestDbWriteRollbackContract:
    """_db_write 装饰器写失败回滚契约：standalone 回滚、嵌套跳过、原异常再抛三分支。"""

    def test_standalone_write_failure_rolls_back_implicit_transaction(self, conn):
        """``in_transaction=False`` 时装饰器 rollback 隐式事务，后续 BEGIN 不报错。

        无 rollback 则隐式事务保持开启，此后 ``BEGIN TRANSACTION`` 会抛
        *"cannot start a transaction within a transaction"*——这是引入回滚契约
        要根治的症状。
        """
        host = _WriteHost(conn, in_transaction=False)

        with pytest.raises(_StandaloneError):
            host.failing_write()

        # 装饰器恰好调用一次 rollback 收尾隐式事务
        assert conn.rollback_calls == 1
        # _guard_write 作为不可遗忘的写守卫被调用
        assert host.guard_write_calls == 1
        # rollback 后隐式事务已结束
        assert conn.in_transaction is False
        # 关键回归点：显式 BEGIN 不再因残留隐式事务报错
        conn.execute("BEGIN TRANSACTION")
        conn.execute("ROLLBACK")

    def test_nested_write_in_explicit_transaction_skips_rollback(self, conn):
        """``in_transaction=True`` 时不在本方法 rollback（外层事务统一处理）。

        显式事务内的嵌套写失败由 ``transaction()`` 上下文统一 rollback；若本装饰器
        再 rollback 会构成双重 rollback，干扰外层事务编排。
        """
        host = _WriteHost(conn, in_transaction=True)

        with pytest.raises(_StandaloneError):
            host.failing_write()

        # 装饰器未调用 rollback——交由外层显式事务处理
        assert conn.rollback_calls == 0
        # 隐式事务仍保持开启（未被本装饰器收尾），由外层事务负责
        assert conn.in_transaction is True
        # 显式清理，避免影响后续
        conn.rollback()

    def test_original_exception_propagates(self, conn):
        """无论是否 rollback，原异常（非包装异常）原样再抛。"""
        host = _WriteHost(conn, in_transaction=False)
        with pytest.raises(_StandaloneError, match="standalone write failed"):
            host.failing_write()


def test_db_write_raises_database_error_when_disconnected(conn):
    """``_conn`` 为 None 时装饰器抛 DatabaseError，不进入方法体。

    覆盖连接态守卫：断开连接后写方法不应静默继续，与 ``_db_operation`` 对齐。
    """
    from src.exceptions import DatabaseError

    host = _WriteHost(conn, in_transaction=False)
    host._conn_real = None  # 模拟断连：_conn property 现返回 None

    with pytest.raises(DatabaseError, match="数据库未连接"):
        host.failing_write()
    # 方法体未执行：无 rollback、无 guard_write（连接检查在 _guard_write 之前短路）
    assert conn.rollback_calls == 0
    assert host.guard_write_calls == 0
