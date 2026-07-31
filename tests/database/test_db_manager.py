"""DatabaseManager / SchemaManager 的错误分支与边界测试。

补充覆盖：
- ``rollback_transaction`` 对非良性 OperationalError 的再抛（对比良性 no-transaction 静默）
- ``open()`` 返回 False 的条件（非数据库文件触发 sqlite3.Error 被捕获）
- ``close()`` 在有活动事务时的回滚告警与状态归零
- ``SchemaManager._check_is_new_database`` 的 SchemaError 分支（缺 vault_meta / 错 schema_format）

这些分支在 test_database.py 的正常路径覆盖之外，需构造损坏态或替换连接对象才能触发。
"""

import logging
import sqlite3

import pytest

from src.database.db_manager import DatabaseManager
from src.exceptions import SchemaError


@pytest.fixture
def db(tmp_path):
    """临时数据库，test_mode 关闭密文断言，便于直接写测试数据。"""
    db_path = tmp_path / 'test_db_manager.db'
    database = DatabaseManager(db_path, test_mode=True)
    database.open()
    database.init_tables()
    yield database
    database.close()


class _StubConn:
    """连接桩：execute 抛指定异常，用于测试 rollback_transaction 的异常分流。

    sqlite3.Connection.execute 为只读属性，无法 monkeypatch，故替换整个连接对象。
    仅需满足 rollback_transaction / close 路径访问的方法子集。
    """

    def __init__(self, exc: BaseException):
        self._exc = exc

    def execute(self, sql: str, *args, **kwargs):
        raise self._exc

    def close(self) -> None:
        pass


# ======== rollback_transaction 异常分流 ========

def test_rollback_transaction_reraises_non_benign_operational_error(db):
    """非良性 OperationalError（database is locked）必须再抛，而非吞掉。

    覆盖 rollback_transaction 的 else 分支：磁盘满 / I/O 错误 / 数据库锁定等
    意味着回滚未生效的错误若被静默，会让调用方误以为事务已干净结束。
    """
    original_conn = db._conn
    db._conn = _StubConn(sqlite3.OperationalError('database is locked'))
    db._transaction_depth = 1
    try:
        with pytest.raises(sqlite3.OperationalError, match='database is locked'):
            db.rollback_transaction()
        # finally 块仍归零事务深度，避免状态粘滞导致后续 transaction() 误走 savepoint 分支
        assert not db.in_transaction
        assert db._savepoint_counter == 0
    finally:
        db._conn = original_conn


def test_rollback_transaction_swallows_benign_no_transaction(db):
    """良性 'no transaction active'（重复回滚 / 事务已结束）静默处理，不抛异常。

    对比上一用例：同样的 OperationalError 类型，仅因文案属于良性集合被吞掉，
    锁定 benign / non-benign 分流的边界。
    """
    original_conn = db._conn
    db._conn = _StubConn(sqlite3.OperationalError('no transaction active'))
    db._transaction_depth = 1
    try:
        db.rollback_transaction()  # 不应抛异常
        assert not db.in_transaction
        assert db._savepoint_counter == 0
    finally:
        db._conn = original_conn


# ======== open() 返回 False ========

def test_open_returns_false_for_non_database_file(tmp_path):
    """指向非数据库文件时 open 返回 False。

    sqlite3.connect 本身不立即校验文件格式（懒打开），首个 PRAGMA 读取时才抛
    ``DatabaseError: file is not a database``（sqlite3.Error 子类），被 open 的
    except 捕获后关闭连接并返回 False。
    """
    db_path = tmp_path / 'not_a_db.bin'
    # 写入足够长的垃圾数据：SQLite 头部校验需读到 100 字节魔法串，过短会被当作空库
    db_path.write_bytes(b'not a sqlite database file padding ' * 20)

    database = DatabaseManager(db_path, test_mode=True)
    assert database.open() is False
    assert not database.is_open
    # 失败路径已关闭并清空连接，避免悬挂句柄
    database.close()


# ======== close() 活动事务告警 ========

def test_close_with_active_transaction_warns_and_rolls_back(db, caplog):
    """关闭时存在未提交事务：记录告警、回滚并归零事务状态，不留状态粘滞。"""
    db.begin_transaction()
    db.set_meta('pending', 'value')  # 事务内写入，未提交
    assert db.in_transaction

    with caplog.at_level(logging.WARNING, logger='src.database.db_manager'):
        db.close()

    assert any('未提交事务' in r.message for r in caplog.records)
    assert not db.in_transaction
    assert not db.is_open


# ======== SchemaManager._check_is_new_database 的 SchemaError 分支 ========

def test_init_tables_rejects_database_missing_vault_meta(tmp_path):
    """非空库但缺 vault_meta 表时抛 SchemaError('数据库格式无效')。

    构造一个含其他表但无 vault_meta 的库（_check_is_new_database 走"非空且缺元数据表"分支）。
    """
    db_path = tmp_path / 'no_vault_meta.db'
    seed = sqlite3.connect(str(db_path))
    seed.execute('CREATE TABLE other (id INTEGER)')
    seed.commit()
    seed.close()

    database = DatabaseManager(db_path, test_mode=True)
    database.open()
    with pytest.raises(SchemaError, match='数据库格式无效'):
        database.init_tables()
    database.close()


def test_init_tables_rejects_wrong_schema_format(tmp_path):
    """vault_meta 存在但 schema_format 值不符时抛 SchemaError('不支持的数据库格式')。

    构造一个含 vault_meta 但 schema_format 为非法值的库，覆盖 _check_is_new_database
    的格式串不匹配分支。
    """
    db_path = tmp_path / 'wrong_format.db'
    seed = sqlite3.connect(str(db_path))
    seed.execute('CREATE TABLE vault_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
    seed.execute(
        "INSERT INTO vault_meta (key, value) VALUES ('schema_format', 'legacy-v0')"
    )
    seed.execute('CREATE TABLE other (id INTEGER)')
    seed.commit()
    seed.close()

    database = DatabaseManager(db_path, test_mode=True)
    database.open()
    with pytest.raises(SchemaError, match='不支持的数据库格式'):
        database.init_tables()
    database.close()
