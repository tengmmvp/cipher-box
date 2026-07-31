"""``SchemaManager._validate_current_schema`` 列篡改检测测试。

覆盖 ``src/database/schema_manager.py`` 的表结构校验：``_validate_current_schema``
对每张表读 ``PRAGMA table_info`` 并比对 ``(type, notnull, pk, dflt_value)`` 四元组
（见模块 ``_TABLE_COLUMNS``）。篡改任一维度须在 ``init_tables`` 重开时抛
``SchemaError``，拒绝打开结构不符的库（不做旧格式迁移）。

复用 ``test_db_manager.py`` 的 sqlite3 seed 模式：先用 DatabaseManager 建合法库，
关闭后用原始 sqlite3 连接 ``ALTER TABLE ... DROP/ADD COLUMN`` 篡改一列，再经
DatabaseManager 重开断言 SchemaError。选 ``password_strength`` / ``metadata_mac``
等未建索引的列，避开 SQLite「DROP COLUMN 不得被索引引用」的限制。
"""

import sqlite3

import pytest

from src.database.db_manager import DatabaseManager
from src.exceptions import SchemaError


def _create_valid_db(db_path) -> None:
    """用 DatabaseManager 建立合法 schema 并关闭，留待后续篡改/重开。"""
    db = DatabaseManager(db_path, test_mode=True)
    db.open()
    db.init_tables()
    db.close()


def _tamper(db_path, *, drop: str, add_sql: str) -> None:
    """用原始 sqlite3 连接 DROP 一列后按 add_sql 重新 ADD，制造结构差异。"""
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(f"ALTER TABLE entries DROP COLUMN {drop}")
        conn.execute(add_sql)
        conn.commit()
    finally:
        conn.close()


class TestColumnTamperDetection:
    def test_init_tables_accepts_valid_unchanged_schema(self, tmp_path):
        """正对照：未篡改的合法库重开时 init_tables 不抛（非误报）。"""
        db_path = tmp_path / 'valid.db'
        _create_valid_db(db_path)

        db = DatabaseManager(db_path, test_mode=True)
        db.open()
        db.init_tables()  # 不抛
        db.close()

    def test_tampered_default_value_rejected(self, tmp_path):
        """篡改列默认值（password_strength DEFAULT 0 → 1）触发 SchemaError。

        PRAGMA table_info 的 dflt_value 从 '0' 变 '1'，与 _TABLE_COLUMNS 预期四元组
        不符。覆盖「篡改默认值」维度。
        """
        db_path = tmp_path / 'dflt.db'
        _create_valid_db(db_path)
        _tamper(
            db_path,
            drop='password_strength',
            add_sql="ALTER TABLE entries ADD COLUMN password_strength INTEGER DEFAULT 1",
        )

        db = DatabaseManager(db_path, test_mode=True)
        db.open()
        with pytest.raises(SchemaError, match='结构损坏'):
            db.init_tables()
        db.close()

    def test_tampered_column_type_rejected(self, tmp_path):
        """篡改列类型（password_strength INTEGER → TEXT）触发 SchemaError。

        覆盖「篡改类型」维度。
        """
        db_path = tmp_path / 'type.db'
        _create_valid_db(db_path)
        _tamper(
            db_path,
            drop='password_strength',
            add_sql="ALTER TABLE entries ADD COLUMN password_strength TEXT DEFAULT 0",
        )

        db = DatabaseManager(db_path, test_mode=True)
        db.open()
        with pytest.raises(SchemaError, match='结构损坏'):
            db.init_tables()
        db.close()

    def test_tampered_notnull_rejected(self, tmp_path):
        """去除 NOTNULL 约束（metadata_mac NOTNULL → 可空）触发 SchemaError。

        metadata_mac 原为 ``TEXT NOT NULL DEFAULT ''``（notnull=1）；DROP 后以
        ``TEXT DEFAULT ''``（notnull=0）重建，四元组第二位不符。覆盖「篡改 notnull」维度。
        """
        db_path = tmp_path / 'notnull.db'
        _create_valid_db(db_path)
        _tamper(
            db_path,
            drop='metadata_mac',
            add_sql="ALTER TABLE entries ADD COLUMN metadata_mac TEXT DEFAULT ''",
        )

        db = DatabaseManager(db_path, test_mode=True)
        db.open()
        with pytest.raises(SchemaError, match='结构损坏'):
            db.init_tables()
        db.close()

    def test_tampered_column_on_categories_rejected(self, tmp_path):
        """categories 表列篡改（sort_order DEFAULT 0 → 1）同样被检测。

        覆盖多表校验：非仅 entries 表，categories / password_history / vault_meta
        的列篡改均被 _validate_current_schema 的逐表循环捕获。
        """
        db_path = tmp_path / 'cat.db'
        _create_valid_db(db_path)
        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute("ALTER TABLE categories DROP COLUMN sort_order")
            conn.execute("ALTER TABLE categories ADD COLUMN sort_order INTEGER DEFAULT 1")
            conn.commit()
        finally:
            conn.close()

        db = DatabaseManager(db_path, test_mode=True)
        db.open()
        with pytest.raises(SchemaError, match='结构损坏'):
            db.init_tables()
        db.close()
