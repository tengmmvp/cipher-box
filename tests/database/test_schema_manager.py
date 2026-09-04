"""``SchemaManager._validate_current_schema`` 列篡改检测与查询计划守护测试。

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
from src.database.entry_repository import (
    _SELECT_ENTRY_WITH_CATEGORY_SQL,
    EntryRepository,
)
from src.database.types import EntryQuery
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
    """_validate_current_schema 列篡改检测：默认值/类型/notnull/多表四维篡改均触发 SchemaError，含正对照。"""

    def test_init_tables_accepts_valid_unchanged_schema(self, tmp_path):
        """正对照：未篡改的合法库重开时 init_tables 不抛（非误报）。"""
        db_path = tmp_path / "valid.db"
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
        db_path = tmp_path / "dflt.db"
        _create_valid_db(db_path)
        _tamper(
            db_path,
            drop="password_strength",
            add_sql="ALTER TABLE entries ADD COLUMN password_strength INTEGER DEFAULT 1",
        )

        db = DatabaseManager(db_path, test_mode=True)
        db.open()
        with pytest.raises(SchemaError, match="结构损坏"):
            db.init_tables()
        db.close()

    def test_tampered_column_type_rejected(self, tmp_path):
        """篡改列类型（password_strength INTEGER → TEXT）触发 SchemaError。

        覆盖「篡改类型」维度。
        """
        db_path = tmp_path / "type.db"
        _create_valid_db(db_path)
        _tamper(
            db_path,
            drop="password_strength",
            add_sql="ALTER TABLE entries ADD COLUMN password_strength TEXT DEFAULT 0",
        )

        db = DatabaseManager(db_path, test_mode=True)
        db.open()
        with pytest.raises(SchemaError, match="结构损坏"):
            db.init_tables()
        db.close()

    def test_tampered_notnull_rejected(self, tmp_path):
        """去除 NOTNULL 约束（metadata_mac NOTNULL → 可空）触发 SchemaError。

        metadata_mac 原为 ``TEXT NOT NULL DEFAULT ''``（notnull=1）；DROP 后以
        ``TEXT DEFAULT ''``（notnull=0）重建，四元组第二位不符。覆盖「篡改 notnull」维度。
        """
        db_path = tmp_path / "notnull.db"
        _create_valid_db(db_path)
        _tamper(
            db_path,
            drop="metadata_mac",
            add_sql="ALTER TABLE entries ADD COLUMN metadata_mac TEXT DEFAULT ''",
        )

        db = DatabaseManager(db_path, test_mode=True)
        db.open()
        with pytest.raises(SchemaError, match="结构损坏"):
            db.init_tables()
        db.close()

    def test_tampered_column_on_categories_rejected(self, tmp_path):
        """categories 表列篡改（sort_order DEFAULT 0 → 1）同样被检测。

        覆盖多表校验：非仅 entries 表，categories / password_history / vault_meta
        的列篡改均被 _validate_current_schema 的逐表循环捕获。
        """
        db_path = tmp_path / "cat.db"
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
        with pytest.raises(SchemaError, match="结构损坏"):
            db.init_tables()
        db.close()


class TestQueryPlanIndexPushdown:
    """热路径查询计划守护（PERF-090/091/095）：ORDER BY/GROUP BY 不得退化为 TEMP B-TREE。

    SQL 经生产构造路径（``EntryRepository._entry_query_clauses``）拼出，计划断言
    锚定「索引序直接满足排序/分组」：一旦 ORDER BY 子句形态或索引定义漂移使计划
    退化（如 PERF-087 并列裁决键无条件追加导致 SEARCH + USE TEMP B-TREE FOR
    ORDER BY 的回归），此处在 CI 即失败，无需 50k 行基准才能发现。
    """

    @pytest.fixture
    def db_with_entries(self, tmp_path):
        """建库并撒少量行（计划选择与行数无关，覆盖索引/排序下推判定即可）。"""
        db = DatabaseManager(tmp_path / "plan.db", test_mode=True)
        db.open()
        db.init_tables()
        conn = db.connection
        conn.executemany(
            "INSERT INTO entries (crypto_id, title_enc, category_id, is_deleted,"
            " is_favorite, updated_at, created_at, metadata_mac)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    f"cid-{i}",
                    "cb2:t",
                    (i % 3) + 1,
                    int(i % 4 == 0),
                    int(i % 2 == 0),
                    f"2026-01-01T00:00:{i:02d}+00:00",
                    "2026-01-01T00:00:00+00:00",
                    "mac",
                )
                for i in range(12)
            ],
        )
        conn.commit()
        yield db
        db.close()

    @staticmethod
    def _plan_details(conn, sql: str, params: list) -> list[str]:
        return [str(row[-1]) for row in conn.execute("EXPLAIN QUERY PLAN " + sql, params)]

    @pytest.mark.parametrize(
        ("order_by", "expected_index"),
        [
            ("updated_at", "idx_entries_active_updated"),
            ("created_at", "idx_entries_active_created"),
        ],
    )
    def test_field_order_uses_index(self, db_with_entries, order_by, expected_index):
        """字段序 SQL 直连路径：索引序下推，无 TEMP B-TREE（PERF-090/095）。

        PERF-087 曾无条件在排序列后追加并列裁决键，使 ORDER BY 不再是
        idx_entries_active_updated 的索引前缀、退化为 filesort（50k 库实测
        81.2ms vs 索引序 0.6ms，且该路径在 UI 线程同步执行）。created_at 序为
        PERF-095 补的 idx_entries_active_created：原无对应索引时走 is_deleted
        过滤 + USE TEMP B-TREE FOR ORDER BY（50k 实测 68.8ms 全扫排序），补后
        索引前缀直接满足纯单列序（4.3ms，16×）。两个 limit 常量锚定两个真实
        调用点（近期更新视图 100 / 主列表字段序 1000）；limit 不参与断言，
        parametrize 仅为两个调用点各留一档守护。
        """
        for limit in (100, 1000):
            sql, params = EntryRepository._entry_query_clauses(
                EntryQuery(order_by=order_by, limit=limit)
            )
            details = self._plan_details(
                db_with_entries.connection, _SELECT_ENTRY_WITH_CATEGORY_SQL + sql, params
            )
            assert any(expected_index in d for d in details)
            assert not any("TEMP B-TREE" in d for d in details)

    def test_category_view_point_query_uses_index(self, db_with_entries):
        """分类视图点查：两列等值 + updated_at 序走三列复合索引（PERF-095）。

        原 planner 仅能用 (is_deleted) 前缀扫描全部未删除行过滤 category_id
        （50k 实测分类视图 updated_at 序 42.0ms、分类+搜索 tie-break 窄投影
        37.4ms），补 idx_entries_active_category_updated 后前缀同时满足过滤与
        排序（3.9ms / 2.5ms）。默认复合序（is_favorite 优先）分支 planner 仍
        选 idx_entries_active_favorite_updated 全扫属估算行为（现状可接受），
        不在守护范围。
        """
        sql, params = EntryRepository._entry_query_clauses(
            EntryQuery(category_id=2, order_by="updated_at", limit=1000)
        )
        details = self._plan_details(
            db_with_entries.connection, _SELECT_ENTRY_WITH_CATEGORY_SQL + sql, params
        )
        assert any("idx_entries_active_category_updated" in d for d in details)
        assert not any("TEMP B-TREE" in d for d in details)

    def test_category_entry_count_uses_covering_index(self, db_with_entries):
        """单分类计数：走 (is_deleted, category_id) 覆盖索引（PERF-095 守护）。

        SQL 与 CategoryRepository.get_category_entry_count 同文（该处内联 SQL，
        此处以注释锚定同步义务）。计数形态由 PERF-091 的两列覆盖索引与 PERF-095
        三列索引共享前两列前缀服务（planner 实测选更窄的两列索引），断言两者
        任一的非全扫计划，防索引再平衡漂移使其退化为全表扫描。
        """
        sql = "SELECT COUNT(*) FROM entries WHERE category_id=? AND is_deleted=0"
        details = self._plan_details(db_with_entries.connection, sql, [2])
        assert any(
            ("idx_entries_deleted_category" in d or "idx_entries_active_category_updated" in d)
            and "COVERING INDEX" in d
            for d in details
        )

    def test_main_list_default_compound_order_uses_index(self, db_with_entries):
        """主列表默认复合序（is_favorite DESC, updated_at DESC）：PERF-011 索引守护。"""
        sql, params = EntryRepository._entry_query_clauses(EntryQuery(limit=1000))
        details = self._plan_details(
            db_with_entries.connection, _SELECT_ENTRY_WITH_CATEGORY_SQL + sql, params
        )
        assert any("idx_entries_active_favorite_updated" in d for d in details)
        assert not any("TEMP B-TREE" in d for d in details)

    def test_category_counts_group_by_uses_covering_index(self, db_with_entries):
        """分类计数 GROUP BY：覆盖索引免排序分组，无 TEMP B-TREE（PERF-091）。

        SQL 与 CategoryRepository.get_category_entry_counts 同文（该处私有常量，
        此处以注释锚定同步义务）。修复前仅 idx_entries_deleted 覆盖过滤，分组走
        USE TEMP B-TREE FOR GROUP BY（50k 库实测 49.8ms，UI 线程防抖刷新内执行）。
        """
        sql = (
            "SELECT category_id, COUNT(*) AS entry_count FROM entries "
            "WHERE is_deleted=0 AND category_id IS NOT NULL GROUP BY category_id"
        )
        details = self._plan_details(db_with_entries.connection, sql, [])
        assert any("idx_entries_deleted_category" in d and "COVERING INDEX" in d for d in details)
        assert not any("TEMP B-TREE" in d for d in details)


class TestExistingDatabaseIndexBackfill:
    """既有库索引幂等补建（PERF-095）：索引演进不使既有库重开被误报「损坏」。

    索引是查询衍生物（不含数据语义），既有库启动时对 _INDEX_DEFINITIONS 缺失项
    补建 IF NOT EXISTS——schema_format 与表结构不变，属 schema 完善而非旧格式迁移。
    """

    def test_existing_db_with_missing_new_index_opens_after_backfill(self, tmp_path):
        """缺新索引（模拟索引演进前的既有库）→ 重开自动补建并验证通过，不抛 SchemaError。"""
        from src.database.db_manager import DatabaseManager

        db_path = tmp_path / "vault.db"
        first = DatabaseManager(db_path, test_mode=True)
        first.open()
        first.init_tables()
        try:
            # 模拟「索引演进前的既有库」：正常建库后删除本轮新增索引之一
            conn = first.connection
            conn.execute("DROP INDEX idx_entries_active_created")
            first.auto_commit()
        finally:
            first.close()

        # 修复前：init_tables 的验证直接抛 SchemaError（索引结构损坏）
        second = DatabaseManager(db_path, test_mode=True)
        second.open()
        second.init_tables()  # 幂等补建 + 验证通过
        try:
            names = {
                row["name"]
                for row in second.connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='index'"
                ).fetchall()
            }
            assert "idx_entries_active_created" in names  # 已被幂等补建
        finally:
            second.close()
            second.close()

    def test_backfill_duplicate_crypto_id_raises_schema_error(self, tmp_path):
        """QL-080：既有库存在重复 crypto_id 时，UNIQUE 索引补建失败归一为 SchemaError。

        数据层违规只在 CREATE UNIQUE INDEX 时暴露，须翻译为含索引名的结构损坏文案。
        """
        db_path = tmp_path / "dup-crypto-id.db"
        _create_valid_db(db_path)
        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute("DROP INDEX idx_entries_crypto_id")
            # 列均有 DEFAULT，最小行即可；两条同 crypto_id 行仅在索引缺失时合法
            conn.executemany(
                "INSERT INTO entries (crypto_id, title_enc, metadata_mac) VALUES (?, ?, ?)",
                [("dup-crypto", "cb2:t", "mac"), ("dup-crypto", "cb2:t", "mac")],
            )
            conn.commit()
        finally:
            conn.close()

        db = DatabaseManager(db_path, test_mode=True)
        db.open()
        try:
            with pytest.raises(SchemaError, match="无法补建索引"):
                db.init_tables()
        finally:
            db.close()
