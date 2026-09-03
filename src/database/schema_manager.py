"""数据库 schema 创建与验证。

职责单一：数据库表结构的初始化与校验，经 DatabaseManager 委托提供统一数据访问接口。
"""

import sqlite3
import threading

from ..exceptions import DatabaseError, SchemaError
from ..models import ENTRY_TYPE_LOGIN
from ..utils.format import utc_now_iso
from .types import ConnectionProvider

# 索引定义：CREATE INDEX 与 _validate_current_schema 的单一事实源，新增索引只需在此
# 追加，建表与校验自动跟随，避免两份硬编码漂移。
# tuple 形式：(索引名, 表名, 列定义, 是否 UNIQUE)
#
# PERF-095 索引再平衡（删 4 补 2，净 10→8，50k 库实测）：
# - 删 idx_entries_favorite / idx_entries_updated / idx_entries_type /
#   idx_entries_password_changed：前两者被复合索引前缀覆盖（收藏视图的
#   ``is_deleted=0 AND is_favorite=1`` 恒走 idx_entries_active_favorite_updated
#   两列等值、全部 updated_at 序恒走 idx_entries_active_updated，EXPLAIN 证实
#   planner 从不选单列索引），后两者全库零谓词消费（entry_type /
#   password_changed_at 无 WHERE 查询，过期检测在内存按解密值计算）——四者均为
#   纯写放大（50k UPDATE 实测 5690→3460ms，−39%；empty_trash DELETE 141→74ms）。
# - 保留 idx_entries_deleted（原候选删除项）：删除后 planner 对全表回表扫描形态
#   （标签投影 / 分析扫描 / strength 序 filesort 的源扫描）改选复合索引前缀，
#   回表行序从 rowid 序（近顺序 IO）变为复合键序（随机 IO），50k 实测标签投影
#   74→228ms、分析扫描 243→382ms、strength tie-break 64→205ms；而保留它的额外
#   写成本仅 ~1%（INSERT 50k 1991 vs 2018ms）。回收站视图（is_deleted=1）与
#   empty_trash 本就不依赖它（planner 恒选复合索引的 is_deleted 前缀）。
# - 补 idx_entries_active_created / idx_entries_active_category_updated（见下方
#   各自注释）。
# - 已知 planner 误选（记录不强改，与 PERF-091 批次「估算行为可接受」口径一致）：
#   分类视图 + created_at 序会误选 idx_entries_active_created 全扫过滤（50k 实测
#   24→50ms），而非走 idx_entries_active_category_updated 前缀定位 + filesort；
#   属非默认排序 × 分类过滤的低频组合形态，绝对值可接受，加第四列索引的写放大
#   不划算。
_INDEX_DEFINITIONS: list[tuple[str, str, tuple[str, ...], bool]] = [
    ("idx_entries_category", "entries", ("category_id",), False),
    # 单列 is_deleted 索引的现役价值不止等值过滤（回收站/计数形态 planner 恒选复合
    # 索引的 is_deleted 前缀，PERF-095 实测）：它是全表回表扫描形态（标签投影/
    # 分析扫描/无前缀匹配的 filesort 源扫描）唯一提供 rowid 有序访问的 is_deleted
    # 索引——复合索引的键序使回表随机化（详见上方 PERF-095 注释），故再平衡中保留。
    ("idx_entries_deleted", "entries", ("is_deleted",), False),
    # 复合索引：服务 WHERE is_deleted=0 + ORDER BY updated_at DESC，单列索引无法同时
    # 覆盖过滤与排序，组合后让 SQLite 走索引扫描而非全表 + filesort。
    (
        "idx_entries_active_updated",
        "entries",
        ("is_deleted", "updated_at DESC"),
        False,
    ),
    # PERF-011：默认列表视图 ORDER BY is_favorite DESC, updated_at DESC 的复合索引，
    # 免 filesort。与 idx_entries_active_updated 共存（后者服务「近期更新」视图）。
    (
        "idx_entries_active_favorite_updated",
        "entries",
        ("is_deleted", "is_favorite DESC", "updated_at DESC"),
        False,
    ),
    # PERF-095：created_at 排序 SQL 直连路径（PERF-090 纯单列序，无并列裁决键）的
    # 复合索引，与 idx_entries_active_updated 同模式。原无对应索引时 planner 只能
    # 走 is_deleted 过滤 + USE TEMP B-TREE FOR ORDER BY（50k 实测 68.8ms 全扫排序），
    # 补后索引序直接满足 ``ORDER BY e.created_at DESC``（4.3ms，16×）——纯单列序与
    # 本索引前缀完全匹配，不与 PERF-090 的「裁决键会破坏索引前缀」论证冲突。
    # password_strength 序不补（审查结论：基数仅 0-4 并列极常见，索引收益有限）。
    (
        "idx_entries_active_created",
        "entries",
        ("is_deleted", "created_at DESC"),
        False,
    ),
    # PERF-095：分类视图查询的复合索引——``WHERE is_deleted=0 AND category_id=?``
    # 两列等值定位 + updated_at DESC 排序由同一索引前缀满足。原 planner 只能用
    # (is_deleted) 前缀扫描全部未删除行过滤 category_id（50k 实测分类视图
    # updated_at 序 42.0ms、分类+搜索 tie-break 窄投影 37.4ms），补后分别 3.9ms
    # （10.7×）与 2.5ms（15×）；tie-break 形态（首键 updated_at）经本索引前缀
    # 排序 + RIGHT PART OF ORDER BY 的并列裁决残余排序完成。与 PERF-091 的
    # idx_entries_deleted_category 共存：后者两列即分类计数 GROUP BY 的覆盖索引
    # （窄行免回表），本索引第三列的 updated_at 对分组形态是冗余宽度。
    (
        "idx_entries_active_category_updated",
        "entries",
        ("is_deleted", "category_id", "updated_at DESC"),
        False,
    ),
    # 分类计数覆盖索引（PERF-091）：get_category_entry_counts 的
    # ``WHERE is_deleted=0 AND category_id IS NOT NULL GROUP BY category_id``
    # 单一复合索引同时承担过滤与分组（两列连续覆盖谓词列与分组键，免回表免排序）
    # ——原仅 idx_entries_deleted 覆盖过滤，分组走 USE TEMP B-TREE FOR GROUP BY
    # （50k 库实测 49.8ms，且增删后防抖刷新在 UI 线程同步执行）。
    # 兼容性注意：索引集属 _validate_current_schema 校验范围，本索引纳入定义后
    # 缺失它的既有库（旧版本创建）重开时按「不做旧格式迁移」约定被拒绝
    # （SchemaError），开发期直接重建库即可（项目未发布、无迁移承诺）。
    (
        "idx_entries_deleted_category",
        "entries",
        ("is_deleted", "category_id"),
        False,
    ),
    ("idx_entries_crypto_id", "entries", ("crypto_id",), True),
    ("idx_pw_history_entry", "password_history", ("entry_id",), False),
    # 复合索引：加速密码历史截断子查询 ORDER BY changed_at DESC
    (
        "idx_pw_history_entry_time",
        "password_history",
        ("entry_id", "changed_at DESC"),
        False,
    ),
]

# 列预期四元组：(type, notnull, pk, dflt_value)。dflt_value 覆盖默认值校验，防止
# 被篡改默认值（如 entry_type DEFAULT）的库仍通过结构校验。PRAGMA table_info 返回
# 带引号原文（如 "'login'"、"0"），无默认为 None。
_TABLE_COLUMNS = {
    "vault_meta": {
        "key": ("TEXT", 0, 1, None),
        "value": ("TEXT", 1, 0, None),
    },
    "categories": {
        "id": ("INTEGER", 0, 1, None),
        "name_enc": ("TEXT", 1, 0, None),
        "icon_char": ("TEXT", 0, 0, "'[DIR]'"),
        "color": ("TEXT", 0, 0, "'#666666'"),
        "sort_order": ("INTEGER", 0, 0, "0"),
        "created_at": ("TEXT", 0, 0, "''"),
        "metadata_mac": ("TEXT", 1, 0, "''"),
    },
    "entries": {
        "id": ("INTEGER", 0, 1, None),
        "crypto_id": ("TEXT", 1, 0, "''"),
        "title_enc": ("TEXT", 1, 0, "''"),
        "username_enc": ("TEXT", 0, 0, "''"),
        "password_enc": ("TEXT", 0, 0, "''"),
        "url_enc": ("TEXT", 0, 0, "''"),
        "category_id": ("INTEGER", 0, 0, None),
        "tags_enc": ("TEXT", 0, 0, "''"),
        "notes_enc": ("TEXT", 0, 0, "''"),
        "custom_fields_enc": ("TEXT", 0, 0, "''"),
        "is_favorite": ("INTEGER", 0, 0, "0"),
        "is_deleted": ("INTEGER", 0, 0, "0"),
        "password_strength": ("INTEGER", 0, 0, "0"),
        "entry_type": ("TEXT", 0, 0, f"'{ENTRY_TYPE_LOGIN}'"),
        "totp_secret_enc": ("TEXT", 0, 0, "''"),
        "created_at": ("TEXT", 0, 0, "''"),
        "updated_at": ("TEXT", 0, 0, "''"),
        "deleted_at": ("TEXT", 0, 0, "''"),
        "password_changed_at": ("TEXT", 0, 0, "''"),
        "metadata_mac": ("TEXT", 1, 0, "''"),
    },
    "password_history": {
        "id": ("INTEGER", 0, 1, None),
        "entry_id": ("INTEGER", 1, 0, None),
        "old_password_enc": ("TEXT", 0, 0, "''"),
        "changed_at": ("TEXT", 0, 0, "''"),
    },
}

_FOREIGN_KEYS = {
    "entries": {("category_id", "categories", "id", "SET NULL")},
    "password_history": {("entry_id", "entries", "id", "CASCADE")},
}


class SchemaManager:
    """数据库 schema 管理 — 表创建、索引创建、schema 验证。

    经 ``conn_provider`` 获取 sqlite3.Connection（通常为 DatabaseManager 实例）。
    """

    SCHEMA_FORMAT = "cipherbox-schema"

    def __init__(self, conn_provider: ConnectionProvider):
        self._mgr = conn_provider

    # ======== 连接与锁代理 ========

    @property
    def _conn(self) -> sqlite3.Connection:
        return self._mgr.connection

    @property
    def _lock(self) -> threading.RLock:
        return self._mgr.db_lock

    def _auto_commit(self) -> None:
        return self._mgr.auto_commit()

    # ==================== Schema 管理 ====================

    def init_tables(self) -> None:
        """初始化数据库表。

        对已有数据库，schema 验证结果经 ``schema_validated`` 连接级缓存，避免同一
        连接内重复 O(tables × columns) 的 PRAGMA 查询；缓存随连接重开重置
        （``open`` 后置 ``schema_validated=False``），故应用每次启动都会重新验证一次。

        锁契约：本方法直接用 cursor 做 DDL/DML/PRAGMA，不经 ``_db_operation`` 装饰器
        也不持 ``_lock``——仅在设计为单线程的初始化期（``open`` 后首次访问、无其他
        操作者）调用，故无需锁；运行期并发访问须经 ``_db_operation`` 路径。
        """
        if self._conn is None:
            raise DatabaseError("数据库未连接")
        cursor = self._conn.cursor()
        is_new_database = self._check_is_new_database(cursor)
        if not is_new_database:
            # 缓存 schema 验证：同一连接生命周期内仅验证一次
            if not self._mgr.schema_validated:
                # 表结构校验先行：缺表/列篡改的库在此被清晰拒绝（SchemaError），
                # 不进入下方的索引补建——否则缺表库的 CREATE INDEX 会抛裸
                # sqlite 错误（no such table）而非既有的结构损坏文案。
                self._validate_table_structure(cursor)
                # 索引幂等补建（PERF-095）：索引是查询衍生物（不含数据语义，
                # CREATE INDEX IF NOT EXISTS 幂等），表结构合法的既有库补齐
                # _INDEX_DEFINITIONS 的缺失项——与「不做旧格式迁移」约定不冲突
                # （表结构与 schema_format 标识均不变，属 schema 完善而非数据迁移），
                # 否则索引演进（如 PERF-091/095 新增）会使既有库重开被
                # _validate_current_schema 误报「索引结构损坏」，完好数据无从恢复。
                existing_indexes = {
                    row["name"]
                    for row in cursor.execute(
                        "SELECT name FROM sqlite_master WHERE type='index'"
                    ).fetchall()
                }
                missing = [
                    (name, table, columns, is_unique)
                    for name, table, columns, is_unique in _INDEX_DEFINITIONS
                    if name not in existing_indexes
                ]
                for index_name, table, columns, is_unique in missing:
                    cursor.execute(
                        f"CREATE {'UNIQUE ' if is_unique else ''}INDEX IF NOT EXISTS "  # nosec B608 - 硬编码常量
                        f"{index_name} ON {table}({', '.join(columns)})"
                    )
                if missing:
                    self._auto_commit()
                self._validate_current_schema(cursor)
                self._mgr.schema_validated = True
            return

        cursor.executescript(f"""
            CREATE TABLE IF NOT EXISTS vault_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name_enc TEXT NOT NULL UNIQUE,
                icon_char TEXT DEFAULT '[DIR]',
                color TEXT DEFAULT '#666666',
                sort_order INTEGER DEFAULT 0,
                created_at TEXT DEFAULT '',
                metadata_mac TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                crypto_id TEXT NOT NULL DEFAULT '',
                title_enc TEXT NOT NULL DEFAULT '',
                username_enc TEXT DEFAULT '',
                password_enc TEXT DEFAULT '',
                url_enc TEXT DEFAULT '',
                category_id INTEGER,
                tags_enc TEXT DEFAULT '',
                notes_enc TEXT DEFAULT '',
                custom_fields_enc TEXT DEFAULT '',
                is_favorite INTEGER DEFAULT 0,
                is_deleted INTEGER DEFAULT 0,
                password_strength INTEGER DEFAULT 0,
                entry_type TEXT DEFAULT '{ENTRY_TYPE_LOGIN}',
                totp_secret_enc TEXT DEFAULT '',
                created_at TEXT DEFAULT '',
                updated_at TEXT DEFAULT '',
                deleted_at TEXT DEFAULT '',
                password_changed_at TEXT DEFAULT '',
                metadata_mac TEXT NOT NULL DEFAULT '',
                FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS password_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_id INTEGER NOT NULL,
                old_password_enc TEXT DEFAULT '',
                changed_at TEXT DEFAULT '',
                FOREIGN KEY (entry_id) REFERENCES entries(id) ON DELETE CASCADE
            );

        """)
        # 索引由 _INDEX_DEFINITIONS 统一定义，与 schema 校验共用单一事实源。
        for index_name, table, columns, is_unique in _INDEX_DEFINITIONS:
            cursor.execute(
                f"CREATE {'UNIQUE ' if is_unique else ''}INDEX IF NOT EXISTS "  # nosec B608 - 硬编码常量
                f"{index_name} ON {table}({', '.join(columns)})"
            )

        # 默认分类仅在首次创建数据库时写入，尊重用户后续删除操作。
        default_categories = [
            ("未分类", "[CAT]", "#888888", 0),
            ("社交", "[SOC]", "#4CAF50", 1),
            ("邮箱", "[MAIL]", "#2196F3", 2),
            ("金融", "[FIN]", "#F44336", 3),
            ("购物", "[CART]", "#FF9800", 4),
            ("工作", "[WORK]", "#607D8B", 5),
            ("娱乐", "[GAME]", "#9C27B0", 6),
            ("开发", "[DEV]", "#00BCD4", 7),
        ]
        # SEC-007：此处把公开默认分类名以明文写入 name_enc 列，是有意为之——schema_manager
        # 属 Data 层不持密钥，init_tables 在 DatabaseManager 装配密钥前/无密钥时调用，
        # 无法在此加密。该明文窗口由 business 层 vault_lifecycle.initialize 在
        # activate_keys 之后立即调 encrypt_plaintext_category_names 补加密（已加密的
        # cb2: 前缀跳过，幂等），使全部 *_enc 列在解锁前转为密文。默认分类名为公开值，
        # 窗口期内无敏感泄漏；不在此引入密钥依赖以保持 schema_manager 无密钥职责。
        for name, icon, color, order in default_categories:
            cursor.execute(
                "INSERT OR IGNORE INTO categories (name_enc, icon_char, color, sort_order, created_at) VALUES (?, ?, ?, ?, ?)",
                (name, icon, color, order, utc_now_iso()),
            )

        cursor.execute(
            "INSERT INTO vault_meta (key, value) VALUES (?, ?)",
            ("schema_format", self.SCHEMA_FORMAT),
        )

        self._auto_commit()
        self._validate_current_schema(cursor)

    def _check_is_new_database(self, cursor: sqlite3.Cursor) -> bool:
        """检查是否为空数据库。返回 True 表示新库需初始化，False 表示已有数据。

        Note: 返回前会对非空却不兼容的库（缺 vault_meta、schema_format 不符）直接抛
        SchemaError，调用方须同时处理 True / False / 异常三种结果。"""
        tables = {
            row["name"]
            for row in cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        }
        if not tables:
            return True
        if "vault_meta" not in tables:
            raise SchemaError("数据库格式无效")
        row = cursor.execute("SELECT value FROM vault_meta WHERE key = 'schema_format'").fetchone()
        if row is None or row["value"] != self.SCHEMA_FORMAT:
            actual = row["value"] if row and row["value"] else "未知"
            raise SchemaError(f"不支持的数据库格式：{actual}")
        return False

    @staticmethod
    @staticmethod
    def _validate_table_structure(cursor: sqlite3.Cursor) -> None:
        """校验全部表结构（列四元组）与预期一致，不符抛 :class:`SchemaError`。

        从 :meth:`_validate_current_schema` 拆出的表校验段（PERF-095 索引补建前置）：
        缺表/列篡改的库在索引补建**之前**被清晰拒绝，避免补建的 CREATE INDEX
        对缺表抛裸 sqlite 错误（``no such table``）掩盖真实病因。
        """
        for table, expected_columns in _TABLE_COLUMNS.items():
            # table 来自硬编码字典键，安全无注入风险；SQLite PRAGMA 不支持参数化，
            # f-string 是唯一方式。
            rows = cursor.execute(f"PRAGMA table_info({table})").fetchall()
            # 比对四元组（含 dflt_value），与 _TABLE_COLUMNS 预期一一对应。
            columns = {
                row["name"]: (row["type"].upper(), row["notnull"], row["pk"], row["dflt_value"])
                for row in rows
            }
            if columns != expected_columns:
                raise SchemaError(f"数据库结构损坏或不是当前格式：{table}")

    @staticmethod
    def _validate_current_schema(cursor: sqlite3.Cursor) -> None:
        """校验表结构、索引与外键与预期完全一致，不匹配则抛 :class:`SchemaError`。

        比对内容：每列四元组（类型/notnull/pk/``dflt_value``，含默认值防篡改如
        ``entry_type`` DEFAULT）、索引的列序与 UNIQUE 性、外键的 ``ON DELETE`` 动作。
        任一不符抛 :class:`SchemaError`——本层拒绝打开不兼容/被篡改的库，**不做旧格式
        迁移**（CLAUDE.md 约定），由调用方提示用户。
        """
        SchemaManager._validate_table_structure(cursor)

        for index_name, table, expected_index_columns, is_unique in _INDEX_DEFINITIONS:
            index_rows = cursor.execute(f"PRAGMA index_list({table})").fetchall()
            index_row = next((row for row in index_rows if row["name"] == index_name), None)
            if index_row is None or bool(index_row["unique"]) != is_unique:
                raise SchemaError(f"数据库索引结构损坏：{index_name}")
            actual_columns = tuple(
                (row["name"], bool(row["desc"]))
                for row in cursor.execute(f"PRAGMA index_xinfo({index_name})").fetchall()
                if row["key"]
            )
            normalized_expected = tuple(
                (
                    column.removesuffix(" DESC"),
                    column.endswith(" DESC"),
                )
                for column in expected_index_columns
            )
            if actual_columns != normalized_expected:
                raise SchemaError(f"数据库索引列损坏：{index_name}")

        for table, expected in _FOREIGN_KEYS.items():
            actual = {
                (row["from"], row["table"], row["to"], row["on_delete"].upper())
                for row in cursor.execute(f"PRAGMA foreign_key_list({table})").fetchall()
            }
            if actual != expected:
                raise SchemaError(f"数据库外键结构损坏：{table}")
