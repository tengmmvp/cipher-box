"""数据库 schema 创建与验证。

从 DatabaseManager 拆分而来，职责单一：数据库表结构的初始化与校验。
通过 DatabaseManager 委托提供统一数据访问接口。
"""

import logging
import sqlite3
import threading

from ..exceptions import DatabaseError, SchemaError
from ..models import ENTRY_TYPE_LOGIN
from ..utils.format import utc_now_iso
from .types import ConnectionProvider

logger = logging.getLogger(__name__)


# 索引定义：CREATE INDEX 与 _validate_current_schema 的单一事实来源。
# 新增索引只需在此追加——建表循环与 schema 校验自动跟随，避免建表 SQL 与
# 校验集合两份硬编码漂移（只改一处忘记另一处）。
# tuple 形式：(索引名, 表名, 列定义, 是否 UNIQUE)
_INDEX_DEFINITIONS: list[tuple[str, str, tuple[str, ...], bool]] = [
    ('idx_entries_category', 'entries', ('category_id',), False),
    ('idx_entries_deleted', 'entries', ('is_deleted',), False),
    ('idx_entries_favorite', 'entries', ('is_favorite',), False),
    ('idx_entries_updated', 'entries', ('updated_at',), False),
    # 复合索引：服务列表默认视图与「近期更新」视图的 WHERE is_deleted=0 +
    # ORDER BY updated_at DESC，免内存排序。单列 is_deleted/updated_at 索引无法
    # 同时满足过滤与排序，组合后才能让 SQLite 走索引扫描而非全表 + filesort。
    (
        'idx_entries_active_updated',
        'entries',
        ('is_deleted', 'updated_at DESC'),
        False,
    ),
    ('idx_entries_type', 'entries', ('entry_type',), False),
    ('idx_entries_password_changed', 'entries', ('password_changed_at',), False),
    ('idx_entries_crypto_id', 'entries', ('crypto_id',), True),
    ('idx_pw_history_entry', 'password_history', ('entry_id',), False),
    # 复合索引：加速密码历史截断子查询 ORDER BY changed_at DESC
    (
        'idx_pw_history_entry_time',
        'password_history',
        ('entry_id', 'changed_at DESC'),
        False,
    ),
]

# 列预期四元组：(type, notnull, pk, dflt_value)。dflt_value 为 PRAGMA table_info
# 返回的默认值原文（带引号字符串如 "'login'"、裸数字如 "0"、无默认为 None），覆盖列
# 默认值校验，防止被篡改默认值（如 entry_type DEFAULT）的库仍通过结构校验。
_TABLE_COLUMNS = {
    'vault_meta': {
        'key': ('TEXT', 0, 1, None), 'value': ('TEXT', 1, 0, None),
    },
    'categories': {
        'id': ('INTEGER', 0, 1, None), 'name': ('TEXT', 1, 0, None),
        'icon_char': ('TEXT', 0, 0, "'[DIR]'"), 'color': ('TEXT', 0, 0, "'#666666'"),
        'sort_order': ('INTEGER', 0, 0, '0'), 'created_at': ('TEXT', 0, 0, "''"),
        'metadata_mac': ('TEXT', 1, 0, "''"),
    },
    'entries': {
        'id': ('INTEGER', 0, 1, None), 'crypto_id': ('TEXT', 1, 0, "''"),
        'title_enc': ('TEXT', 1, 0, "''"), 'username_enc': ('TEXT', 0, 0, "''"),
        'password_enc': ('TEXT', 0, 0, "''"), 'url_enc': ('TEXT', 0, 0, "''"),
        'category_id': ('INTEGER', 0, 0, None), 'tags_enc': ('TEXT', 0, 0, "''"),
        'notes_enc': ('TEXT', 0, 0, "''"), 'custom_fields_enc': ('TEXT', 0, 0, "''"),
        'is_favorite': ('INTEGER', 0, 0, '0'), 'is_deleted': ('INTEGER', 0, 0, '0'),
        'password_strength': ('INTEGER', 0, 0, '0'), 'entry_type': ('TEXT', 0, 0, f"'{ENTRY_TYPE_LOGIN}'"),
        'totp_secret_enc': ('TEXT', 0, 0, "''"), 'created_at': ('TEXT', 0, 0, "''"),
        'updated_at': ('TEXT', 0, 0, "''"), 'deleted_at': ('TEXT', 0, 0, "''"),
        'password_changed_at': ('TEXT', 0, 0, "''"),
        'metadata_mac': ('TEXT', 1, 0, "''"),
    },
    'password_history': {
        'id': ('INTEGER', 0, 1, None), 'entry_id': ('INTEGER', 1, 0, None),
        'old_password_enc': ('TEXT', 0, 0, "''"), 'changed_at': ('TEXT', 0, 0, "''"),
    },
}

_FOREIGN_KEYS = {
    'entries': {('category_id', 'categories', 'id', 'SET NULL')},
    'password_history': {('entry_id', 'entries', 'id', 'CASCADE')},
}


class SchemaManager:
    """数据库 schema 管理 — 表创建、索引创建、schema 验证。

    通过 ``conn_provider`` 获取 sqlite3.Connection，支持外部注入连接，
    通常为 DatabaseManager 实例。
    """

    SCHEMA_FORMAT = 'cipherbox-schema'

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

        对于已有数据库，schema 验证结果会被缓存，避免每次启动都执行
        O(tables × columns) 的 PRAGMA 查询。仅当数据库文件变更后才重新验证。
        """
        if self._conn is None:
            raise DatabaseError("数据库未连接")
        cursor = self._conn.cursor()
        is_new_database = self._check_is_new_database(cursor)
        if not is_new_database:
            # 缓存 schema 验证：同一连接生命周期内仅验证一次
            if not self._mgr.schema_validated:
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
                name TEXT NOT NULL UNIQUE,
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
        # 索引由 _INDEX_DEFINITIONS 统一定义，循环创建以与 schema 校验共用单一来源，
        # 避免建表 SQL 与校验集合两份硬编码漂移。
        for index_name, table, columns, is_unique in _INDEX_DEFINITIONS:
            cursor.execute(
                f"CREATE {'UNIQUE ' if is_unique else ''}INDEX IF NOT EXISTS "  # nosec B608 - 硬编码常量
                f"{index_name} ON {table}({', '.join(columns)})"
            )

        # 默认分类仅在首次创建数据库时写入，尊重用户后续删除操作。
        default_categories = [
            ('未分类', '[CAT]', '#888888', 0),
            ('社交', '[SOC]', '#4CAF50', 1),
            ('邮箱', '[MAIL]', '#2196F3', 2),
            ('金融', '[FIN]', '#F44336', 3),
            ('购物', '[CART]', '#FF9800', 4),
            ('工作', '[WORK]', '#607D8B', 5),
            ('娱乐', '[GAME]', '#9C27B0', 6),
            ('开发', '[DEV]', '#00BCD4', 7),
        ]
        for name, icon, color, order in default_categories:
            cursor.execute(
                "INSERT OR IGNORE INTO categories (name, icon_char, color, sort_order, created_at) VALUES (?, ?, ?, ?, ?)",
                (name, icon, color, order, utc_now_iso()),
            )

        cursor.execute(
            "INSERT INTO vault_meta (key, value) VALUES (?, ?)",
            ('schema_format', self.SCHEMA_FORMAT),
        )

        self._auto_commit()
        self._validate_current_schema(cursor)

    def _check_is_new_database(self, cursor: sqlite3.Cursor) -> bool:
        """检查是否为空数据库。返回 True 表示新库需初始化，False 表示已有数据。

        注意：方法名暗示返回布尔，但在返回前会对非空却不兼容的数据库
        （缺 vault_meta、schema_format 不符）直接抛出 SchemaError，调用方
        须同时处理 True / False / 异常三种结果。"""
        tables = {
            row['name'] for row in cursor.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        }
        if not tables:
            return True
        if 'vault_meta' not in tables:
            raise SchemaError('数据库格式无效')
        row = cursor.execute(
            "SELECT value FROM vault_meta WHERE key = 'schema_format'"
        ).fetchone()
        if row is None or row['value'] != self.SCHEMA_FORMAT:
            actual = row['value'] if row and row['value'] else '未知'
            raise SchemaError(
                f'不支持的数据库格式：{actual}'
            )
        return False

    @staticmethod
    def _validate_current_schema(cursor: sqlite3.Cursor) -> None:
        """校验当前数据库的表结构和索引是否符合预期。"""
        for table, expected_columns in _TABLE_COLUMNS.items():
            # table 来自上方硬编码的 required 字典键，安全无注入风险。
            # SQLite PRAGMA 不支持参数化查询，f-string 是唯一方式。
            rows = cursor.execute(f'PRAGMA table_info({table})').fetchall()
            # 比对 (type, notnull, pk, dflt_value) 四元组：dflt_value 覆盖列默认值，
            # 防止被篡改默认值的库仍通过结构校验。PRAGMA table_info 的 dflt_value
            # 返回带引号原文（如 "'login'"、"0"），无默认时为 None，与 _TABLE_COLUMNS
            # 第四位预期一一对应。
            columns = {
                row['name']: (row['type'].upper(), row['notnull'], row['pk'], row['dflt_value'])
                for row in rows
            }
            if columns != expected_columns:
                raise SchemaError(f'数据库结构损坏或不是当前格式：{table}')

        for index_name, table, expected_index_columns, is_unique in _INDEX_DEFINITIONS:
            index_rows = cursor.execute(f'PRAGMA index_list({table})').fetchall()
            index_row = next(
                (row for row in index_rows if row['name'] == index_name), None
            )
            if index_row is None or bool(index_row['unique']) != is_unique:
                raise SchemaError(f'数据库索引结构损坏：{index_name}')
            actual_columns = tuple(
                (row['name'], bool(row['desc']))
                for row in cursor.execute(
                    f'PRAGMA index_xinfo({index_name})'
                ).fetchall()
                if row['key']
            )
            normalized_expected = tuple(
                (
                    column.removesuffix(' DESC'),
                    column.endswith(' DESC'),
                )
                for column in expected_index_columns
            )
            if actual_columns != normalized_expected:
                raise SchemaError(f'数据库索引列损坏：{index_name}')

        for table, expected in _FOREIGN_KEYS.items():
            actual = {
                (row['from'], row['table'], row['to'], row['on_delete'].upper())
                for row in cursor.execute(f'PRAGMA foreign_key_list({table})').fetchall()
            }
            if actual != expected:
                raise SchemaError(f'数据库外键结构损坏：{table}')
