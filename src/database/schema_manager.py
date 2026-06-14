"""数据库 schema 创建与验证。

从 DatabaseManager 拆分而来，职责单一：数据库表结构的初始化与校验。
通过 DatabaseManager 委托提供统一数据访问接口。
"""

import logging

from ..exceptions import DatabaseError, SchemaError
from ..utils.format import utc_now_iso

logger = logging.getLogger(__name__)


# 索引定义：CREATE INDEX 与 _validate_current_schema 的单一事实来源。
# 新增索引只需在此追加——建表循环与 schema 校验自动跟随，避免建表 SQL 与
# 校验集合两份硬编码漂移（只改一处忘记另一处）。
# 兼容性注意：新增索引会纳入 required_indexes，导致旧版创建的库（无此索引）
# 启动时 schema 校验失败而拒绝打开。仅在可接受破坏旧库兼容性时才追加。
# tuple 形式：(索引名, 表(列)定义, 是否 UNIQUE)
_INDEX_DEFINITIONS: list[tuple[str, str, bool]] = [
    ('idx_entries_category', 'entries(category_id)', False),
    ('idx_entries_deleted', 'entries(is_deleted)', False),
    ('idx_entries_favorite', 'entries(is_favorite)', False),
    ('idx_entries_updated', 'entries(updated_at)', False),
    ('idx_entries_type', 'entries(entry_type)', False),
    ('idx_entries_password_changed', 'entries(password_changed_at)', False),
    ('idx_entries_crypto_id', 'entries(crypto_id)', True),  # UNIQUE
    ('idx_pw_history_entry', 'password_history(entry_id)', False),
    # 复合索引：加速密码历史截断子查询 ORDER BY changed_at DESC
    ('idx_pw_history_entry_time', 'password_history(entry_id, changed_at DESC)', False),
]


class SchemaManager:
    """数据库 schema 管理 — 表创建、索引创建、schema 验证。

    通过 ``conn_provider`` 获取 sqlite3.Connection，支持外部注入连接，
    通常为 DatabaseManager 实例。
    """

    SCHEMA_FORMAT = 'cipherbox-schema'

    def __init__(self, conn_provider):
        self._mgr = conn_provider

    # ======== 连接与锁代理 ========

    @property
    def _conn(self):
        return self._mgr.connection

    @property
    def _lock(self):
        return self._mgr.db_lock

    def _auto_commit(self):
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

        cursor.executescript("""
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
                created_at TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                crypto_id TEXT NOT NULL DEFAULT '',
                title TEXT NOT NULL DEFAULT '',
                username_enc TEXT DEFAULT '',
                password_enc TEXT DEFAULT '',
                url TEXT DEFAULT '',
                category_id INTEGER,
                tags TEXT DEFAULT '',
                notes_enc TEXT DEFAULT '',
                custom_fields_enc TEXT DEFAULT '',
                is_favorite INTEGER DEFAULT 0,
                is_deleted INTEGER DEFAULT 0,
                password_strength INTEGER DEFAULT 0,
                entry_type TEXT DEFAULT 'login',
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
        for index_name, definition, is_unique in _INDEX_DEFINITIONS:
            cursor.execute(
                f"CREATE {'UNIQUE ' if is_unique else ''}INDEX IF NOT EXISTS "  # nosec B608 - 硬编码常量
                f"{index_name} ON {definition}"
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

    def _check_is_new_database(self, cursor) -> bool:
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
            raise SchemaError('数据库缺少版本信息，不支持旧格式')
        row = cursor.execute(
            "SELECT value FROM vault_meta WHERE key = 'schema_format'"
        ).fetchone()
        if row is None or row['value'] != self.SCHEMA_FORMAT:
            actual = row['value'] if row else '未知'
            raise SchemaError(
                f'不支持的数据库格式：{actual}'
            )
        return False

    @staticmethod
    def _validate_current_schema(cursor):
        """校验当前数据库的表结构和索引是否符合预期。"""
        required = {
            'vault_meta': {'key', 'value'},
            'categories': {'id', 'name', 'icon_char', 'color', 'sort_order', 'created_at'},
            'entries': {
                'id', 'crypto_id', 'title', 'username_enc', 'password_enc', 'url',
                'category_id', 'tags', 'notes_enc', 'custom_fields_enc',
                'is_favorite', 'is_deleted', 'password_strength', 'entry_type',
                'totp_secret_enc', 'created_at', 'updated_at', 'deleted_at',
                'password_changed_at', 'metadata_mac',
            },
            'password_history': {'id', 'entry_id', 'old_password_enc', 'changed_at'},
        }
        for table, expected_columns in required.items():
            # table 来自上方硬编码的 required 字典键，安全无注入风险。
            # SQLite PRAGMA 不支持参数化查询，f-string 是唯一方式。
            columns = {
                row['name'] for row in cursor.execute(
                    f'PRAGMA table_info({table})'
                ).fetchall()
            }
            if not expected_columns.issubset(columns):
                raise SchemaError(f'数据库结构损坏或不是当前格式：{table}')
        required_indexes = {name for name, _, _ in _INDEX_DEFINITIONS}
        indexes = {
            row['name'] for row in cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()
        }
        if not required_indexes.issubset(indexes):
            raise SchemaError('数据库索引结构损坏或不是当前格式')
