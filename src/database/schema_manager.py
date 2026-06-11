"""数据库 schema 创建与验证。

从 DatabaseManager 拆分而来，职责单一：数据库表结构的初始化与校验。
通过 DatabaseManager 委托提供统一数据访问接口。
"""

import logging

from ..exceptions import DatabaseError, SchemaError
from ..utils.format import utc_now_iso

logger = logging.getLogger(__name__)


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

            CREATE INDEX IF NOT EXISTS idx_entries_category ON entries(category_id);
            CREATE INDEX IF NOT EXISTS idx_entries_deleted ON entries(is_deleted);
            CREATE INDEX IF NOT EXISTS idx_entries_favorite ON entries(is_favorite);
            CREATE INDEX IF NOT EXISTS idx_entries_updated ON entries(updated_at);
            CREATE INDEX IF NOT EXISTS idx_entries_type ON entries(entry_type);
            CREATE INDEX IF NOT EXISTS idx_entries_password_changed ON entries(password_changed_at);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_entries_crypto_id ON entries(crypto_id);
            CREATE INDEX IF NOT EXISTS idx_pw_history_entry ON password_history(entry_id);
            -- 复合索引：加速密码历史截断子查询 ORDER BY changed_at DESC
            CREATE INDEX IF NOT EXISTS idx_pw_history_entry_time
                ON password_history(entry_id, changed_at DESC);
        """)

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
        非空但不兼容的数据库会抛出 SchemaError。"""
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
        required_indexes = {
            'idx_entries_category', 'idx_entries_deleted',
            'idx_entries_favorite', 'idx_entries_updated',
            'idx_entries_type', 'idx_entries_password_changed',
            'idx_entries_crypto_id',
            'idx_pw_history_entry',
            'idx_pw_history_entry_time',
        }
        indexes = {
            row['name'] for row in cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()
        }
        if not required_indexes.issubset(indexes):
            raise SchemaError('数据库索引结构损坏或不是当前格式')
