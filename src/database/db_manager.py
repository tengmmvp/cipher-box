"""数据库管理器 - SQLite 数据库操作"""

import functools
import logging
import sqlite3
import threading
import time as _time
import uuid
from collections.abc import Callable
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Protocol, runtime_checkable

logger = logging.getLogger(__name__)

from ..exceptions import DatabaseError, SchemaError, TransactionError, VaultError
from ..utils.file_security import secure_directory, secure_file
from .models import Category, Entry, PasswordHistory
from .types import VerifyMode


def _db_operation(method):
    """Decorator: acquires RLock + validates connection. Replaces @_thread_safe and manual connection checks."""
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        if self._conn is None:
            raise DatabaseError("数据库未连接")
        with self._lock:
            return method(self, *args, **kwargs)
    return wrapper

# _ENTRY_COLUMNS 是 entries 表非 id 列名的单一事实来源（single source of truth）。
# 重要：新增 entries 表列时必须在此列表追加，否则 HMAC 签名将缺少该列，
# 导致已有数据签名验证失败。此列表须与 _row_to_entry 读取的字段保持一致。
_ENTRY_COLUMNS = [
    'crypto_id', 'title', 'username_enc', 'password_enc', 'url',
    'category_id', 'tags', 'notes_enc', 'custom_fields_enc',
    'is_favorite', 'is_deleted', 'password_strength', 'entry_type',
    'totp_secret_enc', 'created_at', 'updated_at', 'deleted_at',
    'password_changed_at', 'metadata_mac',
]
_ENTRY_SIGN_COLUMNS = ', '.join(['id'] + _ENTRY_COLUMNS)
# P7: 预计算签名查询 SQL，避免每次调用时重新求值 f-string
_SELECT_ENTRY_SIGN_SQL = f"SELECT {_ENTRY_SIGN_COLUMNS} FROM entries WHERE id=?"

# P-03：批量更新 SQL，列顺序与 update_entry 的 SET 子句完全一致。
_RE_ENCRYPT_BATCH_UPDATE_SQL = """UPDATE entries SET
    crypto_id=?, title=?, username_enc=?, password_enc=?, url=?, category_id=?,
    tags=?, notes_enc=?, custom_fields_enc=?, is_favorite=?,
    password_strength=?, entry_type=?, totp_secret_enc=?, updated_at=?,
    password_changed_at=?, metadata_mac=?
    WHERE id=?"""


# A6: 签名/验证函数的类型协议，替代弱类型 Callable
@runtime_checkable
class EntrySigner(Protocol):
    def __call__(self, entry: Entry) -> str: ...


@runtime_checkable
class EntryVerifier(Protocol):
    def __call__(self, entry: Entry) -> None: ...


# TODO: God Object 分解计划
# DatabaseManager 当前承担了 schema 管理、各类 CRUD、事务管理、文件安全等职责。
# 建议分解为：
# - EntryRepository: 条目 CRUD
# - CategoryRepository: 分类 CRUD
# - HistoryRepository: 密码历史 CRUD
# - SchemaManager: 表创建和 schema 验证

class DatabaseManager:
    """SQLite 数据库管理器"""

    SCHEMA_FORMAT = 'cipherbox-schema'
    MAX_PASSWORD_HISTORY = 10

    def __init__(self, db_path: Path):
        self._db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._lock = threading.RLock()
        self._transaction_depth = 0
        self._savepoint_counter = 0
        self._write_guard: Callable[[], None] | None = None
        self._entry_signer: EntrySigner | None = None
        self._entry_verifier: EntryVerifier | None = None
        self._last_secure_ts: float = 0.0
        self._schema_validated: bool = False
        # A1：实例级加密断言开关。使用固定值，测试只能通过修改实例属性来关闭，
        # 不会影响同进程其他实例。
        self._enforce_encrypted_fields: bool = True

    def set_write_guard(self, guard: Callable[[], None]):
        """设置写入前校验，用于阻止过期密钥会话继续写库。"""
        self._write_guard = guard

    def set_entry_integrity_handlers(
        self,
        signer: EntrySigner,
        verifier: EntryVerifier,
    ):
        """设置条目元数据签名与校验函数。"""
        self._entry_signer = signer
        self._entry_verifier = verifier

    def _guard_write(self):
        if self._write_guard:
            self._write_guard()

    # ========== 事务管理 ==========

    @property
    def in_transaction(self) -> bool:
        return self._transaction_depth > 0

    @property
    def is_open(self) -> bool:
        return self._conn is not None

    @contextmanager
    def transaction(self):
        """事务上下文；嵌套事务使用 SAVEPOINT 独立回滚。

        线程安全契约：
        - 本方法不在整个事务期间持有 _lock。
        - 事务内的单个操作通过 @_db_operation 获取锁，保证操作级原子性。
        - 事务整体不隔离跨线程操作：调用方须确保无并发写同一表。
        - RLock 保证同一线程可重入（事务内嵌套 @_db_operation 可正常工作）。
        """
        if self._conn is None:
            raise DatabaseError("数据库未连接")
        if not self.in_transaction:
            self.begin_transaction()
            try:
                yield
                self.commit_transaction()
            except Exception:
                self.rollback_transaction()
                raise
            return

        self._guard_write()
        self._savepoint_counter += 1
        savepoint = f'"cipherbox_sp_{self._savepoint_counter}"'
        self._conn.execute(f'SAVEPOINT {savepoint}')
        self._transaction_depth += 1
        try:
            yield
            self._conn.execute(f'RELEASE SAVEPOINT {savepoint}')
        except Exception:
            self._conn.execute(f'ROLLBACK TO SAVEPOINT {savepoint}')
            self._conn.execute(f'RELEASE SAVEPOINT {savepoint}')
            raise
        finally:
            self._transaction_depth -= 1

    def begin_transaction(self):
        """开始事务（抑制内部 commit）。

        注意：此方法未加 ``@_db_operation`` 锁，必须在已持有锁的
        上下文（如 ``@_db_operation`` 装饰的方法内、或 ``transaction()``
        上下文管理器内）调用，不可直接从外部线程调用。
        """
        if self._conn is None:
            raise DatabaseError("数据库未连接")
        if self.in_transaction:
            raise TransactionError("数据库事务已经开始")
        self._guard_write()
        self._conn.execute("BEGIN TRANSACTION")
        self._transaction_depth = 1

    def commit_transaction(self):
        """提交事务。

        注意：此方法未加 ``@_db_operation`` 锁，必须在已持有锁的
        上下文内调用。参见 :meth:`begin_transaction`。
        """
        if self._conn is None:
            raise DatabaseError("数据库未连接")
        if self._transaction_depth != 1:
            raise TransactionError("没有可提交的外层事务")
        self._conn.execute("COMMIT")
        self._transaction_depth = 0
        self._savepoint_counter = 0
        self._secure_database_files()

    def rollback_transaction(self):
        """回滚事务。

        注意：此方法未加 ``@_db_operation`` 锁，必须在已持有锁的
        上下文内调用。参见 :meth:`begin_transaction`。
        """
        if self._conn is None:
            raise DatabaseError("数据库未连接")
        try:
            self._conn.execute("ROLLBACK")
        except sqlite3.OperationalError:
            pass
        self._transaction_depth = 0
        self._savepoint_counter = 0

    def _auto_commit(self):
        """内部提交：仅在非事务模式下执行 commit。

        文件权限操作（secure_file）添加 1 秒防抖，避免批量写入时
        每行操作都触发三次文件权限设置，仅在距上次 ≥1 秒后才执行。
        """
        if not self.in_transaction and self._conn:
            try:
                self._conn.commit()
                now = _time.monotonic()
                if now - self._last_secure_ts >= 1.0:
                    self._secure_database_files()
                    self._last_secure_ts = now
            except Exception:
                self._transaction_depth = 0
                self._savepoint_counter = 0
                logger.error("数据库提交失败", exc_info=True)
                raise

    def open(self) -> bool:
        """打开数据库连接"""
        try:
            secure_directory(self._db_path.parent)
            # 线程安全契约：SQLite 连接仅在 DatabaseManager._lock (RLock) 保护下使用。
            # check_same_thread=False 允许同一线程的 RLock 重入和事务内的操作，
            # 不意味着连接可被多线程无锁共享。所有 DB 操作必须通过 @_db_operation
            # 或在已持有 _lock 的上下文中调用。begin/commit/rollback 虽未装饰，
            # 但仅在 @_db_operation 方法内部的事务上下文中被调用。
            self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA secure_delete=ON")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._secure_database_files()
            self._schema_validated = False  # 新连接需要重新验证 schema
            return True
        except sqlite3.Error:
            logger.error("数据库打开失败", exc_info=True)
            return False

    def _secure_database_files(self):
        secure_file(self._db_path)
        secure_file(Path(f'{self._db_path}-wal'))
        secure_file(Path(f'{self._db_path}-shm'))

    def close(self):
        """关闭数据库连接"""
        if self._conn:
            self._conn.close()
            self._conn = None
        self._transaction_depth = 0
        self._savepoint_counter = 0

    def init_tables(self):
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
            if not self._schema_validated:
                self._validate_current_schema(cursor)
                self._schema_validated = True
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
            try:
                cursor.execute(
                    "INSERT OR IGNORE INTO categories (name, icon_char, color, sort_order, created_at) VALUES (?, ?, ?, ?, ?)",
                    (name, icon, color, order, datetime.now(timezone.utc).isoformat()),
                )
            except sqlite3.IntegrityError:
                pass

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
        }
        indexes = {
            row['name'] for row in cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()
        }
        if not required_indexes.issubset(indexes):
            raise SchemaError('数据库索引结构损坏或不是当前格式')

    # ==================== 元数据 ====================

    @_db_operation
    def get_meta(self, key: str) -> Optional[str]:
        """获取元数据"""
        row = self._conn.execute(
            "SELECT value FROM vault_meta WHERE key = ?", (key,)
        ).fetchone()
        return row['value'] if row else None

    @_db_operation
    def set_meta(self, key: str, value: str):
        """设置元数据"""
        self._guard_write()
        self._conn.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?, ?)",
            (key, value),
        )
        self._auto_commit()

    # ==================== 分类（Categories） ====================

    @_db_operation
    def get_categories(self) -> list[Category]:
        """获取所有分类"""
        rows = self._conn.execute(
            "SELECT * FROM categories ORDER BY sort_order, name"
        ).fetchall()
        return [self._row_to_category(r) for r in rows]

    @_db_operation
    def get_category(self, category_id: int) -> Optional[Category]:
        """获取单个分类"""
        row = self._conn.execute(
            "SELECT * FROM categories WHERE id = ?", (category_id,)
        ).fetchone()
        return self._row_to_category(row) if row else None

    @_db_operation
    def add_category(self, category: Category) -> int:
        """添加分类，返回 ID"""
        self._guard_write()
        cursor = self._conn.execute(
            "INSERT INTO categories (name, icon_char, color, sort_order, created_at) VALUES (?, ?, ?, ?, ?)",
            (category.name, category.icon_char, category.color, category.sort_order,
             category.created_at or datetime.now(timezone.utc).isoformat()),
        )
        self._auto_commit()
        return cursor.lastrowid or 0

    @_db_operation
    def update_category(self, category: Category):
        """更新分类"""
        self._guard_write()
        self._conn.execute(
            "UPDATE categories SET name=?, icon_char=?, color=?, sort_order=? WHERE id=?",
            (category.name, category.icon_char, category.color, category.sort_order, category.id),
        )
        self._auto_commit()

    def delete_category(self, category_id: int):
        """删除分类（将关联条目的 category_id 置空并重算签名）。

        优化：批量获取全部条目行，构造 Entry 对象用于签名，
        然后用 executemany 批量更新，将 N+1 模式降为 2+1 次操作。

        注意：不使用 @_db_operation，而是显式组合 _lock + transaction()，
        使事务边界和锁持有关系更清晰。
        """
        with self._lock:
            self._guard_write()
            with self.transaction():
                rows = self._conn.execute(
                    "SELECT e.*, c.name as category_name "
                    "FROM entries e LEFT JOIN categories c ON e.category_id = c.id "
                    "WHERE e.category_id=?",
                    (category_id,),
                ).fetchall()
                # 批量计算签名
                update_data = []
                for row in rows:
                    entry = self._row_to_entry(row)
                    entry.category_id = None
                    entry.metadata_mac = self._sign_entry(entry)
                    update_data.append((entry.metadata_mac, entry.id))
                # 批量更新
                if update_data:
                    self._conn.executemany(
                        "UPDATE entries SET category_id=NULL, metadata_mac=? WHERE id=?",
                        update_data,
                    )
                self._conn.execute("DELETE FROM categories WHERE id=?", (category_id,))

    @_db_operation
    def get_category_entry_count(self, category_id: int) -> int:
        """获取分类下的条目数量"""
        row = self._conn.execute(
            "SELECT COUNT(*) FROM entries WHERE category_id=? AND is_deleted=0",
            (category_id,),
        ).fetchone()
        return row[0]

    @_db_operation
    def get_category_entry_counts(self) -> dict[int, int]:
        """一次查询返回所有分类的有效条目数量。"""
        rows = self._conn.execute(
            """SELECT category_id, COUNT(*) AS entry_count
               FROM entries
               WHERE is_deleted=0 AND category_id IS NOT NULL
               GROUP BY category_id"""
        ).fetchall()
        return {row['category_id']: row['entry_count'] for row in rows}

    # ==================== 条目（Entries） ====================

    @_db_operation
    def get_entries(
        self,
        deleted_only: bool = False,
        include_deleted: bool = False,
        category_id: Optional[int] = None,
        favorite_only: bool = False,
        limit: int | None = None,
        after_id: int | None = None,
    ) -> list[Entry]:
        """获取密码条目列表"""
        query = """
            SELECT e.*, c.name as category_name
            FROM entries e
            LEFT JOIN categories c ON e.category_id = c.id
            WHERE 1=1
        """
        params: list = []

        if deleted_only:
            query += " AND e.is_deleted = 1"
        elif not include_deleted:
            query += " AND e.is_deleted = 0"

        if category_id is not None:
            query += " AND e.category_id = ?"
            params.append(category_id)

        if favorite_only:
            query += " AND e.is_favorite = 1"

        if after_id is not None:
            query += " AND e.id > ?"
            params.append(after_id)
            query += " ORDER BY e.id ASC"
        else:
            query += " ORDER BY e.is_favorite DESC, e.updated_at DESC"

        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)

        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_entry(r, verify=VerifyMode.LENIENT) for r in rows]

    @_db_operation
    def get_entry(self, entry_id: int) -> Optional[Entry]:
        """获取单个条目"""
        row = self._conn.execute(
            """SELECT e.*, c.name as category_name
               FROM entries e
               LEFT JOIN categories c ON e.category_id = c.id
               WHERE e.id = ?""",
            (entry_id,),
        ).fetchone()
        return self._row_to_entry(row) if row else None

    def _assert_encrypted(self, value: str, field_name: str) -> None:
        """防御性断言：加密列的值应为密文（以 cb: 前缀）或空字符串。

        防止绕过 EntryManager 直接调用 db.add_entry/update_entry 时
        明文静默写入加密列。空值允许通过（旧版兼容及未填写字段）。
        读取实例级 _enforce_encrypted_fields，避免测试覆写泄漏到其他实例。
        """
        if self._enforce_encrypted_fields and value and not value.startswith('cb:'):
            raise ValueError(
                f'数据层收到未加密的 {field_name}（期望 cb: 前缀的密文），'
                f'请通过 EntryManager 操作条目'
            )

    @_db_operation
    def add_entry(self, entry: Entry, preserve_metadata: bool = False) -> int:
        """添加条目，返回 ID"""
        self._guard_write()
        # A1：防御性断言，防止明文静默写入加密列
        self._assert_encrypted(entry.username, 'username')
        self._assert_encrypted(entry.password, 'password')
        self._assert_encrypted(entry.notes, 'notes')
        self._assert_encrypted(entry.totp_secret, 'totp_secret')
        self._assert_encrypted(entry.custom_fields_db_value, 'custom_fields')
        now = datetime.now(timezone.utc).isoformat()
        entry.crypto_id = entry.crypto_id or uuid.uuid4().hex
        entry.created_at = entry.created_at or now
        entry.updated_at = entry.updated_at if preserve_metadata and entry.updated_at else now
        entry.is_deleted = bool(preserve_metadata and entry.is_deleted)
        entry.deleted_at = entry.deleted_at if preserve_metadata else ''
        entry.password_changed_at = (
            entry.password_changed_at or entry.updated_at or entry.created_at or now
        )
        entry.metadata_mac = self._sign_entry(entry)
        cursor = self._conn.execute(
            """INSERT INTO entries
               (crypto_id, title, username_enc, password_enc, url, category_id, tags,
                notes_enc, custom_fields_enc, is_favorite, is_deleted,
                 password_strength, entry_type, totp_secret_enc, created_at, updated_at,
                 deleted_at, password_changed_at, metadata_mac)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                entry.crypto_id,
                entry.title,
                entry.username,
                entry.password,
                entry.url,
                entry.category_id,
                entry.tags,
                entry.notes,
                entry.custom_fields_db_value,
                1 if entry.is_favorite else 0,
                1 if entry.is_deleted else 0,
                entry.password_strength,
                entry.entry_type,
                entry.totp_secret,
                entry.created_at,
                entry.updated_at,
                entry.deleted_at,
                entry.password_changed_at,
                entry.metadata_mac,
            ),
        )
        self._auto_commit()
        return cursor.lastrowid or 0

    @_db_operation
    def update_entry(
        self,
        entry: Entry,
        preserve_updated_at: bool = False,
        metadata_mac: str | None = None,
    ):
        """更新条目。

        注意：此方法不写入 is_deleted 和 deleted_at 字段，这两个字段
        仅由 soft_delete_entry / restore_entry 管理。若需修改删除状态，
        请使用上述专用方法。
        """
        self._guard_write()
        # A1：防御性断言，防止明文静默写入加密列
        self._assert_encrypted(entry.username, 'username')
        self._assert_encrypted(entry.password, 'password')
        self._assert_encrypted(entry.notes, 'notes')
        self._assert_encrypted(entry.totp_secret, 'totp_secret')
        self._assert_encrypted(entry.custom_fields_db_value, 'custom_fields')
        entry.updated_at = (
            entry.updated_at
            if preserve_updated_at and entry.updated_at
            else datetime.now(timezone.utc).isoformat()
        )
        entry.metadata_mac = metadata_mac or self._sign_entry(entry)
        self._conn.execute(
            """UPDATE entries SET
               crypto_id=?, title=?, username_enc=?, password_enc=?, url=?, category_id=?,
               tags=?, notes_enc=?, custom_fields_enc=?, is_favorite=?,
               password_strength=?, entry_type=?, totp_secret_enc=?, updated_at=?,
               password_changed_at=?, metadata_mac=?
               WHERE id=?""",
            (
                entry.crypto_id,
                entry.title,
                entry.username,
                entry.password,
                entry.url,
                entry.category_id,
                entry.tags,
                entry.notes,
                entry.custom_fields_db_value,
                1 if entry.is_favorite else 0,
                entry.password_strength,
                entry.entry_type,
                entry.totp_secret,
                entry.updated_at,
                entry.password_changed_at,
                entry.metadata_mac,
                entry.id,
            ),
        )
        self._auto_commit()

    @_db_operation
    def update_entries_batch(self, rows: list[tuple]):
        """批量更新条目（改密重加密专用）。

        rows: list of tuples matching the UPDATE SET + WHERE parameters.
        列顺序须与 _RE_ENCRYPT_BATCH_UPDATE_SQL 一致。
        """
        if not rows:
            return
        self._guard_write()
        self._conn.executemany(_RE_ENCRYPT_BATCH_UPDATE_SQL, rows)
        self._auto_commit()

    @_db_operation
    def soft_delete_entry(self, entry_id: int):
        """软删除条目。"""
        self._guard_write()
        now = datetime.now(timezone.utc).isoformat()
        entry = self._select_entry_for_sign(entry_id)
        if entry is None:
            return
        entry.is_deleted = True
        entry.deleted_at = now
        entry.metadata_mac = self._sign_entry(entry)
        self._conn.execute(
            "UPDATE entries SET is_deleted=1, deleted_at=?, metadata_mac=? WHERE id=?",
            (now, entry.metadata_mac, entry_id),
        )
        self._auto_commit()

    @_db_operation
    def restore_entry(self, entry_id: int):
        """恢复条目。"""
        self._guard_write()
        entry = self._select_entry_for_sign(entry_id)
        if entry is None:
            return
        entry.is_deleted = False
        entry.deleted_at = ''
        entry.metadata_mac = self._sign_entry(entry)
        self._conn.execute(
            "UPDATE entries SET is_deleted=0, deleted_at='', metadata_mac=? WHERE id=?",
            (entry.metadata_mac, entry_id),
        )
        self._auto_commit()

    @_db_operation
    def permanent_delete_entry(self, entry_id: int):
        """永久删除条目"""
        self._guard_write()
        self._conn.execute("DELETE FROM entries WHERE id=?", (entry_id,))
        self._auto_commit()
        self.secure_checkpoint()

    @_db_operation
    def empty_trash(self):
        """清空回收站"""
        self._guard_write()
        self._conn.execute("DELETE FROM entries WHERE is_deleted=1")
        self._auto_commit()
        self.secure_checkpoint()

    @_db_operation
    def clear_vault_data(self):
        """清空领域数据，供事务化恢复使用。"""
        self._guard_write()
        self._conn.execute("DELETE FROM password_history")
        self._conn.execute("DELETE FROM entries")
        self._conn.execute("DELETE FROM categories")
        self._auto_commit()

    @_db_operation
    def secure_checkpoint(self):
        """截断 WAL，降低已删除或重加密数据残留。"""
        if self._conn is not None and not self.in_transaction:
            try:
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except sqlite3.Error:
                logger.warning("WAL 安全截断失败", exc_info=True)

    @_db_operation
    def get_entry_count(self, include_deleted: bool = False) -> int:
        """获取条目数量"""
        query = "SELECT COUNT(*) FROM entries"
        if not include_deleted:
            query += " WHERE is_deleted = 0"
        row = self._conn.execute(query).fetchone()
        return row[0]

    # ==================== 密码历史（Password History） ====================

    @_db_operation
    def add_password_history(
        self,
        entry_id: int,
        old_password_enc: str,
        changed_at: str = '',
    ):
        """添加密码历史记录"""
        self._guard_write()
        self._conn.execute(
            "INSERT INTO password_history (entry_id, old_password_enc, changed_at) VALUES (?, ?, ?)",
            (entry_id, old_password_enc, changed_at or datetime.now(timezone.utc).isoformat()),
        )
        # 仅在超过上限时截断，避免每次插入都运行子查询 DELETE
        count = self._conn.execute(
            "SELECT COUNT(*) FROM password_history WHERE entry_id = ?",
            (entry_id,),
        ).fetchone()[0]
        if count > self.MAX_PASSWORD_HISTORY:
            self._conn.execute(
                "DELETE FROM password_history WHERE entry_id = ? AND id NOT IN ("
                "  SELECT id FROM password_history WHERE entry_id = ?"
                "  ORDER BY changed_at DESC LIMIT ?"
                ")",
                (entry_id, entry_id, self.MAX_PASSWORD_HISTORY),
            )
        self._auto_commit()

    @_db_operation
    def add_password_history_batch(
        self,
        entry_id: int,
        items: list[tuple[str, str]],
    ):
        """M-C1：批量添加密码历史，末尾统一截断到 MAX_PASSWORD_HISTORY 条。

        相比逐条调用 add_password_history，避免每条记录触发一次截断 DELETE。
        用于备份恢复等需一次性写入多条历史的场景。

        Args:
            entry_id: 条目 ID。
            items: [(old_password_enc, changed_at), ...] 列表。
        """
        if not items:
            return
        self._guard_write()
        now = datetime.now(timezone.utc).isoformat()
        rows = [
            (entry_id, enc, changed_at or now)
            for enc, changed_at in items
        ]
        self._conn.executemany(
            "INSERT INTO password_history (entry_id, old_password_enc, changed_at) "
            "VALUES (?, ?, ?)",
            rows,
        )
        # 统一截断：仅一次 DELETE，替代逐条触发的 N 次截断
        self._conn.execute(
            "DELETE FROM password_history WHERE entry_id = ? AND id NOT IN ("
            "  SELECT id FROM password_history WHERE entry_id = ?"
            "  ORDER BY changed_at DESC LIMIT ?"
            ")",
            (entry_id, entry_id, self.MAX_PASSWORD_HISTORY),
        )
        self._auto_commit()

    @_db_operation
    def get_password_history(self, entry_id: int) -> list[PasswordHistory]:
        """获取条目的密码历史"""
        rows = self._conn.execute(
            """SELECT h.*, e.crypto_id AS entry_crypto_id
               FROM password_history h JOIN entries e ON e.id=h.entry_id
               WHERE h.entry_id = ? ORDER BY h.changed_at DESC, h.id DESC""",
            (entry_id,),
        ).fetchall()
        return [self._row_to_password_history(r) for r in rows]

    @_db_operation
    def get_all_password_history(self) -> list[PasswordHistory]:
        """获取全部密码历史，用于改密和备份。"""
        rows = self._conn.execute(
            """SELECT h.*, e.crypto_id AS entry_crypto_id
               FROM password_history h JOIN entries e ON e.id=h.entry_id
               ORDER BY h.id"""
        ).fetchall()
        return [self._row_to_password_history(r) for r in rows]

    @_db_operation
    def get_all_password_history_batch(
        self, after_id: int = 0, limit: int = 200
    ) -> list[PasswordHistory]:
        """分批获取全部密码历史，用于改密重加密时控制内存峰值。

        使用游标分页（after_id），与 get_entries 的分页策略一致，
        避免并发写入时 OFFSET 分页可能导致的跳过/重复问题。
        """
        rows = self._conn.execute(
            """SELECT h.*, e.crypto_id AS entry_crypto_id
               FROM password_history h JOIN entries e ON e.id=h.entry_id
               WHERE h.id > ?
               ORDER BY h.id LIMIT ?""",
            (after_id, limit),
        ).fetchall()
        return [self._row_to_password_history(r) for r in rows]

    @_db_operation
    def get_password_history_count(self, entry_id: int) -> int:
        """获取条目的密码历史记录数（轻量 COUNT 查询）。"""
        row = self._conn.execute(
            "SELECT COUNT(*) FROM password_history WHERE entry_id = ?",
            (entry_id,),
        ).fetchone()
        return row[0] if row else 0

    @_db_operation
    def update_password_history_ciphertext(self, history_id: int, ciphertext: str):
        """更新密码历史密文，不改变历史时间。"""
        self._guard_write()
        self._conn.execute(
            "UPDATE password_history SET old_password_enc=? WHERE id=?",
            (ciphertext, history_id),
        )
        self._auto_commit()

    @_db_operation
    def update_password_history_batch(self, rows: list[tuple]):
        """批量更新密码历史记录的密文。

        M-15：改密重加密时将逐条 UPDATE 合并为单次 executemany，减少数据库
        往返次数。每行格式：(new_password_enc, id)。
        """
        if not rows:
            return
        self._guard_write()
        self._conn.executemany(
            "UPDATE password_history SET old_password_enc=? WHERE id=?",
            rows,
        )
        self._auto_commit()

    # ========== 内部方法 ==========

    @staticmethod
    def _row_to_category(row: sqlite3.Row) -> Category:
        return Category(
            id=row['id'],
            name=row['name'],
            icon_char=row['icon_char'],
            color=row['color'],
            sort_order=row['sort_order'],
            created_at=row['created_at'],
        )

    def _select_entry_for_sign(self, entry_id: int) -> Entry | None:
        """按 ID 查询签名所需的完整行并返回 Entry 对象。

        供 soft_delete_entry / restore_entry 等需要重算签名的操作复用，
        避免在多处重复维护列名列表。跳过完整性校验，因为签名操作本身
        需要读取原始数据来计算 MAC。
        """
        row = self._conn.execute(
            _SELECT_ENTRY_SIGN_SQL,
            (entry_id,),
        ).fetchone()
        return self._row_to_entry(row, verify=VerifyMode.SKIP) if row else None

    def _row_to_entry(self, row: sqlite3.Row,
                       verify: VerifyMode = VerifyMode.STRICT) -> Entry:
        entry = Entry(
            id=row['id'],
            crypto_id=row['crypto_id'],
            title=row['title'],
            username=row['username_enc'],
            password=row['password_enc'],
            url=row['url'] or '',
            category_id=row['category_id'],
            category_name=row['category_name'] if 'category_name' in row.keys() else '',
            tags=row['tags'] or '',
            notes=row['notes_enc'],
            custom_fields_enc=row['custom_fields_enc'] or '',
            custom_fields=row['custom_fields_enc'],
            is_favorite=bool(row['is_favorite']),
            is_deleted=bool(row['is_deleted']),
            password_strength=row['password_strength'],
            entry_type=row['entry_type'],
            totp_secret=row['totp_secret_enc'],
            created_at=row['created_at'] or '',
            updated_at=row['updated_at'] or '',
            deleted_at=row['deleted_at'] or '',
            password_changed_at=row['password_changed_at'] or '',
            metadata_mac=row['metadata_mac'] or '',
        )
        if self._entry_verifier and verify != VerifyMode.SKIP:
            try:
                self._entry_verifier(entry)
            except VaultError:
                if verify == VerifyMode.STRICT:
                    raise
                entry.integrity_error = True
                entry.integrity_message = '元数据完整性校验失败'
        return entry

    @staticmethod
    def _row_to_password_history(row: sqlite3.Row) -> PasswordHistory:
        """从 JOIN 查询行构建 PasswordHistory 对象（含 entry_crypto_id）。"""
        return PasswordHistory(
            id=row['id'],
            entry_id=row['entry_id'],
            old_password_enc=row['old_password_enc'],
            changed_at=row['changed_at'],
            entry_crypto_id=row['entry_crypto_id'],
        )

    @_db_operation
    def get_all_tags(self) -> list[str]:
        """获取所有未删除条目的标签字段（轻量查询，不加载加密列）"""
        rows = self._conn.execute(
            "SELECT tags FROM entries WHERE is_deleted=0"
        ).fetchall()
        return [row['tags'] or '' for row in rows]

    def _sign_entry(self, entry: Entry) -> str:
        if self._entry_signer:
            return self._entry_signer(entry)
        return entry.metadata_mac
