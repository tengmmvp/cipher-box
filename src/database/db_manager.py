"""数据库管理器 - SQLite 数据库操作"""

import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

from .models import Category, Entry, PasswordHistory


class DatabaseManager:
    """SQLite 数据库管理器"""

    SCHEMA_VERSION = 3

    def __init__(self, db_path: Path):
        self._db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._in_transaction = False

    # ========== 事务管理 ==========

    def begin_transaction(self):
        """开始事务（抑制内部 commit）"""
        if self._conn is None:
            raise RuntimeError("数据库未连接")
        self._conn.execute("BEGIN TRANSACTION")
        self._in_transaction = True

    def commit_transaction(self):
        """提交事务"""
        if self._conn is None:
            raise RuntimeError("数据库未连接")
        self._conn.execute("COMMIT")
        self._in_transaction = False

    def rollback_transaction(self):
        """回滚事务"""
        if self._conn is None:
            raise RuntimeError("数据库未连接")
        try:
            self._conn.execute("ROLLBACK")
        except sqlite3.OperationalError:
            pass
        self._in_transaction = False

    def _auto_commit(self):
        """内部提交：仅在非事务模式下执行 commit"""
        if not self._in_transaction and self._conn:
            try:
                self._conn.commit()
            except Exception:
                logger.error("数据库提交失败", exc_info=True)
                raise

    def open(self) -> bool:
        """打开数据库连接"""
        try:
            self._conn = sqlite3.connect(
                str(self._db_path),
                check_same_thread=False,
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            return True
        except sqlite3.Error:
            logger.error("数据库打开失败", exc_info=True)
            return False

    def close(self):
        """关闭数据库连接"""
        if self._conn:
            self._conn.close()
            self._conn = None

    def init_tables(self):
        """初始化数据库表"""
        if self._conn is None:
            raise RuntimeError("数据库未连接")
        cursor = self._conn.cursor()

        cursor.executescript("""
            CREATE TABLE IF NOT EXISTS vault_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                icon_char TEXT DEFAULT '📁',
                color TEXT DEFAULT '#666666',
                sort_order INTEGER DEFAULT 0,
                created_at TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
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
            CREATE INDEX IF NOT EXISTS idx_pw_history_entry ON password_history(entry_id);
        """)

        # 迁移：为已有的 entries 表添加新列
        self._migrate_schema(cursor)

        # 插入默认分类
        default_categories = [
            ('未分类', '📎', '#888888', 0),
            ('社交', '👥', '#4CAF50', 1),
            ('邮箱', '📧', '#2196F3', 2),
            ('金融', '🏦', '#F44336', 3),
            ('购物', '🛒', '#FF9800', 4),
            ('工作', '💼', '#607D8B', 5),
            ('娱乐', '🎮', '#9C27B0', 6),
            ('开发', '💻', '#00BCD4', 7),
        ]
        for name, icon, color, order in default_categories:
            try:
                cursor.execute(
                    "INSERT OR IGNORE INTO categories (name, icon_char, color, sort_order, created_at) VALUES (?, ?, ?, ?, ?)",
                    (name, icon, color, order, datetime.now().isoformat()),
                )
            except sqlite3.IntegrityError:
                pass

        # 记录 schema 版本
        cursor.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?, ?)",
            ('schema_version', str(self.SCHEMA_VERSION)),
        )

        self._auto_commit()

    def _migrate_schema(self, cursor):
        """迁移旧版数据库结构"""
        # 检查是否需要迁移
        try:
            row = cursor.execute(
                "SELECT value FROM vault_meta WHERE key = 'schema_version'"
            ).fetchone()
            version = int(row['value']) if row else 0
        except Exception:
            version = 0

        if version >= self.SCHEMA_VERSION:
            return

        # V1 → V2: 添加 entry_type、totp_secret_enc 列和 password_history 表
        if version < 2:
            # 检查列是否已存在
            cols = [r[1] for r in cursor.execute("PRAGMA table_info(entries)").fetchall()]
            if 'entry_type' not in cols:
                cursor.execute("ALTER TABLE entries ADD COLUMN entry_type TEXT DEFAULT 'login'")
            if 'totp_secret_enc' not in cols:
                cursor.execute("ALTER TABLE entries ADD COLUMN totp_secret_enc TEXT DEFAULT ''")

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS password_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entry_id INTEGER NOT NULL,
                    old_password_enc TEXT DEFAULT '',
                    changed_at TEXT DEFAULT '',
                    FOREIGN KEY (entry_id) REFERENCES entries(id) ON DELETE CASCADE
                )
            """)
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_pw_history_entry ON password_history(entry_id)"
            )

        if version < 3:
            cols = [r[1] for r in cursor.execute("PRAGMA table_info(entries)").fetchall()]
            if 'password_changed_at' not in cols:
                cursor.execute("ALTER TABLE entries ADD COLUMN password_changed_at TEXT DEFAULT ''")
            cursor.execute("""
                UPDATE entries
                SET password_changed_at = CASE
                    WHEN updated_at != '' THEN updated_at ELSE created_at END
                WHERE password_changed_at = ''
            """)

    # ========== Vault Meta ==========

    def get_meta(self, key: str) -> Optional[str]:
        """获取元数据"""
        if self._conn is None:
            raise RuntimeError("数据库未连接")
        row = self._conn.execute(
            "SELECT value FROM vault_meta WHERE key = ?", (key,)
        ).fetchone()
        return row['value'] if row else None

    def set_meta(self, key: str, value: str):
        """设置元数据"""
        if self._conn is None:
            raise RuntimeError("数据库未连接")
        self._conn.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?, ?)",
            (key, value),
        )
        self._auto_commit()

    # ========== Categories ==========

    def get_categories(self) -> list[Category]:
        """获取所有分类"""
        if self._conn is None:
            raise RuntimeError("数据库未连接")
        rows = self._conn.execute(
            "SELECT * FROM categories ORDER BY sort_order, name"
        ).fetchall()
        return [self._row_to_category(r) for r in rows]

    def get_category(self, category_id: int) -> Optional[Category]:
        """获取单个分类"""
        if self._conn is None:
            raise RuntimeError("数据库未连接")
        row = self._conn.execute(
            "SELECT * FROM categories WHERE id = ?", (category_id,)
        ).fetchone()
        return self._row_to_category(row) if row else None

    def add_category(self, category: Category) -> int:
        """添加分类，返回 ID"""
        if self._conn is None:
            raise RuntimeError("数据库未连接")
        cursor = self._conn.execute(
            "INSERT INTO categories (name, icon_char, color, sort_order, created_at) VALUES (?, ?, ?, ?, ?)",
            (category.name, category.icon_char, category.color, category.sort_order,
             category.created_at or datetime.now().isoformat()),
        )
        self._auto_commit()
        return cursor.lastrowid or 0

    def update_category(self, category: Category):
        """更新分类"""
        if self._conn is None:
            raise RuntimeError("数据库未连接")
        self._conn.execute(
            "UPDATE categories SET name=?, icon_char=?, color=?, sort_order=? WHERE id=?",
            (category.name, category.icon_char, category.color, category.sort_order, category.id),
        )
        self._auto_commit()

    def delete_category(self, category_id: int):
        """删除分类"""
        if self._conn is None:
            raise RuntimeError("数据库未连接")
        self._conn.execute(
            "UPDATE entries SET category_id=NULL WHERE category_id=?", (category_id,)
        )
        self._conn.execute("DELETE FROM categories WHERE id=?", (category_id,))
        self._auto_commit()

    def get_category_entry_count(self, category_id: int) -> int:
        """获取分类下的条目数量"""
        if self._conn is None:
            raise RuntimeError("数据库未连接")
        row = self._conn.execute(
            "SELECT COUNT(*) FROM entries WHERE category_id=? AND is_deleted=0",
            (category_id,),
        ).fetchone()
        return row[0]

    # ========== Entries ==========

    def get_entries(
        self,
        deleted_only: bool = False,
        include_deleted: bool = False,
        category_id: Optional[int] = None,
        favorite_only: bool = False,
        search: str = '',
    ) -> list[Entry]:
        """获取密码条目列表"""
        if self._conn is None:
            raise RuntimeError("数据库未连接")

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

        if search:
            query += " AND (e.title LIKE ? OR e.url LIKE ? OR e.tags LIKE ?)"
            search_param = f"%{search}%"
            params.extend([search_param, search_param, search_param])

        query += " ORDER BY e.is_favorite DESC, e.updated_at DESC"

        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def get_entry(self, entry_id: int) -> Optional[Entry]:
        """获取单个条目"""
        if self._conn is None:
            raise RuntimeError("数据库未连接")
        row = self._conn.execute(
            """SELECT e.*, c.name as category_name
               FROM entries e
               LEFT JOIN categories c ON e.category_id = c.id
               WHERE e.id = ?""",
            (entry_id,),
        ).fetchone()
        return self._row_to_entry(row) if row else None

    def add_entry(self, entry: Entry, preserve_metadata: bool = False) -> int:
        """添加条目，返回 ID"""
        if self._conn is None:
            raise RuntimeError("数据库未连接")
        now = datetime.now().isoformat()
        updated_at = entry.updated_at if preserve_metadata and entry.updated_at else now
        deleted_at = entry.deleted_at if preserve_metadata else ''
        cursor = self._conn.execute(
            """INSERT INTO entries
               (title, username_enc, password_enc, url, category_id, tags,
                notes_enc, custom_fields_enc, is_favorite, is_deleted,
                 password_strength, entry_type, totp_secret_enc, created_at, updated_at,
                 deleted_at, password_changed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                entry.title,
                entry.username,
                entry.password,
                entry.url,
                entry.category_id,
                entry.tags,
                entry.notes,
                entry.custom_fields,
                1 if entry.is_favorite else 0,
                1 if preserve_metadata and entry.is_deleted else 0,
                entry.password_strength,
                entry.entry_type,
                entry.totp_secret,
                entry.created_at or now,
                updated_at,
                deleted_at,
                entry.password_changed_at or entry.updated_at or entry.created_at or now,
            ),
        )
        self._auto_commit()
        return cursor.lastrowid or 0

    def update_entry(self, entry: Entry, preserve_updated_at: bool = False):
        """更新条目"""
        if self._conn is None:
            raise RuntimeError("数据库未连接")
        now = entry.updated_at if preserve_updated_at and entry.updated_at else datetime.now().isoformat()
        self._conn.execute(
            """UPDATE entries SET
               title=?, username_enc=?, password_enc=?, url=?, category_id=?,
               tags=?, notes_enc=?, custom_fields_enc=?, is_favorite=?,
               password_strength=?, entry_type=?, totp_secret_enc=?, updated_at=?,
               password_changed_at=?
               WHERE id=?""",
            (
                entry.title,
                entry.username,
                entry.password,
                entry.url,
                entry.category_id,
                entry.tags,
                entry.notes,
                entry.custom_fields,
                1 if entry.is_favorite else 0,
                entry.password_strength,
                entry.entry_type,
                entry.totp_secret,
                now,
                entry.password_changed_at,
                entry.id,
            ),
        )
        self._auto_commit()

    def soft_delete_entry(self, entry_id: int):
        """软删除条目"""
        if self._conn is None:
            raise RuntimeError("数据库未连接")
        now = datetime.now().isoformat()
        self._conn.execute(
            "UPDATE entries SET is_deleted=1, deleted_at=? WHERE id=?",
            (now, entry_id),
        )
        self._auto_commit()

    def restore_entry(self, entry_id: int):
        """恢复条目"""
        if self._conn is None:
            raise RuntimeError("数据库未连接")
        self._conn.execute(
            "UPDATE entries SET is_deleted=0, deleted_at='' WHERE id=?",
            (entry_id,),
        )
        self._auto_commit()

    def permanent_delete_entry(self, entry_id: int):
        """永久删除条目"""
        if self._conn is None:
            raise RuntimeError("数据库未连接")
        self._conn.execute("DELETE FROM entries WHERE id=?", (entry_id,))
        self._auto_commit()

    def empty_trash(self):
        """清空回收站"""
        if self._conn is None:
            raise RuntimeError("数据库未连接")
        self._conn.execute("DELETE FROM entries WHERE is_deleted=1")
        self._auto_commit()

    def get_entry_count(self, include_deleted: bool = False) -> int:
        """获取条目数量"""
        if self._conn is None:
            raise RuntimeError("数据库未连接")
        query = "SELECT COUNT(*) FROM entries"
        if not include_deleted:
            query += " WHERE is_deleted = 0"
        row = self._conn.execute(query).fetchone()
        return row[0]

    def get_all_entry_passwords_encrypted(self) -> list[tuple[int, str, str]]:
        """获取所有加密密码（用于检测重复）"""
        if self._conn is None:
            raise RuntimeError("数据库未连接")
        rows = self._conn.execute(
            "SELECT id, title, password_enc FROM entries WHERE is_deleted=0 AND password_enc != ''"
        ).fetchall()
        return [(r['id'], r['title'], r['password_enc']) for r in rows]

    def get_old_entries(self, days: int) -> list[Entry]:
        """获取超过指定天数未修改的条目"""
        if self._conn is None:
            raise RuntimeError("数据库未连接")
        rows = self._conn.execute(
            """SELECT e.*, c.name as category_name
               FROM entries e
               LEFT JOIN categories c ON e.category_id = c.id
               WHERE e.is_deleted = 0
               AND julianday('now') - julianday(
                   CASE WHEN e.password_changed_at != ''
                        THEN e.password_changed_at ELSE e.updated_at END
               ) > ?
               ORDER BY e.password_changed_at ASC""",
            (days,),
        ).fetchall()
        return [self._row_to_entry(r) for r in rows]

    # ========== Password History ==========

    def add_password_history(
        self,
        entry_id: int,
        old_password_enc: str,
        changed_at: str = '',
    ):
        """添加密码历史记录"""
        if self._conn is None:
            raise RuntimeError("数据库未连接")
        self._conn.execute(
            "INSERT INTO password_history (entry_id, old_password_enc, changed_at) VALUES (?, ?, ?)",
            (entry_id, old_password_enc, changed_at or datetime.now().isoformat()),
        )
        # 只保留最近 10 条
        self._conn.execute("""
            DELETE FROM password_history WHERE entry_id = ? AND id NOT IN (
                SELECT id FROM password_history WHERE entry_id = ?
                ORDER BY changed_at DESC LIMIT 10
            )
        """, (entry_id, entry_id))
        self._auto_commit()

    def get_password_history(self, entry_id: int) -> list[PasswordHistory]:
        """获取条目的密码历史"""
        if self._conn is None:
            raise RuntimeError("数据库未连接")
        rows = self._conn.execute(
            "SELECT * FROM password_history WHERE entry_id = ? ORDER BY changed_at DESC, id DESC",
            (entry_id,),
        ).fetchall()
        return [PasswordHistory(
            id=r['id'],
            entry_id=r['entry_id'],
            old_password_enc=r['old_password_enc'],
            changed_at=r['changed_at'],
        ) for r in rows]

    def get_all_password_history(self) -> list[PasswordHistory]:
        """获取全部密码历史，用于改密和备份。"""
        if self._conn is None:
            raise RuntimeError("数据库未连接")
        rows = self._conn.execute(
            "SELECT * FROM password_history ORDER BY id"
        ).fetchall()
        return [PasswordHistory(
            id=r['id'],
            entry_id=r['entry_id'],
            old_password_enc=r['old_password_enc'],
            changed_at=r['changed_at'],
        ) for r in rows]

    def update_password_history_ciphertext(self, history_id: int, ciphertext: str):
        """更新密码历史密文，不改变历史时间。"""
        if self._conn is None:
            raise RuntimeError("数据库未连接")
        self._conn.execute(
            "UPDATE password_history SET old_password_enc=? WHERE id=?",
            (ciphertext, history_id),
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

    @staticmethod
    def _row_to_entry(row: sqlite3.Row) -> Entry:
        return Entry(
            id=row['id'],
            title=row['title'],
            username=row['username_enc'],
            password=row['password_enc'],
            url=row['url'] or '',
            category_id=row['category_id'],
            category_name=row['category_name'] or '',
            tags=row['tags'] or '',
            notes=row['notes_enc'],
            custom_fields=row['custom_fields_enc'],
            is_favorite=bool(row['is_favorite']),
            is_deleted=bool(row['is_deleted']),
            password_strength=row['password_strength'],
            entry_type=row['entry_type'] if 'entry_type' in row.keys() else 'login',
            totp_secret=row['totp_secret_enc'] if 'totp_secret_enc' in row.keys() else '',
            created_at=row['created_at'] or '',
            updated_at=row['updated_at'] or '',
            deleted_at=row['deleted_at'] or '',
            password_changed_at=(
                row['password_changed_at'] if 'password_changed_at' in row.keys() else row['updated_at']
            ) or '',
        )
