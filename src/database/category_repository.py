"""分类数据访问层 — 分类 CRUD 及条目统计。

从 DatabaseManager 拆分而来，职责单一：categories 表的增删改查。
所有公共方法签名和返回值与原 DatabaseManager 完全一致，确保向后兼容。
"""

import logging
import sqlite3
from typing import Optional

from ..utils.format import utc_now_iso
from ._decorators import _db_operation
from .models import Category, Entry

logger = logging.getLogger(__name__)


class CategoryRepository:
    """分类数据访问层。

    通过 ``conn_provider`` 获取 sqlite3.Connection，支持外部注入连接，
    通常为 DatabaseManager 实例。
    """

    def __init__(self, conn_provider):
        self._mgr = conn_provider

    # ======== 连接与锁代理 ========

    @property
    def _conn(self):
        return self._mgr._conn

    @property
    def _lock(self):
        return self._mgr._lock

    def _guard_write(self):
        return self._mgr._guard_write()

    def _auto_commit(self):
        return self._mgr._auto_commit()

    def _sign_entry(self, entry: Entry) -> str:
        return self._mgr._sign_entry(entry)

    def transaction(self):
        return self._mgr.transaction()

    # ==================== 分类 ====================

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
             category.created_at or utc_now_iso()),
        )
        self._auto_commit()
        return cursor.lastrowid or 0

    @_db_operation
    def update_category(self, category: Category) -> None:
        """更新分类"""
        self._guard_write()
        self._conn.execute(
            "UPDATE categories SET name=?, icon_char=?, color=?, sort_order=? WHERE id=?",
            (category.name, category.icon_char, category.color, category.sort_order, category.id),
        )
        self._auto_commit()

    def delete_category(self, category_id: int) -> None:
        """删除分类，将关联条目的 category_id 置空并重算签名。

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
                    entry = self._mgr.entries._row_to_entry(row)
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
