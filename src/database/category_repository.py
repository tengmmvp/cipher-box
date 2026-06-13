"""分类数据访问层 — 分类 CRUD 及条目统计。

从 DatabaseManager 拆分而来，职责单一：categories 表的增删改查。
通过 DatabaseManager 委托提供统一数据访问接口。
"""

import logging
import sqlite3
from typing import Optional

from ..models import Category
from ..utils.format import utc_now_iso
from ._decorators import _db_operation

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
        return self._mgr.connection

    @property
    def _lock(self):
        return self._mgr.db_lock

    def _guard_write(self):
        return self._mgr.guard_write()

    def _auto_commit(self):
        return self._mgr.auto_commit()

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
        """删除分类行。

        仅删除 categories 表的行；关联条目的解关联与元数据重签由
        DatabaseManager.delete_category 编排 EntryRepository.clear_category_signatures
        完成，避免本 Repository 跨表访问 EntryRepository 的私有方法。

        锁与事务契约：本方法未使用 ``@_db_operation`` 装饰器，不自行获取
        ``db_lock``。调用方（DatabaseManager.delete_category）须已持有
        ``db_lock`` 并处于活动事务内，使本 DELETE 与条目解关联在同事务内
        原子提交或回滚。
        """
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
