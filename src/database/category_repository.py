"""分类数据访问层 — 分类 CRUD 及条目统计。

职责单一：categories 表的增删改查，经 DatabaseManager 委托提供统一数据访问接口。
"""

import logging
import sqlite3
import threading
from dataclasses import replace
from typing import Any

from ..exceptions import DatabaseError, TransactionError, VaultIntegrityError, VaultLockedError
from ..models import Category
from ..utils.format import utc_now_iso
from ._decorators import _db_operation, _db_write
from .types import ConnectionProvider

logger = logging.getLogger(__name__)


class CategoryRepository:
    """分类数据访问层。

    经 ``conn_provider`` 获取 sqlite3.Connection（通常为 DatabaseManager 实例）。
    """

    def __init__(self, conn_provider: ConnectionProvider):
        self._mgr = conn_provider

    # ======== 连接与锁代理 ========

    @property
    def _conn(self) -> sqlite3.Connection:
        return self._mgr.connection

    @property
    def _lock(self) -> threading.RLock:
        return self._mgr.db_lock

    @property
    def in_transaction(self) -> bool:
        return self._mgr.in_transaction

    def _guard_write(self) -> None:
        return self._mgr.guard_write()

    def _auto_commit(self) -> None:
        return self._mgr.auto_commit()

    def _sign_category(self, category: Category) -> str:
        return self._mgr.sign_category(category)

    def _assert_encrypted(self, value: str, field_name: str) -> None:
        """防御性断言：加密列的值应为受支持格式的密文，或空字符串（ARCH-003）。

        与 :meth:`entry_repository._assert_encrypted` 对称，防绕过 CategoryManager
        直接调 db 层写入时明文分类名静默落库。仅校验密文形态，真正认证由 GCM 标签完成。
        """
        self._mgr.assert_encrypted(value, field_name)

    def _verify_category_if_signed(self, category: Category) -> Category:
        """LENIENT 验签分类完整性：有签名（metadata_mac 非空）才验，失败记日志并标记。

        默认分类在首次签名前 mac 为空属合法未签名状态，跳过避免噪音；其余分类有签名
        则验，篡改置 ``integrity_error=True`` 供 UI 可见。分类名密文由 GCM 兜底，本验签
        覆盖 icon/color/sort_order 等非加密元数据。改密重签路径传 verify=False 跳过，
        避免旧签名在新域密钥下的假阳性告警。
        """
        verifier = self._mgr.category_verifier
        if verifier and category.metadata_mac:
            try:
                verifier(category)
            except VaultIntegrityError:
                logger.warning("分类 %s 元数据完整性校验失败", category.id)
                return replace(category, integrity_error=True)
            except VaultLockedError:
                # 锁定竞态：域密钥在取行后被 prepare_for_lock 清零，锁定态验签无意义。
                # 与 entry_repository._row_to_entry 一致向上传播（SEC-012），让调用方
                # 统一处理锁定竞态，避免分类读路径静默返回未验签数据与条目路径行为不一致。
                raise
        return category

    # ==================== 分类 ====================

    @_db_operation
    def get_categories(self, *, verify: bool = True) -> list[Category]:
        """获取所有分类。

        Args:
            verify: True 时对有签名的分类做 LENIENT 完整性验签（失败记日志）；
                改密重签等路径传 False 跳过，避免旧签名在新域密钥下的假阳性告警。
        """
        # 仅按 sort_order 排序：name_enc 为密文，密文序无意义；分类名排序由
        # CategoryManager.get_categories 在解密后按 name.casefold() 完成（PERF-008）。
        rows = self._conn.execute(
            "SELECT id, name_enc, icon_char, color, sort_order, created_at, metadata_mac "
            "FROM categories ORDER BY sort_order"
        ).fetchall()
        categories = [self._row_to_category(r) for r in rows]
        if verify:
            categories = [self._verify_category_if_signed(c) for c in categories]
        return categories

    @_db_operation
    def get_category(self, category_id: int, *, verify: bool = True) -> Category | None:
        """获取单个分类。verify 语义同 :meth:`get_categories`。"""
        row = self._conn.execute(
            "SELECT id, name_enc, icon_char, color, sort_order, created_at, metadata_mac "
            "FROM categories WHERE id = ?",
            (category_id,),
        ).fetchone()
        if row is None:
            return None
        category = self._row_to_category(row)
        if verify:
            category = self._verify_category_if_signed(category)
        return category

    @_db_write
    def add_category(self, category: Category) -> int:
        """添加分类，返回 ID。

        名称以加密形态存储（每次 nonce 不同，同名明文加密后互异），categories.name
        的 UNIQUE 约束与本处查重均无法对加密名触发。本查重仅对直接传明文名的调用方
        （含本层测试）兜底；生产路径的明文查重在 CategoryManager.add_category。
        """
        if self._conn.execute(
            "SELECT 1 FROM categories WHERE name_enc=? LIMIT 1", (category.name,)
        ).fetchone():
            raise ValueError("分类名称已存在（加密名冲突，明文查重见 CategoryManager）")
        # 回填 created_at 至内存对象：保证两阶段重签与 INSERT 用同一值。否则 DB 层
        # 写真实时间戳而内存对象为空，重签用空 created_at 算 mac 致签名与持久化行错配、
        # 重载后验签永久失败。
        created_at = category.created_at or utc_now_iso()
        category = replace(category, created_at=created_at)
        category = replace(category, metadata_mac=self._sign_category(category))
        self._assert_encrypted(category.name, "name_enc")  # ARCH-003：拦截明文落库
        cursor = self._conn.execute(
            "INSERT INTO categories (name_enc, icon_char, color, sort_order, created_at, metadata_mac) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                category.name,
                category.icon_char,
                category.color,
                category.sort_order,
                created_at,
                category.metadata_mac,
            ),
        )
        self._auto_commit()
        return cursor.lastrowid or 0

    @staticmethod
    def _category_update_tuple(category: Category) -> tuple[Any, ...]:
        """构造 UPDATE categories 的参数元组，供单条与批量写入复用以消除列序重复。"""
        return (
            category.name,
            category.icon_char,
            category.color,
            category.sort_order,
            category.metadata_mac,
            category.id,
        )

    def _update_category_row(self, category: Category) -> None:
        """写入分类行（不含查重/created_at 回填/签名），供 update_category 复用同一 UPDATE SQL。"""
        self._assert_encrypted(category.name, "name_enc")  # ARCH-003：拦截明文落库
        self._conn.execute(
            "UPDATE categories SET name_enc=?, icon_char=?, color=?, sort_order=?, metadata_mac=? WHERE id=?",
            self._category_update_tuple(category),
        )
        self._auto_commit()

    @_db_write
    def update_category(self, category: Category) -> None:
        """更新分类。

        加密名每次 nonce 不同致本处查重无法触发，仅对直接传明文名的调用方兜底；
        生产路径的明文查重在 CategoryManager.update_category。
        """
        if (
            category.id is not None
            and self._conn.execute(
                "SELECT 1 FROM categories WHERE name_enc=? AND id!=? LIMIT 1",
                (category.name, category.id),
            ).fetchone()
        ):
            raise ValueError(f"分类名称「{category.name}」已被其他分类占用")
        # created_at 创建后不可变（SQL 不写该列）：签名须用 DB 现有值，否则调用方传
        # 空/不一致值会使签名与持久化行错配、重载验签失败（与 add_category 回填对称）。
        existing = self._conn.execute(
            "SELECT created_at FROM categories WHERE id=?", (category.id,)
        ).fetchone()
        if existing is None:
            raise DatabaseError(f"分类 {category.id} 不存在，无法更新")
        category = replace(category, created_at=existing["created_at"])
        category = replace(category, metadata_mac=self._sign_category(category))
        self._update_category_row(category)

    @_db_write
    def update_categories_batch(self, categories: list[Category]) -> None:
        """改密重加密专用批量写入：executemany 一次性更新已预签名的分类。

        不重算签名（调用方已用新域密钥经 :meth:`MetadataSigner.sign_category_with_domain_key`
        预签名）、不查重（密文名每次 nonce 不同，查重无意义），直接 UPDATE。``category``
        来自 ``get_categories``，``created_at`` 已是 DB 值，SQL 不写该列。``_auto_commit``
        在活动事务内不真正提交，批量只触发一次权限刷新。
        """
        if not categories:
            return
        for c in categories:
            self._assert_encrypted(c.name, "name_enc")  # ARCH-003：拦截明文落库
        self._conn.executemany(
            "UPDATE categories SET name_enc=?, icon_char=?, color=?, sort_order=?, metadata_mac=? WHERE id=?",
            [self._category_update_tuple(c) for c in categories],
        )
        self._auto_commit()

    def delete_category(self, category_id: int) -> None:
        """删除分类行。

        仅删 categories 行；关联条目的解关联与重签由
        DatabaseManager.delete_category 编排 EntryRepository.clear_category_signatures
        完成，避免本 Repository 跨表访问。

        锁与事务契约：未用 ``@_db_operation``，不自行获取 ``db_lock``。调用方
        （DatabaseManager.delete_category）须已持锁并处活动事务内，使 DELETE 与条目
        解关联原子提交/回滚。入口断言将此契约升级为运行期检查。
        """
        if not self.in_transaction:
            raise TransactionError(
                "delete_category 须在活动事务内调用（由 DatabaseManager.delete_category 编排）"
            )
        self._conn.execute("DELETE FROM categories WHERE id=?", (category_id,))

    @_db_operation
    def get_category_entry_count(self, category_id: int) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) FROM entries WHERE category_id=? AND is_deleted=0",
            (category_id,),
        ).fetchone()
        return int(row[0]) if row else 0

    @_db_operation
    def get_category_entry_counts(self) -> dict[int, int]:
        """一次查询返回所有分类的有效条目数量。"""
        rows = self._conn.execute(
            """SELECT category_id, COUNT(*) AS entry_count
               FROM entries
               WHERE is_deleted=0 AND category_id IS NOT NULL
               GROUP BY category_id"""
        ).fetchall()
        return {row["category_id"]: row["entry_count"] for row in rows}

    # ========== 内部方法 ==========

    @staticmethod
    def _row_to_category(row: sqlite3.Row) -> Category:
        return Category(
            id=row["id"],
            name=row["name_enc"],
            icon_char=row["icon_char"],
            color=row["color"],
            sort_order=row["sort_order"],
            created_at=row["created_at"],
            metadata_mac=row["metadata_mac"],
        )
