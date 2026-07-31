"""分类数据访问层 — 分类 CRUD 及条目统计。

从 DatabaseManager 拆分而来，职责单一：categories 表的增删改查。
通过 DatabaseManager 委托提供统一数据访问接口。
"""

import logging
import sqlite3
import threading
from typing import Any

from ..exceptions import VaultIntegrityError, VaultLockedError
from ..models import Category
from ..utils.format import utc_now_iso
from ._decorators import _db_operation, _db_write
from .types import ConnectionProvider

logger = logging.getLogger(__name__)


class CategoryRepository:
    """分类数据访问层。

    通过 ``conn_provider`` 获取 sqlite3.Connection，支持外部注入连接，
    通常为 DatabaseManager 实例。
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

    def _verify_category_if_signed(self, category: Category) -> None:
        """LENIENT 验签分类完整性：有签名（metadata_mac 非空）才验，失败记日志并标记。

        首次初始化的默认分类在 encrypt_plaintext_category_names 签名前 mac 为空，
        属合法未签名状态，跳过验签避免噪音；其余分类有签名则验，篡改记 warning 并
        置 ``category.integrity_error = True``，供 UI（sidebar ⚠ 标识）对用户可见。
        分类名密文仍由 GCM 认证兜底；本验签覆盖 icon/color/sort_order 等非加密元数据。
        改密重签路径以 verify=False 跳过本验签，避免旧签名在新域密钥下的假阳性告警。
        """
        verifier = self._mgr.category_verifier
        if verifier and category.metadata_mac:
            try:
                verifier(category)
            except VaultIntegrityError:
                logger.warning("分类 %s 元数据完整性校验失败", category.id)
                category.integrity_error = True
            except VaultLockedError:
                # 锁定竞态：域密钥在取行后被 prepare_for_lock 清零，锁定态验签无意义，
                # 静默跳过避免 get_categories/get_category 崩溃（entry 路径 re-raise 由
                # 调用方处理；分类读路径为 LENIENT 日志，锁定态直接跳过）。
                pass

    # ==================== 分类 ====================

    @_db_operation
    def get_categories(self, *, verify: bool = True) -> list[Category]:
        """获取所有分类。

        Args:
            verify: True 时对有签名的分类做 LENIENT 完整性验签（失败记日志）；
                改密重签等路径传 False 跳过，避免旧签名在新域密钥下的假阳性告警。
        """
        rows = self._conn.execute(
            "SELECT id, name, icon_char, color, sort_order, created_at, metadata_mac "
            "FROM categories ORDER BY sort_order, name"
        ).fetchall()
        categories = [self._row_to_category(r) for r in rows]
        if verify:
            for category in categories:
                self._verify_category_if_signed(category)
        return categories

    @_db_operation
    def get_category(self, category_id: int, *, verify: bool = True) -> Category | None:
        """获取单个分类。verify 语义同 :meth:`get_categories`。"""
        row = self._conn.execute(
            "SELECT id, name, icon_char, color, sort_order, created_at, metadata_mac "
            "FROM categories WHERE id = ?",
            (category_id,),
        ).fetchone()
        if row is None:
            return None
        category = self._row_to_category(row)
        if verify:
            self._verify_category_if_signed(category)
        return category

    @_db_write
    def add_category(self, category: Category) -> int:
        """添加分类，返回 ID。

        名称在数据层以加密形态存储（每次 nonce 不同），故同名明文加密后互异，
        categories.name 的 UNIQUE 约束与本处查重均无法对加密名触发。本查重仅
        对直接传入明文名的调用方（含本层测试）作防御性兜底；生产路径的真正
        明文查重在 CategoryManager.add_category 完成。
        """
        if self._conn.execute(
            "SELECT 1 FROM categories WHERE name=? LIMIT 1", (category.name,)
        ).fetchone():
            raise ValueError(f'分类名称「{category.name}」已存在')
        # 确定最终 created_at 并回填内存对象：保证后续 update_category（两阶段重签）
        # 与本次 INSERT 用同一 created_at。否则 DB 层用 `created_at or utc_now_iso()`
        # 写入真实时间戳但内存对象仍为空，两阶段重签会用空 created_at 算 mac，
        # 导致持久化行 created_at 与签名载荷错配、重载后 verify_category 永久失败
        # （category HMAC 纵深防御对该分类失效）。
        created_at = category.created_at or utc_now_iso()
        category.created_at = created_at
        category.metadata_mac = self._sign_category(category)
        cursor = self._conn.execute(
            "INSERT INTO categories (name, icon_char, color, sort_order, created_at, metadata_mac) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (category.name, category.icon_char, category.color, category.sort_order,
             created_at, category.metadata_mac),
        )
        self._auto_commit()
        return cursor.lastrowid or 0

    @staticmethod
    def _category_update_tuple(category: Category) -> tuple[Any, ...]:
        """构造 UPDATE categories 的参数元组，供单条与批量写入复用以消除列序重复。"""
        return (
            category.name, category.icon_char, category.color,
            category.sort_order, category.metadata_mac, category.id,
        )

    def _update_category_row(self, category: Category) -> None:
        """写入分类行（不含查重/created_at 回填/签名），供 update_category 与
        update_category_reencrypted 复用同一 UPDATE SQL，消除列序重复维护。"""
        self._conn.execute(
            "UPDATE categories SET name=?, icon_char=?, color=?, sort_order=?, metadata_mac=? WHERE id=?",
            self._category_update_tuple(category),
        )
        self._auto_commit()

    @_db_write
    def update_category(self, category: Category) -> None:
        """更新分类。

        名称在数据层以加密形态存储（每次 nonce 不同），同名明文加密后互异，
        故本查重无法对加密名触发，仅对直接传入明文名的调用方作防御性兜底；
        生产路径的真正明文查重在 CategoryManager.update_category 完成。
        """
        if category.id is not None and self._conn.execute(
            "SELECT 1 FROM categories WHERE name=? AND id!=? LIMIT 1",
            (category.name, category.id),
        ).fetchone():
            raise ValueError(f'分类名称「{category.name}」已被其他分类占用')
        # created_at 创建后不可变（SQL 不写该列）：签名须用 DB 现有值，而非调用方
        # 传入值，否则调用方传空/不一致的 created_at 会使签名与持久化行错配、重载
        # 验签失败（与 add_category 的 created_at 回填守护对称，闭合第二轮 P0 修复
        # 在对称路径上的遗漏）。
        existing = self._conn.execute(
            "SELECT created_at FROM categories WHERE id=?", (category.id,)
        ).fetchone()
        if existing is not None:
            category.created_at = existing['created_at']
        category.metadata_mac = self._sign_category(category)
        self._update_category_row(category)

    @_db_write
    def update_category_reencrypted(self, category: Category) -> None:
        """改密重加密专用：写入已预签名的分类，不重算 metadata_mac。

        与 update_category 的区别：跳过签名（调用方已用新域密钥经
        :meth:`MetadataSigner.sign_category_with_domain_key` 预签名）与明文查重
        （name 为密文，每次 nonce 不同，查重无意义），直接 UPDATE。``category``
        来自 ``get_categories``，``created_at`` 已是 DB 值，SQL 不写 created_at
        列保持不变。与条目 ``update_entries_batch``（改密专用不签名写）对称——
        reencrypt 路径自己用新域密钥预签名，写入路径不再重复签名，使重加密不依赖
        「临时切换 signer 全局 _domain_key」的隐含契约。
        """
        self._update_category_row(category)

    @_db_write
    def update_categories_batch(self, categories: list[Category]) -> None:
        """改密重加密专用批量写入：executemany 一次性更新已预签名的分类。

        与 :meth:`update_category_reencrypted` 语义一致（不重算签名、不查重），仅把
        逐条 UPDATE 合并为单次 executemany，与条目/历史的 ``update_entries_batch`` /
        ``update_password_history_batch`` 改密路径对称。``_auto_commit`` 在活动事务内
        不真正提交，故批量只触发一次权限刷新。
        """
        if not categories:
            return
        self._conn.executemany(
            "UPDATE categories SET name=?, icon_char=?, color=?, sort_order=?, metadata_mac=? WHERE id=?",
            [self._category_update_tuple(c) for c in categories],
        )
        self._auto_commit()

    def delete_category(self, category_id: int) -> None:
        """删除分类行。

        仅删除 categories 表的行；关联条目的解关联与元数据重签由
        DatabaseManager.delete_category 编排 EntryRepository.clear_category_signatures
        完成（公开的跨表编排接口），避免本 Repository 跨表访问 EntryRepository。

        锁与事务契约：本方法未使用 ``@_db_operation`` 装饰器，不自行获取
        ``db_lock``。调用方（DatabaseManager.delete_category）须已持有
        ``db_lock`` 并处于活动事务内，使本 DELETE 与条目解关联在同事务内
        原子提交或回滚。入口断言将此契约从注释升级为运行期检查，防止未来
        误在无事务上下文中直接调用导致裸 DELETE。
        """
        if not self.in_transaction:
            raise RuntimeError(
                'delete_category 须在活动事务内调用（由 DatabaseManager.delete_category 编排）'
            )
        self._conn.execute("DELETE FROM categories WHERE id=?", (category_id,))

    @_db_operation
    def get_category_entry_count(self, category_id: int) -> int:
        """获取分类下的条目数量。"""
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
            metadata_mac=row['metadata_mac'],
        )
