"""密码历史数据访问层 — password_history 表的增删改查。

从 EntryRepository 拆出的单表 Repository（MAINT-071，模式镜像 category_repository）：
条目表与密码历史表的数据访问解耦，各自聚焦单表操作，经 DatabaseManager 委托
提供统一数据访问接口。``clear_vault_data`` 的跨表清空（含 password_history）仍由
EntryRepository 所在的编排层承担。
"""

import logging
import sqlite3
import threading

from ..models import MAX_PASSWORD_HISTORY, PasswordHistory
from ..utils.format import utc_now_iso
from ._decorators import _db_operation, _db_write
from .types import (
    DEFAULT_HISTORY_BATCH_LIMIT,
    ConnectionProvider,
    ReEncryptedHistory,
)

logger = logging.getLogger(__name__)

# 密码历史 JOIN 条目 crypto_id 的基础查询，供 get_password_history /
# get_all_password_history / get_all_password_history_batch 复用。
_SELECT_PASSWORD_HISTORY_SQL = (
    "SELECT h.*, e.crypto_id AS entry_crypto_id "
    "FROM password_history h JOIN entries e ON e.id=h.entry_id"
)
# 密码历史 INSERT 与截断到 MAX_PASSWORD_HISTORY 的 DELETE；add_password_history
# 与 batch 共用。
_INSERT_PASSWORD_HISTORY_SQL = (
    "INSERT INTO password_history (entry_id, old_password_enc, changed_at) VALUES (?, ?, ?)"
)
_TRUNCATE_PASSWORD_HISTORY_SQL = (
    "DELETE FROM password_history WHERE entry_id = ? AND id NOT IN ("
    "  SELECT id FROM password_history WHERE entry_id = ?"
    "  ORDER BY changed_at DESC, id DESC LIMIT ?"
    ")"
)

# 密码历史分页批量别名：引用 types.DEFAULT_HISTORY_BATCH_LIMIT 单一事实源（QL-007）。
_DEFAULT_HISTORY_BATCH_LIMIT = DEFAULT_HISTORY_BATCH_LIMIT


class PasswordHistoryRepository:
    """密码历史数据访问层。

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

    def _guard_write(self) -> None:
        return self._mgr.guard_write()

    def _auto_commit(self) -> None:
        return self._mgr.auto_commit()

    @property
    def in_transaction(self) -> bool:
        return self._mgr.in_transaction

    def _assert_encrypted(self, value: str, field_name: str) -> None:
        self._mgr.assert_encrypted(value, field_name)

    # ==================== 密码历史 ====================

    @_db_write
    def add_password_history(
        self,
        entry_id: int,
        old_password_enc: str,
        changed_at: str = "",
    ) -> None:
        """添加密码历史记录。"""
        self._assert_encrypted(old_password_enc, "password_history")
        self._conn.execute(
            _INSERT_PASSWORD_HISTORY_SQL,
            (entry_id, old_password_enc, changed_at or utc_now_iso()),
        )
        # 无条件截断：NOT IN 子查询对未超限条目不匹配任何行，幂等且高效，比先 COUNT
        # 再 DELETE 少一次查询。隐式依赖 id 为 INTEGER PRIMARY KEY（NOT NULL）：若子查询
        # 含 NULL，NOT IN 对所有行返回 UNKNOWN 而不删除。
        self._conn.execute(
            _TRUNCATE_PASSWORD_HISTORY_SQL,
            (entry_id, entry_id, MAX_PASSWORD_HISTORY),
        )
        self._auto_commit()

    @_db_write
    def add_password_history_batch(
        self,
        entry_id: int,
        items: list[tuple[str, str]],
    ) -> None:
        """批量添加密码历史，末尾统一截断到 MAX_PASSWORD_HISTORY 条。

        相比逐条调用 add_password_history，避免每条触发一次截断 DELETE。

        Args:
            entry_id: 条目 ID。
            items: 由旧密码密文与变更时间组成的二元组列表。
        """
        if not items:
            return
        for encrypted, _changed_at in items:
            self._assert_encrypted(encrypted, "password_history")
        now = utc_now_iso()
        rows = [(entry_id, enc, changed_at or now) for enc, changed_at in items]
        self._conn.executemany(
            _INSERT_PASSWORD_HISTORY_SQL,
            rows,
        )
        # 统一截断：仅一次 DELETE，替代逐条触发的 N 次截断
        self._conn.execute(
            _TRUNCATE_PASSWORD_HISTORY_SQL,
            (entry_id, entry_id, MAX_PASSWORD_HISTORY),
        )
        self._auto_commit()

    @_db_operation
    def get_password_history(self, entry_id: int) -> list[PasswordHistory]:
        """获取指定条目的密码历史，按变更时间倒序返回（供 UI 展示）。"""
        rows = self._conn.execute(
            f"{_SELECT_PASSWORD_HISTORY_SQL} "
            "WHERE h.entry_id = ? ORDER BY h.changed_at DESC, h.id DESC",
            (entry_id,),
        ).fetchall()
        return [self._row_to_password_history(r) for r in rows]

    @_db_operation
    def get_all_password_history(self) -> list[PasswordHistory]:
        """获取全部密码历史，用于改密和备份。"""
        rows = self._conn.execute(f"{_SELECT_PASSWORD_HISTORY_SQL} ORDER BY h.id").fetchall()
        return [self._row_to_password_history(r) for r in rows]

    @_db_operation
    def get_all_password_history_batch(
        self, after_id: int = 0, limit: int = _DEFAULT_HISTORY_BATCH_LIMIT
    ) -> list[PasswordHistory]:
        """分批获取全部密码历史，用于改密重加密时控制内存峰值。

        使用游标分页 after_id，与 get_entries 的分页策略一致，
        避免并发写入时 OFFSET 分页可能导致的跳过/重复问题。
        """
        rows = self._conn.execute(
            f"{_SELECT_PASSWORD_HISTORY_SQL} WHERE h.id > ? ORDER BY h.id LIMIT ?",
            (after_id, limit),
        ).fetchall()
        return [self._row_to_password_history(r) for r in rows]

    @_db_operation
    def get_password_history_count(self, entry_id: int) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) FROM password_history WHERE entry_id = ?",
            (entry_id,),
        ).fetchone()
        return int(row[0]) if row else 0

    @_db_write
    def update_password_history_batch(self, rows: list[ReEncryptedHistory]) -> None:
        """批量更新密码历史记录的密文。

        改密重加密时将逐条 UPDATE 合并为单次 executemany。

        Args:
            rows: ``ReEncryptedHistory`` NamedTuple 列表（re_encryption 产出）。
                NamedTuple 自动适配 executemany 位置绑定；不接受普通二元组——解包
                ``for encrypted, _history_id in rows`` 依赖字段语义，普通 tuple 易错位。
        """
        if not rows:
            return
        for encrypted, _history_id in rows:
            self._assert_encrypted(encrypted, "password_history")
        self._conn.executemany(
            "UPDATE password_history SET old_password_enc=? WHERE id=?",
            rows,
        )
        self._auto_commit()

    # ========== 内部方法 ==========

    @staticmethod
    def _row_to_password_history(row: sqlite3.Row) -> PasswordHistory:
        """从 JOIN 查询行构建 PasswordHistory 对象，含 entry_crypto_id。"""
        return PasswordHistory(
            id=row["id"],
            entry_id=row["entry_id"],
            old_password_enc=row["old_password_enc"],
            changed_at=row["changed_at"],
            entry_crypto_id=row["entry_crypto_id"],
        )
