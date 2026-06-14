"""条目数据访问层 — 条目 CRUD、批量操作、密码历史。

从 DatabaseManager 拆分而来，职责单一：条目及密码历史表的增删改查。
通过 DatabaseManager 委托提供统一数据访问接口。
"""

import logging
import sqlite3
import uuid
from typing import Optional

from ..exceptions import DatabaseError, VaultIntegrityError, VaultLockedError
from ..models import MAX_PASSWORD_HISTORY, PasswordHistory, RawEntry
from ..utils.format import utc_now_iso
from ._decorators import _db_operation, _db_write
from .types import VerifyMode

logger = logging.getLogger(__name__)

# _ENTRY_COLUMNS 是 entries 表非 id 列名的单一事实来源。
# 重要：新增 entries 表列时必须在此列表追加，INSERT/UPDATE/SELECT 等派生 SQL
# 会自动跟随；同时须同步纳入 MetadataSigner._payload 的签名载荷
# （由 test_entry_signature_coverage 断言守护，防止漏签）。
_ENTRY_COLUMNS = [
    'crypto_id', 'title', 'username_enc', 'password_enc', 'url',
    'category_id', 'tags', 'notes_enc', 'custom_fields_enc',
    'is_favorite', 'is_deleted', 'password_strength', 'entry_type',
    'totp_secret_enc', 'created_at', 'updated_at', 'deleted_at',
    'password_changed_at', 'metadata_mac',
]

# 写入用 INSERT：add_entry 写入全部列，列序与 _ENTRY_COLUMNS 一致。
_INSERT_ENTRY_SQL = (
    f"INSERT INTO entries ({', '.join(_ENTRY_COLUMNS)}) "  # nosec B608 - 列名硬编码
    f"VALUES ({', '.join('?' for _ in _ENTRY_COLUMNS)})"
)

# update_entry 不写 is_deleted/deleted_at/created_at：删除状态仅由
# soft_delete_entry/restore_entry 管理，created_at 创建后不可变。
_UPDATE_EXCLUDED_COLUMNS = {'is_deleted', 'deleted_at', 'created_at'}
_UPDATE_ENTRY_COLUMNS = [
    column for column in _ENTRY_COLUMNS
    if column not in _UPDATE_EXCLUDED_COLUMNS
]
_UPDATE_ENTRY_SQL = (
    f"UPDATE entries SET {', '.join(f'{column}=?' for column in _UPDATE_ENTRY_COLUMNS)} "  # nosec B608 - 参数绑定
    f"WHERE id=?"
)

# 重加密批量更新列：改密重写除删除状态与创建时间外的全部列（含全部密文列）。
# 直接从 _UPDATE_ENTRY_COLUMNS 派生（同样排除 is_deleted/deleted_at/created_at），
# 使新增加密列只需加入 _ENTRY_COLUMNS 即自动被改密重写——消除手工维护
# _RE_ENCRYPT_COLUMNS 漏列导致该列保留旧密钥密文、新密钥无法解密的数据损坏风险。
_RE_ENCRYPT_COLUMNS = list(_UPDATE_ENTRY_COLUMNS)

# 运行时断言：所有加密列（_enc 后缀）必须被改密重写，否则该列保留旧密钥密文
# 将导致改密后无法解密。模块加载时执行，捕获未来 _ENTRY_COLUMNS 扩展漏配。
assert all(
    col in _RE_ENCRYPT_COLUMNS
    for col in _ENTRY_COLUMNS
    if col.endswith('_enc')
), '加密列未被纳入改密重写集合，将导致改密后数据损坏'

_RE_ENCRYPT_BATCH_UPDATE_SQL = (
    f"UPDATE entries SET {', '.join(f'{column}=?' for column in _RE_ENCRYPT_COLUMNS)} "  # nosec B608 - 参数绑定
    f"WHERE id=?"
)

# 预计算签名查询 SQL，使用 LEFT JOIN 提供与其他查询一致的列，包括 category_name，
# 避免在 _row_to_entry 中对缺失列做特殊处理。
_SELECT_ENTRY_SIGN_SQL = (
    f"SELECT {', '.join(['e.id'] + [f'e.{c}' for c in _ENTRY_COLUMNS])}, "  # nosec B608 - 列名硬编码
    "c.name as category_name "
    "FROM entries e LEFT JOIN categories c ON e.category_id = c.id WHERE e.id=?"
)


class EntryRepository:
    """条目数据访问层 — 条目 CRUD、批量操作、密码历史。

    通过 ``conn_provider`` 获取 sqlite3.Connection，支持外部注入连接，
    通常为 DatabaseManager 实例。
    """

    def __init__(self, conn_provider):
        # conn_provider 可以是返回 sqlite3.Connection 的可调用对象，
        # 也可以直接是持有 _conn / _lock / transaction / _auto_commit /
        # _guard_write / _sign_entry / _entry_verifier / _enforce_encrypted_fields
        # 等属性的 DatabaseManager 实例。
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

    def _sign_entry(self, entry: RawEntry) -> str:
        return self._mgr.sign_entry(entry)

    @property
    def in_transaction(self) -> bool:
        return self._mgr.in_transaction

    def transaction(self):
        return self._mgr.transaction()

    def secure_checkpoint(self):
        return self._mgr.secure_checkpoint()

    # ======== 防御性断言 ========

    def _assert_encrypted(self, value: str, field_name: str) -> None:
        """防御性断言：加密列的值应为密文，以 cb: 前缀，或空字符串。"""
        self._mgr.assert_encrypted(value, field_name)

    # ==================== 条目 ====================

    @_db_operation
    def get_entries(
        self,
        deleted_only: bool = False,
        include_deleted: bool = False,
        category_id: Optional[int] = None,
        favorite_only: bool = False,
        limit: int | None = None,
        after_id: int | None = None,
        sort_by_updated: bool = False,
    ) -> list[RawEntry]:
        """获取密码条目列表

        sort_by_updated 为 True 时仅按 updated_at DESC 排序（不带 is_favorite），
        供「近期更新」视图下推 LIMIT 到 SQL，避免全量内存排序再截断。
        """
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
        elif sort_by_updated:
            query += " ORDER BY e.updated_at DESC"
        else:
            query += " ORDER BY e.is_favorite DESC, e.updated_at DESC"

        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)

        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_entry(r, verify=VerifyMode.LENIENT) for r in rows]

    @_db_operation
    def get_entry(self, entry_id: int) -> Optional[RawEntry]:
        """获取单个条目。"""
        row = self._conn.execute(
            """SELECT e.*, c.name as category_name
               FROM entries e
               LEFT JOIN categories c ON e.category_id = c.id
               WHERE e.id = ?""",
            (entry_id,),
        ).fetchone()
        return self._row_to_entry(row) if row else None

    @_db_write
    def add_entry(self, entry: RawEntry, preserve_metadata: bool = False) -> int:
        """添加条目，返回 ID。"""
        # 防御性断言，防止明文静默写入加密列
        self._assert_encrypted(entry.username, 'username')
        self._assert_encrypted(entry.password, 'password')
        self._assert_encrypted(entry.notes, 'notes')
        self._assert_encrypted(entry.totp_secret, 'totp_secret')
        self._assert_encrypted(entry.custom_fields_db_value, 'custom_fields')
        now = utc_now_iso()
        entry.crypto_id = entry.crypto_id or uuid.uuid4().hex
        entry.created_at = entry.created_at or now
        entry.updated_at = entry.updated_at if preserve_metadata and entry.updated_at else now
        entry.is_deleted = bool(preserve_metadata and entry.is_deleted)
        entry.deleted_at = entry.deleted_at if preserve_metadata else ''
        # password_changed_at 回退到 created_at（"未改过密码即创建时间"语义），
        # 而非 updated_at/now，避免导入/恢复时用导入时刻的 updated_at 覆盖历史时间。
        entry.password_changed_at = (
            entry.password_changed_at or entry.created_at or now
        )
        entry.metadata_mac = self._sign_entry(entry)
        # 参数顺序须与 _ENTRY_COLUMNS 一致；加密列存 entry 的密文属性。
        try:
            cursor = self._conn.execute(
                _INSERT_ENTRY_SQL,
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
        except sqlite3.IntegrityError as exc:
            # crypto_id 有 UNIQUE 约束；冲突时归一化为领域异常，避免裸驱动异常
            # 泄漏给上层（其余路径经 DatabaseError/ValueError 传递）。
            raise DatabaseError(f'条目写入违反唯一约束（crypto_id 冲突）：{exc}') from exc
        self._auto_commit()
        return cursor.lastrowid or 0

    @_db_write
    def update_entry(
        self,
        entry: RawEntry,
        preserve_updated_at: bool = False,
    ):
        """更新条目。

        注意：此方法不写入 is_deleted 和 deleted_at 字段，这两个字段
        仅由 soft_delete_entry / restore_entry 管理。若需修改删除状态，
        请使用上述专用方法。
        """
        # 防御性断言，防止明文静默写入加密列
        self._assert_encrypted(entry.username, 'username')
        self._assert_encrypted(entry.password, 'password')
        self._assert_encrypted(entry.notes, 'notes')
        self._assert_encrypted(entry.totp_secret, 'totp_secret')
        self._assert_encrypted(entry.custom_fields_db_value, 'custom_fields')
        entry.updated_at = (
            entry.updated_at
            if preserve_updated_at and entry.updated_at
            else utc_now_iso()
        )
        entry.metadata_mac = self._sign_entry(entry)
        # 参数顺序须与 _UPDATE_ENTRY_COLUMNS 一致（不含 is_deleted/deleted_at/created_at）。
        self._conn.execute(
            _UPDATE_ENTRY_SQL,
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

    @_db_write
    def update_entries_batch(self, rows: list) -> None:
        """批量更新条目，改密重加密专用。

        Args:
            rows: ``ReEncryptedEntry`` NamedTuple 列表，或与
                ``_RE_ENCRYPT_BATCH_UPDATE_SQL`` 列顺序一致的 tuple 列表，
                推荐使用 NamedTuple。NamedTuple 自动适配 executemany
                的位置参数绑定。
        """
        if not rows:
            return
        self._conn.executemany(_RE_ENCRYPT_BATCH_UPDATE_SQL, rows)
        self._auto_commit()

    @_db_write
    def soft_delete_entry(self, entry_id: int) -> bool:
        """软删除条目。返回是否实际执行（条目存在）。"""
        now = utc_now_iso()
        entry = self._select_entry_for_sign(entry_id)
        if entry is None:
            logger.warning("软删除条目 %d 失败：条目不存在", entry_id)
            return False
        entry.is_deleted = True
        entry.deleted_at = now
        entry.metadata_mac = self._sign_entry(entry)
        self._conn.execute(
            "UPDATE entries SET is_deleted=1, deleted_at=?, metadata_mac=? WHERE id=?",
            (now, entry.metadata_mac, entry_id),
        )
        self._auto_commit()
        return True

    @_db_write
    def restore_entry(self, entry_id: int) -> bool:
        """恢复条目。返回是否实际执行（条目存在）。"""
        entry = self._select_entry_for_sign(entry_id)
        if entry is None:
            logger.warning("恢复条目 %d 失败：条目不存在", entry_id)
            return False
        entry.is_deleted = False
        entry.deleted_at = ''
        entry.metadata_mac = self._sign_entry(entry)
        self._conn.execute(
            "UPDATE entries SET is_deleted=0, deleted_at='', metadata_mac=? WHERE id=?",
            (entry.metadata_mac, entry_id),
        )
        self._auto_commit()
        return True

    @_db_write
    def permanent_delete_entry(self, entry_id: int) -> None:
        """永久删除条目。"""
        self._conn.execute("DELETE FROM entries WHERE id=?", (entry_id,))
        self._auto_commit()
        self.secure_checkpoint()

    @_db_write
    def empty_trash(self) -> None:
        """清空回收站。"""
        self._conn.execute("DELETE FROM entries WHERE is_deleted=1")
        self._auto_commit()
        self.secure_checkpoint()

    @_db_write
    def clear_vault_data(self) -> None:
        """清空领域数据，供事务化恢复使用。

        删除后截断 WAL 以清除旧密文残留，与 permanent_delete_entry/empty_trash
        一致。事务内调用时 secure_checkpoint 静默跳过，调用方须在事务提交后
        显式 checkpoint 以保证旧密文被清除（见 restore_backup）。
        """
        self._conn.execute("DELETE FROM password_history")
        self._conn.execute("DELETE FROM entries")
        self._conn.execute("DELETE FROM categories")
        self._auto_commit()
        self.secure_checkpoint()

    @_db_operation
    def get_entry_count(self, include_deleted: bool = False) -> int:
        """获取条目数量。"""
        query = "SELECT COUNT(*) FROM entries"
        if not include_deleted:
            query += " WHERE is_deleted = 0"
        row = self._conn.execute(query).fetchone()
        return row[0]

    @_db_operation
    def get_all_tags(self) -> list[str]:
        """获取所有未删除条目的标签字段，轻量查询，不加载加密列。"""
        rows = self._conn.execute(
            "SELECT tags FROM entries WHERE is_deleted=0"
        ).fetchall()
        return [row['tags'] or '' for row in rows]

    @_db_operation
    def get_entries_by_ids(self, entry_ids: list[int]) -> list[RawEntry]:
        """按 ID 列表批量获取条目。

        用于导入覆盖等需要一次性获取多个条目的场景，
        替代逐条 get_entry 的 N+1 查询模式。

        ID 数量超过 SQLite 主机变量数限制（默认 999）时分批查询，
        避免 too many SQL variables 错误。

        Args:
            entry_ids: 要获取的条目 ID 列表。
        """
        if not entry_ids:
            return []
        results = []
        # SQLite 默认限制 999 个变量；取 500 为分批阈值留出余量
        batch_size = 500
        for start in range(0, len(entry_ids), batch_size):
            batch = entry_ids[start:start + batch_size]
            placeholders = ','.join('?' for _ in batch)
            rows = self._conn.execute(
                f"""SELECT e.*, c.name as category_name
                    FROM entries e
                    LEFT JOIN categories c ON e.category_id = c.id
                    WHERE e.id IN ({placeholders})""",  # nosec B608 - 参数化占位符
                batch,
            ).fetchall()
            results.extend(
                self._row_to_entry(r, verify=VerifyMode.LENIENT) for r in rows
            )
        return results

    # ==================== 密码历史 ====================

    @_db_write
    def add_password_history(
        self,
        entry_id: int,
        old_password_enc: str,
        changed_at: str = '',
    ):
        """添加密码历史记录。"""
        self._conn.execute(
            "INSERT INTO password_history (entry_id, old_password_enc, changed_at) VALUES (?, ?, ?)",
            (entry_id, old_password_enc, changed_at or utc_now_iso()),
        )
        # 无条件截断：NOT IN 子查询对未超限条目不匹配任何行，幂等且高效。
        # 比先 COUNT 再 DELETE 少一次数据库查询。
        self._conn.execute(
            "DELETE FROM password_history WHERE entry_id = ? AND id NOT IN ("
            "  SELECT id FROM password_history WHERE entry_id = ?"
            "  ORDER BY changed_at DESC, id DESC LIMIT ?"
            ")",
            (entry_id, entry_id, MAX_PASSWORD_HISTORY),
        )
        self._auto_commit()

    @_db_write
    def add_password_history_batch(
        self,
        entry_id: int,
        items: list[tuple[str, str]],
    ):
        """批量添加密码历史，末尾统一截断到 MAX_PASSWORD_HISTORY 条。

        相比逐条调用 add_password_history，避免每条记录触发一次截断 DELETE。
        用于备份恢复等需一次性写入多条历史的场景。

        Args:
            entry_id: 条目 ID。
            items: 由旧密码密文与变更时间组成的二元组列表。
        """
        if not items:
            return
        now = utc_now_iso()
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
            "  ORDER BY changed_at DESC, id DESC LIMIT ?"
            ")",
            (entry_id, entry_id, MAX_PASSWORD_HISTORY),
        )
        self._auto_commit()

    @_db_operation
    def get_password_history(self, entry_id: int) -> list[PasswordHistory]:
        """获取条目的密码历史。"""
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

        使用游标分页 after_id，与 get_entries 的分页策略一致，
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
        """获取条目的密码历史记录数，轻量 COUNT 查询。"""
        row = self._conn.execute(
            "SELECT COUNT(*) FROM password_history WHERE entry_id = ?",
            (entry_id,),
        ).fetchone()
        return row[0] if row else 0

    @_db_write
    def update_password_history_batch(self, rows: list) -> None:
        """批量更新密码历史记录的密文。

        改密重加密时将逐条 UPDATE 合并为单次 executemany，减少数据库往返次数。

        Args:
            rows: 推荐使用 ``ReEncryptedHistory`` NamedTuple 列表，
                也可传入由新密码密文与记录 id 组成的二元组列表。
        """
        if not rows:
            return
        self._conn.executemany(
            "UPDATE password_history SET old_password_enc=? WHERE id=?",
            rows,
        )
        self._auto_commit()

    # ========== 内部方法 ==========

    def _select_entry_for_sign(self, entry_id: int) -> RawEntry | None:
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

    def clear_category_signatures(self, category_id: int) -> None:
        """将指定分类下所有条目的 category_id 置空并重算元数据签名。

        供删除分类时由 DatabaseManager 编排调用，保持条目元数据完整性。
        批量执行，将 N+1 模式降为 2 次操作。不校验旧签名，因签名将被覆盖。

        锁与事务契约：本方法未使用 ``@_db_operation`` 装饰器，不自行获取
        ``db_lock``。调用方（DatabaseManager.delete_category）须已持有
        ``db_lock`` 并处于活动事务内，以保证 SELECT 与 executemany UPDATE
        的原子性及跨表一致性。入口断言将此契约从注释升级为运行期检查，
        防止未来误在无事务上下文中直接调用。
        """
        assert self.in_transaction, (
            'clear_category_signatures 须在活动事务内调用（由 DatabaseManager.delete_category 编排）'
        )
        rows = self._conn.execute(
            "SELECT e.*, c.name as category_name "
            "FROM entries e LEFT JOIN categories c ON e.category_id = c.id "
            "WHERE e.category_id=?",
            (category_id,),
        ).fetchall()
        update_data = []
        for row in rows:
            entry = self._row_to_entry(row, verify=VerifyMode.SKIP)
            entry.category_id = None
            entry.metadata_mac = self._sign_entry(entry)
            update_data.append((entry.metadata_mac, entry.id))
        if update_data:
            self._conn.executemany(
                "UPDATE entries SET category_id=NULL, metadata_mac=? WHERE id=?",
                update_data,
            )

    def _row_to_entry(self, row: sqlite3.Row,
                       verify: VerifyMode = VerifyMode.STRICT) -> RawEntry:
        """从数据库行构建 Entry 对象。

        Args:
            row: 数据库查询返回的行，需包含所有条目列。
            verify: 完整性校验模式，取 STRICT、LENIENT 或 SKIP。
                STRICT 在校验失败时抛出异常；LENIENT 仅设置
                integrity_error 标志并继续；SKIP 完全跳过校验。
        """
        entry = RawEntry(
            id=row['id'],
            crypto_id=row['crypto_id'],
            title=row['title'],
            username=row['username_enc'],
            password=row['password_enc'],
            url=row['url'] or '',
            category_id=row['category_id'],
            category_name=row['category_name'],
            tags=row['tags'] or '',
            notes=row['notes_enc'],
            custom_fields=row['custom_fields_enc'] or '',
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
        verifier = self._mgr.entry_verifier
        if verifier and verify != VerifyMode.SKIP:
            try:
                verifier(entry)
            except VaultIntegrityError:
                if verify == VerifyMode.STRICT:
                    raise
                entry.integrity_error = True
                entry.integrity_message = '元数据完整性校验失败'
            except VaultLockedError:
                # 未解锁状态（如锁定期间后台分析线程读到已清零的域密钥）
                # 不是完整性错误，向上传播让调用方处理
                raise
        return entry

    @staticmethod
    def _row_to_password_history(row: sqlite3.Row) -> PasswordHistory:
        """从 JOIN 查询行构建 PasswordHistory 对象，含 entry_crypto_id。"""
        return PasswordHistory(
            id=row['id'],
            entry_id=row['entry_id'],
            old_password_enc=row['old_password_enc'],
            changed_at=row['changed_at'],
            entry_crypto_id=row['entry_crypto_id'],
        )
