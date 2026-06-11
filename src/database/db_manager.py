"""数据库管理器 - SQLite 数据库操作。

本模块定义 ``DatabaseManager``，负责：
- 数据库连接的打开/关闭和文件安全
- 事务管理（begin / commit / rollback / savepoint）
- 元数据（vault_meta 表）读写
- ``_db_operation`` 装饰器，提供线程安全锁和连接校验

CRUD 操作已委托给子 Repository：
- ``entries`` → :class:`EntryRepository`
- ``categories`` → :class:`CategoryRepository`
- ``schema`` → :class:`SchemaManager`

DatabaseManager 作为统一数据访问入口，将所有公共方法委托给子 Repository，
为调用方提供简化的单一接口。
"""

import logging
import sqlite3
import threading
import time as _time
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path
from typing import Optional, Protocol, runtime_checkable

from ..exceptions import DatabaseError, TransactionError
from ..models import Category, Entry, PasswordHistory
from ..utils.file_security import secure_directory, secure_file
from ._decorators import _db_operation
from .category_repository import CategoryRepository
from .entry_repository import EntryRepository
from .schema_manager import SchemaManager

logger = logging.getLogger(__name__)


# 签名/验证函数的类型协议，替代弱类型 Callable
@runtime_checkable
class EntrySigner(Protocol):
    def __call__(self, entry: Entry) -> str: ...


@runtime_checkable
class EntryVerifier(Protocol):
    def __call__(self, entry: Entry) -> None: ...


class DatabaseManager:
    """SQLite 数据库管理器

    通过 ``entries`` / ``categories`` / ``schema`` 属性访问子 Repository，
    也可直接通过 DatabaseManager 上的委托方法调用。
    """

    def __init__(self, db_path: Path, *, test_mode: bool = False):
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
        # 实例级加密断言开关。test_mode 下自动关闭，允许测试直接写入明文。
        # 生产环境保持 True，确保密文前缀断言生效。
        self._enforce_encrypted_fields: bool = not test_mode

        # 子 Repository
        self._entry_repo = EntryRepository(self)
        self._category_repo = CategoryRepository(self)
        self._schema_mgr = SchemaManager(self)

    # ==================== Repository 属性 ====================

    @property
    def entries(self) -> EntryRepository:
        return self._entry_repo

    @property
    def categories(self) -> CategoryRepository:
        return self._category_repo

    @property
    def schema(self) -> SchemaManager:
        return self._schema_mgr

    # ==================== 子 Repository 公共访问接口 ====================
    # 替代 Repository 中的 _mgr._conn / _mgr._lock 等私有属性访问。

    @property
    def connection(self) -> sqlite3.Connection:
        """数据库连接（供 Repository 使用）。"""
        return self._conn

    @property
    def db_lock(self) -> threading.RLock:
        """线程安全锁（供 Repository 使用）。"""
        return self._lock

    @property
    def entry_verifier(self):
        """条目元数据校验函数。"""
        return self._entry_verifier

    @property
    def schema_validated(self) -> bool:
        return self._schema_validated

    @schema_validated.setter
    def schema_validated(self, value: bool) -> None:
        self._schema_validated = value

    def guard_write(self) -> None:
        """写入前校验（公共接口）。"""
        self._guard_write()

    def auto_commit(self) -> None:
        """非事务模式下自动提交（公共接口）。"""
        self._auto_commit()

    def sign_entry(self, entry: Entry) -> str:
        """条目元数据签名（公共接口）。"""
        return self._sign_entry(entry)

    def assert_encrypted(self, value: str, field_name: str) -> None:
        """断言加密字段的值格式正确（公共接口）。"""
        self._assert_encrypted(value, field_name)

    def set_write_guard(self, guard: Callable[[], None]) -> None:
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

    def _guard_write(self) -> None:
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

    def begin_transaction(self) -> None:
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

    def commit_transaction(self) -> None:
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

    def rollback_transaction(self) -> None:
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

    def _auto_commit(self) -> None:
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

    # ========== 连接管理 ==========

    def open(self) -> bool:
        """打开数据库连接"""
        try:
            secure_directory(self._db_path.parent)
            # check_same_thread=False 仅允许同一线程的 RLock 重入和事务内操作，
            # 所有 DB 操作仍须通过 @_db_operation 或在已持有 _lock 的上下文中调用。
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

    def _secure_database_files(self) -> None:
        secure_file(self._db_path)
        secure_file(Path(f'{self._db_path}-wal'))
        secure_file(Path(f'{self._db_path}-shm'))

    def close(self) -> None:
        """关闭数据库连接"""
        if self._conn:
            if self._transaction_depth > 0:
                logger.warning(
                    "数据库关闭时存在未提交事务 (depth=%d)，将回滚",
                    self._transaction_depth,
                )
            self._conn.close()
            self._conn = None
        self._transaction_depth = 0
        self._savepoint_counter = 0

    # ==================== 元数据 ====================

    @_db_operation
    def get_meta(self, key: str) -> Optional[str]:
        """获取元数据"""
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT value FROM vault_meta WHERE key = ?", (key,)
        ).fetchone()
        return row['value'] if row else None

    @_db_operation
    def get_meta_batch(self, keys: list[str]) -> dict[str, Optional[str]]:
        """批量获取多条元数据，单次查询返回。

        Args:
            keys: 要获取的元数据键名列表。

        Returns:
            字典，键为请求的键名，值为对应的元数据值，不存在则为 None。
        """
        placeholders = ','.join('?' for _ in keys)
        assert self._conn is not None
        rows = self._conn.execute(
            f"SELECT key, value FROM vault_meta WHERE key IN ({placeholders})",
            keys,
        ).fetchall()
        result: dict[str, Optional[str]] = {k: None for k in keys}
        for row in rows:
            result[row['key']] = row['value']
        return result

    @_db_operation
    def set_meta(self, key: str, value: str) -> None:
        """设置元数据"""
        self._guard_write()
        assert self._conn is not None
        self._conn.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?, ?)",
            (key, value),
        )
        self._auto_commit()

    # ==================== 安全操作 ====================

    @_db_operation
    def secure_checkpoint(self) -> None:
        """截断 WAL，降低已删除或重加密数据残留。"""
        if self._conn is not None and not self.in_transaction:
            try:
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except sqlite3.Error:
                logger.warning("WAL 安全截断失败", exc_info=True)

    # ==================== 内部方法 ====================

    def _assert_encrypted(self, value: str, field_name: str) -> None:
        """防御性断言：加密列的值应为密文，以 cb: 前缀，或空字符串。

        防止绕过 EntryManager 直接调用 db.add_entry/update_entry 时
        明文静默写入加密列。空值允许通过，未填写字段存储为空字符串。
        读取实例级 _enforce_encrypted_fields，避免测试覆写泄漏到其他实例。
        """
        if self._enforce_encrypted_fields and value and not value.startswith('cb:'):
            raise ValueError(
                f'数据层收到未加密的 {field_name}（期望 cb: 前缀的密文），'
                f'请通过 EntryManager 操作条目'
            )

    def _sign_entry(self, entry: Entry) -> str:
        if self._entry_signer:
            return self._entry_signer(entry)
        return entry.metadata_mac

    # ==================== 委托方法 ====================
    # DatabaseManager 作为统一数据访问入口，将所有公共方法委托给子 Repository。

    # -- Schema --

    def init_tables(self) -> None:
        return self._schema_mgr.init_tables()

    # -- Categories --

    def get_categories(self) -> list[Category]:
        return self._category_repo.get_categories()

    def get_category(self, category_id: int) -> Optional[Category]:
        return self._category_repo.get_category(category_id)

    def add_category(self, category: Category) -> int:
        return self._category_repo.add_category(category)

    def update_category(self, category: Category) -> None:
        return self._category_repo.update_category(category)

    def delete_category(self, category_id: int) -> None:
        return self._category_repo.delete_category(category_id)

    def get_category_entry_count(self, category_id: int) -> int:
        return self._category_repo.get_category_entry_count(category_id)

    def get_category_entry_counts(self) -> dict[int, int]:
        return self._category_repo.get_category_entry_counts()

    # -- Entries --

    def get_entries(
        self,
        deleted_only: bool = False,
        include_deleted: bool = False,
        category_id: Optional[int] = None,
        favorite_only: bool = False,
        limit: int | None = None,
        after_id: int | None = None,
    ) -> list[Entry]:
        return self._entry_repo.get_entries(
            deleted_only=deleted_only,
            include_deleted=include_deleted,
            category_id=category_id,
            favorite_only=favorite_only,
            limit=limit,
            after_id=after_id,
        )

    def get_entry(self, entry_id: int) -> Optional[Entry]:
        return self._entry_repo.get_entry(entry_id)

    def add_entry(self, entry: Entry, preserve_metadata: bool = False) -> int:
        return self._entry_repo.add_entry(entry, preserve_metadata=preserve_metadata)

    def update_entry(
        self,
        entry: Entry,
        preserve_updated_at: bool = False,
        metadata_mac: str | None = None,
    ):
        return self._entry_repo.update_entry(
            entry,
            preserve_updated_at=preserve_updated_at,
            metadata_mac=metadata_mac,
        )

    def update_entries_batch(self, rows: list[tuple]) -> None:
        return self._entry_repo.update_entries_batch(rows)

    def soft_delete_entry(self, entry_id: int) -> None:
        return self._entry_repo.soft_delete_entry(entry_id)

    def restore_entry(self, entry_id: int) -> None:
        return self._entry_repo.restore_entry(entry_id)

    def permanent_delete_entry(self, entry_id: int) -> None:
        return self._entry_repo.permanent_delete_entry(entry_id)

    def empty_trash(self) -> None:
        return self._entry_repo.empty_trash()

    def clear_vault_data(self) -> None:
        return self._entry_repo.clear_vault_data()

    def get_entry_count(self, include_deleted: bool = False) -> int:
        return self._entry_repo.get_entry_count(include_deleted=include_deleted)

    def get_all_tags(self) -> list[str]:
        return self._entry_repo.get_all_tags()

    def get_entries_by_ids(self, entry_ids: list[int]) -> list[Entry]:
        return self._entry_repo.get_entries_by_ids(entry_ids)

    # -- Password History --

    def add_password_history(
        self,
        entry_id: int,
        old_password_enc: str,
        changed_at: str = '',
    ):
        return self._entry_repo.add_password_history(entry_id, old_password_enc, changed_at)

    def add_password_history_batch(
        self,
        entry_id: int,
        items: list[tuple[str, str]],
    ):
        return self._entry_repo.add_password_history_batch(entry_id, items)

    def get_password_history(self, entry_id: int) -> list[PasswordHistory]:
        return self._entry_repo.get_password_history(entry_id)

    def get_all_password_history(self) -> list[PasswordHistory]:
        return self._entry_repo.get_all_password_history()

    def get_all_password_history_batch(
        self, after_id: int = 0, limit: int = 200
    ) -> list[PasswordHistory]:
        return self._entry_repo.get_all_password_history_batch(after_id, limit)

    def get_password_history_count(self, entry_id: int) -> int:
        return self._entry_repo.get_password_history_count(entry_id)

    def update_password_history_batch(self, rows: list[tuple]) -> None:
        return self._entry_repo.update_password_history_batch(rows)
