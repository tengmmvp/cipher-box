"""数据库管理器 — SQLite 数据库操作。

本模块定义 ``DatabaseManager``，负责：
- 数据库连接的打开/关闭和文件安全
- 事务管理（begin / commit / rollback / savepoint）
- vault_meta 表的元数据读写
- ``_db_operation`` 装饰器，提供线程安全锁和连接校验

CRUD 操作已委托给子 Repository：
- ``entries`` → :class:`EntryRepository`
- ``categories`` → :class:`CategoryRepository`
- ``schema`` → :class:`SchemaManager`

DatabaseManager 作为统一数据访问入口，将所有公共方法委托给子 Repository，
为调用方提供简化的单一接口。
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import time as _time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Protocol, runtime_checkable

from ..exceptions import DatabaseError, TransactionError
from ..models import CIPHERTEXT_PREFIX, Category, PasswordHistory, RawEntry
from ..utils.file_security import secure_directory, secure_file
from ._decorators import _db_operation, _db_write
from .category_repository import CategoryRepository
from .entry_repository import EntryRepository
from .schema_manager import SchemaManager
from .types import EntryQuery, ReEncryptedEntry, ReEncryptedHistory

logger = logging.getLogger(__name__)


# 提交后刷新文件权限的防抖间隔，单位为秒。批量写入时每行操作都会触发 commit，
# 若每次都重新设置文件权限开销过大，因此仅在距上次刷新达到此间隔后才再次执行。
# 跨层时序常量未集中到 UI 层，以避免数据层反向依赖 UI 模块；本常量作为数据层
# 时序参数的命名事实来源。
SECURE_FILES_DEBOUNCE_SECONDS = 1.0


# 加密列密文的格式自检字符集：版本前缀后为 base64 字符。
_B64_CHARS = frozenset('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')


# 签名/验证函数的类型协议，替代弱类型 Callable
@runtime_checkable
class EntrySigner(Protocol):
    def __call__(self, entry: RawEntry) -> str: ...


@runtime_checkable
class EntryVerifier(Protocol):
    def __call__(self, entry: RawEntry) -> None: ...


@runtime_checkable
class CategorySigner(Protocol):
    def __call__(self, category: Category) -> str: ...


@runtime_checkable
class CategoryVerifier(Protocol):
    def __call__(self, category: Category) -> None: ...


class DatabaseManager:
    """SQLite 数据库管理器

    作为统一数据访问入口，所有公共 CRUD 方法委托给子 Repository
    （entries / categories / schema）。跨表编排（如删除分类时解关联条目
    并重算签名）由本层协调，各 Repository 仅负责单表操作。
    """

    def __init__(self, db_path: Path, *, test_mode: bool = False):
        self._db_path = db_path
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.RLock()
        self._transaction_depth = 0
        self._savepoint_counter = 0
        self._write_guard: Callable[[], None] | None = None
        self._entry_signer: EntrySigner | None = None
        self._entry_verifier: EntryVerifier | None = None
        self._category_signer: CategorySigner | None = None
        self._category_verifier: CategoryVerifier | None = None
        self._last_secure_ts: float = 0.0
        self._schema_validated: bool = False
        # 实例级加密断言开关。test_mode 下自动关闭，允许测试直接写入明文。
        # 生产环境保持 True，确保密文前缀断言生效。
        self._enforce_encrypted_fields: bool = not test_mode

        # 子 Repository
        self._entry_repo = EntryRepository(self)
        self._category_repo = CategoryRepository(self)
        self._schema_mgr = SchemaManager(self)

    # ==================== 子 Repository 公共访问接口 ====================
    # 替代 Repository 中的 _mgr._conn / _mgr._lock 等私有属性访问。

    @property
    def connection(self) -> sqlite3.Connection:
        """数据库连接，供 Repository 使用。调用方须确保数据库已连接。"""
        if self._conn is None:
            raise DatabaseError('数据库未连接')
        return self._conn

    @property
    def db_lock(self) -> threading.RLock:
        """线程安全锁，供 Repository 使用。"""
        return self._lock

    @property
    def entry_verifier(self) -> EntryVerifier | None:
        """条目元数据校验函数。"""
        return self._entry_verifier

    @property
    def category_verifier(self) -> CategoryVerifier | None:
        """分类元数据校验函数。"""
        return self._category_verifier

    @property
    def schema_validated(self) -> bool:
        return self._schema_validated

    @schema_validated.setter
    def schema_validated(self, value: bool) -> None:
        self._schema_validated = value

    def guard_write(self) -> None:
        """写入前校验，公共接口。"""
        self._guard_write()

    def auto_commit(self) -> None:
        """非事务模式下自动提交，公共接口。"""
        self._auto_commit()

    def sign_entry(self, entry: RawEntry) -> str:
        """条目元数据签名，公共接口。"""
        return self._sign_entry(entry)

    def sign_category(self, category: Category) -> str:
        """分类元数据签名，公共接口。"""
        return self._sign_category(category)

    def assert_encrypted(self, value: str, field_name: str) -> None:
        """断言加密字段的值格式正确，公共接口。"""
        self._assert_encrypted(value, field_name)

    def set_write_guard(self, guard: Callable[[], None]) -> None:
        """设置写入前校验，用于阻止过期密钥会话继续写库。"""
        self._write_guard = guard

    def set_entry_integrity_handlers(
        self,
        signer: EntrySigner,
        verifier: EntryVerifier,
    ) -> None:
        """设置条目元数据签名与校验函数。"""
        self._entry_signer = signer
        self._entry_verifier = verifier

    def set_category_integrity_handlers(
        self,
        signer: CategorySigner,
        verifier: CategoryVerifier,
    ) -> None:
        """设置分类元数据签名与校验函数。"""
        self._category_signer = signer
        self._category_verifier = verifier

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
    def transaction(self) -> Iterator[None]:
        """事务上下文；嵌套事务使用 SAVEPOINT 独立回滚。

        线程安全契约：
        - 整个事务期间持有 db_lock，阻止其他线程在此共享连接上插队写入，
          避免 check_same_thread=False 下跨线程事务的部分回滚。
        - 持锁还保证改密重加密、备份恢复等长事务期间，其他线程不会读到
          半完成的中间状态密文（部分新密钥、部分旧密钥），避免解密失败。
          此为有意设计：数据一致性优先于改密/导入期间的 UI 读响应性。
        - RLock 可重入，事务内嵌套的 @_db_operation 可正常重入获取锁。
        - 调用方无需再保证无并发写同一表，本方法通过持锁强制写串行化。
        """
        if self._conn is None:
            raise DatabaseError("数据库未连接")
        with self._lock:
            if not self.in_transaction:
                self.begin_transaction()
                try:
                    yield
                    self.commit_transaction()
                except Exception:
                    self.rollback_transaction()
                    raise
                return

            # 此分支仅在 in_transaction 为真时进入，而 in_transaction 要求
            # _transaction_depth > 0，事务开始必然先经过 begin_transaction 的
            # _conn is None 断言，故此处 conn 必非 None，无需重复检查。
            self._guard_write()
            self._savepoint_counter += 1
            savepoint = f'"cipherbox_sp_{self._savepoint_counter}"'
            self._conn.execute(f'SAVEPOINT {savepoint}')
            # depth 语义不变量：外层事务 begin_transaction 设 depth=1；嵌套 savepoint
            # 每次 +=1 至 2..N，finally 中 -=1 还原。commit_transaction 要求 depth==1
            # （仅外层事务可 commit），嵌套层只 RELEASE SAVEPOINT 不 commit。
            self._transaction_depth += 1
            try:
                yield
                self._conn.execute(f'RELEASE SAVEPOINT {savepoint}')
            except Exception:
                # savepoint 回滚失败不应掩盖原始异常；记录后交由外层事务的
                # rollback_transaction 统一处理，原始异常照常向上抛出。
                try:
                    self._conn.execute(f'ROLLBACK TO SAVEPOINT {savepoint}')
                    self._conn.execute(f'RELEASE SAVEPOINT {savepoint}')
                except sqlite3.Error:
                    logger.warning("savepoint 回滚失败，交由外层事务处理", exc_info=True)
                raise
            finally:
                self._transaction_depth -= 1

    def begin_transaction(self) -> None:
        """开始事务，并抑制内部 commit。

        注意：此方法未加 ``@_db_operation`` 锁，必须在已持有锁的
        上下文内调用，例如 ``@_db_operation`` 装饰的方法内或
        ``transaction()`` 上下文管理器内，不可直接从外部线程调用。
        """
        if self._conn is None:
            raise DatabaseError("数据库未连接")
        if self.in_transaction:
            raise TransactionError("数据库事务已经开始")
        self._guard_write()
        try:
            self._conn.execute("BEGIN TRANSACTION")
        except sqlite3.OperationalError as exc:
            # 纵深防御：正常路径下 in_transaction 守卫已排除重复 BEGIN。若仍触发
            # 'cannot start a transaction within a transaction'（如 standalone
            # @_db_write 写失败后隐式事务悬挂的遗留态），归一为 DatabaseError 而非
            # 让裸驱动异常上泄（与 @_db_write 的失败回滚契约共同关闭连接毒化路径）。
            raise DatabaseError(f'开始事务失败：{exc}') from exc
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
        # 事务已成功提交；文件权限刷新是后续加固，失败不应让调用方误以为事务
        # 失败而重试写入（WAL/SHM 可能因 checkpoint 暂不存在）。参照 secure_checkpoint 降级。
        # _secure_database_files 经 secure_file(strict=True) 仅可能抛 OSError（chmod/
        # icacls/ACL 失败），缩窄为 OSError 避免吞掉未来引入的逻辑 bug。
        try:
            self._secure_database_files()
        except OSError:
            logger.warning("提交后刷新数据库文件权限失败", exc_info=True)

    def rollback_transaction(self) -> None:
        """回滚事务。

        注意：此方法未加 ``@_db_operation`` 锁，必须在已持有锁的
        上下文内调用。参见 :meth:`begin_transaction`。
        """
        if self._conn is None:
            raise DatabaseError("数据库未连接")
        try:
            self._conn.execute("ROLLBACK")
        except sqlite3.OperationalError as exc:
            # 仅吞无活动事务这类良性错误（重复回滚或事务已结束）；
            # 其余 OperationalError（磁盘满、I/O 错误、数据库锁定）意味着
            # 回滚未生效，事务可能仍开着，必须升级处理而非静默通过。
            message = str(exc).lower()
            if 'no transaction' in message or 'no active' in message:
                logger.debug("回滚时无活动事务（良性）：%s", exc)
            else:
                logger.error("回滚事务失败，数据库可能不一致", exc_info=True)
                raise
        finally:
            # 即使 ROLLBACK 抛异常也归零事务深度，避免状态粘滞导致后续
            # transaction() 误判仍处事务内而走 savepoint 分支。
            self._transaction_depth = 0
            self._savepoint_counter = 0

    def _auto_commit(self) -> None:
        """内部提交：仅在非事务模式下执行 commit。

        权限刷新按 ``SECURE_FILES_DEBOUNCE_SECONDS`` 防抖（理由见该常量定义），
        仅在距上次刷新达到间隔后才执行。
        """
        if not self.in_transaction and self._conn:
            try:
                self._conn.commit()
            except Exception:
                self._transaction_depth = 0
                self._savepoint_counter = 0
                logger.error("数据库提交失败", exc_info=True)
                raise
            now = _time.monotonic()
            if now - self._last_secure_ts >= SECURE_FILES_DEBOUNCE_SECONDS:
                # 提交已成功；权限刷新失败仅告警，不污染已成功的事务。
                # secure_file(strict=True) 仅可能抛 OSError，缩窄避免吞掉逻辑 bug。
                try:
                    self._secure_database_files()
                except OSError:
                    logger.warning("提交后刷新数据库文件权限失败", exc_info=True)
                self._last_secure_ts = now

    # ========== 连接管理 ==========

    def open(self) -> bool:
        """打开数据库连接。"""
        try:
            secure_directory(self._db_path.parent)
            # check_same_thread=False 允许跨线程共享连接；真正的并发保护由 _lock
            # （RLock）提供，所有 DB 操作须通过 @_db_operation 或在已持锁上下文中调用。
            self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            # 校验 WAL 是否真正生效：不支持 WAL 的文件系统（网络共享、部分 FAT/exFAT）
            # 上 SQLite 会静默回退到其它日志模式并返回该模式名。WAL 未生效时
            # wal_checkpoint(TRUNCATE) 与 -wal/-shm 权限收紧等安全清理会静默降级为
            # no-op，须记可观测告警让降级可见，而非误以为安全清理仍在工作。
            mode_row = self._conn.execute("PRAGMA journal_mode=WAL").fetchone()
            actual_mode = mode_row[0] if mode_row else ''
            if str(actual_mode).lower() != 'wal':
                logger.warning(
                    "WAL 模式未生效（实际为 %s），WAL 相关安全清理将静默降级；"
                    "建议将数据目录置于支持 WAL 的本地文件系统",
                    actual_mode,
                )
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA secure_delete=ON")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.execute("PRAGMA synchronous=FULL")
            # page cache 与内存映射：本地库虽小，但全表扫描（get_entries + 逐行
            # HMAC 验签）在数千条目下从更大的 cache 受益。cache_size=-8000（约
            # 8MB）远大于默认 2MB；mmap_size=256MB 让只读路径减少系统调用。
            # synchronous=FULL 是耐久性安全取舍，不降级。
            self._conn.execute("PRAGMA cache_size=-8000")
            self._conn.execute("PRAGMA mmap_size=268435456")
            self._secure_database_files()
            self._schema_validated = False  # 新连接需要重新验证 schema
            return True
        except (sqlite3.Error, OSError):
            logger.error("数据库打开失败", exc_info=True)
            if self._conn is not None:
                self._conn.close()
                self._conn = None
            return False

    def _secure_database_files(self) -> None:
        secure_file(self._db_path, strict=True)
        secure_file(Path(f'{self._db_path}-wal'), strict=True)
        secure_file(Path(f'{self._db_path}-shm'), strict=True)

    def close(self) -> None:
        """关闭数据库连接。

        持有 db_lock 以避免与活动事务并发关闭连接：若改密等长事务正在进行，
        close 会等其提交或回滚（释放 db_lock）后再关闭，防止连接在事务中途
        被关闭导致损坏。
        """
        with self._lock:
            if self._conn:
                if self._transaction_depth > 0:
                    logger.warning(
                        "数据库关闭时存在未提交事务 (depth=%d)，将回滚",
                        self._transaction_depth,
                    )
                    # 先回滚再关闭，确保事务状态机被显式清理；仅 close 会
                    # 把 _transaction_depth 留在 > 0，后续若在同实例重开连接，
                    # transaction() 会误判仍处事务内而走 savepoint 分支。
                    self.rollback_transaction()
                self._conn.close()
                self._conn = None
            self._transaction_depth = 0
            self._savepoint_counter = 0

    # ==================== 元数据 ====================

    @_db_operation
    def get_meta(self, key: str) -> str | None:
        """获取元数据。"""
        row = self.connection.execute(
            "SELECT value FROM vault_meta WHERE key = ?", (key,)
        ).fetchone()
        return row['value'] if row else None

    @_db_operation
    def get_meta_batch(self, keys: list[str]) -> dict[str, str | None]:
        """批量获取多条元数据，单次查询返回。

        Args:
            keys: 要获取的元数据键名列表。

        Returns:
            字典，键为请求的键名，值为对应的元数据值，不存在则为 None。
        """
        if not keys:
            return {}
        placeholders = ','.join('?' for _ in keys)
        rows = self.connection.execute(
            f"SELECT key, value FROM vault_meta WHERE key IN ({placeholders})",  # nosec B608 - 参数化占位符
            keys,
        ).fetchall()
        result: dict[str, str | None] = {k: None for k in keys}
        for row in rows:
            result[row['key']] = row['value']
        return result

    @_db_write
    def set_meta(self, key: str, value: str) -> None:
        """设置元数据。"""
        self.connection.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?, ?)",
            (key, value),
        )
        self._auto_commit()

    # ==================== 安全操作 ====================

    @_db_operation
    def secure_checkpoint(self) -> None:
        """截断 WAL，降低已删除或重加密数据残留。

        截断后立即刷新 WAL/SHM 文件权限：checkpoint 会改写这些文件，
        需重新收紧 ACL，而非依赖后续提交的防抖刷新或目录继承 ACL。

        Note:
            事务内调用时静默跳过（checkpoint 会干扰进行中的事务）。此时 WAL
            清除依赖事务提交时 SQLite 的自动 checkpoint；若调用方需保证 WAL
            被显式截断以清除已删密文残留，应在事务提交后调用本方法。
        """
        if self._conn is not None and not self.in_transaction:
            try:
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except sqlite3.Error:
                logger.warning("WAL 安全截断失败", exc_info=True)
                return
            self._secure_database_files()

    # ==================== 内部方法 ====================

    def _assert_encrypted(self, value: str, field_name: str) -> None:
        """格式自检（非密码学保证）：加密列须为受支持前缀的 base64 密文，或空。

        仅校验密文形态以拦截明显的明文误写（明文常含 @、空格、下划线等非 base64
        字符），不验证密文真实性——真正的认证由 GCM 认证标签在解密时完成。纯字母
        数字的明文理论上能通过此字符集校验，但解密时会被 GCM 拒绝，故此处为防御性
        编程提示而非安全边界。防止绕过 EntryManager 直接调用 db.add_entry/
        update_entry 时明文静默落入加密列。空值允许通过，未填写字段存储为空字符串。
        读取实例级 _enforce_encrypted_fields，避免测试覆写泄漏到其他实例。

        适用范围：接受 ``cb2:`` 前缀的文本密文；
        ``encrypt_bytes`` 的字节前缀路径不经过此加密列断言。
        """
        if self._enforce_encrypted_fields and value:
            # 加密层始终产出 CIPHERTEXT_PREFIX 前缀密文；强制要求此前缀，
            # 使纯字母数字明文（如 abc123，恰为 base64 字符子集）无法再以「无前缀
            # 合法密文」名义通过字符集校验。真正认证仍由 GCM 标签在解密时完成，
            # 此处为防御性拦截，防止绕过 EntryManager 直接写库时明文静默落入加密列。
            # 引用共享层 CIPHERTEXT_PREFIX 单一事实源（不经 crypto 层，保持 Data 层
            # 零 crypto 依赖）：前缀重命名时此校验与错误提示自动同步，避免字面量漂移。
            prefix = CIPHERTEXT_PREFIX
            if not value.startswith(prefix):
                raise ValueError(
                    f'数据层收到未加密的 {field_name}'
                    f'（期望 {prefix} 前缀的 base64 密文），请通过 EntryManager 操作条目'
                )
            tail = value[len(prefix):]
            if not _B64_CHARS.issuperset(tail):
                raise ValueError(
                    f'数据层收到格式异常的 {field_name}'
                    f'（{prefix} 前缀后须为 base64 密文），请通过 EntryManager 操作条目'
                )

    def _sign_entry(self, entry: RawEntry) -> str:
        if self._entry_signer:
            return self._entry_signer(entry)
        return entry.metadata_mac

    def _sign_category(self, category: Category) -> str:
        if self._category_signer:
            return self._category_signer(category)
        return category.metadata_mac

    # ==================== 委托与编排 ====================
    # DatabaseManager 作为统一数据访问入口。纯透传方法（get_entries、add_category
    # 等）在下方显式手写委托给子 Repository——保留显式委托而非 __getattr__ 动态
    # 委托：Pyright 严格模式下动态委托会让调用方丢失返回类型推断。调用方一律经
    # db.get_entries() 等透传方法访问（保留完整返回类型）。仅当需要跨表事务编排
    # （如 delete_category）时才在下方显式定义编排方法。

    def init_tables(self) -> None:
        return self._schema_mgr.init_tables()

    def get_categories(self, *, verify: bool = True) -> list[Category]:
        return self._category_repo.get_categories(verify=verify)

    def get_category(self, category_id: int, *, verify: bool = True) -> Category | None:
        return self._category_repo.get_category(category_id, verify=verify)

    def add_category(self, category: Category) -> int:
        return self._category_repo.add_category(category)

    def update_category(self, category: Category) -> None:
        return self._category_repo.update_category(category)

    def update_category_reencrypted(self, category: Category) -> None:
        return self._category_repo.update_category_reencrypted(category)

    def update_categories_batch(self, categories: list[Category]) -> None:
        return self._category_repo.update_categories_batch(categories)

    def get_category_entry_count(self, category_id: int) -> int:
        return self._category_repo.get_category_entry_count(category_id)

    def get_category_entry_counts(self) -> dict[int, int]:
        return self._category_repo.get_category_entry_counts()

    # ======== 跨表编排（非委托透传）========
    # 以下方法含显式事务与多 Repository 协调，锁与事务由本编排层统一管理。
    # 新增编排逻辑请保持此注释边界。

    def delete_category(self, category_id: int) -> None:
        """删除分类：事务内先解关联条目并重算签名，再删除分类行。

        解关联条目与删除分类两步跨表编排由本层协调，各 Repository 仅负责
        单表操作，从而消除跨 Repository 的私有访问越权。
        """
        with self._lock:
            self._guard_write()
            with self.transaction():
                self._entry_repo.clear_category_signatures(category_id)
                self._category_repo.delete_category(category_id)

    # -- 委托透传：Entries --

    def get_entries(self, query: EntryQuery) -> list[RawEntry]:
        return self._entry_repo.get_entries(query)

    def get_entry(self, entry_id: int) -> RawEntry | None:
        return self._entry_repo.get_entry(entry_id)

    def add_entry(self, entry: RawEntry, preserve_metadata: bool = False) -> int:
        return self._entry_repo.add_entry(entry, preserve_metadata=preserve_metadata)

    def add_entries_batch(
        self, entries: list[RawEntry], *, preserve_metadata: bool = False,
    ) -> dict[str, int]:
        return self._entry_repo.add_entries_batch(
            entries, preserve_metadata=preserve_metadata,
        )

    def update_entry(
        self,
        entry: RawEntry,
        preserve_updated_at: bool = False,
    ) -> None:
        return self._entry_repo.update_entry(
            entry,
            preserve_updated_at=preserve_updated_at,
        )

    def update_entries_batch(self, rows: list[ReEncryptedEntry]) -> None:
        return self._entry_repo.update_entries_batch(rows)

    def soft_delete_entry(self, entry_id: int) -> bool:
        return self._entry_repo.soft_delete_entry(entry_id)

    def restore_entry(self, entry_id: int) -> bool:
        return self._entry_repo.restore_entry(entry_id)

    def permanent_delete_entry(self, entry_id: int) -> None:
        return self._entry_repo.permanent_delete_entry(entry_id)

    def empty_trash(self) -> None:
        return self._entry_repo.empty_trash()

    def clear_vault_data(self) -> None:
        return self._entry_repo.clear_vault_data()

    def get_entry_count(self, include_deleted: bool = False) -> int:
        return self._entry_repo.get_entry_count(include_deleted=include_deleted)

    def get_entries_by_ids(self, entry_ids: list[int]) -> list[RawEntry]:
        return self._entry_repo.get_entries_by_ids(entry_ids)

    # -- 委托透传：Password History --

    def add_password_history(
        self,
        entry_id: int,
        old_password_enc: str,
        changed_at: str = '',
    ) -> None:
        return self._entry_repo.add_password_history(entry_id, old_password_enc, changed_at)

    def add_password_history_batch(
        self,
        entry_id: int,
        items: list[tuple[str, str]],
    ) -> None:
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

    def update_password_history_batch(self, rows: list[ReEncryptedHistory]) -> None:
        return self._entry_repo.update_password_history_batch(rows)
