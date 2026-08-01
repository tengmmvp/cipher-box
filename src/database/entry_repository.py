"""条目数据访问层 — 条目 CRUD、批量操作、密码历史。

职责单一：条目及密码历史表的增删改查，经 DatabaseManager 委托提供统一数据访问接口。
"""

import logging
import sqlite3
import threading
import uuid
from collections.abc import Callable, Sequence
from contextlib import AbstractContextManager
from dataclasses import replace
from typing import Any

from ..exceptions import DatabaseError, TransactionError, VaultIntegrityError, VaultLockedError
from ..models import MAX_PASSWORD_HISTORY, PasswordHistory, RawEntry
from ..utils.format import utc_now_iso
from ._decorators import _db_operation, _db_write
from .types import ConnectionProvider, EntryQuery, ReEncryptedEntry, ReEncryptedHistory, VerifyMode

logger = logging.getLogger(__name__)

# _ENTRY_COLUMNS 是 entries 表非 id 列名的单一事实源。
# 新增列必须在此追加，INSERT/UPDATE/SELECT 派生 SQL 自动跟随；同时须同步纳入
# MetadataSigner._payload 签名载荷（由 test_entry_signature_coverage 断言守护）。
# 用 tuple（不可变）：误用 append 会在运行时抛 AttributeError，防止列序被无意改写
# 致 SQL 列错位（ARCH-024）。
_ENTRY_COLUMNS = (
    'crypto_id', 'title_enc', 'username_enc', 'password_enc', 'url_enc',
    'category_id', 'tags_enc', 'notes_enc', 'custom_fields_enc',
    'is_favorite', 'is_deleted', 'password_strength', 'entry_type',
    'totp_secret_enc', 'created_at', 'updated_at', 'deleted_at',
    'password_changed_at', 'metadata_mac',
)

# entries 表列名 → 取值函数。INSERT/UPDATE 参数元组与加密断言均从此派生（列序来自
# _ENTRY_COLUMNS，取值来自本映射），消除手写元组列序错位。bool 列(is_favorite/
# is_deleted)经 int() 转 INTEGER；custom_fields_enc 取密文属性 custom_fields_db_value。
_ENTRY_COLUMN_GETTERS: dict[str, Callable[[RawEntry], object]] = {
    'crypto_id': lambda e: e.crypto_id,
    'title_enc': lambda e: e.title,
    'username_enc': lambda e: e.username,
    'password_enc': lambda e: e.password,
    'url_enc': lambda e: e.url,
    'category_id': lambda e: e.category_id,
    'tags_enc': lambda e: e.tags,
    'notes_enc': lambda e: e.notes,
    'custom_fields_enc': lambda e: e.custom_fields_db_value,
    'is_favorite': lambda e: int(e.is_favorite),
    'is_deleted': lambda e: int(e.is_deleted),
    'password_strength': lambda e: e.password_strength,
    'entry_type': lambda e: e.entry_type,
    'totp_secret_enc': lambda e: e.totp_secret,
    'created_at': lambda e: e.created_at,
    'updated_at': lambda e: e.updated_at,
    'deleted_at': lambda e: e.deleted_at,
    'password_changed_at': lambda e: e.password_changed_at,
    'metadata_mac': lambda e: e.metadata_mac,
}
# 键集守护：getter 须覆盖 _ENTRY_COLUMNS 全部列，新增列忘加 getter 在模块加载即报错。
if set(_ENTRY_COLUMN_GETTERS) != set(_ENTRY_COLUMNS):
    raise RuntimeError('_ENTRY_COLUMN_GETTERS 与 _ENTRY_COLUMNS 列集不一致，参数取值将错位')

# 属性存在性守护：键集守护只校验 getter 键覆盖，不校验 lambda 内属性是否存在。
# 用全默认 RawEntry 遍历所有 getter，捕获属性拼写错误（AttributeError）或签名错配
# （TypeError），模块加载即报错。语义正确性（如取错字段）由 test_re_encrypt 兜底。
_PROBE_ENTRY = RawEntry()
for _col, _getter in _ENTRY_COLUMN_GETTERS.items():
    try:
        _getter(_PROBE_ENTRY)
    except (AttributeError, TypeError) as _exc:
        raise RuntimeError(
            f'_ENTRY_COLUMN_GETTERS[{_col!r}] 取值失败，属性可能拼写错误: {_exc}'
        ) from None
del _PROBE_ENTRY


def _entry_column_values(entry: RawEntry, columns: Sequence[str]) -> tuple[Any, ...]:
    """按给定列序从 entry 取值生成参数元组，供 INSERT/UPDATE 位置绑定。

    取值经 _ENTRY_COLUMN_GETTERS，与 SQL 列序由同一映射驱动，消除手写元组错位。
    """
    return tuple(_ENTRY_COLUMN_GETTERS[column](entry) for column in columns)

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
    "WHERE id=?"
)

# 重加密列：改密重写除删除状态与创建时间外的全部列（含全部密文列）。直接从
# _UPDATE_ENTRY_COLUMNS 派生，使新增加密列只需加入 _ENTRY_COLUMNS 即被改密重写，
# 避免漏列保留旧密钥密文、新密钥无法解密的数据损坏。
_RE_ENCRYPT_COLUMNS = list(_UPDATE_ENTRY_COLUMNS)

# 运行时断言：所有 *_enc 加密列必须被改密重写，否则保留旧密钥密文致改密后无法解密。
if not all(
    col in _RE_ENCRYPT_COLUMNS
    for col in _ENTRY_COLUMNS
    if col.endswith('_enc')
):
    raise RuntimeError(
        '加密列未被纳入改密重写集合，将导致改密后数据损坏'
    )

# ReEncryptedEntry 字段序须与 _RE_ENCRYPT_BATCH_UPDATE_SQL 列序（_RE_ENCRYPT_COLUMNS
# + id）一一对应，供 executemany 位置绑定；错位会被此断言捕获，避免写错列。
if ReEncryptedEntry._fields != tuple(_RE_ENCRYPT_COLUMNS) + ('id',):
    raise RuntimeError(
        'ReEncryptedEntry 字段序与 _RE_ENCRYPT_COLUMNS + id 不一致，executemany 会错位'
    )

_RE_ENCRYPT_BATCH_UPDATE_SQL = (
    f"UPDATE entries SET {', '.join(f'{column}=?' for column in _RE_ENCRYPT_COLUMNS)} "  # nosec B608 - 参数绑定
    "WHERE id=?"
)

# 签名查询 SQL：LEFT JOIN 提供与其他查询一致的列（含 category_name），避免
# _row_to_entry 对缺失列做特殊处理。
_SELECT_ENTRY_SIGN_SQL = (
    f"SELECT {', '.join(['e.id'] + [f'e.{c}' for c in _ENTRY_COLUMNS])}, "  # nosec B608 - 列名硬编码
    "c.name_enc as category_name "
    "FROM entries e LEFT JOIN categories c ON e.category_id = c.id WHERE e.id=?"
)

# 条目带分类名的 JOIN 基础查询（e.* 形态），供 get_entries / get_entry /
# get_entries_by_ids / clear_category_signatures 复用。_SELECT_ENTRY_SIGN_SQL 用
# 显式列名（需与 _ENTRY_COLUMNS 精确对齐），故独立不合并。
_SELECT_ENTRY_WITH_CATEGORY_SQL = (
    "SELECT e.*, c.name_enc as category_name "
    "FROM entries e LEFT JOIN categories c ON e.category_id = c.id"
)

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

# ID 分批阈值：SQLite 默认限制 999 个主机变量，取 500 留余量。
_ID_BATCH_SIZE = 500
# 密码历史重加密分页批量：与 re_encryption._RE_ENCRYPT_BATCH_SIZE 对齐，控制改密
# 重加密内存峰值（QL-008，消除魔法数 200）。
_DEFAULT_HISTORY_BATCH_LIMIT = 200


def _classify_entry_integrity_error(prefix: str, exc: sqlite3.IntegrityError) -> DatabaseError:
    """按 sqlite 原始文案分流 IntegrityError 成因，避免一律误标为「crypto_id 冲突」。

    entries 表除 crypto_id UNIQUE 外还有 category_id 外键约束；FK/NOT NULL 违规被
    误标为唯一约束会误导排障方向。
    """
    message = str(exc).lower()
    if 'foreign key' in message:
        detail = '违反外键约束（引用的分类不存在）'
    elif 'not null' in message:
        detail = '违反非空约束'
    else:
        detail = '违反唯一约束（crypto_id 冲突）'
    return DatabaseError(f'{prefix}{detail}：{exc}')


class EntryRepository:
    """条目数据访问层 — 条目 CRUD、批量操作、密码历史。

    经 ``conn_provider`` 获取 sqlite3.Connection（通常为 DatabaseManager 实例）。
    """

    def __init__(self, conn_provider: ConnectionProvider):
        # conn_provider（通常 DatabaseManager 实例）提供连接、锁与编排方法。
        # 以 Protocol 类型标注便于静态校验与测试替身。
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

    def _sign_entry(self, entry: RawEntry) -> str:
        return self._mgr.sign_entry(entry)

    @property
    def in_transaction(self) -> bool:
        return self._mgr.in_transaction

    def transaction(self) -> AbstractContextManager[None]:
        return self._mgr.transaction()

    def secure_checkpoint(self) -> None:
        return self._mgr.secure_checkpoint()

    # ======== 防御性断言 ========

    def _assert_encrypted(self, value: str, field_name: str) -> None:
        """防御性断言：加密列的值应为受支持格式的密文，或空字符串。"""
        self._mgr.assert_encrypted(value, field_name)

    def _assert_entry_encrypted_fields(self, entry: RawEntry) -> None:
        """防御性断言：条目的全部加密字段(*_enc 列对应)应为受支持格式的密文或空。

        加密字段集从 _ENTRY_COLUMNS 的 *_enc 列派生，单一事实源：新增 *_enc 列只需
        在 _ENTRY_COLUMN_GETTERS 追加 getter，本断言自动覆盖。
        """
        for column in _ENTRY_COLUMNS:
            if column.endswith('_enc'):
                # custom_fields_enc 对应密文属性 custom_fields_db_value，其余 *_enc
                # 去后缀即 RawEntry 同名 str 属性。经 getattr 取值保持加密字段集从
                # _ENTRY_COLUMNS 单一来源派生。
                attr = (
                    'custom_fields_db_value'
                    if column == 'custom_fields_enc'
                    else column[:-4]
                )
                self._assert_encrypted(getattr(entry, attr), column[:-4])

    # ==================== 条目 ====================

    @staticmethod
    def _entry_insert_params(entry: RawEntry) -> tuple[Any, ...]:
        """构造 INSERT 参数元组，列序与 _ENTRY_COLUMNS 一致。

        供 add_entry 与 add_entries_batch 共用，取值经 _ENTRY_COLUMN_GETTERS 驱动。
        """
        return _entry_column_values(entry, _ENTRY_COLUMNS)

    @staticmethod
    def _entry_update_params(entry: RawEntry) -> tuple[Any, ...]:
        """构造 UPDATE SET 参数元组（不含 WHERE id），列序与 _UPDATE_ENTRY_COLUMNS 一致。

        与 _entry_insert_params 对称：UPDATE 不写 is_deleted/deleted_at/created_at，
        取值经 _ENTRY_COLUMN_GETTERS 驱动，列序由同一映射守护。
        """
        return _entry_column_values(entry, _UPDATE_ENTRY_COLUMNS)

    def get_entries(self, query: EntryQuery) -> list[RawEntry]:
        """获取密码条目列表，过滤/排序/limit/verify 经 ``EntryQuery`` 单一传入。

        ``query.sort_by_updated`` 为 True 时仅按 updated_at DESC 排序（不带
        is_favorite），供「近期更新」视图下推 LIMIT 到 SQL，免全量内存排序再截断。

        ``query.verify`` 完整性校验模式：默认 LENIENT（逐行 HMAC 验签并标记异常，
        不抛异常），列表/搜索/标签等只读路径沿用默认以检测篡改；SKIP 仅用于签名
        计算前的原始读取（不能先验签再算签名）；STRICT 单条详情用，失败抛异常。
        """
        # ARCH-005：本方法手写 with self._lock 而非挂 @_db_operation，跳过装饰器连接
        # 校验，显式补齐使未连接时抛 DatabaseError 而非无诊断的 AttributeError。
        if self._conn is None:
            raise DatabaseError("数据库未连接")
        sql = _SELECT_ENTRY_WITH_CATEGORY_SQL + " WHERE 1=1"
        params: list = []

        if query.deleted_only:
            sql += " AND e.is_deleted = 1"
        elif not query.include_deleted:
            sql += " AND e.is_deleted = 0"

        if query.category_id is not None:
            sql += " AND e.category_id = ?"
            params.append(query.category_id)

        if query.favorite_only:
            sql += " AND e.is_favorite = 1"

        if query.after_id is not None:
            sql += " AND e.id > ?"
            params.append(query.after_id)
            sql += " ORDER BY e.id ASC"
        elif query.sort_by_updated:
            sql += " ORDER BY e.updated_at DESC"
        else:
            sql += " ORDER BY e.is_favorite DESC, e.updated_at DESC"

        if query.limit is not None:
            sql += " LIMIT ?"
            params.append(query.limit)

        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        # fetchall 后 sqlite3.Row 已脱离游标；完整性验签与 dataclass 构建不再
        # 持有数据库锁，避免大库后台搜索长期阻塞其他短查询。
        return [self._row_to_entry(r, verify=query.verify) for r in rows]

    @_db_operation
    def get_entry(self, entry_id: int) -> RawEntry | None:
        row = self._conn.execute(
            f"{_SELECT_ENTRY_WITH_CATEGORY_SQL} WHERE e.id = ?",  # nosec B608
            (entry_id,),
        ).fetchone()
        return self._row_to_entry(row) if row else None

    def _normalize_for_insert(
        self, entry: RawEntry, *, now: str, preserve_metadata: bool,
    ) -> RawEntry:
        """填充 INSERT 所需的默认字段(crypto_id/时间戳/删除状态/签名)。

        add_entry 与 add_entries_batch 共用。password_changed_at 回退到 created_at
        （"未改过密码即创建时间"），而非 updated_at/now，避免导入/恢复时用导入时刻
        覆盖历史时间。RawEntry 为 frozen，返回经 replace 的新实例，调用方须承接。
        """
        crypto_id = entry.crypto_id or uuid.uuid4().hex
        created_at = entry.created_at or now
        updated_at = (
            entry.updated_at if preserve_metadata and entry.updated_at else now
        )
        is_deleted = bool(preserve_metadata and entry.is_deleted)
        deleted_at = entry.deleted_at if preserve_metadata else ''
        password_changed_at = entry.password_changed_at or created_at or now
        entry = replace(
            entry,
            crypto_id=crypto_id,
            created_at=created_at,
            updated_at=updated_at,
            is_deleted=is_deleted,
            deleted_at=deleted_at,
            password_changed_at=password_changed_at,
        )
        return replace(entry, metadata_mac=self._sign_entry(entry))

    @_db_write
    def add_entry(self, entry: RawEntry, preserve_metadata: bool = False) -> int:
        """添加条目，返回 ID。"""
        # 防御性断言，防止明文静默写入加密列
        self._assert_entry_encrypted_fields(entry)
        entry = self._normalize_for_insert(
            entry, now=utc_now_iso(), preserve_metadata=preserve_metadata,
        )
        try:
            cursor = self._conn.execute(
                _INSERT_ENTRY_SQL,
                self._entry_insert_params(entry),
            )
        except sqlite3.IntegrityError as exc:
            # 归一化为领域异常并按文案分流 FK/NOT NULL/唯一，真实 sqlite 文案随 {exc} 附出。
            raise _classify_entry_integrity_error('条目写入', exc) from exc
        self._auto_commit()
        return cursor.lastrowid or 0

    @_db_write
    def add_entries_batch(
        self, entries: list[RawEntry], *, preserve_metadata: bool = False,
    ) -> dict[str, int]:
        """批量添加条目（恢复路径专用），返回 ``{crypto_id: new_id}``。

        逐条计算 ``metadata_mac`` 后用 ``executemany`` 一次性 INSERT，将 N 次单独
        INSERT+commit（每次 fsync）合并为 1 次 executemany+1 次 commit，缩短恢复
        长事务持锁时间（否则 UI 冻结）。``executemany`` 不返回逐条 lastrowid，故
        按 ``crypto_id`` 反查 ``id`` 建立映射，供调用方关联旧 entry_id。

        Args:
            entries: 待写入的 RawEntry 列表（加密字段须已加密）。
            preserve_metadata: 是否保留原 created_at/updated_at/is_deleted 等。
        """
        if not entries:
            return {}
        now = utc_now_iso()
        params = []
        normalized: list[RawEntry] = []
        for entry in entries:
            # 恢复数据来自外部备份，逐条断言加密列防明文落库（与 add_entry 一致，
            # 恢复低频全量写入，逐条断言开销可接受）。
            self._assert_entry_encrypted_fields(entry)
            entry = self._normalize_for_insert(
                entry, now=now, preserve_metadata=preserve_metadata,
            )
            params.append(self._entry_insert_params(entry))
            normalized.append(entry)
        try:
            self._conn.executemany(_INSERT_ENTRY_SQL, params)
        except sqlite3.IntegrityError as exc:
            raise _classify_entry_integrity_error('批量条目写入', exc) from exc
        # SEC-011：id 反查须在 _auto_commit() 之前完成——插入与反查在同一隐式事务内
        # （见 _db_write 装饰器），保证反查瞬时 IO 失败时条目尚未落库（standalone 写由
        # 装饰器回滚隐式事务；显式事务由外层 transaction() 统一回滚），避免「已提交但
        # 调用方收到异常」的部分状态。executemany 不提供逐条 lastrowid，按 crypto_id
        # 反查 id；按 _ID_BATCH_SIZE 分批，避免 >999 条目时 IN(...) 超出 SQLite 主机变量上限。
        crypto_ids = [entry.crypto_id for entry in normalized]
        id_map: dict[str, int] = {}
        for start in range(0, len(crypto_ids), _ID_BATCH_SIZE):
            batch = crypto_ids[start:start + _ID_BATCH_SIZE]
            placeholders = ','.join('?' for _ in batch)
            rows = self._conn.execute(
                f'SELECT id, crypto_id FROM entries WHERE crypto_id IN ({placeholders})',  # nosec B608
                batch,
            ).fetchall()
            for row in rows:
                id_map[row[1]] = row[0]
        self._auto_commit()
        return id_map

    @_db_write
    def update_entry(
        self,
        entry: RawEntry,
        preserve_updated_at: bool = False,
    ) -> None:
        """更新条目。

        Note: 不写 is_deleted/deleted_at，删除状态仅由 soft_delete_entry /
        restore_entry 管理。
        """
        # 防御性断言，防止明文静默写入加密列
        self._assert_entry_encrypted_fields(entry)
        updated_at = (
            entry.updated_at
            if preserve_updated_at and entry.updated_at
            else utc_now_iso()
        )
        # RawEntry 为 frozen，replace 产生带新时间戳与签名的新实例供写库。
        entry = replace(entry, updated_at=updated_at)
        entry = replace(entry, metadata_mac=self._sign_entry(entry))
        # SET 参数经 _entry_update_params 取值，末尾追加 WHERE id 绑定。列序由
        # _ENTRY_COLUMN_GETTERS 守护，与 INSERT 路径对称。
        self._conn.execute(
            _UPDATE_ENTRY_SQL,
            (*self._entry_update_params(entry), entry.id),
        )
        self._auto_commit()

    @_db_write
    def update_entries_batch(self, rows: list[ReEncryptedEntry]) -> None:
        """批量更新条目，改密重加密专用。

        Args:
            rows: ``ReEncryptedEntry`` NamedTuple 列表（re_encryption 产出）。
                采样断言按 NamedTuple 属性访问加密列，故不支持普通 tuple；
                NamedTuple 自动适配 executemany 的位置参数绑定。
        """
        if not rows:
            return
        # 全量逐行断言加密列（SEC-005）：_assert_encrypted 仅做 O(1) ``cb2:`` 前缀检查，
        # 全量遍历开销可忽略（数万条 × 加密列仍为微秒级），相比仅采样首行可防部分加密
        # bug 致明文静默落库。字段集从 ReEncryptedEntry._fields 的 *_enc 派生，新增 *_enc
        # 列自动覆盖。
        enc_fields = [f for f in ReEncryptedEntry._fields if f.endswith('_enc')]
        for row in rows:
            for field in enc_fields:
                enc_value = getattr(row, field)
                if enc_value:
                    self._assert_encrypted(enc_value, 're_encrypt_batch')
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
        entry = replace(entry, is_deleted=True, deleted_at=now)
        entry = replace(entry, metadata_mac=self._sign_entry(entry))
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
        entry = replace(entry, is_deleted=False, deleted_at='')
        entry = replace(entry, metadata_mac=self._sign_entry(entry))
        self._conn.execute(
            "UPDATE entries SET is_deleted=0, deleted_at='', metadata_mac=? WHERE id=?",
            (entry.metadata_mac, entry_id),
        )
        self._auto_commit()
        return True

    @_db_write
    def permanent_delete_entry(self, entry_id: int) -> None:
        """永久删除条目。

        不在此触发 secure_checkpoint：单条删除后 WAL 由 autocheckpoint（默认
        1000 页）兜底，频繁的 TRUNCATE+fsync 会拖慢批量永久删除。需即时收缩 WAL
        的场景（清空回收站、改密、恢复）由调用方在批量结束后统一 checkpoint。
        """
        self._conn.execute("DELETE FROM entries WHERE id=?", (entry_id,))
        self._auto_commit()

    @_db_write
    def empty_trash(self) -> None:
        """清空回收站（仅 DELETE；WAL 收缩与文件权限刷新由调用方 checkpoint）。"""
        self._conn.execute("DELETE FROM entries WHERE is_deleted=1")
        self._auto_commit()

    @_db_write
    def clear_vault_data(self) -> None:
        """清空领域数据，供事务化恢复使用。

        不在此 secure_checkpoint：恢复路径在事务内调用本方法（checkpoint 会在
        事务内静默跳过），调用方 ``restore_backup`` 已在事务提交后显式 checkpoint
        以清除旧密文残留并刷新 -wal/-shm 文件权限。
        """
        self._conn.execute("DELETE FROM password_history")
        self._conn.execute("DELETE FROM entries")
        self._conn.execute("DELETE FROM categories")
        self._auto_commit()

    @_db_operation
    def get_entry_count(self, include_deleted: bool = False) -> int:
        query = "SELECT COUNT(*) FROM entries"
        if not include_deleted:
            query += " WHERE is_deleted = 0"
        row = self._conn.execute(query).fetchone()
        return int(row[0]) if row else 0

    def get_entries_by_ids(self, entry_ids: list[int]) -> list[RawEntry]:
        """按 ID 列表批量获取条目。

        用于导入覆盖等场景，替代逐条 get_entry 的 N+1 查询。ID 数量超 SQLite
        主机变量上限（默认 999）时分批查询，避免 too many SQL variables 错误。

        Args:
            entry_ids: 要获取的条目 ID 列表。
        """
        if not entry_ids:
            return []
        # ARCH-005：手写 with self._lock 绕过 @_db_operation，显式补连接校验。
        if self._conn is None:
            raise DatabaseError("数据库未连接")
        # 去重保序：重复 id 致返回行数 < 请求数，调用方按位置对齐会错位。
        unique_ids = list(dict.fromkeys(entry_ids))
        fetched_rows = []
        with self._lock:
            for start in range(0, len(unique_ids), _ID_BATCH_SIZE):
                batch = unique_ids[start:start + _ID_BATCH_SIZE]
                placeholders = ','.join('?' for _ in batch)
                rows = self._conn.execute(
                    f"{_SELECT_ENTRY_WITH_CATEGORY_SQL} WHERE e.id IN ({placeholders})",  # nosec B608 - 参数化占位符
                    batch,
                ).fetchall()
                fetched_rows.extend(rows)
        return [
            self._row_to_entry(row, verify=VerifyMode.LENIENT)
            for row in fetched_rows
        ]

    # ==================== 密码历史 ====================

    @_db_write
    def add_password_history(
        self,
        entry_id: int,
        old_password_enc: str,
        changed_at: str = '',
    ) -> None:
        """添加密码历史记录。"""
        self._assert_encrypted(old_password_enc, 'password_history')
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
            self._assert_encrypted(encrypted, 'password_history')
        now = utc_now_iso()
        rows = [
            (entry_id, enc, changed_at or now)
            for enc, changed_at in items
        ]
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
        rows = self._conn.execute(
            f"{_SELECT_PASSWORD_HISTORY_SQL} "
            "WHERE h.entry_id = ? ORDER BY h.changed_at DESC, h.id DESC",
            (entry_id,),
        ).fetchall()
        return [self._row_to_password_history(r) for r in rows]

    @_db_operation
    def get_all_password_history(self) -> list[PasswordHistory]:
        """获取全部密码历史，用于改密和备份。"""
        rows = self._conn.execute(
            f"{_SELECT_PASSWORD_HISTORY_SQL} ORDER BY h.id"
        ).fetchall()
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
            self._assert_encrypted(encrypted, 'password_history')
        self._conn.executemany(
            "UPDATE password_history SET old_password_enc=? WHERE id=?",
            rows,
        )
        self._auto_commit()

    # ========== 内部方法 ==========

    def _select_entry_for_sign(self, entry_id: int) -> RawEntry | None:
        """按 ID 查询签名所需的完整行并返回 Entry 对象。

        供 soft_delete_entry / restore_entry 等重算签名操作复用。跳过完整性校验，
        因签名需读原始数据来计算 MAC（不能先验签再算签名）。
        """
        row = self._conn.execute(
            _SELECT_ENTRY_SIGN_SQL,
            (entry_id,),
        ).fetchone()
        return self._row_to_entry(row, verify=VerifyMode.SKIP) if row else None

    def clear_category_signatures(self, category_id: int) -> None:
        """将指定分类下所有条目的 category_id 置空并重算元数据签名。

        供删除分类时由 DatabaseManager.delete_category 编排调用。批量执行将 N+1
        模式降为 2 次操作；不校验旧签名，因签名将被覆盖。作为公开跨 Repository
        编排接口供 DatabaseManager 显式调用。

        锁与事务契约：未用 ``@_db_operation``，不自行获取 ``db_lock``。调用方
        须已持锁并处活动事务内，保证 SELECT 与 executemany UPDATE 的原子性与跨表
        一致性。入口断言将此契约升级为运行期检查。

        已知取舍（性能）：持锁下对全部条目逐条 ``_row_to_entry`` + ``_sign_entry``
        （HMAC）是 O(N) Python 循环，大分类下会阻塞其他数据库访问。彻底优化需
        ``MetadataSigner`` 提供批量签名接口；删除分类是低频操作，阻塞窗口可接受。
        """
        if not self.in_transaction:
            raise TransactionError(
                'clear_category_signatures 须在活动事务内调用（由 DatabaseManager.delete_category 编排）'
            )
        rows = self._conn.execute(
            f"{_SELECT_ENTRY_WITH_CATEGORY_SQL} WHERE e.category_id=?",  # nosec B608
            (category_id,),
        ).fetchall()
        update_data = []
        for row in rows:
            entry = self._row_to_entry(row, verify=VerifyMode.SKIP)
            entry = replace(entry, category_id=None)
            entry = replace(entry, metadata_mac=self._sign_entry(entry))
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
            verify: 完整性校验模式。STRICT 失败抛异常；LENIENT 仅设置
                integrity_error 标志并继续；SKIP 完全跳过。
        """
        entry = RawEntry(
            id=row['id'],
            crypto_id=row['crypto_id'],
            title=row['title_enc'],
            username=row['username_enc'] or '',
            password=row['password_enc'] or '',
            url=row['url_enc'] or '',
            category_id=row['category_id'],
            category_name=row['category_name'],
            tags=row['tags_enc'] or '',
            notes=row['notes_enc'] or '',
            custom_fields=row['custom_fields_enc'] or '',
            is_favorite=bool(row['is_favorite']),
            is_deleted=bool(row['is_deleted']),
            password_strength=row['password_strength'],
            entry_type=row['entry_type'],
            totp_secret=row['totp_secret_enc'] or '',
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
                entry = replace(
                    entry,
                    integrity_error=True,
                    integrity_message='元数据完整性校验失败',
                )
            except VaultLockedError:
                # 未解锁态（锁定期间后台线程读到已清零域密钥）非完整性错误，向上传播。
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
