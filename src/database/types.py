"""数据库层类型定义。"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING, NamedTuple, Protocol, runtime_checkable

if TYPE_CHECKING:
    from ..models import Category, PasswordHistory, RawEntry


class VerifyMode(Enum):
    """条目完整性校验模式。"""
    STRICT = auto()    # 校验失败时抛出异常
    LENIENT = auto()   # 设置 integrity_error 标志但不抛出异常
    SKIP = auto()      # 完全跳过校验


@dataclass(frozen=True)
class EntryQuery:
    """entries 表查询参数（过滤 + 排序 + limit + verify），get_entries 的单一入口。

    构造时校验 ``deleted_only`` / ``include_deleted`` 互斥——前者仅回收站、后者含
    全部（含回收站），同时为 True 语义矛盾，须构造即拒绝。
    """

    deleted_only: bool = False
    include_deleted: bool = False
    category_id: int | None = None
    favorite_only: bool = False
    limit: int | None = None
    after_id: int | None = None
    sort_by_updated: bool = False
    verify: VerifyMode = VerifyMode.LENIENT

    def __post_init__(self) -> None:
        if self.deleted_only and self.include_deleted:
            raise ValueError(
                'EntryQuery: deleted_only 与 include_deleted 互斥——'
                'deleted_only=True 仅返回回收站，include_deleted=True 含全部（含回收站）'
            )


@runtime_checkable
class ConnectionProvider(Protocol):
    """Repository 所需的 DatabaseManager 接口协议（结构化类型）。

    EntryRepository / CategoryRepository / SchemaManager 经 ``conn_provider`` 访问
    DatabaseManager 的连接、锁与编排方法。以 Protocol 显式声明所需成员，便于静态
    检查与测试替身。DatabaseManager 满足此协议。
    """

    @property
    def connection(self) -> sqlite3.Connection: ...

    @property
    def db_lock(self) -> threading.RLock: ...

    @property
    def in_transaction(self) -> bool: ...

    # schema_validated 可读写：Protocol 须以 property + setter 声明，Pyright 下
    # 可读写数据属性不接受 property+setter 实现。
    @property
    def schema_validated(self) -> bool: ...

    @schema_validated.setter
    def schema_validated(self, value: bool) -> None: ...

    @property
    def entry_verifier(self) -> Callable[[RawEntry], None] | None: ...

    @property
    def category_verifier(self) -> Callable[[Category], None] | None: ...

    def auto_commit(self) -> None: ...
    def guard_write(self) -> None: ...
    def sign_entry(self, entry: RawEntry) -> str: ...
    def sign_category(self, category: Category) -> str: ...
    def assert_encrypted(self, value: str, field_name: str) -> None: ...
    def secure_checkpoint(self) -> None: ...
    def transaction(self) -> AbstractContextManager[None]: ...


@runtime_checkable
class EntryStore(Protocol):
    """业务层条目与密码历史读写所需的数据接口切片。

    DatabaseManager 满足此协议；Business 层（EntryManager / BackupRestoreManager 等）
    经此协议访问条目数据，替代依赖具体 DatabaseManager，收窄暴露面（不含
    ``set_write_guard`` 等装配期 setter），并为测试替身提供明确契约。
    """

    def get_entries(self, query: EntryQuery) -> list[RawEntry]: ...

    def get_entry(self, entry_id: int) -> RawEntry | None: ...

    def get_entry_count(self, include_deleted: bool = False) -> int: ...

    def get_entries_by_ids(self, entry_ids: list[int]) -> list[RawEntry]: ...

    def add_entry(self, entry: RawEntry, preserve_metadata: bool = False) -> int: ...

    def add_entries_batch(
        self, entries: list[RawEntry], *, preserve_metadata: bool = False,
    ) -> dict[str, int]: ...

    def update_entry(self, entry: RawEntry, preserve_updated_at: bool = False) -> None: ...

    def update_entries_batch(self, rows: list[ReEncryptedEntry]) -> None: ...

    def soft_delete_entry(self, entry_id: int) -> bool: ...

    def restore_entry(self, entry_id: int) -> bool: ...

    def permanent_delete_entry(self, entry_id: int) -> None: ...

    def empty_trash(self) -> None: ...

    def clear_vault_data(self) -> None: ...

    def add_password_history(
        self, entry_id: int, old_password_enc: str, changed_at: str = '',
    ) -> None: ...

    def add_password_history_batch(
        self, entry_id: int, items: list[tuple[str, str]],
    ) -> None: ...

    def get_password_history(self, entry_id: int) -> list[PasswordHistory]: ...

    def get_all_password_history(self) -> list[PasswordHistory]: ...

    def get_all_password_history_batch(
        self, after_id: int = 0, limit: int = 200,
    ) -> list[PasswordHistory]: ...

    def get_password_history_count(self, entry_id: int) -> int: ...

    def update_password_history_batch(self, rows: list[ReEncryptedHistory]) -> None: ...


@runtime_checkable
class CategoryStore(Protocol):
    """业务层分类读写所需的数据接口切片。

    ``delete_category`` 是跨表编排方法（事务内清条目分类签名 + 删分类），实现方
    须保证在活动事务内调用。
    """

    def get_categories(self, *, verify: bool = True) -> list[Category]: ...

    def get_category(self, category_id: int, *, verify: bool = True) -> Category | None: ...

    def add_category(self, category: Category) -> int: ...

    def update_category(self, category: Category) -> None: ...

    def delete_category(self, category_id: int) -> None: ...

    def get_category_entry_count(self, category_id: int) -> int: ...

    def get_category_entry_counts(self) -> dict[int, int]: ...


@runtime_checkable
class VaultDataConnection(Protocol):
    """业务层事务 / 连接 / 元数据所需的基础设施切片。

    Business 层经此协议访问事务与元数据，不经由 ``set_write_guard`` /
    ``set_entry_integrity_handlers`` 等装配期 setter（仅 VaultManager 装配根使用）。
    与 ``ConnectionProvider``（Repository 消费）平行，二者成员有重叠但消费方不同。
    """

    @property
    def in_transaction(self) -> bool: ...

    def transaction(self) -> AbstractContextManager[None]: ...

    def get_meta(self, key: str) -> str | None: ...

    def get_meta_batch(self, keys: list[str]) -> dict[str, str | None]: ...

    def set_meta(self, key: str, value: str) -> None: ...

    def secure_checkpoint(self) -> None: ...


@runtime_checkable
class VaultDataStore(EntryStore, CategoryStore, VaultDataConnection, Protocol):
    """Business 层访问数据库的统一协议：EntryStore + CategoryStore + VaultDataConnection。

    Business manager 经 ``VaultManager.db`` 拿到此协议视图，收窄暴露面（不含装配期
    setter，仅 VaultManager 内部经 ``self._db`` 使用），便于测试替身。
    """


class ReEncryptedEntry(NamedTuple):
    """重加密后条目的批量更新 DTO（数据库行结构）。

    字段顺序与 ``EntryRepository._RE_ENCRYPT_BATCH_UPDATE_SQL`` 一一对应，供改密
    重加密 executemany 位置绑定。``ReEncryptionService`` 构造、``EntryRepository``
    消费，故定义于数据层避免反向依赖。
    """
    crypto_id: str
    title_enc: str
    username_enc: str
    password_enc: str
    url_enc: str
    category_id: int | None
    tags_enc: str
    notes_enc: str
    custom_fields_enc: str
    is_favorite: int  # 0 or 1
    password_strength: int
    entry_type: str
    totp_secret_enc: str
    updated_at: str
    password_changed_at: str
    metadata_mac: str
    id: int


class ReEncryptedHistory(NamedTuple):
    """重加密后密码历史的批量更新 DTO（密文, id）。"""
    ciphertext: str
    id: int
