"""数据库层类型定义。"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Callable
from contextlib import AbstractContextManager
from enum import Enum, auto
from typing import TYPE_CHECKING, NamedTuple, Protocol, runtime_checkable

if TYPE_CHECKING:
    from ..models import RawEntry


class VerifyMode(Enum):
    """条目完整性校验模式。"""
    STRICT = auto()    # 校验失败时抛出异常
    LENIENT = auto()   # 设置 integrity_error 标志但不抛出异常
    SKIP = auto()      # 完全跳过校验


@runtime_checkable
class ConnectionProvider(Protocol):
    """Repository 所需的 DatabaseManager 接口协议（结构化类型）。

    EntryRepository / CategoryRepository / SchemaManager 通过 ``conn_provider``
    访问 DatabaseManager 的连接、锁与编排方法。以 Protocol 显式声明所需成员，
    使 ``conn_provider`` 参数有明确类型（替代原先无注解的 Any），便于静态检查
    与测试替身。DatabaseManager 满足此协议；仿 ``ReEncryptionService.ReEncryptionDB``。
    """

    @property
    def connection(self) -> sqlite3.Connection: ...

    @property
    def db_lock(self) -> threading.RLock: ...

    @property
    def in_transaction(self) -> bool: ...

    # schema_validated 可读写：DatabaseManager 提供 property + setter，SchemaManager
    # 在校验后赋值。Protocol 以 property + setter 声明精确匹配（Pyright 下可读写
    # 数据属性不接受 property+setter 实现）。
    @property
    def schema_validated(self) -> bool: ...

    @schema_validated.setter
    def schema_validated(self, value: bool) -> None: ...

    @property
    def entry_verifier(self) -> Callable[[RawEntry], None] | None: ...

    def auto_commit(self) -> None: ...
    def guard_write(self) -> None: ...
    def sign_entry(self, entry: RawEntry) -> str: ...
    def assert_encrypted(self, value: str, field_name: str) -> None: ...
    def secure_checkpoint(self) -> None: ...
    def transaction(self) -> AbstractContextManager[None]: ...


class ReEncryptedEntry(NamedTuple):
    """重加密后条目的批量更新 DTO（数据库行结构）。

    归属数据层：字段顺序与 ``EntryRepository._RE_ENCRYPT_BATCH_UPDATE_SQL``
    一一对应，供改密重加密批量 executemany 写入。业务层 ``ReEncryptionService``
    构造、``EntryRepository`` 消费，故定义在数据层类型模块，避免业务层 DTO 被
    数据层反向依赖。
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
