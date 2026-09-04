"""数据库层类型定义 — 接口协议切片、查询 DTO、校验模式与重加密 DTO。

集中声明三层间解耦用的 Protocol（``ConnectionProvider`` 供 Repository 消费
DatabaseManager；``EntryStore`` / ``CategoryStore`` / ``VaultDataConnection`` /
``VaultDataStore`` 收窄 Business 层暴露面），以及 ``EntryQuery``（查询参数）、
``VerifyMode``（完整性校验模式）、``ReEncryptedEntry`` / ``ReEncryptedHistory``
（改密重加密批量更新 DTO）。置于数据层避免 Business→Data 反向依赖。
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING, NamedTuple, Protocol, runtime_checkable

if TYPE_CHECKING:
    from ..models import Category, PasswordHistory, RawEntry


# 密码历史分页默认批量（QL-007 单一事实源）：控制改密重加密内存峰值。
# password_history_repository（MAINT-071 拆分自 entry_repository）/ db_manager /
# re_encryption 的 get_all_password_history_batch 默认 limit 均引用此常量，
# 消除魔法数 200 跨文件漂移。
DEFAULT_HISTORY_BATCH_LIMIT: int = 200


class VerifyMode(Enum):
    """读取条目时的元数据完整性（HMAC）校验模式。

    - ``STRICT``：校验失败抛 :class:`VaultIntegrityError`，单条详情路径用。
    - ``LENIENT``：失败仅置 ``integrity_error`` 标志，列表/搜索/标签等只读路径默认。
    - ``SKIP``：完全跳过，签名计算前的原始读取用（不能先验签再算签名）。
    """

    STRICT = auto()  # 校验失败时抛出异常
    LENIENT = auto()  # 设置 integrity_error 标志但不抛出异常
    SKIP = auto()  # 完全跳过校验


@dataclass(frozen=True)
class EntryQuery:
    """entries 表查询参数（过滤 + 排序 + limit + verify），get_entries 的单一入口。

    构造时校验 ``deleted_only`` / ``include_deleted`` 互斥——前者仅回收站、后者含
    全部（含回收站），同时为 True 语义矛盾，须构造即拒绝。``order_by`` 同样构造即
    校验白名单（PERF-073）：排序子句经字段名拼接 SQL，白名单外的值在构造点拒绝，
    与 repository 侧的硬编码映射构成双重防注入（值来自调用方内部常量，非用户输入，
    防线是纵深而非唯一屏障）。
    """

    deleted_only: bool = False
    include_deleted: bool = False
    category_id: int | None = None
    favorite_only: bool = False
    limit: int | None = None
    after_id: int | None = None
    # 明文排序字段（PERF-073）：None 走默认复合序（is_favorite DESC, updated_at
    # DESC）；指定白名单字段时 ORDER BY 仅按该列（供列表视图按用户所选排序下推
    # LIMIT 到 SQL，替代原 sort_by_updated 布尔的单一表达——50k 库标题序全量拉取
    # 实测 1756ms vs 字段序下推 ~50ms，8 种排序中 6 种可字段化，title 为密文
    # 无法 SQL 排序属加密架构固有限制）。类型层保留 str（调用方 fetch 层持动态
    # 排序字段名，Literal 化会在该处产生类型错误），值集约束由 __post_init__ 的
    # ORDER_BY_FIELDS 白名单运行期把关；新增可排序字段须同时更新 ORDER_BY_FIELDS
    # 与 entry_repository._ORDER_BY_COLUMN_SQL（后者的键集断言守护联动）。
    order_by: str | None = None
    order_desc: bool = True
    # 并列裁决开关（PERF-090）：True 时排序列后追加并列裁决键（is_favorite DESC,
    # updated_at DESC），使带 LIMIT 的 SQL 下推序与「全量收集→内存稳定排序→截断」
    # 在排序键并列的截断边界上等价（PERF-087，搜索的排序下推分支专用）。首键为
    # updated_at 时第三裁决键与首键同列、恒 no-op，SQL 拼接处省略（见
    # entry_repository），语义不变。
    # False（默认）为纯单列序——无内存对等路径的 SQL 直连路径（主列表字段序/
    # 近期更新视图）不为裁决键付 filesort 成本：首键为 updated_at 的序一旦追加
    # 裁决键，ORDER BY 不再是 idx_entries_active_updated 的索引前缀，计划退化为
    # SEARCH + USE TEMP B-TREE FOR ORDER BY（50k 库 recent LIMIT 100 实测
    # 0.6ms→81.2ms）。裁决键对带 LIMIT 的 SQL 直连路径同样「无害但也无益」：
    # 该路径没有与之对齐的内存排序路径，并列序选哪种都无等价性诉求。
    tie_break_order: bool = False
    verify: VerifyMode = VerifyMode.LENIENT

    def __post_init__(self) -> None:
        if self.deleted_only and self.include_deleted:
            raise ValueError(
                "EntryQuery: deleted_only 与 include_deleted 互斥——"
                "deleted_only=True 仅返回回收站，include_deleted=True 含全部（含回收站）"
            )
        if self.order_by is not None and self.order_by not in ORDER_BY_FIELDS:
            raise ValueError(
                f"EntryQuery: order_by 仅支持白名单字段 {sorted(ORDER_BY_FIELDS)}，"
                f"收到 {self.order_by!r}"
            )


# 可 SQL 排序的明文列白名单（PERF-073）：repository 的 ORDER BY 子句经硬编码映射
# 消费此集合，字段名不经任何字符串拼接进 SQL。title/username 等展示字段为密文列
# （title_enc），无法 SQL 排序，不在此集合。
ORDER_BY_FIELDS: frozenset[str] = frozenset({"updated_at", "created_at", "password_strength"})


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

    # schema_validated 可读写：Protocol 须以 property + setter 双声明。Pyright 严格
    # 模式下，协议用普通可读写数据属性（``schema_validated: bool``）声明时，不匹配
    # 实现方 DatabaseManager 的 property + setter 实现。
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
    def sign_entry(self, entry: RawEntry | Mapping[str, object]) -> str: ...
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

    # 轻量存在性探测（PERF-099）：仅需「存在与否」的检查替代 get_entry 宽行拉取与验签。
    def entry_exists(self, entry_id: int) -> bool: ...

    def get_entry_count(self, include_deleted: bool = False) -> int: ...

    def get_entries_by_ids(self, entry_ids: list[int]) -> list[RawEntry]: ...

    # 搜索路径窄投影（PERF-074）：供 get_entry_summaries 的 search 分支替代宽行
    # 全量物化——50k 库实测宽行拉取+24 字段 RawEntry 构造 656ms 中，同条件 6 列
    # 窄投影仅 102ms，命中行按 id 回查完整行（LENIENT 验签）。
    def get_entries_search_projection(self, query: EntryQuery) -> list[SearchRow]: ...

    def get_entry_by_crypto_id(
        self,
        crypto_id: str,
        *,
        verify: VerifyMode = VerifyMode.STRICT,
    ) -> RawEntry | None: ...

    def get_entries_for_analysis(self) -> list[RawEntry]: ...

    def get_entries_tags_projection(self) -> list[tuple[str, str]]: ...

    def add_entry(self, entry: RawEntry, preserve_metadata: bool = False) -> int: ...

    def add_entries_batch(
        self,
        entries: list[RawEntry],
        *,
        preserve_metadata: bool = False,
    ) -> dict[str, int]: ...

    # preserve_updated_at 参数已退役（ARCH-021）：唯一 True 调用方是测试，恢复路径
    # 走 update_overwrite_batch；该参数在三层协议/委托/实现中均为死代码面。
    def update_entry(self, entry: RawEntry) -> None: ...

    def update_overwrite_batch(self, entries: list[RawEntry]) -> None: ...

    def update_entries_batch(self, rows: list[ReEncryptedEntry]) -> None: ...

    def soft_delete_entry(self, entry_id: int) -> bool: ...

    def restore_entry(self, entry_id: int) -> bool: ...

    def permanent_delete_entry(self, entry_id: int) -> None: ...

    def empty_trash(self) -> None: ...

    def clear_vault_data(self) -> None: ...

    def add_password_history(
        self,
        entry_id: int,
        old_password_enc: str,
        changed_at: str = "",
    ) -> None: ...

    def add_password_history_batch(
        self,
        entry_id: int,
        items: list[tuple[str, str]],
    ) -> None: ...

    def get_password_history(self, entry_id: int) -> list[PasswordHistory]: ...

    def get_all_password_history(self) -> list[PasswordHistory]: ...

    def get_all_password_history_batch(
        self,
        after_id: int = 0,
        limit: int = DEFAULT_HISTORY_BATCH_LIMIT,
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

    # 改密重加密专用的批量分类写入（ARCH-031）：补入协议后 re_encryption /
    # crypto_utils 的分类重加密路径无需自造局部协议或绑定具体 DatabaseManager。
    def update_categories_batch(self, categories: list[Category]) -> None: ...

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

    # require_top_level（ARCH-058 演进）：True 且已处事务内时抛 TransactionError
    # ——供 epoch_guarded_transaction 等「本层必为顶层」的调用方做入口断言。
    def transaction(self, *, require_top_level: bool = False) -> AbstractContextManager[None]: ...

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


class SearchRow(NamedTuple):
    """搜索/内存排序路径的窄投影行（PERF-074/078）：匹配所需密文字段 + 排序键 + 定位键。

    搜索只需解密 title/username/url/tags 四摘要字段做小写匹配（宽行 24 字段构造
    是温态搜索的主导成本，50k 库实测占 656ms 拉取中的大头，同条件窄投影仅
    102ms）；命中行按 ``id`` 经 :meth:`EntryStore.get_entries_by_ids`（LENIENT
    验签）回查完整行构建摘要。字段名与 :class:`RawEntry` 的密文属性同名
    （title/username/url/tags 存密文），使 EntryCacheManager 的摘要解密入口可经
    结构协议同时接受 RawEntry 与本类型（见 entry_cache.SearchRowSource）。

    ``password_strength``/``created_at``/``updated_at`` 三个明文列（PERF-078）：
    内存排序路径的排序键——title 序的键在解密后的 meta.title_lower，其余排序
    键来自行的明文列，使「全量窄投影 → 内存排序 → 仅前 limit 回查宽行」的
    截断与 SQL ``ORDER BY ... LIMIT`` 语义同构（截断集合=排序序前 N）。
    """

    id: int | None
    crypto_id: str
    title: str  # 密文（title_enc 列）
    username: str  # 密文
    url: str  # 密文
    tags: str  # 密文
    password_strength: int
    created_at: str
    updated_at: str


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
    """重加密后密码历史的批量更新 DTO（密文, id）。

    字段顺序与 ``PasswordHistoryRepository.update_password_history_batch`` 的
    ``UPDATE ... WHERE id=?`` SQL 位置绑定一致，供 ``executemany``。
    ``ReEncryptionService`` 构造、``PasswordHistoryRepository``（MAINT-071 拆分自
    entry_repository）消费，故定义于数据层避免反向依赖。
    """

    ciphertext: str
    id: int
