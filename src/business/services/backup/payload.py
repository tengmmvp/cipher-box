"""备份可移植载荷的类型定义、预采集产物与开销常量。

纯数据契约层，零 manager/db 依赖：

- ``Portable*`` TypedDict 描述备份载荷（与 :mod:`.validator` 的
  ``REQUIRED_*_KEYS`` 经启动期断言一致，漏改校验键集时模块加载即失败）；
- :class:`PreparedBackup` 为「锁内 prepare → 锁外 finalize」拆分的中间产物；
- 开销常量为 payload 字节估算的单一事实源。
"""

from typing import Any, NamedTuple, TypedDict

from ....models import PasswordHistory, RawEntry
from .header_codec import BackupFlag
from .validator import (
    REQUIRED_CATEGORY_KEYS,
    REQUIRED_ENTRY_KEYS,
    REQUIRED_HISTORY_KEYS,
)


class PortableCategory(TypedDict):
    """备份载荷中的分类项（与 Category.to_dict 对称，不含 metadata_mac：恢复时重签）。"""

    id: int
    name: str
    icon_char: str
    color: str
    sort_order: int
    created_at: str


class PortableEntry(TypedDict):
    """备份载荷中的条目项（与 decrypt_entry_to_portable_dict 输出对称）。

    键集与 require_keys 精确匹配，恢复消费端可安全直接索引（无 .get 死分支）。
    """

    id: int
    crypto_id: str
    title: str
    username: str
    password: str
    url: str
    category_id: int | None
    tags: str
    notes: str
    custom_fields: list[dict[str, Any]]
    is_favorite: bool
    is_deleted: bool
    password_strength: int
    entry_type: str
    totp_secret: str
    created_at: str
    updated_at: str
    deleted_at: str
    password_changed_at: str


class PortableHistoryItem(TypedDict):
    """备份载荷中的密码历史项。"""

    entry_id: int
    password: str
    changed_at: str


class PortableBackup(TypedDict):
    """已校验的备份载荷结构（validate_restore_data 通过后 cast 使用）。"""

    format: str
    version: int
    created_at: str
    categories: list[PortableCategory]
    entries: list[PortableEntry]
    password_history: list[PortableHistoryItem]


# 启动期一致性断言：Portable* 字段集须与 REQUIRED_*_KEYS 完全一致，漏改一侧模块
# 加载即失败。用显式 raise 而非 assert（python -O 会剔除 assert）。
_PORTABLE_KEY_ASSERTS = (
    (set(PortableCategory.__annotations__), REQUIRED_CATEGORY_KEYS, "PortableCategory"),
    (set(PortableEntry.__annotations__), REQUIRED_ENTRY_KEYS, "PortableEntry"),
    (set(PortableHistoryItem.__annotations__), REQUIRED_HISTORY_KEYS, "PortableHistoryItem"),
)
for _actual, _expected, _name in _PORTABLE_KEY_ASSERTS:
    if _actual != _expected:
        raise RuntimeError(
            f"{_name} 字段集与 validator 校验键集不一致："
            f"{sorted(_actual)} != {sorted(_expected)}"
        )


# payload 字节估算的固定开销常量（供 collector 复用，避免魔术数漂移）。
CATEGORY_OVERHEAD_BYTES = 128
ENTRY_OVERHEAD_BYTES = 512
HISTORY_OVERHEAD_BYTES = 64


class PreparedBackup(NamedTuple):
    """``prepare_backup_locked`` 的输出，承载锁外 ``finalize_backup`` 的全部输入。

    A4（备份锁外解密）：prepare 在 vault_write_lock 内完成快速 DB 读与 snapshot_key/
    master_key 副本采集；全量解密与 PASSWORD 密钥派生（Argon2id）推迟到锁外 finalize，
    缩短主线程 ``lock()`` 中止备份前的阻塞窗口。

    ``snapshot_key`` 与 ``master_key`` 均为锁内 property 返回的 bytes 副本，锁外
    finalize 持此副本，主线程 ``lock()`` 经 KeyManager.clear 原地清零内部 bytearray
    不影响该独立拷贝。``master_key`` 与 ``raw_entries`` 严格同源（同在持锁阶段采集），
    锁外 finalize 用它解密 raw_entries，不受锁外**改密**（轮换主密钥 + 重加密 DB）
    的竞态影响——raw_entries 旧密文与快照旧主密钥配对解密。
    """

    filepath: str
    salt: bytes
    flags: BackupFlag
    backup_password: str | None
    snapshot_key: bytes | None
    raw_entries: list[RawEntry]
    history_rows: list[PasswordHistory]
    categories: list[dict[str, Any]]
    master_key: bytes
