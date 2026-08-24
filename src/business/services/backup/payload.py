"""备份可移植载荷的类型定义、预采集产物与开销常量。

纯数据契约层，零 manager/db 依赖：

- ``Portable*`` TypedDict 描述备份载荷（与 :mod:`.validator` 的
  ``REQUIRED_*_KEYS`` 经启动期断言一致，漏改校验键集时模块加载即失败）；
- :class:`PreparedBackup` 为「锁内 prepare → 锁外 finalize」拆分的中间产物；
- 开销常量为 payload 字节估算的单一事实源。
"""

import json
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
            f"{_name} 字段集与 validator 校验键集不一致：{sorted(_actual)} != {sorted(_expected)}"
        )


# payload 字节估算的固定开销常量（供 collector 复用，避免魔术数漂移）。
#
# PERF-068：常量按「实际 JSON 序列化的模板字节数」校准（json.dumps 默认分隔符
# ``", "``/``": "``、ensure_ascii=False），替代旧版拍脑袋的粗放值（entry 512 vs
# 实测空模板 334）——旧估算对 50k 空库虚高 1.65 倍，使「50k 全空库 ≈ 43MB」在
# 32MB 上限下数学上不可能备份通过。各常量已含列表语境的分隔符分摊（每项 +2），
# 典型画像误差由 test_backup_collector 的校准测试守护（≤10%）。
#
# 条目模板：PortableEntry 全字段取空值/最小值（id=0、空串、空列表、False、None），
# 序列化 334 字节 + 2 分隔符。name/value 等变长内容由 collector 按明文字节数累加。
ENTRY_OVERHEAD_BYTES = (
    len(
        json.dumps(
            {
                "id": 0,
                "crypto_id": "",
                "title": "",
                "username": "",
                "password": "",
                "url": "",
                "category_id": None,
                "tags": "",
                "notes": "",
                "custom_fields": [],
                "is_favorite": False,
                "is_deleted": False,
                "password_strength": 0,
                "entry_type": "",
                "totp_secret": "",
                "created_at": "",
                "updated_at": "",
                "deleted_at": "",
                "password_changed_at": "",
            },
            ensure_ascii=False,
        ).encode("utf-8")
    )
    + 2
)  # entries 数组内 ", " 分隔符分摊

# 单个自定义字段项的模板开销（field_type 以最常见 "text" 计，其余类型差 ≤4 字节）。
CUSTOM_FIELD_OVERHEAD_BYTES = (
    len(
        json.dumps({"name": "", "value": "", "field_type": "text"}, ensure_ascii=False).encode(
            "utf-8"
        )
    )
    + 2
)  # custom_fields 数组内 ", " 分隔符分摊

# 分类模板：icon/color/created_at 取典型内容（名称字节数由 collector 累加），
# 分类数量 ≤ MAX_BACKUP_CATEGORIES，粗粒度即可。
CATEGORY_OVERHEAD_BYTES = len(
    json.dumps(
        {
            "id": 0,
            "name": "",
            "icon_char": "[DIR]",
            "color": "#666666",
            "sort_order": 0,
            "created_at": "2024-01-01T00:00:00",
        },
        ensure_ascii=False,
    ).encode("utf-8")
)

# 密码历史模板：entry_id=0 / password 空 / changed_at 空（变长部分由 collector 累加）。
HISTORY_OVERHEAD_BYTES = (
    len(
        json.dumps({"entry_id": 0, "password": "", "changed_at": ""}, ensure_ascii=False).encode(
            "utf-8"
        )
    )
    + 2
)  # password_history 数组内 ", " 分隔符分摊

# 顶层结构（format/version/created_at/categories/entries/password_history 键与括号）。
PAYLOAD_TOP_OVERHEAD_BYTES = len(
    json.dumps(
        {
            "format": "CipherBoxBackup",
            "version": 1,
            "created_at": "2026-08-24T00:00:00",
            "categories": [],
            "entries": [],
            "password_history": [],
        },
        ensure_ascii=False,
    ).encode("utf-8")
)


class PreparedBackup(NamedTuple):
    """``prepare_backup_locked`` 的输出，承载锁外 ``finalize_backup`` 的全部输入。

    备份锁外解密决策（导入路径 MAINT-004「CPU 密集加密移出锁」的对称决策）：
    prepare 在 vault_write_lock 内完成快速 DB 读与 snapshot_key/
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
