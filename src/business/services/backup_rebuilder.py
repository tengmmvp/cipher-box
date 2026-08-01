"""备份恢复重建：在事务内把可移植载荷重新加密写回数据库。

纯变换：全入参注入（``db`` / ``backup`` / ``key`` / 映射），不依赖 manager 状态。
调用方（``BackupRestoreManager._restore_data``）负责事务、epoch 守卫与
key_epoch/snapshot_key 轮换编排；本模块仅做载荷→加密行的逐表重建。
"""

from collections.abc import Callable
from typing import TYPE_CHECKING, Any, cast

from ...models import Category, RawEntry
from ...utils.format import utc_now_iso
from .backup_payload import PortableBackup
from .crypto_utils import build_encrypted_entry_fields, encrypt_field

if TYPE_CHECKING:
    from ...database.types import VaultDataStore


def restore_categories(
    add_categories_batch: Callable[[list[Category]], list[int]],
    backup: PortableBackup,
) -> dict[int, int]:
    """重建分类，返回旧 ID 到新 ID 的映射（PF-003：批量两阶段加密，消除 O(N²) 查重）。

    ARCH-002：经 ``add_categories_batch`` 回调注入写能力，本纯变换模块不再依赖
    EntryManager 类型——恢复前已 clear_vault_data 清空分类表，回调内批量写入无需查重。
    """
    # 收集非空名分类及其旧 id（同步保序），经回调在单事务内批量两阶段加密写入。
    categories: list[Category] = []
    item_ids: list[int] = []
    for item in backup["categories"]:
        # PortableCategory(TypedDict)经 cast 桥接到 dict 参数：pyright 不允许
        # TypedDict 隐式赋给 dict，validator 已保证键集，cast 安全。
        category = Category.from_dict(cast(dict[str, Any], item))
        if not category.name:
            continue
        categories.append(category)
        # item['id'] 由 validator 校验为 int（非 None），直接索引。
        item_ids.append(item["id"])
    new_ids = add_categories_batch(categories)
    # categories 与 item_ids 同步收集、长度一致，strict=True 守护不变量。
    return dict(zip(item_ids, new_ids, strict=True))


def restore_entries(
    db: "VaultDataStore",
    backup: PortableBackup,
    key: bytes,
    category_map: dict[int, int],
) -> tuple[dict[int, int], dict[int, str]]:
    """重建条目，加密敏感字段，返回 (entry_map, crypto_id_map)。

    全部条目先在内存构建再经 ``add_entries_batch`` 一次性 executemany 写入，
    避免逐条 INSERT+commit 的 N 次 fsync 拖长 vault_write_lock 持锁（UI 冻结窗口）。
    item 经 validator 校验，直接索引字段，无 .get(default) 死分支。
    """
    items = backup["entries"]
    entries: list[RawEntry] = []
    for item in items:
        # PortableEntry(TypedDict)经 cast 桥接到 dict 参数（同上，TypedDict 不兼容 dict）。
        enc = build_encrypted_entry_fields(cast(dict[str, Any], item), key, item["crypto_id"])
        entries.append(
            RawEntry(
                crypto_id=item["crypto_id"],
                title=enc["title"],
                username=enc["username"],
                password=enc["password"],
                url=enc["url"],
                category_id=(
                    category_map.get(item["category_id"])
                    if item["category_id"] is not None
                    else None
                ),
                tags=enc["tags"],
                notes=enc["notes"],
                custom_fields=enc["custom_fields"],
                is_favorite=item["is_favorite"],
                is_deleted=item["is_deleted"],
                password_strength=item["password_strength"],
                entry_type=item["entry_type"],
                totp_secret=enc["totp_secret"],
                created_at=item["created_at"],
                updated_at=item["updated_at"],
                deleted_at=item["deleted_at"],
                password_changed_at=(
                    item["password_changed_at"]
                    or item["updated_at"]
                    or item["created_at"]
                    or utc_now_iso()
                ),
            )
        )
    crypto_id_to_new_id = db.add_entries_batch(entries, preserve_metadata=True)
    entry_map: dict[int, int] = {}
    crypto_id_map: dict[int, str] = {}  # 旧 entry_id 到 crypto_id 的映射
    for item, entry in zip(items, entries, strict=True):
        # item['id'] 经 validate_entries 保证为正整数，直接索引建立映射。
        entry_map[item["id"]] = crypto_id_to_new_id[entry.crypto_id]
        crypto_id_map[item["id"]] = entry.crypto_id
    return entry_map, crypto_id_map


def restore_history(
    db: "VaultDataStore",
    backup: PortableBackup,
    key: bytes,
    entry_map: dict[int, int],
    crypto_id_map: dict[int, str],
) -> None:
    """重建密码历史，按 entry_id 分组批量写入并统一截断。"""
    history_by_entry: dict[int, list[tuple[str, str]]] = {}
    for item in backup["password_history"]:
        new_entry_id = entry_map.get(item["entry_id"])
        if not new_entry_id:
            continue
        # entry_map 命中则 crypto_id_map 必存在（同填充），直接取避免空 crypto_id 致 AAD 不一致。
        crypto_id = crypto_id_map[item["entry_id"]]
        ciphertext = encrypt_field(item["password"], key, crypto_id, "password")
        if ciphertext:
            history_by_entry.setdefault(new_entry_id, []).append((ciphertext, item["changed_at"]))
    for entry_id, items in history_by_entry.items():
        db.add_password_history_batch(entry_id, items)
