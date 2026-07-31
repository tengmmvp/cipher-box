"""备份恢复重建：在事务内把可移植载荷重新加密写回数据库。

从 :class:`..managers.backup_restore.BackupRestoreManager` 下沉的纯变换逻辑：原
``_restore_entries`` / ``_restore_history`` staticmethod 与 ``_restore_categories``
迁移为模块级函数，全入参注入（``db`` / ``backup`` / ``key`` / 映射），不依赖
manager 实例状态，便于独立测试与未来恢复流程复用。

调用方（``BackupRestoreManager._restore_data``）负责事务、epoch 守卫与
key_epoch/snapshot_key 轮换编排；本模块仅做载荷→加密行的逐表重建。
"""

from typing import TYPE_CHECKING, Any, cast

from ...models import Category, RawEntry
from ...utils.format import utc_now_iso
from .backup_payload import PortableBackup
from .crypto_utils import build_encrypted_entry_fields, encrypt_field

if TYPE_CHECKING:
    from ...database.types import VaultDataStore
    from ..managers.entry_manager import EntryManager


def restore_categories(
    entry_manager: 'EntryManager', backup: PortableBackup,
) -> dict[int, int]:
    """重建分类，返回旧 ID 到新 ID 的映射。"""
    category_map: dict[int, int] = {}
    for item in backup['categories']:
        # PortableCategory(TypedDict)经 cast 桥接到 from_dict 的 dict 参数：
        # pyright 严格模式不允许 TypedDict 隐式赋给 dict（结构化类型限制），
        # validator 已保证键集，cast 安全。
        category = Category.from_dict(cast(dict[str, Any], item))
        if not category.name:
            continue
        new_id = entry_manager.categories.add_category(category, notify=False)
        # item['id'] 由 validator 校验为 int（非 None），直接索引建立映射。
        category_map[item['id']] = new_id
    return category_map


def restore_entries(
    db: 'VaultDataStore',
    backup: PortableBackup,
    key: bytes,
    category_map: dict[int, int],
) -> tuple[dict[int, int], dict[int, str]]:
    """重建条目，加密敏感字段，返回 (entry_map, crypto_id_map)。

    全部条目先在内存构建为 RawEntry，再经 ``add_entries_batch`` 一次性
    executemany 写入，避免逐条 INSERT+commit 的 N 次 fsync 拖长恢复期间
    ``vault_write_lock`` 的持锁时间（UI 冻结窗口）。

    item 经 validator 校验类型/长度，直接索引 PortableEntry 字段，消除原先
    .get(default) 的死分支（键集由 require_keys 精确匹配保证存在）。
    """
    items = backup['entries']
    entries: list[RawEntry] = []
    for item in items:
        # PortableEntry(TypedDict)经 cast 桥接到 build_encrypted_entry_fields 的
        # dict 参数（同 from_dict，TypedDict 不隐式兼容 dict）。
        enc = build_encrypted_entry_fields(cast(dict[str, Any], item), key, item['crypto_id'])
        entries.append(RawEntry(
            crypto_id=item['crypto_id'],
            title=enc['title'],
            username=enc['username'],
            password=enc['password'],
            url=enc['url'],
            category_id=(
                category_map.get(item['category_id'])
                if item['category_id'] is not None
                else None
            ),
            tags=enc['tags'],
            notes=enc['notes'],
            custom_fields=enc['custom_fields'],
            is_favorite=item['is_favorite'],
            is_deleted=item['is_deleted'],
            password_strength=item['password_strength'],
            entry_type=item['entry_type'],
            totp_secret=enc['totp_secret'],
            created_at=item['created_at'],
            updated_at=item['updated_at'],
            deleted_at=item['deleted_at'],
            password_changed_at=(
                item['password_changed_at']
                or item['updated_at']
                or item['created_at']
                or utc_now_iso()
            ),
        ))
    crypto_id_to_new_id = db.add_entries_batch(entries, preserve_metadata=True)
    entry_map: dict[int, int] = {}
    crypto_id_map: dict[int, str] = {}  # 旧 entry_id 到 crypto_id 的映射
    for item, entry in zip(items, entries, strict=True):
        # item['id'] 由 validate_entries 保证为正整数（require_keys + is_real_int），
        # 直接索引建立映射，与 PortableEntry 文档「无 .get 死分支」契约一致。
        entry_map[item['id']] = crypto_id_to_new_id[entry.crypto_id]
        crypto_id_map[item['id']] = entry.crypto_id
    return entry_map, crypto_id_map


def restore_history(
    db: 'VaultDataStore',
    backup: PortableBackup,
    key: bytes,
    entry_map: dict[int, int],
    crypto_id_map: dict[int, str],
) -> None:
    """重建密码历史，按 entry_id 分组批量写入并统一截断。"""
    history_by_entry: dict[int, list[tuple[str, str]]] = {}
    for item in backup['password_history']:
        new_entry_id = entry_map.get(item['entry_id'])
        if not new_entry_id:
            continue
        # entry_map 命中则 crypto_id_map 必同步存在（restore_entries 同填充），
        # 直接取而非 get 默认 ''，避免空 crypto_id 产生 AAD 不一致的密文。
        crypto_id = crypto_id_map[item['entry_id']]
        ciphertext = encrypt_field(item['password'], key, crypto_id, 'password')
        if ciphertext:
            history_by_entry.setdefault(new_entry_id, []).append(
                (ciphertext, item['changed_at'])
            )
    for entry_id, items in history_by_entry.items():
        db.add_password_history_batch(entry_id, items)
