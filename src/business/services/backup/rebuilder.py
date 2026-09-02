"""备份恢复重建：在事务内把可移植载荷重新加密写回数据库。

纯变换：全入参注入（``db`` / ``backup`` / ``key`` / 映射），不依赖 manager 状态。
调用方（``BackupRestoreManager._restore_data``）负责事务、epoch 守卫与
key_epoch/snapshot_key 轮换编排；本模块仅做载荷→加密行的逐表重建。
"""

from collections.abc import Callable
from typing import TYPE_CHECKING, Any, cast

from ....models import Category, RawEntry
from ....utils.format import utc_now_iso
from ..crypto_utils import build_encrypted_entry_fields, encrypt_field
from ..entry_batch_writer import should_report_progress
from .payload import PortableBackup

if TYPE_CHECKING:
    from ....database.types import VaultDataStore


def restore_categories(
    add_categories_batch: Callable[[list[Category]], list[int]],
    backup: PortableBackup,
) -> dict[int, int]:
    """重建分类，返回旧 ID 到新 ID 的映射（PERF-004：批量两阶段加密，消除 O(N²) 查重）。

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
    progress: Callable[[int, int], None] | None = None,
) -> tuple[dict[int, int], dict[int, str]]:
    """重建条目，加密敏感字段，返回 (entry_map, crypto_id_map)。

    全部条目先在内存构建再经 ``add_entries_batch`` 一次性 executemany 写入，
    避免逐条 INSERT+commit 的 N 次 fsync 拖长 vault_write_lock 持锁（UI 冻结窗口）。
    item 经 validator 校验，直接索引字段，无 .get(default) 死分支。
    ``progress``（PERF-083）按已加密构建条目数每 ``PROGRESS_REPORT_EVERY`` 条节流
    上报原始 ``(done, total)`` 计数、终值恒上报，加权映射由调用方完成。
    """
    items = backup["entries"]
    total = len(items)
    entries: list[RawEntry] = []
    for done, item in enumerate(items, start=1):
        # PortableEntry(TypedDict)经 cast 桥接到 dict 参数（同上，TypedDict 不兼容 dict）。
        # 加密字段整体经 **encrypted 展开（消费 crypto_utils 的 QL-046 循环化入口）：
        # SENSITIVE_ENCRYPTED_FIELDS 新增字段时自动随展写入 RawEntry，消除本处手工
        # 枚举的第三份键集（漏映射会致恢复往返静默丢字段）。键来自运行期元组，
        # 静态检查器无法验证字段名↔构造参数匹配，value 标注 Any 使解包通过，
        # 键集完备性由 test_backup_rebuilder 的守护测试兜底。
        encrypted: dict[str, Any] = build_encrypted_entry_fields(
            cast(dict[str, Any], item), key, item["crypto_id"]
        )
        entries.append(
            RawEntry(
                crypto_id=item["crypto_id"],
                category_id=(
                    category_map.get(item["category_id"])
                    if item["category_id"] is not None
                    else None
                ),
                is_favorite=item["is_favorite"],
                is_deleted=item["is_deleted"],
                password_strength=item["password_strength"],
                entry_type=item["entry_type"],
                created_at=item["created_at"],
                updated_at=item["updated_at"],
                deleted_at=item["deleted_at"],
                password_changed_at=(
                    item["password_changed_at"]
                    or item["updated_at"]
                    or item["created_at"]
                    or utc_now_iso()
                ),
                **encrypted,
            )
        )
        if progress is not None and should_report_progress(done, total):
            progress(done, total)
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
    progress: Callable[[int, int], None] | None = None,
) -> None:
    """重建密码历史，按 entry_id 分组批量写入并统一截断。

    ``progress``（PERF-083）按已加密历史条数节流上报原始 ``(done, total)`` 计数
    （总数按载荷内全部历史计，未命中 entry_map 的跳过项亦计入 done 保持单调）。
    """
    history_by_entry: dict[int, list[tuple[str, str]]] = {}
    total = len(backup["password_history"])
    done = 0
    for item in backup["password_history"]:
        done += 1
        new_entry_id = entry_map.get(item["entry_id"])
        if not new_entry_id:
            if progress is not None and should_report_progress(done, total):
                progress(done, total)
            continue
        # entry_map 命中则 crypto_id_map 必存在（同填充），直接取避免空 crypto_id 致 AAD 不一致。
        crypto_id = crypto_id_map[item["entry_id"]]
        ciphertext = encrypt_field(item["password"], key, crypto_id, "password")
        # encrypt_field 经 EncryptionEngine.encrypt 总返回非空密文（空明文亦产 cb2: 前缀），
        # 无需 if 守卫；保留恒真分支会暗示 encrypt_field 可能返回空串的错误心智模型。
        history_by_entry.setdefault(new_entry_id, []).append((ciphertext, item["changed_at"]))
        if progress is not None and should_report_progress(done, total):
            progress(done, total)
    for entry_id, items in history_by_entry.items():
        db.add_password_history_batch(entry_id, items)
