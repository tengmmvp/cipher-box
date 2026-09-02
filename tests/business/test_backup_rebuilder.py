"""backup.rebuilder 模块测试 — 恢复重建的载荷→加密行纯变换。

覆盖 restore_categories / restore_entries / restore_history 的分类映射、空名跳过、
条目加密与 category_map 映射、密码历史按 entry_id 分组批量写入。直接测纯变换
函数（mock db 回调，不经 BackupRestoreManager），补齐 ARCH-002 SRP 拆分后遗留的
单元测试缺口。
"""

from unittest.mock import MagicMock

from src.business.services.backup.rebuilder import (
    restore_categories,
    restore_entries,
    restore_history,
)
from tests.helpers import make_test_config, make_vault


def _category(item_id: int, name: str = "工作") -> dict:
    return {
        "id": item_id,
        "name": name,
        "icon_char": "[DIR]",
        "color": "#666",
        "sort_order": 0,
        "created_at": "2024-01-01T00:00:00",
    }


def _entry(
    item_id: int = 1,
    crypto_id: str = "a" * 32,
    category_id: int | None = 1,
) -> dict:
    return {
        "id": item_id,
        "crypto_id": crypto_id,
        "title": "标题",
        "username": "user",
        "password": "pass",
        "url": "https://x",
        "category_id": category_id,
        "tags": "",
        "notes": "",
        "custom_fields": [],
        "is_favorite": False,
        "is_deleted": False,
        "password_strength": 3,
        "entry_type": "login",
        "totp_secret": "",
        "created_at": "2024-01-01T00:00:00",
        "updated_at": "2024-01-01T00:00:00",
        "deleted_at": "",
        "password_changed_at": "2024-01-01T00:00:00",
    }


def _backup(categories=None, entries=None, history=None) -> dict:
    return {
        "format": "cipherbox-backup",
        "version": 2,
        "created_at": "2024-01-01T00:00:00",
        "categories": categories or [],
        "entries": entries or [],
        "password_history": history or [],
    }


def test_restore_categories_maps_old_to_new_ids():
    """restore_categories 经回调批量写入并返回旧 id→新 id 映射。"""
    backup = _backup(categories=[_category(1), _category(2)])
    add_batch = MagicMock(return_value=[10, 20])

    mapping = restore_categories(add_batch, backup)

    assert mapping == {1: 10, 2: 20}
    add_batch.assert_called_once()


def test_restore_categories_skips_empty_name():
    """空名分类跳过（不写入、不进映射）。"""
    backup = _backup(categories=[_category(1, name="   "), _category(2, name="工作")])
    add_batch = MagicMock(return_value=[99])

    mapping = restore_categories(add_batch, backup)

    assert mapping == {2: 99}
    # 仅 1 个非空分类传入回调
    written = add_batch.call_args[0][0]
    assert len(written) == 1


def test_restore_entries_encrypts_and_maps(tmp_path):
    """restore_entries 加密字段批量写入并返回 (entry_map, crypto_id_map)。

    category_id 经 category_map 映射到新 id；旧 category_id 为 None 时保持 None。
    """
    vault = make_vault(make_test_config(str(tmp_path)))
    vault.initialize("test_password_12345")
    try:
        key = vault.key
        backup = _backup(entries=[_entry(1, "a" * 32, 1), _entry(2, "b" * 32, None)])
        db = MagicMock()
        db.add_entries_batch.return_value = {"a" * 32: 100, "b" * 32: 200}

        entry_map, crypto_id_map = restore_entries(db, backup, key, {1: 5})

        assert entry_map == {1: 100, 2: 200}
        assert crypto_id_map == {1: "a" * 32, 2: "b" * 32}
        written = db.add_entries_batch.call_args[0][0]
        assert written[0].category_id == 5  # 经 category_map 映射
        assert written[1].category_id is None  # None 保持
    finally:
        vault.close()


def test_restore_entries_reports_progress_with_final_value(tmp_path):
    """restore_entries 的 progress 按已构建条目计数节流、终值恒上报（PERF-083）。"""
    vault = make_vault(make_test_config(str(tmp_path)))
    vault.initialize("test_password_12345")
    try:
        key = vault.key
        backup = _backup(entries=[_entry(1, "a" * 32), _entry(2, "b" * 32)])
        db = MagicMock()
        db.add_entries_batch.return_value = {"a" * 32: 100, "b" * 32: 200}

        calls: list[tuple[int, int]] = []

        def _record(done: int, total: int) -> None:
            calls.append((done, total))

        restore_entries(db, backup, key, {}, _record)

        # 2 条 < PROGRESS_REPORT_EVERY(100)，仅终值触发
        assert calls == [(2, 2)]
    finally:
        vault.close()


def test_restore_history_groups_by_entry_and_encrypts(tmp_path):
    """restore_history 按 entry_id 分组，每组一次 add_password_history_batch 批量写入。"""
    vault = make_vault(make_test_config(str(tmp_path)))
    vault.initialize("test_password_12345")
    try:
        key = vault.key
        backup = _backup(
            history=[
                {"entry_id": 1, "password": "old1", "changed_at": "2024-01-01T00:00:00"},
                {"entry_id": 1, "password": "old2", "changed_at": "2024-01-02T00:00:00"},
                {"entry_id": 2, "password": "old3", "changed_at": "2024-01-03T00:00:00"},
            ]
        )
        db = MagicMock()

        restore_history(db, backup, key, {1: 10, 2: 20}, {1: "a" * 32, 2: "b" * 32})

        # entry 1（2 条历史）与 entry 2（1 条历史）各一次批量写入
        assert db.add_password_history_batch.call_count == 2
    finally:
        vault.close()


def test_restore_history_skips_unmapped_entry(tmp_path):
    """entry_map 未命中的历史项跳过（孤儿历史不写入）。"""
    vault = make_vault(make_test_config(str(tmp_path)))
    vault.initialize("test_password_12345")
    try:
        key = vault.key
        backup = _backup(
            history=[
                {"entry_id": 999, "password": "orphan", "changed_at": "2024-01-01T00:00:00"},
            ]
        )
        db = MagicMock()

        restore_history(db, backup, key, {1: 10}, {1: "a" * 32})

        # entry 999 不在 entry_map，无批量写入
        db.add_password_history_batch.assert_not_called()
    finally:
        vault.close()


def test_restore_history_reports_progress_counting_skipped(tmp_path):
    """restore_history 的 progress 终值恒上报，跳过项亦计入 done 保持计数单调（PERF-083）。"""
    vault = make_vault(make_test_config(str(tmp_path)))
    vault.initialize("test_password_12345")
    try:
        key = vault.key
        backup = _backup(
            history=[
                {"entry_id": 1, "password": "old1", "changed_at": "2024-01-01T00:00:00"},
                {"entry_id": 999, "password": "orphan", "changed_at": "2024-01-01T00:00:00"},
            ]
        )
        db = MagicMock()

        calls: list[tuple[int, int]] = []

        def _record(done: int, total: int) -> None:
            calls.append((done, total))

        restore_history(db, backup, key, {1: 10}, {1: "a" * 32}, _record)

        # 孤儿项（entry 999）计入总数与进度，终值 (2, 2) 恒上报
        assert calls == [(2, 2)]
    finally:
        vault.close()


def test_restore_entries_covers_all_sensitive_fields(tmp_path):
    """restore_entries 的 RawEntry 构建覆盖全部 SENSITIVE_ENCRYPTED_FIELDS（守护测试）。

    rebuilder 逐字段手工构造 RawEntry（区别于加密侧 build_encrypted_entry_fields 的
    键集）：若 SENSITIVE_ENCRYPTED_FIELDS 新增字段而本处漏映射，该字段会以空串
    静默落库（恢复往返丢字段）。本测试对单一事实源的每个敏感字段填充可辨识明文，
    经 restore_entries 写出的密文行逐字段解密回读断言——新增字段漏映射时直接失败。
    """
    from src.business.services.backup.rebuilder import restore_entries
    from src.business.services.crypto_utils import (
        SENSITIVE_ENCRYPTED_FIELDS,
        decrypt_field,
    )
    from tests.helpers import make_test_config, make_vault

    vault = make_vault(make_test_config(str(tmp_path)))
    vault.initialize("test_password_12345")
    try:
        key = vault.key
        item = _entry(1, "c" * 32, None)
        # 对每个敏感字段填充可辨识明文（custom_fields 为 JSON 结构）
        expected: dict[str, str] = {}
        for field in SENSITIVE_ENCRYPTED_FIELDS:
            if field == "custom_fields":
                item["custom_fields"] = [{"name": "n1", "value": "v1", "field_type": "text"}]
            else:
                item[field] = f"payload-{field}"
                expected[field] = f"payload-{field}"
        backup = _backup(entries=[item])
        db = MagicMock()
        db.add_entries_batch.return_value = {"c" * 32: 100}

        restore_entries(db, backup, key, {})

        written = db.add_entries_batch.call_args[0][0][0]
        # 字符串型敏感字段：逐字段解密回读与源明文一致（漏映射字段为空串即失败）
        for field, plaintext in expected.items():
            decrypted = decrypt_field(
                getattr(written, field), key, written.crypto_id, field, strict=True
            )
            assert decrypted == plaintext, f"rebuilder 漏加密字段 {field}（守护失败）"
        # custom_fields：密文 JSON 解密回读结构与源一致
        import json as _json

        cf_cipher = written.custom_fields
        assert cf_cipher, "custom_fields 须写入密文"
        cf_json = decrypt_field(cf_cipher, key, written.crypto_id, "custom_fields", strict=True)
        assert _json.loads(cf_json) == item["custom_fields"]
    finally:
        vault.close()
