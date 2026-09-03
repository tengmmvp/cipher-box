"""backup.rebuilder 模块测试 — 恢复重建的载荷→加密行纯变换。

覆盖 restore_categories / restore_entries / restore_history 的分类映射、空名跳过、
条目加密与 category_map 映射、密码历史按 entry_id 分组批量写入。直接测纯变换
函数（mock db 回调，不经 BackupRestoreManager），补齐 ARCH-002 SRP 拆分后遗留的
单元测试缺口。需要真实密钥的用例经 make_vault_env 工厂建库（teardown 幂等
close 由工厂统一承担）；节流分支经 monkeypatch ``PROGRESS_REPORT_EVERY`` 真实
触达（MAINT-099：should_report_progress 的谓词常量在其定义模块 entry_batch_writer
解析，消费方经函数引用共享同一节流纪律）。
"""

from unittest.mock import MagicMock

from src.business.services.backup.rebuilder import (
    restore_categories,
    restore_entries,
    restore_history,
)


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


def test_restore_entries_encrypts_and_maps(make_vault_env):
    """restore_entries 加密字段批量写入并返回 (entry_map, crypto_id_map)。

    category_id 经 category_map 映射到新 id；旧 category_id 为 None 时保持 None。
    """
    key = make_vault_env().vault.key
    backup = _backup(entries=[_entry(1, "a" * 32, 1), _entry(2, "b" * 32, None)])
    db = MagicMock()
    db.add_entries_batch.return_value = {"a" * 32: 100, "b" * 32: 200}

    entry_map, crypto_id_map = restore_entries(db, backup, key, {1: 5})

    assert entry_map == {1: 100, 2: 200}
    assert crypto_id_map == {1: "a" * 32, 2: "b" * 32}
    written = db.add_entries_batch.call_args[0][0]
    assert written[0].category_id == 5  # 经 category_map 映射
    assert written[1].category_id is None  # None 保持


def test_restore_entries_reports_throttled_progress(make_vault_env, monkeypatch):
    """restore_entries 的加密段按已构建条目计数节流、终值恒上报（PERF-083）。

    monkeypatch 节流间隔为 2 使 3 条载荷真实触达节流分支：done=2 命中
    ``% EVERY == 0`` 中间上报，done=3 走终值恒上报——两条分支均执行（默认
    EVERY=100 时 3 条载荷只能覆盖终值分支）。
    """
    monkeypatch.setattr("src.business.services.entry_batch_writer.PROGRESS_REPORT_EVERY", 2)
    key = make_vault_env().vault.key
    backup = _backup(entries=[_entry(1, "a" * 32), _entry(2, "b" * 32), _entry(3, "c" * 32)])
    db = MagicMock()
    db.add_entries_batch.return_value = {"a" * 32: 100, "b" * 32: 200, "c" * 32: 300}

    calls: list[tuple[int, int]] = []

    def _record(done: int, total: int) -> None:
        calls.append((done, total))

    restore_entries(db, backup, key, {}, encrypt_progress=_record)

    # EVERY=2：done=2 走节流分支上报中间值，done=3 走终值恒上报分支
    assert calls == [(2, 3), (3, 3)]


def test_restore_entries_write_progress_reports_chunked(make_vault_env, monkeypatch):
    """批量写入段按 WRITE_PROGRESS_CHUNK 分块上报（PERF-089）。

    monkeypatch 分块阈值为 1 使 3 条 entries 产生 3 次上报（多批中间进度 + 终值），
    对齐 write_new_entries 的分块模式；不传 write_progress 时保持单次批量路径。
    分块循环收敛至 entry_batch_writer.write_chunks（MAINT-106）后，monkeypatch
    锚点随之迁移到该模块（write_chunks 调用时解析模块属性，锚点仍可达）。
    """
    import src.business.services.entry_batch_writer as batch_writer_module

    monkeypatch.setattr(batch_writer_module, "WRITE_PROGRESS_CHUNK", 1)
    key = make_vault_env().vault.key
    backup = _backup(entries=[_entry(1, "a" * 32), _entry(2, "b" * 32), _entry(3, "c" * 32)])
    db = MagicMock()
    db.add_entries_batch.side_effect = [
        {"a" * 32: 100},
        {"b" * 32: 200},
        {"c" * 32: 300},
    ]

    calls: list[tuple[int, int]] = []

    def _record(done: int, total: int) -> None:
        calls.append((done, total))

    entry_map, _crypto_id_map = restore_entries(db, backup, key, {}, write_progress=_record)

    # 分块阈值 1：3 条 entries 逐条上报，覆盖中间进度与终值
    assert calls == [(1, 3), (2, 3), (3, 3)]
    # 分块写入 3 次，映射合并后与单次写入结果一致
    assert db.add_entries_batch.call_count == 3
    assert entry_map == {1: 100, 2: 200, 3: 300}


def test_restore_entries_without_write_progress_single_batch(make_vault_env):
    """未提供 write_progress 时保持单次批量写入路径（既有调用方零改动）。"""
    key = make_vault_env().vault.key
    backup = _backup(entries=[_entry(1, "a" * 32), _entry(2, "b" * 32)])
    db = MagicMock()
    db.add_entries_batch.return_value = {"a" * 32: 100, "b" * 32: 200}

    restore_entries(db, backup, key, {})

    db.add_entries_batch.assert_called_once()


def test_restore_history_groups_by_entry_and_encrypts(make_vault_env):
    """restore_history 按 entry_id 分组，每组一次 add_password_history_batch 批量写入。"""
    key = make_vault_env().vault.key
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


def test_restore_history_skips_unmapped_entry(make_vault_env):
    """entry_map 未命中的历史项跳过（孤儿历史不写入）。"""
    key = make_vault_env().vault.key
    backup = _backup(
        history=[
            {"entry_id": 999, "password": "orphan", "changed_at": "2024-01-01T00:00:00"},
        ]
    )
    db = MagicMock()

    restore_history(db, backup, key, {1: 10}, {1: "a" * 32})

    # entry 999 不在 entry_map，无批量写入
    db.add_password_history_batch.assert_not_called()


def test_restore_history_reports_throttled_progress_counting_skipped(make_vault_env, monkeypatch):
    """restore_history 的加密段节流上报真实触发，跳过项亦计入 done 保持单调（PERF-083）。

    EVERY=2（monkeypatch 锚点见模块 docstring）：2 条映射 + 1 条孤儿，done=2 走
    节流分支上报中间值、done=3 走终值恒上报——孤儿项计入总数与进度，节流与
    终值两分支均真实执行（默认 EVERY=100 时仅能覆盖终值分支）。
    """
    monkeypatch.setattr("src.business.services.entry_batch_writer.PROGRESS_REPORT_EVERY", 2)
    key = make_vault_env().vault.key
    backup = _backup(
        history=[
            {"entry_id": 1, "password": "old1", "changed_at": "2024-01-01T00:00:00"},
            {"entry_id": 1, "password": "old2", "changed_at": "2024-01-02T00:00:00"},
            {"entry_id": 999, "password": "orphan", "changed_at": "2024-01-03T00:00:00"},
        ]
    )
    db = MagicMock()

    calls: list[tuple[int, int]] = []

    def _record(done: int, total: int) -> None:
        calls.append((done, total))

    restore_history(db, backup, key, {1: 10}, {1: "a" * 32}, encrypt_progress=_record)

    # 孤儿项（entry 999）计入总数与进度：节流中间值 + 终值均上报
    assert calls == [(2, 3), (3, 3)]


def test_restore_history_write_progress_counts_rows(make_vault_env, monkeypatch):
    """历史分组写入段按写入的历史行数累计上报、终值恒上报（PERF-089）。

    计数取行数而非组数——entry 1 含 2 条、entry 2 含 1 条，应上报 (2, 3)、(3, 3)。
    monkeypatch 节流间隔为 2（锚点见模块 docstring）：done=2 走节流分支上报
    中间行数进度，done=3 走终值恒上报——默认 EVERY=100 时 3 行仅终值可触发，
    (2, 3) 中间值无法覆盖。
    """
    monkeypatch.setattr("src.business.services.entry_batch_writer.PROGRESS_REPORT_EVERY", 2)
    key = make_vault_env().vault.key
    backup = _backup(
        history=[
            {"entry_id": 1, "password": "old1", "changed_at": "2024-01-01T00:00:00"},
            {"entry_id": 1, "password": "old2", "changed_at": "2024-01-02T00:00:00"},
            {"entry_id": 2, "password": "old3", "changed_at": "2024-01-03T00:00:00"},
        ]
    )
    db = MagicMock()

    calls: list[tuple[int, int]] = []

    def _record(done: int, total: int) -> None:
        calls.append((done, total))

    restore_history(
        db,
        backup,
        key,
        {1: 10, 2: 20},
        {1: "a" * 32, 2: "b" * 32},
        write_progress=_record,
    )

    assert calls == [(2, 3), (3, 3)]
    assert db.add_password_history_batch.call_count == 2


def test_restore_entries_covers_all_sensitive_fields(make_vault_env):
    """restore_entries 的 RawEntry 构建覆盖全部 SENSITIVE_ENCRYPTED_FIELDS（守护测试）。

    rebuilder 逐字段手工构造 RawEntry（区别于加密侧 build_encrypted_entry_fields 的
    键集）：若 SENSITIVE_ENCRYPTED_FIELDS 新增字段而本处漏映射，该字段会以空串
    静默落库（恢复往返丢字段）。本测试对单一事实源的每个敏感字段填充可辨识明文，
    经 restore_entries 写出的密文行逐字段解密回读断言——新增字段漏映射时直接失败。
    """
    from src.business.services.crypto_utils import (
        SENSITIVE_ENCRYPTED_FIELDS,
        decrypt_field,
    )

    key = make_vault_env().vault.key
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
