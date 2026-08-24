"""backup.collector 模块测试 — 备份载荷采集的解密、大小校验与取消。

覆盖 collect_portable_data / collect_portable_entries 的解密正确性、payload 上限
校验、cancel_check 中止路径，以及 payload 开销常量。直接测纯函数（不经
BackupRestoreManager 编排），补齐 MAINT-004 / ARCH-002 SRP 拆分后遗留的单元测试缺口。
"""

import json

import pytest

from src.business.services.backup import header_codec
from src.business.services.backup.collector import (
    check_payload_limit,
    collect_portable_data,
    collect_portable_entries,
    estimate_entry_payload_bytes,
)
from src.business.services.backup.payload import (
    CATEGORY_OVERHEAD_BYTES,
    ENTRY_OVERHEAD_BYTES,
    HISTORY_OVERHEAD_BYTES,
    PAYLOAD_TOP_OVERHEAD_BYTES,
)
from src.database.types import EntryQuery, VerifyMode
from src.exceptions import PayloadTooLargeError
from src.models import Entry
from tests.helpers import make_entry_manager, make_test_config, make_vault


def test_check_payload_limit_under_limit_no_raise():
    """未超限（含等于上限）不抛。"""
    check_payload_limit(0)
    check_payload_limit(header_codec.MAX_BACKUP_PAYLOAD_SIZE)


def test_check_payload_limit_over_limit_raises():
    """超限抛 PayloadTooLargeError。"""
    with pytest.raises(PayloadTooLargeError):
        check_payload_limit(header_codec.MAX_BACKUP_PAYLOAD_SIZE + 1)


def test_collect_portable_entries_decrypts_fields(tmp_path):
    """采集正确解密条目全部字段为 portable dict，返回 (entries, count, estimated_size)。"""
    vault = make_vault(make_test_config(str(tmp_path)))
    vault.initialize("test_password_12345")
    try:
        entry_mgr = make_entry_manager(vault)
        entry_mgr.add_entry(Entry(title="标题", username="user1", password="pass123"))
        raw_entries = vault.db.get_entries(EntryQuery(verify=VerifyMode.SKIP))
        key = vault.key

        entries, count, _estimated = collect_portable_entries(key, None, 0, raw_entries)

        assert count == 1
        assert len(entries) == 1
        item = entries[0]
        assert item["title"] == "标题"
        assert item["username"] == "user1"
        assert item["password"] == "pass123"
    finally:
        vault.close()


def test_collect_portable_data_cancel_returns_none(tmp_path):
    """cancel_check 触发时返回 None（不产出残缺备份）。

    守护采集的取消契约：备份期间收到取消信号须中止且不返回部分载荷，编排层据此
    不写出残缺备份文件。
    """
    vault = make_vault(make_test_config(str(tmp_path)))
    vault.initialize("test_password_12345")
    try:
        entry_mgr = make_entry_manager(vault)
        entry_mgr.add_entry(Entry(title="t", username="u", password="p"))
        raw_entries = vault.db.get_entries(EntryQuery(verify=VerifyMode.SKIP))
        key = vault.key

        result = collect_portable_data(key, lambda: True, raw_entries, [], [])

        assert result is None
    finally:
        vault.close()


def test_collect_portable_data_returns_full_portable_dict(tmp_path):
    """正常采集返回含 format/version/categories/entries/password_history 的完整载荷。"""
    vault = make_vault(make_test_config(str(tmp_path)))
    vault.initialize("test_password_12345")
    try:
        entry_mgr = make_entry_manager(vault)
        entry_mgr.add_entry(Entry(title="t", username="u", password="p"))
        raw_entries = vault.db.get_entries(EntryQuery(verify=VerifyMode.SKIP))
        key = vault.key
        categories = [
            {
                "id": 1,
                "name": "工作",
                "icon_char": "[DIR]",
                "color": "#666",
                "sort_order": 0,
                "created_at": "2024-01-01T00:00:00",
            }
        ]

        result = collect_portable_data(key, None, raw_entries, [], categories)

        assert result is not None
        assert result["format"] == header_codec.BACKUP_FORMAT
        assert result["version"] == header_codec.BACKUP_VERSION
        assert "created_at" in result
        assert result["categories"] == categories
        assert len(result["entries"]) == 1
        assert result["entries"][0]["title"] == "t"
        assert result["password_history"] == []
    finally:
        vault.close()


def test_payload_overhead_constants_positive():
    """payload 字节估算开销常量为正值（collector 与估算路径的单一事实源）。"""
    assert CATEGORY_OVERHEAD_BYTES > 0
    assert ENTRY_OVERHEAD_BYTES > 0
    assert HISTORY_OVERHEAD_BYTES > 0


# ======== 明文长度估算与上限联动（PERF-068）========


def _empty_portable_item(i: int) -> dict:
    """构造与 decrypt_entry_to_portable_dict 输出同构的全空条目。"""
    return {
        "id": i,
        "crypto_id": f"{i:032x}",
        "title": "",
        "username": "",
        "password": "",
        "url": "",
        "tags": "",
        "notes": "",
        "totp_secret": "",
        "custom_fields": [],
        "category_id": None,
        "password_strength": 0,
        "entry_type": "login",
        "is_favorite": False,
        "is_deleted": False,
        "created_at": "",
        "updated_at": "",
        "deleted_at": "",
        "password_changed_at": "",
    }


def _typical_portable_item(i: int) -> dict:
    """构造典型画像条目（≈758B 序列化）：中英文混合字段 + 1 个自定义字段。"""
    return {
        "id": i,
        "crypto_id": f"{i:032x}",
        "title": "网上银行-工商银行",
        "username": "user_name@example.com",
        "password": "P@ssw0rd!2026#secure",
        "url": "https://example.com/login?from=nav",
        "tags": "银行,工作,重要",
        "notes": "主卡备注\n线下网点已开通" * 3,
        "totp_secret": "",
        "custom_fields": [{"name": "客服电话", "value": "95588", "field_type": "text"}],
        "category_id": 3,
        "password_strength": 4,
        "entry_type": "login",
        "is_favorite": True,
        "is_deleted": False,
        "created_at": "2024-01-01T00:00:00",
        "updated_at": "2024-06-01T00:00:00",
        "deleted_at": "",
        "password_changed_at": "2024-05-01T00:00:00",
    }


def test_estimate_50k_empty_entries_below_limit():
    """PERF-068：50k 全空条目库的估算低于 MAX_BACKUP_PAYLOAD_SIZE。

    旧密文估算（8 字段空串密文 44 字符 × 50k + 512B/条 overhead ≈ 43MB）在 32MB
    上限下数学上不可能备份通过；明文估算 + 校准模板后 50k 空库 ≈ 17MB。
    """
    estimated = PAYLOAD_TOP_OVERHEAD_BYTES + sum(
        estimate_entry_payload_bytes(_empty_portable_item(i)) for i in range(50_000)
    )
    assert estimated < header_codec.MAX_BACKUP_PAYLOAD_SIZE, (
        f"50k 空条目库估算 {estimated / 1024 / 1024:.1f}MB 超上限，"
        "MAX_BACKUP_PAYLOAD_SIZE 与 MAX_ENTRIES_LIMIT 联动断裂（PERF-068）"
    )


def test_estimate_50k_typical_profile_below_limit():
    """PERF-068：50k 典型画像（~760B/条）估算仍低于 40MB 上限（联动校准依据）。"""
    estimated = PAYLOAD_TOP_OVERHEAD_BYTES + sum(
        estimate_entry_payload_bytes(_typical_portable_item(i)) for i in range(50_000)
    )
    assert estimated < header_codec.MAX_BACKUP_PAYLOAD_SIZE


def test_estimate_typical_payload_accuracy_within_10_percent():
    """PERF-068 校准守护：对典型画像，估算与实际 json.dumps 字节数误差 ≤10%。

    构造含分类/条目/密码历史的完整载荷（与 collect_portable_data 输出同构），
    对比逐项估算总和与 len(json.dumps(payload))——旧密文估算对 30k 库虚高
    1.65 倍，本测试锁定明文估算的精度承诺。
    """
    entries = [_typical_portable_item(i) for i in range(500)]
    entries += [_empty_portable_item(500 + i) for i in range(100)]
    categories = [
        {
            "id": 1,
            "name": "工作",
            "icon_char": "[DIR]",
            "color": "#666666",
            "sort_order": 0,
            "created_at": "2024-01-01T00:00:00",
        }
    ]
    history = [
        {"entry_id": i, "password": "OldP@ss!2026", "changed_at": "2024-02-01T00:00:00"}
        for i in range(200)
    ]
    payload = {
        "format": header_codec.BACKUP_FORMAT,
        "version": header_codec.BACKUP_VERSION,
        "created_at": "2026-08-24T00:00:00",
        "categories": categories,
        "entries": entries,
        "password_history": history,
    }
    actual = len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))

    estimated = PAYLOAD_TOP_OVERHEAD_BYTES
    estimated += sum(len(c["name"].encode("utf-8")) + CATEGORY_OVERHEAD_BYTES for c in categories)
    estimated += sum(estimate_entry_payload_bytes(item) for item in entries)
    estimated += sum(
        HISTORY_OVERHEAD_BYTES
        + len(str(h["entry_id"]))
        - 1
        + len(h["password"].encode("utf-8"))
        + len(h["changed_at"].encode("utf-8"))
        for h in history
    )

    error = abs(estimated - actual) / actual
    assert error <= 0.10, f"估算误差 {error:.1%} 超过 10%（估算 {estimated} / 实际 {actual}）"


def test_estimate_accounts_for_json_escape_inflation():
    """含引号/换行等转义字符的值按膨胀后长度估算（转义字符序列化占 2 字节）。"""
    plain = _empty_portable_item(1)
    plain["title"] = "a" * 100
    escaped = _empty_portable_item(1)
    # 同为 100 字符：每 4 字符（a/"/\/换行）含 3 个转义字符，各膨胀 1 字节。
    escaped["title"] = 'a"\\\n' * 25
    delta = estimate_entry_payload_bytes(escaped) - estimate_entry_payload_bytes(plain)
    assert delta == 75
