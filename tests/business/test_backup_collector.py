"""backup.collector 模块测试 — 备份载荷采集的解密、大小校验与取消。

覆盖 collect_portable_data / collect_portable_entries 的解密正确性、payload 上限
校验、cancel_check 中止路径，以及 payload 开销常量。直接测纯函数（不经
BackupRestoreManager 编排），补齐 MAINT-004 / ARCH-002 SRP 拆分后遗留的单元测试缺口。
"""

import pytest

from src.business.services.backup import header_codec
from src.business.services.backup.collector import (
    check_payload_limit,
    collect_portable_data,
    collect_portable_entries,
)
from src.business.services.backup.payload import (
    CATEGORY_OVERHEAD_BYTES,
    ENTRY_OVERHEAD_BYTES,
    HISTORY_OVERHEAD_BYTES,
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
