"""Entry.from_dict 时间戳字段校验测试（QL-042）。

守护导入路径对 created_at/updated_at/password_changed_at 的 ISO 8601 可解析性
校验：非空且格式无效的值抛 EntryError（与恢复路径 backup/validator 的同款校验
对齐），防止无效时间戳入库导致 updated_at 字符串排序错乱与该条目永久退出
过期检测（_parse_changed_utc 返回 None）。
"""

import pytest

from src.exceptions import EntryError
from src.models import Entry


def _base_dict(**overrides):
    """构建 Entry.from_dict 的最小合法输入 dict，调用方经 kwargs 覆盖关注字段。"""
    d = dict(
        title="Test",
        username="user",
        password="pass",
    )
    d.update(overrides)
    return d


@pytest.mark.parametrize(
    "field",
    ["created_at", "updated_at", "password_changed_at"],
)
class TestTimestampRejection:
    """三个时间戳字段的非法值统一拒绝。"""

    @pytest.mark.parametrize(
        "bad_value",
        ["not-a-date", "2026-13-45", "T00:00:00", "abc 123"],
    )
    def test_invalid_timestamp_raises(self, field, bad_value):
        """非空且 fromisoformat 不可解析的时间戳抛 EntryError（IS ValueError）。"""
        with pytest.raises(EntryError, match=f"{field}格式无效"):
            Entry.from_dict(_base_dict(**{field: bad_value}))
        # EntryError 兼容 except ValueError 的既有处理范式
        with pytest.raises(ValueError, match=f"{field}格式无效"):
            Entry.from_dict(_base_dict(**{field: bad_value}))

    def test_non_string_type_raises(self, field):
        """int 等非字符串时间戳仍按类型校验拒绝（先于格式校验）。"""
        with pytest.raises(EntryError, match=f"{field}类型无效"):
            Entry.from_dict(_base_dict(**{field: 12345}))


@pytest.mark.parametrize(
    "good_value",
    [
        "2026-01-02T03:04:05",  # 无微秒
        "2026-01-02T03:04:05.123456",  # 含微秒
        "2026-01-02T03:04:05+00:00",  # 显式 UTC 偏移
        "2026-01-02 03:04:05",  # 空格分隔（fromisoformat 接受）
        "2026-01-02",  # 纯日期
    ],
)
def test_valid_iso_timestamps_pass(good_value):
    """合法 ISO 8601 形态（含/不含微秒、+00:00、空格分隔）均通过并原样保留。"""
    entry = Entry.from_dict(
        _base_dict(
            created_at=good_value,
            updated_at=good_value,
            password_changed_at=good_value,
        )
    )
    assert entry.created_at == good_value
    assert entry.updated_at == good_value
    assert entry.password_changed_at == good_value


def test_empty_and_missing_timestamps_pass():
    """空串与缺省（None 语义）通过：字段可选，不强制填充。"""
    entry = Entry.from_dict(_base_dict(created_at="", updated_at=""))
    assert entry.created_at == ""
    assert entry.updated_at == ""
    assert entry.password_changed_at == ""  # 缺省 → 默认空串
