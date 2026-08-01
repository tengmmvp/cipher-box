"""Entry.from_dict 的 entry_type 校验测试。

验证 Entry.from_dict 对 entry_type 字段的校验逻辑，包括合法类型正常构造、
默认值取 login，以及非法类型、空字符串、纯数字字符串均抛出 ValueError。
"""

import pytest

from src.models import ENTRY_TYPE_LOGIN, ENTRY_TYPES, Entry


def _base_dict(**overrides):
    d = dict(
        title="Test",
        username="user",
        password="pass",
    )
    d.update(overrides)
    return d


def test_valid_entry_types():
    """所有合法 entry_type 应正常构造。"""
    for entry_type in ENTRY_TYPES:
        d = _base_dict(entry_type=entry_type)
        entry = Entry.from_dict(d)
        assert entry.entry_type == entry_type


def test_default_entry_type_is_login():
    """不传 entry_type 应默认为 login。"""
    entry = Entry.from_dict(_base_dict())
    assert entry.entry_type == ENTRY_TYPE_LOGIN


def test_invalid_entry_type_raises():
    """非法 entry_type 应抛出 ValueError。"""
    with pytest.raises(ValueError, match="无效的条目类型"):
        Entry.from_dict(_base_dict(entry_type="invalid_type"))


def test_empty_entry_type_raises():
    """空字符串 entry_type 应抛出 ValueError。"""
    with pytest.raises(ValueError):
        Entry.from_dict(_base_dict(entry_type=""))


def test_numeric_entry_type_raises():
    """数字 entry_type 应抛出 ValueError，字符串 '123' 不是合法类型。"""
    with pytest.raises(ValueError):
        Entry.from_dict(_base_dict(entry_type="123"))
