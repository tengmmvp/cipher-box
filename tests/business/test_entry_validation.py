"""validate_plain_entry 明文条目校验逻辑测试（entry_validation 服务）。

覆盖字段类型与长度校验、自定义字段数量及单字段长度限制，以及导入/编辑路径
校验一致的回归守护——堵住 Entry(...) 直接构造绕过 from_dict 的约束缺口。
"""

import dataclasses

import pytest

from src.business.services.entry_validation import validate_plain_entry
from src.models import (
    ENTRY_FIELD_LIMITS,
    MAX_CUSTOM_FIELD_NAME,
    MAX_CUSTOM_FIELD_VALUE,
    MAX_CUSTOM_FIELDS_PER_ENTRY,
    CustomField,
    Entry,
)


def _make_entry(**overrides) -> Entry:
    """构造合法默认 Entry，调用方覆盖特定字段。"""
    return Entry(
        title="t",
        username="u",
        password="p",
        custom_fields=[],
        **overrides,
    )


class TestValidatePlainEntry:
    """validate_plain_entry 的合法通过与各类非法拒绝。"""

    def test_valid_login_entry_passes(self):
        assert validate_plain_entry(_make_entry()) is None

    def test_valid_each_entry_type_passes(self):
        for entry_type in ("login", "card", "identity", "note", "server"):
            assert validate_plain_entry(_make_entry(entry_type=entry_type)) is None

    def test_invalid_entry_type_rejected(self):
        with pytest.raises(ValueError, match="类型"):
            validate_plain_entry(_make_entry(entry_type="unknown"))

    def test_string_field_non_string_rejected(self):
        """加密字符串字段类型非 str 应拒绝（title 为 int）。"""
        entry = _make_entry()
        entry = dataclasses.replace(entry, title=123)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="类型"):
            validate_plain_entry(entry)

    def test_password_non_string_rejected(self):
        entry = _make_entry()
        entry = dataclasses.replace(entry, password=None)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="类型"):
            validate_plain_entry(entry)

    @pytest.mark.parametrize(
        ("field_name", "max_len"),
        [(name, max_len) for name, _label, max_len in ENTRY_FIELD_LIMITS],
    )
    def test_field_too_long_rejected(self, field_name, max_len):
        """每个长度受限字段超出上限应被拒绝。"""
        entry = _make_entry()
        entry = dataclasses.replace(entry, **{field_name: "x" * (max_len + 1)})
        with pytest.raises(ValueError, match="过长"):
            validate_plain_entry(entry)

    @pytest.mark.parametrize(
        ("field_name", "max_len"),
        [(name, max_len) for name, _label, max_len in ENTRY_FIELD_LIMITS],
    )
    def test_field_at_limit_passes(self, field_name, max_len):
        """恰等于上限应通过（边界守护）。"""
        entry = _make_entry()
        entry = dataclasses.replace(entry, **{field_name: "x" * max_len})
        assert validate_plain_entry(entry) is None

    def test_custom_fields_non_list_rejected(self):
        """custom_fields 非 list 时 assert_decrypted 先拒绝（仍未解密态）。

        validate_plain_entry 在结构校验前调用 entry.assert_decrypted()，
        非 list 的 custom_fields 使 is_decrypted 为 False，应被拒绝。
        """
        entry = _make_entry()
        entry = dataclasses.replace(entry, custom_fields="not-a-list")  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            validate_plain_entry(entry)

    def test_custom_fields_contains_non_custom_field_rejected(self):
        entry = _make_entry()
        entry = dataclasses.replace(
            entry,
            custom_fields=[CustomField(name="n", value="v"), "x"],  # type: ignore[list-item]
        )
        with pytest.raises(ValueError, match="自定义字段"):
            validate_plain_entry(entry)


def test_validate_plain_entry_rejects_too_many_custom_fields():
    """validate_plain_entry 拒绝超过上限的自定义字段。

    回归守护：堵住 Bitwarden 导入用 Entry(...) 直接构造绕过 from_dict 的
    MAX_CUSTOM_FIELDS_PER_ENTRY 校验缺口，使 add/update 路径的约束与
    导入/恢复路径一致。
    """
    entry = Entry(
        title="t",
        username="u",
        password="p",
        custom_fields=[
            CustomField(name=f"f{i}", value="v") for i in range(MAX_CUSTOM_FIELDS_PER_ENTRY + 1)
        ],
    )
    with pytest.raises(ValueError, match="自定义字段过多"):
        validate_plain_entry(entry)


def test_validate_plain_entry_accepts_within_limit():
    """上限内的自定义字段应通过校验。"""
    entry = Entry(
        title="t",
        username="u",
        password="p",
        custom_fields=[
            CustomField(name=f"f{i}", value="v") for i in range(MAX_CUSTOM_FIELDS_PER_ENTRY)
        ],
    )
    assert validate_plain_entry(entry) is None


def test_validate_plain_entry_rejects_custom_field_name_too_long():
    """自定义字段名称超长应拒绝（与 CustomField.from_dict strict 对齐）。

    回归守护：编辑路径经 Entry(...) 直接构造绕过 from_dict，此前缺单字段长度
    校验，导致「编辑可存超长值、导入拒绝」的往返断裂——编辑存的超长值导出
    再导入会被 from_dict 跳过整条。
    """
    entry = Entry(
        title="t",
        username="u",
        password="p",
        custom_fields=[CustomField(name="n" * (MAX_CUSTOM_FIELD_NAME + 1), value="v")],
    )
    with pytest.raises(ValueError, match="名称"):
        validate_plain_entry(entry)


def test_validate_plain_entry_rejects_custom_field_value_too_long():
    """自定义字段值超长应拒绝（与 CustomField.from_dict strict 对齐）。"""
    entry = Entry(
        title="t",
        username="u",
        password="p",
        custom_fields=[CustomField(name="n", value="v" * (MAX_CUSTOM_FIELD_VALUE + 1))],
    )
    with pytest.raises(ValueError, match="值"):
        validate_plain_entry(entry)


def test_validate_plain_entry_accepts_custom_field_at_length_limit():
    """自定义字段 name/value 恰好等于上限应通过（边界守护）。"""
    entry = Entry(
        title="t",
        username="u",
        password="p",
        custom_fields=[
            CustomField(
                name="n" * MAX_CUSTOM_FIELD_NAME,
                value="v" * MAX_CUSTOM_FIELD_VALUE,
            )
        ],
    )
    assert validate_plain_entry(entry) is None
