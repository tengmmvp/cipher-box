"""EntryManager 明文条目校验逻辑测试。"""

import pytest

from src.business.managers.entry_manager import EntryManager
from src.models import MAX_CUSTOM_FIELDS_PER_ENTRY, CustomField, Entry


def test_validate_plain_entry_rejects_too_many_custom_fields():
    """_validate_plain_entry 拒绝超过上限的自定义字段。

    回归守护：堵住 Bitwarden 导入用 Entry(...) 直接构造绕过 from_dict 的
    MAX_CUSTOM_FIELDS_PER_ENTRY 校验缺口，使 add/update 路径的约束与
    导入/恢复路径一致。
    """
    entry = Entry(
        title='t', username='u', password='p',
        custom_fields=[
            CustomField(name=f'f{i}', value='v')
            for i in range(MAX_CUSTOM_FIELDS_PER_ENTRY + 1)
        ],
    )
    with pytest.raises(ValueError, match='自定义字段过多'):
        EntryManager._validate_plain_entry(entry)


def test_validate_plain_entry_accepts_within_limit():
    """上限内的自定义字段应通过校验。"""
    entry = Entry(
        title='t', username='u', password='p',
        custom_fields=[
            CustomField(name=f'f{i}', value='v')
            for i in range(MAX_CUSTOM_FIELDS_PER_ENTRY)
        ],
    )
    # 不抛异常即通过
    EntryManager._validate_plain_entry(entry)
