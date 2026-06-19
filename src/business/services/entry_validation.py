"""条目明文校验 — 从 EntryManager 抽离的纯校验逻辑。

供 add_entry / update_entry 路径在写入前校验明文条目：entry_type 合法性、
加密字符串字段类型、字段长度上限、custom_fields 结构与数量。
"""

from ...models import (
    ENTRY_FIELD_LIMITS,
    ENTRY_TYPES,
    MAX_CUSTOM_FIELDS_PER_ENTRY,
    CustomField,
    Entry,
)
from .crypto_utils import STRING_ENCRYPTED_FIELDS


def validate_plain_entry(entry: Entry) -> None:
    """校验待写入的明文条目。

    Args:
        entry: 已解密的明文条目。

    Raises:
        ValueError: 类型非法、字段类型/长度超限或自定义字段结构/数量违规。
    """
    if entry.entry_type not in ENTRY_TYPES:
        raise ValueError('条目类型无效')
    for field_name in STRING_ENCRYPTED_FIELDS:
        if not isinstance(getattr(entry, field_name), str):
            raise ValueError(f'条目字段 {field_name} 类型无效')
    for field_name, _label, max_len in ENTRY_FIELD_LIMITS:
        if len(getattr(entry, field_name)) > max_len:
            raise ValueError(f'条目字段 {field_name} 过长（最多 {max_len} 字符）')
    # 此函数仅用于 add_entry/update_entry 路径的明文条目校验。
    # custom_fields 必须为已解密的 list[CustomField]。
    # DB 原始条目的 custom_fields 为 str 类型的密文，不经过此校验。
    entry.assert_decrypted()
    if not isinstance(entry.custom_fields, list) or not all(
        isinstance(field, CustomField) for field in entry.custom_fields
    ):
        raise ValueError('自定义字段结构无效')
    if len(entry.custom_fields) > MAX_CUSTOM_FIELDS_PER_ENTRY:
        raise ValueError(
            f'自定义字段过多（最多 {MAX_CUSTOM_FIELDS_PER_ENTRY} 个）'
        )
