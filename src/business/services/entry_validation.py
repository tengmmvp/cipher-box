"""条目明文校验。供 add_entry/update_entry 写入前校验 entry_type、字段类型/长度、custom_fields 结构与数量。"""

from ...exceptions import EntryError
from ...models import (
    ENTRY_FIELD_LIMITS,
    ENTRY_TYPES,
    MAX_CUSTOM_FIELD_NAME,
    MAX_CUSTOM_FIELD_VALUE,
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
        EntryError: 类型非法、字段类型/长度超限或自定义字段结构/数量违规。
            双继承 ``ValueError``，既有 ``except ValueError`` 兜底与 ``pytest.raises(ValueError)`` 仍可捕获。
    """
    if entry.entry_type not in ENTRY_TYPES:
        raise EntryError('条目类型无效')
    for field_name in STRING_ENCRYPTED_FIELDS:
        if not isinstance(getattr(entry, field_name), str):
            raise EntryError(f'条目字段 {field_name} 类型无效')
    for field_name, _label, max_len in ENTRY_FIELD_LIMITS:
        if len(getattr(entry, field_name)) > max_len:
            raise EntryError(f'条目字段 {field_name} 过长（最多 {max_len} 字符）')
    # 此函数仅校验明文条目：custom_fields 须为已解密的 list[CustomField]，
    # DB 原始条目的 custom_fields 为密文 str，不经过此校验。
    entry.assert_decrypted()
    if not isinstance(entry.custom_fields, list) or not all(
        isinstance(field, CustomField) for field in entry.custom_fields
    ):
        raise EntryError('自定义字段结构无效')
    if len(entry.custom_fields) > MAX_CUSTOM_FIELDS_PER_ENTRY:
        raise EntryError(
            f'自定义字段过多（最多 {MAX_CUSTOM_FIELDS_PER_ENTRY} 个）'
        )
    # 自定义字段长度与类型校验：与 CustomField.from_dict(strict=True) 对齐，消除
    # 「编辑可存任意长度、导入拒绝」的往返断裂（超长值导出再导入会被跳过整条）。
    # len() 对非 str 的 TypeError 归一化为 EntryError(ValueError)。
    for field in entry.custom_fields:
        if not isinstance(field.name, str) or len(field.name) > MAX_CUSTOM_FIELD_NAME:
            raise EntryError(
                f'自定义字段名称无效或过长（最多 {MAX_CUSTOM_FIELD_NAME} 字符）'
            )
        if not isinstance(field.value, str) or len(field.value) > MAX_CUSTOM_FIELD_VALUE:
            raise EntryError(
                f'自定义字段值无效或过长（最多 {MAX_CUSTOM_FIELD_VALUE} 字符）'
            )
