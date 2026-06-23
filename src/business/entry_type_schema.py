"""条目类型 schema 注册表——类型特化字段与行为的单一事实源。

上提自 ``entry_dialog._SpecialFieldSpec`` / ``_SPECIAL_SCHEMA`` / ``_TYPE_FIELDS``，
消除 UI 层定义类型 schema（C1 数据迁移，行为不变）。``EntryTypeSchema`` 含专用
字段 spec、可见字段顺序与类型特化行为钩子（C2 填充），供 entry_dialog /
custom_fields_renderer / import_export 等消费。新增条目类型只需扩展注册表，
无需散弹式修改多处 ``if entry_type ==`` 分支。

label/icon 从 ``models.ENTRY_TYPES`` 派生（单一源），专用字段 storage_name 复用
``models.SPECIAL_FIELD_*`` 常量，确保导入路径与 UI schema 写出一致的 storage_name。
"""

from __future__ import annotations

from dataclasses import dataclass

from ..models import (
    ENTRY_TYPE_CARD,
    ENTRY_TYPE_IDENTITY,
    ENTRY_TYPE_LOGIN,
    ENTRY_TYPE_NOTE,
    ENTRY_TYPE_SERVER,
    ENTRY_TYPES,
    SPECIAL_FIELD_CARD_CVV,
    SPECIAL_FIELD_CARD_EXPIRY,
    SPECIAL_FIELD_CARD_HOLDER,
    SPECIAL_FIELD_CARD_NUMBER,
    SPECIAL_FIELD_ID_ADDRESS,
    SPECIAL_FIELD_ID_EMAIL,
    SPECIAL_FIELD_ID_FULLNAME,
    SPECIAL_FIELD_ID_PHONE,
    SPECIAL_FIELD_SERVER_HOST,
    SPECIAL_FIELD_SERVER_PORT,
    SPECIAL_FIELD_SERVER_PROTOCOL,
)


@dataclass(frozen=True)
class SpecialFieldSpec:
    """专用字段配置，驱动表单构建 / 收集 / 加载 / 显隐。

    storage_name 沿用 ``_`` 前缀作为专用字段命名空间，将其与用户自定义字段隔离。
    加载时按 storage_name 精确匹配归属，而非按前缀 ``startswith`` 推断，消除用户
    自定义字段名以 ``_card_`` / ``_id_`` / ``_server_`` 开头时被误判为专用字段的风险。
    """

    field_key: str           # widget 标识，如 'card_holder'
    storage_name: str        # custom_fields 中的存储名，如 '_card_holder'
    label: str               # 表单标签文案
    placeholder: str = ''
    sensitive: bool = False  # 密码型字段（EchoMode.Password + field_type='password'）
    max_length: int = 0      # 0 表示不设置 maxLength
    kind: str = 'line'       # 'line' 或 'combo'
    combo_items: tuple = ()


@dataclass(frozen=True)
class EntryTypeSchema:
    """单个条目类型的完整 schema：字段集 + 可见字段顺序。

    type_id / label / icon 标识类型；visible_fields 为通用 + 专用字段的显示顺序，
    驱动类型切换时的显隐；special_fields 为该类型的专用字段配置。类型特化行为
    （校验 / 格式化 / 拼接等）在 C2 以钩子形式挂入。
    """

    type_id: str
    label: str
    icon: str
    visible_fields: tuple[str, ...]
    special_fields: tuple[SpecialFieldSpec, ...] = ()


_CARD_FIELDS = (
    SpecialFieldSpec('card_holder', SPECIAL_FIELD_CARD_HOLDER, '持卡人', '持卡人姓名'),
    SpecialFieldSpec('card_number', SPECIAL_FIELD_CARD_NUMBER, '卡号', '卡号', sensitive=True),
    SpecialFieldSpec('card_expiry', SPECIAL_FIELD_CARD_EXPIRY, '有效期', 'MM/YY', max_length=5),
    SpecialFieldSpec('card_cvv', SPECIAL_FIELD_CARD_CVV, 'CVV', 'CVV', sensitive=True, max_length=4),
)
_IDENTITY_FIELDS = (
    SpecialFieldSpec('id_fullname', SPECIAL_FIELD_ID_FULLNAME, '姓名', '姓名'),
    SpecialFieldSpec('id_email', SPECIAL_FIELD_ID_EMAIL, '邮箱', '邮箱'),
    SpecialFieldSpec('id_phone', SPECIAL_FIELD_ID_PHONE, '电话', '电话'),
    SpecialFieldSpec('id_address', SPECIAL_FIELD_ID_ADDRESS, '地址', '地址'),
)
_SERVER_FIELDS = (
    SpecialFieldSpec('server_host', SPECIAL_FIELD_SERVER_HOST, '主机', '主机地址'),
    SpecialFieldSpec('server_port', SPECIAL_FIELD_SERVER_PORT, '端口', '22'),
    SpecialFieldSpec('server_protocol', SPECIAL_FIELD_SERVER_PROTOCOL, '协议',
                     kind='combo', combo_items=('SSH', 'FTP', 'HTTP', 'HTTPS', '其他')),
)


def _build_schemas() -> dict[str, EntryTypeSchema]:
    """构建类型 schema 注册表，label/icon 从 models.ENTRY_TYPES 派生（单一源）。"""
    special_by_type: dict[str, tuple[SpecialFieldSpec, ...]] = {
        ENTRY_TYPE_LOGIN: (),
        ENTRY_TYPE_CARD: _CARD_FIELDS,
        ENTRY_TYPE_IDENTITY: _IDENTITY_FIELDS,
        ENTRY_TYPE_NOTE: (),
        ENTRY_TYPE_SERVER: _SERVER_FIELDS,
    }
    schemas: dict[str, EntryTypeSchema] = {}
    for type_id, meta in ENTRY_TYPES.items():
        special = special_by_type.get(type_id, ())
        if type_id in (ENTRY_TYPE_CARD, ENTRY_TYPE_IDENTITY):
            visible = ('title', *(s.field_key for s in special))
        elif type_id == ENTRY_TYPE_SERVER:
            visible = ('title', *(s.field_key for s in special), 'username', 'password')
        elif type_id == ENTRY_TYPE_NOTE:
            visible = ('title',)
        else:  # LOGIN 及未知类型
            visible = ('title', 'username', 'password', 'url')
        schemas[type_id] = EntryTypeSchema(
            type_id=type_id,
            label=meta['label'],
            icon=meta['icon'],
            visible_fields=visible,
            special_fields=special,
        )
    return schemas


ENTRY_TYPE_SCHEMAS: dict[str, EntryTypeSchema] = _build_schemas()


def get_schema(type_id: str) -> EntryTypeSchema:
    """获取类型 schema，未知类型回退到 login。"""
    return ENTRY_TYPE_SCHEMAS.get(type_id, ENTRY_TYPE_SCHEMAS[ENTRY_TYPE_LOGIN])


def all_special_fields_by_storage() -> dict[str, SpecialFieldSpec]:
    """全部专用字段的 storage_name → spec 映射，加载时按 storage_name 精确匹配。"""
    return {
        spec.storage_name: spec
        for schema in ENTRY_TYPE_SCHEMAS.values()
        for spec in schema.special_fields
    }
