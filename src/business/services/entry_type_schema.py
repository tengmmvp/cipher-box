"""条目类型 schema 注册表——类型特化字段与行为的单一事实源。

``EntryTypeSchema`` 含专用字段 spec、可见字段顺序与类型特化行为钩子，供
entry_dialog / custom_fields_renderer / import_export 等消费。新增条目类型只需
扩展注册表，无需散弹式修改多处 ``if entry_type ==`` 分支。

注册表键集从 ``models.ENTRY_TYPES`` 派生（合法类型单一事实源），专用字段
storage_name 复用 ``models.SPECIAL_FIELD_*`` 常量，确保导入路径与 UI schema
写出一致的 storage_name。类型的展示文案（label/icon）不在此层——见
``ui/resources/strings.py``（ARCH-037）。
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

from ...models import (
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

    field_key: str  # widget 标识，如 'card_holder'
    storage_name: str  # custom_fields 中的存储名，如 '_card_holder'
    label: str  # 表单标签文案
    placeholder: str = ""
    sensitive: bool = False  # 密码型字段（EchoMode.Password + field_type='password'）
    max_length: int = 0  # 0 表示不设置 maxLength
    kind: str = "line"  # 'line' 或 'combo'
    combo_items: tuple = ()


@dataclass(frozen=True)
class EntryTypeSchema:
    """单个条目类型的完整 schema：字段集 + 可见字段顺序 + 类型特化行为钩子。

    type_id 标识类型；visible_fields 为通用 + 专用字段的显示顺序，驱动类型切换时
    的显隐；special_fields 为该类型的专用字段配置。原 label/icon 转发字段已随
    ARCH-037 删除——其值仅是 models.ENTRY_TYPES 展示文案的搬运且无生产消费方，
    UI 展示（下拉/详情/列表图标）直接查 ``ui/resources/strings.py``。

    行为钩子（ARCH-007）以布尔标志形式挂入，消除消费方 ``if entry_type ==``
    类型身份判断——改为查阅 schema 标志。标志默认无副作用（不会触发密码置空、
    备注展开、URL 拼接或额外校验）；按类型覆写即可启用对应行为。具体「如何」
    执行（如卡号校验算法、URL 拼接格式）仍由消费方（entry_dialog）实现，
    使业务层 schema 不依赖 UI 控件，保持依赖方向 UI → Business。

    - ``uses_password``：该类型是否使用密码字段（NOTE 置 False，保存时密码强制置空）；
    - ``notes_expanded``：是否放大备注编辑区（NOTE 置 True）；
    - ``composes_url``：是否由专用字段拼接 URL（SERVER 置 True，host/port/protocol→url）；
    - ``validate_extra``：是否需要额外的专用字段校验（CARD 置 True，校验卡号/有效期/CVV）。
    """

    type_id: str
    visible_fields: tuple[str, ...]
    special_fields: tuple[SpecialFieldSpec, ...] = ()
    uses_password: bool = True
    notes_expanded: bool = False
    composes_url: bool = False
    validate_extra: bool = False


_CARD_FIELDS = (
    SpecialFieldSpec("card_holder", SPECIAL_FIELD_CARD_HOLDER, "持卡人", "持卡人姓名"),
    SpecialFieldSpec("card_number", SPECIAL_FIELD_CARD_NUMBER, "卡号", "卡号", sensitive=True),
    SpecialFieldSpec("card_expiry", SPECIAL_FIELD_CARD_EXPIRY, "有效期", "MM/YY", max_length=5),
    SpecialFieldSpec(
        "card_cvv", SPECIAL_FIELD_CARD_CVV, "CVV", "CVV", sensitive=True, max_length=4
    ),
)
_IDENTITY_FIELDS = (
    SpecialFieldSpec("id_fullname", SPECIAL_FIELD_ID_FULLNAME, "姓名", "姓名"),
    SpecialFieldSpec("id_email", SPECIAL_FIELD_ID_EMAIL, "邮箱", "邮箱"),
    SpecialFieldSpec("id_phone", SPECIAL_FIELD_ID_PHONE, "电话", "电话"),
    SpecialFieldSpec("id_address", SPECIAL_FIELD_ID_ADDRESS, "地址", "地址"),
)
_SERVER_FIELDS = (
    SpecialFieldSpec("server_host", SPECIAL_FIELD_SERVER_HOST, "主机", "主机地址"),
    SpecialFieldSpec("server_port", SPECIAL_FIELD_SERVER_PORT, "端口", "22"),
    SpecialFieldSpec(
        "server_protocol",
        SPECIAL_FIELD_SERVER_PROTOCOL,
        "协议",
        kind="combo",
        combo_items=("SSH", "FTP", "HTTP", "HTTPS", "其他"),
    ),
)


def _build_schemas() -> dict[str, EntryTypeSchema]:
    """构建类型 schema 注册表，键集遍历 models.ENTRY_TYPES（合法类型单一事实源）。"""
    special_by_type: dict[str, tuple[SpecialFieldSpec, ...]] = {
        ENTRY_TYPE_LOGIN: (),
        ENTRY_TYPE_CARD: _CARD_FIELDS,
        ENTRY_TYPE_IDENTITY: _IDENTITY_FIELDS,
        ENTRY_TYPE_NOTE: (),
        ENTRY_TYPE_SERVER: _SERVER_FIELDS,
    }
    # 类型特化行为钩子覆写（ARCH-007）。未列出的类型沿用 EntryTypeSchema 默认值
    # （uses_password=True，其余 False）。新增类型若需特化行为，在此追加覆写即可，
    # 消费方（entry_dialog）只需查阅 schema 标志，无需新增 ``if entry_type ==`` 分支。
    behavior_overrides: dict[str, dict[str, bool]] = {
        ENTRY_TYPE_CARD: {"validate_extra": True},
        ENTRY_TYPE_NOTE: {"uses_password": False, "notes_expanded": True},
        ENTRY_TYPE_SERVER: {"composes_url": True},
    }
    # 专用字段之后的通用尾部字段（MAINT-105 数据化）：visible_fields 统一按
    # 「title + 专用字段 + 通用尾部」组装，替代原 CARD/IDENTITY…elif SERVER…elif
    # NOTE…else LOGIN 四分支硬编码——新增类型只需登记本表（缺省沿用 LOGIN 尾部），
    # 与模块「新增类型只需扩展注册表」的承诺一致。
    common_tail_by_type: dict[str, tuple[str, ...]] = {
        ENTRY_TYPE_LOGIN: ("username", "password", "url"),
        ENTRY_TYPE_CARD: (),
        ENTRY_TYPE_IDENTITY: (),
        ENTRY_TYPE_NOTE: (),
        ENTRY_TYPE_SERVER: ("username", "password"),
    }
    schemas: dict[str, EntryTypeSchema] = {}
    # ENTRY_TYPES 已收敛为类型键集合（ARCH-037），遍历注册全部类型；注册表消费方
    # 经 get_schema 按 type_id 查询，不依赖遍历顺序。
    for type_id in ENTRY_TYPES:
        special = special_by_type.get(type_id, ())
        # 未登记尾部的类型（ENTRY_TYPES 之外的兜底路径）沿用 LOGIN 尾部，与原 else
        # 分支及 get_schema 的 login 回退语义一致。
        common_tail = common_tail_by_type.get(type_id, common_tail_by_type[ENTRY_TYPE_LOGIN])
        visible = ("title", *(s.field_key for s in special), *common_tail)
        schemas[type_id] = EntryTypeSchema(
            type_id=type_id,
            visible_fields=visible,
            special_fields=special,
            **behavior_overrides.get(type_id, {}),
        )
    return schemas


ENTRY_TYPE_SCHEMAS: MappingProxyType[str, EntryTypeSchema] = MappingProxyType(_build_schemas())


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
