"""entry_type_schema 注册表单元测试。

锚定注册表不变量：覆盖全部 5 种 ENTRY_TYPES、专用字段 storage_name 复用
models.SPECIAL_FIELD_* 常量（防手写字符串漂移导致导入路径与 UI schema 写出
不一致的 storage_name，使导入的卡片/身份/服务器条目在编辑对话框无法回填）。
"""

from src.business.services.entry_type_schema import (
    ENTRY_TYPE_SCHEMAS,
    all_special_fields_by_storage,
    get_schema,
)
from src.models import (
    ENTRY_TYPES,
    SPECIAL_FIELD_CARD_HOLDER,
    SPECIAL_FIELD_CARD_NUMBER,
    SPECIAL_FIELD_ID_FULLNAME,
    SPECIAL_FIELD_SERVER_PROTOCOL,
)


def test_schemas_cover_all_entry_types():
    """注册表须覆盖 models.ENTRY_TYPES 的全部 5 种类型。"""
    assert set(ENTRY_TYPE_SCHEMAS) == set(ENTRY_TYPES)


def test_schema_has_no_display_fields():
    """schema 不含展示字段（ARCH-037）：label/icon 已随展示语义下沉 UI 层。

    守护注册表不回潮：业务层 schema 只描述字段集与行为钩子，展示文案单一
    事实源在 ``ui/resources/strings.py``（本测试在 business 层，不 import UI 模块，
    仅断言字段不存在）。
    """
    for schema in ENTRY_TYPE_SCHEMAS.values():
        assert not hasattr(schema, "label")
        assert not hasattr(schema, "icon")
        assert schema.type_id in ENTRY_TYPES


def test_get_schema_unknown_falls_back_to_login():
    """未知类型回退到 login schema，而非 KeyError。"""
    from src.models import ENTRY_TYPE_LOGIN

    schema = get_schema("nonexistent_type")
    assert schema.type_id == ENTRY_TYPE_LOGIN


def test_special_field_storage_names_reuse_constants():
    """专用字段 storage_name 复用 models.SPECIAL_FIELD_* 常量，防字符串漂移。"""
    by_storage = all_special_fields_by_storage()
    # 抽样 card / identity / server 各一，确认 storage_name 键与常量一致
    assert by_storage[SPECIAL_FIELD_CARD_HOLDER].field_key == "card_holder"
    assert by_storage[SPECIAL_FIELD_CARD_NUMBER].sensitive is True
    assert by_storage[SPECIAL_FIELD_ID_FULLNAME].label == "姓名"
    protocol = by_storage[SPECIAL_FIELD_SERVER_PROTOCOL]
    assert protocol.kind == "combo"
    assert "SSH" in protocol.combo_items


def test_login_and_note_have_no_special_fields():
    """login / note 类型无专用字段。"""
    from src.models import ENTRY_TYPE_LOGIN, ENTRY_TYPE_NOTE

    assert ENTRY_TYPE_SCHEMAS[ENTRY_TYPE_LOGIN].special_fields == ()
    assert ENTRY_TYPE_SCHEMAS[ENTRY_TYPE_NOTE].special_fields == ()


def test_storage_names_are_namespaced_with_underscore():
    """所有专用字段 storage_name 以 _ 前缀隔离，避免与用户自定义字段冲突。"""
    by_storage = all_special_fields_by_storage()
    assert by_storage, "应至少有一个专用字段"
    assert all(name.startswith("_") for name in by_storage)
    assert len(by_storage) == len(set(by_storage))


def test_card_and_server_visible_fields_order():
    """card 含专用字段在前；server 含专用字段 + username/password。"""
    from src.models import ENTRY_TYPE_CARD, ENTRY_TYPE_SERVER

    card_visible = ENTRY_TYPE_SCHEMAS[ENTRY_TYPE_CARD].visible_fields
    assert card_visible[0] == "title"
    assert "card_number" in card_visible
    server_visible = ENTRY_TYPE_SCHEMAS[ENTRY_TYPE_SERVER].visible_fields
    assert "server_host" in server_visible
    assert "username" in server_visible and "password" in server_visible


def test_visible_fields_registry_driven_snapshot():
    """visible_fields 注册表驱动组装后的逐类型快照（MAINT-105）。

    与改造前 if/elif 链的产物逐字段等价——数据化重构（title + 专用字段 + 通用尾部）
    不得改变任何类型的可见字段集与顺序；新增类型漏登记 common_tail 时也会在此暴露
    （意外落到 LOGIN 兜底尾部）。
    """
    from src.models import (
        ENTRY_TYPE_CARD,
        ENTRY_TYPE_IDENTITY,
        ENTRY_TYPE_LOGIN,
        ENTRY_TYPE_NOTE,
        ENTRY_TYPE_SERVER,
    )

    assert ENTRY_TYPE_SCHEMAS[ENTRY_TYPE_LOGIN].visible_fields == (
        "title",
        "username",
        "password",
        "url",
    )
    assert ENTRY_TYPE_SCHEMAS[ENTRY_TYPE_CARD].visible_fields == (
        "title",
        "card_holder",
        "card_number",
        "card_expiry",
        "card_cvv",
    )
    assert ENTRY_TYPE_SCHEMAS[ENTRY_TYPE_IDENTITY].visible_fields == (
        "title",
        "id_fullname",
        "id_email",
        "id_phone",
        "id_address",
    )
    assert ENTRY_TYPE_SCHEMAS[ENTRY_TYPE_NOTE].visible_fields == ("title",)
    assert ENTRY_TYPE_SCHEMAS[ENTRY_TYPE_SERVER].visible_fields == (
        "title",
        "server_host",
        "server_port",
        "server_protocol",
        "username",
        "password",
    )


def test_visible_fields_follow_special_field_order():
    """visible_fields 的专用字段段与 special_fields 声明序一致（注册表驱动的联动）。

    MAINT-105 数据化后专用字段在 visible 中的顺序由 special_fields 元组派生——
    调整 _CARD_FIELDS 等声明顺序时 visible 自动跟随，不再存在第二份手抄顺序。
    """
    for schema in ENTRY_TYPE_SCHEMAS.values():
        special_keys = [s.field_key for s in schema.special_fields]
        assert list(schema.visible_fields[1 : 1 + len(special_keys)]) == special_keys
        # title 恒为首个可见字段（组装公式的公共头）
        assert schema.visible_fields[0] == "title"
