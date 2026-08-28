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
