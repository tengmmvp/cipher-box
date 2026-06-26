"""Bitwarden 导入器对畸形/被污染导出 JSON 的容错测试。

回归守护：外部 Bitwarden 导出可能被污染或损坏（嵌套字段为非预期类型、item 本身
非对象、字段超长）。解析须对这些结构容错——以类型守卫避免 AttributeError 中断整个
导入（单个畸形 item 导致的拒绝服务），并以 validate_plain_entry 跳过类型混淆/
超长字段，使 ImportExportManager 的 skip_validation=True 假设对本路径成立。
"""

import json

from src.business.managers.importers.bitwarden_importer import BitwardenImporter


def _write_bitwarden_json(tmp_path, data) -> str:
    path = tmp_path / 'bitwarden.json'
    path.write_text(json.dumps(data, ensure_ascii=False), encoding='utf-8')
    return str(path)


def test_malformed_fields_string_does_not_crash(tmp_path):
    """fields 为字符串时不应被逐字符迭代后对字符调 .get 抛 AttributeError。"""
    path = _write_bitwarden_json(tmp_path, {
        'items': [{'name': 'x', 'fields': 'not-a-list'}],
    })
    result = BitwardenImporter().parse(path)
    assert len(result.entries) == 1
    assert result.entries[0].custom_fields == []


def test_malformed_card_as_list_does_not_crash(tmp_path):
    """card 为列表时不应 .get 抛 AttributeError。"""
    path = _write_bitwarden_json(tmp_path, {
        'items': [{'type': 3, 'card': [1, 2, 3]}],
    })
    result = BitwardenImporter().parse(path)
    assert len(result.entries) == 1


def test_non_string_top_level_fields_coerced(tmp_path):
    """顶层字段非 str（int/list）应被强制为空串，而非类型混淆落库。"""
    path = _write_bitwarden_json(tmp_path, {
        'items': [{'name': 12345, 'notes': ['a', 'b']}],
    })
    result = BitwardenImporter().parse(path)
    assert len(result.entries) == 1
    entry = result.entries[0]
    assert entry.title == ''
    assert entry.notes == ''


def test_malformed_uris_string_does_not_crash(tmp_path):
    """login.uris 为字符串时 uris[0] 不应是单字符 str 调 .get 抛 AttributeError。"""
    path = _write_bitwarden_json(tmp_path, {
        'items': [{'login': {'uris': 'http://x'}}],
    })
    result = BitwardenImporter().parse(path)
    assert len(result.entries) == 1
    assert result.entries[0].url == ''


def test_non_dict_item_skipped(tmp_path):
    """item 本身非对象（数字/字符串）应被跳过，而非 _validate_items 抛 AttributeError。"""
    path = _write_bitwarden_json(tmp_path, {
        'items': [123, 'abc', {'name': 'valid'}],
    })
    result = BitwardenImporter().parse(path)
    assert len(result.entries) == 1
    assert result.entries[0].title == 'valid'


def test_overlong_field_skipped(tmp_path):
    """超长字段（超 MAX_FIELD_TITLE=1024）应被 validate_plain_entry 跳过。

    单条目总 payload（2KB）远低于 MAX_ENTRY_PAYLOAD_SIZE（2MB），故 _validate_items
    放行；parse 内 validate_plain_entry 复核字段长度，超限跳过单条而非中断导入。
    """
    path = _write_bitwarden_json(tmp_path, {
        'items': [{'name': 'x' * 2000}],
    })
    result = BitwardenImporter().parse(path)
    assert len(result.entries) == 0


def test_malformed_folders_string_does_not_crash(tmp_path):
    """folders 为字符串时不应被逐字符迭代。"""
    path = _write_bitwarden_json(tmp_path, {
        'folders': 'not-a-list',
        'items': [{'name': 'x', 'folderId': 'f1'}],
    })
    result = BitwardenImporter().parse(path)
    assert len(result.entries) == 1
    assert result.entries[0].category_name == ''
