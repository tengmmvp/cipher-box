"""Bitwarden 导入器对畸形/被污染导出 JSON 的容错测试。

外部导出可能被污染（字段错型、item 非对象、字段超长）：以类型守卫避免单个畸形 item
的 AttributeError 中断整个导入，并以 validate_plain_entry 跳过类型混淆/超长字段，
使 ImportExportManager 的 skip_validation=True 假设对本路径成立。
"""

import json

from src.business.managers.importers.bitwarden_importer import BitwardenImporter


def _write_bitwarden_json(tmp_path, data) -> str:
    path = tmp_path / "bitwarden.json"
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return str(path)


def test_malformed_fields_string_does_not_crash(tmp_path):
    """fields 为字符串时不应被逐字符迭代后对字符调 .get 抛出 AttributeError。"""
    path = _write_bitwarden_json(
        tmp_path,
        {
            "items": [{"name": "x", "fields": "not-a-list"}],
        },
    )
    result = BitwardenImporter().parse(path)
    assert len(result.entries) == 1
    assert result.entries[0].custom_fields == []


def test_malformed_card_as_list_does_not_crash(tmp_path):
    """card 为列表时不应因调用 .get 抛出 AttributeError。"""
    path = _write_bitwarden_json(
        tmp_path,
        {
            "items": [{"type": 3, "card": [1, 2, 3]}],
        },
    )
    result = BitwardenImporter().parse(path)
    assert len(result.entries) == 1


def test_non_string_top_level_fields_coerced(tmp_path):
    """顶层字段非 str（int/list）应被强制为空串，而非类型混淆落库。"""
    path = _write_bitwarden_json(
        tmp_path,
        {
            "items": [{"name": 12345, "notes": ["a", "b"]}],
        },
    )
    result = BitwardenImporter().parse(path)
    assert len(result.entries) == 1
    entry = result.entries[0]
    assert entry.title == ""
    assert entry.notes == ""


def test_malformed_uris_string_does_not_crash(tmp_path):
    """login.uris 为字符串时不应将单字符 str 当 dict 调 .get 抛出 AttributeError。"""
    path = _write_bitwarden_json(
        tmp_path,
        {
            "items": [{"login": {"uris": "http://x"}}],
        },
    )
    result = BitwardenImporter().parse(path)
    assert len(result.entries) == 1
    assert result.entries[0].url == ""


def test_non_dict_item_skipped(tmp_path):
    """item 本身非对象（数字/字符串）应被跳过，而非 _validate_items 抛出 AttributeError。"""
    path = _write_bitwarden_json(
        tmp_path,
        {
            "items": [123, "abc", {"name": "valid"}],
        },
    )
    result = BitwardenImporter().parse(path)
    assert len(result.entries) == 1
    assert result.entries[0].title == "valid"


def test_overlong_field_skipped(tmp_path):
    """超长字段（超 MAX_FIELD_TITLE=1024）应被 validate_plain_entry 跳过。

    单条目总 payload（2KB）远低于 MAX_ENTRY_PAYLOAD_SIZE（2MB），故 _validate_items
    放行；parse 内 validate_plain_entry 复核字段长度，超限跳过单条而非中断导入。
    """
    path = _write_bitwarden_json(
        tmp_path,
        {
            "items": [{"name": "x" * 2000}],
        },
    )
    result = BitwardenImporter().parse(path)
    assert len(result.entries) == 0


def test_malformed_folders_string_does_not_crash(tmp_path):
    """folders 为字符串时不应被逐字符迭代。"""
    path = _write_bitwarden_json(
        tmp_path,
        {
            "folders": "not-a-list",
            "items": [{"name": "x", "folderId": "f1"}],
        },
    )
    result = BitwardenImporter().parse(path)
    assert len(result.entries) == 1
    assert result.entries[0].category_name == ""


def test_password_revision_date_preserved(tmp_path):
    """login.passwordRevisionDate 应解析为 password_changed_at（M5），避免导入后过期
    检测把本应过期的密码当作「刚修改」。

    Bitwarden 用 Z 后缀的 ISO 时间；Python 3.10 fromisoformat 不支持 Z，须替换为
    +00:00 后解析归一为 UTC ISO。
    """
    path = _write_bitwarden_json(
        tmp_path,
        {
            "items": [
                {
                    "name": "old-pass",
                    "login": {
                        "username": "u",
                        "password": "p",
                        "passwordRevisionDate": "2024-01-15T10:30:00.000Z",
                    },
                }
            ],
        },
    )
    result = BitwardenImporter().parse(path)
    assert len(result.entries) == 1
    assert result.entries[0].password_changed_at == "2024-01-15T10:30:00+00:00"


def test_password_revision_date_null_or_absent_empty(tmp_path):
    """passwordRevisionDate 为 null / 缺失时 password_changed_at 为空串（M5）。

    空串在 _encrypt_entry 经 ``or now`` 回退当前时间——note/card 等无密码条目本无
    passwordRevisionDate，空串回退合理。
    """
    path = _write_bitwarden_json(
        tmp_path,
        {
            "items": [
                {"name": "no-rev", "login": {"passwordRevisionDate": None}},
                {"name": "absent", "login": {}},
            ],
        },
    )
    result = BitwardenImporter().parse(path)
    assert [e.password_changed_at for e in result.entries] == ["", ""]


def test_password_revision_date_invalid_empty(tmp_path):
    """非法日期格式应容错为空串（M5），不中断导入。"""
    path = _write_bitwarden_json(
        tmp_path,
        {
            "items": [{"name": "bad", "login": {"passwordRevisionDate": "not-a-date"}}],
        },
    )
    result = BitwardenImporter().parse(path)
    assert len(result.entries) == 1
    assert result.entries[0].password_changed_at == ""


def test_boolean_custom_field_preserved(tmp_path):
    """Bitwarden 布尔自定义字段（type=2）值转 true/false 字符串保真（P2）。

    ``_as_str`` 对非 str（JSON bool）返回空串会丢失；布尔字段经 ``_bitwarden_field_value``
    转 true/false 字符串保留语义，文本字段仍经 ``_as_str``。
    """
    path = _write_bitwarden_json(
        tmp_path,
        {
            "items": [
                {
                    "name": "bool",
                    "fields": [
                        {"name": "flag_on", "type": 2, "value": True},
                        {"name": "flag_off", "type": 2, "value": False},
                        {"name": "text", "type": 0, "value": "hello"},
                    ],
                }
            ],
        },
    )
    result = BitwardenImporter().parse(path)
    assert len(result.entries) == 1
    fields = {f.name: f.value for f in result.entries[0].custom_fields}
    assert fields["flag_on"] == "true"
    assert fields["flag_off"] == "false"
    assert fields["text"] == "hello"
