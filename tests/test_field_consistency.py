"""字段集一致性守护测试。

防止字段集在多处定义间漂移：

- ``Entry`` 与 ``RawEntry`` 字段名集合须一致——``entry_view_decryption.copy_entry_fields``
  手写逐字段映射，任一 dataclass 加字段需同步更新，否则映射遗漏导致字段丢失。
- 加密字段集（``SENSITIVE_ENCRYPTED_FIELDS``）被 ``re_encryption`` 重加密与
  ``crypto_utils`` 加解密引用，新增加密字段须三处同步。
"""

import dataclasses

import pytest

from src.business.services.crypto_utils import SENSITIVE_ENCRYPTED_FIELDS
from src.business.services.metadata_signer import SIGNATURE_ENCRYPTED_FIELD_ORDER
from src.business.services.re_encryption import _ENCRYPTED_ENTRY_FIELDS
from src.models import Entry, RawEntry


def test_entry_and_raw_entry_share_field_names():
    """Entry 与 RawEntry 字段名集合须一致，防 copy_entry_fields 手写映射漂移。"""
    entry_fields = {f.name for f in dataclasses.fields(Entry)}
    raw_fields = {f.name for f in dataclasses.fields(RawEntry)}
    assert entry_fields == raw_fields, (
        "Entry/RawEntry 字段名不一致，entry_view_decryption.copy_entry_fields 的"
        f"逐字段映射需同步更新：仅 Entry={entry_fields - raw_fields}，"
        f"仅 RawEntry={raw_fields - entry_fields}"
    )


def test_encrypted_field_set_single_source():
    """re_encryption._ENCRYPTED_ENTRY_FIELDS 须引用 crypto_utils 单一事实源。"""
    assert tuple(_ENCRYPTED_ENTRY_FIELDS) == SENSITIVE_ENCRYPTED_FIELDS


def test_signature_encrypted_field_order_is_subset():
    """SIGNATURE_ENCRYPTED_FIELD_ORDER 须是 SENSITIVE_ENCRYPTED_FIELDS 的子集且顺序固定。

    签名绑定的加密字段 = 全部加密字段减去在载荷顶层以明文签名的 title/url/tags。
    改顺序或字段集会破坏已有数据的 metadata_mac，故以测试守护此不变量。
    """
    sensitive = set(SENSITIVE_ENCRYPTED_FIELDS)
    signature = set(SIGNATURE_ENCRYPTED_FIELD_ORDER)
    assert signature <= sensitive, (
        f"SIGNATURE_ENCRYPTED_FIELD_ORDER 含非加密字段：额外={signature - sensitive}"
    )
    assert signature == sensitive - {"title", "url", "tags"}


def test_encrypted_entry_columns_single_source():
    """加密字段集的 ``{f}_enc`` 列集须与 entries 表实际 _enc 列集一致（QL-046）。

    entry_manager.build_encrypted_entry 与 crypto_utils.build_encrypted_entry_fields
    已改为对 SENSITIVE_ENCRYPTED_FIELDS 循环产出（加密侧单一事实源跟随），本测试
    把该事实源再与数据库列单一事实源（entry_repository._ENTRY_COLUMNS）对齐：
    逻辑字段名→``_enc`` 列的映射漂移（如新增加密字段未建列、或建列未登记字段）
    在此立即失败。
    """
    from src.database.entry_repository import _ENTRY_COLUMNS

    logical_enc_columns = {f"{field}_enc" for field in SENSITIVE_ENCRYPTED_FIELDS}
    table_enc_columns = {column for column in _ENTRY_COLUMNS if column.endswith("_enc")}
    assert logical_enc_columns == table_enc_columns, (
        "SENSITIVE_ENCRYPTED_FIELDS 与 entries 表 _enc 列集漂移："
        f"仅逻辑字段={logical_enc_columns - table_enc_columns}，"
        f"仅表列={table_enc_columns - logical_enc_columns}"
    )


def test_build_encrypted_output_covers_all_sensitive_fields(vault, entry_mgr, make_entry):
    """两条加密构建路径产出的密文字段集 == 单一事实源（QL-046）。

    EntryManager.build_encrypted_entry（单条 CRUD/导入共用）与 crypto_utils.
    build_encrypted_entry_fields（备份恢复重建共用）此前手工枚举加密字段——新增
    加密字段时解密/校验侧响亮失败而加密侧静默丢字段（恢复往返断裂）。现二者对
    SENSITIVE_ENCRYPTED_FIELDS 循环产出；本测试以「每个加密字段写入可区分明文 →
    构建产出的每个字段必须是有效密文且解密回原明文」守护完备性：字段集漂移
    （常量加了字段而构建侧未跟随）在此立即失败。
    """
    import json

    from src.business.services.crypto_utils import (
        build_encrypted_entry_fields,
        decrypt_field,
        require_vault_key,
    )
    from src.models import CustomField

    plaintext = {
        "title": "t-标题",
        "username": "u-用户",
        "password": "p-密码",
        "url": "https://url-x",
        "tags": "tag-1",
        "notes": "n-备注",
        "totp_secret": "JBSWY3DPEHPK3PXP",
    }
    entry = make_entry(
        **plaintext,
        custom_fields=[CustomField(name="f-字段", value="v-值")],
    )

    # 路径 1：EntryManager.build_encrypted_entry（Entry → RawEntry）
    raw = entry_mgr.build_encrypted_entry(
        entry, "cid-consistency-guard", "2026-01-01T00:00:00+00:00"
    )
    # 路径 2：crypto_utils.build_encrypted_entry_fields（明文 dict → 密文 dict）
    # custom_fields 沿备份恢复的 portable 形态（CustomField.to_dict 的键结构）
    item = {
        **plaintext,
        "custom_fields": [{"name": "f-字段", "value": "v-值", "field_type": "text"}],
    }
    enc_dict = build_encrypted_entry_fields(item, require_vault_key(vault), "cid-consistency-guard")

    # 两条路径的产出键集都恰为单一事实源（custom_fields 在 RawEntry 上为密文 str）
    assert set(enc_dict.keys()) == set(SENSITIVE_ENCRYPTED_FIELDS)
    key = require_vault_key(vault)
    for field in SENSITIVE_ENCRYPTED_FIELDS:
        cipher = enc_dict[field]
        # 每个字段都是有效密文（非空明文 → cb2: 前缀密文，而非静默丢字段后的空串）
        assert cipher.startswith("cb2:"), f"build_encrypted_entry_fields 漏加密 {field}"
        raw_cipher = getattr(raw, field)
        assert raw_cipher.startswith("cb2:"), f"build_encrypted_entry 漏加密 {field}"
        # 就地往返：解密回原明文（custom_fields 为 JSON 序列化形态，比较解析结构）
        expected_plain = (
            [{"name": "f-字段", "value": "v-值", "field_type": "text"}]
            if field == "custom_fields"
            else plaintext[field]
        )
        for got in (
            decrypt_field(cipher, key, "cid-consistency-guard", field),
            decrypt_field(raw_cipher, key, "cid-consistency-guard", field),
        ):
            if field == "custom_fields":
                assert json.loads(got) == expected_plain
            else:
                assert got == expected_plain


def test_entries_table_columns_single_source():
    """schema_manager 建表列与 entry_repository SQL 列须一致（除 autoincrement id）。

    两份列名列表描述同一张 entries 表：``schema_manager._TABLE_COLUMNS`` 用于
    CREATE TABLE / schema 校验，``entry_repository._ENTRY_COLUMNS`` 派生
    INSERT/UPDATE/SELECT SQL 与加密字段断言。新增列须两处同步——只改一处会在某一
    运行路径（新建库 INSERT 或旧库 SELECT）才暴露 ``sqlite3.OperationalError``，
    模块加载期不报错。
    """
    from src.database.entry_repository import _ENTRY_COLUMNS
    from src.database.schema_manager import _TABLE_COLUMNS

    schema_cols: set[str] = set(_TABLE_COLUMNS["entries"])
    repo_cols: set[str] = set(_ENTRY_COLUMNS)
    # id 是 autoincrement PK，不在 INSERT 列(_ENTRY_COLUMNS)，但在建表列。
    assert schema_cols - {"id"} == repo_cols, (
        "entries 表列名在 schema_manager 与 entry_repository 间漂移："
        f"仅建表列={schema_cols - repo_cols - {'id'}}，"
        f"仅 SQL 列={repo_cols - schema_cols}"
    )


def test_entry_signature_payload_keys_match_column_getters():
    """签名载荷键族与 entries 列集一致（除 metadata_mac，加 id）（SEC-073 补充守护）。

    _PAYLOAD_ROW_ATTRS 手拷贝列名，新增/改名非加密列漏改会使签名载荷不跟随——
    全库验签失配或新列脱离 MAC 保护，漂移在此立即失败。
    """
    from src.business.services.metadata_signer import _PAYLOAD_ROW_ATTRS
    from src.database.entry_repository import _ENTRY_COLUMN_GETTERS

    expected = (set(_ENTRY_COLUMN_GETTERS) - {"metadata_mac"}) | {"id"}
    assert set(_PAYLOAD_ROW_ATTRS) == expected, (
        "签名载荷键族与 entries 列集漂移："
        f"仅载荷键={set(_PAYLOAD_ROW_ATTRS) - expected}，"
        f"仅列集键={expected - set(_PAYLOAD_ROW_ATTRS)}"
    )


def test_entry_query_rejects_conflicting_deleted_flags():
    """EntryQuery 拒绝 deleted_only 与 include_deleted 同时为 True（互斥校验）。"""
    from src.database.types import EntryQuery

    # 两者互斥：deleted_only 仅回收站 vs include_deleted 含回收站
    with pytest.raises(ValueError):
        EntryQuery(deleted_only=True, include_deleted=True)
    # 单独使用合法
    EntryQuery(deleted_only=True)
    EntryQuery(include_deleted=True)
    EntryQuery()


def test_strict_decrypt_paths_cover_all_sensitive_fields(vault, entry_mgr, make_entry):
    """两条严格解密路径产出的字段键集 == SENSITIVE_ENCRYPTED_FIELDS 派生集（QL-018）。

    EntryManager._decrypt_for_export（Entry 组装）与 backup/collector.
    decrypt_entry_to_portable_dict（portable dict）是导出/备份的两条同构解密链路，
    此前各自手工枚举加密字段，新增加密字段会静默漏解密。二者现统一消费
    decrypt_string_fields_strict（STRING_ENCRYPTED_FIELDS 单一事实源循环）；
    本测试以「每个加密字段写入可区分明文 → 两条路径必须解出该明文」守护覆盖
    完备性：字段集漂移（常量加了字段而消费方未跟随）在此立即失败。
    """
    from src.business.services.backup.collector import decrypt_entry_to_portable_dict
    from src.business.services.crypto_utils import (
        SENSITIVE_ENCRYPTED_FIELDS,
        STRING_ENCRYPTED_FIELDS,
        require_vault_key,
    )
    from src.models import CustomField

    plaintext = {
        "title": "t-标题",
        "username": "u-用户",
        "password": "p-密码",
        "url": "https://url-x",
        "tags": "tag-1",
        "notes": "n-备注",
        "totp_secret": "JBSWY3DPEHPK3PXP",
    }
    entry_id = entry_mgr.add_entry(
        make_entry(
            **plaintext,
            custom_fields=[CustomField(name="f-字段", value="v-值")],
        )
    )
    raw = entry_mgr.db.get_entry(entry_id)
    assert raw is not None
    key = require_vault_key(vault)

    # 路径 1：导出 Entry 组装（直调视图解密器，与生产链路一致，MAINT-118）
    exported = entry_mgr._view_decryptor.decrypt_entry_for_export(raw, include_secrets=True)
    # 路径 2：备份/恢复 portable dict
    portable = decrypt_entry_to_portable_dict(raw, key, include_secrets=True)

    # portable dict 的加密字段键集须完整覆盖单一事实源（custom_fields 单独处理）
    assert set(STRING_ENCRYPTED_FIELDS) <= set(portable.keys())
    for field, expected in plaintext.items():
        assert portable[field] == expected, f"portable dict 漏解密 {field}"
        assert getattr(exported, field) == expected, f"导出 Entry 漏解密 {field}"
    assert portable["custom_fields"][0]["name"] == "f-字段"
    assert exported.custom_fields[0].value == "v-值"
    # SENSITIVE_ENCRYPTED_FIELDS（含 custom_fields）在两条路径各有承载：
    # Entry 侧为 custom_fields 属性，portable 侧为同名键
    assert set(SENSITIVE_ENCRYPTED_FIELDS) <= {
        *STRING_ENCRYPTED_FIELDS,
        "custom_fields",
    }

    # include_secrets=False：password/totp_secret 不解密（空串），其余字段仍覆盖
    exported_no_secrets = entry_mgr._view_decryptor.decrypt_entry_for_export(
        raw, include_secrets=False
    )
    portable_no_secrets = decrypt_entry_to_portable_dict(raw, key, include_secrets=False)
    for result in (exported_no_secrets.password, portable_no_secrets["password"]):
        assert result == ""
    assert exported_no_secrets.title == plaintext["title"]
    assert portable_no_secrets["notes"] == plaintext["notes"]
