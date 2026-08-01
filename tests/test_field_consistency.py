"""字段集一致性守护测试。

防止字段集在多处定义间漂移：

- ``Entry`` 与 ``RawEntry`` 字段名集合须一致——``crypto_utils.copy_entry_fields``
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
        'Entry/RawEntry 字段名不一致，crypto_utils.copy_entry_fields 的逐字段映射'
        f'需同步更新：仅 Entry={entry_fields - raw_fields}，'
        f'仅 RawEntry={raw_fields - entry_fields}'
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
        'SIGNATURE_ENCRYPTED_FIELD_ORDER 含非加密字段：'
        f'额外={signature - sensitive}'
    )
    assert signature == sensitive - {'title', 'url', 'tags'}


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

    schema_cols: set[str] = set(_TABLE_COLUMNS['entries'])
    repo_cols: set[str] = set(_ENTRY_COLUMNS)
    # id 是 autoincrement PK，不在 INSERT 列(_ENTRY_COLUMNS)，但在建表列。
    assert schema_cols - {'id'} == repo_cols, (
        'entries 表列名在 schema_manager 与 entry_repository 间漂移：'
        f'仅建表列={schema_cols - repo_cols - {"id"}}，'
        f'仅 SQL 列={repo_cols - schema_cols}'
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
