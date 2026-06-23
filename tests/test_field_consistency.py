"""字段集一致性守护测试。

防止字段集在多处定义间漂移：

- ``Entry`` 与 ``RawEntry`` 字段名集合须一致——``crypto_utils.copy_entry_fields``
  手写逐字段映射，任一 dataclass 加字段需同步更新，否则映射遗漏导致字段丢失。
- 加密字段集（``SENSITIVE_ENCRYPTED_FIELDS``）被 ``re_encryption`` 重加密与
  ``crypto_utils`` 加解密引用，新增加密字段须三处同步。
"""

import dataclasses

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
    """re_encryption._ENCRYPTED_ENTRY_FIELDS 须引用 crypto_utils 单一来源。"""
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
