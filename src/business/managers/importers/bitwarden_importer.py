"""Bitwarden JSON 导入策略。"""

import enum
import json
from typing import Any

from ....models import (
    ENTRY_TYPE_CARD,
    ENTRY_TYPE_IDENTITY,
    ENTRY_TYPE_LOGIN,
    ENTRY_TYPE_NOTE,
    SPECIAL_FIELD_CARD_CVV,
    SPECIAL_FIELD_CARD_EXPIRY,
    SPECIAL_FIELD_CARD_HOLDER,
    SPECIAL_FIELD_CARD_NUMBER,
    SPECIAL_FIELD_ID_ADDRESS,
    SPECIAL_FIELD_ID_EMAIL,
    SPECIAL_FIELD_ID_FULLNAME,
    SPECIAL_FIELD_ID_PHONE,
    CustomField,
    Entry,
)
from .base import (
    ParsedImport,
    _merge_bitwarden_secrets,
    _sanitize_totp_secret,
    _sanitize_url_scheme,
    _validate_items,
)

_SOURCE_LABEL = 'Bitwarden 导入'


class BitwardenItemType(enum.IntEnum):
    """Bitwarden item 的 type 字段值映射。

    Bitwarden 导出 JSON 中 type 为整数：1=login, 2=secure note, 3=card, 4=identity。
    用 IntEnum 而非裸整数，使映射具名、防魔法数字误读；未知值回退 login
    （见 _bitwarden_entry_fields）。这是 Bitwarden 外部格式的本地映射，不属于
    CipherBox 类型系统，故独立于 entry_type_schema。
    """

    LOGIN = 1
    NOTE = 2
    CARD = 3
    IDENTITY = 4


def _bitwarden_entry_fields(item: dict[str, Any]) -> tuple[str, list[CustomField]]:
    """解析 Bitwarden item 的条目类型与自定义字段。

    item_type 经 BitwardenItemType 映射；未知/缺失类型回退 login。
    """
    try:
        item_type = BitwardenItemType(item.get('type', BitwardenItemType.LOGIN))
    except ValueError:
        item_type = BitwardenItemType.LOGIN
    custom_fields = [
        CustomField(
            name=field.get('name') or '自定义字段',
            value=str(field.get('value') or ''),
            field_type='password' if field.get('type') == 1 else 'text',
        )
        for field in item.get('fields', [])
        if field.get('value') is not None
    ]
    if item_type == BitwardenItemType.NOTE:
        return ENTRY_TYPE_NOTE, custom_fields
    if item_type == BitwardenItemType.CARD:
        card = item.get('card', {})
        exp_year = str(card.get('expYear', ''))
        exp_month = str(card.get('expMonth', ''))
        if exp_month:
            exp_month = exp_month.zfill(2)
        # 截断为两位年份以匹配卡片常见的 MM/YY 显示格式
        if len(exp_year) == 4:
            exp_year = exp_year[-2:]
        custom_fields.extend([
            CustomField(SPECIAL_FIELD_CARD_HOLDER, str(card.get('cardholderName') or '')),
            CustomField(SPECIAL_FIELD_CARD_NUMBER, str(card.get('number') or ''), 'password'),
            CustomField(
                SPECIAL_FIELD_CARD_EXPIRY,
                '/'.join(filter(None, [exp_month, exp_year])),
            ),
            CustomField(SPECIAL_FIELD_CARD_CVV, str(card.get('code') or ''), 'password'),
        ])
        return ENTRY_TYPE_CARD, custom_fields
    if item_type == BitwardenItemType.IDENTITY:
        identity = item.get('identity', {})
        fullname = ' '.join(filter(None, [
            str(identity.get('firstName') or ''), str(identity.get('middleName') or ''),
            str(identity.get('lastName') or ''),
        ]))
        custom_fields.extend([
            CustomField(SPECIAL_FIELD_ID_FULLNAME, fullname),
            CustomField(SPECIAL_FIELD_ID_EMAIL, str(identity.get('email') or '')),
            CustomField(SPECIAL_FIELD_ID_PHONE, str(identity.get('phone') or '')),
            CustomField(SPECIAL_FIELD_ID_ADDRESS, ' '.join(filter(None, [
                str(identity.get('address1') or ''), str(identity.get('address2') or ''),
                str(identity.get('city') or ''), str(identity.get('state') or ''),
                str(identity.get('postalCode') or ''), str(identity.get('country') or ''),
            ]))),
        ])
        return ENTRY_TYPE_IDENTITY, custom_fields
    return ENTRY_TYPE_LOGIN, custom_fields


class BitwardenImporter:
    """Bitwarden JSON 导出文件的解析策略。

    解析 login/card/identity/note 四种 item 类型，映射 folder 为分类。Bitwarden
    JSON 可完整表达敏感字段，覆盖导入时信任导入数据，仅空值保留已有
    （见 ``_merge_bitwarden_secrets``）。
    """

    def parse(self, filepath: str) -> ParsedImport:
        with open(filepath, encoding='utf-8') as f:
            data = json.load(f)

        items = data.get('items', [])
        if not isinstance(items, list):
            raise ValueError('Bitwarden 导入结构无效')
        _validate_items(items)
        if not items:
            return ParsedImport(
                entries=[],
                entries_data=[],
                overwrite_merger=_merge_bitwarden_secrets,
                source_label=_SOURCE_LABEL,
            )

        folder_map = {
            folder.get('id'): folder.get('name', '')
            for folder in data.get('folders', [])
            if folder.get('id')
        }

        # 解析 Bitwarden 条目
        entries: list[Entry] = []
        entries_data: list[dict[str, str]] = []
        for item in items:
            login = item.get('login', {})
            entry_type, custom_fields = _bitwarden_entry_fields(item)
            folder_name = folder_map.get(item.get('folderId'), '')
            uris = login.get('uris') or []
            url = uris[0].get('uri', '') if uris else ''
            entry = Entry(
                title=item.get('name', ''),
                username=login.get('username', ''),
                password=login.get('password', ''),
                # url scheme / totp_secret 经模块级清洗，与 CSV/JSON 路径一致
                # （_sanitize_url_scheme / _sanitize_totp_secret）。
                url=_sanitize_url_scheme(url),
                notes=item.get('notes', ''),
                custom_fields=custom_fields,
                entry_type=entry_type,
                totp_secret=_sanitize_totp_secret(login.get('totp', '')),
                is_favorite=item.get('favorite', False),
                category_name=folder_name,
            )
            entries.append(entry)
            entries_data.append({
                'title': item.get('name', ''),
                'username': login.get('username', ''),
            })

        return ParsedImport(
            entries=entries,
            entries_data=entries_data,
            overwrite_merger=_merge_bitwarden_secrets,
            source_label=_SOURCE_LABEL,
        )
