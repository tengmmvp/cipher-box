"""Bitwarden JSON 导入策略。"""

import enum
import json
import logging
from datetime import UTC, datetime
from typing import Any

from ....exceptions import EntryError, ImportFormatError
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
from ...services.entry_validation import validate_plain_entry
from ...services.url_hygiene import sanitize_url_scheme
from .base import (
    ParsedImport,
    _check_import_file_size,
    _merge_bitwarden_secrets,
    _sanitize_totp_secret,
    _validate_items,
)

logger = logging.getLogger(__name__)

_SOURCE_LABEL = "Bitwarden 导入"


def _as_dict(value: Any) -> dict[str, Any]:
    """Bitwarden 嵌套结构守卫：非 dict 一律视为空 dict。

    被污染或损坏的 Bitwarden 导出中，fields/card/identity/login 等字段可能是
    list/str/int 等非 dict 类型，直接 ``.get`` 会抛 AttributeError 中断整个导入
    （单个畸形 item 使全部已解析条目无法导入——拒绝服务）。守卫为空 dict 使解析
    对畸形结构容错，再由末尾 ``validate_plain_entry`` 兜底校验。
    """
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    """Bitwarden 列表字段守卫：非 list 视为空列表，避免字符串被逐字符迭代。"""
    return value if isinstance(value, list) else []


def _as_str(value: Any) -> str:
    """标量字段守卫：非 str 一律视为空串。

    Bitwarden 正常导出的标量字段均为 str；异常导出中可能是 None/数字/嵌套结构。
    强制非 str → '' 防止类型混淆数据进入加密链路破坏 ``metadata_mac`` 载荷的可
    重现性。丢弃而非 ``str(value)`` 转换：异常值多为污染数据，丢弃更安全，且
    ``validate_plain_entry`` 会复核长度。
    """
    return value if isinstance(value, str) else ""


def _parse_bitwarden_date(value: Any) -> str:
    """解析 Bitwarden ISO 日期为 CipherBox 统一 ISO 格式，失败返回空串。

    Bitwarden 的 passwordRevisionDate 等为 ISO 8601 字符串（如
    ``2024-01-15T10:30:00.000Z``）。末尾 ``Z`` 替换为 ``+00:00`` 后解析（显式归一
    与 ``utc_now_iso`` 产物形态一致，requires-python >= 3.12 的 fromisoformat 虽
    已直接接受 Z）；无时区视作 UTC；解析失败返回空串使调用方回退当前时间。
    """
    raw = _as_str(value)
    if not raw:
        return ""
    normalized = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat()


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


class BitwardenFieldType(enum.IntEnum):
    """Bitwarden 自定义字段的 type 字段值映射。

    Bitwarden 导出 JSON 中字段 type 为整数：0=Text, 1=Hidden, 2=Boolean。与
    ``BitwardenItemType`` 同样用 IntEnum 避免裸魔法数字；hidden 字段映射到
    CipherBox 的 ``password`` 自定义字段类型（见 ``_bitwarden_entry_fields``）。
    """

    TEXT = 0
    HIDDEN = 1
    BOOLEAN = 2


def _bitwarden_field_value(field: dict[str, Any]) -> str:
    """提取 Bitwarden 自定义字段值，布尔型转 true/false 字符串保真（转换保真决策）。

    Bitwarden 布尔字段（type=2）值为 JSON bool，``_as_str`` 对非 str 返回空串会丢失；
    转为 ``true``/``false`` 字符串保留语义。文本/隐藏字段经 ``_as_str`` 守卫。
    """
    if field.get("type") == BitwardenFieldType.BOOLEAN:
        return "true" if field.get("value") else "false"
    return _as_str(field.get("value"))


def _bitwarden_entry_fields(item: dict[str, Any]) -> tuple[str, list[CustomField]]:
    """解析 Bitwarden item 的条目类型与自定义字段。

    item_type 经 BitwardenItemType 映射；未知/缺失/非法类型回退 login。所有嵌套
    结构经 _as_dict/_as_list/_as_str 守卫，对畸形 item 容错不抛 AttributeError。
    """
    try:
        item_type = BitwardenItemType(item.get("type", BitwardenItemType.LOGIN))
    except (ValueError, TypeError):
        item_type = BitwardenItemType.LOGIN
    custom_fields = [
        CustomField(
            name=_as_str(field.get("name")) or "自定义字段",
            value=_bitwarden_field_value(field),
            field_type="password" if field.get("type") == BitwardenFieldType.HIDDEN else "text",
        )
        for field in _as_list(item.get("fields"))
        if isinstance(field, dict) and field.get("value") is not None
    ]
    if item_type == BitwardenItemType.NOTE:
        return ENTRY_TYPE_NOTE, custom_fields
    if item_type == BitwardenItemType.CARD:
        card = _as_dict(item.get("card"))
        exp_year = _as_str(card.get("expYear"))
        exp_month = _as_str(card.get("expMonth"))
        if exp_month:
            exp_month = exp_month.zfill(2)
        # 截断为两位年份以匹配卡片常见的 MM/YY 显示格式
        if len(exp_year) == 4:
            exp_year = exp_year[-2:]
        custom_fields.extend(
            [
                CustomField(SPECIAL_FIELD_CARD_HOLDER, _as_str(card.get("cardholderName"))),
                CustomField(SPECIAL_FIELD_CARD_NUMBER, _as_str(card.get("number")), "password"),
                CustomField(
                    SPECIAL_FIELD_CARD_EXPIRY,
                    "/".join(filter(None, [exp_month, exp_year])),
                ),
                CustomField(SPECIAL_FIELD_CARD_CVV, _as_str(card.get("code")), "password"),
            ]
        )
        return ENTRY_TYPE_CARD, custom_fields
    if item_type == BitwardenItemType.IDENTITY:
        identity = _as_dict(item.get("identity"))
        fullname = " ".join(
            filter(
                None,
                [
                    _as_str(identity.get("firstName")),
                    _as_str(identity.get("middleName")),
                    _as_str(identity.get("lastName")),
                ],
            )
        )
        custom_fields.extend(
            [
                CustomField(SPECIAL_FIELD_ID_FULLNAME, fullname),
                CustomField(SPECIAL_FIELD_ID_EMAIL, _as_str(identity.get("email"))),
                CustomField(SPECIAL_FIELD_ID_PHONE, _as_str(identity.get("phone"))),
                CustomField(
                    SPECIAL_FIELD_ID_ADDRESS,
                    " ".join(
                        filter(
                            None,
                            [
                                _as_str(identity.get("address1")),
                                _as_str(identity.get("address2")),
                                _as_str(identity.get("city")),
                                _as_str(identity.get("state")),
                                _as_str(identity.get("postalCode")),
                                _as_str(identity.get("country")),
                            ],
                        )
                    ),
                ),
            ]
        )
        return ENTRY_TYPE_IDENTITY, custom_fields
    return ENTRY_TYPE_LOGIN, custom_fields


class BitwardenImporter:
    """Bitwarden JSON 导出文件的解析策略。

    解析 login/card/identity/note 四种 item 类型，映射 folder 为分类。Bitwarden
    JSON 可完整表达敏感字段，覆盖导入时信任导入数据，仅空值保留已有
    （见 ``_merge_bitwarden_secrets``）。

    对畸形/被污染的导出 JSON 容错：嵌套结构经类型守卫避免 AttributeError 中断整个
    导入；每个条目构造后经 ``validate_plain_entry`` 校验，失败跳过该条目并记录，
    使 ``skip_validation=True`` 假设对本路径成立。
    """

    def parse(self, filepath: str) -> ParsedImport:
        _check_import_file_size(filepath)
        with open(filepath, encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, dict):
            raise ImportFormatError("Bitwarden 导入结构无效")
        items = data.get("items", [])
        if not isinstance(items, list):
            raise ImportFormatError("Bitwarden 导入结构无效")
        _validate_items(items)
        if not items:
            return ParsedImport(
                entries=[],
                entries_data=[],
                overwrite_merger=_merge_bitwarden_secrets,
                source_label=_SOURCE_LABEL,
            )

        folder_map = {
            _as_str(folder.get("id")): _as_str(folder.get("name"))
            for folder in _as_list(data.get("folders"))
            if isinstance(folder, dict) and folder.get("id")
        }

        entries: list[Entry] = []
        entries_data: list[dict[str, str]] = []
        for item in items:
            if not isinstance(item, dict):
                logger.warning("跳过非对象类型的 Bitwarden item")
                continue
            login = _as_dict(item.get("login"))
            entry_type, custom_fields = _bitwarden_entry_fields(item)
            folder_name = folder_map.get(_as_str(item.get("folderId")), "")
            uris = _as_list(login.get("uris"))
            first_uri = uris[0] if uris and isinstance(uris[0], dict) else {}
            url = _as_str(first_uri.get("uri"))
            entry = Entry(
                title=_as_str(item.get("name")),
                username=_as_str(login.get("username")),
                password=_as_str(login.get("password")),
                # url scheme / totp_secret 经模块级清洗，与 CSV/JSON 路径一致
                # （url_hygiene.sanitize_url_scheme / _sanitize_totp_secret）。
                url=sanitize_url_scheme(url),
                notes=_as_str(item.get("notes")),
                custom_fields=custom_fields,
                entry_type=entry_type,
                totp_secret=_sanitize_totp_secret(_as_str(login.get("totp"))),
                is_favorite=bool(item.get("favorite", False)),
                category_name=folder_name,
                # 保留 Bitwarden 密码修改时间（时间戳保真决策）：避免导入后 password_changed_at 全部
                # 冻结为导入时刻，使过期检测把本应过期的密码当作「刚修改」而漏报。
                # passwordRevisionDate 仅 login 有值；note/card 为 null → 空串回退当前时间。
                password_changed_at=_parse_bitwarden_date(login.get("passwordRevisionDate")),
            )
            # 校验类型/长度/自定义字段结构，闭合 skip_validation=True 的假设；失败跳过
            # 单条而非中断整个导入，与 _import_entries 的逐条容错语义一致。
            try:
                validate_plain_entry(entry)
            except EntryError as exc:
                logger.warning(
                    "跳过校验失败的 Bitwarden 条目（crypto_id=%s）: %s",
                    entry.crypto_id or "(未生成)",
                    exc,
                )
                continue
            entries.append(entry)
            entries_data.append(
                {
                    "title": entry.title,
                    "username": entry.username,
                }
            )

        return ParsedImport(
            entries=entries,
            entries_data=entries_data,
            overwrite_merger=_merge_bitwarden_secrets,
            source_label=_SOURCE_LABEL,
        )
