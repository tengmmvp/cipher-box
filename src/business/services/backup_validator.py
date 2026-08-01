"""备份数据校验：恢复前对可移植载荷做结构、键完整性与长度上限校验。所有函数无状态。"""

import logging
from collections.abc import Set
from datetime import datetime
from typing import Any

from ...crypto.password_generator import MAX_STRENGTH_SCORE
from ...exceptions import BackupError, PayloadTooLargeError
from ...models import (
    ENTRY_TYPES,
    MAX_CUSTOM_FIELD_NAME,
    MAX_CUSTOM_FIELD_VALUE,
    MAX_CUSTOM_FIELDS_PER_ENTRY,
    MAX_ENTRIES_LIMIT,
    MAX_ENTRY_PAYLOAD_SIZE,
    MAX_FIELD_NOTES,
    MAX_FIELD_PASSWORD,
    MAX_FIELD_TAGS,
    MAX_FIELD_TITLE,
    MAX_FIELD_TOTP_SECRET,
    MAX_FIELD_URL,
    MAX_FIELD_USERNAME,
    MAX_PASSWORD_HISTORY,
    CustomField,
    is_real_int,
)
from .backup_header_codec import BACKUP_FORMAT, BACKUP_VERSION
from .crypto_utils import STRING_ENCRYPTED_FIELDS

logger = logging.getLogger(__name__)

# 备份语境别名（指向 models 单一事实源），非独立的第二份上限。
MAX_BACKUP_ENTRIES = MAX_ENTRIES_LIMIT
MAX_ENTRY_JSON_SIZE = MAX_ENTRY_PAYLOAD_SIZE
MAX_HISTORY_PER_ENTRY = MAX_PASSWORD_HISTORY * 2  # 每条目历史上限，2 倍余量
MAX_BACKUP_CATEGORIES = 10_000  # 备份分类数量上限（远超实际，防恶意超大批量恢复致 UI 冻结）

# 备份校验的字符串型加密字段→明文长度上限映射，派生自 models 单一事实源（SEC-006）：
# 使恢复校验与加密侧 ENTRY_FIELD_LIMITS 对齐，避免大字段绕过 validate_plain_entry
# 落库后致编辑拒绝或 UI 冻结。
_BACKUP_FIELD_LIMITS: dict[str, int] = {
    "title": MAX_FIELD_TITLE,
    "username": MAX_FIELD_USERNAME,
    "password": MAX_FIELD_PASSWORD,
    "url": MAX_FIELD_URL,
    "tags": MAX_FIELD_TAGS,
    "notes": MAX_FIELD_NOTES,
    "totp_secret": MAX_FIELD_TOTP_SECRET,
}
# 启动期断言：STRING_ENCRYPTED_FIELDS 须全部纳入 _BACKUP_FIELD_LIMITS，否则
# validate_entry_fields 索引会 KeyError；模块加载即暴露字段集漂移。
_missing_limits = set(STRING_ENCRYPTED_FIELDS) - set(_BACKUP_FIELD_LIMITS)
if _missing_limits:
    raise RuntimeError(
        f"STRING_ENCRYPTED_FIELDS 未全部纳入 _BACKUP_FIELD_LIMITS：{sorted(_missing_limits)}"
    )
# 启动期断言：备份校验的自定义字段类型集须与 CustomField._VALID_FIELD_TYPES 一致，
# 漏改一侧会产生"能创建却无法备份恢复"的往返断裂。用 raise 而非 assert（-O 剥离 assert）。
if {"text", "password", "url", "email"} != CustomField._VALID_FIELD_TYPES:
    raise RuntimeError("备份自定义字段类型集与 CustomField._VALID_FIELD_TYPES 不一致")

# 备份载荷各 TypedDict 的必备键集。提为模块级常量供 validate_* 复用；
# backup_payload 启动期断言 Portable*.__annotations__ 与此一致，消除双重维护漂移。
REQUIRED_CATEGORY_KEYS = frozenset(
    {
        "id",
        "name",
        "icon_char",
        "color",
        "sort_order",
        "created_at",
    }
)
REQUIRED_ENTRY_KEYS = frozenset(
    {
        "id",
        "crypto_id",
        "title",
        "username",
        "password",
        "url",
        "category_id",
        "tags",
        "notes",
        "custom_fields",
        "is_favorite",
        "is_deleted",
        "password_strength",
        "entry_type",
        "totp_secret",
        "created_at",
        "updated_at",
        "deleted_at",
        "password_changed_at",
    }
)
REQUIRED_HISTORY_KEYS = frozenset({"entry_id", "password", "changed_at"})

# 条目时间戳字段（ISO 8601 字符串，64 字节上限），与字符串型加密字段长度上限分离。
_ENTRY_TIMESTAMP_FIELDS: tuple[str, ...] = (
    "created_at",
    "updated_at",
    "deleted_at",
    "password_changed_at",
)

# 启动期断言：字符串型加密字段须全部纳入 REQUIRED_ENTRY_KEYS，否则 validate_entry_fields
# 直接索引会键缺失；模块加载即暴露字段集漂移。用显式 raise 而非 assert（python -O
# 会剔除 assert），空集同样拒绝防校验被静默放过。
if not STRING_ENCRYPTED_FIELDS:
    raise RuntimeError("STRING_ENCRYPTED_FIELDS 为空，明文长度校验将被静默跳过")
_missing_enc_fields = set(STRING_ENCRYPTED_FIELDS) - REQUIRED_ENTRY_KEYS
if _missing_enc_fields:
    raise RuntimeError(
        "STRING_ENCRYPTED_FIELDS 未全部纳入 REQUIRED_ENTRY_KEYS，"
        f"校验会因键缺失而失败：{sorted(_missing_enc_fields)}"
    )


def validate_restore_data(data: dict[str, Any]) -> None:
    """恢复前对完整备份数据做结构、键完整性与数量上限的总校验。

    校验顶层标识与必备键后委托 validate_categories/validate_entries/validate_history
    分项校验，任一项不符即抛出，使恢复在写库前中止避免半成品入库。

    Raises:
        BackupError: 格式标识、版本、顶层结构或子项内容不符。
        PayloadTooLargeError: 条目/历史/分类数量超出上限。
    """
    if data.get("format") != BACKUP_FORMAT:
        raise BackupError("备份格式标识无效")
    version = data.get("version")
    if version != BACKUP_VERSION:
        raise BackupError(f"不支持的备份格式版本：{version}（当前支持 v{BACKUP_VERSION}）")
    # 严格校验顶层必备键，缺键直接拒绝（不以默认空列表静默放行），允许额外键。
    required_top_keys = {"format", "version", "entries", "categories", "password_history"}
    missing = required_top_keys - set(data)
    if missing:
        raise BackupError(f"备份数据缺少必备字段：{sorted(missing)}")
    entries = data["entries"]
    categories = data["categories"]
    history = data["password_history"]
    if not all(isinstance(items, list) for items in (entries, categories, history)):
        raise BackupError("备份数据结构无效")
    if len(entries) > MAX_BACKUP_ENTRIES:
        raise PayloadTooLargeError("备份条目数量超出限制")
    if len(history) > len(entries) * MAX_HISTORY_PER_ENTRY:
        raise PayloadTooLargeError("密码历史数量超出限制")
    if len(categories) > MAX_BACKUP_CATEGORIES:
        raise PayloadTooLargeError("备份分类数量超出限制")

    category_ids = validate_categories(categories)
    entry_ids = validate_entries(entries, category_ids)
    validate_history(history, entry_ids)


def validate_categories(categories: list[dict[str, Any]]) -> set[int]:
    """验证备份分类数据，返回有效的分类 ID 集合。"""
    category_ids: set[int] = set()
    for item in categories:
        if not isinstance(item, dict):
            raise BackupError("备份分类格式无效")
        require_keys(item, REQUIRED_CATEGORY_KEYS, "备份分类")
        category_id = item["id"]
        if not is_real_int(category_id):
            raise BackupError("备份分类 ID 无效")
        if category_id in category_ids:
            raise BackupError("备份分类 ID 重复")
        category_ids.add(category_id)
        require_text(item["name"], "分类名称", 256, allow_empty=False)
        require_text(item["icon_char"], "分类图标", 32)
        require_text(item["color"], "分类颜色", 32)
        require_text(item["created_at"], "分类创建时间", 64)
        if not is_real_int(item["sort_order"]):
            raise BackupError("分类排序值无效")
    return category_ids


def validate_entry_fields(item: dict[str, Any], category_ids: set[int]) -> None:
    """验证单条备份条目的必填键、字段类型和文本长度。"""
    # 先 require_keys（O(1) 项数，不触及值）再做字节估算，避免超大非必填键触发 DoS。
    require_keys(item, REQUIRED_ENTRY_KEYS, "备份条目")
    if sum(len(str(v).encode("utf-8")) for v in item.values()) > MAX_ENTRY_JSON_SIZE:
        raise BackupError("备份条目格式或大小无效")

    # 字符串型加密字段明文长度按字段精确上限校验（_BACKUP_FIELD_LIMITS，SEC-006），与
    # 加密侧 ENTRY_FIELD_LIMITS 对齐；custom_fields 为 list 由下方单独校验。
    for field in STRING_ENCRYPTED_FIELDS:
        require_text(item[field], f"条目字段 {field}", _BACKUP_FIELD_LIMITS[field])
    # 时间戳字段：64 字节上限（ISO 8601 字符串）
    for field in _ENTRY_TIMESTAMP_FIELDS:
        require_text(item[field], f"条目字段 {field}", 64)
    # ISO 8601 格式校验：非空时间戳格式无效则拒绝整条（此前仅 warning 致无效时间戳
    # 入库，使 security_analyzer 的过期检测静默失效）。空值跳过（如未删除条目的 deleted_at）。
    for key in _ENTRY_TIMESTAMP_FIELDS:
        val = item.get(key, "")
        if val:
            try:
                datetime.fromisoformat(val)
            except (ValueError, TypeError):
                raise BackupError(f"备份条目字段 {key} 日期格式无效") from None

    category_id = item["category_id"]
    if category_id is not None:
        if not is_real_int(category_id):
            raise BackupError("备份条目分类 ID 类型无效")
        if category_id not in category_ids:
            raise BackupError("备份条目引用了不存在的分类")
    if not isinstance(item["is_favorite"], bool) or not isinstance(item["is_deleted"], bool):
        raise BackupError("备份条目布尔字段无效")
    strength = item["password_strength"]
    if not is_real_int(strength) or not 0 <= strength <= MAX_STRENGTH_SCORE:
        raise BackupError("备份条目密码强度无效")
    if item["entry_type"] not in ENTRY_TYPES:
        raise BackupError("备份条目类型无效")


def validate_entry_custom_fields(fields: list[dict[str, Any]]) -> None:
    """验证自定义字段列表结构（数量、键完整性、类型）。数量上限与 ``Entry.from_dict`` 一致。"""
    if not isinstance(fields, list) or len(fields) > MAX_CUSTOM_FIELDS_PER_ENTRY:
        raise BackupError("备份自定义字段结构无效")
    for field in fields:
        if not isinstance(field, dict):
            raise BackupError("备份自定义字段格式无效")
        require_keys(field, {"name", "value", "field_type"}, "备份自定义字段")
        require_text(field["name"], "自定义字段名称", MAX_CUSTOM_FIELD_NAME)
        require_text(field["value"], "自定义字段值", MAX_CUSTOM_FIELD_VALUE)
        if field["field_type"] not in {"text", "password", "url", "email"}:
            raise BackupError("备份自定义字段类型无效")


def validate_entries(entries: list[dict[str, Any]], category_ids: set[int]) -> set[int]:
    """验证备份条目数据，返回有效的 entry_ids 集合。"""
    entry_ids: set[int] = set()
    crypto_ids: set[str] = set()
    for item in entries:
        if not isinstance(item, dict):
            raise BackupError("备份条目格式无效")
        validate_entry_fields(item, category_ids)

        entry_id = item["id"]
        if not is_real_int(entry_id) or entry_id <= 0:
            raise BackupError("备份条目 ID 无效")
        if entry_id in entry_ids:
            raise BackupError("备份条目 ID 重复")
        entry_ids.add(entry_id)
        crypto_id = item["crypto_id"]
        if (
            not isinstance(crypto_id, str)
            or len(crypto_id) != 32
            or any(char not in "0123456789abcdef" for char in crypto_id)
        ):
            raise BackupError("备份条目加密标识无效")
        if crypto_id in crypto_ids:
            raise BackupError("备份条目加密标识重复")
        crypto_ids.add(crypto_id)

        validate_entry_custom_fields(item["custom_fields"])
    return entry_ids


def validate_history(history: list[dict[str, Any]], entry_ids: set[int]) -> None:
    """验证备份密码历史数据。"""
    for item in history:
        if not isinstance(item, dict):
            raise BackupError("备份密码历史格式无效")
        require_keys(item, REQUIRED_HISTORY_KEYS, "备份密码历史")
        entry_id = item["entry_id"]
        # 与 validate_entries 的 ID 校验对齐：拒绝 bool/float 等伪装成 int 的类型
        if not is_real_int(entry_id):
            raise BackupError("备份密码历史 entry_id 必须为整数")
        if entry_id not in entry_ids:
            raise BackupError("备份密码历史引用了不存在的条目")
        require_text(item["password"], "密码历史密码", MAX_FIELD_PASSWORD)
        require_text(item["changed_at"], "密码历史时间", 64)


def require_keys(item: dict[str, Any], expected: Set[str], label: str) -> None:
    """验证 item 是否恰好包含所需的键集合，拒绝多余或缺失的键。"""
    if set(item) != expected:
        raise BackupError(f"{label}字段不完整")


def require_text(value: Any, label: str, max_bytes: int, allow_empty: bool = True) -> None:
    """校验 value 为字符串且 UTF-8 字节长度不超过 max_bytes。

    allow_empty 为 False 时额外拒绝空白串；超长抛 :class:`PayloadTooLargeError`，
    其余失败抛 :class:`BackupError`（二者经 ``to_user_message`` 呈现不同文案）。
    """
    if not isinstance(value, str):
        raise BackupError(f"{label}类型无效")
    if not allow_empty and not value.strip():
        raise BackupError(f"{label}不能为空")
    if len(value.encode("utf-8")) > max_bytes:
        raise PayloadTooLargeError(f"{label}过大")
