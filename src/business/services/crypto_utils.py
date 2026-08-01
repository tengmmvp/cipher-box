"""业务层共享加密工具函数。"""

from __future__ import annotations

import json
import logging
from dataclasses import replace
from typing import TYPE_CHECKING, Any, TypedDict

if TYPE_CHECKING:
    from typing_extensions import Unpack

    from ...database.db_manager import DatabaseManager
    from ..managers.vault_manager import VaultManager

from ...crypto.encryption import EncryptionEngine
from ...exceptions import DecryptionError, VaultLockedError
from ...models import CustomField, Entry, RawEntry

logger = logging.getLogger(__name__)


class EntryOverrides(TypedDict, total=False):
    """copy_entry_fields 的可选覆盖字段，键集合与 :class:`Entry` 字段一一对应。

    total=False 全可选。custom_fields 解密路径传 ``list[CustomField]``；password
    运行时可为 :class:`Sensitive`（str 子类），标注为 str 兼容二者。
    """

    id: int | None
    crypto_id: str
    title: str
    username: str
    password: str
    url: str
    category_id: int | None
    category_name: str
    tags: str
    notes: str
    custom_fields: list[CustomField]
    is_favorite: bool
    is_deleted: bool
    password_strength: int
    entry_type: str
    totp_secret: str
    created_at: str
    updated_at: str
    deleted_at: str
    password_changed_at: str
    metadata_mac: str
    integrity_error: bool
    integrity_message: str
    password_present: bool
    totp_present: bool


# 条目需加密的敏感字段名（逻辑属性名）。加解密字段集的单一事实源，新增加密字段
# 须同步 decrypt/build 与 metadata_signer._payload 的 _enc_hash 绑定。custom_fields
# 序列化为 JSON 字符串再加密。
SENSITIVE_ENCRYPTED_FIELDS: tuple[str, ...] = (
    "title",
    "username",
    "password",
    "url",
    "tags",
    "notes",
    "totp_secret",
    "custom_fields",
)

# 字符串型加密字段（custom_fields 为 list，单独校验），供明文校验复用的单一事实源。
STRING_ENCRYPTED_FIELDS: tuple[str, ...] = tuple(
    f for f in SENSITIVE_ENCRYPTED_FIELDS if f != "custom_fields"
)


def require_vault_key(vault_manager: VaultManager) -> bytes:
    """获取保险库加密密钥，未解锁时抛出 VaultLockedError。

    vault.key 自身已 fail-fast 守卫（MAINT-009）；本函数保留 is_unlocked 前置检查
    收紧 unlock 窗口（unlock 在 vault_meta_mac 校验通过前 key 已装入但 is_unlocked
    仍为 False，前置检查在此窄窗即抛，无需依赖 key 守卫的二次判定）。

    Args:
        vault_manager: 保险库管理器，提供解锁状态与加密密钥。

    Returns:
        当前有效的 32 字节 AES-256 主密钥。

    Raises:
        VaultLockedError: 保险库未解锁或正处 unlock 窄窗时抛出。
    """
    if not vault_manager.is_unlocked:
        raise VaultLockedError("保险库未解锁")
    return vault_manager.key


def entry_aad(crypto_id: str, field_name: str) -> str:
    """构造条目字段加密的标准 AAD：将 crypto_id 与 field_name 纳入 AAD，绑定密文到
    具体条目与字段，防密文在条目间或字段间置换。"""
    return f"entry:{crypto_id}:{field_name}"


def category_crypto_id(category_id: int) -> str:
    """构造分类名加密的 crypto_id。

    分类名 AAD 的单一事实源，与 entry_aad 组合：``entry_aad(category_crypto_id(id), 'category_name')``。
    """
    return f"category-{category_id}"


def encrypt_field(plaintext: str, key: bytes | bytearray, crypto_id: str, field_name: str) -> str:
    """加密单个条目字段。统一入口保证 AAD 构造一致；空串亦经 AES-GCM 加密确保 AAD 始终参与认证。

    Args:
        plaintext: 待加密的明文字段值。
        key: AES-256 密钥。
        crypto_id: 条目加密标识，与 field_name 共同构成 AAD，绑定密文到具体条目与字段。
        field_name: 字段名称，参与 AAD 防字段间密文置换。
    """
    return EncryptionEngine.encrypt(plaintext, key, entry_aad(crypto_id, field_name))


def decrypt_field(
    encrypted: str,
    key: bytes | bytearray,
    crypto_id: str,
    field_name: str,
    *,
    strict: bool = False,
) -> str:
    """解密单个条目字段，统一入口保证 AAD 与容错策略一致。

    Args:
        encrypted: 密文字符串。
        key: AES-256 密钥。
        crypto_id: 条目加密标识。
        field_name: 字段名称。
        strict: 为 True 时解密失败抛出 DecryptionError（ValueError 子类），否则返回空字符串。
    """
    if not encrypted:
        return ""
    try:
        return EncryptionEngine.decrypt(encrypted, key, entry_aad(crypto_id, field_name))
    except DecryptionError:
        # 显式捕获 DecryptionError（ValueError 子类）而非宽泛 ValueError，使
        # 「密文损坏」语义清晰，不吞掉其他 ValueError。
        if strict:
            raise
        logger.warning(
            "字段解密失败（容错模式）: crypto_id=%s field=%s，密文可能损坏",
            crypto_id,
            field_name,
        )
        return ""


def matches_search(entry: Entry | RawEntry, query: str) -> bool:
    """检查条目是否匹配搜索关键词（大小写不敏感，搜 title/username/url/tags）。

    Args:
        entry: 待匹配的明文 Entry 摘要。生产路径不应传入 RawEntry。
        query: 搜索关键词，空串匹配所有。
    """
    if not query:
        return True
    kw = query.lower()
    username = entry.username or ""
    return (
        kw in (entry.title or "").lower()
        or kw in username.lower()
        or kw in (entry.url or "").lower()
        or kw in (entry.tags or "").lower()
    )


def matches_search_lower(
    lower: tuple[str, str, str, str],
    query: str,
) -> bool:
    """检查条目是否匹配搜索关键词，复用预计算的小写字段值，省去每条目 4 次 ``.lower()``。

    供批量搜索热路径消除 N×4 次 ``.lower()`` 开销，匹配语义与 :func:`matches_search` 一致。

    Args:
        lower: 预计算小写形式的 (title, username, url, tags)。
        query: 搜索关键词，空串匹配所有。
    """
    if not query:
        return True
    kw = query.lower()
    return kw in lower[0] or kw in lower[1] or kw in lower[2] or kw in lower[3]


def matches_tag(entry: Entry, tag: str) -> bool:
    """检查条目是否含指定标签（大小写不敏感精确匹配），解析逻辑与 ``Entry.get_tag_list()`` 一致。"""
    if not tag:
        return True
    tag_lower = tag.strip().lower()
    entry_tags = [t.strip().lower() for t in (entry.tags or "").split(",") if t.strip()]
    return tag_lower in entry_tags


def copy_entry_fields(raw: RawEntry, **overrides: Unpack[EntryOverrides]) -> Entry:
    """从密文态 RawEntry 构建明文 Entry，按需覆盖字段。

    RawEntry 与 Entry 是不同 dataclass，不能跨类型 ``dataclasses.replace``（产出 RawEntry），
    故直接构造。custom_fields 默认空 list，解密路径应在 overrides 传入解密后的 list。
    """
    return Entry(
        id=overrides.get("id", raw.id),
        crypto_id=overrides.get("crypto_id", raw.crypto_id),
        title=overrides.get("title", raw.title),
        username=overrides.get("username", raw.username),
        password=overrides.get("password", raw.password),
        url=overrides.get("url", raw.url),
        category_id=overrides.get("category_id", raw.category_id),
        category_name=overrides.get("category_name", raw.category_name),
        tags=overrides.get("tags", raw.tags),
        notes=overrides.get("notes", raw.notes),
        custom_fields=overrides.get("custom_fields", []),
        is_favorite=overrides.get("is_favorite", raw.is_favorite),
        is_deleted=overrides.get("is_deleted", raw.is_deleted),
        password_strength=overrides.get("password_strength", raw.password_strength),
        entry_type=overrides.get("entry_type", raw.entry_type),
        totp_secret=overrides.get("totp_secret", raw.totp_secret),
        created_at=overrides.get("created_at", raw.created_at),
        updated_at=overrides.get("updated_at", raw.updated_at),
        deleted_at=overrides.get("deleted_at", raw.deleted_at),
        password_changed_at=overrides.get("password_changed_at", raw.password_changed_at),
        metadata_mac=overrides.get("metadata_mac", raw.metadata_mac),
        integrity_error=overrides.get("integrity_error", raw.integrity_error),
        integrity_message=overrides.get("integrity_message", raw.integrity_message),
        password_present=overrides.get("password_present", bool(raw.password)),
        totp_present=overrides.get("totp_present", bool(raw.totp_secret)),
    )


def build_entry_summary(raw: RawEntry, username: str = "") -> Entry:
    """从原始数据库字段构建摘要 Entry（不含敏感字段，仅用于列表显示与安全分析）。"""
    return copy_entry_fields(
        raw,
        username=username,
        password="",
        notes="",
        custom_fields=[],
        totp_secret="",
    )


def decrypt_entry_to_portable_dict(
    raw_entry: RawEntry,
    key: bytes | bytearray,
    *,
    include_secrets: bool = True,
) -> dict[str, Any]:
    """将原始 Entry 解密为明文字典，任一字段损坏抛异常。供备份/导出等整条解密场景。

    Args:
        raw_entry: 数据库层原始 Entry，加密字段为密文字符串。
        key: AES-256 密钥。
        include_secrets: 是否包含密码和 TOTP 密钥等敏感字段。

    Raises:
        DecryptionError: 元数据完整性失败，或任一加密字段解密失败。
        json.JSONDecodeError: 自定义字段密文解密成功但 JSON 结构损坏。
    """
    if raw_entry.integrity_error:
        raise DecryptionError(f"条目 {raw_entry.crypto_id} 元数据完整性校验失败")
    # 全部加密字段统一 strict=True：任一字段损坏即抛 DecryptionError。实际触发极少，
    # 因 metadata_mac 已绑定全部加密字段密文（title/url/tags 直接入签，余者经 _enc_hash），
    # 损坏会先触发完整性失败。
    custom_json = decrypt_field(
        raw_entry.custom_fields_db_value,
        key,
        raw_entry.crypto_id,
        "custom_fields",
        strict=True,
    )
    custom_fields = json.loads(custom_json) if custom_json else []
    return {
        "id": raw_entry.id,
        "crypto_id": raw_entry.crypto_id,
        "title": decrypt_field(
            raw_entry.title,
            key,
            raw_entry.crypto_id,
            "title",
            strict=True,
        ),
        "username": decrypt_field(
            raw_entry.username,
            key,
            raw_entry.crypto_id,
            "username",
            strict=True,
        ),
        "password": (
            decrypt_field(
                raw_entry.password,
                key,
                raw_entry.crypto_id,
                "password",
                strict=True,
            )
            if include_secrets
            else ""
        ),
        "url": decrypt_field(
            raw_entry.url,
            key,
            raw_entry.crypto_id,
            "url",
            strict=True,
        ),
        "category_id": raw_entry.category_id,
        "tags": decrypt_field(
            raw_entry.tags,
            key,
            raw_entry.crypto_id,
            "tags",
            strict=True,
        ),
        "notes": decrypt_field(
            raw_entry.notes,
            key,
            raw_entry.crypto_id,
            "notes",
            strict=True,
        ),
        "custom_fields": custom_fields,
        "totp_secret": (
            decrypt_field(
                raw_entry.totp_secret,
                key,
                raw_entry.crypto_id,
                "totp_secret",
                strict=True,
            )
            if include_secrets
            else ""
        ),
        "password_strength": raw_entry.password_strength,
        "entry_type": raw_entry.entry_type,
        "is_favorite": raw_entry.is_favorite,
        "is_deleted": raw_entry.is_deleted,
        "created_at": raw_entry.created_at,
        "updated_at": raw_entry.updated_at,
        "deleted_at": raw_entry.deleted_at,
        "password_changed_at": raw_entry.password_changed_at,
    }


def build_encrypted_entry_fields(
    item: dict[str, Any], key: bytes | bytearray, crypto_id: str
) -> dict[str, Any]:
    """加密条目的敏感字段，与 decrypt_entry_to_portable_dict 对称。

    供备份恢复等从明文字典重建加密条目场景，字段集与解密侧保持一致避免漂移。

    Args:
        item: 含明文字段的字典（来自备份 JSON）。
        key: AES-256 密钥。
        crypto_id: 条目加密标识，参与 AAD。
    """
    custom_fields = item.get("custom_fields", [])
    custom_json = json.dumps(custom_fields, ensure_ascii=False) if custom_fields else ""
    return {
        "title": encrypt_field(item.get("title", ""), key, crypto_id, "title"),
        "username": encrypt_field(item.get("username", ""), key, crypto_id, "username"),
        "password": encrypt_field(item.get("password", ""), key, crypto_id, "password"),
        "url": encrypt_field(item.get("url", ""), key, crypto_id, "url"),
        "tags": encrypt_field(item.get("tags", ""), key, crypto_id, "tags"),
        "notes": encrypt_field(item.get("notes", ""), key, crypto_id, "notes"),
        "custom_fields": encrypt_field(custom_json, key, crypto_id, "custom_fields"),
        "totp_secret": encrypt_field(item.get("totp_secret", ""), key, crypto_id, "totp_secret"),
    }


def encrypt_plaintext_category_names(db: DatabaseManager, key: bytes | bytearray) -> None:
    """加密 data 层以明文写入的默认分类名（首次初始化后补加密）。

    data 层建表插入默认分类时不持密钥无法加密，故在 business 层补加密，使全部
    category.name 以密文存储，满足改密时 re_encrypt_categories 的解密契约。已加密
    （cb2: 前缀）的分类跳过，重复调用幂等。
    """
    with db.transaction():
        for category in db.get_categories():
            if category.id is None or category.name.startswith(EncryptionEngine.TEXT_PREFIX):
                continue
            encrypted_name = encrypt_field(
                category.name,
                key,
                category_crypto_id(category.id),
                "category_name",
            )
            db.update_category(replace(category, name=encrypted_name))
