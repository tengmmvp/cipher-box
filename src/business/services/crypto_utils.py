"""业务层共享加密工具函数。"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, TypedDict

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

    total=False：所有字段均可选，调用方按需覆盖子集。custom_fields 在解密路径
    传入 ``list[CustomField]``；password 运行时可为 :class:`Sensitive`（str 子类），
    标注为 str 兼容二者。
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


# 条目中需加密的敏感字段名（RawEntry/Entry 逻辑属性名，非 DB 列名）。单一事实
# 来源：ReEncryptionService 重加密、下方 decrypt_entry_to_portable_dict /
# build_encrypted_entry_fields 的加解密字段集均与此一致。custom_fields 在加解密
# 时序列化为 JSON 字符串再加密，字段名仍计入此集合。新增加密字段须同步更新
# decrypt/build 的显式字段处理与 metadata_signer._payload 的 _enc_hash 绑定。
SENSITIVE_ENCRYPTED_FIELDS: tuple[str, ...] = (
    'title', 'username', 'password', 'url', 'tags', 'notes',
    'totp_secret', 'custom_fields',
)

# 字符串型加密字段（custom_fields 为 list[CustomField]，单独校验）。
# 供 entry_validation.validate_plain_entry 等明文条目校验复用，单一来源。
STRING_ENCRYPTED_FIELDS: tuple[str, ...] = tuple(
    f for f in SENSITIVE_ENCRYPTED_FIELDS if f != 'custom_fields'
)


def require_vault_key(vault_manager: VaultManager) -> bytes:
    """获取保险库加密密钥，未解锁时抛出 VaultLockedError。"""
    key = vault_manager.key
    if key is None:
        raise VaultLockedError("保险库未解锁")
    return key


def entry_aad(crypto_id: str, field_name: str) -> str:
    """构造条目字段加密的标准 AAD：将 crypto_id 与 field_name 纳入 AAD，绑定密文到
    具体条目与字段，防密文在条目间或字段间置换。"""
    return f'entry:{crypto_id}:{field_name}'


def category_crypto_id(category_id: int) -> str:
    """构造分类名加密的 crypto_id。

    统一此字面量（曾散落于 entry_manager._category_crypto_id、re_encryption、
    security_analyzer），使分类名加解密 AAD 为单一真相源，避免漂移导致解密失败。
    与 entry_aad 组合：``entry_aad(category_crypto_id(id), 'category_name')``。
    """
    return f'category-{category_id}'


def encrypt_field(plaintext: str, key: bytes | bytearray, crypto_id: str, field_name: str) -> str:
    """加密单个条目字段。

    统一入口，替代各处内联的 EncryptionEngine.encrypt 调用（EntryManager、
    backup_restore 等），保证 AAD 构造一致。

    空字符串也直接经过 AES-GCM 加密，确保 AAD 始终参与认证。
    """
    return EncryptionEngine.encrypt(
        plaintext, key, entry_aad(crypto_id, field_name)
    )


def decrypt_field(
    encrypted: str,
    key: bytes | bytearray,
    crypto_id: str,
    field_name: str,
    *,
    strict: bool = False,
) -> str:
    """解密单个条目字段。

    统一入口，替代各处内联的 EncryptionEngine.decrypt 调用（EntryManager、
    backup_restore、security_analyzer 等），保证 AAD 与容错策略一致。

    Args:
        encrypted: 密文字符串。
        key: AES-256 密钥。
        crypto_id: 条目加密标识。
        field_name: 字段名称。
        strict: 为 True 时解密失败抛出 ValueError，否则返回空字符串。
    """
    if not encrypted:
        return ''
    try:
        return EncryptionEngine.decrypt(
            encrypted, key, entry_aad(crypto_id, field_name)
        )
    except ValueError:
        if strict:
            raise
        logger.warning(
            "字段解密失败（容错模式）: crypto_id=%s field=%s，密文可能损坏",
            crypto_id, field_name,
        )
        return ''


def matches_search(entry: Entry | RawEntry, query: str) -> bool:
    """检查条目是否匹配搜索关键词，大小写不敏感，搜索 title/username/url/tags。

    Args:
        entry: 待匹配的明文 Entry 摘要。生产路径不应传入 RawEntry。
        query: 搜索关键词，空字符串匹配所有条目。
    """
    if not query:
        return True
    kw = query.lower()
    username = entry.username or ''
    return (kw in (entry.title or '').lower()
            or kw in username.lower()
            or kw in (entry.url or '').lower()
            or kw in (entry.tags or '').lower())


def matches_tag(entry: Entry, tag: str) -> bool:
    """检查条目是否包含指定标签，大小写不敏感的精确匹配。

    与 ``Entry.get_tag_list()`` 使用一致的解析逻辑：
    以逗号分隔、逐元素 strip 空白、大小写不敏感比较。
    """
    if not tag:
        return True
    tag_lower = tag.strip().lower()
    entry_tags = [t.strip().lower() for t in (entry.tags or '').split(',') if t.strip()]
    return tag_lower in entry_tags


def copy_entry_fields(raw: RawEntry, **overrides: Unpack[EntryOverrides]) -> Entry:
    """从密文态 RawEntry 构建明文 Entry，按需覆盖字段。

    RawEntry 与 Entry 是不同 dataclass，不能用 ``dataclasses.replace`` 跨类型
    （会产出 RawEntry）。直接构造 Entry，逐字段从 raw 取值；可变字段（username/
    password/notes/totp_secret/custom_fields 等）经 overrides 覆盖。``custom_fields``
    默认空 list，调用方解密路径应在 ``overrides`` 传入解密后的 ``list[CustomField]``。
    """
    return Entry(
        id=overrides.get('id', raw.id),
        crypto_id=overrides.get('crypto_id', raw.crypto_id),
        title=overrides.get('title', raw.title),
        username=overrides.get('username', raw.username),
        password=overrides.get('password', raw.password),
        url=overrides.get('url', raw.url),
        category_id=overrides.get('category_id', raw.category_id),
        category_name=overrides.get('category_name', raw.category_name),
        tags=overrides.get('tags', raw.tags),
        notes=overrides.get('notes', raw.notes),
        custom_fields=overrides.get('custom_fields', []),
        is_favorite=overrides.get('is_favorite', raw.is_favorite),
        is_deleted=overrides.get('is_deleted', raw.is_deleted),
        password_strength=overrides.get('password_strength', raw.password_strength),
        entry_type=overrides.get('entry_type', raw.entry_type),
        totp_secret=overrides.get('totp_secret', raw.totp_secret),
        created_at=overrides.get('created_at', raw.created_at),
        updated_at=overrides.get('updated_at', raw.updated_at),
        deleted_at=overrides.get('deleted_at', raw.deleted_at),
        password_changed_at=overrides.get('password_changed_at', raw.password_changed_at),
        metadata_mac=overrides.get('metadata_mac', raw.metadata_mac),
        integrity_error=overrides.get('integrity_error', raw.integrity_error),
        integrity_message=overrides.get('integrity_message', raw.integrity_message),
        password_present=overrides.get('password_present', bool(raw.password)),
        totp_present=overrides.get('totp_present', bool(raw.totp_secret)),
    )


def build_entry_summary(raw: RawEntry, username: str = '') -> Entry:
    """从原始数据库字段构建摘要 Entry，可选附带已解密的用户名。

    Summary 条目不含 password/notes/totp_secret/custom_fields 等敏感字段，
    仅用于列表显示和安全分析。
    """
    return copy_entry_fields(
        raw,
        username=username,
        password='',
        notes='',
        custom_fields=[],
        totp_secret='',
    )


def decrypt_entry_to_portable_dict(
    raw_entry: RawEntry,
    key: bytes | bytearray,
    *,
    include_secrets: bool = True,
) -> dict | None:
    """将原始 Entry 解密为明文字典，容错处理。

    供备份、导出等需要跳过损坏条目继续处理的场景使用。
    单条目解密失败时返回 None。

    BackupRestoreManager._collect_portable_data() 共享此解密逻辑。

    Args:
        raw_entry: 数据库层原始 Entry，加密字段为密文字符串。
        key: AES-256 密钥。
        include_secrets: 是否包含密码和 TOTP 密钥等敏感字段。
    """
    if raw_entry.integrity_error:
        logger.warning(
            "拒绝转换元数据完整性失败的条目 crypto_id=%s",
            raw_entry.crypto_id,
        )
        return None
    try:
        # 全部加密字段统一 strict=True：任一字段损坏即抛 ValueError，由下方 except
        # 捕获返回 None（跳过整条），保证「部分损坏即整条不可用」的一致契约。
        # 实际触发极少——metadata_mac 的 _enc_hash 已覆盖全部加密字段密文，单字段
        # 损坏会先触发元数据完整性失败使 raw_entry.integrity_error=True，在进入本
        # 函数前即被上方检查拦截返回 None。
        custom_json = decrypt_field(
            raw_entry.custom_fields_db_value,
            key, raw_entry.crypto_id, 'custom_fields', strict=True,
        )
        try:
            custom_fields = json.loads(custom_json) if custom_json else []
        except json.JSONDecodeError:
            return None
        return {
            'id': raw_entry.id,
            'crypto_id': raw_entry.crypto_id,
            'title': decrypt_field(
                raw_entry.title, key, raw_entry.crypto_id, 'title', strict=True,
            ),
            'username': decrypt_field(
                raw_entry.username, key, raw_entry.crypto_id, 'username', strict=True,
            ),
            'password': (
                decrypt_field(
                    raw_entry.password, key, raw_entry.crypto_id, 'password', strict=True,
                ) if include_secrets else ''
            ),
            'url': decrypt_field(
                raw_entry.url, key, raw_entry.crypto_id, 'url', strict=True,
            ),
            'category_id': raw_entry.category_id,
            'tags': decrypt_field(
                raw_entry.tags, key, raw_entry.crypto_id, 'tags', strict=True,
            ),
            'notes': decrypt_field(
                raw_entry.notes, key, raw_entry.crypto_id, 'notes', strict=True,
            ),
            'custom_fields': custom_fields,
            'totp_secret': (
                decrypt_field(
                    raw_entry.totp_secret, key, raw_entry.crypto_id, 'totp_secret', strict=True,
                ) if include_secrets else ''
            ),
            'password_strength': raw_entry.password_strength,
            'entry_type': raw_entry.entry_type,
            'is_favorite': raw_entry.is_favorite,
            'is_deleted': raw_entry.is_deleted,
            'created_at': raw_entry.created_at,
            'updated_at': raw_entry.updated_at,
            'deleted_at': raw_entry.deleted_at,
            'password_changed_at': raw_entry.password_changed_at,
        }
    except (ValueError, DecryptionError):
        logger.warning(
            "decrypt_entry_to_portable_dict 跳过损坏条目 crypto_id=%s",
            raw_entry.crypto_id, exc_info=True,
        )
        return None


def build_encrypted_entry_fields(item: dict, key: bytes | bytearray, crypto_id: str) -> dict:
    """加密条目的敏感字段，与 decrypt_entry_to_portable_dict 对称。

    供备份恢复等需要从明文字典重建加密条目的场景使用。加密字段集与
    decrypt_entry_to_portable_dict 的解密字段集保持一致，避免加/解密两侧
    字段集漂移。

    Args:
        item: 含明文字段的字典（来自备份 JSON）。
        key: AES-256 密钥。
        crypto_id: 条目加密标识，参与 AAD。

    Returns:
        由字段名到加密密文的字典。
    """
    custom_fields = item.get('custom_fields', [])
    custom_json = json.dumps(custom_fields, ensure_ascii=False) if custom_fields else ''
    return {
        'title': encrypt_field(item.get('title', ''), key, crypto_id, 'title'),
        'username': encrypt_field(item.get('username', ''), key, crypto_id, 'username'),
        'password': encrypt_field(item.get('password', ''), key, crypto_id, 'password'),
        'url': encrypt_field(item.get('url', ''), key, crypto_id, 'url'),
        'tags': encrypt_field(item.get('tags', ''), key, crypto_id, 'tags'),
        'notes': encrypt_field(item.get('notes', ''), key, crypto_id, 'notes'),
        'custom_fields': encrypt_field(custom_json, key, crypto_id, 'custom_fields'),
        'totp_secret': encrypt_field(item.get('totp_secret', ''), key, crypto_id, 'totp_secret'),
    }


def encrypt_plaintext_category_names(db: DatabaseManager, key: bytes | bytearray) -> None:
    """加密 data 层以明文写入的默认分类名（首次初始化后补加密）。

    ``SchemaManager.init_tables`` 建表时插入默认分类（如"未分类"），但 data 层不持
    密钥无法加密；首次初始化后在 business 层补加密，使全部 category.name 以密文存储，
    满足改密时 ``re_encrypt_categories`` 的解密契约。已加密（cb2: 前缀）的分类跳过，
    故重复调用幂等。从 EntryManager 提取为纯函数，供 VaultManager.initialize 直接
    调用，消除二者间的循环依赖（原经延迟 import 调用 EntryManager 方法）。
    """
    with db.transaction():
        for category in db.get_categories():
            if category.id is None or category.name.startswith(EncryptionEngine.TEXT_PREFIX):
                continue
            category.name = encrypt_field(
                category.name, key, category_crypto_id(category.id), 'category_name',
            )
            db.update_category(category)
