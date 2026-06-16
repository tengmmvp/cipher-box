"""业务层共享加密工具函数。"""

import json
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..managers.vault_manager import VaultManager

from ...crypto.encryption import EncryptionEngine
from ...exceptions import DecryptionError, VaultLockedError
from ...models import Entry, RawEntry

logger = logging.getLogger(__name__)


# 条目中需加密的敏感字段名（RawEntry/Entry 逻辑属性名，非 DB 列名）。单一事实
# 来源：KeyRotationService 重加密、下方 decrypt_entry_to_portable_dict /
# build_encrypted_entry_fields 的加解密字段集均与此一致。custom_fields 在加解密
# 时序列化为 JSON 字符串再加密，字段名仍计入此集合。新增加密字段须同步更新
# decrypt/build 的显式字段处理与 metadata_signer._payload 的 _enc_hash 绑定。
SENSITIVE_ENCRYPTED_FIELDS: tuple[str, ...] = (
    'title', 'username', 'password', 'url', 'tags', 'notes',
    'totp_secret', 'custom_fields',
)


def require_vault_key(vault_manager: 'VaultManager') -> bytes:
    """获取保险库加密密钥，未解锁时抛出 VaultLockedError。"""
    key = vault_manager.key
    if key is None:
        raise VaultLockedError("保险库未解锁")
    return key


def entry_aad(crypto_id: str, field_name: str) -> str:
    """构造条目字段加密的标准 AAD 字符串。"""
    return f'entry:{crypto_id}:{field_name}'


def encrypt_field(plaintext: str, key: bytes, crypto_id: str, field_name: str) -> str:
    """加密单个条目字段。

    统一入口，替代 EntryManager._encrypt_field、VaultManager._encrypt_entry_field
    以及 backup_restore 中的内联 EncryptionEngine.encrypt 调用。

    空字符串也直接经过 AES-GCM 加密，确保 AAD 始终参与认证。
    """
    return EncryptionEngine.encrypt(
        plaintext, key, entry_aad(crypto_id, field_name)
    )


def decrypt_field(
    encrypted: str,
    key: bytes,
    crypto_id: str,
    field_name: str,
    *,
    strict: bool = False,
) -> str:
    """解密单个条目字段。

    统一入口，替代 EntryManager._decrypt_field、VaultManager._decrypt_entry_field
    以及 backup_restore/security_analyzer 中的内联解密调用。

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


def copy_entry_fields(raw: RawEntry, **overrides) -> Entry:
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
    key: bytes,
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
        # 捕获返回 None（跳过整条），消除原先 notes/password/custom_fields 容错
        # （返回空串、条目仍导出）与 title/url/tags 严格的不一致契约。实际触发
        # 极少——metadata_mac 的 _enc_hash 已覆盖全部加密字段密文，单字段损坏会
        # 先触发元数据完整性失败使 raw_entry.integrity_error=True，在进入本函数前
        # 即被上方 integrity_error 检查拦截返回 None。
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


def build_encrypted_entry_fields(item: dict, key: bytes, crypto_id: str) -> dict:
    """加密条目的敏感字段，与 decrypt_entry_to_portable_dict 对称。

    供备份恢复等需要从明文字典重建加密条目的场景使用，统一敏感字段
    的加密序列，消除
    恢复路径内联加密与解密辅助的双向映射漂移风险。

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
