"""业务层共享加密工具函数。"""

import copy
import dataclasses
import json
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..managers.vault_manager import VaultManager

from ...crypto.encryption import EncryptionEngine
from ...exceptions import DecryptionError, VaultLockedError
from ...models import Entry

logger = logging.getLogger(__name__)


def require_vault_key(vault_manager: 'VaultManager') -> bytes:
    """获取保险库加密密钥，未解锁时抛出 VaultLockedError"""
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

    空字符串也经过 EncryptionEngine.encrypt，内部使用 _EMPTY_SENTINEL，
    确保 AAD 始终参与认证，维持逐字段完整性保护的一致性。
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
        logger.debug(
            "字段解密失败（容错模式）: crypto_id=%s field=%s",
            crypto_id, field_name, exc_info=True,
        )
        return ''


def matches_search(entry: Entry, query: str, *, username_override: str | None = None) -> bool:
    """检查条目是否匹配搜索关键词，大小写不敏感，搜索 title/username/url/tags。

    Args:
        entry: 待匹配条目。
        query: 搜索关键词，空字符串匹配所有条目。
        username_override: 若提供，替代 entry.username 用于搜索。
            用于原始条目 username 仍为密文时传入缓存解密值。
    """
    if not query:
        return True
    kw = query.lower()
    username = username_override if username_override is not None else (entry.username or '')
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


def copy_entry_fields(raw: Entry, **overrides) -> Entry:
    """从 raw Entry 复制所有字段，按需覆盖。

    使用 dataclasses.replace 实现，自动复制 Entry 的全部字段，
    仅 overrides 中指定的字段会被替换。运行时字段 password_present
    和 totp_present 根据 DB 原始值 raw.password 与 raw.totp_secret
    自动设置，除非调用方已在 overrides 中显式提供。

    custom_fields 为 list 时执行深拷贝，避免浅拷贝导致多个 Entry
    共享同一个可变列表对象。
    """
    overrides.setdefault('password_present', bool(raw.password))
    overrides.setdefault('totp_present', bool(raw.totp_secret))
    # 深拷贝 custom_fields 防止浅拷贝别名问题
    if 'custom_fields' not in overrides and raw.is_decrypted:
        overrides['custom_fields'] = copy.deepcopy(raw.custom_fields)
    return dataclasses.replace(raw, **overrides)


def build_entry_summary(raw: Entry, username: str = '') -> Entry:
    """从原始数据库字段构建摘要 Entry，可选附带已解密的用户名。

    Summary 条目不含 password/notes/totp_secret/custom_fields 等敏感字段，
    仅用于列表显示和安全分析。
    """
    return copy_entry_fields(
        raw,
        username=username,
        password='',
        notes='',
        custom_fields='',
        totp_secret='',
    )


def decrypt_entry_to_portable_dict(
    raw_entry: Entry,
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
    try:
        custom_json = decrypt_field(
            raw_entry.custom_fields_db_value,
            key, raw_entry.crypto_id, 'custom_fields',
        )
        try:
            custom_fields = json.loads(custom_json) if custom_json else []
        except json.JSONDecodeError:
            return None
        return {
            'id': raw_entry.id,
            'crypto_id': raw_entry.crypto_id,
            'title': raw_entry.title,
            'username': decrypt_field(
                raw_entry.username, key, raw_entry.crypto_id, 'username',
            ),
            'password': (
                decrypt_field(
                    raw_entry.password, key, raw_entry.crypto_id, 'password',
                ) if include_secrets else ''
            ),
            'url': raw_entry.url,
            'category_id': raw_entry.category_id,
            'tags': raw_entry.tags,
            'notes': decrypt_field(
                raw_entry.notes, key, raw_entry.crypto_id, 'notes',
            ),
            'custom_fields': custom_fields,
            'totp_secret': (
                decrypt_field(
                    raw_entry.totp_secret, key, raw_entry.crypto_id, 'totp_secret',
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
