"""业务层字段加解密的统一入口与加密字段集单一事实源。

``encrypt_field``/``decrypt_field`` 为条目与分类字段加解密的统一入口，确保 AAD 构造
一致（防密文在条目或字段间置换）；``SENSITIVE_ENCRYPTED_FIELDS`` 为全项目加密字段集
的单一事实源，新增加密字段须同步解密/构建与签名绑定（详见常量处注释）。另含保险库
解锁守卫（:func:`require_vault_key`）。搜索谓词/视图构造/备份 portable dict 解密已按
职责域拆出（MAINT-097）：见 entry_search_match / entry_view_decryption /
backup.collector。
"""

from __future__ import annotations

import json
import logging
from dataclasses import replace
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    # VaultDataStore（数据库协议切片）替代具体 DatabaseManager：本模块实际只用
    # transaction/get_categories/update_category（均在协议内），是 services 层与
    # 数据层解耦的统一协议视图（ARCH-031）。
    from ...database.types import VaultDataStore

from ...crypto.encryption import EncryptionEngine
from ...exceptions import DecryptionError, VaultLockedError
from ...models import RawEntry

logger = logging.getLogger(__name__)


class KeyProvider(Protocol):
    """取密钥所需的最小保险库协议：解锁状态 + 主密钥（ARCH-039）。

    ``VaultManager`` 自然满足此协议。require_vault_key（crypto_utils）与
    entry_view_decryption 对保险库的依赖面仅此两成员；password_history_service
    以本协议为基扩展出 4 成员协议（另加 db 与 vault_write_lock，见
    PasswordHistoryVaultProtocol）——经协议声明后 services 子包不再 TYPE_CHECKING
    引用具体 manager 类，测试替身只需协议成员即可满足（对齐 TotpCacheProtocol /
    ViewDecryptCacheProtocol 的既有模式，ARCH-032）。
    """

    @property
    def is_unlocked(self) -> bool: ...

    @property
    def key(self) -> bytes: ...


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


def require_vault_key(vault_manager: KeyProvider) -> bytes:
    """获取保险库加密密钥，未解锁时抛出 VaultLockedError。

    vault.key 自身已 fail-fast 守卫（MAINT-007）；本函数保留 is_unlocked 前置检查
    收紧 unlock 窗口（unlock 在 vault_meta_mac 校验通过前 key 已装入但 is_unlocked
    仍为 False，前置检查在此窄窗即抛，无需依赖 key 守卫的二次判定）。

    Args:
        vault_manager: 提供解锁状态与加密密钥的最小协议视图（:class:`KeyProvider`，
            VaultManager 及测试替身均自然满足，ARCH-039）。

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


def decrypt_string_fields_strict(
    raw_entry: RawEntry,
    key: bytes | bytearray,
    *,
    include_secrets: bool = False,
) -> dict[str, str]:
    """严格解密条目的全部字符串型加密字段，返回 ``{字段名: 明文}``（QL-018）。

    基于 :data:`STRING_ENCRYPTED_FIELDS` 单一事实源循环（custom_fields 为 JSON
    结构非纯字符串，由各消费方单独处理），password/totp_secret 受 ``include_secrets``
    门控：False 时输出空串且**不解密**，保持「默认不让密码进入内存」的安全默认。
    任一字段解密失败抛 :class:`DecryptionError`（strict），调用方按各自语义包装。

    供导出路径的两条同构解密链路消费（EntryViewDecryptor.decrypt_entry_for_export 组装 Entry
    与 backup/collector.decrypt_entry_to_portable_dict 组装 portable dict），消除手工
    逐字段枚举——新增加密字段只需加入 SENSITIVE_ENCRYPTED_FIELDS，两条路径自动跟随，
    不会静默漏解密。
    """
    return {
        field: (
            decrypt_field(
                getattr(raw_entry, field),
                key,
                raw_entry.crypto_id,
                field,
                strict=True,
            )
            if include_secrets or field not in ("password", "totp_secret")
            else ""
        )
        for field in STRING_ENCRYPTED_FIELDS
    }


def build_encrypted_entry_fields(
    item: dict[str, Any], key: bytes | bytearray, crypto_id: str
) -> dict[str, Any]:
    """加密条目的敏感字段，与 backup/collector.decrypt_entry_to_portable_dict 对称。

    供备份恢复等从明文字典重建加密条目场景，字段集与解密侧保持一致避免漂移。

    对 :data:`SENSITIVE_ENCRYPTED_FIELDS` 循环产出（QL-046）：custom_fields 为 JSON
    结构非纯字符串，序列化特判；其余字符串字段统一经 encrypt_field（AAD 构造与原
    手工枚举逐字段完全一致）。新增加密字段只需登记单一事实源，加密侧自动跟随——
    消除「解密/验签侧响亮失败、加密侧静默丢字段」的写读不对称（丢字段的密文入库
    会使恢复往返断裂）。键集完备性由 tests/test_field_consistency.py 守护。

    Args:
        item: 含明文字段的字典（来自备份 JSON）。
        key: AES-256 密钥。
        crypto_id: 条目加密标识，参与 AAD。

    Returns:
        ``{逻辑字段名: 密文}``，键集恰为 SENSITIVE_ENCRYPTED_FIELDS。
    """
    custom_fields = item.get("custom_fields", [])
    custom_json = json.dumps(custom_fields, ensure_ascii=False) if custom_fields else ""
    return {
        field: encrypt_field(
            custom_json if field == "custom_fields" else item.get(field, ""),
            key,
            crypto_id,
            field,
        )
        for field in SENSITIVE_ENCRYPTED_FIELDS
    }


def encrypt_plaintext_category_names(db: VaultDataStore, key: bytes | bytearray) -> None:
    """加密 data 层以明文写入的默认分类名（首次初始化后补加密）。

    data 层建表插入默认分类时不持密钥无法加密，故在 business 层补加密，使全部
    category.name 以密文存储，满足改密时 re_encrypt_categories 的解密契约。已加密
    （cb2: 前缀）的分类跳过，重复调用幂等。参数为 VaultDataStore 协议而非具体
    DatabaseManager——本函数仅用 transaction/get_categories/update_category，均为
    协议成员，消除 services 层对具体数据库管理器的唯一残余绑定（ARCH-031）。
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
