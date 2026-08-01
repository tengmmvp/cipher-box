"""条目元数据 HMAC 签名与验证：计算并校验条目/分类元数据与 vault_meta 的完整性签名，防篡改。"""

import hashlib
import hmac
import json
import logging

from ...exceptions import VaultIntegrityError, VaultLockedError
from ...models import Category, RawEntry
from ...utils.memory import secure_zero_buffer
from .vault_meta_keys import VAULT_META_SIGNED_KEYS

logger = logging.getLogger(__name__)

# 域分离 info 标签：条目/分类元数据与 vault_meta 完整性各自派生独立域密钥，
# 与主密钥/备份密钥域分离原则一致。
_DOMAIN_INFO_ENTRY_METADATA = b"cipherbox:entry-metadata-key"
_DOMAIN_INFO_VAULT_META = b"cipherbox:vault-meta-key"

# vault_meta 完整性签名覆盖的键集（源自 vault_meta_keys 单一事实源），此处 re-export
# 供既有调用方引用（vault_meta_store / backup_restore 经本模块 import）。

# 签名绑定的加密字段及固定顺序（顺序变更会破坏已有 metadata_mac）。等于
# crypto_utils.SENSITIVE_ENCRYPTED_FIELDS 减 {title,url,tags}（这三者以密文形态直接
# 入签），由 tests/test_field_consistency.py 守护此子集关系。custom_fields 取密文 db_value。
SIGNATURE_ENCRYPTED_FIELD_ORDER = ("username", "password", "notes", "totp_secret", "custom_fields")


class MetadataSigner:
    """条目元数据 HMAC 签名与验证。

    用主密钥派生的域密钥对非敏感元数据生成 HMAC-SHA256，载荷含加密字段密文的
    SHA-256 哈希以绑定密文与元数据，防密文置换或回滚。域密钥经 set_domain_key
    装入，或在 sign/verify 时显式传入。
    """

    def __init__(self, domain_key: bytes | bytearray | None = None):
        self._domain_key = bytearray(domain_key) if domain_key is not None else None

    def set_domain_key(self, key: bytes | bytearray) -> None:
        """设置预计算的域密钥（解锁/改密成功后调用），统一归一为 bytearray 以便原地清零。"""
        self._rotate_domain_key(key)

    def _rotate_domain_key(self, value: bytes | bytearray | None) -> None:
        """替换域密钥：归一为新 bytearray 后，显式清零旧 bytearray 收缩残留面。

        None 用于锁定/改密清零。与 ``compute_vault_meta_mac`` 的 finally 清零纪律一致
        ——旧域密钥虽不可逆推主密钥，仍可独立伪造 ``metadata_mac``，不应在锁定后留存。
        """
        old = self._domain_key
        self._domain_key = self._normalize_domain_key(value)
        if old is not None:
            secure_zero_buffer(old)

    @property
    def domain_key(self) -> bytearray | None:
        """当前域密钥，供 VaultManager 清零密钥时访问。"""
        return self._domain_key

    @domain_key.setter
    def domain_key(self, value: bytearray | None) -> None:
        # 归一为 bytearray 防 bytes 绕过清零；VaultManager 经此传 None 清零。
        self._rotate_domain_key(value)

    @staticmethod
    def _normalize_domain_key(value: bytes | bytearray | None) -> bytearray | None:
        """归一域密钥：None 透传，bytes|bytearray 转 bytearray 副本，使清零能原地生效。"""
        if value is None:
            return None
        return value if isinstance(value, bytearray) else bytearray(value)

    @staticmethod
    def compute_domain_key(key: bytes | bytearray) -> bytearray:
        """从主密钥派生 metadata 签名域密钥，返回 bytearray 以便原地清零。"""
        return bytearray(hmac.new(key, _DOMAIN_INFO_ENTRY_METADATA, hashlib.sha256).digest())

    @staticmethod
    def compute_vault_meta_domain_key(key: bytes | bytearray) -> bytearray:
        """从主密钥派生 vault_meta 完整性签名的独立域密钥，返回 bytearray 以便清零。

        与 :meth:`compute_domain_key` 显式域分离：vault_meta 完整性（保险库级）与
        条目/分类元数据（条目级）经各自 info 标签派生，避免跨协议交互。
        """
        return bytearray(hmac.new(key, _DOMAIN_INFO_VAULT_META, hashlib.sha256).digest())

    @staticmethod
    def compute_vault_meta_mac(meta: dict, key: bytes | bytearray) -> str:
        """计算 vault_meta 安全相关字段的 HMAC-SHA256，用主密钥派生的域密钥签名。

        检测 vault_meta 被外部篡改（替换 salt、改写 KDF 参数、伪造 key_epoch）。
        篡改 KDF 参数会使主密钥派生变化、verify_token 解密先行失败，此 MAC 主要
        在 verify 通过后对未致派生失败的篡改提供统一完整性校验。域密钥局部副本用后清零。
        """
        dk = MetadataSigner.compute_vault_meta_domain_key(key)
        try:
            payload = MetadataSigner._canonical_json_bytes(
                {k: meta.get(k) for k in VAULT_META_SIGNED_KEYS}
            )
            return hmac.new(dk, payload, hashlib.sha256).hexdigest()
        finally:
            secure_zero_buffer(dk)

    def sign(self, entry: RawEntry) -> str:
        """计算条目元数据 HMAC 签名，使用预计算的域密钥。

        Raises:
            VaultLockedError: 域密钥未设置（保险库未解锁）。
        """
        if self._domain_key is None:
            raise VaultLockedError("保险库未解锁，无法签名条目元数据")
        return hmac.new(
            self._domain_key,
            self._payload(entry),
            hashlib.sha256,
        ).hexdigest()

    def sign_with_domain_key(self, entry: RawEntry, domain_key: bytes | bytearray) -> str:
        """直接用预计算的域密钥签名，跳过密钥派生。供 ReEncryptionService 批量重加密避免每条重复派生。

        Args:
            entry: 条目对象。
            domain_key: 预计算的域密钥（``compute_domain_key`` 返回 bytearray），接受 bytes|bytearray。
        """
        return hmac.new(
            domain_key,
            self._payload(entry),
            hashlib.sha256,
        ).hexdigest()

    def verify(self, entry: RawEntry) -> None:
        """验证条目元数据完整性签名。

        Raises:
            VaultIntegrityError: 签名验证失败。
            VaultLockedError: 保险库未解锁。
        """
        if not entry.metadata_mac:
            raise VaultIntegrityError(f"条目 {entry.id} 缺少元数据完整性签名")
        expected = self.sign(entry)
        if not hmac.compare_digest(entry.metadata_mac, expected):
            raise VaultIntegrityError(f"条目 {entry.id} 元数据完整性校验失败")

    def sign_category(self, category: Category) -> str:
        """计算分类元数据 HMAC 签名，与条目签名共享同一域密钥。

        跨 epoch 隔离由域密钥轮换提供：改密产生新域密钥，故改密时
        re_encrypt_categories 须在重加密分类名后重签。
        """
        if self._domain_key is None:
            raise VaultLockedError("保险库未解锁，无法签名分类元数据")
        return hmac.new(
            self._domain_key,
            self._category_payload(category),
            hashlib.sha256,
        ).hexdigest()

    def sign_category_with_domain_key(
        self,
        category: Category,
        domain_key: bytes | bytearray,
    ) -> str:
        """直接用预计算的域密钥签名分类，对称 :meth:`sign_with_domain_key`。

        供 re_encrypt_categories 在改密事务内用新域密钥重签：事务内 ``_domain_key``
        仍是旧值（vault_manager 提交后才 set_domain_key(new)），沿用 sign_category
        会用旧域密钥致改密后 verify_category 永久失败。调用方预计算新域密钥注入，
        不临时切换 signer 全局 _domain_key。

        Args:
            category: 分类对象。
            domain_key: 预计算的域密钥，接受 bytes|bytearray。
        """
        return hmac.new(
            domain_key,
            self._category_payload(category),
            hashlib.sha256,
        ).hexdigest()

    def verify_category(self, category: Category) -> None:
        """验证分类元数据完整性签名。

        Raises:
            VaultIntegrityError: 签名验证失败（含空签名）。
            VaultLockedError: 保险库未解锁。
        """
        if not category.metadata_mac:
            raise VaultIntegrityError(f"分类 {category.id} 缺少元数据完整性签名")
        expected = self.sign_category(category)
        if not hmac.compare_digest(category.metadata_mac, expected):
            raise VaultIntegrityError(f"分类 {category.id} 元数据完整性校验失败")

    @staticmethod
    def _canonical_json_bytes(data: dict) -> bytes:
        """规范化 JSON 字节串：排序键、紧凑分隔、UTF-8 编码。

        供条目与分类载荷复用，确保两侧序列化参数一致，避免漂移致一侧验签失败。
        """
        return json.dumps(
            data,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @staticmethod
    def _payload(entry: RawEntry) -> bytes:
        """构造签名载荷。

        Note:
            载荷不含 ``key_epoch``：跨 epoch 隔离由域密钥本身提供（域密钥从主密钥
            派生，轮换主密钥即新域密钥，旧签名验证必然失败），无需显式纳入 epoch。

            SEC-004 威胁边界：同一主密码周期内（域密钥不变），有数据库写权限+旧快照的
            攻击者可把整条目回滚到旧版本——旧密文+旧元数据+旧签名自洽，验签通过，用户
            无感使用泄露的旧密码。纯本地防御需在保险库外记录全局单调 revision 最高值，
            但该记录同样在本地可被篡改；本地优先应用下 DB 写权限攻击者通常已有更高权限
            （可改可执行文件/读内存密钥），故此项作为已知边界接受，不做部分有效的防御。
        """
        data = {
            "crypto_id": entry.crypto_id,
            "title": entry.title,
            "url": entry.url,
            "category_id": entry.category_id,
            "tags": entry.tags,
            "is_favorite": bool(entry.is_favorite),
            "is_deleted": bool(entry.is_deleted),
            "password_strength": entry.password_strength,
            "entry_type": entry.entry_type,
            "created_at": entry.created_at,
            "updated_at": entry.updated_at,
            "deleted_at": entry.deleted_at,
            "password_changed_at": entry.password_changed_at,
        }
        # 绑定加密字段密文到签名，防密文置换或回滚。长度前缀拼接避免固定分隔符
        # 在未来加密格式下产生歧义载荷。
        enc_parts = [
            entry.custom_fields_db_value if field == "custom_fields" else getattr(entry, field)
            for field in SIGNATURE_ENCRYPTED_FIELD_ORDER
        ]
        enc_concat = "".join(f"{len(p)}:{p}" for p in enc_parts)
        data["_enc_hash"] = hashlib.sha256(enc_concat.encode("utf-8")).hexdigest()
        return MetadataSigner._canonical_json_bytes(data)

    @staticmethod
    def _category_payload(category: Category) -> bytes:
        """构造分类签名载荷。

        name 为密文，以 SHA-256 摘要绑定（name_hash）防置换。与条目 ``_payload`` 的
        ``_enc_hash`` 不同：分类仅单个加密字段，直接对 name 取 SHA-256，勿按条目
        范式「对齐」（会改签名格式、破坏已持久化的 metadata_mac）。id 入载荷防错配。
        """
        data = {
            "id": category.id,
            "name_hash": hashlib.sha256(category.name.encode("utf-8")).hexdigest(),
            "icon_char": category.icon_char,
            "color": category.color,
            "sort_order": category.sort_order,
            "created_at": category.created_at,
        }
        return MetadataSigner._canonical_json_bytes(data)
