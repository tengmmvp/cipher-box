"""条目元数据 HMAC 签名与验证。

从 VaultManager 提取的职责：计算和验证条目元数据的 HMAC 签名，
防止未授权篡改条目的密文元数据、分类关联与状态字段。
"""

import hashlib
import hmac
import json
import logging

from ...exceptions import VaultIntegrityError, VaultLockedError
from ...models import RawEntry
from ...utils.memory import secure_zero_buffer

logger = logging.getLogger(__name__)

# vault_meta 完整性签名覆盖的安全相关键（密码派生与密钥版本元数据）。
# 不含 snapshot_key_enc（已由主密钥加密保护，其篡改会在 _load_snapshot_key
# 解密时失败）；不含 vault_meta_mac 自身（签名不能包含自身）。
VAULT_META_SIGNED_KEYS = (
    'master_salt', 'master_verify',
    'master_kdf_time_cost', 'master_kdf_memory_cost', 'master_kdf_parallelism',
    'ciphertext_format', 'key_epoch',
)


class MetadataSigner:
    """条目元数据 HMAC 签名与验证。

    使用从主密钥派生的域密钥对条目的非敏感元数据生成 HMAC-SHA256 签名。
    签名载荷包含加密字段密文的 SHA-256 哈希，以绑定密文与元数据，
    防止密文置换或回滚攻击。

    域密钥通过 ``set_domain_key()`` 设置，解锁时由 VaultManager 调用，
    或在 ``sign()`` / ``verify()`` 时传入显式 key 临时派生。
    """

    def __init__(self, domain_key: bytes | bytearray | None = None):
        self._domain_key = (
            bytearray(domain_key) if domain_key is not None else None
        )

    def set_domain_key(self, key: bytes | bytearray) -> None:
        """设置预计算的域密钥，解锁或改密成功后调用。

        统一以 bytearray 持有，使 _clear_vault_state 的 secure_zero_buffer 能
        原地清零；传入不可变 bytes 时转为 bytearray 副本，避免清零失效。
        compute_domain_key 已返回 bytearray，归一化对其为 no-op。
        """
        self._domain_key = key if isinstance(key, bytearray) else bytearray(key)

    @property
    def domain_key(self) -> bytearray | None:
        """当前域密钥，供 VaultManager 清零密钥时访问。"""
        return self._domain_key

    @domain_key.setter
    def domain_key(self, value: bytearray | None) -> None:
        self._domain_key = value

    @staticmethod
    def compute_domain_key(key: bytes | bytearray) -> bytearray:
        """从主密钥派生 metadata 签名域密钥，返回 bytearray 以便真正清零。

        返回 bytearray（而非 bytes）使 _clear_vault_state 的 secure_zero_buffer
        能原地清零，与 KeyManager 的清零策略一致；bytes 不可变只能清零副本。
        """
        return bytearray(hmac.new(key, b'cipherbox:entry-metadata-key', hashlib.sha256).digest())

    @staticmethod
    def compute_vault_meta_mac(meta: dict, key: bytes | bytearray) -> str:
        """计算 vault_meta 安全相关字段的 HMAC-SHA256，用主密钥派生的域密钥签名。

        检测 vault_meta 被外部篡改（如替换 master_salt、改写 KDF 参数、伪造
        key_epoch）。用主密钥派生的域密钥签名：篡改 KDF 参数会使主密钥派生变化，
        导致 unlock 的 verify_token 解密先行失败，故此 MAC 主要在 verify 通过后
        对未导致派生失败的篡改提供统一的完整性校验与明确拒绝。域密钥为局部副本，
        用后清零收缩驻留。
        """
        dk = MetadataSigner.compute_domain_key(key)
        try:
            payload = json.dumps(
                {k: meta.get(k) for k in VAULT_META_SIGNED_KEYS},
                sort_keys=True, ensure_ascii=False, separators=(',', ':'),
            ).encode('utf-8')
            return hmac.new(dk, payload, hashlib.sha256).hexdigest()
        finally:
            secure_zero_buffer(dk)

    def sign(self, entry: RawEntry) -> str:
        """计算条目元数据 HMAC 签名，使用预计算的域密钥。

        Returns:
            HMAC-SHA256 十六进制摘要字符串。

        Raises:
            VaultLockedError: 域密钥未设置（保险库未解锁）。
        """
        if self._domain_key is None:
            raise VaultLockedError('保险库未解锁，无法签名条目元数据')
        return hmac.new(
            self._domain_key,
            self._payload(entry),
            hashlib.sha256,
        ).hexdigest()

    def sign_with_domain_key(self, entry: RawEntry, domain_key: bytes | bytearray) -> str:
        """直接使用预计算的域密钥签名，跳过密钥派生步骤。

        用于 ReEncryptionService 批量重加密场景，避免每条条目
        重复调用 ``compute_domain_key`` 的 HMAC 开销。

        Args:
            entry: 条目对象。
            domain_key: 预计算的域密钥，由 ``compute_domain_key`` 生成
                （返回 bytearray）。接受 bytes | bytearray，与 ``compute_domain_key``
                的返回类型及清零语义统一。
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
            raise VaultIntegrityError(f'条目 {entry.id} 缺少元数据完整性签名')
        expected = self.sign(entry)
        if not hmac.compare_digest(entry.metadata_mac, expected):
            raise VaultIntegrityError(f'条目 {entry.id} 元数据完整性校验失败')

    @staticmethod
    def _payload(entry: RawEntry) -> bytes:
        """构造签名载荷。

        Args:
            entry: 条目对象。

        Returns:
            UTF-8 编码的 JSON 字节串。

        Note:
            载荷不含 ``key_epoch``：跨 epoch 的签名隔离已由域密钥本身提供——
            域密钥从主密钥派生，改密/恢复轮换主密钥即产生新域密钥，旧签名在新
            域密钥下验证必然失败。故无需将 epoch 显式纳入载荷。
        """
        data = {
            'crypto_id': entry.crypto_id,
            'title': entry.title,
            'url': entry.url,
            'category_id': entry.category_id,
            'tags': entry.tags,
            'is_favorite': bool(entry.is_favorite),
            'is_deleted': bool(entry.is_deleted),
            'password_strength': entry.password_strength,
            'entry_type': entry.entry_type,
            'created_at': entry.created_at,
            'updated_at': entry.updated_at,
            'deleted_at': entry.deleted_at,
            'password_changed_at': entry.password_changed_at,
        }
        # 绑定加密字段密文到签名，防止密文置换或回滚攻击。长度前缀拼接消除对
        # 「密文不含分隔符」的隐式假设：固定分隔符（如 '|'）在当前 cb2: base64 密文
        # 下安全，但未来加密格式若使密文含该字符会产生歧义载荷；长度前缀无歧义。
        enc_parts = [
            entry.username, entry.password, entry.notes,
            entry.totp_secret, entry.custom_fields_db_value,
        ]
        enc_concat = ''.join(f'{len(p)}:{p}' for p in enc_parts)
        data['_enc_hash'] = hashlib.sha256(enc_concat.encode('utf-8')).hexdigest()
        return json.dumps(
            data,
            ensure_ascii=False,
            sort_keys=True,
            separators=(',', ':'),
        ).encode('utf-8')
