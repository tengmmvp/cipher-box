"""条目元数据 HMAC 签名与验证。

从 VaultManager 提取的职责：计算和验证条目元数据的 HMAC 签名，
防止未授权篡改条目的非敏感字段，如标题、URL、分类等。
"""

import hashlib
import hmac
import json
import logging

from ...exceptions import VaultIntegrityError, VaultLockedError

logger = logging.getLogger(__name__)


class MetadataSigner:
    """条目元数据 HMAC 签名与验证。

    使用从主密钥派生的域密钥对条目的非敏感元数据生成 HMAC-SHA256 签名。
    签名载荷包含加密字段密文的 SHA-256 哈希，以绑定密文与元数据，
    防止密文置换或回滚攻击。

    域密钥通过 ``set_domain_key()`` 设置，解锁时由 VaultManager 调用，
    或在 ``sign()`` / ``verify()`` 时传入显式 key 临时派生。
    """

    def __init__(self, domain_key: bytes | None = None):
        self._domain_key = domain_key

    def set_domain_key(self, key: bytes) -> None:
        """设置预计算的域密钥，解锁或改密成功后调用。"""
        self._domain_key = key

    @property
    def domain_key(self) -> bytes | None:
        """当前域密钥，供 VaultManager 清零密钥时访问。"""
        return self._domain_key

    @domain_key.setter
    def domain_key(self, value: bytes | None) -> None:
        self._domain_key = value

    @staticmethod
    def compute_domain_key(key: bytes) -> bytearray:
        """从主密钥派生 metadata 签名域密钥，返回 bytearray 以便真正清零。

        返回 bytearray（而非 bytes）使 _clear_vault_state 的 secure_zero_buffer
        能原地清零，与 KeyManager 的清零策略一致；bytes 不可变只能清零副本。
        """
        return bytearray(hmac.new(key, b'cipherbox:entry-metadata-key', hashlib.sha256).digest())

    def sign(self, entry) -> str:
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

    def sign_with_domain_key(self, entry, domain_key: bytes) -> str:
        """直接使用预计算的域密钥签名，跳过密钥派生步骤。

        用于 KeyRotationService 批量重加密场景，避免每条条目
        重复调用 ``compute_domain_key`` 的 HMAC 开销。

        Args:
            entry: 条目对象。
            domain_key: 预计算的域密钥，由 ``compute_domain_key`` 生成。
        """
        return hmac.new(
            domain_key,
            self._payload(entry),
            hashlib.sha256,
        ).hexdigest()

    def verify(self, entry) -> None:
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
    def _payload(entry) -> bytes:
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
        # 绑定加密字段密文到签名，防止密文置换或回滚攻击
        enc_concat = '|'.join([
            entry.username, entry.password, entry.notes,
            entry.totp_secret, entry.custom_fields_db_value,
        ])
        data['_enc_hash'] = hashlib.sha256(enc_concat.encode('utf-8')).hexdigest()
        return json.dumps(
            data,
            ensure_ascii=False,
            sort_keys=True,
            separators=(',', ':'),
        ).encode('utf-8')
