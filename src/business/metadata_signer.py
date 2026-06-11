"""条目元数据 HMAC 签名与验证。

从 VaultManager 提取的职责：计算和验证条目元数据的 HMAC 签名，
防止未授权篡改条目的非敏感字段，如标题、URL、分类等。
"""

import hashlib
import hmac
import json
import logging

from ..exceptions import VaultIntegrityError, VaultLockedError

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
    def compute_domain_key(key: bytes) -> bytes:
        """从主密钥派生 metadata 签名域密钥。"""
        return hmac.new(key, b'cipherbox:entry-metadata-key', hashlib.sha256).digest()

    def sign(self, entry, key: bytes | None = None) -> str:
        """计算条目元数据 HMAC 签名。

        Args:
            entry: 条目对象（Entry dataclass 实例）。
            key: 可选的显式密钥。为 None 时使用预计算的域密钥。

        Returns:
            HMAC-SHA256 十六进制摘要字符串。

        Raises:
            VaultLockedError: 未提供密钥且域密钥不可用。
        """
        signing_key = key or self._domain_key
        if signing_key is None:
            raise VaultLockedError('保险库未解锁，无法签名条目元数据')
        # 使用预计算的域密钥，仅在传入显式 key 时临时计算。
        # 当 key=None 时 signing_key=self._domain_key，上方已验证非 None，
        # 直接复用预计算域密钥避免重复 HMAC 派生。
        domain_key = self._domain_key if key is None else self.compute_domain_key(signing_key)
        assert domain_key is not None  # signing_key 非空检查保证
        return hmac.new(
            domain_key,
            self._payload(entry),
            hashlib.sha256,
        ).hexdigest()

    def sign_with_domain_key(self, entry, domain_key: bytes) -> str:
        """直接使用预计算的域密钥签名，跳过密钥派生步骤。

        用于批量重加密场景（KeyRotationService），避免每条条目
        重复调用 ``compute_domain_key`` 的 HMAC 开销。

        Args:
            entry: 条目对象。
            domain_key: 预计算的域密钥（由 ``compute_domain_key`` 生成）。
        """
        return hmac.new(
            domain_key,
            self._payload(entry),
            hashlib.sha256,
        ).hexdigest()

    def verify(self, entry, key: bytes | None = None) -> None:
        """验证条目元数据完整性签名。

        签名格式迁移策略：
          - 新格式（v3+）：payload 包含加密字段哈希（``_enc_hash``），
            由 ``sign`` 默认生成。
          - 旧格式（v2）：payload 不含 ``_enc_hash``，由
            ``_payload(entry, include_enc_hash=False)`` 生成。

        验证时先尝试新格式，失败后回退旧格式。旧签名条目在下次写入时
        由 ``sign`` 自动升级为新格式签名，无需显式迁移。
        两种格式均不匹配则抛出 VaultIntegrityError。

        Args:
            entry: 条目对象。
            key: 可选的显式密钥。

        Raises:
            VaultIntegrityError: 签名验证失败。
            VaultLockedError: 保险库未解锁。
        """
        if not entry.metadata_mac:
            raise VaultIntegrityError(f'条目 {entry.id} 缺少元数据完整性签名')
        # 先尝试新格式，含加密字段哈希，失败后回退旧格式，自迁移策略
        expected_new = self.sign(entry, key=key)
        if hmac.compare_digest(entry.metadata_mac, expected_new):
            return
        # 回退旧格式，不含 _enc_hash，兼容已有条目
        domain_key = self._domain_key
        if domain_key is None:
            if key is None:
                raise VaultLockedError('保险库未解锁')
            domain_key = self.compute_domain_key(key)
        expected_old = hmac.new(
            domain_key,
            self._payload(entry, include_enc_hash=False),
            hashlib.sha256,
        ).hexdigest()
        if hmac.compare_digest(entry.metadata_mac, expected_old):
            logger.debug("条目 %s 签名使用旧格式，下次写入时自动升级", entry.id)
            return
        raise VaultIntegrityError(f'条目 {entry.id} 元数据完整性校验失败')

    @staticmethod
    def _payload(entry, *, include_enc_hash: bool = True) -> bytes:
        """构造签名载荷。

        Args:
            entry: 条目对象。
            include_enc_hash: 是否包含加密字段密文的 SHA-256 哈希，
                v3+ 签名包含，默认 True，v2 兼容验证不含。

        Returns:
            UTF-8 编码的 JSON 字节串。
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
        if include_enc_hash:
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
