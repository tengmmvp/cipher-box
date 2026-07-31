"""条目元数据 HMAC 签名与验证。

从 VaultManager 提取的职责：计算和验证条目元数据的 HMAC 签名，
防止未授权篡改条目的密文元数据、分类关联与状态字段。
"""

import hashlib
import hmac
import json
import logging

from ...exceptions import VaultIntegrityError, VaultLockedError
from ...models import Category, RawEntry
from ...utils.memory import secure_zero_buffer

logger = logging.getLogger(__name__)

# vault_meta 完整性签名覆盖的安全相关键（密码派生与密钥版本元数据）。
# 含 snapshot_key_enc：虽由主密钥加密保护（随机篡改会在 _load_snapshot_key 解密
# 时失败），但 GCM 用常量 AAD 不防重放——有 DB 写权限者可用旧有效密文替换而绕过；
# 纳入签名后此类回滚/重放使 mac 失配而被 unlock 拒绝。不含 vault_meta_mac 自身
# （签名不能包含自身）。
VAULT_META_SIGNED_KEYS = (
    'master_salt', 'master_verify',
    'master_kdf_time_cost', 'master_kdf_memory_cost', 'master_kdf_parallelism',
    'ciphertext_format', 'key_epoch', 'snapshot_key_enc',
)

# 签名绑定的加密字段及固定顺序（子集 + 顺序单一源）。必须等于
# crypto_utils.SENSITIVE_ENCRYPTED_FIELDS 减 {title, url, tags}（这三者在 _payload
# 顶层以密文形态直接入签——sign/verify 操作 RawEntry，其 title/url/tags 即密文），
# 且顺序固定——改顺序会破坏已有数据的 metadata_mac。
# tests/test_field_consistency.py 守护此子集关系。custom_fields 在签名侧取
# custom_fields_db_value（密文形态），故遍历时特判。
SIGNATURE_ENCRYPTED_FIELD_ORDER = ('username', 'password', 'notes', 'totp_secret', 'custom_fields')


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
        self._domain_key = self._normalize_domain_key(key)

    @property
    def domain_key(self) -> bytearray | None:
        """当前域密钥，供 VaultManager 清零密钥时访问。"""
        return self._domain_key

    @domain_key.setter
    def domain_key(self, value: bytearray | None) -> None:
        # 与 set_domain_key 归一一致：防经 setter 传入 bytes 绕过 bytearray 持有
        # 使清零失效。VaultManager 经此传 None 清零，None 保留。
        self._domain_key = self._normalize_domain_key(value)

    @staticmethod
    def _normalize_domain_key(value: bytes | bytearray | None) -> bytearray | None:
        """归一域密钥为 bytearray：None 透传，bytes|bytearray 转 bytearray 副本。

        统一 set_domain_key 与 domain_key setter 的归一逻辑：始终以 bytearray 持有，
        使 secure_zero_buffer 能原地清零；传入不可变 bytes 时转为 bytearray 副本，
        避免清零失效。compute_domain_key 已返回 bytearray，对其为 no-op。
        """
        if value is None:
            return None
        return value if isinstance(value, bytearray) else bytearray(value)

    @staticmethod
    def compute_domain_key(key: bytes | bytearray) -> bytearray:
        """从主密钥派生 metadata 签名域密钥，返回 bytearray 以便真正清零。

        返回 bytearray（而非 bytes）使 _clear_vault_state 的 secure_zero_buffer
        能原地清零，与 KeyManager 的清零策略一致；bytes 不可变只能清零副本。
        """
        return bytearray(hmac.new(key, b'cipherbox:entry-metadata-key', hashlib.sha256).digest())

    @staticmethod
    def compute_vault_meta_domain_key(key: bytes | bytearray) -> bytearray:
        """从主密钥派生 vault_meta 完整性签名的独立域密钥，返回 bytearray 以便清零。

        与 :meth:`compute_domain_key`（条目/分类元数据签名）显式域分离：vault_meta
        完整性（保险库级密码派生参数/密钥版本）与条目/分类元数据（条目级）是两类
        不同用途的签名，使用各自独立的 HKDF-style info 标签派生密钥，遵循与主密钥/
        备份密钥域分离一致的原则，避免未来消息空间扩展时产生跨协议交互。
        """
        return bytearray(hmac.new(key, b'cipherbox:vault-meta-key', hashlib.sha256).digest())

    @staticmethod
    def compute_vault_meta_mac(meta: dict, key: bytes | bytearray) -> str:
        """计算 vault_meta 安全相关字段的 HMAC-SHA256，用主密钥派生的域密钥签名。

        检测 vault_meta 被外部篡改（如替换 master_salt、改写 KDF 参数、伪造
        key_epoch）。用主密钥派生的域密钥签名：篡改 KDF 参数会使主密钥派生变化，
        导致 unlock 的 verify_token 解密先行失败，故此 MAC 主要在 verify 通过后
        对未导致派生失败的篡改提供统一的完整性校验与明确拒绝。域密钥为局部副本，
        用后清零收缩驻留。
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

    def sign_category(self, category: Category) -> str:
        """计算分类元数据 HMAC 签名，使用预计算的域密钥。

        与条目签名共享同一域密钥（主密钥派生）。跨 epoch 隔离同样由域密钥轮换
        提供：改密产生新域密钥，旧分类签名在新域密钥下验证失败，故改密时
        re_encrypt_categories 须在重加密分类名后重签。
        """
        if self._domain_key is None:
            raise VaultLockedError('保险库未解锁，无法签名分类元数据')
        return hmac.new(
            self._domain_key, self._category_payload(category), hashlib.sha256,
        ).hexdigest()

    def sign_category_with_domain_key(
        self, category: Category, domain_key: bytes | bytearray,
    ) -> str:
        """直接用预计算的域密钥签名分类，跳过密钥派生与 ``_domain_key`` 读取。

        对称 :meth:`sign_with_domain_key`，供 ``ReEncryptionService.re_encrypt_categories``
        在改密事务内用新域密钥重签分类。改密事务内 ``_domain_key`` 仍是旧值
        （vault_manager 在事务提交后才正式 ``set_domain_key(new)``），若分类重签
        沿用 ``sign_category``（读 ``_domain_key``）会用旧域密钥，导致改密后
        ``verify_category`` 永久失败。调用方预计算 ``compute_domain_key(new_key)``
        后注入，使分类重签与条目 ``sign_with_domain_key(new)`` 对称，且不临时切换
        signer 全局 ``_domain_key``。

        Args:
            category: 分类对象。
            domain_key: 预计算的域密钥（``compute_domain_key`` 返回 bytearray），
                接受 bytes | bytearray，与 ``sign_with_domain_key`` 的清零语义统一。
        """
        return hmac.new(
            domain_key, self._category_payload(category), hashlib.sha256,
        ).hexdigest()

    def verify_category(self, category: Category) -> None:
        """验证分类元数据完整性签名。

        Raises:
            VaultIntegrityError: 签名验证失败（含空签名）。
            VaultLockedError: 保险库未解锁。
        """
        if not category.metadata_mac:
            raise VaultIntegrityError(f'分类 {category.id} 缺少元数据完整性签名')
        expected = self.sign_category(category)
        if not hmac.compare_digest(category.metadata_mac, expected):
            raise VaultIntegrityError(f'分类 {category.id} 元数据完整性校验失败')

    @staticmethod
    def _canonical_json_bytes(data: dict) -> bytes:
        """规范化 JSON 字节串：排序键、紧凑分隔、UTF-8 编码。

        供 ``_payload``（条目）与 ``_category_payload``（分类）复用，确保两类签名
        载荷的序列化参数完全一致，避免两处独立维护导致漂移——漏改一处会使一侧
        签名可验、另一侧验签失败却难以定位。
        """
        return json.dumps(
            data, ensure_ascii=False, sort_keys=True, separators=(',', ':'),
        ).encode('utf-8')

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
            entry.custom_fields_db_value if field == 'custom_fields' else getattr(entry, field)
            for field in SIGNATURE_ENCRYPTED_FIELD_ORDER
        ]
        enc_concat = ''.join(f'{len(p)}:{p}' for p in enc_parts)
        data['_enc_hash'] = hashlib.sha256(enc_concat.encode('utf-8')).hexdigest()
        return MetadataSigner._canonical_json_bytes(data)

    @staticmethod
    def _category_payload(category: Category) -> bytes:
        """构造分类签名载荷。

        name 为密文，以 SHA-256 摘要绑定（name_hash），防止分类名密文置换。注意
        与条目 ``_payload`` 的 ``_enc_hash`` 机制不同：条目对「长度前缀拼接的全部
        加密字段」取单个 SHA-256（多字段），分类仅对单个 name 取 SHA-256——因分类
        只有一个加密字段。两者均为「密文 SHA-256 绑定」但实现非镜像，勿按条目范式
        「对齐」分类载荷，否则会改变签名格式、破坏已持久化的 category metadata_mac
        验签。其余元数据（icon/color/sort_order/created_at）直接入签；id 入载荷防
        id 与元数据错配。
        """
        data = {
            'id': category.id,
            'name_hash': hashlib.sha256(category.name.encode('utf-8')).hexdigest(),
            'icon_char': category.icon_char,
            'color': category.color,
            'sort_order': category.sort_order,
            'created_at': category.created_at,
        }
        return MetadataSigner._canonical_json_bytes(data)
