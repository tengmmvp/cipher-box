"""加密引擎 - AES-256-GCM 加密/解密。

内存安全说明：``_cipher_cache`` 使用密钥的 SHA-256 摘要作为缓存键，
不再以原始密钥 bytes 作为 dict key，避免缓存字典持有原始密钥材料的额外
引用。缓存在 ``clear_cache`` 被显式调用前会一直驻留进程内存，
``VaultManager.lock`` 与 ``_re_encrypt_all`` 负责调用。
调用方必须在密钥失效（锁定或改密）时调用 ``clear_cache``。

CPython 固有限制：``bytes`` 对象不可变，无法从 Python 层面原地清零。
``clear_cache`` 仅清除缓存字典的引用，原始 ``bytes`` 对象依赖 GC 回收。
这是 CPython 的根本限制，非代码缺陷——如需更强保障需使用 C 扩展或 mmap。
"""

import base64
import hashlib
import logging
import os
import threading

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)


def _cache_key(key: bytes) -> bytes:
    """返回密钥的 SHA-256 摘要用作缓存键，避免缓存持有原始密钥材料。"""
    return hashlib.sha256(key).digest()


# AESGCM 实例缓存线程锁，保护 _cipher_cache 的并发读写。
_cache_lock = threading.RLock()

# AESGCM 实例缓存：按密钥 SHA-256 摘要索引，避免缓存持有原始密钥材料。
# 缓存通常仅含 1-2 条（当前活跃密钥），_MAX_CACHE_SIZE 为安全上限。
# 在 VaultManager.lock() 和 _re_encrypt_all 完成后显式清除。
_MAX_CACHE_SIZE = 16
_cipher_cache: dict[bytes, AESGCM] = {}


class EncryptionEngine:
    """使用 AES-256-GCM 进行数据加密和解密"""

    NONCE_SIZE = 12  # GCM 推荐 nonce 长度
    TAG_SIZE = 16    # GCM 认证标签长度，128 位
    FORMAT_ID = 'aes-256-gcm-aad'
    TEXT_PREFIX = 'cb:'
    BYTES_PREFIX = b'CBX'
    # 空值哨兵：使用 UUID 前缀降低碰撞概率，保留旧哨兵用于解密兼容。
    _EMPTY_SENTINEL = '__CBX_EMPTY_7f3a2b1c-4d5e-6f8a-9b0c-1d2e3f4a5b6c__'
    _EMPTY_BYTES_SENTINEL = b'__CBX_BE_7f3a2b1c-4d5e-6f8a-9b0c-1d2e3f4a5b6c__'
    # 旧版哨兵，仅解密时兼容
    _EMPTY_SENTINEL_LEGACY = '__CBX_INTERNAL_EMPTY_V1__'
    _EMPTY_BYTES_SENTINEL_LEGACY = b'__CBX_BYTES_EMPTY_V1__'
    _EMPTY_BYTES_SENTINEL_V0 = b'\x00'  # V0 旧版哨兵，仅解密时兼容

    @classmethod
    def _get_cipher(cls, key: bytes) -> AESGCM:
        """获取或创建 AESGCM 实例，按密钥 SHA-256 摘要缓存"""
        # 密钥校验：类型与长度，防止意外降级为 AES-128
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError(f'AES-256 密钥类型无效：期望 bytes，实际 {type(key).__name__}')
        if len(key) != 32:
            raise ValueError(
                f'AES-256 密钥长度无效：期望 32 字节，实际 {len(key)} 字节'
            )
        with _cache_lock:
            ck = _cache_key(key)
            cipher = _cipher_cache.get(ck)
            if cipher is None:
                # 安全上限：防止异常场景下缓存无限增长
                if len(_cipher_cache) > _MAX_CACHE_SIZE:
                    logger.warning("加密缓存超过上限 (%d > %d)，执行全量清除",
                                   len(_cipher_cache), _MAX_CACHE_SIZE)
                    _cipher_cache.clear()
                cipher = AESGCM(key)
                _cipher_cache[ck] = cipher
            return cipher

    @classmethod
    def clear_cache(cls):
        """清除 AESGCM 实例缓存（密钥失效后调用，如锁定或改密）。

        清除缓存字典中所有条目，释放密钥引用。由于 CPython ``bytes`` 不可变，
        无法原地清零密钥内容；清除引用后依赖 GC 回收释放内存。
        调用方应在 ``clear_cache`` 后考虑触发 ``gc.collect()`` 以加速回收
        （VaultManager.lock 已处理）。
        """
        with _cache_lock:
            _cipher_cache.clear()

    @staticmethod
    def _aad_bytes(associated_data: str | bytes) -> bytes:
        return associated_data.encode('utf-8') if isinstance(associated_data, str) else associated_data

    @classmethod
    def encrypt(
        cls,
        plaintext: str,
        key: bytes,
        associated_data: str | bytes,
    ) -> str:
        """加密明文，返回 base64 编码的密文

        Args:
            plaintext: 待加密的明文字符串
            key: 32 字节 AES-256 密钥

        Returns:
            base64 编码的 (nonce + ciphertext + tag) 字节串
        """
        # 空字符串加密 sentinel 而非跳过，确保 AAD 始终参与认证。
        # 旧版数据库中的空串密文字段解密时仍走 `if not encrypted: return ''` 路径，兼容。
        if not plaintext:
            plaintext = cls._EMPTY_SENTINEL
        nonce = os.urandom(cls.NONCE_SIZE)
        aesgcm = cls._get_cipher(key)
        aad = cls._aad_bytes(associated_data)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), aad)
        # nonce + ciphertext (ciphertext 已包含 tag)
        encoded = base64.b64encode(nonce + ciphertext).decode('ascii')
        return cls.TEXT_PREFIX + encoded

    @classmethod
    def decrypt(
        cls,
        encrypted_b64: str,
        key: bytes,
        associated_data: str | bytes,
        *,
        strict: bool = False,
    ) -> str:
        """解密 base64 编码的密文

        Args:
            encrypted_b64: base64 编码的 (nonce + ciphertext + tag)
            key: 32 字节 AES-256 密钥
            strict: 为 True 时对空密文抛出 ValueError 而非静默返回空串。
                新代码路径（如 EntryManager 非容错模式）可启用。

        Returns:
            解密后的明文字符串

        Raises:
            ValueError: 解密失败时抛出
        """
        # 空密文兼容路径废弃计划
        # DESIGN LIMITATION: 空密文跳过 AAD 验证是向后兼容的必要折衷。
        # 旧版数据库中未加密的空字段存储为空字符串，此处必须放行。
        # 元数据完整性签名（metadata_mac）在条目级别覆盖了此场景——
        # 即使空字段绕过了单值 AAD 验证，条目级 MAC 仍能检测篡改。
        #
        # DEPRECATION TIMELINE: 此兼容路径计划在 CipherBox v2.0 移除。
        # 新数据库不再产生空密文字段（encrypt() 将空字符串替换为 sentinel）。
        # 迁移计划：在下次 schema 升级时，将所有空字段加密为 sentinel 值，
        # 然后移除此分支并将 strict 默认值改为 True。
        if not encrypted_b64:
            if strict:
                raise ValueError('收到空密文，数据可能已被篡改')
            logger.warning("解密收到空密文，此兼容路径计划在未来版本移除")
            return ''
        try:
            if not encrypted_b64.startswith(cls.TEXT_PREFIX):
                raise ValueError('不支持的密文格式')
            encoded = encrypted_b64[len(cls.TEXT_PREFIX):]
            raw = base64.b64decode(encoded, validate=True)
            if len(raw) < cls.NONCE_SIZE + cls.TAG_SIZE:
                raise ValueError('密文长度无效')
            nonce = raw[:cls.NONCE_SIZE]
            ciphertext = raw[cls.NONCE_SIZE:]
            aesgcm = cls._get_cipher(key)
            aad = cls._aad_bytes(associated_data)
            plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
            result = plaintext.decode('utf-8')
            # 匹配新旧哨兵
            if result in (cls._EMPTY_SENTINEL, cls._EMPTY_SENTINEL_LEGACY):
                return ''
            return result
        except (InvalidTag, ValueError, AttributeError, TypeError) as exc:
            # 仅记录异常类型，不记录完整堆栈，防止密文片段泄露到日志
            logger.warning("解密失败: %s", type(exc).__name__)
            raise ValueError('解密失败，密钥或数据可能已损坏') from None

    @classmethod
    def encrypt_bytes(
        cls,
        data: bytes,
        key: bytes,
        associated_data: str | bytes,
    ) -> bytes:
        """加密字节数据"""
        if not data:
            # 使用哨兵走正常 GCM 加密，确保 AAD 始终参与认证。
            # 与字符串路径的 _EMPTY_SENTINEL 对称。
            data = cls._EMPTY_BYTES_SENTINEL
        nonce = os.urandom(cls.NONCE_SIZE)
        aesgcm = cls._get_cipher(key)
        aad = cls._aad_bytes(associated_data)
        ciphertext = aesgcm.encrypt(nonce, data, aad)
        payload = nonce + ciphertext
        return cls.BYTES_PREFIX + payload

    @classmethod
    def decrypt_bytes(
        cls,
        data: bytes,
        key: bytes,
        associated_data: str | bytes,
        *,
        strict: bool = False,
    ) -> bytes:
        """解密字节数据

        Args:
            strict: 为 True 时对空密文抛出 ValueError 而非静默返回空字节。
        """
        if not data.startswith(cls.BYTES_PREFIX):
            raise ValueError('不支持的密文字节格式')
        payload = data[len(cls.BYTES_PREFIX):]
        # 向后兼容：旧格式中空输入仅存储前缀，payload 为空。
        if not payload:
            if strict:
                raise ValueError('收到空密文字节，数据可能已被篡改')
            return b''
        if len(payload) < cls.NONCE_SIZE + cls.TAG_SIZE:
            raise ValueError('密文长度无效')
        nonce = payload[:cls.NONCE_SIZE]
        ciphertext = payload[cls.NONCE_SIZE:]
        aesgcm = cls._get_cipher(key)
        aad = cls._aad_bytes(associated_data)
        try:
            result = aesgcm.decrypt(nonce, ciphertext, aad)
        except (InvalidTag, ValueError, AttributeError, TypeError) as exc:
            # 仅记录异常类型，不记录完整堆栈
            logger.warning("解密失败: %s", type(exc).__name__)
            raise ValueError('解密失败，密钥或数据可能已损坏') from None
        # 匹配所有版本的哨兵
        if result in (
            cls._EMPTY_BYTES_SENTINEL,
            cls._EMPTY_BYTES_SENTINEL_LEGACY,
            cls._EMPTY_BYTES_SENTINEL_V0,
        ):
            return b''
        return result
