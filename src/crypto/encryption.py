"""加密引擎 — AES-256-GCM 加密/解密。

``_cipher_cache`` 以密钥 SHA-256 摘要索引 AESGCM（不持原始密钥），密钥失效
（锁定/改密）须 ``clear_cache``。bytes 不可变，彻底清零依赖 GC（CPython 限制）。
"""

import base64
import hashlib
import logging
import os
import threading
from collections import OrderedDict

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..exceptions import DecryptionError
from ..models import CIPHERTEXT_BYTES_PREFIX, CIPHERTEXT_PREFIX

logger = logging.getLogger(__name__)


def _cache_key(key: bytes | bytearray) -> bytes:
    """返回密钥的 SHA-256 摘要用作缓存键，避免缓存持有原始密钥材料。"""
    return hashlib.sha256(key).digest()


_cache_lock = threading.RLock()
# 容量 2：改密瞬间旧+新两个密钥并存，恰好容纳双密钥窗口避免反复 evict 重建；
# 超过 2 会扩大历史密钥 AESGCM 副本（持 C 层密钥拷贝）驻留，增大崩溃 dump 攻击面。
_MAX_CACHE_SIZE = 2
_cipher_cache: OrderedDict[bytes, AESGCM] = OrderedDict()


class EncryptionEngine:
    """使用 AES-256-GCM 进行数据加密和解密。"""

    NONCE_SIZE = 12  # GCM 推荐 nonce 长度
    TAG_SIZE = 16    # GCM 认证标签长度，128 位
    KEY_SIZE = 32    # AES-256 密钥长度
    FORMAT_ID = 'aes-256-gcm-aad'
    # 前缀取自共享层 models.CIPHERTEXT_PREFIX（单一事实源），数据层密文自检与日志脱敏共用。
    TEXT_PREFIX = CIPHERTEXT_PREFIX
    BYTES_PREFIX = CIPHERTEXT_BYTES_PREFIX

    @classmethod
    def _get_cipher(cls, key: bytes | bytearray) -> AESGCM:
        """获取或创建 AESGCM 实例，按密钥 SHA-256 摘要缓存。"""
        # 密钥校验：类型与长度，防止意外降级为 AES-128
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError(f'AES-256 密钥类型无效：期望 bytes，实际 {type(key).__name__}')
        if len(key) != cls.KEY_SIZE:
            raise ValueError(
                f'AES-256 密钥长度无效：期望 {cls.KEY_SIZE} 字节，实际 {len(key)} 字节'
            )
        with _cache_lock:
            cache_key = _cache_key(key)
            cipher = _cipher_cache.get(cache_key)
            if cipher is None:
                cipher = AESGCM(key)
                _cipher_cache[cache_key] = cipher
                # LRU：超限时淘汰最旧条目，而非全量清空（保留活跃密钥）
                if len(_cipher_cache) > _MAX_CACHE_SIZE:
                    _cipher_cache.popitem(last=False)
            else:
                _cipher_cache.move_to_end(cache_key)
            return cipher

    @classmethod
    def clear_cache(cls) -> None:
        """清除 AESGCM 实例缓存。密钥失效（锁定/改密）后调用。"""
        with _cache_lock:
            _cipher_cache.clear()

    @staticmethod
    def _aad_bytes(associated_data: str | bytes) -> bytes:
        """将 AAD 归一为 bytes：str 经 UTF-8 编码，bytes 原样返回。"""
        return associated_data.encode('utf-8') if isinstance(associated_data, str) else associated_data

    @classmethod
    def encrypt(
        cls,
        plaintext: str,
        key: bytes | bytearray,
        associated_data: str | bytes,
    ) -> str:
        """加密明文，返回带前缀的 base64 密文。

        Args:
            plaintext: 待加密的明文字符串
            key: 32 字节 AES-256 密钥
            associated_data: 参与认证的附加数据，解密时需原样提供

        Returns:
            ``cb2:`` 前缀加 base64 的密文字符串（随机 nonce + 密文 + GCM 标签）。
        """
        nonce = os.urandom(cls.NONCE_SIZE)
        aesgcm = cls._get_cipher(key)
        aad = cls._aad_bytes(associated_data)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), aad)
        encoded = base64.b64encode(nonce + ciphertext).decode('ascii')
        return cls.TEXT_PREFIX + encoded

    @classmethod
    def decrypt(
        cls,
        encrypted_b64: str,
        key: bytes | bytearray,
        associated_data: str | bytes,
    ) -> str:
        """解密由 encrypt 产生的密文，返回明文字符串。

        Args:
            encrypted_b64: encrypt 返回的密文字符串
            key: 32 字节 AES-256 密钥
            associated_data: 加密时使用的附加数据，须与加密时完全一致

        Returns:
            解密后的明文字符串

        Raises:
            DecryptionError: 密文为空、格式不符、长度不足、base64 非法或 GCM
                认证失败时抛出。注意 DecryptionError 双继承 ValueError——调用方
                若同时兜底 ValueError，须先捕获 DecryptionError。
        """
        if not encrypted_b64:
            raise DecryptionError('收到空密文')
        # 格式/长度校验置于 try 之外：DecryptionError 双继承 ValueError，放进 try
        # 会被下方 ``except (..., ValueError, ...)`` 改写为通用文案，丢失细分诊断。
        if not encrypted_b64.startswith(cls.TEXT_PREFIX):
            raise DecryptionError('不支持的密文格式')
        encoded = encrypted_b64[len(cls.TEXT_PREFIX):]
        try:
            raw = base64.b64decode(encoded, validate=True)
        except ValueError as exc:
            # binascii.Error（非法 base64 字符 / 长度）IS-A ValueError
            logger.warning("密文 base64 解码失败: %s", type(exc).__name__)
            raise DecryptionError('密文解码失败') from exc
        if len(raw) < cls.NONCE_SIZE + cls.TAG_SIZE:
            raise DecryptionError('密文长度无效')
        nonce = raw[:cls.NONCE_SIZE]
        ciphertext = raw[cls.NONCE_SIZE:]
        aesgcm = cls._get_cipher(key)
        aad = cls._aad_bytes(associated_data)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
            return plaintext.decode('utf-8')
        except (InvalidTag, ValueError, AttributeError, TypeError) as exc:
            logger.warning("解密失败: %s", type(exc).__name__)
            raise DecryptionError('解密失败，密钥或数据可能已损坏') from exc

    @classmethod
    def encrypt_bytes(
        cls,
        data: bytes,
        key: bytes | bytearray,
        associated_data: str | bytes,
    ) -> bytes:
        """加密字节数据，返回带 ``CB2`` 字节前缀的密文（与 encrypt 对称）。

        空数据也经 AES-GCM 加密，保证 AAD 始终参与认证。
        """
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
        key: bytes | bytearray,
        associated_data: str | bytes,
    ) -> bytes:
        """解密由 encrypt_bytes 产生的字节密文。

        Args:
            data: encrypt_bytes 返回的密文字节
            key: 32 字节 AES-256 密钥
            associated_data: 加密时使用的附加数据，须与加密时完全一致

        Returns:
            解密后的原始字节数据

        Raises:
            DecryptionError: 密文格式不符、长度不足或认证失败时抛出。双继承
                ValueError，旧 ``except ValueError`` 兜底仍能捕获。
        """
        if not data.startswith(cls.BYTES_PREFIX):
            raise DecryptionError('不支持的密文字节格式')
        payload = data[len(cls.BYTES_PREFIX):]
        if not payload:
            raise DecryptionError('收到空密文字节')
        if len(payload) < cls.NONCE_SIZE + cls.TAG_SIZE:
            raise DecryptionError('密文长度无效')
        nonce = payload[:cls.NONCE_SIZE]
        ciphertext = payload[cls.NONCE_SIZE:]
        aesgcm = cls._get_cipher(key)
        aad = cls._aad_bytes(associated_data)
        try:
            return aesgcm.decrypt(nonce, ciphertext, aad)
        except (InvalidTag, ValueError, AttributeError, TypeError) as exc:
            logger.warning("解密失败: %s", type(exc).__name__)
            raise DecryptionError('解密失败，密钥或数据可能已损坏') from exc
