"""加密引擎 — AES-256-GCM 加密/解密。

内存安全说明：``_cipher_cache`` 使用密钥的 SHA-256 摘要作为缓存键，
不再以原始密钥 bytes 作为 dict key，避免缓存字典持有原始密钥材料的额外
引用。缓存在 ``clear_cache`` 被显式调用前会一直驻留进程内存，
``VaultManager.lock`` 与 ``_re_encrypt_all`` 负责调用。
调用方必须在密钥失效时调用 ``clear_cache``，例如锁定或改密场景。

CPython 固有限制：``bytes`` 对象不可变，无法从 Python 层面原地清零。
``clear_cache`` 仅清除缓存字典的引用，原始 ``bytes`` 对象依赖 GC 回收。
这是 CPython 的根本限制，非代码缺陷——如需更强保障需使用 C 扩展或 mmap。
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

logger = logging.getLogger(__name__)


def _cache_key(key: bytes | bytearray) -> bytes:
    """返回密钥的 SHA-256 摘要用作缓存键，避免缓存持有原始密钥材料。"""
    return hashlib.sha256(key).digest()


_cache_lock = threading.RLock()
# AESGCM 实例缓存容量上限。正常使用仅 1 个活跃主密钥；改密瞬间旧+新两个密钥
# 并存，取 2 恰好容纳双密钥窗口，避免任一方反复 evict 重建（key schedule 开销），
# 同时最小化历史密钥的 AESGCM 副本（内部持有 C 层密钥拷贝）驻留进程内存，
# 收缩崩溃 dump 攻击面。上限过大（原 16）会扩大内存 dump 攻击面。
_MAX_CACHE_SIZE = 2
# AESGCM 实例缓存：按密钥摘要索引，通常仅含当前活跃密钥。模块级缓存会跨
# VaultManager 实例共享（如同一进程内的测试创建多个实例），经 SHA-256 摘要索引，
# 缓存键不持有也不泄漏明文密钥材料。
_cipher_cache: OrderedDict[bytes, AESGCM] = OrderedDict()


class EncryptionEngine:
    """使用 AES-256-GCM 进行数据加密和解密。"""

    NONCE_SIZE = 12  # GCM 推荐 nonce 长度
    TAG_SIZE = 16    # GCM 认证标签长度，128 位
    KEY_SIZE = 32    # AES-256 密钥长度
    FORMAT_ID = 'aes-256-gcm-aad'
    TEXT_PREFIX = 'cb2:'
    BYTES_PREFIX = b'CB2'

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
        """清除 AESGCM 实例缓存。

        密钥失效后调用，例如锁定或改密。清除引用后依赖 GC 回收，
        VaultManager.lock 已负责触发 gc.collect。
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
        key: bytes | bytearray,
        associated_data: str | bytes,
    ) -> str:
        """加密明文，返回带前缀的 base64 密文。

        Args:
            plaintext: 待加密的明文字符串
            key: 32 字节 AES-256 密钥
            associated_data: 参与认证的附加数据，解密时需原样提供

        Returns:
            形如 ``cb2:`` 前缀加 base64 的密文字符串。密文内部由随机 nonce、
            密文与 GCM 认证标签拼接后编码得到。
        """
        nonce = os.urandom(cls.NONCE_SIZE)
        aesgcm = cls._get_cipher(key)
        aad = cls._aad_bytes(associated_data)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), aad)
        # nonce + ciphertext，ciphertext 已包含 GCM 认证标签
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
            DecryptionError: 密文为空、格式不符或认证失败时抛出。DecryptionError
                双继承 ValueError，旧的 ``except ValueError`` 兜底仍能捕获。
        """
        if not encrypted_b64:
            raise DecryptionError('收到空密文')
        try:
            if not encrypted_b64.startswith(cls.TEXT_PREFIX):
                raise DecryptionError('不支持的密文格式')
            encoded = encrypted_b64[len(cls.TEXT_PREFIX):]
            raw = base64.b64decode(encoded, validate=True)
            if len(raw) < cls.NONCE_SIZE + cls.TAG_SIZE:
                raise DecryptionError('密文长度无效')
            nonce = raw[:cls.NONCE_SIZE]
            ciphertext = raw[cls.NONCE_SIZE:]
            aesgcm = cls._get_cipher(key)
            aad = cls._aad_bytes(associated_data)
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
        """加密字节数据，返回带 ``CB2`` 字节前缀的密文。

        与 encrypt 对称，区别在于处理 bytes 并以字节前缀返回；空数据直接
        经 AES-GCM 加密，保证附加数据始终参与认证。
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
            DecryptionError: 密文格式不符、长度不足或认证失败时抛出。DecryptionError
                双继承 ValueError，旧的 ``except ValueError`` 兜底仍能捕获。
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
