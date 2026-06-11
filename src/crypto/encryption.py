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


_cache_lock = threading.RLock()
# AESGCM 实例缓存：按密钥摘要索引，通常仅含当前活跃密钥。
_MAX_CACHE_SIZE = 16
_cipher_cache: dict[bytes, AESGCM] = {}


class EncryptionEngine:
    """使用 AES-256-GCM 进行数据加密和解密"""

    NONCE_SIZE = 12  # GCM 推荐 nonce 长度
    TAG_SIZE = 16    # GCM 认证标签长度，128 位
    FORMAT_ID = 'aes-256-gcm-aad'
    TEXT_PREFIX = 'cb:'
    BYTES_PREFIX = b'CBX'
    # 空值哨兵：使用 UUID 前缀降低碰撞概率，加密空输入时替换为哨兵走正常流程。
    _EMPTY_SENTINEL = '__CBX_EMPTY_7f3a2b1c-4d5e-6f8a-9b0c-1d2e3f4a5b6c__'
    _EMPTY_BYTES_SENTINEL = b'__CBX_BE_7f3a2b1c-4d5e-6f8a-9b0c-1d2e3f4a5b6c__'

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
        # 空字符串替换为哨兵值走正常加密流程，确保 AAD 始终参与认证。
        if not plaintext:
            plaintext = cls._EMPTY_SENTINEL
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
        key: bytes,
        associated_data: str | bytes,
    ) -> str:
        """解密 base64 编码的密文

        Args:
            encrypted_b64: base64 编码的 (nonce + ciphertext + tag)
            key: 32 字节 AES-256 密钥

        Returns:
            解密后的明文字符串

        Raises:
            ValueError: 解密失败或密文为空时抛出
        """
        if not encrypted_b64:
            raise ValueError('收到空密文')
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
            if result == cls._EMPTY_SENTINEL:
                return ''
            return result
        except (InvalidTag, ValueError, AttributeError, TypeError) as exc:
            logger.warning("解密失败: %s", type(exc).__name__)
            raise ValueError('解密失败，密钥或数据可能已损坏') from exc

    @classmethod
    def encrypt_bytes(
        cls,
        data: bytes,
        key: bytes,
        associated_data: str | bytes,
    ) -> bytes:
        """加密字节数据"""
        if not data:
            # 与字符串路径对称：空数据替换为哨兵值走正常加密流程
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
    ) -> bytes:
        """解密字节数据

        Raises:
            ValueError: 解密失败或密文无效时抛出
        """
        if not data.startswith(cls.BYTES_PREFIX):
            raise ValueError('不支持的密文字节格式')
        payload = data[len(cls.BYTES_PREFIX):]
        if not payload:
            raise ValueError('收到空密文字节')
        if len(payload) < cls.NONCE_SIZE + cls.TAG_SIZE:
            raise ValueError('密文长度无效')
        nonce = payload[:cls.NONCE_SIZE]
        ciphertext = payload[cls.NONCE_SIZE:]
        aesgcm = cls._get_cipher(key)
        aad = cls._aad_bytes(associated_data)
        try:
            result = aesgcm.decrypt(nonce, ciphertext, aad)
        except (InvalidTag, ValueError, AttributeError, TypeError) as exc:
            logger.warning("解密失败: %s", type(exc).__name__)
            raise ValueError('解密失败，密钥或数据可能已损坏') from exc
        if result == cls._EMPTY_BYTES_SENTINEL:
            return b''
        return result
