"""加密引擎 - AES-256-GCM 加密/解密"""

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class EncryptionEngine:
    """使用 AES-256-GCM 进行数据加密和解密"""

    NONCE_SIZE = 12  # GCM 推荐 nonce 长度

    @staticmethod
    def encrypt(plaintext: str, key: bytes) -> str:
        """加密明文，返回 base64 编码的密文

        Args:
            plaintext: 待加密的明文字符串
            key: 32 字节 AES-256 密钥

        Returns:
            base64 编码的 (nonce + ciphertext + tag) 字节串
        """
        if not plaintext:
            return ''
        nonce = os.urandom(EncryptionEngine.NONCE_SIZE)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        # nonce + ciphertext (ciphertext 已包含 tag)
        return base64.b64encode(nonce + ciphertext).decode('ascii')

    @staticmethod
    def decrypt(encrypted_b64: str, key: bytes) -> str:
        """解密 base64 编码的密文

        Args:
            encrypted_b64: base64 编码的 (nonce + ciphertext + tag)
            key: 32 字节 AES-256 密钥

        Returns:
            解密后的明文字符串

        Raises:
            ValueError: 解密失败时抛出
        """
        if not encrypted_b64:
            return ''
        try:
            raw = base64.b64decode(encrypted_b64)
            nonce = raw[:EncryptionEngine.NONCE_SIZE]
            ciphertext = raw[EncryptionEngine.NONCE_SIZE:]
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValueError(f"解密失败: {e}") from e

    @staticmethod
    def encrypt_bytes(data: bytes, key: bytes) -> bytes:
        """加密字节数据"""
        nonce = os.urandom(EncryptionEngine.NONCE_SIZE)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext

    @staticmethod
    def decrypt_bytes(data: bytes, key: bytes) -> bytes:
        """解密字节数据"""
        nonce = data[:EncryptionEngine.NONCE_SIZE]
        ciphertext = data[EncryptionEngine.NONCE_SIZE:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)
