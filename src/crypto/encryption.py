"""加密引擎 - AES-256-GCM 加密/解密"""

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class EncryptionEngine:
    """使用 AES-256-GCM 进行数据加密和解密"""

    NONCE_SIZE = 12  # GCM 推荐 nonce 长度
    FORMAT_ID = 'aes-256-gcm-aad'
    TEXT_PREFIX = 'cb:'
    BYTES_PREFIX = b'CBX'

    @staticmethod
    def _aad_bytes(associated_data: str | bytes) -> bytes:
        return associated_data.encode('utf-8') if isinstance(associated_data, str) else associated_data

    @staticmethod
    def encrypt(
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
        if not plaintext:
            return ''
        nonce = os.urandom(EncryptionEngine.NONCE_SIZE)
        aesgcm = AESGCM(key)
        aad = EncryptionEngine._aad_bytes(associated_data)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), aad)
        # nonce + ciphertext (ciphertext 已包含 tag)
        encoded = base64.b64encode(nonce + ciphertext).decode('ascii')
        return EncryptionEngine.TEXT_PREFIX + encoded

    @staticmethod
    def decrypt(
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
            ValueError: 解密失败时抛出
        """
        if not encrypted_b64:
            return ''
        try:
            if not encrypted_b64.startswith(EncryptionEngine.TEXT_PREFIX):
                raise ValueError('不支持的密文格式')
            encoded = encrypted_b64[len(EncryptionEngine.TEXT_PREFIX):]
            raw = base64.b64decode(encoded, validate=True)
            if len(raw) < EncryptionEngine.NONCE_SIZE + 16:
                raise ValueError('密文长度无效')
            nonce = raw[:EncryptionEngine.NONCE_SIZE]
            ciphertext = raw[EncryptionEngine.NONCE_SIZE:]
            aesgcm = AESGCM(key)
            aad = EncryptionEngine._aad_bytes(associated_data)
            plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValueError(f"解密失败: {e}") from e

    @staticmethod
    def encrypt_bytes(
        data: bytes,
        key: bytes,
        associated_data: str | bytes,
    ) -> bytes:
        """加密字节数据"""
        nonce = os.urandom(EncryptionEngine.NONCE_SIZE)
        aesgcm = AESGCM(key)
        aad = EncryptionEngine._aad_bytes(associated_data)
        ciphertext = aesgcm.encrypt(nonce, data, aad)
        payload = nonce + ciphertext
        return EncryptionEngine.BYTES_PREFIX + payload

    @staticmethod
    def decrypt_bytes(
        data: bytes,
        key: bytes,
        associated_data: str | bytes,
    ) -> bytes:
        """解密字节数据"""
        if not data.startswith(EncryptionEngine.BYTES_PREFIX):
            raise ValueError('不支持的密文字节格式')
        payload = data[len(EncryptionEngine.BYTES_PREFIX):]
        if len(payload) < EncryptionEngine.NONCE_SIZE + 16:
            raise ValueError('密文长度无效')
        nonce = payload[:EncryptionEngine.NONCE_SIZE]
        ciphertext = payload[EncryptionEngine.NONCE_SIZE:]
        aesgcm = AESGCM(key)
        aad = EncryptionEngine._aad_bytes(associated_data)
        return aesgcm.decrypt(nonce, ciphertext, aad)
