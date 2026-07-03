"""vault_meta 表的写入与完整性签名（从 VaultManager 下沉的元数据持久化职责）。

initialize 与改密共用此写入序列，避免两处逐字重复。``snapshot_key`` 经主密钥加密后
写入 ``snapshot_key_enc``；安全相关字段经主密钥派生的域密钥 HMAC 签名为
``vault_meta_mac``，供 unlock 强制校验。``write`` 须在调用方事务内调用，保证 mac
与被签字段原子一致。
"""

from __future__ import annotations

import base64

from ...crypto.encryption import EncryptionEngine
from ...crypto.master_key import DEFAULT_KDF_PARAMS, KDF_NAME, KdfParams
from ...database.types import VaultDataConnection
from ...exceptions import VaultIntegrityError
from .metadata_signer import VAULT_META_SIGNED_KEYS, MetadataSigner

# snapshot_key 加密的 AAD 域标签，与主密钥绑定防跨域重用。
_SNAPSHOT_KEY_AAD = 'vault:snapshot-key'


class VaultMetaStore:
    """保险库元数据（vault_meta 表）的持久化与完整性签名。

    纯数据库写入 + HMAC 计算，不持有密钥与状态：``key`` 由调用方（生命周期编排）
    传入。``write`` 须在调用方事务内调用，使 mac 与被签字段原子提交。
    """

    @staticmethod
    def encrypt_snapshot_key(
        snapshot_key: bytes | bytearray, key: bytes | bytearray,
    ) -> str:
        """加密 snapshot_key 以便写入 ``snapshot_key_enc``。

        供 ``write`` 内部与恢复流程（事务内单独写 ``snapshot_key_enc``）复用，使加密
        与 ``set_meta`` 解耦——恢复流程能将 ``snapshot_key_enc`` 与 ``key_epoch`` 在
        同一事务内写入，消除事务外崩溃导致 epoch 已提交而 snapshot_key_enc 未写入的
        不一致窗口。
        """
        return EncryptionEngine.encrypt(
            base64.b64encode(snapshot_key).decode('ascii'), key, _SNAPSHOT_KEY_AAD,
        )

    @staticmethod
    def decrypt_snapshot_key(encrypted: str, key: bytes | bytearray) -> bytes:
        """解密 ``snapshot_key_enc``，校验长度后返回原始 snapshot_key。

        与 :meth:`encrypt_snapshot_key` 对称；32 字节长度校验防损坏或降级为弱密钥。
        """
        encoded = EncryptionEngine.decrypt(encrypted, key, _SNAPSHOT_KEY_AAD)
        snapshot_key = base64.b64decode(encoded)
        if len(snapshot_key) != 32:
            raise VaultIntegrityError('自动快照密钥损坏')
        return snapshot_key

    def write(
        self,
        db: VaultDataConnection,
        *,
        salt: bytes,
        verify_token: str,
        snapshot_key: bytes | bytearray,
        key: bytes | bytearray,
        key_epoch: str,
        params: KdfParams = DEFAULT_KDF_PARAMS,
    ) -> None:
        """将保险库元数据写入 vault_meta，并在同事务写入完整性签名。

        包含盐、验证令牌、KDF 参数、加密后的 snapshot_key、epoch，以及覆盖安全字段
        的 ``vault_meta_mac``。``params`` 为实际派生所用的 Argon2id 参数，写入数据库
        而非硬编码常量，为未来调整参数保留正确性。
        """
        db.set_meta('master_salt', base64.b64encode(salt).decode('ascii'))
        db.set_meta('master_verify', verify_token)
        db.set_meta('master_kdf', KDF_NAME)
        db.set_meta('master_kdf_time_cost', str(params.time_cost))
        db.set_meta('master_kdf_memory_cost', str(params.memory_cost))
        db.set_meta('master_kdf_parallelism', str(params.parallelism))
        db.set_meta('ciphertext_format', EncryptionEngine.FORMAT_ID)
        db.set_meta('snapshot_key_enc', self.encrypt_snapshot_key(snapshot_key, key))
        db.set_meta('key_epoch', key_epoch)
        # vault_meta 完整性签名：签名键集从 VAULT_META_SIGNED_KEYS 单一源派生——
        # 写完所有字段后回读刚写入的值再签，与恢复路径（backup_restore 经
        # get_meta_batch(list(VAULT_META_SIGNED_KEYS)) 取值）对称，消除「手工重建
        # 键集漏键致写入即签错、下次 unlock 比对失败」的漂移（ARCH-3）。回读须在
        # 调用方事务内（write 契约要求调用方持事务），同事务 set_meta 后立即
        # get_meta_batch 可见刚写值。
        meta_for_mac = db.get_meta_batch(list(VAULT_META_SIGNED_KEYS))
        db.set_meta(
            'vault_meta_mac', MetadataSigner.compute_vault_meta_mac(meta_for_mac, key),
        )

    def update(
        self,
        db: VaultDataConnection,
        new_key: bytes | bytearray,
        new_salt: bytes,
        new_verify_token: str,
        new_epoch: str,
        *,
        snapshot_key: bytes | bytearray | None,
        params: KdfParams = DEFAULT_KDF_PARAMS,
    ) -> None:
        """改密时更新 vault_meta：snapshot_key 由调用方轮换为新值，不再复用旧值。"""
        if snapshot_key is None:
            raise VaultIntegrityError('snapshot_key 未加载，无法更新保险库元数据')
        self.write(
            db,
            salt=new_salt, verify_token=new_verify_token,
            snapshot_key=snapshot_key, key=new_key, key_epoch=new_epoch,
            params=params,
        )
