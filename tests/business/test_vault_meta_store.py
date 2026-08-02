"""``VaultMetaStore`` 元数据持久化与 snapshot_key 加密测试。

覆盖 ``src/business/services/vault_meta_store.py``：
- snapshot_key 加解密往返。
- 解密后长度校验（防损坏/降级为弱密钥）。
- ``update`` 在 snapshot_key=None 时拒绝写。
- ``write`` 持久化全部字段并在最后写入 ``vault_meta_mac`` 完整性签名。
"""

import base64
import os
from unittest.mock import MagicMock

import pytest

from src.business.services import vault_meta_store
from src.business.services.vault_meta_store import VaultMetaStore
from src.crypto.encryption import EncryptionEngine
from src.exceptions import VaultIntegrityError

_KEY = os.urandom(32)


class TestSnapshotKeyCrypto:
    """snapshot_key 加解密往返与解密后的长度/密钥校验。"""

    def test_snapshot_key_round_trip(self):
        """encrypt → decrypt 恢复原始 32 字节 snapshot_key。"""
        snap = os.urandom(vault_meta_store.SNAPSHOT_KEY_LEN)
        encrypted = VaultMetaStore.encrypt_snapshot_key(snap, _KEY)

        decrypted = VaultMetaStore.decrypt_snapshot_key(encrypted, _KEY)

        assert decrypted == snap

    def test_decrypt_rejects_wrong_length_payload(self):
        """内层载荷解 base64 后非 32 字节 → VaultIntegrityError。

        模拟损坏或降级：构造 16 字节内层载荷，用相同的 snapshot-key AAD 加密，
        decrypt_snapshot_key 解密成功但长度校验（SNAPSHOT_KEY_LEN=32）失败。
        """
        inner = base64.b64encode(b"\x00" * 16).decode("ascii")
        encrypted = EncryptionEngine.encrypt(inner, _KEY, vault_meta_store._SNAPSHOT_KEY_AAD)

        with pytest.raises(VaultIntegrityError, match="损坏"):
            VaultMetaStore.decrypt_snapshot_key(encrypted, _KEY)

    def test_decrypt_rejects_wrong_key(self):
        """错误主密钥解密 snapshot_key → DecryptionError（GCM 认证失败）。"""
        snap = os.urandom(vault_meta_store.SNAPSHOT_KEY_LEN)
        encrypted = VaultMetaStore.encrypt_snapshot_key(snap, _KEY)
        other_key = os.urandom(32)

        from src.exceptions import DecryptionError

        with pytest.raises(DecryptionError):
            VaultMetaStore.decrypt_snapshot_key(encrypted, other_key)


class TestUpdate:
    """update 的 snapshot_key=None 拒绝写与非空时委托 write 写入。"""

    def test_update_raises_when_snapshot_key_none(self):
        """update 收到 snapshot_key=None 时抛 VaultIntegrityError（防 None 落库）。

        改密/恢复须轮换 snapshot_key 为新值；None 表示调用方未加载，拒绝写入避免
        把空值持久化到 vault_meta 造成后续恢复无法解密快照。
        """
        db = MagicMock()
        with pytest.raises(VaultIntegrityError, match="snapshot_key 未加载"):
            VaultMetaStore().update(
                db,
                new_key=_KEY,
                new_salt=b"salt",
                new_verify_token="tok",
                new_epoch="e1",
                snapshot_key=None,
            )

    def test_update_delegates_to_write_with_provided_snapshot_key(self):
        """update 在 snapshot_key 非空时委托 write 写入全部字段。"""
        store = VaultStoreSpy()
        snap = os.urandom(vault_meta_store.SNAPSHOT_KEY_LEN)
        db = MagicMock()

        store.update(
            db,
            new_key=_KEY,
            new_salt=b"salt",
            new_verify_token="tok",
            new_epoch="e1",
            snapshot_key=snap,
        )

        assert store.write_called
        assert store.write_kwargs["snapshot_key"] == snap
        assert store.write_kwargs["key_epoch"] == "e1"


class VaultStoreSpy(VaultMetaStore):
    """捕获 write 调用参数的测试替身。"""

    def __init__(self) -> None:
        super().__init__()
        self.write_called = False
        self.write_kwargs: dict = {}

    def write(self, db, **kwargs):  # type: ignore[override]
        self.write_called = True
        self.write_kwargs = kwargs


class TestWrite:
    """write 持久化全部字段并在最后写入 vault_meta_mac 完整性签名。"""

    def test_write_persists_all_fields_and_mac(self):
        """write 写入 8 个值字段 + vault_meta_mac（最后写入，覆盖全部已签字段）。"""
        db = MagicMock()
        # get_meta_batch 回读刚写入的值用于签名
        db.get_meta_batch.return_value = {}
        snap = os.urandom(vault_meta_store.SNAPSHOT_KEY_LEN)

        VaultMetaStore().write(
            db,
            salt=b"salt-bytes",
            verify_token="verify-tok",
            snapshot_key=snap,
            key=_KEY,
            key_epoch="epoch-1",
        )

        set_meta_calls = db.set_meta.call_args_list
        written_keys = [c.args[0] for c in set_meta_calls]
        expected_keys = {
            "master_salt",
            "master_verify",
            "master_kdf",
            "master_kdf_time_cost",
            "master_kdf_memory_cost",
            "master_kdf_parallelism",
            "ciphertext_format",
            "snapshot_key_enc",
            "key_epoch",
            "vault_meta_mac",
        }
        assert expected_keys.issubset(set(written_keys))
        # vault_meta_mac 是最后一个 set_meta（所有被签字段写完后再回读签名）
        assert written_keys[-1] == "vault_meta_mac"
        db.get_meta_batch.assert_called_once()
