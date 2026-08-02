"""备份恢复边界场景测试。

覆盖损坏文件、截断数据、超大备份、错误密码等异常输入下
BackupRestoreManager 的拒绝行为，以及快照密钥备份、已删除条目
保留等正确性场景。
"""

import os
import struct
from pathlib import Path

import pytest

from src.business.managers.backup_restore import BackupRestoreManager
from src.business.managers.restore_point_manager import RestorePointManager
from src.business.services.backup_header_codec import (
    BACKUP_MAGIC,
    BACKUP_SALT_SIZE,
    inspect_backup,
)
from src.crypto.master_key import DEFAULT_KDF_PARAMS, MasterKeyManager
from src.exceptions import BackupError
from src.models import Entry
from tests.helpers import make_entry_manager, make_vault


class TestBackupCorruption:
    """备份文件损坏与恢复边界场景测试集合。"""

    @pytest.fixture(autouse=True)
    def setup_vault(self, tmp_path, vault_config):
        self._tmp_dir = str(tmp_path)
        self._vault = make_vault(vault_config)
        self._vault.initialize("test_password_12345")
        self._entry_mgr = make_entry_manager(self._vault)
        self._backup_mgr = BackupRestoreManager(self._vault, self._entry_mgr)
        self._entry_mgr.add_entry(
            Entry(
                title="测试条目",
                username="user1",
                password="pass123",
                url="https://example.com",
                notes="备注",
                entry_type="login",
            )
        )
        yield
        self._vault.close()

    def _create_valid_backup(self, filepath: str, password: str = "BackupTest!2026"):
        """创建一个有效的密码保护备份。"""
        success, error = self._backup_mgr.create_backup(filepath, password)
        assert success, f"创建备份失败: {error}"
        return filepath

    def test_rejects_truncated_backup(self):
        """截断的备份文件应被拒绝。"""
        path = os.path.join(self._tmp_dir, "truncated.cbox")
        self._create_valid_backup(path)
        full_size = os.path.getsize(path)
        with open(path, "r+b") as f:
            # 截断到原文件一半长度，破坏 GCM 认证标签
            f.truncate(full_size // 2)
        success, error = self._backup_mgr.restore_backup(path, "BackupTest!2026")
        assert not success
        assert "损坏" in error

    def test_rejects_oversized_backup_payload(self, monkeypatch):
        """备份数据载荷超过上限时应拒绝并返回友好的过大提示。"""
        import src.business.managers.backup_restore as br

        monkeypatch.setattr(br, "MAX_BACKUP_PAYLOAD_SIZE", 10)
        path = os.path.join(self._tmp_dir, "oversized.cbox")
        success, error = self._backup_mgr.create_backup(path, "BackupTest!2026")
        assert not success
        # PayloadTooLargeError 归一为固定友好文案（防 str 泄漏内部细节，与 DecryptionError
        # 一致）；诊断详情由 create_backup 记录到日志（exc_info）。断言走大小限制文案分支。
        assert "大小" in error or "限制" in error

    def test_rejects_corrupted_magic_bytes(self):
        """损坏的 magic bytes 应被拒绝。"""
        path = os.path.join(self._tmp_dir, "bad_magic.cbox")
        with open(path, "wb") as f:
            f.write(b"CORRUPTED_HEADER\x00")
            f.write(b"\x00" * 100)
        success, error = self._backup_mgr.restore_backup(path)
        assert not success

    def test_rejects_empty_file(self):
        """空文件应被拒绝。"""
        path = os.path.join(self._tmp_dir, "empty.cbox")
        Path(path).write_bytes(b"")
        success, error = self._backup_mgr.restore_backup(path)
        assert not success

    def test_rejects_random_bytes(self):
        """随机字节数据应被拒绝。"""
        path = os.path.join(self._tmp_dir, "random.cbox")
        Path(path).write_bytes(os.urandom(256))
        success, error = self._backup_mgr.restore_backup(path)
        assert not success

    def test_rejects_wrong_backup_password(self):
        """错误的备份密码应被拒绝。"""
        path = os.path.join(self._tmp_dir, "wrong_pwd.cbox")
        self._create_valid_backup(path, "correct_password")
        success, error = self._backup_mgr.restore_backup(path, "WrongPassword!99")
        assert not success

    def test_rejects_password_required_backup_without_password(self):
        """需要密码的备份但未提供密码应被拒绝。"""
        path = os.path.join(self._tmp_dir, "no_pwd.cbox")
        self._create_valid_backup(path, "SomePassword!99")
        success, error = self._backup_mgr.restore_backup(path, None)
        assert not success

    def test_inspect_backup_returns_correct_info(self):
        """inspect_backup 应返回正确的备份信息。"""
        path = os.path.join(self._tmp_dir, "inspect.cbox")
        self._create_valid_backup(path, "TestPassword!99")
        info = inspect_backup(path)
        assert info["password_required"]
        assert not info["snapshot_required"]
        assert info["kdf"]["memory_cost"] == DEFAULT_KDF_PARAMS.memory_cost

    def test_inspect_snapshot_backup(self):
        """检查快照备份应标记为 snapshot_required。"""
        path = os.path.join(self._tmp_dir, "snapshot.cbox")
        success, error = self._backup_mgr.create_backup(path, use_snapshot_key=True)
        assert success, f"快照备份失败: {error}"
        info = inspect_backup(path)
        assert not info["password_required"]
        assert info["snapshot_required"]

    def test_restore_and_verify_data_integrity(self):
        """恢复后数据应与原始数据一致。"""
        path = os.path.join(self._tmp_dir, "verify.cbox")
        self._create_valid_backup(path, "Verify_Pwd!2026")

        original = self._entry_mgr.get_entries()[0]

        success, error = self._backup_mgr.restore_backup(path, "Verify_Pwd!2026")
        assert success, f"恢复失败: {error}"

        restored = self._entry_mgr.get_entries()[0]
        assert restored.title == original.title
        assert restored.username == original.username
        assert restored.password == original.password
        assert restored.url == original.url
        assert restored.notes == original.notes

    def test_inspect_rejects_unknown_flags(self):
        """包含未知标志的备份应被拒绝。"""
        path = os.path.join(self._tmp_dir, "bad_flags.cbox")
        with open(path, "wb") as f:
            f.write(BACKUP_MAGIC)
            # flags=0xFF 非法；time/memory/parallelism 取合法值以越过结构校验
            f.write(struct.pack("<BIII", 0xFF, 3, 65536, 4))
            f.write(b"\x00" * BACKUP_SALT_SIZE)
        with pytest.raises(BackupError):
            inspect_backup(path)

    def test_backup_uses_persisted_kdf_params(self, monkeypatch):
        """恢复必须使用文件头参数，而不是进程当前默认参数。"""
        path = os.path.join(self._tmp_dir, "persisted_kdf.cbox")
        self._create_valid_backup(path, "persisted_password")

        seen = []
        original = MasterKeyManager.derive_backup_key

        def _capture(password, salt, params=DEFAULT_KDF_PARAMS):
            seen.append(params)
            return original(password, salt, params)

        monkeypatch.setattr(MasterKeyManager, "derive_backup_key", _capture)
        success, error = self._backup_mgr.restore_backup(path, "persisted_password")

        assert success, error
        assert seen[-1] == DEFAULT_KDF_PARAMS

    def test_backup_with_snapshot_key(self):
        """使用快照密钥的备份应可恢复。"""
        path = os.path.join(self._tmp_dir, "snapshot_restore.cbox")
        success, error = self._backup_mgr.create_backup(path, use_snapshot_key=True)
        assert success, f"快照备份失败: {error}"

        success, error = self._backup_mgr.restore_backup(path)
        assert success, f"快照恢复失败: {error}"

    def test_backup_preserves_deleted_entries(self):
        """备份应保留已删除的条目。"""
        entry_id = self._entry_mgr.add_entry(
            Entry(
                title="将被删除",
                username="u",
                password="p",
                entry_type="login",
            )
        )
        self._entry_mgr.delete_entry(entry_id)

        path = os.path.join(self._tmp_dir, "with_deleted.cbox")
        self._create_valid_backup(path, "DeletedEntry!26")

        success, error = self._backup_mgr.restore_backup(path, "DeletedEntry!26")
        assert success, f"恢复失败: {error}"

        all_entries = self._entry_mgr.get_entries(include_deleted=True)
        deleted = [e for e in all_entries if e.is_deleted]
        assert len(deleted) >= 1

    def test_rejects_weak_backup_password(self):
        """业务层应拒绝极弱备份密码，作为 UI 之外的兜底防御。"""
        path = os.path.join(self._tmp_dir, "weak.cbox")
        success, error = self._backup_mgr.create_backup(path, "pwd")
        assert not success
        assert "备份密码" in error
        assert not os.path.exists(path)

    def test_rejects_downgraded_kdf_params(self):
        """备份头 KDF 参数被篡改为更弱值时应拒绝恢复（防降级加速离线破解）。"""
        path = os.path.join(self._tmp_dir, "downgraded.cbox")
        self._create_valid_backup(path, "BackupTest!2026")
        # 篡改头部 KDF 参数为更弱的合法值（time=2 / memory=16MB / parallelism=1）
        with open(path, "r+b") as f:
            f.seek(len(BACKUP_MAGIC))
            f.write(struct.pack("<BIII", 1, 2, 16 * 1024, 1))
        success, error = self._backup_mgr.restore_backup(path, "BackupTest!2026")
        assert not success
        # BackupError 归一为固定友好文案（KDF 篡改的具体诊断记入日志，用户层归一）。
        # 核心守护是 not success（防降级拒绝）；文案断言验证走了 BackupError 友好分支。
        assert "损坏" in error or "格式" in error

    def test_restore_point_cleaned_on_creation_exception(self, monkeypatch):
        """恢复点创建抛异常时应触发清理，避免含明文的恢复点残留。"""
        path = os.path.join(self._tmp_dir, "rp.cbox")
        self._create_valid_backup(path, "BackupTest!2026")

        cleaned: list[str] = []

        def _spy(path_arg):
            cleaned.append(str(path_arg))

        monkeypatch.setattr(
            RestorePointManager,
            "_safe_delete_restore_point",
            staticmethod(_spy),
        )

        def _raise(*_args, **_kwargs):
            raise OSError("simulated write failure")

        monkeypatch.setattr(self._backup_mgr, "_create_backup_locked", _raise)

        success, _error = self._backup_mgr.restore_backup(path, "BackupTest!2026")
        assert not success
        assert cleaned, "恢复点创建异常时应调用 _safe_delete_restore_point 清理"


class TestBackupSizeLimits:
    """备份大小限制测试。"""

    def test_inspect_rejects_oversized_file(self, tmp_path, monkeypatch):
        """过大的备份文件应被拒绝。"""
        # 缩容上限到 1KB，避免每次写真实 64MB+1（CI 6 job ≈ 384MB I/O），与
        # test_rejects_oversized_backup_payload 的 monkeypatch 缩容模式一致。
        import src.business.services.backup_header_codec as codec

        monkeypatch.setattr(codec, "MAX_BACKUP_FILE_SIZE", 1024)
        path = tmp_path / "huge.cbox"
        # 写正确文件头 + body 超过缩容上限（inspect_backup 读模块级常量判定）
        with open(path, "wb") as f:
            f.write(BACKUP_MAGIC)
            f.write(b"\x00" * (1024 + 1))
        with pytest.raises(ValueError):
            inspect_backup(path)


class TestAADCentralization:
    """验证 AAD 集中化，确认 crypto_utils.entry_aad 是单一事实源。"""

    def test_entry_aad_format(self):
        from src.business.services.crypto_utils import entry_aad

        aad = entry_aad("abc123", "password")
        assert aad == "entry:abc123:password"

    def test_entry_aad_different_fields(self):
        from src.business.services.crypto_utils import entry_aad

        aad1 = entry_aad("id1", "username")
        aad2 = entry_aad("id1", "password")
        assert aad1 != aad2

    def test_entry_aad_different_crypto_ids(self):
        from src.business.services.crypto_utils import entry_aad

        aad1 = entry_aad("id1", "password")
        aad2 = entry_aad("id2", "password")
        assert aad1 != aad2
