"""关键安全路径的事务回滚与一致性回归测试。

补充近期重构后的安全不变量：
- snapshot_key 随主密钥 epoch 轮换，改密时旧 snapshot 备份失效并清理
- 改密重加密的回滚仍保证密钥与数据匹配
- epoch 写守卫在导入期间并发改密时仍能拦截

覆盖三类场景：
1. 改密中途重加密失败 → 事务回滚 → 原主密码仍可用、原条目可正常解密
2. 备份恢复中途失败 → 数据库未被清空、且未残留新的恢复点快照
3. 导入事务内 epoch 被并发改密轮换 → 导入被守卫中止，数据保持一致
"""

import contextlib
import json
import os
from pathlib import Path
from unittest.mock import PropertyMock, patch

import pytest

from src.business.managers.import_export import ImportExportManager
from src.business.services.backup.header_codec import (
    BACKUP_HEADER_SIZE,
    BACKUP_SALT_SIZE,
)
from src.exceptions import VaultKeyEpochMismatchError
from src.models import CustomField, Entry
from tests.helpers import make_backup_manager, make_entry_manager, make_test_config, make_vault


class TestChangePasswordRollbackConsistency:
    """改密重加密失败时的事务回滚与密钥/数据一致性。"""

    @pytest.fixture(autouse=True)
    def setup_vault(self, tmp_path):
        self._tmp_dir = str(tmp_path)
        config = make_test_config(self._tmp_dir)
        self._vault = make_vault(config)
        self._master_pwd = "OriginalMaster!2026"
        self._vault.initialize(self._master_pwd)
        self._entry_mgr = make_entry_manager(self._vault)
        # 写入一条含全部敏感字段的条目，验证回滚后密钥/数据匹配
        self._entry_id = self._entry_mgr.add_entry(
            Entry(
                title="改密回滚测试",
                username="rollback_user@example.com",
                password="RollbackP@ss!2026",
                notes="回滚保护备注",
                totp_secret="JBSWY3DPEHPK3PXP",
                custom_fields=[
                    CustomField(name="API Key", value="sk-secret-123", field_type="password"),
                ],
                entry_type="login",
            )
        )
        # 记录原始明文，供回滚后逐字段比对
        self._original = self._entry_mgr.get_entry(self._entry_id)
        yield
        self._vault.close()

    def test_change_password_rollback_preserves_vault(self):
        """重加密中途抛异常时，改密失败且回滚到原始状态。

        安全属性：改密流程包裹在事务中；当 ReEncryptionService 的重加密条目
        或重加密历史任一步骤抛出异常时，_re_encrypt_all 必须回滚所有数据库
        变更并清除内存中的新密钥，保证两点：其一，原主密码仍可重新解锁
        保险库；其二，原条目的全部敏感字段含密码历史、TOTP、自定义字段，
        仍可用原密钥正确解密。即密钥与数据始终匹配，不会出现新密钥已落盘
        但数据仍是旧密钥加密、或反之的损坏窗口。
        """
        original = self._original
        assert original is not None

        # 记录恢复点前的 epoch，验证回滚后数据库 epoch 未被推进
        epoch_before = self._vault.db.get_meta("key_epoch")

        # 在 re_encrypt_entries 第一步即抛异常，模拟重加密中途失败。
        # 使用 RuntimeError 而非 CipherBoxError，确保被 _change_master_password_locked
        # 的 except Exception 捕获并返回失败元组，而非向上传播。
        def _failing_re_encrypt_entries(self_rotator, old_key, new_key, *, cancel_event=None):
            raise RuntimeError("模拟重加密中途失败")

        with patch(
            "src.business.services.re_encryption.ReEncryptionService.re_encrypt_entries",
            new=_failing_re_encrypt_entries,
        ):
            ok, _error = self._vault.change_master_password(self._master_pwd, "NewMaster!2026")

        assert not ok

        # 关键一致性验证：原主密码仍可解锁，密钥与数据匹配且未损坏
        self._vault.lock()
        unlock_ok, _ = self._vault.unlock(self._master_pwd)
        assert unlock_ok, "改密回滚后原主密码应仍能解锁保险库"

        # epoch 不应被推进，事务回滚生效
        epoch_after = self._vault.db.get_meta("key_epoch")
        assert epoch_after == epoch_before, "回滚后数据库 epoch 不应变化"

        # 原条目全部字段仍可用原密钥正确解密
        entry_mgr = make_entry_manager(self._vault)
        entry = entry_mgr.get_entry(self._entry_id)
        assert entry is not None
        assert entry.title == original.title
        assert entry.username == original.username
        assert entry.password == original.password
        assert entry.notes == original.notes
        assert entry.totp_secret == original.totp_secret
        assert isinstance(entry.custom_fields, list)
        assert len(entry.custom_fields) == 1
        assert entry.custom_fields[0].value == "sk-secret-123"

    def test_change_password_rollback_on_history_failure(self):
        """重加密历史步骤失败时同样回滚并保持一致。

        安全属性：re_encrypt_entries 成功但 re_encrypt_history 抛异常时，
        事务必须整体回滚，条目重加密、历史重加密、元数据更新一并撤销，
        不出现"条目已用新密钥落盘但历史仍为旧密钥"的部分推进状态。
        """
        original = self._original
        assert original is not None
        epoch_before = self._vault.db.get_meta("key_epoch")

        # 条目重加密放行，历史重加密抛异常
        def _failing_re_encrypt_history(self_rotator, old_key, new_key, *, cancel_event=None):
            raise RuntimeError("模拟历史重加密失败")

        with patch(
            "src.business.services.re_encryption.ReEncryptionService.re_encrypt_history",
            new=_failing_re_encrypt_history,
        ):
            ok, _error = self._vault.change_master_password(
                self._master_pwd, "AnotherNewMaster!2026"
            )

        assert not ok

        # 原密码仍可用，数据完好
        self._vault.lock()
        assert self._vault.unlock(self._master_pwd)[0]
        epoch_after = self._vault.db.get_meta("key_epoch")
        assert epoch_after == epoch_before

        entry_mgr = make_entry_manager(self._vault)
        entry = entry_mgr.get_entry(self._entry_id)
        assert entry is not None
        assert entry.password == original.password

    def test_change_password_cancel_event_rolls_back(self):
        """改密重加密期间通过 cancel_event 取消时，抛 VaultError 并事务回滚。

        安全属性：区别于 RuntimeError 触发的失败，cancel_event 由 request_cancel
        或 close 设置，ReEncryptionService 检测后抛 VaultError。该路径同样必须
        回滚事务、清除新密钥，原主密码与数据保持匹配，不出现损坏窗口。
        """
        from src.business.services.re_encryption import ReEncryptionService
        from src.exceptions import VaultError

        original = self._original
        assert original is not None
        epoch_before = self._vault.db.get_meta("key_epoch")
        real_re_encrypt = ReEncryptionService.re_encrypt_entries

        def _cancel_then_re_encrypt(rotator, old_key, new_key, *, cancel_event=None):
            # 模拟改密已开始、重加密循环运行时收到取消请求：设置取消事件后
            # 调用真实实现，首批循环即检测到 cancel_event 已设置而抛 VaultError。
            if cancel_event is not None:
                cancel_event.set()
            return real_re_encrypt(rotator, old_key, new_key, cancel_event=cancel_event)

        with patch(
            "src.business.services.re_encryption.ReEncryptionService.re_encrypt_entries",
            new=_cancel_then_re_encrypt,
        ):
            with pytest.raises(VaultError):
                self._vault.change_master_password(self._master_pwd, "CancelTest!2026")

        # 原密码仍可用，epoch 未被推进，事务回滚生效
        self._vault.lock()
        assert self._vault.unlock(self._master_pwd)[0]
        assert self._vault.db.get_meta("key_epoch") == epoch_before

        entry_mgr = make_entry_manager(self._vault)
        entry = entry_mgr.get_entry(self._entry_id)
        assert entry is not None
        assert entry.password == original.password

    def test_change_password_reports_purge_failure(self):
        """改密成功但旧快照清理失败时返回 True 并附带 warning 提示手动清理。"""
        with patch(
            "src.business.managers.vault_lifecycle.purge_snapshot_backups",
            return_value=[Path(self._tmp_dir) / "occupied.cbox"],
        ):
            ok, msg = self._vault.change_master_password(self._master_pwd, "PurgeFailure!2026")
        assert ok  # 改密本身成功
        assert "未能删除" in msg  # 附带 purge 失败 warning


class TestBackupRestoreRollbackAndRestorePointCleanup:
    """备份恢复失败时数据库回滚与恢复点清理。"""

    @pytest.fixture(autouse=True)
    def setup_vault(self, tmp_path):
        self._tmp_dir = str(tmp_path)
        config = make_test_config(self._tmp_dir)
        self._vault = make_vault(config)
        self._master_pwd = "test_password_123"
        self._vault.initialize(self._master_pwd)
        self._entry_mgr = make_entry_manager(self._vault)
        self._backup_mgr = make_backup_manager(self._vault, self._entry_mgr)
        # 写入两条条目作为恢复失败时“不应被清空”的存量数据
        self._entry_mgr.add_entry(
            Entry(
                title="存量条目A",
                username="keep_user_a",
                password="KeepP@ssA!2026",
                entry_type="login",
            )
        )
        self._entry_mgr.add_entry(
            Entry(
                title="存量条目B",
                username="keep_user_b",
                password="KeepP@ssB!2026",
                entry_type="login",
            )
        )
        self._backups_dir = self._vault.data_dir / "backups"
        yield
        self._vault.close()

    def _count_restore_points(self) -> int:
        """统计备份目录下 pre_restore_*.cbox 文件数量。"""
        if not self._backups_dir.is_dir():
            return 0
        return len(list(self._backups_dir.glob("pre_restore_*.cbox")))

    def _make_corrupted_snapshot_backup(self) -> str:
        """创建 header 合法但密文被篡改的 snapshot 备份。

        先用快照密钥创建一个合法备份，再翻转密文区中部若干字节，
        破坏 AES-GCM 认证标签，使其解密时抛出 ValueError 而非结构错误。
        """
        valid_path = str(Path(self._tmp_dir) / "valid_snapshot.cbox")
        success, error = self._backup_mgr.create_backup(valid_path, use_snapshot_key=True)
        assert success, f"创建合法快照备份失败: {error}"

        corrupted_path = str(Path(self._tmp_dir) / "corrupted_snapshot.cbox")
        with open(valid_path, "rb") as f:
            raw = f.read()

        # v2 固定头后为 ciphertext。
        header_len = BACKUP_HEADER_SIZE
        assert len(raw) > header_len + 16, "备份密文区过短，无法构造篡改"

        body = bytearray(raw[header_len:])
        # 翻转密文中部的若干字节，破坏 GCM 认证标签与密文
        mid = len(body) // 2
        for i in range(mid, min(mid + 8, len(body))):
            body[i] ^= 0xFF

        with open(corrupted_path, "wb") as f:
            f.write(raw[:header_len])
            f.write(bytes(body))
        return corrupted_path

    def test_restore_corrupted_backup_rolls_back_and_leaves_no_restore_point(self):
        """恢复密文损坏的备份应失败，数据库回滚，且不残留恢复点。

        安全属性有三点。其一，当备份密文被篡改导致 GCM 认证失败时，
        restore_backup 必须返回失败，不应用任何备份数据。其二，失败必须
        发生在创建恢复点之前，因为解密在 _create_restore_point 之前完成，
        因此本次失败不应残留新的 pre_restore_*.cbox 恢复点。其三，当前
        数据库的存量条目必须完好，未被 clear_vault_data 清空，即使恢复
        流程开始执行，事务回滚也保障了数据完整性。
        """
        # 失败前不应存在任何恢复点
        restore_points_before = self._count_restore_points()

        corrupted_path = self._make_corrupted_snapshot_backup()
        success, error = self._backup_mgr.restore_backup(corrupted_path)

        # 恢复应失败，且错误信息指向损坏/密码错误
        assert not success, "损坏密文的备份不应恢复成功"
        assert "损坏" in error or "密码错误" in error

        # 数据库存量条目未被清空，回滚生效或未到达数据清理步骤
        entries = self._entry_mgr.get_entries()
        assert len(entries) == 2, "恢复失败后存量条目不应丢失"
        titles = {e.title for e in entries}
        assert titles == {"存量条目A", "存量条目B"}

        # 关键安全属性：失败不残留新的恢复点
        restore_points_after = self._count_restore_points()
        assert restore_points_after == restore_points_before, (
            "恢复失败不应残留新的 pre_restore 恢复点"
        )

    def test_restore_structurally_invalid_backup_leaves_no_restore_point(self):
        """恢复解密通过但格式错误的无效备份应失败且不残留恢复点。

        安全属性：解密通过但备份 JSON 结构校验失败、由 _validate_restore_data
        抛出异常时，失败同样发生在 _create_restore_point 之前，不应残留恢复点，
        且数据库存量数据完好。
        """
        restore_points_before = self._count_restore_points()

        # 构造一个用快照密钥加密的、解密通过但 format 标识错误的备份。
        # 加密一段合法 JSON 但 format 字段不匹配 BACKUP_FORMAT。
        invalid_data = json.dumps(
            {
                "format": "NotCipherBoxBackup",
                "version": 1,
                "entries": [],
                "categories": [],
                "password_history": [],
            },
            ensure_ascii=False,
        ).encode("utf-8")
        snapshot_key = self._vault.snapshot_key
        from src.business.services.backup.header_codec import (
            BACKUP_AAD,
            BackupFlag,
            write_backup_header,
        )
        from src.crypto.encryption import EncryptionEngine

        encrypted = EncryptionEngine.encrypt_bytes(invalid_data, snapshot_key, BACKUP_AAD)

        path = str(Path(self._tmp_dir) / "bad_format.cbox")
        with open(path, "wb") as f:
            from src.crypto.master_key import DEFAULT_KDF_PARAMS

            write_backup_header(
                f,
                BackupFlag.SNAPSHOT,
                os.urandom(BACKUP_SALT_SIZE),
                DEFAULT_KDF_PARAMS,
            )
            f.write(encrypted)

        success, error = self._backup_mgr.restore_backup(path)

        assert not success, "格式无效的备份不应恢复成功"

        # 存量数据完好
        entries = self._entry_mgr.get_entries()
        assert len(entries) == 2

        # 不残留恢复点
        restore_points_after = self._count_restore_points()
        assert restore_points_after == restore_points_before, "结构无效的恢复不应残留新的恢复点"

    def test_restore_succeeds_when_post_commit_checkpoint_fails(self):
        """事务提交后 secure_checkpoint 失败应非致命：数据已提交完整，恢复仍成功。

        回归守护 _restore_data 的事务外 WAL 截断：secure_checkpoint 因 WAL 锁/IO
        失败时不应使整个恢复失败并清零 new_snapshot_key——否则库已提交
        snapshot_key_enc + key_epoch 但当前会话无对应密钥，状态不一致。截断失败
        仅影响泄漏面（WAL 残留 clear_vault_data 删除的旧明文密文），与改密路径
        （vault_manager._re_encrypt_all）secure_checkpoint 的非致命处理对称。
        """
        from unittest.mock import patch

        # 用快照密钥创建合法备份（restore 无需备份密码）
        backup_path = str(Path(self._tmp_dir) / "snapshot.cbox")
        success, _ = self._backup_mgr.create_backup(backup_path, use_snapshot_key=True)
        assert success, "创建快照备份失败"

        # mock 事务提交后的 secure_checkpoint 抛异常（模拟 WAL 锁/IO 失败）
        with patch.object(
            self._vault.db,
            "secure_checkpoint",
            side_effect=OSError("WAL 锁定"),
        ):
            success, error = self._backup_mgr.restore_backup(backup_path)

        # 恢复应成功：secure_checkpoint 失败非致命，数据已事务提交完整，
        # snapshot_key 正确 apply（若被误清零，restore 会失败返回 False）
        assert success, f"secure_checkpoint 失败不应使恢复失败: {error}"


class TestImportEpochGuard:
    """导入事务内 epoch 被轮换时，导入被守卫中止。"""

    @pytest.fixture(autouse=True)
    def setup_vault(self, tmp_path):
        self._tmp_dir = str(tmp_path)
        config = make_test_config(self._tmp_dir)
        self._vault = make_vault(config)
        self._master_pwd = "test_password_123"
        self._vault.initialize(self._master_pwd)
        self._entry_mgr = make_entry_manager(self._vault)
        self._import_export = ImportExportManager(self._entry_mgr)

        # 写入一份合法的 CipherBox JSON 导出文件供导入
        entry = Entry(
            title="导入条目",
            username="import_user@example.com",
            password="ImportP@ss!2026",
            url="https://import.example.com",
        )
        self._entry_mgr.add_entry(entry)
        entries = self._entry_mgr.get_entries()
        self._json_path = str(Path(self._tmp_dir) / "export.json")
        self._import_export.export_to_json(self._json_path, entries, include_password=True)
        self._entry_mgr.get_entries()
        yield
        self._vault.close()

    def test_import_aborted_when_epoch_changes_mid_transaction(self):
        """导入写入前 key_epoch 被并发改密轮换时，导入被守卫中止。

        安全属性（MAINT-004）：``_import_entries`` 把加密移出 db_lock，在加密前快照
        ``pre_epoch``，写入时 ``epoch_guarded_transaction(pre_epoch=...)`` 复查；若
        「加密后→写入前」主密码被改导致 epoch 轮换，复查检测到不匹配，必须抛
        VaultKeyEpochMismatchError 并回滚事务，避免旧密钥密文落到新 epoch 库。

        经包装 ``epoch_guarded_transaction``：捕获 ``_import_entries`` 传入的 ``pre_epoch``
        （验证快照契约），并在守卫复查侧把 ``key_epoch`` 轮换为伪造值（模拟并发改密）。
        不依赖 ``_import_entries`` 内部读 ``key_epoch`` 的次数——``pre_epoch`` 作为显式
        参数传入、复查侧 ``key_epoch`` 经 patch 轮换，二者来源解耦，实现新增 key_epoch
        读取（日志/校验）不会令测试错位漏报。
        """
        real_epoch = self._vault.key_epoch
        assert real_epoch is not None

        entry_count_before = len(self._entry_mgr.get_entries())

        original_egt = self._vault.epoch_guarded_transaction
        captured: dict[str, object] = {}

        @contextlib.contextmanager
        def _shifting_egt(*args: object, **kwargs: object):
            # 捕获 _import_entries 传入的 pre_epoch（MAINT-004 快照契约的显式证据）
            captured["pre_epoch"] = kwargs.get("pre_epoch")
            # 复查侧轮换 key_epoch：模拟「加密后→写入前」并发改密，pre_epoch 仍是
            # 调用前快照的真实值，二者不一致触发守卫。
            with patch.object(
                type(self._vault),
                "key_epoch",
                new=PropertyMock(return_value=real_epoch + "_concurrent_rotation"),
            ):
                with original_egt(*args, **kwargs) as cm:
                    yield cm

        with patch.object(self._vault, "epoch_guarded_transaction", _shifting_egt):
            with pytest.raises(VaultKeyEpochMismatchError):
                self._import_export.import_file(self._json_path, "json")

        # _import_entries 正确把 pre_epoch 传入守卫（快照契约生效）
        assert captured["pre_epoch"] == real_epoch

        # 导入被中止，数据保持一致：条目数不变
        entry_count_after = len(self._entry_mgr.get_entries())
        assert entry_count_after == entry_count_before, "epoch 守卫中止导入后，数据库条目数不应变化"

    def test_import_succeeds_when_epoch_unchanged(self):
        """对照测试：epoch 未变化时导入正常完成。

        作为上一个测试的对照，确认 epoch 守卫不会误伤正常导入路径，
        _import_entries 的二次校验在 epoch 一致时放行。
        """
        entry_count_before = len(self._entry_mgr.get_entries())

        count = self._import_export.import_file(self._json_path, "json")

        # 正常导入应成功导入 1 条
        assert count == 1
        entry_count_after = len(self._entry_mgr.get_entries())
        assert entry_count_after == entry_count_before + 1


def test_restore_rotates_snapshot_key(tmp_path):
    """恢复成功后轮换 snapshot_key，使旧 snapshot 加密的快照失效以收缩泄漏面。

    与改密路径一致：恢复整体替换数据后，旧 snapshot_key 加密的快照含恢复前
    明文，轮换并清理使其失效。验证 snapshot_key 实际变化且恢复点被清理。
    """
    source_dir = str(tmp_path / "source")
    target_dir = str(tmp_path / "target")
    Path(source_dir).mkdir()
    Path(target_dir).mkdir()

    source = make_vault(make_test_config(source_dir))
    source.initialize("SourceMaster!2026")
    make_entry_manager(source).add_entry(Entry(title="Incoming", password="IncomingSecret!2026"))
    portable = str(Path(source_dir) / "portable.cbox")
    assert make_backup_manager(source).create_backup(portable, "PortableBackup!2026")[0]

    target = make_vault(make_test_config(target_dir))
    target.initialize("TargetMaster!2026")
    old_snapshot_key = bytes(target.snapshot_key)
    backup_mgr = make_backup_manager(target)
    assert backup_mgr.restore_backup(portable, "PortableBackup!2026")[0]

    # 恢复后 snapshot_key 应轮换为全新值
    assert bytes(target.snapshot_key) != old_snapshot_key
    # 旧恢复点被清理（snapshot_key 轮换使其失效并 purge）
    backup_dir = Path(target_dir) / "backups"
    assert list(backup_dir.glob("pre_restore_*.cbox")) == []

    source.close()
    target.close()
