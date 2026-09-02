"""entry_batch_writer 单元测试 — 导入批量写入的加密与落库编排。

覆盖 encrypt_new_entries / write_new_entries / prepare_overwrite_updates /
write_overwrite_updates 四个公开函数：加密密文构建、空批次静默、密码变更检测、
覆盖缺 id 失败收集、preserve_password_changed_at 透传、epoch 守卫与密码历史归档。
补足该核心安全路径的独立回归网（此前仅端到端 + mock 覆盖，与同轮 collector/rebuilder
不对称）。进度契约共享函数（phase_progress / should_report_progress，MAINT-099）
的语义在此直测——import_export 与 backup_restore 的消费语义由各自加权刻度测试
覆盖。
"""

import dataclasses

import pytest

from src.business.services.entry_batch_writer import (
    PROGRESS_REPORT_EVERY,
    BatchUpdateItem,
    encrypt_new_entries,
    phase_progress,
    prepare_overwrite_updates,
    should_report_progress,
    write_new_entries,
    write_overwrite_updates,
)
from src.exceptions import EntryError, VaultKeyEpochMismatchError
from src.models import CIPHERTEXT_PREFIX


class TestProgressContractHelpers:
    """进度契约共享函数（MAINT-099）：加权映射与节流谓词的单一事实源语义。"""

    def test_phase_progress_maps_fraction_linearly(self):
        """阶段内 (done/total) 线性映射到 [start, end] 的整数下取整。"""
        assert phase_progress(0, 4, 10, 20) == 10
        assert phase_progress(2, 4, 10, 20) == 15
        assert phase_progress(3, 4, 10, 20) == 17  # 10 + 10*3//4

    def test_phase_progress_full_at_terminal_and_empty(self):
        """done>=total 与 total<=0（空阶段）均取满 end（单调不减、不留悬挂）。"""
        assert phase_progress(4, 4, 10, 20) == 20
        assert phase_progress(5, 4, 10, 20) == 20  # 越界钳制到 end
        assert phase_progress(0, 0, 10, 20) == 20
        assert phase_progress(3, -1, 10, 20) == 20

    def test_phase_progress_clamps_below_start(self):
        """非单调输入（done<=0）钳制到 start，不越阶段下界。"""
        assert phase_progress(0, 4, 10, 20) == 10
        assert phase_progress(-2, 4, 10, 20) == 10

    def test_should_report_progress_throttles_and_reports_terminal(self):
        """每 PROGRESS_REPORT_EVERY 条一次、终值恒上报。"""
        assert should_report_progress(PROGRESS_REPORT_EVERY, 250) is True
        assert should_report_progress(PROGRESS_REPORT_EVERY + 1, 250) is False
        assert should_report_progress(250, 250) is True  # 终值（非整间隔也上报）
        assert should_report_progress(7, 7) is True  # 小批量终值同样上报


class TestEncryptNewEntries:
    """encrypt_new_entries：锁外加密新条目，返回 (enc_entries, preserve)。"""

    def test_encrypts_fields_to_ciphertext(self, entry_mgr, make_entry):
        entries = [
            make_entry(title="Alpha", password="Pass1!@#"),
            make_entry(title="Beta", password="Pass2!@#"),
        ]
        enc_entries, _ = encrypt_new_entries(entry_mgr, entries)
        assert len(enc_entries) == 2
        for enc in enc_entries:
            assert enc.crypto_id  # 无 crypto_id 时自动生成
            assert enc.title.startswith(CIPHERTEXT_PREFIX)
            assert enc.username.startswith(CIPHERTEXT_PREFIX)
            assert enc.password.startswith(CIPHERTEXT_PREFIX)

    def test_preserve_false_without_timestamps(self, entry_mgr, make_entry):
        # Entry 默认 created_at/updated_at 为空 → preserve False（新增导入不保留元数据）
        _, preserve = encrypt_new_entries(entry_mgr, [make_entry()])
        assert preserve is False

    def test_preserve_true_with_timestamps(self, entry_mgr, make_entry):
        entry = make_entry(created_at="2024-01-01T00:00:00")
        _, preserve = encrypt_new_entries(entry_mgr, [entry])
        assert preserve is True


class TestWriteNewEntries:
    """write_new_entries：事务内裸写入 + 空批次静默 no-op（通知由调用方统一发）。"""

    def test_writes_entries(self, entry_mgr, make_entry):
        enc, _ = encrypt_new_entries(entry_mgr, [make_entry(title="New", password="P1!@#")])
        write_new_entries(entry_mgr, enc, preserve=False)
        assert entry_mgr.db.get_entry_count() == 1

    def test_empty_batch_noop_without_notify(self, entry_mgr):
        # 空列表不写入、不通知、不抛错（PERF-022 移除 notify 参数后的唯一语义）
        write_new_entries(entry_mgr, [], preserve=False)
        assert entry_mgr.db.get_entry_count() == 0


class TestPrepareOverwriteUpdates:
    """prepare_overwrite_updates：锁外验证+加密覆盖项，失败逐条收集。"""

    def test_detects_password_change(self, entry_mgr, make_entry):
        entry_id = entry_mgr.add_entry(make_entry(title="A", password="OldPass1!"))
        raw = entry_mgr.db.get_entry(entry_id)
        assert raw is not None
        new_entry = dataclasses.replace(make_entry(title="A", password="NewPass2!"), id=entry_id)
        item = BatchUpdateItem(entry=new_entry, raw=raw, old_password="OldPass1!")
        prepared, failures = prepare_overwrite_updates(entry_mgr, [item])
        assert failures == []
        assert len(prepared) == 1
        assert prepared[0].password_changed is True

    def test_password_unchanged(self, entry_mgr, make_entry):
        entry_id = entry_mgr.add_entry(make_entry(title="A", password="Same1!@#"))
        raw = entry_mgr.db.get_entry(entry_id)
        new_entry = dataclasses.replace(make_entry(title="A", password="Same1!@#"), id=entry_id)
        item = BatchUpdateItem(entry=new_entry, raw=raw, old_password="Same1!@#")
        prepared, failures = prepare_overwrite_updates(entry_mgr, [item])
        assert failures == []
        assert prepared[0].password_changed is False

    def test_missing_id_collected_as_failure(self, entry_mgr, make_entry):
        entry_id = entry_mgr.add_entry(make_entry(title="A", password="P1!@#"))
        raw = entry_mgr.db.get_entry(entry_id)
        # entry.id 默认 None → EntryError 收集（不中止整批）
        new_entry = make_entry(title="A", password="P2!@#")
        item = BatchUpdateItem(entry=new_entry, raw=raw, old_password=None)
        prepared, failures = prepare_overwrite_updates(entry_mgr, [item])
        assert prepared == []
        assert len(failures) == 1
        assert isinstance(failures[0][1], EntryError)
        # 失败索引 0 基对齐 items（QL-062）：消费方以其直接索引同序覆盖计划列表
        assert failures[0][0] == 0

    def test_failure_indices_are_zero_based(self, entry_mgr, make_entry):
        """失败索引 0 基对齐 items 位置（QL-062）：首项与末项失败各归其位。

        旧行为为 1 基索引：末项失败时消费方 ``overwrite_plans[batch_idx]`` 越界
        （IndexError 中止整次导入），非末项失败时警告/日志指向下一条目。
        """
        ok_id = entry_mgr.add_entry(make_entry(title="A", password="P1!@#"))
        raw = entry_mgr.db.get_entry(ok_id)
        assert raw is not None
        ok_item = BatchUpdateItem(
            entry=dataclasses.replace(make_entry(title="A", password="P2!@#"), id=ok_id),
            raw=raw,
            old_password="P1!@#",
        )
        # 缺 id → EntryError：置于首项与末项，锁定两个边界位置的索引语义
        bad_item = BatchUpdateItem(entry=make_entry(title="bad"), raw=raw, old_password=None)
        prepared, failures = prepare_overwrite_updates(entry_mgr, [bad_item, ok_item, bad_item])
        assert [idx for idx, _exc in failures] == [0, 2]
        assert all(isinstance(exc, EntryError) for _idx, exc in failures)
        assert len(prepared) == 1

    def test_preserve_password_changed_at_passthrough(self, entry_mgr, make_entry):
        entry_id = entry_mgr.add_entry(make_entry(title="A", password="P1!@#"))
        raw = entry_mgr.db.get_entry(entry_id)
        new_entry = dataclasses.replace(
            make_entry(title="A", password="P2!@#", password_changed_at="2020-05-05T00:00:00"),
            id=entry_id,
        )
        item = BatchUpdateItem(entry=new_entry, raw=raw, old_password="P1!@#")
        prepared, _ = prepare_overwrite_updates(
            entry_mgr, [item], preserve_password_changed_at=True
        )
        assert prepared[0].password_changed_at == "2020-05-05T00:00:00"


class TestWriteOverwriteUpdates:
    """write_overwrite_updates：epoch 守卫 + 批量写入 + 密码历史分组。"""

    def test_empty_returns_zero(self, entry_mgr):
        assert write_overwrite_updates(entry_mgr, [], pre_epoch="any") == 0

    def test_epoch_mismatch_raises(self, entry_mgr, make_entry):
        entry_id = entry_mgr.add_entry(make_entry(title="A", password="P1!@#"))
        raw = entry_mgr.db.get_entry(entry_id)
        new_entry = dataclasses.replace(make_entry(title="A", password="P2!@#"), id=entry_id)
        item = BatchUpdateItem(entry=new_entry, raw=raw, old_password="P1!@#")
        prepared, _ = prepare_overwrite_updates(entry_mgr, [item])
        with pytest.raises(VaultKeyEpochMismatchError):
            write_overwrite_updates(entry_mgr, prepared, pre_epoch="stale-epoch")

    def test_writes_update_and_archives_history(self, entry_mgr, make_entry):
        entry_id = entry_mgr.add_entry(make_entry(title="A", password="OldPass1!"))
        raw = entry_mgr.db.get_entry(entry_id)
        new_entry = dataclasses.replace(make_entry(title="A", password="NewPass2!"), id=entry_id)
        item = BatchUpdateItem(entry=new_entry, raw=raw, old_password="OldPass1!")
        prepared, _ = prepare_overwrite_updates(entry_mgr, [item])
        pre_epoch = entry_mgr.key_epoch
        count = write_overwrite_updates(entry_mgr, prepared, pre_epoch=pre_epoch)
        assert count == 1
        # 密码已更新为明文 NewPass2!（解密读回）
        read = entry_mgr.get_entry(entry_id)
        assert read is not None
        assert read.password == "NewPass2!"
        # 密码变更归档历史（db 层计数，含旧密文）
        assert entry_mgr.db.get_password_history_count(entry_id) >= 1


class TestOverwriteProgressReporting:
    """prepare/write_overwrite_updates 的进度上报（PERF-069）。

    纯覆盖导入此前全程冻结在 15%——两函数增可选 progress 后按已处理条目数上报
    ``(done, total)``，每 ``PROGRESS_REPORT_EVERY=100`` 条节流、终值恒上报。
    """

    ROWS = 250  # > PROGRESS_REPORT_EVERY：3 次节流上报（100/200/250）

    def _seed_items(self, entry_mgr, make_entry):
        items = []
        for i in range(self.ROWS):
            entry_id = entry_mgr.add_entry(make_entry(title=f"A{i:04d}", password=f"Old{i:04d}!x"))
            raw = entry_mgr.db.get_entry(entry_id)
            assert raw is not None
            new_entry = dataclasses.replace(
                make_entry(title=f"A{i:04d}", password=f"New{i:04d}!y"), id=entry_id
            )
            items.append(BatchUpdateItem(entry=new_entry, raw=raw, old_password=f"Old{i:04d}!x"))
        return items

    def test_prepare_reports_throttled_with_final(self, entry_mgr, make_entry):
        """prepare：250 条 → 3 次上报，终值 (250, 250)。"""
        items = self._seed_items(entry_mgr, make_entry)
        events: list[tuple[int, int]] = []
        prepared, failures = prepare_overwrite_updates(
            entry_mgr, items, progress=lambda done, total: events.append((done, total))
        )
        assert failures == []
        assert len(prepared) == self.ROWS
        assert events == [(100, 250), (200, 250), (250, 250)]

    def test_prepare_progress_counts_failed_items(self, entry_mgr, make_entry):
        """失败项也计入进度（done 覆盖全部已处理条目，终值恒达 total）。"""
        good = self._seed_items(entry_mgr, make_entry)
        # 追加一个缺 id 的失败项（EntryError 收集为 failure）
        raw = good[0].raw
        bad = BatchUpdateItem(entry=make_entry(title="bad"), raw=raw, old_password=None)
        events: list[tuple[int, int]] = []
        prepared, failures = prepare_overwrite_updates(
            entry_mgr, good + [bad], progress=lambda done, total: events.append((done, total))
        )
        assert len(failures) == 1
        assert events[-1] == (len(good) + 1, len(good) + 1)

    def test_write_reports_chunked_progress(self, entry_mgr, make_entry):
        """write：>500 条分块上报中间值（600 → 2 块，500/600 中间值）。"""
        rows = 600
        items = []
        for i in range(rows):
            entry_id = entry_mgr.add_entry(make_entry(title=f"B{i:04d}", password=f"Old{i:04d}!x"))
            raw = entry_mgr.db.get_entry(entry_id)
            assert raw is not None
            new_entry = dataclasses.replace(
                make_entry(title=f"B{i:04d}", password=f"New{i:04d}!y"), id=entry_id
            )
            items.append(BatchUpdateItem(entry=new_entry, raw=raw, old_password=f"Old{i:04d}!x"))
        prepared, _ = prepare_overwrite_updates(entry_mgr, items)
        events: list[tuple[int, int]] = []
        count = write_overwrite_updates(
            entry_mgr,
            prepared,
            pre_epoch=entry_mgr.key_epoch,
            progress=lambda done, total: events.append((done, total)),
        )
        assert count == rows
        assert (500, rows) in events  # 分块中间值
        assert events[-1] == (rows, rows)

    def test_write_without_progress_single_batch(self, entry_mgr, make_entry, monkeypatch):
        """未提供 progress 时保持单次批量路径（不分块，既有调用方零改动）。"""
        items = self._seed_items(entry_mgr, make_entry)[:150]
        prepared, _ = prepare_overwrite_updates(entry_mgr, items)
        calls: list[int] = []
        real_batch = type(entry_mgr.db).update_overwrite_batch

        def _counting_batch(self_db, entries):
            calls.append(len(entries))
            return real_batch(self_db, entries)

        monkeypatch.setattr(
            type(entry_mgr.db),
            "update_overwrite_batch",
            _counting_batch,
        )
        count = write_overwrite_updates(entry_mgr, prepared, pre_epoch=entry_mgr.key_epoch)
        assert count == 150
        assert calls == [150]  # 单次批量，未按 500 分块
