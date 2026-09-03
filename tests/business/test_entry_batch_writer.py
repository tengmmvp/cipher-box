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
    ProgressSegment,
    encrypt_new_entries,
    phase_progress,
    prepare_overwrite_updates,
    segment_progress,
    should_report_progress,
    validate_progress_segments,
    write_chunks,
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


class TestSegmentTablePrimitives:
    """段表共享件（MAINT-112）：段内映射 segment_progress 与启动期校验 validate_progress_segments。

    自 backup_restore（MAINT-107 首创）下沉公开，供恢复/导入/导出三组加权刻度段表
    共用；两组段表的具名结构与刻度锚定由各自消费方测试守护（TestImportProgressSegmentTable /
    TestExportProgressSegmentTable / TestRestoreProgressSegmentTable）。
    """

    def test_segment_progress_maps_into_segment_range(self):
        """segment_progress 把段内 (done,total) 线性映射到 [base, base+span]（整数下取整）。"""
        seg = ProgressSegment(45, 17)
        assert segment_progress(seg, 0, 10) == 45
        assert segment_progress(seg, 5, 10) == 53  # 45 + 17*5//10
        assert segment_progress(seg, 10, 10) == 62

    def test_segment_progress_full_at_terminal_and_empty(self):
        """终值/空阶段取段终点、零进度钳制段起点（语义同 phase_progress）。"""
        seg = ProgressSegment(70, 30)
        assert segment_progress(seg, 10, 10) == 100
        assert segment_progress(seg, 0, 0) == 100  # 空阶段取满（零条目导出不留悬挂）
        assert segment_progress(seg, 0, 10) == 70

    def test_validate_progress_segments_accepts_seamless(self):
        """无缝段表（首段承接 start、逐段衔接、尾段止于 end）通过校验不抛。"""
        # 正常返回 None（记录断言）：与下方 drift 用例的 RuntimeError 形成对照
        assert (
            validate_progress_segments((ProgressSegment(0, 5), ProgressSegment(5, 95)), 0, 100)
            is None
        )

    def test_validate_progress_segments_rejects_drift(self):
        """首段不承接 start / 缝隙 / 零跨度 / 尾段未达终值分别被 RuntimeError 拒绝。"""
        # 首段起点与 start 不符（缝隙形态）
        with pytest.raises(RuntimeError, match="缝隙"):
            validate_progress_segments((ProgressSegment(3, 5),), 0, 8)
        # 上一段终点 != 下一段 base（缝隙/重叠）
        with pytest.raises(RuntimeError, match="缝隙"):
            validate_progress_segments((ProgressSegment(0, 5), ProgressSegment(6, 10)), 0, 16)
        # 零跨度段不上报中间值，拒绝
        with pytest.raises(RuntimeError, match="正"):
            validate_progress_segments((ProgressSegment(0, 0),), 0, 0)
        # 尾段终点未精确到达 end（终值跳变）
        with pytest.raises(RuntimeError, match="终值"):
            validate_progress_segments((ProgressSegment(0, 5), ProgressSegment(5, 10)), 0, 100)


class TestWriteChunks:
    """write_chunks 共享分块原语（MAINT-106）：三处分块写入循环的单一事实源语义。

    write_new_entries / write_overwrite_updates / rebuilder.restore_entries 的
    分块循环收敛于此，分块行为等价性（块边界、逐块 (done,total) 上报、无进度
    单批路径、各块结果按序返回）在此直测。
    """

    def test_without_progress_single_call(self):
        """未提供 on_progress：整批单次调用（既有调用方的原路径，不分块）。"""
        seen: list[list[int]] = []

        def _write(chunk: list[int]) -> int:
            seen.append(chunk)
            return len(chunk)

        assert write_chunks([1, 2, 3], _write) == [3]
        assert seen == [[1, 2, 3]]

    def test_chunked_calls_and_progress_reports(self, monkeypatch):
        """提供 on_progress：按 WRITE_PROGRESS_CHUNK 分块调用并逐块上报终值。"""
        import src.business.services.entry_batch_writer as ebw_module

        monkeypatch.setattr(ebw_module, "WRITE_PROGRESS_CHUNK", 2)
        seen: list[list[int]] = []
        reports: list[tuple[int, int]] = []

        def _write(chunk: list[int]) -> int:
            seen.append(chunk)
            return len(chunk)

        results = write_chunks(
            [1, 2, 3, 4, 5], _write, on_progress=lambda d, t: reports.append((d, t))
        )

        assert seen == [[1, 2], [3, 4], [5]]  # 尾块为剩余行数
        assert reports == [(2, 5), (4, 5), (5, 5)]  # 终值恒达 total
        assert results == [2, 2, 1]  # 各块结果按序返回，合并策略留在调用方

    def test_empty_rows_with_progress_zero_calls(self):
        """空批次 + on_progress：零调用零上报（调用方空集语义不变）。"""
        seen: list[list[int]] = []
        reports: list[tuple[int, int]] = []

        def _write(chunk: list[int]) -> int:
            seen.append(chunk)
            return len(chunk)

        assert write_chunks([], _write, on_progress=reports.append) == []
        assert seen == []
        assert reports == []


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


class TestOverwriteTotpCacheInvalidation:
    """批量覆盖路径的 TOTP 缓存失效（SEC-063：前置 evict + 提交后统一 seam）。

    复现审查发现的唯一真实可达竞态：prepare（worker 线程锁外）evict → 主线程
    TOTP 定时器在「evict → 写库」窗口内重解密 DB 旧 totp_secret 并回写缓存
    （resolve 回写守卫的 version 采样晚于 evict，检测不到该失效）→ worker 写库
    落新 secret 后无人再清 → 旧 secret 持续生成错误 2FA 验证码。写库后的失效由
    ``epoch_guarded_transaction`` 提交回调的统一 seam 承担（原写库后逐条 evict
    循环已删，PERF-093）。序列在此单线程内确定性重放（时序即竞态交错），断言
    事务提交后旧 secret 不在缓存、新 secret 生效。
    """

    OLD_SECRET = "JBSWY3DPEHPK3PXP"  # 10 字节 base32，满足 validate_secret 下限
    NEW_SECRET = "KRSXG5CTMVRXEZLU"

    def _seed_totp_entry(self, entry_mgr, make_entry) -> int:
        entry_id = entry_mgr.add_entry(
            make_entry(title="A", password="P1!@#", totp_secret=self.OLD_SECRET)
        )
        # 预热旧 secret（模拟 TOTP 定时器已缓存命中）
        assert entry_mgr.totp.generate_cached(entry_id) is not None
        return entry_id

    def test_write_overwrite_clears_racy_old_totp_secret(self, entry_mgr, make_entry):
        """「evict → 主线程重解密回写 → 写库提交」序列后，旧 secret 不在缓存、新值生效。"""
        entry_id = self._seed_totp_entry(entry_mgr, make_entry)
        raw = entry_mgr.db.get_entry(entry_id)
        assert raw is not None
        new_entry = dataclasses.replace(
            make_entry(title="A", password="P2!@#", totp_secret=self.NEW_SECRET),
            id=entry_id,
        )
        item = BatchUpdateItem(entry=new_entry, raw=raw, old_password="P1!@#")

        # ---- worker：prepare（前置 evict 在其内发生）----
        prepared, failures = prepare_overwrite_updates(entry_mgr, [item])
        assert failures == []
        assert len(prepared) == 1

        # ---- 主线程：窗口内重解密 DB 旧 secret 并回写（竞态交错的重放）----
        # DB 尚未写入 → resolve 解出旧 secret；其回写守卫的 version 采样晚于
        # prepare 的 evict → 守卫通过 → 旧 secret 入缓存（修复前即此形态）。
        resolved = entry_mgr.cache.resolve_totp_secret(entry_id, use_cache=True)
        assert resolved == self.OLD_SECRET
        assert entry_mgr.cache._totp_secret_cache.get(entry_id) == self.OLD_SECRET

        # ---- worker：写库（生产路径：epoch 守卫事务内，提交后统一 seam 清空）----
        with entry_mgr.epoch_guarded_transaction(operation="导入", pre_epoch=entry_mgr.key_epoch):
            count = write_overwrite_updates(entry_mgr, prepared, pre_epoch=entry_mgr.key_epoch)
        assert count == 1

        # seam 生效：窗口内回写的旧 secret 已被清空，缓存不再持有本条目
        assert entry_id not in entry_mgr.cache._totp_secret_cache
        # DB 已是新 secret（写库本身正确）
        assert entry_mgr.db.get_entry(entry_id) is not None

        # 下次定时器周期重解密 → 新 secret 生效（缓存持有新值、生成的码基于新值）
        assert entry_mgr.totp.generate_cached(entry_id) is not None
        assert entry_mgr.cache._totp_secret_cache.get(entry_id) == self.NEW_SECRET

    def test_prepared_without_totp_change_still_invalidates_post_commit(
        self, entry_mgr, make_entry
    ):
        """覆盖条目即便 totp 未变也统一失效（幂等）：提交后缓存为空、重解密回填。"""
        entry_id = self._seed_totp_entry(entry_mgr, make_entry)
        raw = entry_mgr.db.get_entry(entry_id)
        assert raw is not None
        # 覆盖时 totp_secret 保持旧值（同值覆盖）
        new_entry = dataclasses.replace(
            make_entry(title="A", password="P2!@#", totp_secret=self.OLD_SECRET),
            id=entry_id,
        )
        item = BatchUpdateItem(entry=new_entry, raw=raw, old_password="P1!@#")
        prepared, _ = prepare_overwrite_updates(entry_mgr, [item])
        # 窗口内重解密回写（同值）
        assert entry_mgr.cache.resolve_totp_secret(entry_id, use_cache=True) is not None

        with entry_mgr.epoch_guarded_transaction(operation="导入", pre_epoch=entry_mgr.key_epoch):
            write_overwrite_updates(entry_mgr, prepared, pre_epoch=entry_mgr.key_epoch)

        # seam 不区分 totp 是否变化（幂等失效，只损失一次重解密）
        assert entry_id not in entry_mgr.cache._totp_secret_cache
        assert entry_mgr.cache.resolve_totp_secret(entry_id, use_cache=True) == (self.OLD_SECRET)


class TestStalePreloadedSecretRejected:
    """SEC-063 b 层真实通道：解密时点 TOTP 域版本快照透传，旧 preloaded secret
    不入缓存。

    复刻审查确认的场景：导入覆盖 worker（evict → 写库 → 提交）后异步刷新恢复
    选中，详情面板持**解密于写库前**的旧 totp_secret 预热——修复前 get_state 的
    自采样取当前（已推进）版本，store 侧比对「自己采的 vs 微秒后的当前」恒等，
    守卫无效果，旧 secret 入缓存生成错误 2FA 码；修复后 data_version 从
    ``get_entry_with_epoch`` 读锁内同刻带出，「解密 → 预热」窗口内的失效使旧
    secret 被拒收。
    """

    OLD_SECRET = "JBSWY3DPEHPK3PXP"
    NEW_SECRET = "KRSXG5CTMVRXEZLU"

    def test_stale_preloaded_rejected_after_overwrite_commit(self, entry_mgr, make_entry):
        """「解密（旧 secret + 版本快照）→ 覆盖提交 → 预热」交错：旧 secret 不入缓存。"""
        entry_id = entry_mgr.add_entry(
            make_entry(title="选中条目", password="P1!@#", totp_secret=self.OLD_SECRET)
        )

        # ---- GUI 线程：异步刷新恢复选中，get_entry_with_epoch 带出旧 secret 与
        # 解密时点的版本快照（此后任何 TOTP 失效都会使其失配）----
        read = entry_mgr.get_entry_with_epoch(entry_id)
        assert read.entry is not None and read.entry.totp_secret == self.OLD_SECRET

        # ---- worker：导入覆盖（prepare evict → 写库 → 提交，版本经 evict 与
        # seam 两路推进）----
        raw = entry_mgr.db.get_entry(entry_id)
        assert raw is not None
        new_entry = dataclasses.replace(
            make_entry(title="选中条目", password="P2!@#", totp_secret=self.NEW_SECRET),
            id=entry_id,
        )
        prepared, _ = prepare_overwrite_updates(
            entry_mgr, [BatchUpdateItem(entry=new_entry, raw=raw, old_password="P1!@#")]
        )
        with entry_mgr.epoch_guarded_transaction(operation="导入", pre_epoch=entry_mgr.key_epoch):
            write_overwrite_updates(entry_mgr, prepared, pre_epoch=entry_mgr.key_epoch)

        # ---- GUI 线程：面板以旧 preloaded secret 预热（携带解密时点快照）——
        # TOTPWidget.start → get_state 的等价链 ----
        state = entry_mgr.totp.get_state(
            entry_id,
            preloaded_secret=read.entry.totp_secret,
            data_epoch=read.data_epoch,
            data_version=read.data_version,
        )
        assert state is not None  # 本次展示仍用 preloaded 值（不阻断 UI）
        # 旧 secret 不得入缓存（版本快照失配被拒收；自采样形态在此交错下会放行）
        assert entry_id not in entry_mgr.cache._totp_secret_cache

        # 下次定时器周期重解密 → 新 secret 生效
        assert entry_mgr.totp.generate_cached(entry_id) is not None
        assert entry_mgr.cache._totp_secret_cache.get(entry_id) == self.NEW_SECRET
