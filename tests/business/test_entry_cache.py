"""EntryCacheManager 多级明文缓存的行为测试。

覆盖缓存命中、失效矩阵（单条/全清）、TOTP secret 缓存清理、invalidate_all、
LRU 驱逐等关键行为。
"""

import pytest

from src.business.managers import entry_cache as entry_cache_module
from src.database.types import EntryQuery
from src.exceptions import DecryptionError
from src.models import Entry


@pytest.fixture
def cache(entry_mgr):
    """EntryManager 持有的 EntryCacheManager（公开只读 property，MAINT-095）。"""
    return entry_mgr.cache


class TestSearchMetadataCache:
    """cached_search_metadata 的填充/命中与单条、全清失效矩阵。"""

    def test_decrypts_and_caches_summary(self, entry_mgr, cache):
        entry_mgr.add_entry(Entry(title="GitHub", username="alice", password="p"))
        raw = entry_mgr.db.get_entries(EntryQuery())[0]
        title, username, url, tags = cache.cached_search_metadata(raw)
        assert title == "GitHub"
        assert username == "alice"
        # 第二次命中缓存，返回相同结果（不重复解密）
        assert cache.cached_search_metadata(raw) == (title, username, url, tags)

    def test_single_entry_invalidation(self, entry_mgr, cache):
        entry_mgr.add_entry(Entry(title="A", username="u", password="p"))
        raw = entry_mgr.db.get_entries(EntryQuery())[0]
        cache.cached_search_metadata(raw)
        assert raw.crypto_id in cache._search_metadata_cache
        # 单条 crypto_id 失效：仅 pop 该条
        cache.apply_change(crypto_id=raw.crypto_id)
        assert raw.crypto_id not in cache._search_metadata_cache

    def test_bulk_change_clears_all_summaries(self, entry_mgr, cache):
        entry_mgr.add_entry(Entry(title="A", username="u", password="p"))
        entry_mgr.add_entry(Entry(title="B", username="u", password="p"))
        for raw in entry_mgr.db.get_entries(EntryQuery()):
            cache.cached_search_metadata(raw)
        assert len(cache._search_metadata_cache) == 2
        # crypto_id=None + clear_summaries=True：全清
        cache.apply_change(crypto_id=None, clear_summaries=True)
        assert len(cache._search_metadata_cache) == 0

    def test_category_change_keeps_summaries(self, entry_mgr, cache):
        entry_mgr.add_entry(Entry(title="A", username="u", password="p"))
        raw = entry_mgr.db.get_entries(EntryQuery())[0]
        cache.cached_search_metadata(raw)
        # 分类 CRUD：保留摘要缓存
        cache.apply_change(crypto_id=None, clear_summaries=False, category_changed=True)
        assert len(cache._search_metadata_cache) == 1

    def test_apply_change_advances_invalidate_version(self, cache):
        """apply_change 推进 _invalidate_version（M4），使进行中的解密回写失效。"""
        version_before = cache._invalidate_version
        cache.apply_change(crypto_id="nonexistent")
        assert cache._invalidate_version == version_before + 1

    def test_concurrent_invalidate_during_decrypt_skips_stale_write(
        self, entry_mgr, cache, monkeypatch
    ):
        """解密期间并发 apply_change 推进 version，旧密文解密结果不回写缓存（M4）。

        模拟读线程锁外解密条目期间，写线程更新该条目并 apply_change pop 缓存。无
        version 守卫时回写会把基于旧密文的摘要重新塞回已 pop 的缓存，下次命中返回
        旧摘要（污染）；version 守卫使回写丢弃。
        """
        entry_mgr.add_entry(Entry(title="old", username="u", password="p"))
        raw = entry_mgr.db.get_entries(EntryQuery())[0]
        cid = raw.crypto_id

        real_decrypt = entry_cache_module._decrypt_field_impl
        triggered = {"done": False}

        def _decrypt_with_concurrent_apply_change(encrypted, key, crypto_id, field_name, *, strict):
            # 首次解密本条目时模拟并发写更新（apply_change pop + 推进 version）
            if not triggered["done"] and crypto_id == cid:
                triggered["done"] = True
                cache.apply_change(crypto_id=cid)
            return real_decrypt(encrypted, key, crypto_id, field_name, strict=strict)

        monkeypatch.setattr(
            entry_cache_module,
            "_decrypt_field_impl",
            _decrypt_with_concurrent_apply_change,
        )
        cache._cached_search_metadata_no_check(raw)
        # version 守卫丢弃回写：缓存不含本条目（旧密文摘要未污染）
        assert cid not in cache._search_metadata_cache

    def test_batch_writeback_survives_exception_exit(self, entry_mgr, cache):
        """with 体抛异常时 pending 仍回写缓存（PERF-086 回归）。

        @contextmanager 此前无 try/finally：with 体抛非 DecryptionError 异常时
        yield 后的全部回写被跳过（含 _search_metadata_failed 完整性标记），
        与 docstring「含循环 break/异常退出的场景」不符。已解密的 pending 是
        采样世代密钥下的自洽结果，异常退出同样应入缓存（version 守卫仍在）。
        """
        entry_mgr.add_entry(Entry(title="A", username="u", password="p"))
        raw = entry_mgr.db.get_entries(EntryQuery())[0]
        cache.invalidate_if_epoch_changed()

        with pytest.raises(RuntimeError, match="boom"):
            with cache.search_metadata_batch() as batch:
                batch.get(raw)  # 锁外解密并入 pending
                raise RuntimeError("boom")

        # 异常路径的回写未被跳过：pending 可见于缓存
        assert raw.crypto_id in cache._search_metadata_cache


class TestWriterEpochGuard:
    """摘要缓存回写的写入方世代守卫（SEC-041 接入搜索分支 / SEC-043 全读路径接入）。

    跨世代解密结果不回写新世代缓存；四个读路径分支（非搜索列表/近期更新/详情/
    安全分析）各自的「解密期间恢复重臂 → 旧世代回写被拒」行为在此一并守护。
    """

    def test_stale_epoch_writeback_dropped_after_ream(self, entry_mgr, cache):
        """恢复重臂新 epoch 后，旧世代 worker 的解密结果不得写入新世代缓存。

        场景仿真（后台搜索 worker 未被取消）：worker 在 E1 取 raw+密钥+世代快照 →
        恢复提交 ``invalidate_all`` → 新读路径重臂 ``cache_epoch=E2`` → 旧 worker
        用旧 raw+旧密钥解密成功后回写。缓存侧双检（重臂后采样 cache_epoch）会放行，
        写入方世代守卫拒收（data_epoch=E1 ≠ cache_epoch=E2），恢复前明文不入新缓存。
        """
        entry_mgr.add_entry(Entry(title="OldTitle", username="u", password="p"))
        raw = entry_mgr.db.get_entries(EntryQuery())[0]
        old_epoch = cache._vault.key_epoch
        key = cache._key  # E1 世代密钥（worker 锁内快照）

        # 恢复提交：缓存整体失效；随后密钥世代轮换 + 新读路径重臂缓存
        cache.invalidate_all()
        cache._vault.set_epoch("restored-e2")
        cache.invalidate_if_epoch_changed()
        assert cache.cache_epoch == "restored-e2"  # 公开观察面（MAINT-095）

        # 旧 worker 回写（携带 E1 快照世代）：结果本身可正确解密，但守卫拒收入缓存
        meta = cache._cached_search_metadata_no_check(raw, key=key, data_epoch=old_epoch)
        assert meta.title == "OldTitle"
        assert raw.crypto_id not in cache._search_metadata_cache

    def test_inlock_caller_without_data_epoch_keeps_fallback(self, entry_mgr, cache):
        """不传 data_epoch 的调用方退回缓存侧采样并正常回写（回退语义保持）。

        SEC-043 全路径接入后，锁外解密的生产路径（列表/近期/详情/分析）均传锁内
        快照世代；回退保留给未接线的调用方（category_manager 的分类名会话缓存
        路径不在本轮文件集内，其防护面与既有 version 守卫一致）与测试直调——本
        测试守护回退行为不回归：同世代下采样即写入方世代，回写正常入缓存。
        """
        entry_mgr.add_entry(Entry(title="T", username="u", password="p"))
        raw = entry_mgr.db.get_entries(EntryQuery())[0]
        cache.invalidate_if_epoch_changed()

        meta = cache._cached_search_metadata_no_check(raw)
        assert meta.title == "T"
        assert raw.crypto_id in cache._search_metadata_cache

    def _install_mid_decrypt_rotation(self, monkeypatch, cache):
        """在首次摘要解密期间模拟恢复提交：invalidate_all → 轮换 epoch → 重臂 E2。

        时序对应真实竞态：worker 在 E1 锁内取 raw+密钥+世代快照后进入锁外解密；
        恢复在解密期间提交（清缓存+轮换密钥世代），随后新读路径把缓存重臂为 E2。
        旧 worker 的解密结果本身正确（旧 raw+旧密钥自洽），但不得回写 E2 缓存。
        """

        real_decrypt = entry_cache_module._decrypt_field_impl
        triggered = {"done": False}

        def _decrypt_with_restore_commit(encrypted, key, crypto_id, field_name, *, strict):
            if not triggered["done"]:
                triggered["done"] = True
                cache.invalidate_all()
                cache._vault.set_epoch("restored-e2")
                cache.invalidate_if_epoch_changed()
            return real_decrypt(encrypted, key, crypto_id, field_name, strict=strict)

        monkeypatch.setattr(
            entry_cache_module,
            "_decrypt_field_impl",
            _decrypt_with_restore_commit,
        )

    def test_non_search_list_rejects_cross_generation_writeback(
        self, entry_mgr, cache, monkeypatch
    ):
        """非搜索列表分支（SEC-043）：解密期间恢复重臂 E2 后，旧世代回写被拒收。

        复现口径：get_entry_summaries 无搜索词路径此前 meta=None 走缓存侧采样，
        旧明文可植入新 epoch 缓存；接入锁内快照世代后守卫拒收。
        """
        entry_mgr.add_entry(Entry(title="T1", username="u", password="p"))
        entry_mgr.add_entry(Entry(title="T2", username="u", password="p"))
        self._install_mid_decrypt_rotation(monkeypatch, cache)

        summaries = entry_mgr.get_entry_summaries()

        # 结果本身完整返回（旧 raw+旧密钥自洽解密成功），但缓存不收旧世代明文
        assert {s.title for s in summaries} == {"T1", "T2"}
        assert len(cache._search_metadata_cache) == 0

    def test_recent_summaries_rejects_cross_generation_writeback(
        self, entry_mgr, cache, monkeypatch
    ):
        """近期更新分支（SEC-043）：同上时序，get_recent_summaries 的回写被拒收。"""
        entry_mgr.add_entry(Entry(title="R1", username="u", password="p"))
        entry_mgr.add_entry(Entry(title="R2", username="u", password="p"))
        self._install_mid_decrypt_rotation(monkeypatch, cache)

        summaries = entry_mgr.get_recent_summaries(limit=10)

        assert {s.title for s in summaries} == {"R1", "R2"}
        assert len(cache._search_metadata_cache) == 0

    def test_detail_path_rejects_cross_generation_writeback(self, entry_mgr, cache, monkeypatch):
        """详情分支（SEC-043）：get_entry 的摘要/分类名缓存回写在重臂后被拒收。"""
        from src.models import Category

        category_id = entry_mgr.categories.add_category(Category(name="详情分类"))
        entry_id = entry_mgr.add_entry(
            Entry(title="D1", username="u", password="p", category_id=category_id)
        )
        self._install_mid_decrypt_rotation(monkeypatch, cache)

        detail = entry_mgr.get_entry(entry_id)

        assert detail is not None
        assert detail.title == "D1"
        assert detail.category_name == "详情分类"
        # 摘要与分类名缓存均不收旧世代明文
        assert len(cache._search_metadata_cache) == 0
        assert len(cache._category_name_cache) == 0

    def test_analyzer_summary_rejects_cross_generation_writeback(
        self, entry_mgr, cache, monkeypatch
    ):
        """安全分析分支（SEC-043）：full_analysis 摘要构建期间重臂后回写被拒收。"""
        from src.business.services.security_analyzer import SecurityAnalyzer

        entry_mgr.add_entry(Entry(title="A1", username="u", password="Str0ngPass!1"))
        entry_mgr.add_entry(Entry(title="A2", username="u", password="Str0ngPass!2"))
        analyzer = SecurityAnalyzer(entry_mgr._vault, cache)
        self._install_mid_decrypt_rotation(monkeypatch, cache)

        report = analyzer.full_analysis()

        assert report["total"] == 2
        assert len(cache._search_metadata_cache) == 0

    def test_same_epoch_writeback_accepted(self, entry_mgr, cache):
        """世代一致的回写正常入缓存（守卫不误伤常规路径）。"""
        entry_mgr.add_entry(Entry(title="T", username="u", password="p"))
        raw = entry_mgr.db.get_entries(EntryQuery())[0]
        cache.invalidate_if_epoch_changed()
        epoch = cache._vault.key_epoch

        meta = cache.cached_search_metadata_full(raw, data_epoch=epoch)
        assert meta.title == "T"
        assert raw.crypto_id in cache._search_metadata_cache


class TestTotpSecretCache:
    """TOTP secret 缓存的 store/pop/clear 与回写世代守卫（SEC-044）。"""

    def test_store_pop_clear(self, cache):
        cache.store_totp(1, "SECRET")
        assert cache._totp_secret_cache.get(1) == "SECRET"
        cache.pop_totp(1)
        assert 1 not in cache._totp_secret_cache
        cache.store_totp(2, "SECRET2")
        cache.clear_totp()
        assert len(cache._totp_secret_cache) == 0

    def test_resolve_rejects_cross_generation_writeback(self, entry_mgr, cache, monkeypatch):
        """resolve_totp_secret 回写世代守卫（SEC-044）：解密后、回写前恢复重臂新世代。

        时序仿真（TOTP 定时器是真实并发读者）：E1 读守卫内取 raw+采样世代 →
        解密成功 → 退出读守卫后恢复提交（invalidate_all + 轮换 + 重臂 E2）→ 回写。
        旧世代 secret 不得写入新世代缓存（TOTP secret 为双因子凭证）。
        """
        entry_id = entry_mgr.add_entry(
            Entry(title="T", username="u", password="p", totp_secret="JBSWY3DPEHPK3PXP")
        )

        real_decrypt = entry_cache_module._decrypt_field_impl
        rotated = {"done": False}

        def _decrypt_then_rotate(encrypted, key, crypto_id, field_name, *, strict=False):
            value = real_decrypt(encrypted, key, crypto_id, field_name, strict=strict)
            # 解密完成后、缓存回写前插入恢复提交时序
            if not rotated["done"] and field_name == "totp_secret":
                rotated["done"] = True
                cache.invalidate_all()
                cache._vault.set_epoch("restored-e2")
                cache.invalidate_if_epoch_changed()
            return value

        monkeypatch.setattr(entry_cache_module, "_decrypt_field_impl", _decrypt_then_rotate)

        secret = cache.resolve_totp_secret(entry_id, use_cache=True)

        # 明文照常返回（旧 raw+旧密钥自洽），但缓存拒收旧世代回写
        assert secret == "JBSWY3DPEHPK3PXP"
        assert entry_id not in cache._totp_secret_cache

    def test_store_totp_with_stale_data_epoch_rejected(self, entry_mgr, cache):
        """store_totp 世代复查（SEC-044）：data_epoch 失配（恢复已重臂）时拒收。"""
        entry_mgr.add_entry(Entry(title="T", username="u", password="p"))
        cache.invalidate_if_epoch_changed()
        stale_epoch = cache._vault.key_epoch

        cache.invalidate_all()
        cache._vault.set_epoch("restored-e2")
        cache.invalidate_if_epoch_changed()

        # 旧世代调用方携带 E1 快照预热：新世代缓存拒收；同世代快照正常落缓存
        cache.store_totp(7, "OLD-SECRET", data_epoch=stale_epoch)
        assert 7 not in cache._totp_secret_cache
        cache.store_totp(8, "NEW-SECRET", data_epoch="restored-e2")
        assert cache._totp_secret_cache.get(8) == "NEW-SECRET"

    def test_pop_and_clear_advance_totp_domain_version(self, cache):
        """pop_totp/clear_totp 只推进 TOTP 域失效版本，不动主域（QL-070 分域）。

        回写守卫的注释一直承诺「单条失效（pop_totp）不回写」，此前 pop 只清 dict
        不推进版本，防护名存实亡；推进 TOTP 域后守卫真实覆盖（下一个测试）。
        主域版本不动使 pop 不击穿投影行集/摘要/标签缓存——pop 的高频来源是
        detail_panel 离开条目的 evict（无任何 DB 写）；全局失效（apply_change）
        两域一并推进，整体失效仍阻止在飞的 TOTP 解密回写。
        """
        main_before = cache._invalidate_version
        totp_before = cache._totp_invalidate_version
        cache.store_totp(1, "SECRET")
        cache.pop_totp(1)
        assert cache._totp_invalidate_version == totp_before + 1
        assert cache._invalidate_version == main_before  # 主域不动
        cache.clear_totp()
        assert cache._totp_invalidate_version == totp_before + 2
        assert cache._invalidate_version == main_before
        # 全局失效两域一并推进：整体失效窗口内 TOTP 回写同样被拒收
        cache.apply_change(crypto_id="nonexistent")
        assert cache._invalidate_version == main_before + 1
        assert cache._totp_invalidate_version == totp_before + 3

    def test_pop_totp_during_decrypt_window_blocks_writeback(self, entry_mgr, cache, monkeypatch):
        """解密窗口内 pop_totp：旧 secret 不回写（QL-070，守卫真实覆盖单条失效）。

        时序仿真（条目更新路径与 TOTP 定时器并发）：定时器在 E1 读守卫内采样
        世代/TOTP 域版本并解密 → 解密完成、回写前，主线程 update_entry 的
        pop_totp 失效该条（totp_secret 已变）→ 定时器回写。pop 不推进版本时
        守卫放行，**旧 secret** 重新落入缓存并持续命中（展示过期验证码）；现
        pop 推进 TOTP 域版本（QL-070 分域后回写守卫比对 TOTP 域），守卫拒收。
        """
        entry_id = entry_mgr.add_entry(
            Entry(title="T", username="u", password="p", totp_secret="JBSWY3DPEHPK3PXP")
        )

        real_decrypt = entry_cache_module._decrypt_field_impl
        popped = {"done": False}

        def _decrypt_then_pop(encrypted, key, crypto_id, field_name, *, strict=False):
            value = real_decrypt(encrypted, key, crypto_id, field_name, strict=strict)
            if not popped["done"] and field_name == "totp_secret":
                popped["done"] = True
                # 解密完成后、缓存回写前插入条目更新的单条失效
                cache.pop_totp(entry_id)
            return value

        monkeypatch.setattr(entry_cache_module, "_decrypt_field_impl", _decrypt_then_pop)

        secret = cache.resolve_totp_secret(entry_id, use_cache=True)

        # 明文照常返回（解密本身成功），但旧 secret 不回写缓存
        assert secret == "JBSWY3DPEHPK3PXP"
        assert entry_id not in cache._totp_secret_cache

    def test_resolve_writeback_survives_other_entry_pop(self, entry_mgr, cache, monkeypatch):
        """resolve 回写守卫按条目粒度（SEC-063 守卫粒度演进的 resolve 侧对齐）。

        时序：详情切换对**上一条目**的 evict（pop A，仅推进全局版本）与正在解密
        的条目 B 的 TOTP 刷新交错——原守卫比对全局版本精确相等，A 的 pop 使 B 的
        回写被误拒（V != V+1），「免重解密」目标在 resolve 侧部分失效（store 侧
        修复前的自冲突同型）；改两级水位后 B 的回写照常落缓存，本条目自身的
        pop / 整体失效仍拒收（见上下两个测试）。
        """
        entry_id = entry_mgr.add_entry(
            Entry(title="B", username="u", password="p", totp_secret="JBSWY3DPEHPK3PXP")
        )

        real_decrypt = entry_cache_module._decrypt_field_impl
        popped_other = {"done": False}

        def _decrypt_then_pop_other(encrypted, key, crypto_id, field_name, *, strict=False):
            value = real_decrypt(encrypted, key, crypto_id, field_name, strict=strict)
            if not popped_other["done"] and field_name == "totp_secret":
                popped_other["done"] = True
                # 解密完成后、回写前：其他条目的 evict（仅推进全局版本）
                cache.pop_totp(999)
            return value

        monkeypatch.setattr(entry_cache_module, "_decrypt_field_impl", _decrypt_then_pop_other)

        secret = cache.resolve_totp_secret(entry_id, use_cache=True)

        # 本条目未被失效：回写照常落缓存（不被其他条目的 pop 误拒）
        assert secret == "JBSWY3DPEHPK3PXP"
        assert cache._totp_secret_cache.get(entry_id) == "JBSWY3DPEHPK3PXP"

    def test_soft_delete_reentry_window_rejected_by_post_write_repop(self, cache):
        """软删重入窗口（SEC-072）：快照恰=前置 pop 水位的写入在写后再清后恒被拒收。

        时序复刻 delete_entry 的并发交错（当前靠 GUI 线程串行不可达，ARCH-054
        线程模型）：前置 pop(N) → 读者恰在 pop 后快照 data_version=N 并读到尚未
        删除的活跃行 → 删除提交 → 写后再 pop(N+1) → 读者 store。仅有前置 pop 时
        水位=N，store 复查 N > N 为 False 放行——软删条目的明文 secret 重入缓存；
        写后再 pop 把水位推过 N，一切早于提交的快照自此恒拒收。
        """
        cache.invalidate_if_epoch_changed()
        cache.pop_totp(11)  # delete_entry 的前置 pop（QL-070）
        sampled = cache.totp_invalidate_version  # 读者恰在 pop 后的快照（=pop 水位）
        cache.pop_totp(11)  # 写后 TOTP 再清（SEC-072）

        stored = cache.store_totp(
            11, "SECRET-SOFT-DELETED", data_epoch=cache.cache_epoch, data_version=sampled
        )

        assert stored is False
        assert 11 not in cache._totp_secret_cache

    def test_totp_to_totp_switch_preload_accepted(self, entry_mgr, cache):
        """TOTP→TOTP 切换预热落缓存（SEC-063 守卫粒度修复的核心场景）。

        时序复刻 do_select_entry 链路（真实 EntryCacheManager 复现的时序自冲突）：
        get_entry_with_epoch 锁内快照版本 V → show_entry 的 _prepare_display 对
        **上一条目** pop_totp（全局版本 → V+1）→ _render_totp_and_history 带旧
        快照 V 预热新条目。原守卫比对全局版本恒失配，新条目 preloaded secret
        永远进不了缓存（预热免重解密在最常见的 TOTP 条目间浏览场景被结构性
        击穿）；改条目粒度后其他条目的失效不再拒收本条目。
        """
        entry_mgr.add_entry(Entry(title="T", username="u", password="p"))
        cache.invalidate_if_epoch_changed()
        sampled = cache.totp_invalidate_version  # 新条目的解密时点快照
        cache.pop_totp(99)  # 离开上一条目的 evict：仅推进全局版本，与本条目无关

        stored = cache.store_totp(
            11, "SECRET-NEW", data_epoch=cache.cache_epoch, data_version=sampled
        )

        assert stored is True
        assert cache._totp_secret_cache.get(11) == "SECRET-NEW"

    def test_revisit_after_own_pop_accepted(self, cache):
        """A→B→A 往返重访：快照晚于自身失效的预热照常落缓存（单条版本水位）。

        pop 记录「该条目失效完成后的版本」：重访读取（快照 ≥ 水位）本身晚于
        失效、secret 已是新值，须放行——纯 set 记录「曾被失效过」会把 A 的
        历史失效误判到重访预热上，退回全局版本比对的自冲突形态。
        """
        cache.invalidate_if_epoch_changed()
        cache.pop_totp(11)  # A→B 切换时对 A 的 evict
        sampled = cache.totp_invalidate_version  # B→A 重访快照（晚于 A 的失效）
        cache.pop_totp(12)  # 离开 B 的 evict（全局版本再推进）

        stored = cache.store_totp(
            11, "SECRET-A2", data_epoch=cache.cache_epoch, data_version=sampled
        )

        assert stored is True
        assert cache._totp_secret_cache.get(11) == "SECRET-A2"

    def test_own_pop_after_snapshot_still_rejected(self, cache):
        """被失效条目自身的旧 secret 仍拒收：快照后才失效（导入覆盖 evict 时序）。"""
        cache.invalidate_if_epoch_changed()
        sampled = cache.totp_invalidate_version
        cache.pop_totp(11)  # 快照后本条目被失效

        stored = cache.store_totp(
            11, "SECRET-OLD", data_epoch=cache.cache_epoch, data_version=sampled
        )

        assert stored is False
        assert 11 not in cache._totp_secret_cache

    def test_global_invalidation_after_snapshot_still_rejected(self, cache):
        """整体失效仍整体拒收（SEC-063 全局口径保持）：任意条目写路径后旧快照失配。"""
        cache.invalidate_if_epoch_changed()
        sampled = cache.totp_invalidate_version
        cache.apply_change(crypto_id="other-entry")  # 整体失效：版本推进 + 水位前移

        stored = cache.store_totp(
            11, "SECRET-OLD", data_epoch=cache.cache_epoch, data_version=sampled
        )

        assert stored is False
        assert 11 not in cache._totp_secret_cache
        # 整体失效同时清空条目粒度记录（内存驻留以「无写操作的浏览会话」为界）
        assert cache._totp_invalidated_versions == {}

    def test_store_totp_empty_secret_returns_false(self, cache):
        """空串归一跳过返回 False（与 resolve 的空串归一口径对齐）。"""
        assert cache.store_totp(1, "") is False
        assert 1 not in cache._totp_secret_cache

    def test_resolve_totp_tampered_entry_returns_none(self, entry_mgr, cache, caplog):
        """元数据被篡改的条目 TOTP 解析优雅降级返回 None，不抛 VaultIntegrityError
        （QL-077）。

        db.get_entry 默认 STRICT 验签，篡改（改入签元数据不重签）直通抛
        VaultIntegrityError——此前直达 Qt 槽，TOTP 定时器每秒触发一条异常日志
        冲刷且条目 TOTP 静默停止；现对齐 ARCH-005 的优雅处理返回 None（定时器
        随首个 None 停表），单次 warning 记定位符不刷屏。
        """
        import logging

        entry_id = entry_mgr.add_entry(
            Entry(title="T", username="u", password="p", totp_secret="JBSWY3DPEHPK3PXP")
        )
        conn = entry_mgr.db._conn
        assert conn is not None
        conn.execute("UPDATE entries SET is_favorite = 1 - is_favorite WHERE id=?", (entry_id,))
        conn.commit()

        with caplog.at_level(logging.WARNING, logger="src.business.managers.entry_cache"):
            secret = cache.resolve_totp_secret(entry_id, use_cache=True)

        assert secret is None
        assert entry_id not in cache._totp_secret_cache
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1  # 单次 warning，不随定时器刷屏


class TestGetAllTagsBackfillGuard:
    """get_all_tags 回填的 epoch+version 双守卫（QL-069）。"""

    def test_stale_aggregation_rejected_after_concurrent_invalidation(
        self, entry_mgr, cache, monkeypatch
    ):
        """「聚合出锁 → 回填」窗口内写入失效：陈旧快照被拒，下次重算吸收。

        时序仿真（后台 tag worker 与主线程写入交错）：worker 聚合得快照 S1
        （不含并发条目）→ 出锁后主线程 add_entry + notify（此刻 _tags_cache 为
        None，apply_tag_delta no-op，version+1）→ worker 回填。旧实现回填只比
        epoch（单条 notify 不动 epoch），陈旧 S1 落入 _tags_cache 且无自愈
        （标签缓存无 TTL，仅锁定/改密/恢复/写路径可纠正）；现回填须 epoch+
        version 双比对，陈旧快照被拒（下次重算吸收）。
        """
        entry_mgr.add_entry(Entry(title="A", username="u", password="p", tags="工作"))

        real_projection = entry_mgr.db.get_entries_tags_projection
        injected = {"done": False}

        def _projection_with_concurrent_write():
            rows = real_projection()
            if not injected["done"]:
                injected["done"] = True
                # 模拟主线程在 worker 聚合出锁后的写入 + notify（测试单线程内
                # 重入 epoch_guarded_read 的 db_lock：RLock 可重入）
                entry_mgr.add_entry(Entry(title="并发", username="u", password="p", tags="新标签"))
            return rows

        monkeypatch.setattr(
            entry_mgr.db, "get_entries_tags_projection", _projection_with_concurrent_write
        )

        # 第一次调用：返回旧快照的聚合值（旧上下文可接受），但不得落入缓存
        assert dict(cache.get_all_tags()) == {"工作": 1}
        assert cache._tags_cache is None  # 陈旧快照被拒（旧实现在此落入 S1）

        # 下次调用无并发窗口：重算吸收并发条目并正常回填
        assert dict(cache.get_all_tags()) == {"工作": 1, "新标签": 1}
        assert cache._tags_cache is not None

    def test_epoch_mismatch_still_rejects_backfill(self, entry_mgr, cache, monkeypatch):
        """epoch 失配（改密/锁定）拒收回填的既有语义保持（SEC-010 不回归）。"""
        entry_mgr.add_entry(Entry(title="A", username="u", password="p", tags="工作"))
        assert dict(cache.get_all_tags()) == {"工作": 1}

        # 模拟锁定：整体失效 + 世代清零，缓存侧不再接收本快照
        cache.invalidate_all()
        assert cache._tags_cache is None


class TestSearchProjectionCache:
    """搜索投影行集缓存（PERF-086）：命中免重拉、写路径失效、键隔离与行为等价。"""

    def _spy_projection(self, vault, monkeypatch) -> "list[int]":
        """spy db.get_entries_search_projection 的调用次数（投影重拉的标志）。"""
        calls: list[int] = []
        original = vault.db.get_entries_search_projection

        def _spy(query):
            calls.append(1)
            return original(query)

        monkeypatch.setattr(vault.db, "get_entries_search_projection", _spy)
        return calls

    def test_warm_search_hits_projection_cache(self, entry_mgr, monkeypatch):
        """同键（过滤三元组+排序规格）重复搜索命中缓存，投影零重拉。"""
        entry_mgr.add_entry(Entry(title="Alpha", username="u", password="p"))
        spy = self._spy_projection(entry_mgr._vault, monkeypatch)

        entry_mgr.get_entry_summaries(search="alp")  # 冷：拉一次
        assert len(spy) == 1
        entry_mgr.get_entry_summaries(search="alp")  # 暖：行集与搜索词无关，命中
        entry_mgr.get_entry_summaries(search="alph")  # 搜索词变化仍命中
        assert len(spy) == 1

    def test_write_path_invalidates_projection_cache(self, entry_mgr, monkeypatch):
        """任意写路径（notify 推进 version）后投影缓存失效，下次搜索重拉。"""
        entry_mgr.add_entry(Entry(title="Alpha", username="u", password="p"))
        spy = self._spy_projection(entry_mgr._vault, monkeypatch)
        entry_mgr.get_entry_summaries(search="alp")
        assert len(spy) == 1

        entry_mgr.add_entry(Entry(title="Beta", username="u", password="p"))
        results = entry_mgr.get_entry_summaries(search="alp")
        # 写后重拉（version 失配），且结果不残留陈旧行集
        assert len(spy) == 2
        assert {r.title for r in results} == {"Alpha"}

    def test_invalidate_all_clears_projection_cache(self, entry_mgr, monkeypatch):
        """锁定/改密（invalidate_all）清空投影缓存：下次重拉。"""
        entry_mgr.add_entry(Entry(title="Alpha", username="u", password="p"))
        spy = self._spy_projection(entry_mgr._vault, monkeypatch)
        entry_mgr.get_entry_summaries(search="alp")
        assert len(spy) == 1
        entry_mgr.invalidate_caches()
        entry_mgr.get_entry_summaries(search="alp")
        assert len(spy) == 2

    def test_projection_key_isolation(self, entry_mgr, monkeypatch):
        """不同过滤/排序规格各占一键：互不串用、各自命中。"""
        from src.models import Category

        cat_id = entry_mgr.categories.add_category(Category(name="分类"))
        a_id = entry_mgr.add_entry(
            Entry(title="Alpha", username="u", password="p", category_id=cat_id)
        )
        entry_mgr.add_entry(Entry(title="Beta", username="u", password="p"))
        entry_mgr.delete_entry(a_id)  # Alpha 入回收站
        spy = self._spy_projection(entry_mgr._vault, monkeypatch)

        # 主视图（复合序键）
        assert {r.title for r in entry_mgr.get_entry_summaries(search="a")} == {"Beta"}
        # 回收站（deleted_only 键）：分别拉取
        assert {r.title for r in entry_mgr.get_entry_summaries(deleted_only=True, search="a")} == {
            "Alpha"
        }
        assert len(spy) == 2
        # 近期更新序（排序下推键）：与复合序键不同，再拉一次
        entry_mgr.get_entry_summaries(search="a", order_by="updated_at", limit=5)
        assert len(spy) == 3
        # 三个键各自重复调用均命中
        entry_mgr.get_entry_summaries(search="a")
        entry_mgr.get_entry_summaries(deleted_only=True, search="a")
        entry_mgr.get_entry_summaries(search="a", order_by="updated_at", limit=5)
        assert len(spy) == 3

    def test_cached_search_results_match_uncached(self, entry_mgr):
        """行为等价：暖缓存（投影+摘要命中）与冷路径的搜索结果一致。"""
        for title in ("zebra", "alpha", "middle"):
            entry_mgr.add_entry(Entry(title=title, username="u", password="p"))

        cold = entry_mgr.get_entry_summaries(search="a", order_by="title", order_desc=True)
        warm = entry_mgr.get_entry_summaries(search="a", order_by="title", order_desc=True)
        assert [r.id for r in warm] == [r.id for r in cold]
        assert [r.title for r in warm] == [r.title for r in cold]

    def test_pop_totp_keeps_projection_cache(self, entry_mgr, monkeypatch):
        """pop_totp 只推进 TOTP 域版本：投影行集缓存不受单条 TOTP 失效影响。

        QL-070 分域回归：detail_panel 离开带 TOTP 的条目时经 evict → pop_totp
        （无任何 DB 写），此前 pop 推进主域 ``_invalidate_version`` 使该高频交互
        每次作废全部 4 个投影缓存键，PERF-086 的暖态命中（免 50k 行重取
        ~160ms）被无关失效击穿；分域后主域版本不动，投影缓存照常命中。
        """
        entry_mgr.add_entry(Entry(title="Alpha", username="u", password="p"))
        spy = self._spy_projection(entry_mgr._vault, monkeypatch)
        entry_mgr.get_entry_summaries(search="alp")  # 冷：拉一次并回填缓存
        assert len(spy) == 1

        entry_mgr.cache.pop_totp(1)  # 离开条目的 evict（entry_id 与库内条目无关）
        entry_mgr.get_entry_summaries(search="alp")

        assert len(spy) == 1  # 投影缓存仍命中，零重拉

    def test_projection_rows_exit_isolated_from_cache(self, entry_mgr):
        """search_projection_rows 出口为隔离副本：调用方变异不污染缓存行集。

        命中与未命中两条路径均不外泄缓存内部 list 引用（对齐 get_failed_fields
        的 QL-056 防御性拷贝纪律）——返回引用时任何未来调用方的就地变异
        （sort/append/reverse）会直接改写缓存行集且无失败信号。
        """
        entry_mgr.add_entry(Entry(title="Alpha", username="u", password="p"))
        entry_mgr.add_entry(Entry(title="Beta", username="u", password="p"))
        cache = entry_mgr.cache
        key = (False, None, False, None, True)

        def _fetch():
            return entry_mgr.db.get_entries_search_projection(EntryQuery())

        # 未命中路径：fetch 回填缓存后出口变异不影响缓存
        first = cache.search_projection_rows(key, _fetch)
        original_ids = [row.id for row in first]
        first.reverse()  # 模拟调用方就地变异
        second = cache.search_projection_rows(key, _fetch)  # 命中路径
        assert [row.id for row in second] == original_ids  # 缓存行集未被污染
        # 命中路径：出口变异同样不回写缓存
        second.reverse()
        third = cache.search_projection_rows(key, _fetch)
        assert [row.id for row in third] == original_ids


class TestTagsCacheValid:
    """tags_cache_valid 在填充与失效前后的状态迁移。"""

    def test_invalid_before_population(self, cache):
        """初始未填充标签缓存，tags_cache_valid 为 False。"""
        assert not cache.tags_cache_valid

    def test_valid_after_population(self, entry_mgr, cache):
        """填充标签后 tags_cache_valid 为 True（_tags_cache 非空且 epoch 一致）。"""
        entry_mgr.add_entry(Entry(title="T", username="u", password="p", tags="work,dev"))
        cache.get_all_tags()  # 填充 _tags_cache
        assert cache.tags_cache_valid

    def test_invalid_after_invalidate(self, entry_mgr, cache):
        """invalidate_all 后 tags_cache_valid 回到 False。"""
        entry_mgr.add_entry(Entry(title="T", username="u", password="p", tags="work"))
        cache.get_all_tags()
        assert cache.tags_cache_valid
        cache.invalidate_all()
        assert not cache.tags_cache_valid


class TestApplyTagDelta:
    """apply_tag_delta 的差分语义（PERF-079）：缓存有效时原地增减，无效时无操作。

    QL-065 后签名为 ``(old_tags, new_tags)``：一次锁内先减旧再加新（编辑路径原先
    两次锁调用中间可见撕裂态），空 old/空 new 是合法端点（纯增/纯减）。
    QL-070 起返回是否应用：False 时调用方保守置 tags_changed=True 走整表失效。
    """

    def _populate(self, entry_mgr, cache) -> None:
        entry_mgr.add_entry(Entry(title="A", username="u", password="p", tags="工作,社交"))
        entry_mgr.add_entry(Entry(title="B", username="u", password="p", tags="工作"))
        cache.get_all_tags()  # 填充 _tags_cache

    def test_add_increments_counts_and_resorts(self, entry_mgr, cache):
        """新增差分 +1：计数上调且维持「计数降序」出口契约。"""
        self._populate(entry_mgr, cache)
        cache.apply_tag_delta("", "工作,新标签")
        tags = dict(cache.get_all_tags())
        assert tags == {"工作": 3, "社交": 1, "新标签": 1}
        # 出口按计数降序（工作 在前）
        assert cache.get_all_tags()[0] == ("工作", 3)

    def test_remove_decrements_and_drops_zero_counts(self, entry_mgr, cache):
        """移除差分 -1：计数归零的标签从结果移除。"""
        self._populate(entry_mgr, cache)
        cache.apply_tag_delta("社交,工作")
        assert dict(cache.get_all_tags()) == {"工作": 1}

    def test_combined_rename_single_call(self, entry_mgr, cache):
        """合并调用一次锁内先减后加（QL-065）：改名净效果正确、总量守恒。

        行为断言原子性：一次调用产出的最终状态与「先减旧、后加新」的语义一致，
        不存在旧已减而新未加的中间态出口（撕裂态下「工作」会瞬时归零移除）。
        """
        self._populate(entry_mgr, cache)
        before_total = sum(c for _, c in cache.get_all_tags())
        cache.apply_tag_delta("工作", "临时")
        # 工作 2→1、临时 0→1：净效果一次到位
        assert dict(cache.get_all_tags()) == {"工作": 1, "社交": 1, "临时": 1}
        assert sum(c for _, c in cache.get_all_tags()) == before_total

    def test_identical_old_new_is_idempotent(self, entry_mgr, cache):
        """old == new 的合并调用幂等（先减后加净零，不改变任何计数）。"""
        self._populate(entry_mgr, cache)
        cache.apply_tag_delta("工作", "工作")
        assert dict(cache.get_all_tags()) == {"工作": 2, "社交": 1}

    def test_noop_when_cache_invalid(self, entry_mgr, cache):
        """缓存未填充（None）时差分无操作，下次 get_all_tags 全量重算吸收。"""
        entry_mgr.add_entry(Entry(title="A", username="u", password="p", tags="工作"))
        assert cache._tags_cache is None
        cache.apply_tag_delta("", "工作")
        assert cache._tags_cache is None
        assert dict(cache.get_all_tags()) == {"工作": 1}

    def test_noop_for_empty_or_blank_tags(self, entry_mgr, cache):
        """空串/全空白 tags 的差分无操作（不创建空计数条目）。"""
        self._populate(entry_mgr, cache)
        cache.apply_tag_delta("", "  ,  ")
        assert dict(cache.get_all_tags()) == {"工作": 2, "社交": 1}

    def test_roundtrip_matches_full_recalc(self, entry_mgr, cache):
        """+1/-1 往返后差分结果与全量重算一致（等价守护）。"""
        self._populate(entry_mgr, cache)
        cache.apply_tag_delta("", "工作")
        cache.apply_tag_delta("工作")
        by_delta = dict(cache.get_all_tags())
        cache.invalidate_all()
        assert dict(cache.get_all_tags()) == by_delta

    def test_delta_and_full_recalc_share_parse_with_whitespace(self, entry_mgr, cache):
        """差分与全量重算共用 models.parse_tag_list（QL-065 守护）。

        带首尾空白/空段/重复标签的 tags（" a , b ,, a " → [a, b, a]）：add_entry
        走差分口径计数，与失效后的全量重算（解析 db 同一 tags 字符串）逐标签
        一致——两口径若各持一份解析（漂移即计数分歧）此测试失败。
        """
        self._populate(entry_mgr, cache)
        entry_mgr.add_entry(Entry(title="C", username="u", password="p", tags=" a , b ,, a "))
        by_delta = dict(cache.get_all_tags())
        cache.invalidate_all()
        assert dict(cache.get_all_tags()) == by_delta
        # 精确口径：工作 2、社交 1、a 2、b 1（重复标签逐次累加）
        assert by_delta == {"工作": 2, "社交": 1, "a": 2, "b": 1}

    def test_delta_abandoned_when_invalidated_during_window(self, entry_mgr, cache):
        """差分执行中失效 → 差分被放弃（QL-065 写回世代守卫）。

        场景仿真（并发导入/恢复与单条删除交错）：调用方在写事务前快照
        ``invalidate_version``，窗口内并发 notify 触发 ``_tags_cache`` 置空并由
        后续 get_all_tags 基于新库重建（重建已含本条变更）——差分携带过期版本
        到达时被守卫放弃，不向重建后的缓存叠加旧变更（双扣）。
        """
        self._populate(entry_mgr, cache)
        stale_version = cache.invalidate_version
        # 窗口内发生失效（并发 notify 的 apply_change 置 None + 推进版本）
        cache.apply_change(tags_changed=True)
        assert cache._tags_cache is None
        # 重建（模拟基于新库的 get_all_tags）
        rebuilt = dict(cache.get_all_tags())
        assert rebuilt == {"工作": 2, "社交": 1}
        # 过期版本的差分被放弃：计数保持重建值而非再扣一次
        cache.apply_tag_delta("工作", expected_version=stale_version)
        assert dict(cache.get_all_tags()) == rebuilt

    def test_delta_applied_when_version_matches(self, entry_mgr, cache):
        """世代一致的差分正常写回（守卫不误伤常规路径）。"""
        self._populate(entry_mgr, cache)
        version = cache.invalidate_version
        cache.apply_tag_delta("", "新标签", expected_version=version)
        assert dict(cache.get_all_tags()) == {"工作": 2, "社交": 1, "新标签": 1}

    def test_delta_without_version_bypasses_guard(self, entry_mgr, cache):
        """不传 expected_version 保持无条件写回（测试直调等既有调用方语义）。"""
        self._populate(entry_mgr, cache)
        # 推进版本但不触碰标签缓存（tags_changed=False 且单条 pop 不相干条目）
        cache.apply_change(crypto_id="nonexistent", tags_changed=False, clear_summaries=False)
        cache.apply_tag_delta("", "新标签")
        assert dict(cache.get_all_tags()) == {"工作": 2, "社交": 1, "新标签": 1}

    def test_returns_true_when_applied(self, entry_mgr, cache):
        """缓存有效且世代一致：差分应用并返回 True（QL-070 返回值契约）。"""
        self._populate(entry_mgr, cache)
        version = cache.invalidate_version
        assert cache.apply_tag_delta("", "新标签", expected_version=version) is True
        assert dict(cache.get_all_tags()) == {"工作": 2, "社交": 1, "新标签": 1}

    def test_returns_false_when_cache_absent(self, entry_mgr, cache):
        """缓存未填充（None）：差分无操作并返回 False，供调用方保守整表失效。"""
        entry_mgr.add_entry(Entry(title="A", username="u", password="p", tags="工作"))
        assert cache._tags_cache is None
        assert cache.apply_tag_delta("", "工作") is False

    def test_returns_false_when_version_mismatch(self, entry_mgr, cache):
        """世代失配：差分被放弃并返回 False（旧实现静默放弃且调用方不知情）。"""
        self._populate(entry_mgr, cache)
        stale_version = cache.invalidate_version
        cache.apply_change(crypto_id="nonexistent", tags_changed=False, clear_summaries=False)
        assert cache.apply_tag_delta("工作", expected_version=stale_version) is False
        # 缓存保持失效前的计数（差分未叠加）
        assert dict(cache.get_all_tags()) == {"工作": 2, "社交": 1}

    def test_returns_true_for_empty_delta(self, entry_mgr, cache):
        """old/new 解析后均为空：本就无需变更，返回 True（非「放弃」）。"""
        self._populate(entry_mgr, cache)
        assert cache.apply_tag_delta("  ,  ", "") is True

    def test_applied_delta_advances_invalidate_version(self, entry_mgr, cache):
        """应用差分推进 _invalidate_version（QL-069）：在飞 get_all_tags 聚合的
        回填守卫据此拒收不含本次变更的旧快照（否则旧快照覆盖已差分的缓存）。"""
        self._populate(entry_mgr, cache)
        before = cache.invalidate_version
        assert cache.apply_tag_delta("", "新标签") is True
        assert cache.invalidate_version == before + 1
        # 空差分（未触碰缓存）不推进
        before = cache.invalidate_version
        assert cache.apply_tag_delta("", "  ") is True
        assert cache.invalidate_version == before


class TestDecryptTagsForDelta:
    """decrypt_tags_for_delta 的失败语义（QL-066）：None=解密失败，''=合法空。"""

    def test_returns_empty_for_blank_ciphertext(self, cache):
        """无 tags 密文（空串）是合法端点：返回 ''（差分 no-op），非 None。"""
        assert cache.decrypt_tags_for_delta("cid-x", "") == ""

    def test_returns_none_for_corrupted_ciphertext(self, entry_mgr, cache):
        """tags 密文损坏（GCM 认证失败）：返回 None 哨兵，供调用方保守整表失效。"""
        entry_mgr.add_entry(Entry(title="A", username="u", password="p", tags="标签"))
        raw = entry_mgr.db.get_entries(EntryQuery())[0]
        # 直改 tags 密文为非法载荷（不重签）：GCM 认证必然失败
        conn = entry_mgr.db._conn
        conn.execute("UPDATE entries SET tags_enc=? WHERE id=?", ("cb2:garbage", raw.id))
        conn.commit()

        assert cache.decrypt_tags_for_delta(raw.crypto_id, "cb2:garbage") is None

    def test_aggregate_view_falls_back_to_empty(self, entry_mgr, cache):
        """聚合口径（_decrypt_tags_by_crypto_id）对损坏 tags 回退空串不贡献计数。"""
        entry_mgr.add_entry(Entry(title="A", username="u", password="p", tags="标签"))
        raw = entry_mgr.db.get_entries(EntryQuery())[0]
        assert cache._decrypt_tags_by_crypto_id(raw.crypto_id, "cb2:garbage") == ""

    def test_warm_cache_hit_distinguishes_failure_from_empty(self, entry_mgr, cache, monkeypatch):
        """暖缓存复用（PERF-020）经 _search_metadata_failed 区分失败与合法空（QL-066）。

        摘要缓存的 tags 为「失败回退空串」形态：命中暖缓存时若该字段在失败集
        中须返回 None（差分保守），否则返回缓存 tags（合法值，含合法空串）。
        """
        entry_mgr.add_entry(Entry(title="A", username="u", password="p", tags="工作"))

        real_decrypt = entry_cache_module._decrypt_field_impl

        def _failing_tags_decrypt(encrypted, key, crypto_id, field_name, *, strict):
            if field_name == "tags":
                raise DecryptionError("GCM 认证失败（模拟）")
            return real_decrypt(encrypted, key, crypto_id, field_name, strict=strict)

        monkeypatch.setattr(entry_cache_module, "_decrypt_field_impl", _failing_tags_decrypt)
        # 列表路径填充摘要缓存：tags 解密失败回退空串并记入 failed 集
        raw = entry_mgr.db.get_entries(EntryQuery())[0]
        meta = cache.cached_search_metadata_full(raw)
        assert meta.tags == ""
        assert "tags" in cache.get_failed_fields(raw.crypto_id)

        # 暖缓存命中：failed 集含 tags → None（而非把回退空串误当合法空）
        assert cache.decrypt_tags_for_delta(raw.crypto_id, raw.tags) is None


class TestInvalidateAll:
    """invalidate_all 清空全部多级缓存。"""

    def test_clears_all_caches(self, entry_mgr, cache):
        entry_mgr.add_entry(Entry(title="A", username="u", password="p"))
        raw = entry_mgr.db.get_entries(EntryQuery())[0]
        cache.cached_search_metadata(raw)
        cache.store_totp(1, "S")
        cache.invalidate_all()
        assert len(cache._search_metadata_cache) == 0
        assert len(cache._totp_secret_cache) == 0


class TestLruEviction:
    """搜索摘要缓存超容量时 LRU 驱逐最旧条目。"""

    def test_evicts_oldest_beyond_capacity(self, entry_mgr, cache, monkeypatch):
        # 缩小缓存上限，避免构造 2000 条目
        monkeypatch.setattr(entry_cache_module, "_MAX_SEARCH_METADATA_CACHE_SIZE", 2)
        for i in range(3):
            entry_mgr.add_entry(Entry(title=f"T{i}", username="u", password="p"))
        for raw in entry_mgr.db.get_entries(EntryQuery()):
            cache.cached_search_metadata(raw)
        # 上限 2，加入第 3 条后应驱逐最旧的一条
        assert len(cache._search_metadata_cache) <= 2


class TestEntryManagerFineGrainedInvalidation:
    """守护 EntryManager 增删/软删除/恢复的精细缓存失效（clear_summaries=False）。

    这三类操作不改变**其他条目**的 title/username/url/tags 摘要内容，不应触发
    全量清空（整库摘要重解密）。增删改走 crypto_id 单条增量（PERF-079）后，被删
    条目自身的摘要会经单条 pop 失效（下次访问重新解密一条），其余条目保留——
    防止未来误改回 notify()（默认 clear_summaries=True 全清）。
    """

    def test_delete_preserves_other_summaries(self, entry_mgr, cache):
        """软删除一条仅 pop 该条摘要，其他条目的摘要缓存保留。"""
        entry_mgr.add_entry(Entry(title="A", username="u", password="p"))
        entry_mgr.add_entry(Entry(title="B", username="u", password="p"))
        raws = entry_mgr.db.get_entries(EntryQuery())
        for raw in raws:
            cache.cached_search_metadata(raw)
        assert len(cache._search_metadata_cache) == 2
        entry_mgr.delete_entry(raws[0].id)
        # 单条增量通知（PERF-079）：被删条目自身摘要 pop，B 的摘要保留
        assert raws[0].crypto_id not in cache._search_metadata_cache
        assert raws[1].crypto_id in cache._search_metadata_cache

    def test_restore_preserves_other_summaries(self, entry_mgr, cache):
        """恢复一条不清空其他条目的摘要缓存（恢复通知的 crypto_id 单条 pop 为 no-op）。"""
        entry_mgr.add_entry(Entry(title="A", username="u", password="p"))
        entry_mgr.add_entry(Entry(title="B", username="u", password="p"))
        raws = entry_mgr.db.get_entries(EntryQuery())
        for raw in raws:
            cache.cached_search_metadata(raw)
        entry_mgr.delete_entry(raws[0].id)
        assert raws[0].crypto_id not in cache._search_metadata_cache
        entry_mgr.restore_entry(raws[0].id)
        # 恢复不触发全清：B 保留（A 已在删除时 pop，重新访问时自然重填）
        assert raws[1].crypto_id in cache._search_metadata_cache
        assert len(cache._search_metadata_cache) == 1

    def test_add_preserves_existing_summaries(self, entry_mgr, cache):
        """新增条目不应清空既有条目的摘要缓存（新条目摘要自然填充）。"""
        entry_mgr.add_entry(Entry(title="A", username="u", password="p"))
        raw_a = entry_mgr.db.get_entries(EntryQuery())[0]
        cache.cached_search_metadata(raw_a)
        assert len(cache._search_metadata_cache) == 1
        entry_mgr.add_entry(Entry(title="B", username="u", password="p"))
        # 新增 B 后 A 的摘要仍保留
        assert raw_a.crypto_id in cache._search_metadata_cache
