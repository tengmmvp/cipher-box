"""宽松完整性校验测试，验证列表操作容忍损坏条目。

覆盖 get_entries 的宽容模式与 get_entry 的严格模式差异：
列表查询遇到元数据签名校验失败的条目时标记 integrity_error 而非抛异常，
单条查询仍抛出异常；同时验证宽容模式通过参数传递而非实例状态。
"""

import pytest

from src.exceptions import VaultIntegrityError
from src.models import Entry, RawEntry
from tests.helpers import decrypt_all_entries


class TestLenientVerify:
    """验证 get_entries 宽容模式与 get_entry 严格模式的差异。"""

    @pytest.fixture(autouse=True)
    def setup_vault(self, make_vault_env):
        env = make_vault_env()
        self._vault = env.vault
        self._entry_mgr = env.entry_mgr

    def test_get_entries_lenient_marks_integrity_error(self):
        """列表摘要路径与全量 get_entries 均 LENIENT，签名失败标记 integrity_error。

        列表/搜索/近期更新路径统一用 LENIENT 逐行 HMAC 验签（不抛异常），使列表
        能检测非加密元数据篡改并展示完整性警示；单条详情用 STRICT 抛异常。
        """
        self._entry_mgr.add_entry(
            Entry(
                title="正常条目",
                username="user",
                password="pass",
                entry_type="login",
            )
        )

        def bad_verifier(entry: RawEntry):
            raise VaultIntegrityError("元数据签名不匹配")

        self._vault.db._entry_verifier = bad_verifier

        # 列表摘要路径 LENIENT 验签：签名层篡改在列表标记 integrity_error
        summaries = self._entry_mgr.get_entry_summaries()
        assert len(summaries) == 1
        assert summaries[0].integrity_error is True

        # 全量 get_entries 同样 LENIENT：签名失败标记 integrity_error
        decrypted = decrypt_all_entries(self._entry_mgr)
        assert decrypted[0].integrity_error is True
        assert "完整性" in decrypted[0].integrity_message

    def test_summary_marks_decryption_corruption(self):
        """列表摘要路径在密文损坏时标记 integrity_error。

        密文损坏（GCM 认证失败）被两层机制捕获：LENIENT 逐行验签因 title 密文与
        metadata_mac 不匹配而标记，且 _cached_search_metadata_no_check 的 strict 解密失败
        计入 failed 集合，二者都反映到 integrity_error，使列表能提示损坏条目。
        """
        self._entry_mgr.add_entry(
            Entry(
                title="正常条目",
                username="user",
                password="pass",
                entry_type="login",
            )
        )
        entry_id = decrypt_all_entries(self._entry_mgr)[0].id
        assert entry_id is not None
        # 直接 SQL 写入「合法 cb2: 前缀但 GCM 标签必然失败」的密文，绕过
        # add_entry 的正常加密，模拟密文损坏。
        conn = self._vault.db._conn
        assert conn is not None
        conn.execute(
            "UPDATE entries SET title_enc=? WHERE id=?",
            ("cb2:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", entry_id),
        )
        conn.commit()
        summaries = self._entry_mgr.get_entry_summaries()
        assert summaries[0].integrity_error is True

    def test_get_entry_with_bad_verifier_raises(self):
        """单条 get_entry 在验证失败时仍抛异常。"""
        self._entry_mgr.add_entry(
            Entry(
                title="测试条目",
                username="user",
                password="pass",
                entry_type="login",
            )
        )

        def bad_verifier(entry: RawEntry):
            raise VaultIntegrityError("元数据签名不匹配")

        self._vault.db._entry_verifier = bad_verifier

        entries = decrypt_all_entries(self._entry_mgr)
        entry_id = entries[0].id
        assert entry_id is not None

        with pytest.raises(VaultIntegrityError):
            self._vault.db.get_entry(entry_id)

    def test_lenient_mode_is_parameter_not_instance_state(self):
        """宽松验证通过参数传递，不存储在实例变量上。"""
        assert not hasattr(self._vault.db, "_lenient_verify")


class TestSearchPathReverify:
    """搜索路径的窄投影拉取 + 命中行回查 LENIENT 验签（PERF-019/074）。

    搜索拉取改窄投影（仅 4 摘要密文字段 + id，免宽行 24 字段物化），完整性标记由
    命中行按 id 经 get_entries_by_ids（LENIENT，db 层 _row_to_entry 验签）回查完整
    行时补偿（PERF-074：替代 PERF-067 的就地验签——窄投影后宽行不再物化，回查是
    摘要构建的必要步骤而非重复读库）。篡改一律以真实 SQL 改写非加密元数据
    （password_strength 入签载荷，改动即 mac 失配）模拟。守护三点：命中行仍被验签
    （篡改行在结果中带 integrity_error，不抛异常）、回查仅覆盖命中 id 集、
    过滤语义与全量路径一致。
    """

    @pytest.fixture(autouse=True)
    def setup_vault(self, make_vault_env):
        env = make_vault_env()
        self._vault = env.vault
        self._entry_mgr = env.entry_mgr
        self._entry_mgr.add_entry(
            Entry(title="GitHub 首页", username="alice", password="pass1", entry_type="login")
        )
        self._entry_mgr.add_entry(
            Entry(title="GitLab 备用", username="bob", password="pass2", entry_type="login")
        )
        self._entry_mgr.add_entry(
            Entry(title="邮箱", username="carol", password="pass3", entry_type="login")
        )

    def _tamper_all_rows(self):
        """SQL 改写全部行的非加密元数据（入签载荷），使 metadata_mac 比对必然失配。"""
        conn = self._vault.db._conn
        assert conn is not None
        conn.execute("UPDATE entries SET password_strength = password_strength + 40")
        conn.commit()

    def test_search_matched_rows_still_verified(self):
        """搜索命中的行经就地补验签：篡改行在结果中带 integrity_error 而非抛异常。"""
        self._tamper_all_rows()

        # SKIP 拉取阶段不验签（否则此处直接全量标记）；补验签仅覆盖命中行
        results = self._entry_mgr.get_entry_summaries(search="git")
        # GitHub 首页 / GitLab 备用 命中（title 小写含 "git"），均应带完整性警示
        assert {r.title for r in results} == {"GitHub 首页", "GitLab 备用"}
        assert all(r.integrity_error is True for r in results)
        assert all(r.integrity_message == "元数据完整性校验失败" for r in results)

    def test_search_results_consistent_with_full_list(self):
        """SKIP 后的内存过滤语义与原全量路径一致（同一数据两种路径结果一致）。"""
        full = self._entry_mgr.get_entry_summaries()  # 无搜索词路径（LENIENT）
        searched = self._entry_mgr.get_entry_summaries(search="gi")

        by_title_full = {e.title: e for e in full}
        expected = {t for t in by_title_full if "gi" in t.lower()}
        assert {e.title for e in searched} == expected == {"GitHub 首页", "GitLab 备用"}
        # 命中条目的展示字段与全量路径一致（两路径解密同一密文，无语义漂移）
        for s in searched:
            f = by_title_full[s.title]
            assert s.username == f.username
            assert s.integrity_error == f.integrity_error
            assert s.integrity_message == f.integrity_message

    def test_search_no_match_returns_empty_without_verify(self):
        """无命中时不做回查也不抛异常（未命中行的篡改检测由全量列表刷新覆盖）。

        守护窄投影链路（PERF-074）的「未命中行零回查」：get_entries_by_ids 被替换为
        抛错哨兵，无命中路径若经其重读会立即失败。
        """

        def _forbid_reread(*_args, **_kwargs):
            raise AssertionError("无命中时不应回查完整行")

        self._vault.db.get_entries_by_ids = _forbid_reread  # type: ignore[method-assign]
        assert self._entry_mgr.get_entry_summaries(search="不存在的关键词") == []

    def test_hit_rows_reread_exactly_matched_ids(self):
        """命中行回查（PERF-074）：仅命中 id 集合经 get_entries_by_ids 回读验签。

        窄投影后宽行不再物化，回查是摘要构建与 LENIENT 验签的必要步骤（替代原
        PERF-067 就地验签的「不回查」不变量——该不变量以「宽行已物化」为前提，
        架构变化后退役）。本测试守护新的最小回查面：回查 id 集 == 命中 id 集，
        未命中行（本例 1 条）不产生回查。
        """
        self._tamper_all_rows()
        reread_ids: list[list[int]] = []
        original = self._vault.db.get_entries_by_ids

        def _spy_reread(entry_ids):
            reread_ids.append(list(entry_ids))
            return original(entry_ids)

        self._vault.db.get_entries_by_ids = _spy_reread  # type: ignore[method-assign]
        results = self._entry_mgr.get_entry_summaries(search="git")
        assert len(results) == 2
        assert all(r.integrity_error is True for r in results)
        # 单次回查且 id 集恰为命中行（3 条中 "git" 命中 2 条，邮箱未命中不在集合内）
        assert len(reread_ids) == 1
        assert len(reread_ids[0]) == 2

    def test_in_place_verify_matches_db_reread_path(self):
        """搜索路径与 db 回读（LENIENT）路径的判定结果一致（PERF-067/074）。

        同一批篡改行，搜索结果与 get_entries_by_ids 直读（db 层 verifier 钩子）对
        integrity_error/integrity_message 的结论必须一致——窄投影回查链路与直读
        走同一验签钩子，本测试锚定零语义漂移。
        """
        entry_id = next(e.id for e in decrypt_all_entries(self._entry_mgr) if e.username == "alice")
        assert entry_id is not None
        conn = self._vault.db._conn
        assert conn is not None
        conn.execute("UPDATE entries SET is_favorite = 1 - is_favorite WHERE id=?", (entry_id,))
        conn.commit()

        searched = self._entry_mgr.get_entry_summaries(search="alice")
        assert len(searched) == 1
        # db 层参照路径：get_entries_by_ids 内部走 _row_to_entry 的 LENIENT 验签
        reread = self._vault.db.get_entries_by_ids([entry_id])
        assert len(reread) == 1
        assert searched[0].integrity_error == reread[0].integrity_error is True
        assert searched[0].integrity_message == reread[0].integrity_message

    def test_search_ciphertext_corruption_marks_integrity(self):
        """搜索命中行的密文损坏（GCM 失败）仍计入完整性警示。"""
        # 按 username 定位目标行（updated_at 同刻创建时 get_entries()[0] 顺序不定）
        entry_id = next(e.id for e in decrypt_all_entries(self._entry_mgr) if e.username == "alice")
        assert entry_id is not None
        conn = self._vault.db._conn
        assert conn is not None
        conn.execute(
            "UPDATE entries SET title_enc=? WHERE id=?",
            ("cb2:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", entry_id),
        )
        conn.commit()

        # title 损坏后按 title 搜不中；按 username 搜仍命中该行并标记损坏
        results = self._entry_mgr.get_entry_summaries(search="alice")
        assert len(results) == 1
        assert results[0].integrity_error is True

    def test_search_all_matched_rows_verified_beyond_sql_order_cap(self):
        """命中 >1000 时全部命中行（含 SQL 序 1000 名之外）均经验签（PERF-032）。

        旧实现对 ``matched`` 按 SQL 序取前 1000 补验签，但 UI 在排序字段重排 + 标签
        过滤后才截断渲染——SQL 序 1000 名之外的行可能落入渲染窗口而未验签（仿真
        复现默认排序 67/1000）。修复后对全部命中行验签：本测试构造 1005 条命中并
        全部篡改（SQL 批量改写入签元数据），断言每条渲染结果都带 integrity_error。
        """
        for i in range(1005):
            self._entry_mgr.add_entry(
                Entry(title=f"site{i:04d}", username="u", password="pass1", entry_type="login")
            )
        self._tamper_all_rows()

        results = self._entry_mgr.get_entry_summaries(search="site")
        # 全部 1005 条命中且全部经验签带警示（旧实现仅前 1000 条带警示）
        assert len(results) == 1005
        assert all(r.integrity_error is True for r in results)


class TestInMemorySortPath:
    """内存 meta 排序 + 前 N 回查路径（PERF-078 守护）。

    标题序（密文列不可 SQL 排序）与搜索路径统一走「窄投影全量 → 内存排序
    （title 键在 meta.title_lower，其余键在窄投影明文列）→ 仅前 limit 回查宽行」；
    PERF-074 重写时掉落的搜索分支 data_epoch 透传（SEC-043 漏点）与第二段
    cancel_check 亦在此锚定。
    """

    @pytest.fixture(autouse=True)
    def setup_vault(self, make_vault_env):
        env = make_vault_env()
        self._vault = env.vault
        self._entry_mgr = env.entry_mgr
        # 标题字母序与插入序刻意不同，检验排序真实生效
        for title in ("zebra", "alpha", "middle"):
            self._entry_mgr.add_entry(
                Entry(title=title, username="u", password="pass1", entry_type="login")
            )

    def test_title_order_sorts_by_meta_and_truncates(self):
        """无搜索标题序：按 meta.title_lower 排序后截断，与全量路径排序等价。"""
        results = self._entry_mgr.get_entry_summaries(order_by="title", order_desc=False, limit=2)
        assert [r.title for r in results] == ["alpha", "middle"]

        desc = self._entry_mgr.get_entry_summaries(order_by="title", order_desc=True, limit=2)
        assert [r.title for r in desc] == ["zebra", "middle"]

        # 无 limit 全量：完整字母序（旧行为锁定——内存路径 limit 为 None 时全量回查）
        full = self._entry_mgr.get_entry_summaries(order_by="title", order_desc=False)
        assert [r.title for r in full] == ["alpha", "middle", "zebra"]

    def test_title_order_matches_legacy_full_path(self):
        """标题序新路径与「全量拉取 + entry_sort_key 内存排序」等价（PERF-078 核心声明）。

        对照组复现旧 UI 路径的键语义 ``(e.title or "").lower()``（原
        EntryListController.sort_entries 的实现，已随 QL-074 删除；键函数
        entry_sort_key 与 manager 的 meta.title_lower 同源——同一解密缓存），
        两路径对同一数据的前 N 集合与顺序一致。
        """
        from src.business.services.entry_sorting import entry_sort_key

        legacy_full = self._entry_mgr.get_entry_summaries()
        legacy_sorted = sorted(list(legacy_full), key=entry_sort_key("title"), reverse=True)[:2]

        new_path = self._entry_mgr.get_entry_summaries(order_by="title", order_desc=True, limit=2)
        assert [r.id for r in new_path] == [r.id for r in legacy_sorted]

    def test_search_with_limit_rereads_only_top_n(self):
        """搜索 + limit：回查收口到前 limit 条（PERF-078 悬崖修复）。

        原实现收集全部命中后**全量回查**才出口截断——宽搜索词（命中 20k）时
        836ms 反超旧宽行直拉。现排序后仅回查前 limit；spy 断言回查 id 数 == limit。
        """
        reread_ids: list[list[int]] = []
        original = self._vault.db.get_entries_by_ids

        def _spy_reread(entry_ids):
            reread_ids.append(list(entry_ids))
            return original(entry_ids)

        self._vault.db.get_entries_by_ids = _spy_reread  # type: ignore[method-assign]
        results = self._entry_mgr.get_entry_summaries(search="a", limit=1)
        # "a" 命中全部 3 条标题，limit=1 仅回查/返回排序序第 1 条
        assert len(results) == 1
        assert len(reread_ids) == 1
        assert len(reread_ids[0]) == 1

    def test_reread_missing_row_skipped(self):
        """回查缺失（并发删除）跳过不抛异常（PERF-074 容忍语义锁定）。"""
        self._vault.db.get_entries_by_ids = lambda _ids: []  # type: ignore[method-assign]
        results = self._entry_mgr.get_entry_summaries(search="a")
        assert results == []  # 全部回查缺失 → 尽力视图返回空，不抛异常

    def test_cancel_in_reread_phase_returns_partial(self):
        """回查构建段可取消（PERF-078）：取消后返回已构建部分，不抛异常。"""
        # 第 1 次调用（解密 meta 段）放行，第 2 次（回查构建段首条）取消
        calls = {"n": 0}

        def _cancel_after_first_phase() -> bool:
            calls["n"] += 1
            return calls["n"] > 3  # 3 条解密放行后，第 4 次起取消（回查段循环头）

        results = self._entry_mgr.get_entry_summaries(
            search="a", cancel_check=_cancel_after_first_phase
        )
        # 取消时机在第 4 次探针（回查段第一条之前或之中）——部分或空结果，绝不抛异常
        assert isinstance(results, list)

    def test_search_passes_data_epoch_to_summary(self):
        """搜索分支 decrypt_summary 透传锁内快照世代（PERF-078 修复 PERF-074 回归）。

        PERF-074 重写搜索链时 data_epoch 从 decrypt_summary 调用中掉落——meta 路径
        的 title 等四字段取自 meta 无回写，但分类名解密回写需要世代守卫（SEC-043
        的搜索分支漏点）。锚定：搜索路径与非搜索路径同样传 data_epoch 且值等于
        vault.key_epoch。
        """
        received: list[str | None] = []
        original = self._entry_mgr._view_decryptor.decrypt_summary

        def _spy_summary(raw, **kwargs):
            received.append(kwargs.get("data_epoch"))
            return original(raw, **kwargs)

        self._entry_mgr._view_decryptor.decrypt_summary = _spy_summary  # type: ignore[method-assign]
        self._entry_mgr.get_entry_summaries(search="a")
        assert received, "搜索路径应调用 decrypt_summary"
        assert all(epoch == self._vault.key_epoch for epoch in received)
