"""宽松完整性校验测试，验证列表操作容忍损坏条目。

覆盖 get_entries 的宽容模式与 get_entry 的严格模式差异：
列表查询遇到元数据签名校验失败的条目时标记 integrity_error 而非抛异常，
单条查询仍抛出异常；同时验证宽容模式通过参数传递而非实例状态。
"""

import pytest

from src.exceptions import VaultIntegrityError
from src.models import Entry, RawEntry
from tests.helpers import make_entry_manager, make_vault  # noqa: F401 复用既有装配 helper


class TestLenientVerify:
    """验证 get_entries 宽容模式与 get_entry 严格模式的差异。"""

    @pytest.fixture(autouse=True)
    def setup_vault(self, vault_config):
        self._vault = make_vault(vault_config)
        self._vault.initialize("test_password_12345")
        self._entry_mgr = make_entry_manager(self._vault)
        yield
        self._vault.close()

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
        decrypted = self._entry_mgr.get_entries()
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
        entry_id = self._entry_mgr.get_entries()[0].id
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

        entries = self._entry_mgr.get_entries()
        entry_id = entries[0].id
        assert entry_id is not None

        with pytest.raises(VaultIntegrityError):
            self._vault.db.get_entry(entry_id)

    def test_lenient_mode_is_parameter_not_instance_state(self):
        """宽松验证通过参数传递，不存储在实例变量上。"""
        assert not hasattr(self._vault.db, "_lenient_verify")


class TestSearchPathReverify:
    """搜索路径的 SKIP 拉取 + 命中行 LENIENT 补验签（PERF-019）。

    搜索 fetch 改 VerifyMode.SKIP（省全部行逐行 HMAC 验签），完整性标记改为对
    匹配命中且将渲染的行经 get_entries_by_ids 补验签。守护两点：命中行仍被验签
    （篡改行在结果中带 integrity_error，不抛异常），过滤语义与全量路径一致。
    """

    @pytest.fixture(autouse=True)
    def setup_vault(self, vault_config):
        self._vault = make_vault(vault_config)
        self._vault.initialize("test_password_12345")
        self._entry_mgr = make_entry_manager(self._vault)
        self._entry_mgr.add_entry(
            Entry(title="GitHub 首页", username="alice", password="pass1", entry_type="login")
        )
        self._entry_mgr.add_entry(
            Entry(title="GitLab 备用", username="bob", password="pass2", entry_type="login")
        )
        self._entry_mgr.add_entry(
            Entry(title="邮箱", username="carol", password="pass3", entry_type="login")
        )
        yield
        self._vault.close()

    def test_search_matched_rows_still_verified(self):
        """搜索命中的行经补验签：篡改行在结果中带 integrity_error 而非抛异常。"""

        def bad_verifier(entry: RawEntry):
            raise VaultIntegrityError("元数据签名不匹配")

        self._vault.db._entry_verifier = bad_verifier

        # SKIP 拉取阶段不验签（否则此处直接全量标记）；补验签仅覆盖命中行
        results = self._entry_mgr.get_entry_summaries(search="git")
        # GitHub 首页 / GitLab 备用 命中（title 小写含 "git"），均应带完整性警示
        assert {r.title for r in results} == {"GitHub 首页", "GitLab 备用"}
        assert all(r.integrity_error is True for r in results)

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
        """无命中时不做补验签也不抛异常（未命中行的篡改检测由全量列表刷新覆盖）。"""

        def bad_verifier(entry: RawEntry):
            raise VaultIntegrityError("元数据签名不匹配")

        self._vault.db._entry_verifier = bad_verifier
        assert self._entry_mgr.get_entry_summaries(search="不存在的关键词") == []

    def test_search_ciphertext_corruption_marks_integrity(self):
        """搜索命中行的密文损坏（GCM 失败）仍计入完整性警示。"""
        # 按 username 定位目标行（updated_at 同刻创建时 get_entries()[0] 顺序不定）
        entry_id = next(
            e.id for e in self._entry_mgr.get_entries() if e.username == "alice"
        )
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
