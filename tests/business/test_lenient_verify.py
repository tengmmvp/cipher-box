"""宽松完整性校验测试，验证列表操作容忍损坏条目。

覆盖 get_entries 的宽容模式与 get_entry 的严格模式差异：
列表查询遇到元数据签名校验失败的条目时标记 integrity_error 而非抛异常，
单条查询仍抛出异常；同时验证宽容模式通过参数传递而非实例状态。
"""

import pytest

from src.exceptions import VaultIntegrityError
from src.models import Entry, RawEntry
from tests.helpers import make_entry_manager, make_vault


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
