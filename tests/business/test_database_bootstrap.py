"""DatabaseBootstrap 装配测试：db + signer 创建与完整性 handler 注入 wiring。

bootstrap 的核心职责是把 ``MetadataSigner.sign/verify`` 注入 DatabaseManager
（条目与分类两组 handler）——漏注入任一组会使对应表的元数据篡改检测整体失效
（静默读出被篡改数据）。此处经行为方式守护：签名后的正常读回不抛、直接 SQL
篡改密文列后读取被拒。
"""

import os
import sqlite3

import pytest

from src.business.services.database_bootstrap import DatabaseBootstrap
from src.exceptions import VaultIntegrityError
from src.models import RawEntry
from tests.helpers import make_test_config


@pytest.fixture
def bootstrapped(tmp_path):
    """bootstrap 装配的 (db, signer)，打开并建表、设置域密钥。"""
    db, signer = DatabaseBootstrap.bootstrap(make_test_config(tmp_path), test_mode=True)
    db.open()
    db.init_tables()
    signer.set_domain_key(os.urandom(32))
    yield db, signer, tmp_path
    db.close()


class TestBootstrapAssembly:
    """bootstrap 返回物与 handler 注入。"""

    def test_returns_db_and_signer(self, bootstrapped):
        """bootstrap 返回 (DatabaseManager, MetadataSigner) 二元组。"""
        from src.business.services.metadata_signer import MetadataSigner
        from src.database.db_manager import DatabaseManager

        db, signer, _ = bootstrapped
        assert isinstance(db, DatabaseManager)
        assert isinstance(signer, MetadataSigner)

    def test_entry_sign_verify_roundtrip(self, bootstrapped):
        """经 bootstrap 注入的条目 handler：写入自动签名、读回验签通过。"""
        db, _signer, _ = bootstrapped
        raw = RawEntry(title="t", username="u", password="p", notes="", custom_fields="")
        entry_id = db.add_entry(raw)

        read = db.get_entry(entry_id)

        assert read is not None
        assert read.title == "t"

    def test_entry_ciphertext_tamper_rejected_via_wired_verifier(self, bootstrapped):
        """篡改条目密文列后读取被注入的验签 handler 拒绝（条目侧 wiring 守护）。"""
        db, _signer, tmp_path = bootstrapped
        entry_id = db.add_entry(
            RawEntry(title="orig", username="u", password="p", notes="", custom_fields="")
        )
        conn = sqlite3.connect(tmp_path / "vault.db")
        conn.execute("UPDATE entries SET title_enc='Tampered' WHERE id=?", (entry_id,))
        conn.commit()
        conn.close()

        with pytest.raises(VaultIntegrityError):
            db.get_entry(entry_id)

    def test_category_handler_wired_detects_tamper(self, bootstrapped):
        """篡改分类非密文元数据后读取被验签 handler 标记（分类侧 wiring 守护）。

        分类列表读为 LENIENT 形态：篡改行以 ``integrity_error=True`` 标记暴露
        （记 warning 日志）而非抛异常。篡改 color（非加密元数据）隔离验签失败，
        排除 GCM 解密失败的干扰路径。
        """
        from src.models import Category

        db, _signer, tmp_path = bootstrapped
        db.add_category(Category(name="cb2:encrypted-name", icon_char="[X]", color="#000000"))
        conn = sqlite3.connect(tmp_path / "vault.db")
        conn.execute(
            "UPDATE categories SET color='#FFFFFF' WHERE id=(SELECT MAX(id) FROM categories)"
        )
        conn.commit()
        conn.close()

        categories = db.get_categories()

        assert any(c.integrity_error for c in categories)

    def test_db_uses_config_db_path(self, bootstrapped):
        """db 落在 config.db_path（bootstrap 从 config 取路径）。"""
        db, _signer, tmp_path = bootstrapped
        assert (tmp_path / "vault.db").exists()
