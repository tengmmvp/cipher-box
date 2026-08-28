"""CSV 注入防护测试。

验证 csv_safe 对公式注入前缀的转义，
确保 CSV 公式注入仅在导出写入路径处理；以及密钥类列（password/totp_secret）
不转义、导入侧不 strip 的密钥保真决策（SEC-039）。
"""

import csv

from src.business.managers.exporters import csv_safe
from src.business.managers.import_export import ImportExportManager
from src.models import Entry


class TestCsvSafe:
    """csv_safe 转义防护测试。"""

    def test_formula_prefix_equals(self):
        """以 = 开头的值应被单引号前缀转义。"""
        result = csv_safe("=CMD")
        assert result == "'=CMD"

    def test_formula_prefix_plus(self):
        """以 + 开头的值应被单引号前缀转义。"""
        result = csv_safe("+CMD")
        assert result == "'+CMD"

    def test_formula_prefix_minus(self):
        """以 - 开头的值应被单引号前缀转义。"""
        result = csv_safe("-CMD")
        assert result == "'-CMD"

    def test_formula_prefix_at(self):
        """以 @ 开头的值应被单引号前缀转义。"""
        result = csv_safe("@SUM")
        assert result == "'@SUM"

    def test_normal_text_unchanged(self):
        """普通文本不应被修改。"""
        assert csv_safe("hello") == "hello"
        assert csv_safe("user@example.com") == "user@example.com"
        assert csv_safe("1+2=3") == "1+2=3"

    def test_none_returns_empty(self):
        """None 应返回空字符串。"""
        assert csv_safe(None) == ""

    def test_empty_string_unchanged(self):
        """空字符串不变。"""
        assert csv_safe("") == ""

    def test_non_string_converted(self):
        """非字符串值应先转为字符串。"""
        assert csv_safe(42) == "42"
        assert csv_safe(3.14) == "3.14"


class TestCsvSafeSecretColumns:
    """密钥类列跳过公式前缀转义（SEC-039），换行替换仍执行。"""

    def test_escape_formula_false_keeps_prefix_verbatim(self):
        """escape_formula=False 时以 =/+/-/@ 开头的值原样返回（密钥不转义）。"""
        for value in ("=J6f*kL", "+K3yn", "-topsecret", "@token"):
            assert csv_safe(value, escape_formula=False) == value

    def test_escape_formula_false_still_replaces_newlines(self):
        """escape_formula=False 仍替换换行符（保 CSV 行结构），仅跳过前缀转义。"""
        assert csv_safe("a\nb", escape_formula=False) == "a b"
        assert csv_safe("a\r\nb", escape_formula=False) == "a b"
        assert csv_safe("a\rb", escape_formula=False) == "a b"


class TestCsvSecretRoundtrip:
    """CSV 导出→导入的密钥保真往返（SEC-039）：password/totp_secret 不被转义破坏。"""

    def test_export_keeps_secret_columns_verbatim_and_escapes_title(self, entry_mgr, tmp_path):
        """以 =/+/-/@ 开头的密码/TOTP 导出后原样落 CSV，title 列仍被转义。"""

        entry_mgr.add_entry(
            Entry(
                title="=危险标题",
                username="alice",
                password="=J6f*kL",
                totp_secret="JBSWY3DPEHPK3PXP",
            )
        )
        csv_path = tmp_path / "export.csv"
        ImportExportManager(entry_mgr).export_to_csv(
            str(csv_path), entry_mgr.get_entries(), include_password=True
        )

        with csv_path.open(encoding="utf-8-sig", newline="") as f:
            row = next(csv.DictReader(f))
        # 密钥类列原样（SEC-039）：无 ' 前缀，用户从 CSV 复制得到正确秘密
        assert row["password"] == "=J6f*kL"
        assert row["totp_secret"] == "JBSWY3DPEHPK3PXP"
        # 外流文本列仍被转义（SEC-008 对称的纵深防御）
        assert row["title"] == "'=危险标题"

    def test_export_import_roundtrip_preserves_formula_password(self, entry_mgr, tmp_path):
        """含危险前缀密码经 CSV 导出→导入往返后不变（不静默损坏）。"""

        mgr = ImportExportManager(entry_mgr)
        entry_mgr.add_entry(Entry(title="公式密码条目", username="alice", password="=J6f*kL"))
        csv_path = tmp_path / "roundtrip.csv"
        mgr.export_to_csv(str(csv_path), entry_mgr.get_entries(), include_password=True)

        count = mgr.import_file(str(csv_path), "csv", duplicate_action="overwrite")
        assert count == 1
        restored = entry_mgr.get_entries()[0]
        assert restored.password == "=J6f*kL"

    def test_import_keeps_whitespace_password_verbatim(self, entry_mgr, tmp_path):
        """CSV 导入的 password 列不 strip：首尾空白是密码的一部分（SEC-039）。"""

        mgr = ImportExportManager(entry_mgr)
        csv_path = tmp_path / "ws.csv"
        csv_path.write_text(
            'title,username,password\n带空白密码,alice,"  spaced Pass!  "\n',
            encoding="utf-8",
        )
        assert mgr.import_file(str(csv_path), "csv") == 1
        assert entry_mgr.get_entries()[0].password == "  spaced Pass!  "
