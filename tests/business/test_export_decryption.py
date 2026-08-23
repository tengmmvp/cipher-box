"""导出严格解密链路测试：get_entries_for_export / decrypt_entry_for_export。

守护导出路径两个数据完整性保证的唯一执行点：

1. 「任一字段密文损坏立即抛 DecryptionError 拒绝整次导出」——区别于详情/列表
   路径的容错汇总（失败字段置空 + integrity_message），导出路径不允许把损坏
   数据静默写成空字段的部分导出；
2. 「include_secrets=False 不解密 password/totp_secret」——用损坏的 password
   密文 + include_secrets=False 仍能成功导出，反证该分支确实跳过了解密。

测试面向公开 API（get_entries_for_export / decrypt_entry_for_export），经真实
vault 全链路（Argon2id 派生 → AES-256-GCM → SQLite）验证，不 mock
EncryptionEngine；密文损坏经篡改 base64 字符后回写 DB 模拟磁盘位翻转。
"""

import dataclasses

import pytest

from src.exceptions import DecryptionError
from src.models import CIPHERTEXT_PREFIX, CustomField


def _tamper_cipher(cipher: str) -> str:
    """篡改密文中段一个 base64 字符（换成不同的合法 base64 字符）。

    保持 ``cb2:`` 前缀与合法 base64 字符集，仅改变解码后的密文字节，使 GCM
    认证必然失败（strict 解密抛 DecryptionError），模拟磁盘损坏/外部篡改。
    """
    body = cipher[len(CIPHERTEXT_PREFIX) :]
    idx = len(body) // 2
    flipped = "A" if body[idx] != "A" else "B"
    return CIPHERTEXT_PREFIX + body[:idx] + flipped + body[idx + 1 :]


def _corrupt_field(entry_mgr, entry_id: int, field: str) -> None:
    """把库内指定条目的指定加密字段密文篡改为损坏态（回写 DB）。"""
    raw = entry_mgr.db.get_entry(entry_id)
    assert raw is not None
    tampered = _tamper_cipher(getattr(raw, field))
    raw = dataclasses.replace(raw, **{field: tampered})
    entry_mgr.db.update_entry(raw)


class TestExportNormalPath:
    """正常导出：include_secrets 两档的字段解密行为。"""

    def test_export_with_secrets_decrypts_all_fields(self, entry_mgr, make_entry):
        """include_secrets=True 解出全部字段（含 password/totp/custom_fields 明文）。"""
        entry_mgr.add_entry(
            make_entry(
                title="GitHub",
                username="alice@example.com",
                password="S3cret-Pass-2024!",
                url="https://github.com",
                notes="备注内容",
                tags="work,dev",
                totp_secret="JBSWY3DPEHPK3PXP",
                custom_fields=[CustomField(name="recover", value="code-123")],
            )
        )

        entries = entry_mgr.get_entries_for_export(include_secrets=True)

        assert len(entries) == 1
        exported = entries[0]
        assert exported.title == "GitHub"
        assert exported.username == "alice@example.com"
        assert exported.password == "S3cret-Pass-2024!"
        assert exported.url == "https://github.com"
        assert exported.notes == "备注内容"
        assert exported.tags == "work,dev"
        assert exported.totp_secret == "JBSWY3DPEHPK3PXP"
        # 自定义字段解密为明文列表
        assert len(exported.custom_fields) == 1
        assert exported.custom_fields[0].name == "recover"
        assert exported.custom_fields[0].value == "code-123"
        # 导出路径正常条目不标记完整性错误
        assert exported.integrity_error is False

    def test_export_without_secrets_leaves_password_and_totp_empty(
        self, entry_mgr, make_entry
    ):
        """include_secrets=False 时 password/totp_secret 为空，其余字段正常解密。"""
        entry_mgr.add_entry(
            make_entry(
                title="GitHub",
                username="alice@example.com",
                password="S3cret-Pass-2024!",
                totp_secret="JBSWY3DPEHPK3PXP",
            )
        )

        entries = entry_mgr.get_entries_for_export(include_secrets=False)

        assert len(entries) == 1
        exported = entries[0]
        assert exported.title == "GitHub"
        assert exported.username == "alice@example.com"
        assert exported.password == ""
        assert exported.totp_secret == ""

    def test_export_defaults_to_no_secrets(self, entry_mgr, make_entry):
        """get_entries_for_export 默认（不传参）不含密码，安全默认。"""
        entry_mgr.add_entry(make_entry(password="Default-Check-123!"))

        exported = entry_mgr.get_entries_for_export()[0]

        assert exported.password == ""

    def test_empty_vault_returns_empty_list(self, entry_mgr):
        """空库导出返回空列表，不抛异常。"""
        assert entry_mgr.get_entries_for_export(include_secrets=True) == []

    def test_empty_optional_fields_export_cleanly(self, entry_mgr, make_entry):
        """空字符串可选字段（url/notes/tags/totp/custom_fields）正常导出。"""
        entry_mgr.add_entry(
            make_entry(title="最小条目", username="", password="", url="", notes="", tags="")
        )

        entries = entry_mgr.get_entries_for_export(include_secrets=True)

        assert len(entries) == 1
        exported = entries[0]
        assert exported.title == "最小条目"
        assert exported.url == ""
        assert exported.notes == ""
        assert exported.tags == ""
        assert exported.totp_secret == ""
        assert exported.custom_fields == []

    def test_trash_entries_excluded_from_export(self, entry_mgr, make_entry):
        """软删除（回收站）条目不进入导出结果。"""
        keep_id = entry_mgr.add_entry(make_entry(title="保留"))
        trash_id = entry_mgr.add_entry(make_entry(title="已删除"))
        entry_mgr.delete_entry(trash_id)

        entries = entry_mgr.get_entries_for_export(include_secrets=True)

        assert [e.id for e in entries] == [keep_id]
        assert entries[0].title == "保留"


class TestExportRejectsCorruptedData:
    """任一字段密文损坏 → DecryptionError 拒绝整次导出。"""

    @pytest.mark.parametrize(
        "field",
        ["title", "username", "url", "notes", "tags"],
    )
    def test_corrupted_summary_field_rejects_export(self, entry_mgr, make_entry, field):
        """非敏感摘要字段（始终解密）密文损坏 → 抛 DecryptionError。"""
        entry_id = entry_mgr.add_entry(make_entry(title="损坏条目"))
        _corrupt_field(entry_mgr, entry_id, field)

        with pytest.raises(DecryptionError):
            entry_mgr.get_entries_for_export(include_secrets=False)

    def test_corrupted_password_rejects_secret_export(self, entry_mgr, make_entry):
        """password 密文损坏 + include_secrets=True → 拒绝导出。"""
        entry_id = entry_mgr.add_entry(make_entry(password="Secret-123!"))

        _corrupt_field(entry_mgr, entry_id, "password")

        with pytest.raises(DecryptionError):
            entry_mgr.get_entries_for_export(include_secrets=True)

    def test_corrupted_totp_rejects_secret_export(self, entry_mgr, make_entry):
        """totp_secret 密文损坏 + include_secrets=True → 拒绝导出。"""
        entry_id = entry_mgr.add_entry(make_entry(totp_secret="JBSWY3DPEHPK3PXP"))

        _corrupt_field(entry_mgr, entry_id, "totp_secret")

        with pytest.raises(DecryptionError):
            entry_mgr.get_entries_for_export(include_secrets=True)

    def test_corrupted_custom_fields_rejects_export(self, entry_mgr, make_entry):
        """custom_fields 密文损坏 → 拒绝导出（无论 include_secrets）。"""
        entry_id = entry_mgr.add_entry(
            make_entry(custom_fields=[CustomField(name="k", value="v")])
        )

        _corrupt_field(entry_mgr, entry_id, "custom_fields")

        with pytest.raises(DecryptionError):
            entry_mgr.get_entries_for_export(include_secrets=False)

    def test_one_corrupted_entry_fails_entire_export(self, entry_mgr, make_entry):
        """多条目中一条损坏 → 整次导出失败（不是跳过损坏条目的部分导出）。"""
        entry_mgr.add_entry(make_entry(title="正常条目A"))
        bad_id = entry_mgr.add_entry(make_entry(title="损坏条目B"))
        entry_mgr.add_entry(make_entry(title="正常条目C"))
        _corrupt_field(entry_mgr, bad_id, "notes")

        with pytest.raises(DecryptionError):
            entry_mgr.get_entries_for_export(include_secrets=True)


class TestExportSkipsSecretDecryption:
    """include_secrets=False 不解密 password/totp_secret 的反证。"""

    def test_corrupted_password_still_exports_without_secrets(self, entry_mgr, make_entry):
        """损坏的 password 密文不阻断不含密码导出——证明该分支未解密 password。"""
        entry_id = entry_mgr.add_entry(
            make_entry(title="密码损坏", username="user1", password="Secret-123!")
        )
        _corrupt_field(entry_mgr, entry_id, "password")

        entries = entry_mgr.get_entries_for_export(include_secrets=False)

        assert len(entries) == 1
        exported = entries[0]
        assert exported.title == "密码损坏"
        assert exported.username == "user1"
        assert exported.password == ""

    def test_corrupted_totp_still_exports_without_secrets(self, entry_mgr, make_entry):
        """损坏的 totp_secret 密文不阻断不含密码导出——证明该分支未解密 totp。"""
        entry_id = entry_mgr.add_entry(
            make_entry(title="TOTP损坏", totp_secret="JBSWY3DPEHPK3PXP")
        )
        _corrupt_field(entry_mgr, entry_id, "totp_secret")

        entries = entry_mgr.get_entries_for_export(include_secrets=False)

        assert len(entries) == 1
        assert entries[0].totp_secret == ""


class TestDecryptEntryForExport:
    """decrypt_entry_for_export 公开 API 直接验证。"""

    def test_decrypt_entry_for_export_roundtrip(self, entry_mgr, make_entry):
        """对库内 raw 条目直接解密导出，往返一致。"""
        entry_id = entry_mgr.add_entry(
            make_entry(title="直解", password="Direct-123!")
        )
        raw = entry_mgr.db.get_entry(entry_id)
        assert raw is not None

        entry = entry_mgr.decrypt_entry_for_export(raw, include_secrets=True)

        assert entry.title == "直解"
        assert entry.password == "Direct-123!"

    def test_decrypt_entry_for_export_defaults_to_no_secrets(self, entry_mgr, make_entry):
        """decrypt_entry_for_export 默认 include_secrets=False（安全默认）。"""
        entry_id = entry_mgr.add_entry(make_entry(password="Default-123!"))
        raw = entry_mgr.db.get_entry(entry_id)
        assert raw is not None

        entry = entry_mgr.decrypt_entry_for_export(raw)

        assert entry.password == ""

    def test_decrypt_entry_for_export_raises_on_corruption(self, entry_mgr, make_entry):
        """decrypt_entry_for_export 任一字段损坏立即抛 DecryptionError。"""
        entry_id = entry_mgr.add_entry(make_entry(title="x"))
        _corrupt_field(entry_mgr, entry_id, "title")
        raw = entry_mgr.db.get_entry(entry_id)
        assert raw is not None

        with pytest.raises(DecryptionError):
            entry_mgr.decrypt_entry_for_export(raw, include_secrets=False)
