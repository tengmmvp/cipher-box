"""EntryManager 核心加密 CRUD 与编排行为测试（真实 vault，不 mock EncryptionEngine）。

覆盖：

1. add_entry：明文加密入库、get_entry 读回解密一致、password_strength 自动计算。
2. update_entry：字段更新读回一致、密码变更归档历史、密码不变不归档。
3. toggle_favorite：仅切换收藏，不改密码/不产生历史。
4. delete_entry（软删除）/ restore_entry / permanent_delete_entry：回收站语义正确。
5. 视图解密下沉（MAINT-021）：公开解密 API 薄委托 EntryViewDecryptor、共用缓存实例。

依赖 conftest 的 ``entry_mgr`` fixture（经 ``vault`` fixture 装配真实 vault 并在
teardown ``v.close()`` 释放 Windows 文件锁；fixture teardown 比逐测试 try/finally
更健壮——断言失败时仍会执行关闭）。
"""

import dataclasses

from src.crypto.password_generator import PasswordGenerator
from src.models import CIPHERTEXT_PREFIX, CustomField


class TestAddEntry:
    """add_entry：明文加密入库、读回解密一致、强度自动计算。"""

    def test_encrypts_and_reads_back_all_fields(self, entry_mgr, make_entry):
        """明文条目加密入库后，get_entry 读回的解密条目与原值一致。"""
        entry = make_entry(
            title="GitHub",
            username="alice@example.com",
            password="S3cret-Pass-2024!",
            url="https://github.com",
            notes="我的备注",
            tags="work,dev",
            entry_type="login",
            custom_fields=[CustomField(name="recover", value="code-123")],
            totp_secret="JBSWY3DPEHPK3PXP",
        )
        entry_id = entry_mgr.add_entry(entry)
        assert isinstance(entry_id, int)

        read = entry_mgr.get_entry(entry_id)
        assert read is not None
        assert read.id == entry_id
        assert read.title == "GitHub"
        assert read.username == "alice@example.com"
        assert read.password == "S3cret-Pass-2024!"
        assert read.url == "https://github.com"
        assert read.notes == "我的备注"
        assert read.tags == "work,dev"
        assert read.entry_type == "login"
        assert read.totp_secret == "JBSWY3DPEHPK3PXP"
        # 自定义字段经 JSON 序列化→加密→解密→反序列化往返一致
        assert len(read.custom_fields) == 1
        assert read.custom_fields[0].name == "recover"
        assert read.custom_fields[0].value == "code-123"

    def test_stores_encrypted_not_plaintext(self, entry_mgr, make_entry):
        """验证敏感字段以密文（cb2: 前缀）入库，而非明文落库。"""
        entry_id = entry_mgr.add_entry(
            make_entry(
                title="SecretTitle",
                password="PlainPass123!",
                notes="top-secret",
            )
        )
        raw = entry_mgr.db.get_entry(entry_id)
        assert raw.title.startswith(CIPHERTEXT_PREFIX)
        assert raw.password.startswith(CIPHERTEXT_PREFIX)
        assert raw.notes.startswith(CIPHERTEXT_PREFIX)
        # 密文不等于明文，确认真实加密而非直写
        assert raw.title != "SecretTitle"
        assert raw.password != "PlainPass123!"
        assert raw.notes != "top-secret"

    def test_password_strength_auto_computed(self, entry_mgr, make_entry):
        """add_entry 依密码自动计算 password_strength，读回值与生成器评分一致。"""
        pwd = "S3cret-Pass-2024!"
        entry = make_entry(password=pwd)
        # 入库前 password_strength 为默认 0
        assert entry.password_strength == 0

        entry_id = entry_mgr.add_entry(entry)
        expected = PasswordGenerator.check_strength(pwd).score
        # frozen：传入 Entry 不被原地修改，password_strength 仍为默认 0
        assert entry.password_strength == 0
        # 读回的解密条目携带 add_entry 计算出的 strength
        read = entry_mgr.get_entry(entry_id)
        assert read.password_strength == expected

    def test_strength_reflects_password_quality(self, entry_mgr, make_entry):
        """强密码的强度评分高于弱密码，确认 strength 随密码质量变化。"""
        weak_id = entry_mgr.add_entry(make_entry(password="1"))
        strong_id = entry_mgr.add_entry(make_entry(password="S3cret-Pass-2024!"))
        weak = entry_mgr.get_entry(weak_id)
        strong = entry_mgr.get_entry(strong_id)
        assert strong.password_strength > weak.password_strength


class TestUpdateEntry:
    """update_entry：字段更新读回一致、密码变更检测与历史归档。"""

    def test_updates_non_password_fields_read_back(self, entry_mgr, make_entry):
        """更新非密码字段读回一致，密码保持不变。"""
        entry_id = entry_mgr.add_entry(
            make_entry(
                title="Old",
                username="u",
                password="Pass123!@#",
            )
        )
        entry = entry_mgr.get_entry(entry_id)
        entry = dataclasses.replace(
            entry,
            title="New Title",
            username="new_user",
            url="https://example.com",
            notes="updated notes",
            tags="tag1,tag2",
        )
        entry_mgr.update_entry(entry)

        read = entry_mgr.get_entry(entry_id)
        assert read.title == "New Title"
        assert read.username == "new_user"
        assert read.url == "https://example.com"
        assert read.notes == "updated notes"
        assert read.tags == "tag1,tag2"
        assert read.password == "Pass123!@#"

    def test_password_change_archives_history(self, entry_mgr, make_entry):
        """密码变更时归档旧密码到历史，计数 +1，读回为新密码。"""
        entry_id = entry_mgr.add_entry(make_entry(password="OldPass123!@#"))
        assert entry_mgr.password_history.get_count(entry_id) == 0

        entry = entry_mgr.get_entry(entry_id)
        entry = dataclasses.replace(entry, password="NewStrongPass456!@#")
        entry_mgr.update_entry(entry)

        assert entry_mgr.password_history.get_count(entry_id) == 1
        assert entry_mgr.get_entry(entry_id).password == "NewStrongPass456!@#"

    def test_password_unchanged_does_not_archive(self, entry_mgr, make_entry):
        """密码不变（仅改其他字段）时不归档历史。"""
        entry_id = entry_mgr.add_entry(make_entry(password="StablePass123!@#"))
        entry = entry_mgr.get_entry(entry_id)
        # get_entry 解密回的 password 即原明文，不改它 → update 检测为未变更
        entry = dataclasses.replace(entry, title="Renamed Only")
        entry_mgr.update_entry(entry)

        assert entry_mgr.password_history.get_count(entry_id) == 0
        assert entry_mgr.get_entry(entry_id).title == "Renamed Only"

    def test_multiple_password_changes_archive_each(self, entry_mgr, make_entry):
        """多次密码变更逐次归档，历史计数等于变更次数。"""
        entry_id = entry_mgr.add_entry(make_entry(password="Pass1-aaa!"))
        for new_pwd in ("Pass2-bbb!", "Pass3-ccc!", "Pass4-ddd!"):
            entry = entry_mgr.get_entry(entry_id)
            entry = dataclasses.replace(entry, password=new_pwd)
            entry_mgr.update_entry(entry)

        assert entry_mgr.password_history.get_count(entry_id) == 3
        assert entry_mgr.get_entry(entry_id).password == "Pass4-ddd!"

    # 非 ASCII 密码回归（QL-019）：compare_digest 对 str 仅接受 ASCII，密码含
    # 中文/重音/emoji 时旧实现抛 TypeError，该条目永远无法编辑、覆盖导入整体中止。
    _UNICODE_PWD = "密码·Pässword·🔐123"

    def test_non_ascii_password_unchanged_edit_succeeds(self, entry_mgr, make_entry):
        """非 ASCII 密码「未变」分支：仅改标题可正常保存，不归档历史。"""
        entry_id = entry_mgr.add_entry(make_entry(password=self._UNICODE_PWD, title="原标题"))
        entry = entry_mgr.get_entry(entry_id)
        entry = dataclasses.replace(entry, title="新标题")
        entry_mgr.update_entry(entry)  # 旧实现在此抛 TypeError

        read = entry_mgr.get_entry(entry_id)
        assert read.title == "新标题"
        assert read.password == self._UNICODE_PWD
        assert entry_mgr.password_history.get_count(entry_id) == 0

    def test_non_ascii_password_change_archives_history(self, entry_mgr, make_entry):
        """非 ASCII 密码「已变」分支：判定为变更，归档历史并读回新密码。"""
        entry_id = entry_mgr.add_entry(make_entry(password=self._UNICODE_PWD))
        entry = entry_mgr.get_entry(entry_id)
        new_pwd = "新密码·NëwPass·🔐456"
        entry = dataclasses.replace(entry, password=new_pwd)
        entry_mgr.update_entry(entry)

        assert entry_mgr.password_history.get_count(entry_id) == 1
        read = entry_mgr.get_entry(entry_id)
        assert read.password == new_pwd
        # 归档的旧密码历史可解密回原非 ASCII 明文
        history = entry_mgr.password_history.get(entry_id)
        decrypted = entry_mgr.password_history.decrypt(history)
        assert decrypted[0]["password"] == self._UNICODE_PWD


class TestToggleFavorite:
    """toggle_favorite：仅切换收藏，不影响密码与历史。"""

    def test_toggles_favorite_state_both_directions(self, entry_mgr, make_entry):
        """toggle_favorite 在两个方向上切换收藏状态并返回新状态。"""
        entry_id = entry_mgr.add_entry(make_entry(is_favorite=False))
        assert entry_mgr.get_entry(entry_id).is_favorite is False

        assert entry_mgr.toggle_favorite(entry_id) is True
        assert entry_mgr.get_entry(entry_id).is_favorite is True

        assert entry_mgr.toggle_favorite(entry_id) is False
        assert entry_mgr.get_entry(entry_id).is_favorite is False

    def test_toggle_favorite_does_not_touch_password_or_history(
        self,
        entry_mgr,
        make_entry,
    ):
        """切换收藏不改密码、不产生密码历史。"""
        pwd = "Pass123!@#"
        entry_id = entry_mgr.add_entry(make_entry(password=pwd))
        entry_mgr.toggle_favorite(entry_id)
        entry_mgr.toggle_favorite(entry_id)

        assert entry_mgr.password_history.get_count(entry_id) == 0
        read = entry_mgr.get_entry(entry_id)
        assert read.password == pwd
        assert read.is_favorite is False

    def test_toggle_favorite_missing_entry_returns_none(self, entry_mgr):
        """对不存在的条目切换收藏返回 None。"""
        assert entry_mgr.toggle_favorite(999999) is None


class TestDeleteRestorePermanent:
    """delete_entry（软删除）/ restore_entry / permanent_delete_entry 语义。"""

    def test_soft_delete_hides_from_default_shows_in_trash(
        self,
        entry_mgr,
        make_entry,
    ):
        """软删除后默认视图不含、回收站含。"""
        entry_id = entry_mgr.add_entry(make_entry(title="A"))
        assert entry_mgr.delete_entry(entry_id) is True

        active = [e.id for e in entry_mgr.get_entries()]
        assert entry_id not in active
        trash = [e.id for e in entry_mgr.get_entries(deleted_only=True)]
        assert entry_id in trash

    def test_restore_returns_entry_to_active(self, entry_mgr, make_entry):
        """恢复后条目回到默认视图、移出回收站。"""
        entry_id = entry_mgr.add_entry(make_entry(title="A"))
        entry_mgr.delete_entry(entry_id)
        assert entry_mgr.restore_entry(entry_id) is True

        active = [e.id for e in entry_mgr.get_entries()]
        assert entry_id in active
        trash = [e.id for e in entry_mgr.get_entries(deleted_only=True)]
        assert entry_id not in trash

    def test_restore_preserves_decrypted_fields(self, entry_mgr, make_entry):
        """软删除→恢复往返后，加密字段解密读回仍与原值一致。"""
        entry_id = entry_mgr.add_entry(
            make_entry(
                title="KeepMe",
                username="bob",
                password="Pass123!@#",
                notes="secret-notes",
            )
        )
        entry_mgr.delete_entry(entry_id)
        assert entry_mgr.restore_entry(entry_id) is True

        read = entry_mgr.get_entry(entry_id)
        assert read.title == "KeepMe"
        assert read.username == "bob"
        assert read.password == "Pass123!@#"
        assert read.notes == "secret-notes"

    def test_permanent_delete_makes_entry_unreadable(self, entry_mgr, make_entry):
        """永久删除后条目不可读，且不出现在任何视图。"""
        entry_id = entry_mgr.add_entry(make_entry(title="Gone"))
        entry_mgr.delete_entry(entry_id)
        entry_mgr.permanent_delete_entry(entry_id)

        assert entry_mgr.get_entry(entry_id) is None
        assert entry_id not in [e.id for e in entry_mgr.get_entries()]
        assert entry_id not in [e.id for e in entry_mgr.get_entries(deleted_only=True)]

    def test_delete_and_restore_missing_entry_return_false(self, entry_mgr):
        """对不存在的条目软删除/恢复返回 False，不抛异常。"""
        assert entry_mgr.delete_entry(999999) is False
        assert entry_mgr.restore_entry(999999) is False


class TestViewDecryptionDelegation:
    """视图解密下沉（MAINT-021）：公开 API 薄委托 EntryViewDecryptor 的接线守护。"""

    def test_public_decrypt_apis_match_view_decryptor(self, entry_mgr, make_entry):
        """decrypt_entry / decrypt_entry_for_export 与解密器直调结果逐字段一致。"""
        entry_id = entry_mgr.add_entry(make_entry(notes="n1", totp_secret="JBSWY3DPEHPK3PXP"))
        raw = entry_mgr.db.get_entry(entry_id)
        assert raw is not None

        detail = entry_mgr.decrypt_entry(raw)
        direct = entry_mgr._view_decryptor.decrypt_entry(raw)  # noqa: SLF001
        assert detail == direct

        exported = entry_mgr.decrypt_entry_for_export(raw, include_secrets=True)
        direct_export = entry_mgr._view_decryptor.decrypt_entry_for_export(
            raw, include_secrets=True
        )  # noqa: SLF001
        assert exported == direct_export
        assert exported.notes == "n1"
        assert exported.totp_secret == "JBSWY3DPEHPK3PXP"

    def test_view_decryptor_shares_cache_instance(self, entry_mgr):
        """解密器与 EntryManager 共用同一 EntryCacheManager（详情路径复用摘要缓存的前提）。"""
        assert (
            entry_mgr._view_decryptor._cache is entry_mgr._cache  # noqa: SLF001
        )
