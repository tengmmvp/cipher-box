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

from src.business.managers.entry_manager import EntryManager
from src.crypto.password_generator import PasswordGenerator
from src.models import CIPHERTEXT_PREFIX, CustomField
from tests.helpers import decrypt_all_entries


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

    def test_get_entry_with_epoch_carries_current_epoch(self, entry_mgr, make_entry):
        """get_entry_with_epoch 随 entry 携带读锁内快照的数据世代（SEC-054 闭合）。

        世代供 detail_panel 的 TOTP 预热守卫消费；与 get_entry 同一读路径，
        未知 id 返回 (None, None)。
        """
        entry_id = entry_mgr.add_entry(
            make_entry(title="带世代", username="u", password="S3cret-Pass-2024!")
        )

        entry, data_epoch = entry_mgr.get_entry_with_epoch(entry_id)
        assert entry is not None
        assert entry.title == "带世代"
        assert data_epoch == entry_mgr.key_epoch  # 锁内快照即当前世代（无并发轮换）

        assert entry_mgr.get_entry_with_epoch(99999) == (None, None)

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

        active = [e.id for e in decrypt_all_entries(entry_mgr)]
        assert entry_id not in active
        trash = [e.id for e in decrypt_all_entries(entry_mgr, deleted_only=True)]
        assert entry_id in trash

    def test_restore_returns_entry_to_active(self, entry_mgr, make_entry):
        """恢复后条目回到默认视图、移出回收站。"""
        entry_id = entry_mgr.add_entry(make_entry(title="A"))
        entry_mgr.delete_entry(entry_id)
        assert entry_mgr.restore_entry(entry_id) is True

        active = [e.id for e in decrypt_all_entries(entry_mgr)]
        assert entry_id in active
        trash = [e.id for e in decrypt_all_entries(entry_mgr, deleted_only=True)]
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
        assert entry_id not in [e.id for e in decrypt_all_entries(entry_mgr)]
        assert entry_id not in [e.id for e in decrypt_all_entries(entry_mgr, deleted_only=True)]

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
        # cache 观察面（MAINT-095）：两侧均为公开只读 property
        assert entry_mgr._view_decryptor.cache is entry_mgr.cache  # noqa: SLF001


class TestListLimitPushdown:
    """无搜索列表的 SQL LIMIT 下推契约（PERF-066，EntryListController.fetch_all 消费）。

    超过 limit 的全量视图查询返回 ≤limit 条且排序为 SQL 索引序
    （is_favorite DESC, updated_at DESC，PERF-011 复合索引），而非插入序/标题序——
    UI 渲染截断（MAX_SEARCH_RESULTS_DISPLAY）依赖该等价性才能安全下推。
    """

    def test_limit_truncates_in_index_order(self, entry_mgr, make_entry):
        """60 条目 + limit=50：返回恰 50 条，前段为索引序（收藏优先，再按更新时间倒序）。"""
        from datetime import UTC, datetime, timedelta

        base = datetime(2026, 8, 20, 10, 0, 0, tzinfo=UTC)
        # 3 条收藏（更新时间递增落库）+ 57 条普通条目
        for i in range(3):
            entry_mgr.add_entry(
                make_entry(
                    title=f"收藏-{i:02d}",
                    created_at=base.isoformat(),
                    updated_at=(base + timedelta(minutes=i)).isoformat(),
                    is_favorite=True,
                )
            )
        for i in range(57):
            entry_mgr.add_entry(
                make_entry(
                    title=f"普通-{i:02d}",
                    created_at=base.isoformat(),
                    updated_at=(base + timedelta(minutes=i)).isoformat(),
                )
            )

        summaries = entry_mgr.get_entry_summaries(limit=50)

        assert len(summaries) == 50
        # 索引序断言：前 3 条为收藏（收藏内部按 updated_at 倒序），第 4 条起为
        # 非收藏的最新条目——证明截断发生在 SQL 索引序上而非其他顺序。
        assert [s.title for s in summaries[:3]] == ["收藏-02", "收藏-01", "收藏-00"]
        assert summaries[3].title == "普通-56"
        assert summaries[-1].title == "普通-10"
        # 全部返回均非回收站条目
        assert all(not s.is_deleted for s in summaries)


class TestUpdateEntrySignature:
    """update_entry 签名收口（MAINT-090）：preloaded_raw/preloaded_old_password 已删除。

    两参数全库（含测试）零调用方传入，docstring 自述「保留是为签名兼容」而项目
    未发布无兼容包袱。守护签名不再回退加回这两个参数。
    """

    def test_signature_has_no_preloaded_params(self):
        """update_entry 的签名不含 preloaded_raw/preloaded_old_password。"""
        import inspect

        params = inspect.signature(EntryManager.update_entry).parameters
        assert "preloaded_raw" not in params
        assert "preloaded_old_password" not in params
        assert set(params) == {"self", "entry", "preserve_password_changed_at", "notify"}


class TestGetEntriesRetired:
    """get_entries 退役守护（MAINT-098）：测试专用「一次性解密全部密码」入口不再回到生产 API 面。

    原方法 src 零调用、测试 40+ 处消费（docstring 自述「主要供测试断言」），在生产
    API 面上保留等于公开一个无消费方的全量密码解密入口。等价能力已移
    ``tests.helpers.decrypt_all_entries``；此处守护方法不被重新加回。
    """

    def test_get_entries_not_on_entry_manager(self):
        """EntryManager 公开面上不存在 get_entries 方法（防回退）。"""
        assert not hasattr(EntryManager, "get_entries")


class TestAddDeleteIncrementalNotify:
    """增删恢复的单条增量通知（PERF-079）：crypto_id 透传 + 标签计数差分。

    增删携带该条 crypto_id 经 change_bus 通知（订阅方如 SecurityAnalyzer 据此做
    单条增量而非整库失效）；标签计数经 apply_tag_delta 差分维护，不再触发
    get_all_tags 的全量重解密重算（以 db 窄投影 spy 断言零重算）。
    """

    def _register_recorder(self, entry_mgr) -> list[tuple[bool, bool, str | None]]:
        received: list[tuple[bool, bool, str | None]] = []
        entry_mgr.register_on_change(lambda pw, md, cid: received.append((pw, md, cid)))
        return received

    @staticmethod
    def _tags_projection_calls(vault, monkeypatch) -> "list[int]":
        """spy db.get_entries_tags_projection 的调用次数（全量标签重算的标志）。"""
        calls: list[int] = []
        original = vault.db.get_entries_tags_projection

        def _spy():
            calls.append(1)
            return original()

        monkeypatch.setattr(vault.db, "get_entries_tags_projection", _spy)
        return calls

    def test_add_delete_notify_with_crypto_id(self, entry_mgr, make_entry):
        """add/delete/restore 的通知携带该条 crypto_id（单条增量语义入口）。"""
        received = self._register_recorder(entry_mgr)
        entry_id = entry_mgr.add_entry(make_entry(title="A", tags="t1"))
        raw = entry_mgr.db.get_entry(entry_id)
        assert raw is not None
        assert received[-1][2] == raw.crypto_id

        entry_mgr.delete_entry(entry_id)
        assert received[-1][2] == raw.crypto_id

        entry_mgr.restore_entry(entry_id)
        assert received[-1][2] == raw.crypto_id

    def test_tags_counts_tracked_by_delta_without_full_recalc(
        self, entry_mgr, make_entry, monkeypatch
    ):
        """增删后标签计数差分正确且不触发全量重算（窄投影零调用）。"""
        entry_mgr.add_entry(make_entry(title="A", tags="工作,社交"))
        entry_mgr.add_entry(make_entry(title="B", tags="工作"))
        before = dict(entry_mgr.get_all_tags())
        assert before == {"工作": 2, "社交": 1}

        spy = self._tags_projection_calls(
            entry_mgr._vault,
            monkeypatch,  # noqa: SLF001
        )
        # 新增：工作 → 3（差分，无全量重算）
        entry_id_c = entry_mgr.add_entry(make_entry(title="C", tags="工作"))
        assert dict(entry_mgr.get_all_tags())["工作"] == 3
        # 软删除 C：工作 → 2（差分）
        entry_mgr.delete_entry(entry_id_c)
        assert dict(entry_mgr.get_all_tags())["工作"] == 2
        # 恢复 C：工作 → 3
        entry_mgr.restore_entry(entry_id_c)
        assert dict(entry_mgr.get_all_tags())["工作"] == 3
        # 全量重算（窄投影）零触发——差分全程命中缓存
        assert len(spy) == 0

    def test_tags_delta_on_edit_replaces_counts(self, entry_mgr, make_entry):
        """编辑改 tags：旧标签 -1、新标签 +1（update 路径差分，PERF-079）。"""
        import dataclasses as dc

        entry_id = entry_mgr.add_entry(make_entry(title="A", tags="旧标签"))
        assert dict(entry_mgr.get_all_tags()) == {"旧标签": 1}

        entry = entry_mgr.get_entry(entry_id)
        entry_mgr.update_entry(dc.replace(entry, tags="新标签"))

        assert dict(entry_mgr.get_all_tags()) == {"新标签": 1}

    def test_permanent_delete_of_active_entry_dedupes_tags(self, entry_mgr, make_entry):
        """直接物理删除活跃条目补齐差分（回收站二次删除路径则幂等 no-op）。"""
        entry_id = entry_mgr.add_entry(make_entry(title="A", tags="仅此一条"))
        assert dict(entry_mgr.get_all_tags()) == {"仅此一条": 1}

        entry_mgr.permanent_delete_entry(entry_id)  # 未经软删除的直接物理删除
        assert entry_mgr.get_all_tags() == []

        # 回收站路径：软删除已差分，物理删除不再重复扣减
        entry_id2 = entry_mgr.add_entry(make_entry(title="B", tags="回收站路径"))
        entry_mgr.delete_entry(entry_id2)
        assert entry_mgr.get_all_tags() == []
        entry_mgr.permanent_delete_entry(entry_id2)
        assert entry_mgr.get_all_tags() == []

    def test_delete_tampered_entry_still_works(self, entry_mgr, make_entry):
        """元数据被篡改（HMAC 失配）的条目仍可软删除（PERF-079 前置读取 LENIENT）。

        差分前置读取走 ``get_entries_by_ids``（LENIENT）而非 ``get_entry``（STRICT
        抛 EntryIntegrityError）——删除损坏条目是清理路径，不得因验签失败而不可用。
        """
        entry_id = entry_mgr.add_entry(make_entry(title="被篡改", tags="篡改标签"))
        conn = entry_mgr.db._conn  # noqa: SLF001
        assert conn is not None
        # 改写入签载荷的非加密元数据且不重签：metadata_mac 比对必然失配
        conn.execute("UPDATE entries SET is_favorite = 1 - is_favorite WHERE id=?", (entry_id,))
        conn.commit()

        assert entry_mgr.delete_entry(entry_id) is True  # 不抛 EntryIntegrityError

        trash = [e.id for e in decrypt_all_entries(entry_mgr, deleted_only=True)]
        assert entry_id in trash

    def test_delete_corrupted_tags_entry_invalidates_tags_cache(
        self, entry_mgr, make_entry, monkeypatch
    ):
        """tags 密文损坏的条目删除后标签缓存被失效（QL-066，问题 1 回归守护）。

        旧行为：delete/restore 的差分对解密失败回退空串（静默 no-op）且
        ``tags_changed=False``，损坏 tags 条目被删除后 ``_tags_cache`` 陈旧。
        现解密失败返回 None 哨兵 → 保守 ``tags_changed=True`` 整表失效（对齐
        编辑路径 ``_notify_entry_updated`` 的既有保守口径）。
        """
        entry_mgr.add_entry(make_entry(title="好条目", tags="正常标签"))
        entry_id = entry_mgr.add_entry(make_entry(title="损坏", tags="损坏标签"))
        conn = entry_mgr.db._conn  # noqa: SLF001
        assert conn is not None
        # 直改 tags 密文为非法载荷（不重签）：GCM 认证必然失败
        conn.execute("UPDATE entries SET tags_enc='cb2:garbage' WHERE id=?", (entry_id,))
        conn.commit()

        # 全量聚合对损坏 tags 回退空串：缓存不含「损坏标签」
        assert dict(entry_mgr.get_all_tags()) == {"正常标签": 1}
        spy = self._tags_projection_calls(entry_mgr._vault, monkeypatch)
        assert entry_mgr.delete_entry(entry_id) is True

        # 解密失败 → 保守整表失效：下次 get_all_tags 触发全量重算（非差分命中）
        assert dict(entry_mgr.get_all_tags()) == {"正常标签": 1}
        assert len(spy) == 1  # 全量重算发生（差分被放弃，缓存经失效重建）

    def test_restore_corrupted_tags_entry_invalidates_tags_cache(self, entry_mgr, make_entry):
        """恢复路径同款保守失效（QL-066）：损坏 tags 条目恢复不残留陈旧计数。"""
        entry_id = entry_mgr.add_entry(make_entry(title="损坏", tags="损坏标签"))
        conn = entry_mgr.db._conn  # noqa: SLF001
        conn.execute("UPDATE entries SET tags_enc='cb2:garbage' WHERE id=?", (entry_id,))
        conn.commit()
        assert entry_mgr.delete_entry(entry_id) is True
        assert entry_mgr.get_all_tags() == []

        assert entry_mgr.restore_entry(entry_id) is True
        # 恢复的差分解密失败 → 保守整表失效，不引入陈旧计数
        assert entry_mgr.get_all_tags() == []

    def test_abandoned_tag_delta_falls_back_to_full_invalidation(
        self, entry_mgr, make_entry, monkeypatch
    ):
        """差分被世代守卫放弃后保守整表失效（QL-070 回归）。

        时序仿真（写事务前快照 vs 窗口内并发失效）：调用方在写事务前快照
        ``invalidate_version``，窗口内并发失效推进版本——差分到达时被守卫放弃。
        旧行为放弃后仍 tags_changed=False（「既未差分也未失效」第三态），缓存
        正确性靠后续 apply_change 的未声明行为巧合收敛；现 apply_tag_delta 返回
        False，_notify_entry_structure_changed 保守置 tags_changed=True 整表失效。
        """
        entry_mgr.add_entry(make_entry(title="A", tags="工作"))
        assert dict(entry_mgr.get_all_tags()) == {"工作": 1}  # 惰性填充 _tags_cache
        assert entry_mgr._cache._tags_cache is not None

        # 拦截 apply_tag_delta：固定「放弃」出口（真实竞态窗口在写事务与差分
        # 之间，此处以替身隔离验证调用方的回退分支本身）
        monkeypatch.setattr(entry_mgr._cache, "apply_tag_delta", lambda *a, **k: False)

        entry_mgr.add_entry(make_entry(title="B", tags="新标签"))

        # 差分被放弃 → 保守整表失效：_tags_cache 置 None，下次 get_all_tags 全量重算
        assert entry_mgr._cache._tags_cache is None
        assert dict(entry_mgr.get_all_tags()) == {"工作": 1, "新标签": 1}


class TestSearchOrderPushdown:
    """搜索 + SQL 白名单排序 + limit 的排序下推（PERF-087）——结果与全量内存排序一致。

    分支条件：内存路径（搜索非空）且 order_by 属 ORDER_BY_FIELDS 且 limit 非 None，
    投影查询下推 ORDER BY，匹配循环按序扫描凑满 limit 即 break。守护：与
    「全量收集 → 内存排序 → 截断」选出同一集合与同一序、命中数不足/恰好等于
    limit 的边界、升序方向。
    """

    def _setup_entries(self, entry_mgr, make_entry):
        """5 条同前缀条目，updated_at 单调递增（最旧条目是收藏：复合序与序不同）。"""
        from datetime import UTC, datetime, timedelta

        base = datetime(2026, 8, 20, 10, 0, 0, tzinfo=UTC)
        for i in range(5):
            entry_mgr.add_entry(
                make_entry(
                    title=f"item-{i}",
                    created_at=base.isoformat(),
                    updated_at=(base + timedelta(minutes=i)).isoformat(),
                    is_favorite=(i == 0),
                )
            )

    def test_desc_pushdown_matches_full_sort(self, entry_mgr, make_entry):
        """降序：凑满 limit 即停的结果 == 全量命中按 updated_at 倒序的前 3。"""
        self._setup_entries(entry_mgr, make_entry)

        results = entry_mgr.get_entry_summaries(
            search="item", order_by="updated_at", order_desc=True, limit=3
        )

        assert [r.title for r in results] == ["item-4", "item-3", "item-2"]
        # 收藏条目（item-0，最旧）不因复合序挤进前 3：下推序即纯 updated_at 序
        assert all(r.title != "item-0" for r in results)

    def test_asc_pushdown(self, entry_mgr, make_entry):
        """升序：order_desc=False 的下推方向正确（最旧匹配在前）。"""
        self._setup_entries(entry_mgr, make_entry)
        results = entry_mgr.get_entry_summaries(
            search="item", order_by="updated_at", order_desc=False, limit=2
        )
        assert [r.title for r in results] == ["item-0", "item-1"]

    def test_hits_fewer_than_limit_returns_all_sorted(self, entry_mgr, make_entry):
        """边界：命中数（1）< limit（10）——全部命中按序返回，无截断放大。"""
        self._setup_entries(entry_mgr, make_entry)
        results = entry_mgr.get_entry_summaries(
            search="item-4", order_by="updated_at", order_desc=True, limit=10
        )
        # "item-4" 仅命中 1 条（其余条目不含该前缀）
        assert [r.title for r in results] == ["item-4"]

    def test_hits_exactly_equal_limit(self, entry_mgr, make_entry):
        """边界：命中数恰好 == limit——全部命中按序返回。"""
        self._setup_entries(entry_mgr, make_entry)
        results = entry_mgr.get_entry_summaries(
            search="item", order_by="updated_at", order_desc=True, limit=5
        )
        assert [r.title for r in results] == [
            "item-4",
            "item-3",
            "item-2",
            "item-1",
            "item-0",
        ]

    def test_tie_break_pushdown_selects_same_set_as_full_sort(self, entry_mgr, make_entry):
        """并列裁决（PERF-087 回归）：排序键同刻并列 + limit 截断边界，下推路径与
        全量内存排序选出同一集合与同一序。

        6 条 created_at 同刻并列（批量导入的常见形态），名次由并列裁决键决定：
        SQL 序带 tie-breaker（is_favorite DESC, updated_at DESC，与复合序一致），
        与内存稳定排序继承的复合序逐层等价。不带裁决键时 SQL 并列行为引擎内序
        （rowid 序），凑满 limit 即 break 选出的集合与「全量收集→稳定排序→截断」
        分叉——对照组为 limit=None 强制走内存排序路径后手动取前 N（旧路径语义）。
        """
        from datetime import UTC, datetime, timedelta

        base = datetime(2026, 8, 20, 10, 0, 0, tzinfo=UTC)
        # 后三条为收藏（裁决第一层），updated_at 三档递增（裁决第二层）
        for i in range(6):
            entry_mgr.add_entry(
                make_entry(
                    title=f"tie-{i}",
                    created_at=base.isoformat(),
                    updated_at=(base + timedelta(minutes=(i % 3) * 10)).isoformat(),
                    is_favorite=i >= 3,
                )
            )

        pushed = entry_mgr.get_entry_summaries(
            search="tie", order_by="created_at", order_desc=True, limit=3
        )
        # 对照组：limit=None → 不走排序下推，全量收集 + 内存稳定排序（继承复合序）
        full = entry_mgr.get_entry_summaries(search="tie", order_by="created_at", order_desc=True)

        assert [r.id for r in pushed] == [r.id for r in full[:3]]
        # 具体序锚定：并列集内收藏优先、再按 updated_at 倒序（tie-5 > tie-4 > tie-3）
        assert [r.title for r in pushed] == ["tie-5", "tie-4", "tie-3"]

    def test_tie_break_on_strength_scale_matches_full_sort(self, entry_mgr, make_entry):
        """强度刻度并列（0-4 档位天然并列常见）：同款等价守护（PERF-087）。

        三条同形态短数字密码（score 恒同）构成排序键并列，limit=2 的截断边界
        与全量内存排序对照——裁决键（复合序）保证两路径选出同一集合与同一序。
        """
        from datetime import UTC, datetime, timedelta

        base = datetime(2026, 8, 20, 10, 0, 0, tzinfo=UTC)
        for i, pwd in enumerate(("111", "222", "333")):
            entry_mgr.add_entry(
                make_entry(
                    title=f"weak-{i}",
                    password=pwd,
                    updated_at=(base + timedelta(minutes=i)).isoformat(),
                    is_favorite=i == 2,
                )
            )
        # 前提锚定：三条密码的 strength 刻度确实并列
        strengths = {e.password_strength for e in entry_mgr.get_entry_summaries(search="weak-")}
        assert len(strengths) == 1

        pushed = entry_mgr.get_entry_summaries(
            search="weak-", order_by="password_strength", order_desc=True, limit=2
        )
        full = entry_mgr.get_entry_summaries(
            search="weak-", order_by="password_strength", order_desc=True
        )

        assert [r.id for r in pushed] == [r.id for r in full[:2]]
        # 并列集内收藏优先（weak-2），再按 updated_at 倒序（weak-1 > weak-0）
        assert [r.title for r in pushed] == ["weak-2", "weak-1"]


class TestLimitZeroSemantics:
    """limit=0 两路径语义统一（QL-072）：均返回空集。

    旧行为：SQL 路径 LIMIT 0 返回空，内存路径 ``if limit`` 视 0 为 falsy 跳过
    截断返回全部——同参数不同路径结果分叉。
    """

    def test_limit_zero_sql_path(self, entry_mgr, make_entry):
        """SQL 下推路径 limit=0 → 空集（既有语义锁定）。"""
        entry_mgr.add_entry(make_entry(title="A"))
        assert entry_mgr.get_entry_summaries(limit=0) == []

    def test_limit_zero_memory_path_no_order(self, entry_mgr, make_entry):
        """内存路径（无排序下推）limit=0 → 空集（修复点：原返回全部）。"""
        entry_mgr.add_entry(make_entry(title="A"))
        assert entry_mgr.get_entry_summaries(search="a", limit=0) == []

    def test_limit_zero_memory_path_with_order_pushdown(self, entry_mgr, make_entry):
        """排序下推分支 limit=0 → 循环首轮即 break，返回空集。"""
        entry_mgr.add_entry(make_entry(title="A"))
        assert entry_mgr.get_entry_summaries(search="a", order_by="updated_at", limit=0) == []


class TestEmptyTrashBypassNotification:
    """empty_trash 的通知降级（PERF-088）：回收站条目不在活跃分析集合。"""

    def test_empty_trash_preserves_security_cache(self, entry_mgr, make_entry):
        """清空回收站后安全分析缓存不失效（软删除时已增量移出，物理清空无增量可算）。"""
        from src.business.services.security_analyzer import SecurityAnalyzer

        analyzer = SecurityAnalyzer(entry_mgr._vault, entry_mgr._cache)
        entry_mgr.register_on_change(analyzer.invalidate_cache)

        entry_id = entry_mgr.add_entry(make_entry(title="待清理", password="weak"))
        entry_mgr.delete_entry(entry_id)  # 软删除：增量差分移出分析集合
        analyzer.get_or_compute_report()  # 填充安全分析缓存
        assert analyzer.get_cached_counts() is not None

        entry_mgr.empty_trash()

        # 双 False 旁路通知：缓存保留，不触发整库 O(n) 重算
        assert analyzer.get_cached_counts() is not None

    def test_empty_trash_still_invalidates_rowset_caches(self, entry_mgr, make_entry):
        """降级不影响行集/摘要失效：清空后回收站视图为空（apply_change 照常执行）。"""
        entry_id = entry_mgr.add_entry(make_entry(title="待清理"))
        entry_mgr.delete_entry(entry_id)
        assert entry_mgr.get_entry_summaries(deleted_only=True, search="清理") != []

        entry_mgr.empty_trash()

        assert entry_mgr.get_entry_summaries(deleted_only=True, search="清理") == []


class TestTotpInvalidateOrdering:
    """写路径的 TOTP 缓存失效时序守护（QL-070）：pop_totp 必须先于写库。

    「写库 → pop」窗口内 TOTP 定时器命中缓存的旧 secret 生成过期验证码；把
    pop 挪回写库后的回退重构无行为失败信号（仅竞态窗口复活），此处以调用
    顺序 spy 锁定。update_entry 与 permanent_delete_entry 两路径守护
    （delete_entry 为同型路径）。
    """

    @staticmethod
    def _install_order_spy(entry_mgr, monkeypatch, db_write_method: str) -> list[str]:
        """记录 pop_totp 与指定 db 写方法的调用顺序（先 pop 后写为正确序）。"""
        events: list[str] = []
        cache = entry_mgr._cache  # noqa: SLF001
        real_pop = cache.pop_totp

        def _pop(entry_id: int) -> None:
            events.append("pop_totp")
            real_pop(entry_id)

        monkeypatch.setattr(cache, "pop_totp", _pop)

        db = entry_mgr.db
        real_write = getattr(db, db_write_method)

        def _record_write(*args, **kwargs):
            events.append(f"db.{db_write_method}")
            return real_write(*args, **kwargs)

        monkeypatch.setattr(db, db_write_method, _record_write)
        return events

    def test_update_entry_pops_totp_before_db_write(self, entry_mgr, make_entry, monkeypatch):
        """update_entry：旧 TOTP secret 缓存在新密文落库前已清除。"""
        events = self._install_order_spy(entry_mgr, monkeypatch, "update_entry")
        entry_id = entry_mgr.add_entry(make_entry(title="A"))

        entry = entry_mgr.get_entry(entry_id)
        entry_mgr.update_entry(dataclasses.replace(entry, title="B"))

        assert events == ["pop_totp", "db.update_entry"]

    def test_permanent_delete_entry_pops_totp_before_db_write(
        self, entry_mgr, make_entry, monkeypatch
    ):
        """permanent_delete_entry：pop 先于物理删除写库（条目不存在时亦保持先 pop）。"""
        events = self._install_order_spy(entry_mgr, monkeypatch, "permanent_delete_entry")
        entry_id = entry_mgr.add_entry(make_entry(title="A"))

        entry_mgr.permanent_delete_entry(entry_id)

        assert events == ["pop_totp", "db.permanent_delete_entry"]
