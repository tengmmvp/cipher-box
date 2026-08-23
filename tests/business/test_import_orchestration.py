"""ImportExportManager 导入编排边界测试。

覆盖导入入口的共享编排逻辑：

- ``MAX_IMPORT_FILE_SIZE`` 超限文件在路径校验阶段被拒绝。
- ``duplicate_action='skip'``：与现有库重复的条目跳过，新条目照常导入。
  （``'overwrite'`` 已在 ``test_product_hardening`` 覆盖，``'import_all'`` 为
  默认行为由各 roundtrip 测试覆盖，此处补 ``'skip'``。）
- CipherBox JSON 结构性拒绝：``app`` 字段错、缺 ``secrets_included`` 布尔声明、
  ``entries`` 非 list、条目非对象。

结构性拒绝的 ImportError 由 ``JsonImporter.parse`` 抛出，经 ``import_file`` →
``_run_importer`` 冒泡（``_validate_import_input`` 仅捕获 UnicodeDecodeError）。
"""

import json

import pytest

from src.business.managers import import_export as ie_module
from src.business.managers.import_export import ImportExportManager
from src.exceptions import ImportFormatError, ImportSizeError
from src.models import Entry


def test_import_rejects_oversized_file(entry_mgr, tmp_path, monkeypatch):
    """超过 MAX_IMPORT_FILE_SIZE 的文件应在路径校验阶段被拒绝。

    经 monkeypatch 把阈值降到很小，避免实际写出 25 MB 文件；``_validate_import_path``
    在调用时读取模块全局 ``MAX_IMPORT_FILE_SIZE``，monkeypatch 即时生效。
    """
    monkeypatch.setattr(ie_module, "MAX_IMPORT_FILE_SIZE", 10)
    mgr = ImportExportManager(entry_mgr)
    csv_path = tmp_path / "big.csv"
    csv_path.write_text(
        "name,url,username,password\nGitHub,https://github.com,alice,Pass123!\n",
        encoding="utf-8",
    )  # 内容远超 10 字节阈值

    with pytest.raises(ImportSizeError, match="导入文件过大"):
        mgr.import_file(str(csv_path), "csv")


def test_import_skip_action_skips_duplicates(entry_mgr, tmp_path):
    """duplicate_action='skip'：与现有库重复的条目跳过（保留原值），新条目照常导入。

    去重键为 ``(title.casefold(), username.casefold())``，与 overwrite 路径共享
    ``_duplicate_plan``。跳过的条目不计入返回值，且不覆盖现有密码。
    """
    mgr = ImportExportManager(entry_mgr)
    # 现有条目：与导入的第一条重复（按 title+username 匹配）
    entry_mgr.add_entry(
        Entry(
            title="Existing",
            username="alice",
            password="OldPass!1",
        )
    )

    json_path = tmp_path / "dup.json"
    json_path.write_text(
        json.dumps(
            {
                "app": "CipherBox",
                "secrets_included": True,
                "entries": [
                    {"title": "Existing", "username": "alice", "password": "NewPass!2"},
                    {"title": "Brand New", "username": "bob", "password": "FreshPass!3"},
                ],
            }
        ),
        encoding="utf-8",
    )

    count = mgr.import_file(str(json_path), "json", duplicate_action="skip")

    assert count == 1
    by_title = {e.title: e for e in entry_mgr.get_entries()}
    assert set(by_title) == {"Existing", "Brand New"}
    # 重复条目保留原密码，未被覆盖（区别于 duplicate_action='overwrite'）
    assert by_title["Existing"].password == "OldPass!1"
    assert by_title["Brand New"].password == "FreshPass!3"


def test_import_rejects_non_cipherbox_json(entry_mgr, tmp_path):
    """app 字段非 'CipherBox' 应被拒绝（防误导入其他格式 JSON）。"""
    mgr = ImportExportManager(entry_mgr)
    path = tmp_path / "wrong_app.json"
    path.write_text(
        json.dumps(
            {
                "app": "SomethingElse",
                "secrets_included": True,
                "entries": [],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ImportFormatError, match="不是 CipherBox JSON 导出文件"):
        mgr.import_file(str(path), "json")


def test_import_rejects_json_without_secrets_declaration(entry_mgr, tmp_path):
    """缺少 secrets_included 布尔声明应被拒绝。

    ``type(data.get('secrets_included')) is not bool`` 严格校验：缺失（None）
    或非布尔类型一律拒绝。这闭合了 ``secrets_included=False`` 路径「导入值必为空」
    代码保证的前置条件——声明缺失即拒绝，杜绝覆盖合并器据错误假设处理对抗性文件。
    """
    mgr = ImportExportManager(entry_mgr)
    path = tmp_path / "no_secrets_flag.json"
    path.write_text(
        json.dumps(
            {
                "app": "CipherBox",
                "entries": [{"title": "x", "password": "leak"}],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ImportFormatError, match="缺少敏感字段声明"):
        mgr.import_file(str(path), "json")


def test_import_rejects_json_entries_not_list(entry_mgr, tmp_path):
    """entries 字段非 list 应被拒绝，而非静默按空导入处理非 list 结构。"""
    mgr = ImportExportManager(entry_mgr)
    path = tmp_path / "bad_entries.json"
    path.write_text(
        json.dumps(
            {
                "app": "CipherBox",
                "secrets_included": True,
                "entries": {"not": "a list"},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ImportFormatError, match="JSON 导入结构无效"):
        mgr.import_file(str(path), "json")


def test_import_rejects_json_non_dict_item(entry_mgr, tmp_path):
    """entries 中存在非对象元素（字符串/数字）应给出明确提示。

    此校验先于 ``_validate_items``：防止非 dict item 触发 ``item.values()``
    的 AttributeError（绕过友好提示），确保畸形条目以可定位的「第 N 项」消息暴露。
    """
    mgr = ImportExportManager(entry_mgr)
    path = tmp_path / "bad_item.json"
    path.write_text(
        json.dumps(
            {
                "app": "CipherBox",
                "secrets_included": True,
                "entries": ["a-string-item", {"title": "valid"}],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ImportFormatError, match="不是有效的对象"):
        mgr.import_file(str(path), "json")


# ======== 导入后摘要缓存保留（PERF-022）========


class TestImportSummaryCacheRetention:
    """导入写入完成后摘要缓存的失效粒度（PERF-022）。

    旧行为：notify_batch_change() 默认 clear_summaries=True，导入后清空全部摘要
    缓存，下一次列表刷新全量重解密；与 add_entry / write_new_entries / docstring
    声明的「导入新增不改变既有条目摘要」矛盾。
    """

    def test_pure_new_import_preserves_summary_cache(self, entry_mgr, tmp_path, monkeypatch):
        """纯新增导入后既有条目摘要缓存命中，刷新不重解密既有条目。"""
        from src.business.managers import entry_cache as ec_module

        mgr = ImportExportManager(entry_mgr)
        keep_id = entry_mgr.add_entry(
            Entry(title="Existing", username="u", password="OldPass!1")
        )
        entry_mgr.get_entry_summaries()  # 预热摘要/分类名缓存
        keep_cid = entry_mgr.db.get_entry(keep_id).crypto_id
        cache = entry_mgr._cache  # noqa: SLF001 测试取内部缓存断言失效粒度
        assert keep_cid in cache._search_metadata_cache  # noqa: SLF001

        json_path = tmp_path / "new_only.json"
        json_path.write_text(
            json.dumps(
                {
                    "app": "CipherBox",
                    "secrets_included": True,
                    "entries": [
                        {"title": "Brand New", "username": "bob", "password": "FreshPass!3"},
                    ],
                }
            ),
            encoding="utf-8",
        )
        assert mgr.import_file(str(json_path), "json") == 1

        # 既有条目摘要缓存保留（导入新增不触碰它）
        assert keep_cid in cache._search_metadata_cache  # noqa: SLF001

        # 计数字段解密：温缓存刷新不应重解密既有条目的摘要字段
        decrypt_calls: list[tuple[str, str]] = []
        real_decrypt = ec_module._decrypt_field_impl

        def counting_decrypt(encrypted, key, crypto_id, field_name, **kwargs):
            decrypt_calls.append((crypto_id, field_name))
            return real_decrypt(encrypted, key, crypto_id, field_name, **kwargs)

        monkeypatch.setattr(ec_module, "_decrypt_field_impl", counting_decrypt)
        refreshed = entry_mgr.get_entry_summaries()
        assert {e.title for e in refreshed} == {"Existing", "Brand New"}
        # 既有条目的 4 个摘要字段零解密（缓存命中）；新条目按需解密属预期
        assert all(cid != keep_cid for cid, _field in decrypt_calls)

    def test_overwrite_import_invalidates_only_overwritten_summaries(
        self, entry_mgr, tmp_path
    ):
        """含覆盖导入后被覆盖条目摘要精确失效，未覆盖条目摘要保留。"""
        mgr = ImportExportManager(entry_mgr)
        keep_id = entry_mgr.add_entry(
            Entry(title="Keep", username="k", password="KeepPass!1")
        )
        target_id = entry_mgr.add_entry(
            Entry(title="Target", username="t", password="OldPass!1", tags="")
        )
        entry_mgr.get_entry_summaries()  # 预热
        keep_cid = entry_mgr.db.get_entry(keep_id).crypto_id
        target_cid = entry_mgr.db.get_entry(target_id).crypto_id
        cache = entry_mgr._cache  # noqa: SLF001
        assert keep_cid in cache._search_metadata_cache  # noqa: SLF001
        assert target_cid in cache._search_metadata_cache  # noqa: SLF001

        json_path = tmp_path / "overwrite.json"
        json_path.write_text(
            json.dumps(
                {
                    "app": "CipherBox",
                    "secrets_included": True,
                    "entries": [
                        # 同 (title, username) 命中覆盖；改 tags 供摘要可观测
                        {"title": "Target", "username": "t", "password": "NewPass!2",
                         "tags": "fresh-tag"},
                    ],
                }
            ),
            encoding="utf-8",
        )
        assert mgr.import_file(str(json_path), "json", duplicate_action="overwrite") == 1

        # 被覆盖条目摘要缓存已失效（旧摘要不残留），未覆盖条目保留
        assert target_cid not in cache._search_metadata_cache  # noqa: SLF001
        assert keep_cid in cache._search_metadata_cache  # noqa: SLF001

        # 刷新后摘要反映覆盖后的数据（tags 已更新）
        refreshed = {e.title: e for e in entry_mgr.get_entry_summaries()}
        assert refreshed["Target"].tags == "fresh-tag"
