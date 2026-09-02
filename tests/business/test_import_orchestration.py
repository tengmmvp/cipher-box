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
from src.models import CustomField, Entry
from tests.helpers import decrypt_all_entries


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
    by_title = {e.title: e for e in decrypt_all_entries(entry_mgr)}
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
        keep_id = entry_mgr.add_entry(Entry(title="Existing", username="u", password="OldPass!1"))
        entry_mgr.get_entry_summaries()  # 预热摘要/分类名缓存
        keep_cid = entry_mgr.db.get_entry(keep_id).crypto_id
        cache = entry_mgr.cache  # QL-044 公开缓存视图：断言导入后的失效粒度
        assert keep_cid in cache.search_metadata_cached_ids

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
        assert keep_cid in cache.search_metadata_cached_ids

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

    def test_overwrite_import_invalidates_only_overwritten_summaries(self, entry_mgr, tmp_path):
        """含覆盖导入后被覆盖条目摘要精确失效，未覆盖条目摘要保留。"""
        mgr = ImportExportManager(entry_mgr)
        keep_id = entry_mgr.add_entry(Entry(title="Keep", username="k", password="KeepPass!1"))
        target_id = entry_mgr.add_entry(
            Entry(title="Target", username="t", password="OldPass!1", tags="")
        )
        entry_mgr.get_entry_summaries()  # 预热
        keep_cid = entry_mgr.db.get_entry(keep_id).crypto_id
        target_cid = entry_mgr.db.get_entry(target_id).crypto_id
        cache = entry_mgr._cache  # noqa: SLF001
        assert keep_cid in cache.search_metadata_cached_ids
        assert target_cid in cache.search_metadata_cached_ids

        json_path = tmp_path / "overwrite.json"
        json_path.write_text(
            json.dumps(
                {
                    "app": "CipherBox",
                    "secrets_included": True,
                    "entries": [
                        # 同 (title, username) 命中覆盖；改 tags 供摘要可观测
                        {
                            "title": "Target",
                            "username": "t",
                            "password": "NewPass!2",
                            "tags": "fresh-tag",
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        assert mgr.import_file(str(json_path), "json", duplicate_action="overwrite") == 1

        # 被覆盖条目摘要缓存已失效（旧摘要不残留），未覆盖条目保留
        assert target_cid not in cache.search_metadata_cached_ids
        assert keep_cid in cache.search_metadata_cached_ids

        # 刷新后摘要反映覆盖后的数据（tags 已更新）
        refreshed = {e.title: e for e in entry_mgr.get_entry_summaries()}
        assert refreshed["Target"].tags == "fresh-tag"


# ======== 导入加权总进度（PERF-065）========


class TestImportWeightedProgress:
    """progress_callback 覆盖全阶段的加权总进度（PERF-065）。

    旧行为：进度仅在分类阶段逐条上报（50k CSV 端到端 8.43s 中占 0.61s），进度条
    先冲 100% 再在加密（3.29s）与写入（2.85s）期间冻结。加权后 ``(current, total)``
    恒为百分比语义：total=100、单调不减、终值 100、emit 次数远小于行数（节流）。
    """

    # 250 行：加密阶段按 100 行节流上报 3 次（100/200/250），写入阶段单块（<500），
    # 总 emit 次数远小于行数，可同时验证节流与单调性。
    ROWS = 250

    @staticmethod
    def _make_json_import(tmp_path, rows: int) -> str:
        path = tmp_path / "progress.json"
        path.write_text(
            json.dumps(
                {
                    "app": "CipherBox",
                    "secrets_included": True,
                    "entries": [
                        {
                            "title": f"Entry-{i:04d}",
                            "username": f"user{i:04d}",
                            "password": f"Pass{i:04d}!x",
                        }
                        for i in range(rows)
                    ],
                }
            ),
            encoding="utf-8",
        )
        return str(path)

    def test_progress_monotonic_and_reaches_100(self, entry_mgr, tmp_path):
        """进度值单调不减、total 恒 100、终值 100。"""
        mgr = ImportExportManager(entry_mgr)
        events: list[tuple[int, int]] = []
        count = mgr.import_file(
            self._make_json_import(tmp_path, self.ROWS),
            "json",
            progress_callback=lambda current, total: events.append((current, total)),
        )
        assert count == self.ROWS

        assert events, "进度回调应至少被调用一次"
        assert all(total == 100 for _current, total in events)
        values = [current for current, _total in events]
        assert all(a <= b for a, b in zip(values, values[1:], strict=False)), (
            f"进度值须单调不减：{values}"
        )
        assert values[-1] == 100

    def test_progress_covers_expensive_phases(self, entry_mgr, tmp_path):
        """加密/写入耗时主导阶段有中间值：存在 (15,70) 与 (70,100) 区间的上报。"""
        mgr = ImportExportManager(entry_mgr)
        events: list[tuple[int, int]] = []
        mgr.import_file(
            self._make_json_import(tmp_path, self.ROWS),
            "json",
            progress_callback=lambda current, total: events.append((current, total)),
        )
        values = [current for current, _total in events]
        # 加密阶段（15→70）与写入阶段（70→100）均有中间值，进度不再 100% 后冻结。
        assert any(15 <= v < 70 for v in values)
        assert any(70 <= v < 100 for v in values)
        # parse/sanitize 里程碑在最前。
        assert values[0] <= 10

    def test_progress_throttled_well_below_row_count(self, entry_mgr, tmp_path):
        """节流生效（PERF-069）：全阶段合计上报次数远小于行数。

        classify 阶段原为逐条上报（250 行 = 250 次跨线程信号发射，50k 行同放大），
        PERF-069 起与加密/写入阶段同款按 ``PROGRESS_REPORT_EVERY=100`` 节流、终值
        恒上报。250 行的期望总 emit 数：parse/sanitize/plan 里程碑 3 + classify 3
        （100/200/250）+ 加密 3 + 写入 1 + 终值 1 = 11。
        """
        mgr = ImportExportManager(entry_mgr)
        events: list[tuple[int, int]] = []
        mgr.import_file(
            self._make_json_import(tmp_path, self.ROWS),
            "json",
            progress_callback=lambda current, total: events.append((current, total)),
        )
        # 总 emit 次数远小于行数（无节流时 classify 单段即为 ROWS 次）。
        assert len(events) <= 15, f"节流失效：250 行导入产生 {len(events)} 次上报"
        assert len(events) < self.ROWS // 10
        # 分类阶段（12→15）节流后仍有中间值（13/14 一档），非仅首尾跳变。
        classify_mid = [current for current, _total in events if 12 < current < 15]
        assert len(classify_mid) >= 1
        # 加密阶段（15→70）确有节流后的中间值（37/59 一档），非仅终值跳变。
        encrypt_mid = [current for current, _total in events if 15 < current < 70]
        assert len(encrypt_mid) >= 2

    def test_empty_import_still_reports_100(self, entry_mgr, tmp_path):
        """空导入（无条目）也上报终值 100，进度条不留悬挂。"""
        mgr = ImportExportManager(entry_mgr)
        events: list[tuple[int, int]] = []
        path = tmp_path / "empty.json"
        path.write_text(
            json.dumps({"app": "CipherBox", "secrets_included": True, "entries": []}),
            encoding="utf-8",
        )
        count = mgr.import_file(
            str(path),
            "json",
            progress_callback=lambda current, total: events.append((current, total)),
        )
        assert count == 0
        assert events[-1] == (100, 100)


# ======== 纯覆盖导入进度（PERF-069）========


class TestOverwriteOnlyImportProgress:
    """duplicate_action=overwrite 全命中时进度不再冻结在 15%（PERF-069）。

    旧行为：encrypt/write 进度只挂在「新条目」子批（encrypt_new_entries /
    write_new_entries），纯覆盖导入两子批均空，进度条分类结束（15%）后冻结到
    终值 100 直跳——重导全量覆盖是典型场景。PERF-069 起覆盖条目的
    prepare_overwrite_updates / write_overwrite_updates 与新条目合并计量同一
    加权刻度（15→70 / 70→100）。
    """

    # 600 行 > _WRITE_PROGRESS_CHUNK(500)：覆盖写入分 2 块产生 (70,100) 开区间中间值；
    # 加密子批按 100 节流产生 (15,70) 开区间中间值。
    ROWS = 600

    @staticmethod
    def _seed_existing(entry_mgr, rows: int) -> None:
        """预置与导入文件同 (title, username) 的既有条目，使全量命中覆盖。"""
        for i in range(rows):
            entry_mgr.add_entry(
                Entry(
                    title=f"Entry-{i:04d}",
                    username=f"user{i:04d}",
                    password=f"OldPass{i:04d}!x",
                )
            )

    def _make_overwrite_import(self, tmp_path) -> str:
        path = tmp_path / "overwrite.json"
        path.write_text(
            json.dumps(
                {
                    "app": "CipherBox",
                    "secrets_included": True,
                    "entries": [
                        {
                            "title": f"Entry-{i:04d}",
                            "username": f"user{i:04d}",
                            "password": f"NewPass{i:04d}!y",
                        }
                        for i in range(self.ROWS)
                    ],
                }
            ),
            encoding="utf-8",
        )
        return str(path)

    def test_overwrite_only_progress_monotonic_with_midvalues(self, entry_mgr, tmp_path):
        """纯覆盖导入：进度单调、有 (15,100) 开区间中间值、终值 100。"""
        self._seed_existing(entry_mgr, self.ROWS)
        mgr = ImportExportManager(entry_mgr)
        events: list[tuple[int, int]] = []
        count = mgr.import_file(
            self._make_overwrite_import(tmp_path),
            "json",
            duplicate_action="overwrite",
            progress_callback=lambda current, total: events.append((current, total)),
        )
        assert count == self.ROWS

        values = [current for current, _total in events]
        assert all(total == 100 for _current, total in events)
        assert all(a <= b for a, b in zip(values, values[1:], strict=False)), (
            f"进度值须单调不减：{values}"
        )
        assert values[-1] == 100
        # 覆盖加密（15→70）与覆盖写入（70→100）均有中间值——不再冻结在 15%。
        assert any(15 < v < 70 for v in values), f"覆盖加密阶段无中间进度：{values}"
        assert any(70 < v < 100 for v in values), f"覆盖写入阶段无中间进度：{values}"

    def test_overwrite_only_updates_passwords(self, entry_mgr, tmp_path):
        """进度改造不改变覆盖语义：全量命中时密码被覆盖为新值。"""
        self._seed_existing(entry_mgr, self.ROWS)
        mgr = ImportExportManager(entry_mgr)
        count = mgr.import_file(
            self._make_overwrite_import(tmp_path),
            "json",
            duplicate_action="overwrite",
        )
        assert count == self.ROWS
        by_title = {e.title: e for e in decrypt_all_entries(entry_mgr)}
        assert len(by_title) == self.ROWS
        assert by_title["Entry-0000"].password == "NewPass0000!y"


# ======== 自定义字段公式清洗（SEC-045）========


class TestCustomFieldsFormulaSanitize:
    """导入入库边界对 custom_fields 的公式前缀清洗（SEC-045）。

    旧行为：``_sanitize_entry_formula_fields`` 显式字段集不含 custom_fields——
    非 password 类型字段的 name/value 含 ``=cmd|...`` 类公式值原样入库，详情
    面板「一键复制」与 CSV 导出（拼入 notes）使其直达粘贴执行。password 类型
    值豁免（密钥完整性优先，与 SEC-008/SEC-039 决策一致）。
    """

    @staticmethod
    def _import_with_custom_fields(entry_mgr, tmp_path, custom_fields):
        mgr = ImportExportManager(entry_mgr)
        path = tmp_path / "cf.json"
        path.write_text(
            json.dumps(
                {
                    "app": "CipherBox",
                    "secrets_included": True,
                    "entries": [
                        {
                            "title": "CF Entry",
                            "username": "u",
                            "password": "Pass1234!x",
                            "custom_fields": custom_fields,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        assert mgr.import_file(str(path), "json") == 1
        return decrypt_all_entries(entry_mgr)[0]

    def test_malicious_text_field_sanitized(self, entry_mgr, tmp_path):
        """text 字段的恶意公式 name/value 均被前置 ``'`` 转义入库。"""
        imported = self._import_with_custom_fields(
            entry_mgr,
            tmp_path,
            [
                {
                    "name": '+HYPERLINK("http://evil")',
                    "value": "=cmd|' /C calc'!A0",
                    "field_type": "text",
                }
            ],
        )
        field = imported.custom_fields[0]
        assert field.name == '\'+HYPERLINK("http://evil")'
        assert field.value == "'=cmd|' /C calc'!A0"

    def test_password_field_value_untouched(self, entry_mgr, tmp_path):
        """password 类型字段的值不清洗（密钥完整性优先，SEC-039 对称决策）。"""
        imported = self._import_with_custom_fields(
            entry_mgr,
            tmp_path,
            [{"name": "恢复代码", "value": "=CMD-secret-key", "field_type": "password"}],
        )
        field = imported.custom_fields[0]
        assert field.value == "=CMD-secret-key"
        assert field.name == "恢复代码"

    def test_benign_custom_fields_unchanged(self, entry_mgr, tmp_path):
        """无危险前缀的普通字段原样保留（不引入误伤）。"""
        imported = self._import_with_custom_fields(
            entry_mgr,
            tmp_path,
            [{"name": "邮箱", "value": "a@b.com", "field_type": "email"}],
        )
        field = imported.custom_fields[0]
        assert field.name == "邮箱"
        assert field.value == "a@b.com"


# ======== 覆盖失败索引对齐（QL-062）========


class TestOverwriteFailureIndexAlignment:
    """覆盖项预处理失败的索引 0 基对齐覆盖计划（QL-062）。

    旧行为：``prepare_overwrite_updates`` 以 1 基索引记录失败项，消费循环
    ``overwrite_plans[batch_idx]`` 按 0 基取值——末项失败时 IndexError 中止整次
    导入；非末项失败时警告/日志报告下一条目（source_idx 与条目整体偏移一条）。
    末项失败真实可达：覆盖合并后 custom_fields 数超上限（导入项 ≤100 项 +
    库内密码型字段增量，合并侧无计数校验）。
    """

    def test_last_item_prepare_failure_skips_item_not_import(self, entry_mgr, tmp_path, caplog):
        """末项覆盖预处理失败：导入整体成功、失败项正确报告、其余条目正常写入。"""
        mgr = ImportExportManager(entry_mgr)
        ok_id = entry_mgr.add_entry(Entry(title="Ok Target", username="u1", password="OkOld!1"))
        # 末项失败触发：secrets_included=False 的合并器保留库内密码型字段，
        # 98 个导入 text 字段 + 5 个库内 password 字段 = 103 > MAX_CUSTOM_FIELDS_PER_ENTRY
        bad_id = entry_mgr.add_entry(
            Entry(
                title="Bad Target",
                username="u2",
                password="BadOld!1",
                custom_fields=[CustomField(f"pin{i}", f"v{i}", "password") for i in range(5)],
            )
        )
        json_path = tmp_path / "overwrite.json"
        json_path.write_text(
            json.dumps(
                {
                    "app": "CipherBox",
                    "secrets_included": False,
                    "entries": [
                        {"title": "Ok Target", "username": "u1", "notes": "updated-ok"},
                        {
                            "title": "Bad Target",
                            "username": "u2",
                            "custom_fields": [
                                {"name": f"f{i}", "value": "v", "field_type": "text"}
                                for i in range(98)
                            ],
                        },
                    ],
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

        with caplog.at_level("WARNING", logger="src.business.managers.import_export"):
            count = mgr.import_file(str(json_path), "json", duplicate_action="overwrite")

        # 导入整体成功：首项覆盖写入、末项仅逐条跳过（旧行为在此 IndexError）
        assert count == 1
        ok = entry_mgr.get_entry(ok_id)
        assert ok is not None and ok.notes == "updated-ok"
        bad = entry_mgr.get_entry(bad_id)
        assert bad is not None
        assert bad.password == "BadOld!1"  # 失败目标未被覆盖
        assert len(bad.custom_fields) == 5
        # 失败报告指向正确的条目：导入数据中第 2 项、失败原因为合并后字段超限
        warnings = [r for r in caplog.records if "跳过覆盖" in r.getMessage()]
        assert len(warnings) == 1
        assert "第 2 个条目" in warnings[0].getMessage()
        assert "自定义字段过多" in warnings[0].getMessage()


# ======== 去重键空白归一（QL-063）========


class TestDedupKeyWhitespaceNormalization:
    """导入去重键两侧对称 strip().casefold()（QL-063）。

    旧行为：导入侧键 strip 后 casefold，库内侧（``get_entry_dedup_index`` 返回的
    meta.title/username）仅 casefold——JSON 导入路径 ``Entry.from_dict`` 不 strip
    标题（CSV 与 UI 会），库内可存在带首尾空白的标题，对这类条目 skip/overwrite
    匹配不上，产生本应被拦截的重复条目。
    """

    @staticmethod
    def _seed_padded_title(entry_mgr, tmp_path) -> None:
        """经 JSON 导入置入带首尾空白的标题条目（from_dict 不 strip，空白原样入库）。"""
        mgr = ImportExportManager(entry_mgr)
        path = tmp_path / "padded.json"
        path.write_text(
            json.dumps(
                {
                    "app": "CipherBox",
                    "secrets_included": True,
                    "entries": [
                        {"title": "  Padded  ", "username": "alice", "password": "OldPass!1"}
                    ],
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        assert mgr.import_file(str(path), "json") == 1
        # 守护测试前提：空白标题确实原样入库（若 from_dict 将来开始 strip，此处先失败）
        assert decrypt_all_entries(entry_mgr)[0].title == "  Padded  "

    @staticmethod
    def _write_plain_import(tmp_path, name: str) -> str:
        """构造与库内条目 strip 后同键（title 无空白、username 相同）的导入文件。"""
        path = tmp_path / name
        path.write_text(
            json.dumps(
                {
                    "app": "CipherBox",
                    "secrets_included": True,
                    "entries": [{"title": "Padded", "username": "alice", "password": "NewPass!2"}],
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        return str(path)

    def test_skip_matches_after_strip(self, entry_mgr, tmp_path):
        """skip 策略命中 strip 后同键的库内条目，跳过而非新建重复。"""
        self._seed_padded_title(entry_mgr, tmp_path)
        mgr = ImportExportManager(entry_mgr)
        count = mgr.import_file(
            self._write_plain_import(tmp_path, "plain_skip.json"), "json", duplicate_action="skip"
        )
        assert count == 0
        entries = decrypt_all_entries(entry_mgr)
        assert len(entries) == 1  # 未新建重复（旧行为：匹配不上 → 新建第 2 条）
        assert entries[0].password == "OldPass!1"  # 跳过保留原值

    def test_overwrite_matches_after_strip(self, entry_mgr, tmp_path):
        """overwrite 策略命中 strip 后同键的库内条目，覆盖而非新建重复。"""
        self._seed_padded_title(entry_mgr, tmp_path)
        mgr = ImportExportManager(entry_mgr)
        count = mgr.import_file(
            self._write_plain_import(tmp_path, "plain_overwrite.json"),
            "json",
            duplicate_action="overwrite",
        )
        assert count == 1
        entries = decrypt_all_entries(entry_mgr)
        assert len(entries) == 1  # 覆盖而非新建重复（旧行为：匹配不上 → 新建第 2 条）
        assert entries[0].password == "NewPass!2"
        assert entries[0].title == "Padded"

    @staticmethod
    def _seed_blank_title(entry_mgr, tmp_path) -> None:
        """经 JSON 导入置入纯空白标题条目（from_dict 不 strip，' ' 原样入库）。"""
        mgr = ImportExportManager(entry_mgr)
        path = tmp_path / "blank.json"
        path.write_text(
            json.dumps(
                {
                    "app": "CipherBox",
                    "secrets_included": True,
                    "entries": [{"title": " ", "username": "bob", "password": "OldPass!1"}],
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        assert mgr.import_file(str(path), "json") == 1
        # 守护测试前提：纯空白标题确实原样入库
        assert decrypt_all_entries(entry_mgr)[0].title == " "

    @staticmethod
    def _write_untitled_import(tmp_path, name: str) -> str:
        """构造无标题（title 缺省为空串）的同用户名导入文件。"""
        path = tmp_path / name
        path.write_text(
            json.dumps(
                {
                    "app": "CipherBox",
                    "secrets_included": True,
                    "entries": [{"username": "bob", "password": "NewPass!2"}],
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        return str(path)

    def test_skip_does_not_match_blank_title_against_untitled(self, entry_mgr, tmp_path):
        """纯空白标题库内条目不与无标题导入项匹配去重（QL-063 守卫补齐）。

        旧行为：``if title`` 守卫测未 strip 值（' ' 通过），键 strip 后成 ''，
        与无标题导入项的 ``('', username)`` 键匹配 → skip 丢行；守卫本意是
        「无标题不入去重」，须按 strip 后判空。
        """
        self._seed_blank_title(entry_mgr, tmp_path)
        mgr = ImportExportManager(entry_mgr)
        count = mgr.import_file(
            self._write_untitled_import(tmp_path, "untitled_skip.json"),
            "json",
            duplicate_action="skip",
        )
        # 无标题导入项不参与去重：正常新建，不因空白标题条目被跳过
        assert count == 1
        entries = decrypt_all_entries(entry_mgr)
        assert len(entries) == 2
        blank = [e for e in entries if e.title == " "]
        assert len(blank) == 1
        assert blank[0].password == "OldPass!1"  # 空白标题条目未被误动

    def test_overwrite_does_not_target_blank_title_entry(self, entry_mgr, tmp_path):
        """overwrite 策略不把无标题导入项覆盖到纯空白标题条目上（QL-063 守卫补齐）。"""
        self._seed_blank_title(entry_mgr, tmp_path)
        mgr = ImportExportManager(entry_mgr)
        count = mgr.import_file(
            self._write_untitled_import(tmp_path, "untitled_overwrite.json"),
            "json",
            duplicate_action="overwrite",
        )
        # 无标题导入项不参与去重：作为新增写入，不覆盖空白标题条目
        assert count == 1
        entries = decrypt_all_entries(entry_mgr)
        assert len(entries) == 2
        blank = [e for e in entries if e.title == " "]
        assert len(blank) == 1
        assert blank[0].password == "OldPass!1"  # 空白标题条目未被覆盖
