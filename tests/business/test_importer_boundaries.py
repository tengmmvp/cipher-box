"""Importer 边界用例：超大字段、畸形结构、类型守卫、BOM 回归、别名隔离（聚焦 importer.parse 级）。"""

import json

import pytest

from src.business.managers.importers.bitwarden_importer import BitwardenImporter
from src.business.managers.importers.csv_importer import CsvImporter, KeePassCsvImporter
from src.business.managers.importers.json_importer import JsonImporter
from src.exceptions import ImportFormatError, ImportSizeError


def _write_json(tmp_path, name: str, data) -> str:
    path = tmp_path / name
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return str(path)


def _write_csv(tmp_path, name: str, text: str) -> str:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


class TestBitwardenBoundaries:
    """BitwardenImporter.parse 的边界守卫：login 非 dict、顶层结构、items 类型与 fields 元素。"""

    def test_login_as_list_does_not_crash(self, tmp_path):
        """login 为 list 经 ``_as_dict`` 守卫，不抛 AttributeError（最常见导入入口）。

        现有 robustness 测试覆盖了 card/identity/uris 的非 dict 守卫，唯独漏了 login。
        """
        path = _write_json(tmp_path, "b.json", {"items": [{"login": [1, 2, 3]}]})
        result = BitwardenImporter().parse(path)
        assert len(result.entries) == 1
        assert result.entries[0].username == ""
        assert result.entries[0].password == ""

    def test_top_level_list_rejected(self, tmp_path):
        path = _write_json(tmp_path, "b.json", [{"items": []}])
        with pytest.raises(ImportFormatError):
            BitwardenImporter().parse(path)

    def test_items_non_list_rejected(self, tmp_path):
        path = _write_json(tmp_path, "b.json", {"items": {"not": "list"}})
        with pytest.raises(ImportFormatError):
            BitwardenImporter().parse(path)

    def test_empty_items_returns_empty(self, tmp_path):
        path = _write_json(tmp_path, "b.json", {"items": []})
        result = BitwardenImporter().parse(path)
        assert result.entries == []

    def test_field_non_dict_skipped(self, tmp_path):
        """fields 中混入非 dict 元素被跳过，仅保留合法字段。"""
        path = _write_json(
            tmp_path,
            "b.json",
            {
                "items": [{"fields": [123, {"name": "a", "value": "b"}]}],
            },
        )
        result = BitwardenImporter().parse(path)
        assert len(result.entries) == 1
        cf = result.entries[0].custom_fields
        assert len(cf) == 1
        assert cf[0].name == "a"


class TestJsonBoundaries:
    """JsonImporter.parse 的格式守卫：顶层结构、app 标识、secrets_included 类型与空 entries。"""

    def test_top_level_list_rejected(self, tmp_path):
        path = _write_json(tmp_path, "b.json", [{"app": "CipherBox"}])
        with pytest.raises(ImportFormatError):
            JsonImporter().parse(path)

    def test_top_level_string_rejected(self, tmp_path):
        path = tmp_path / "b.json"
        path.write_text('"just a string"', encoding="utf-8")
        with pytest.raises(ImportFormatError):
            JsonImporter().parse(path)

    def test_wrong_app_rejected(self, tmp_path):
        path = _write_json(
            tmp_path,
            "b.json",
            {
                "app": "Other",
                "secrets_included": True,
                "entries": [],
            },
        )
        with pytest.raises(ImportFormatError):
            JsonImporter().parse(path)

    def test_secrets_included_wrong_type_rejected(self, tmp_path):
        """secrets_included 非 bool（如 int 1）被 ``type(...) is not bool`` 拒绝。"""
        path = _write_json(
            tmp_path,
            "b.json",
            {
                "app": "CipherBox",
                "secrets_included": 1,
                "entries": [],
            },
        )
        with pytest.raises(ImportFormatError):
            JsonImporter().parse(path)

    def test_empty_entries_with_valid_header(self, tmp_path):
        """合法 header（app/secrets_included）+ 空 entries 返回空，不抛错。"""
        path = _write_json(
            tmp_path,
            "b.json",
            {
                "app": "CipherBox",
                "version": 1,
                "secrets_included": True,
                "entries": [],
            },
        )
        result = JsonImporter().parse(path)
        assert result.entries == []


class TestCsvBoundaries:
    """CsvImporter.parse 的边界：BOM 剥离、超长字段中止与行字段缺失容忍。"""

    def test_bom_stripped(self, tmp_path):
        """utf-8-sig 剥离 BOM：含 BOM 的 CSV 正常解析（回归保护，防改回 utf-8）。"""
        # write_text('﻿...', encoding='utf-8') 将 BOM 写为字节；CsvImporter 用
        # utf-8-sig 读取剥离，title 列命中别名。
        text = "﻿title,username,password\nGitHub,user,pw\n"
        path = _write_csv(tmp_path, "b.csv", text)
        result = CsvImporter().parse(path)
        assert len(result.entries) == 1
        assert result.entries[0].title == "GitHub"

    def test_overlong_field_raises(self, tmp_path):
        """超长字段（title > 1024）整批中止（ImportSizeError）。"""
        text = f"title,username,password\n{'x' * 2000},u,p\n"
        path = _write_csv(tmp_path, "b.csv", text)
        with pytest.raises(ImportSizeError):
            CsvImporter().parse(path)

    def test_row_fewer_fields_than_header(self, tmp_path):
        """行字段数少于表头时缺失值按空串处理，不崩。"""
        text = "title,username,password\nGitHub\n"
        path = _write_csv(tmp_path, "b.csv", text)
        result = CsvImporter().parse(path)
        assert len(result.entries) == 1
        assert result.entries[0].title == "GitHub"
        assert result.entries[0].username == ""


class TestKeePassAliasIsolation:
    """固化 KeePass 与 CSV 列别名的隔离边界，防 _build_col_map 重构时互相误匹配。"""

    def test_bitwarden_specific_aliases_not_matched(self, tmp_path):
        """KeePass 严格别名不命中 Bitwarden/CSV 专有列名（name/login_uri/login_password）。

        固化 ``_KEEPASS_COLUMN_ALIASES``（单元素严格）与 ``_CSV_COLUMN_ALIASES``（含
        name/login_uri/login_password 等）的隔离边界——防 ``_build_col_map`` 重构时
        KeePass 误匹配 CSV 别名，导致 Bitwarden CSV 喂 keepass_csv 格式错位入库。
        """
        text = "name,login_uri,login_password\nGitHub,http://x,pw\n"
        path = _write_csv(tmp_path, "b.csv", text)
        result = KeePassCsvImporter().parse(path)
        assert len(result.entries) == 1
        entry = result.entries[0]
        assert entry.title == ""
        assert entry.url == ""
        assert entry.password == ""
