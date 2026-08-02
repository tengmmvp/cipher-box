"""Chrome/Edge CSV 导入测试：固化 name/url/username/password 列到内部字段的映射。"""

import pytest

from src.business.managers.import_export import ImportExportManager
from src.exceptions import ImportFormatError


def test_import_from_chrome_csv_maps_columns(entry_mgr, tmp_path):
    mgr = ImportExportManager(entry_mgr)
    csv_path = tmp_path / "chrome.csv"
    csv_path.write_text(
        "name,url,username,password\n"
        "GitHub,https://github.com,alice,Pass123!\n"
        "Gmail,https://gmail.com,bob,Secret456@\n",
        encoding="utf-8",
    )

    count = mgr.import_file(str(csv_path), "chrome_csv")

    assert count == 2
    entries = entry_mgr.get_entries()
    by_title = {e.title: e for e in entries}
    assert set(by_title) == {"GitHub", "Gmail"}
    gh = by_title["GitHub"]
    assert gh.username == "alice"
    assert gh.url == "https://github.com"
    assert gh.password == "Pass123!"
    gm = by_title["Gmail"]
    assert gm.username == "bob"
    assert gm.password == "Secret456@"


def test_import_from_chrome_csv_empty(entry_mgr, tmp_path):
    """仅含表头的空 CSV 导入返回 0，不产生条目。"""
    mgr = ImportExportManager(entry_mgr)
    csv_path = tmp_path / "empty.csv"
    csv_path.write_text("name,url,username,password\n", encoding="utf-8")

    assert mgr.import_file(str(csv_path), "chrome_csv") == 0
    assert entry_mgr.get_entries() == []


def test_import_rejects_missing_default_category(entry_mgr, tmp_path):
    mgr = ImportExportManager(entry_mgr)
    csv_path = tmp_path / "chrome.csv"
    csv_path.write_text(
        "name,url,username,password\nGitHub,https://github.com,alice,Pass123!\n",
        encoding="utf-8",
    )

    with pytest.raises(ImportFormatError, match="默认分类不存在"):
        mgr.import_file(str(csv_path), "chrome_csv", default_category_id=999_999)
