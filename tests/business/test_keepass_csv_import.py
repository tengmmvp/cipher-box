"""KeePass CSV 导入测试。

验证 ``import_file('keepass_csv')`` 经 ``KeePassCsvImporter`` 正确映射
KeePass 导出 CSV 的 ``Title/UserName/Password/URL/Notes/Group`` 列，
其中 ``Group`` 列映射到内部 ``category_name`` 字段（由 ``_KEEPASS_COLUMN_ALIASES``
声明、经 ``_build_col_map`` 大小写不敏感匹配）。与 ``test_chrome_csv_import.py``
平行，固化列名映射以防止列别名回归。
"""

from src.business.managers.import_export import ImportExportManager
from tests.helpers import decrypt_all_entries


def test_import_from_keepass_csv_maps_columns(entry_mgr, tmp_path):
    """KeePass CSV 的 Title/UserName/Password/URL/Notes/Group 列应正确映射。

    KeePass 桌面导出列为首字母大写形式；``_KEEPASS_COLUMN_ALIASES`` 仅声明小写
    别名，经 ``_build_col_map`` 的 ``.lower().strip()`` 归一化后仍能命中。
    ``Group`` 列经 ``entry_key_map`` 映射到 ``category_name``，导入时由
    ``_resolve_category`` 创建对应分类。
    """
    mgr = ImportExportManager(entry_mgr)
    csv_path = tmp_path / "keepass.csv"
    csv_path.write_text(
        "Group,Title,UserName,Password,URL,Notes\n"
        "社交,GitHub,alice,Pass123!,https://github.com,账号备注\n"
        "工作,Gmail,bob,Secret456@,https://gmail.com,\n",
        encoding="utf-8",
    )

    count = mgr.import_file(str(csv_path), "keepass_csv")

    assert count == 2
    entries = decrypt_all_entries(entry_mgr)
    by_title = {e.title: e for e in entries}
    assert set(by_title) == {"GitHub", "Gmail"}

    gh = by_title["GitHub"]
    assert gh.username == "alice"
    assert gh.password == "Pass123!"
    assert gh.url == "https://github.com"
    assert gh.notes == "账号备注"
    # Group 列映射到 category_name，并在导入时创建对应分类
    assert gh.category_name == "社交"

    gm = by_title["Gmail"]
    assert gm.username == "bob"
    assert gm.password == "Secret456@"
    assert gm.category_name == "工作"
    assert gm.notes == ""

    # 分类经 _resolve_category 创建（category_name 能回填依赖分类已落库）
    category_names = {c.name for c in entry_mgr.categories.get_categories()}
    assert {"社交", "工作"}.issubset(category_names)


def test_import_from_keepass_csv_without_group(entry_mgr, tmp_path):
    """无 Group 列的 KeePass CSV 仍可导入，条目不带分类。

    ``_KEEPASS_COLUMN_ALIASES`` 不含其他指向分类的别名，缺 Group 列时
    ``col_map`` 不含分类键，Entry 以默认 ``category_name=''`` 构造。
    """
    mgr = ImportExportManager(entry_mgr)
    csv_path = tmp_path / "keepass_no_group.csv"
    csv_path.write_text(
        "Title,UserName,Password,URL,Notes\nGitHub,alice,Pass123!,https://github.com,memo\n",
        encoding="utf-8",
    )

    count = mgr.import_file(str(csv_path), "keepass_csv")

    assert count == 1
    entries = decrypt_all_entries(entry_mgr)
    assert len(entries) == 1
    entry = entries[0]
    assert entry.title == "GitHub"
    assert entry.username == "alice"
    assert entry.password == "Pass123!"
    assert entry.url == "https://github.com"
    assert entry.notes == "memo"
    assert entry.category_name == ""


def test_import_from_keepass_csv_empty(entry_mgr, tmp_path):
    """仅含表头的空 KeePass CSV 导入返回 0，不产生条目。"""
    mgr = ImportExportManager(entry_mgr)
    csv_path = tmp_path / "empty.csv"
    csv_path.write_text(
        "Group,Title,UserName,Password,URL,Notes\n",
        encoding="utf-8",
    )

    assert mgr.import_file(str(csv_path), "keepass_csv") == 0
    assert decrypt_all_entries(entry_mgr) == []
