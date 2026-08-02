"""ImportExportDialog 接线守护：UI 格式键映射与业务层 import_file 一致（MAINT-013）。

import_export_dialog 经 ``_IMPORT_FORMAT_KEYS`` 把 UI 格式名映射到 ``import_file`` 的
``format_key``，再经 ``ImportExportManager._IMPORTERS`` 注册表 dispatch 到策略类。映射的
``format_key`` 与注册表键漂移会在运行时抛 ``ValueError``（不支持格式）。此处于收集期静态
守护「UI 格式选项 ↔ ``format_key`` 映射 ↔ ``_IMPORTERS`` 注册表」三者一致，防重构时漏改映射。
"""

from src.business.managers.import_export import ImportExportManager
from src.ui.dialogs import import_export_dialog as _ied_module


def test_import_format_keys_covered_by_importers():
    """_IMPORT_FORMAT_KEYS 每个 format_key 在 _IMPORTERS 注册表存在（dispatch 守护）。"""
    for fmt, format_key in _ied_module._IMPORT_FORMAT_KEYS.items():
        assert format_key in ImportExportManager._IMPORTERS, (
            f"_IMPORT_FORMAT_KEYS[{fmt!r}] -> {format_key!r} 不在 _IMPORTERS 注册表，"
            f"import_file 会在运行时抛 ValueError"
        )


def test_import_filters_and_format_keys_share_keys():
    """_IMPORT_FILTERS（UI 格式选项）与 _IMPORT_FORMAT_KEYS（format_key 映射）键集一致。"""
    assert set(_ied_module._IMPORT_FILTERS) == set(_ied_module._IMPORT_FORMAT_KEYS)
