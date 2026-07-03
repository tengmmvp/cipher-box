"""ImportExportDialog 接线守护：动态分派方法名与业务层一致（MAINT-3）。

import_export_dialog 经 ``getattr(self._import_export, method_name)`` 动态分派导入方法，
方法名（``_IMPORT_HANDLERS`` 映射）与 ``ImportExportManager`` 实际方法漂移会在运行时
抛 ``AttributeError``。此处于收集期静态守护「格式选项 ↔ 处理器映射 ↔ 业务方法」三者
一致，防重构改名时漏改映射——该动态分派是审查点名的重构脆弱点。
"""

from src.business.managers.import_export import ImportExportManager
from src.ui.dialogs import import_export_dialog as _ied_module
from src.ui.dialogs.import_export_dialog import ImportExportDialog


def test_import_handlers_map_to_real_methods():
    """_IMPORT_HANDLERS 每个方法名在 ImportExportManager 真实存在（动态分派守护）。"""
    for fmt, method_name in ImportExportDialog._IMPORT_HANDLERS.items():
        assert hasattr(ImportExportManager, method_name), (
            f"_IMPORT_HANDLERS[{fmt!r}] -> {method_name!r} 在 ImportExportManager 不存在，"
            f"动态分派会在运行时抛 AttributeError"
        )


def test_import_filters_and_handlers_share_format_keys():
    """_IMPORT_FILTERS（UI 格式选项）与 _IMPORT_HANDLERS（处理器）键集一致。"""
    assert set(_ied_module._IMPORT_FILTERS) == set(ImportExportDialog._IMPORT_HANDLERS)
