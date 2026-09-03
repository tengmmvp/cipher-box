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


class TestExportWarningText:
    """含密码导出确认文案：CSV 格式附加公式注入豁免提示（SEC-039 取舍的用户告知）。

    password/totp_secret 为密钥类列不做公式前缀转义（exporters.base 的
    CSV_SECRET_COLUMNS 豁免），以 = + - @ 开头的密码在表格软件可能被当公式执行；
    提示仅在 CSV + 包含密码时出现（本组守护文案触发条件，接线守护见 wiring 测试）。
    """

    def test_csv_warning_contains_formula_note(self):
        """CSV 格式：警告文案含公式解析提示与「确定」确认问句。"""
        text = _ied_module.export_warning_text("CSV")
        assert "公式" in text
        assert "确定要继续吗" in text
        assert "明文形式" in text  # 既有明文风险提示保留

    def test_json_warning_has_no_formula_note(self):
        """JSON 格式：不附加公式提示（无密钥列豁免场景）。"""
        text = _ied_module.export_warning_text("JSON")
        assert "公式" not in text
        assert "明文形式" in text
