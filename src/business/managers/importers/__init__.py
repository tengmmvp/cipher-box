"""导入格式策略类包。

每种导入格式（JSON/CSV/KeePass CSV/Bitwarden JSON）封装为独立的 Importer
策略类，负责「文件解析为 Entry 列表」与「覆盖合并器」；事务、去重、分类、
写入等共享编排由 :class:`..import_export.ImportExportManager` 统一处理。
新增格式只需新增策略类并在 ``_IMPORTERS`` 注册表登记，即可经 ``import_file``
单一 dispatch 导入，无需为每格式编写独立方法。
"""

from .base import FormatImporter, ParsedImport
from .bitwarden_importer import BitwardenImporter
from .csv_importer import CsvImporter, KeePassCsvImporter
from .json_importer import JsonImporter

__all__ = [
    "BitwardenImporter",
    "CsvImporter",
    "FormatImporter",
    "JsonImporter",
    "KeePassCsvImporter",
    "ParsedImport",
]
