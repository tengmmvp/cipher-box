"""导出格式策略类包。

每种导出格式（JSON/CSV）封装为独立的写回调策略函数，负责「Entry 列表序列化并
写入已打开的文件」；路径校验、原子写入、进度百分比映射等共享编排由
:class:`..import_export.ImportExportManager` 统一处理（ARCH-038，与 ``importers/``
导入策略包对称）。新增导出格式只需新增策略函数并在 manager 增加薄编排方法。
"""

from .base import CSV_SECRET_COLUMNS, csv_safe
from .csv_exporter import write_csv_entries
from .json_exporter import write_json_entries

__all__ = [
    "CSV_SECRET_COLUMNS",
    "csv_safe",
    "write_csv_entries",
    "write_json_entries",
]
