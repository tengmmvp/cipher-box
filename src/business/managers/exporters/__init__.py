"""导出格式策略类包。

每种导出格式（JSON/CSV）封装为独立的写回调策略函数，负责「Entry 列表序列化并
写入已打开的文件」；路径校验、原子写入、进度百分比映射等共享编排由
:class:`..import_export.ImportExportManager` 统一处理（ARCH-038，与 ``importers/``
导入策略包对称）。新增导出格式只需新增策略函数并在 manager 增加薄编排方法。
"""

from .base import csv_safe
from .csv_exporter import write_csv_entries
from .json_exporter import write_json_entries

# 包级 re-export 仅保留经包级导入消费的名字（MAINT-085 先例，MAINT-109 复核）：
# write_csv_entries/write_json_entries 由 import_export 与 test_export_progress 经
# ``from .exporters import ...`` 消费，csv_safe 由 test_csv_safe 经包级导入消费；
# CSV_SECRET_COLUMNS 的唯一消费方（csv_exporter）直接从 ``.base`` 导入，包级
# re-export 为零消费孤儿，已删（MAINT-109）。

__all__ = [
    "csv_safe",
    "write_csv_entries",
    "write_json_entries",
]
