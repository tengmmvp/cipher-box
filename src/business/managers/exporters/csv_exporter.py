"""CSV 导出策略：Entry 列表 → CSV 文件写回调（含公式注入防护与自定义字段内联）。

原 ``ImportExportManager.export_to_csv`` 的格式化内联块拆出（ARCH-038）；manager
保留路径校验与原子写入编排骨架。CSV 为扁平格式，custom_fields 以
``[自定义字段] name=value; ...`` 内联追加到 notes 列。
"""

from __future__ import annotations

import csv
from collections.abc import Callable
from typing import IO

from ....models import Entry
from ...services.entry_batch_writer import PROGRESS_REPORT_EVERY
from .base import CSV_SECRET_COLUMNS, csv_safe

# CSV 列序（include_password=False 时移除两个密钥列）
_FIELDNAMES = [
    "title",
    "username",
    "password",
    "totp_secret",
    "url",
    "category",
    "tags",
    "notes",
    "is_favorite",
    "created_at",
    "updated_at",
]


def write_csv_entries(
    f: IO[str],
    entries: list[Entry],
    include_password: bool,
    cancel_check: Callable[[], bool] | None,
    progress: Callable[[int, int], None] | None,
) -> bool:
    """把条目逐行写入已打开的 CSV 文件（atomic_write 的写回调体）。

    公式注入转义仅应用于外流至表格软件的文本列；password/totp_secret 为密钥类
    列，跳过 ``'`` 前缀转义（SEC-039）——与导入侧 ``_sanitize_entry_formula_fields``
    「不清洗密钥字段」（SEC-008）的决策对称。

    进度度量「遍历位置」而非「成功写出数」（QL-055）：防御性 continue（当前类型
    系统下不可达）若按写出数计，``processed == total`` 终值永不可达，「终值恒上报」
    契约（PERF-070）silently 失效。取消时返回 False。
    """
    fieldnames = list(_FIELDNAMES)
    if not include_password:
        fieldnames.remove("password")
        fieldnames.remove("totp_secret")
    writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    total = len(entries)
    processed = 0
    for entry in entries:
        if cancel_check and cancel_check():
            return False
        if not entry.is_decrypted:
            processed += 1
            continue
        row = entry.to_dict(include_password=include_password)
        cf = entry.custom_fields
        if not isinstance(cf, list):
            processed += 1
            continue
        exported_fields = [
            field for field in cf if include_password or field.field_type != "password"
        ]
        cf_str = "; ".join(f"{f.name}={f.value}" for f in exported_fields)
        if row.get("notes"):
            if cf_str:
                row["notes"] += f"\n[自定义字段] {cf_str}"
        elif cf_str:
            row["notes"] = f"[自定义字段] {cf_str}"
        # 密钥类列（password/totp_secret）跳过公式前缀转义（SEC-039）：转义破坏
        # 密钥有效性，与导入侧不清洗密钥字段的决策对称；换行替换等保结构完整的
        # 处理由 csv_safe 无差别保留。
        writer.writerow(
            {
                key: csv_safe(value, escape_formula=key not in CSV_SECRET_COLUMNS)
                for key, value in row.items()
            }
        )
        processed += 1
        if progress is not None and (processed % PROGRESS_REPORT_EVERY == 0 or processed == total):
            progress(processed, total)
    if progress is not None and total == 0:
        progress(0, 0)  # 空导出也上报终值（UI 侧映射为 100，进度不留悬挂）
    return True
