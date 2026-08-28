"""CipherBox JSON 导出策略：Entry 列表 → CipherBox JSON 文件写回调。

原 ``ImportExportManager.export_to_json`` 的格式化内联块拆出（ARCH-038，镜像
``importers/`` 策略包的对称结构）；manager 保留路径校验与原子写入编排骨架。
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import IO

from ....models import Entry
from ....utils.format import utc_now_iso
from ...services.entry_batch_writer import PROGRESS_REPORT_EVERY


def write_json_entries(
    f: IO[str],
    entries: list[Entry],
    include_password: bool,
    cancel_check: Callable[[], bool] | None,
    progress: Callable[[int, int], None] | None,
) -> bool:
    """把条目流式写入已打开的 JSON 文件（atomic_write 的写回调体）。

    进度契约（PERF-070）：``progress`` 提供时按已写条目数上报 ``(written, total)``，
    每 ``PROGRESS_REPORT_EVERY`` 条节流、终值恒上报（空导出上报 ``(0, 0)``，UI 侧
    映射为 100 不留悬挂）。取消时返回 False（调用方 atomic_write 不落盘）。
    """
    header = {
        "app": "CipherBox",
        "exported_at": utc_now_iso(),
        "secrets_included": include_password,
    }
    f.write("{\n")
    for key, value in header.items():
        comma = ","  # header 后必跟 entries 数组，故每项后都加逗号
        f.write(f"  {json.dumps(key)}: {json.dumps(value, ensure_ascii=False)}{comma}\n")
    f.write('  "entries": [')
    first = True
    total = len(entries)
    written = 0
    for entry in entries:
        if cancel_check and cancel_check():
            return False
        if not first:
            f.write(",")
        f.write("\n")
        serialized = json.dumps(
            entry.to_dict(include_password=include_password),
            indent=2,
            ensure_ascii=False,
        )
        f.write("\n".join(f"    {line}" for line in serialized.splitlines()))
        first = False
        written += 1
        if progress is not None and (written % PROGRESS_REPORT_EVERY == 0 or written == total):
            progress(written, total)
    if progress is not None and total == 0:
        progress(0, 0)  # 空导出也上报终值（UI 侧映射为 100，进度不留悬挂）
    if not first:
        f.write("\n")
    f.write("  ]\n}\n")
    return True
