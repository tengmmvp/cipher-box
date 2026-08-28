"""导出写回调的进度契约守护测试（PERF-070 / QL-055）。

守护 ``exporters.write_json_entries`` / ``write_csv_entries`` 的进度上报契约：
``progress(done, total)`` 按已处理条目数上报、每 PROGRESS_REPORT_EVERY 条节流、
**终值恒上报**（含空导出 ``(0, 0)`` 与跳过条目场景）——QL-055 曾因防御性
continue 按「成功写出数」计量使终值永不可达，契约 silently 失效。
"""

import csv
import io
import json
from types import SimpleNamespace
from typing import Any

import pytest

from src.business.managers.exporters import write_csv_entries, write_json_entries
from src.business.services.entry_batch_writer import PROGRESS_REPORT_EVERY
from src.models import CustomField, Entry


def _make_entry(i: int) -> Entry:
    return Entry(
        title=f"条目{i}",
        username=f"user{i}",
        password=f"pw{i}",
        custom_fields=[CustomField(name="备注", value=f"v{i}")],
    )


def _collect_progress() -> tuple[list[tuple[int, int]], Any]:
    calls: list[tuple[int, int]] = []

    def progress(done: int, total: int) -> None:
        calls.append((done, total))

    return calls, progress


class TestJsonExportProgress:
    """write_json_entries 的进度契约。"""

    def test_terminal_value_reported(self):
        """节流下终值 (total, total) 恒上报。"""
        entries = [_make_entry(i) for i in range(PROGRESS_REPORT_EVERY + 5)]
        calls, progress = _collect_progress()

        with io.StringIO() as f:
            ok = write_json_entries(f, entries, True, None, progress)

        assert ok is True
        assert calls[-1] == (len(entries), len(entries))

    def test_empty_export_reports_zero_terminal(self):
        """空导出上报 (0, 0)，进度不留悬挂。"""
        calls, progress = _collect_progress()
        with io.StringIO() as f:
            write_json_entries(f, [], False, None, progress)
        assert calls == [(0, 0)]

    def test_cancel_returns_false(self):
        """cancel_check 为真时立即返回 False。"""
        with io.StringIO() as f:
            ok = write_json_entries(f, [_make_entry(0)], False, lambda: True, None)
        assert ok is False


class TestCsvExportProgress:
    """write_csv_entries 的进度契约（QL-055 核心：跳过条目也推进 processed）。"""

    def test_terminal_value_with_skipped_entries(self):
        """含不可达防御分支的跳过条目（is_decrypted=False）时终值仍可达。

        Entry 的 is_decrypted 恒为 True（类型系统下该分支不可达），用
        SimpleNamespace 模拟未来调用方变化触达 continue 路径，守护
        「processed 度量遍历位置」的计量语义不回退为「成功写出数」。
        """
        real = _make_entry(0)
        skipped = SimpleNamespace(
            **{
                "is_decrypted": False,
                "custom_fields": None,
                "to_dict": lambda **kw: {},
            }
        )
        real2 = _make_entry(1)
        calls, progress = _collect_progress()

        with io.StringIO(newline="") as f:
            ok = write_csv_entries(f, [real, skipped, real2], False, None, progress)

        assert ok is True
        # 终值为 (3, 3)：跳过条目计入 processed，不因写出数 < total 而悬挂
        assert calls[-1] == (3, 3)

    def test_csv_output_roundtrip_valid(self):
        """写回调产出可被 csv.DictReader 解析（防进度改造破坏写出主体）。"""
        entries = [_make_entry(i) for i in range(3)]
        with io.StringIO(newline="") as f:
            write_csv_entries(f, entries, True, None, None)
            f.seek(0)
            rows = list(csv.DictReader(f))
        assert len(rows) == 3
        assert rows[0]["title"] == "条目0"

    def test_json_output_roundtrip_valid(self):
        """JSON 写回调产出可解析且条目数一致。"""
        entries = [_make_entry(i) for i in range(2)]
        with io.StringIO() as f:
            write_json_entries(f, entries, False, None, None)
            f.seek(0)
            data = json.load(f)
        assert data["app"] == "CipherBox"
        assert len(data["entries"]) == 2


@pytest.mark.parametrize("writer", [write_json_entries, write_csv_entries])
def test_progress_none_accepted(writer):
    """progress=None（无进度消费方）不抛异常。"""
    entries = [_make_entry(0)]
    with io.StringIO(newline="") as f:
        ok = writer(f, entries, False, None, None)
    assert ok is True
