#!/usr/bin/env python3
"""审计编号索引校验脚本（docs/audit_codes.md 与代码的一致性把关）。

用法（与 CI 同源）::

    uv run python scripts/verify_audit_codes.py

校验内容
--------
1. **代码侧计数**：统计每个审计编号（``ARCH|MAINT|PERF|QL|SEC-NNN``）在
   ``src/**/*.py`` 与 ``tests/**/*.py`` 的实际出现次数（等价 ``rg -o`` 逐次计数，
   非按行计数），并检测旧格式残留（未填充两位数、``PF-`` 前缀）。
2. **文档侧解析**：各分区标题的「（N 项）」声明、表格行（新编号 / 处数单元格）、
   「编号约定」中的当前下一可用号声明。
3. **比对规则**（任一不符即差异）：
   - 代码有号、文档缺登 → 差异（新增编号须先登记再引用）；
   - 处数单元格为纯数字 → 必须等于 src 实际计数（tests 计数不入口径）；
   - 处数单元格为 ``0（位置注记）`` → src 计数必须为 0，且该编号须在仓库内
     （docs/audit_codes.md 之外）至少出现 1 次，防位置注记过期；
   - 裸 ``0``（已放弃 / 已退役 / 纯约定豁免类）→ 仅要求 src 计数为 0；
   - 分区标题「（N 项）」必须等于该分区表格行数；
   - 「当前下一可用」必须等于该维度最大已用号 +1（历史断档不回填）；
   - 分区内编号须严格升序、全文档不得重复、编号前缀须与所在分区一致。

输出差异清单；存在差异时以退出码 1 结束（供 CI gate），零差异退出码 0。

实现约束：纯标准库；路径一律 pathlib；不调用平台特定命令，Windows / Linux /
macOS 行为一致。扫描跳过 ``.git`` / ``.venv`` / ``__pycache__`` 等目录及二进制
文件（按扩展名白名单读取文本）。
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# 输出含中文差异信息：Windows 下管道默认走区域代码页（cp936/cp1252），中文可能
# 编码失败或乱码；统一重配为 UTF-8（GitHub Actions 日志按 UTF-8 解码，三平台一致）
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):  # 非 TextIOWrapper 等极端场景，容忍降级
            pass

ROOT = Path(__file__).resolve().parents[1]
DOC_PATH = ROOT / "docs" / "audit_codes.md"

DIMENSIONS = ("ARCH", "MAINT", "PERF", "QL", "SEC")

# 目录名黑名单（版本库元数据 / 虚拟环境 / 各类缓存，均与平台无关）
SKIP_DIRS = {
    ".git",
    ".venv",
    ".venv-windows",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".pyright",
    "dist",
    "build",
    ".tox",
    ".eggs",
}

# 仓库全域扫描（位置注记复核用）仅读取文本类扩展名，避免读入二进制
TEXT_SUFFIXES = {
    ".py",
    ".pyi",
    ".md",
    ".txt",
    ".yml",
    ".yaml",
    ".toml",
    ".cfg",
    ".ini",
    ".json",
    ".html",
    ".htm",
    ".js",
    ".css",
    ".qss",
    ".sh",
    ".ps1",
}

# 规范编号：三位零填充；旧格式（1-2 位数字）单独检测
CODE_RE = re.compile(r"\b(?:ARCH|MAINT|PERF|QL|SEC)-\d{3}\b")
LEGACY_RE = re.compile(r"\b(?:ARCH|MAINT|PERF|QL|SEC)-\d{1,2}\b|\bPF-\d+")

SECTION_RE = re.compile(r"^### (ARCH|MAINT|PERF|QL|SEC) — .*?（(\d+) 项）\s*$")
ROW_RE = re.compile(r"^\|\s*`((?:ARCH|MAINT|PERF|QL|SEC)-\d{3})`\s*\|")
# 处数单元格两种合法形态：纯数字 / 0（位置注记）
COUNT_PLAIN_RE = re.compile(r"^\d+$")
COUNT_ANNOTATED_RE = re.compile(r"^0（.+）$")
# 「编号约定」中的下一可用号声明（允许跨行折行：分隔符为空白 / 反引号）
NEXT_AVAILABLE_RE = re.compile(
    r"当前下一可用[\s:：`]*ARCH-(\d{3})[\s/`]*MAINT-(\d{3})[\s/`]*PERF-(\d{3})"
    r"[\s/`]*QL-(\d{3})[\s/`]*SEC-(\d{3})"
)


def iter_files(base: Path, suffixes: set[str] | None = None):
    """遍历 base 下文本文件，跳过 SKIP_DIRS 目录与（可选）非目标扩展名。"""
    if not base.is_dir():
        return
    for path in sorted(base.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(base).parts):
            continue
        if suffixes is not None and path.suffix not in suffixes:
            continue
        yield path


def count_codes_in_tree(base: Path) -> dict[str, int]:
    """统计 base 树内 .py 文件中各编号的出现次数（rg -o 语义）。"""
    counts: dict[str, int] = {}
    for path in iter_files(base, {".py"}):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for code in CODE_RE.findall(text):
            counts[code] = counts.get(code, 0) + 1
    return counts


def scan_repo_occurrences() -> dict[str, int]:
    """仓库全域（docs/audit_codes.md 自身除外）各编号出现次数，供位置注记复核。"""
    counts: dict[str, int] = {}
    for path in iter_files(ROOT, TEXT_SUFFIXES):
        if path.resolve() == DOC_PATH.resolve():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for code in CODE_RE.findall(text):
            counts[code] = counts.get(code, 0) + 1
    return counts


def parse_doc() -> tuple[dict[str, dict], dict[str, list[tuple[str, str]]], tuple[str, ...] | None]:
    """解析 audit_codes.md。

    Returns:
        (sections, rows, next_available_groups)
        sections: 分区前缀 -> {"declared": 标题声明项数}
        rows: 分区前缀 -> [(编号, 处数单元格原文), ...]（按出现顺序）
        next_available_groups: 下一可用号声明按 ARCH/MAINT/PERF/QL/SEC 顺序的
            号码字符串元组（未匹配为 None）
    """
    sections: dict[str, dict] = {}
    rows: dict[str, list[tuple[str, str]]] = {dim: [] for dim in DIMENSIONS}
    doc_text = DOC_PATH.read_text(encoding="utf-8")
    next_available_match = NEXT_AVAILABLE_RE.search(doc_text)
    next_available_groups = next_available_match.groups() if next_available_match else None
    current: str | None = None

    for line in doc_text.splitlines():
        header = SECTION_RE.match(line)
        if header:
            current = header.group(1)
            sections[current] = {"declared": int(header.group(2))}
            continue
        if current is None:
            continue
        row = ROW_RE.match(line)
        if row:
            cells = [c.strip() for c in line.split("|")]
            # cells[0] 为行首空串，cells[1]=编号 cells[2]=旧编号 cells[3]=处数
            rows[current].append((row.group(1), cells[3] if len(cells) > 3 else ""))
    return sections, rows, next_available_groups


def main() -> int:
    src_counts = count_codes_in_tree(ROOT / "src")
    tests_counts = count_codes_in_tree(ROOT / "tests")
    repo_counts = scan_repo_occurrences()
    sections, rows, next_available_groups = parse_doc()

    problems: list[str] = []

    # ---- 旧格式残留检测（src / tests 的 .py 内不应再有未填充或 PF- 前缀形态）----
    for label, base in (("src", ROOT / "src"), ("tests", ROOT / "tests")):
        for path in iter_files(base, {".py"}):
            text = path.read_text(encoding="utf-8", errors="ignore")
            problems.extend(
                f"旧格式编号残留：{match.group(0)}（{label}/{path.relative_to(ROOT)}）"
                for match in LEGACY_RE.finditer(text)
            )

    registered: dict[str, str] = {}  # 编号 -> 所在分区

    # ---- 分区内行级校验 ----
    for dim in DIMENSIONS:
        dim_rows = rows.get(dim, [])
        info = sections.get(dim)
        if info is None:
            problems.append(f"缺少分区：### {dim} — …（N 项）标题未找到")
            continue
        if info["declared"] != len(dim_rows):
            problems.append(
                f"{dim} 分区项数不符：标题声明 {info['declared']}，实际 {len(dim_rows)} 行"
            )
        prev_num = 0
        for code, cell in dim_rows:
            num = int(code.split("-")[1])
            prefix = code.split("-")[0]
            if prefix != dim:
                problems.append(f"{code} 前缀与所在分区 {dim} 不符")
            if num <= prev_num:
                problems.append(
                    f"{dim} 分区编号未严格升序或重复：{code}（前一号尾数 {prev_num:03d}）"
                )
            prev_num = num
            if code in registered:
                problems.append(f"{code} 重复登记（{registered[code]} 与 {dim}）")
            registered[code] = dim

            src_n = src_counts.get(code, 0)
            if COUNT_PLAIN_RE.match(cell):
                doc_n = int(cell)
                if doc_n != src_n:
                    problems.append(
                        f"{code} 处数不符：文档 {doc_n}，src 实际 {src_n}"
                        f"（tests 另有 {tests_counts.get(code, 0)}，不入口径）"
                    )
            elif COUNT_ANNOTATED_RE.match(cell):
                if src_n != 0:
                    problems.append(f"{code} 处数单元格为「0（位置注记）」但 src 实际 {src_n} 处")
                repo_n = repo_counts.get(code, 0)
                if repo_n == 0:
                    problems.append(f"{code} 位置注记过期：仓库内（本文档之外）已无任何引用")
            else:
                problems.append(f"{code} 处数单元格格式无法识别：{cell!r}")

    # ---- 代码有号、文档缺登 ----
    problems.extend(
        f"{code} 代码有号、文档缺登（src={src_counts.get(code, 0)}，"
        f"tests={tests_counts.get(code, 0)}）——新增编号须先登记索引"
        for code in sorted(set(src_counts) | set(tests_counts))
        if code not in registered
    )

    # ---- 下一可用号校验（新编号 = 最大已用号 + 1，断档不回填）----
    expected_next: dict[str, int] = {}
    for dim in DIMENSIONS:
        nums = [int(c.split("-")[1]) for c in registered if c.startswith(dim + "-")]
        expected_next[dim] = (max(nums) + 1) if nums else 1
    if next_available_groups is None:
        problems.append(
            "「编号约定」缺少『当前下一可用』声明行（格式：当前下一可用：`ARCH-NNN / MAINT-NNN / …`）"
        )
    else:
        for dim, claimed_n in zip(DIMENSIONS, (int(g) for g in next_available_groups), strict=True):
            if claimed_n != expected_next[dim]:
                problems.append(
                    f"{dim} 下一可用号不符：文档声明 {dim}-{claimed_n:03d}，"
                    f"按最大已用号 +1 应为 {dim}-{expected_next[dim]:03d}"
                )

    # ---- 输出 ----
    total_rows = sum(len(v) for v in rows.values())
    if problems:
        print(f"审计编号索引校验失败（{len(problems)} 项差异）：")
        for p in problems:
            print(f"  [差异] {p}")
        print(
            f"\n已登记 {len(registered)} 个编号（"
            + " / ".join(f"{dim} {len(rows[dim])}" for dim in DIMENSIONS)
            + f"）；详见 docs/audit_codes.md 与 scripts/verify_audit_codes.py。"
        )
        return 1

    print("审计编号索引校验通过，零差异。")
    print(
        "  已登记编号 "
        + "，".join(f"{dim} {len(rows[dim])} 项" for dim in DIMENSIONS)
        + f"（共 {total_rows} 项）"
    )
    print("  下一可用 " + " / ".join(f"{dim}-{expected_next[dim]:03d}" for dim in DIMENSIONS))
    print(
        f"  计数口径 src/**/*.py：{sum(src_counts.values())} 处引用，"
        f"{len(src_counts)} 个编号；tests/**/*.py 另有 "
        f"{sum(tests_counts.values())} 处（不入口径，仅用于缺登检测）。"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
