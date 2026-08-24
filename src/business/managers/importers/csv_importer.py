"""CSV / KeePass CSV 导入策略。

两者共享「列别名匹配 + 行解析」逻辑（``_CsvLikeImporter`` 基类），仅列别名、
Entry 字段映射与日志标签不同。Chrome/Edge CSV 与 CipherBox CSV 列名格式
相同，由 :class:`ImportExportManager` 经 ``import_file(format_key='chrome_csv')``
分发到 ``CsvImporter`` 处理。
"""

import csv
from collections.abc import Callable
from typing import Any

from ....exceptions import ImportSizeError
from ....models import ENTRY_FIELD_LIMITS, MAX_ENTRY_PAYLOAD_SIZE, Entry
from ...services.url_hygiene import sanitize_url_scheme
from .base import (
    ParsedImport,
    _merge_csv_secrets,
    _sanitize_totp_secret,
    _validate_items,
)

# CSV 列数硬上限（SEC-001）：先 ``list(reader)`` 物化行前校验 header 列数，防止单行
# ×数百万列构造的文件触发 OOM。密码管理器 CSV 列数有限（CipherBox ~11 列、KeePass ~6
# 列），256 远超实际需要且为单行字段数封顶。
MAX_CSV_COLUMNS = 256

# CSV 导入列名别名映射：每个字段对应一组可能的列名，匹配时不区分大小写。
# 由 _parse_csv_like 经 _build_col_map 用于 CsvImporter。
_CSV_COLUMN_ALIASES: dict[str, tuple[str, ...]] = {
    "title": ("title", "Title", "名称", "name"),
    "username": ("username", "Username", "用户名", "login", "user"),
    "password": ("password", "Password", "密码", "login_password", "pass"),
    "url": ("url", "URL", "网址", "website", "login_uri", "uri", "origin"),
    "tags": ("tags", "Tags", "标签"),
    "notes": ("notes", "Notes", "备注", "note", "comment"),
    "totp_secret": ("totp_secret", "TOTP", "totp"),
    "category": ("category", "Category", "分类", "folder"),
}

# KeePass CSV 列名别名映射：键为内部字段名，值为 CSV 中可能的列名，均为小写用于匹配。
# 值统一为 tuple，与 _CSV_COLUMN_ALIASES 保持一致，利用不可变性避免误改。
_KEEPASS_COLUMN_ALIASES: dict[str, tuple[str, ...]] = {
    "title": ("title",),
    "username": ("username",),
    "password": ("password",),
    "url": ("url",),
    "notes": ("notes",),
    "group": ("group",),
}


def _build_col_map(
    headers: list[str],
    aliases: dict[str, tuple[str, ...]],
) -> dict[str, str]:
    """构建内部字段名到 CSV 实际列名的映射，大小写不敏感匹配。

    aliases 的值为候选列名可迭代对象，按声明顺序匹配，首个命中即确定。
    供 CSV 与 KeePass 等表格类导入共享，消除两套并列的列名匹配机制。
    """
    normalized = {str(h).lower().strip(): h for h in headers}
    col_map: dict[str, str] = {}
    for internal, alias_list in aliases.items():
        for alias in alias_list:
            actual = normalized.get(alias.lower())
            if actual is not None:
                col_map[internal] = actual
                break
    return col_map


def _parse_csv_like(
    rows: list[dict[str, str]],
    aliases: dict[str, tuple[str, ...]],
    entry_key_map: dict[str, str],
) -> tuple[list[Entry], list[dict[str, str]], bool]:
    """统一的 CSV 类行解析：列名别名匹配后构建 Entry 与去重数据。

    Args:
        rows: csv.DictReader 的行列表。
        aliases: 内部字段名到候选列名列表的映射。
        entry_key_map: 内部字段名到 Entry 构造关键字的映射，允许同一
            Entry 字段接收不同来源列，例如分类字段对应 CSV 的 category
            与 KeePass 的 group。

    Returns:
        由条目列表、去重摘要列表、是否存在密码列标志组成的三元组。
    """
    if not rows:
        return [], [], False
    headers = list(rows[0].keys())
    col_map = _build_col_map(headers, aliases)
    password_present = "password" in col_map
    # 长度受限字段的内部名→上限映射，单一事实源见 models.ENTRY_FIELD_LIMITS。
    # category_name 非长度受限字段，不在此校验；它对应 CSV 的 category 或 KeePass 的 group。
    field_limits = {name: limit for name, _label, limit in ENTRY_FIELD_LIMITS}
    entries: list[Entry] = []
    entries_data: list[dict[str, str]] = []
    for row in rows:
        kwargs: dict[str, Any] = {}
        for field in col_map:
            value = row.get(col_map[field], "") or ""
            # password 列不做 strip（SEC-039）：首尾空白可能是密码的一部分，任何改变
            # 其值的清洗都破坏密钥有效性——与导出侧「密钥类列不转义公式前缀」、导入侧
            # _sanitize_entry_formula_fields「不清洗密钥字段」为同一决策的三个触点。
            kwargs[entry_key_map[field]] = value if field == "password" else value.strip()
        # 对长度受限字段做 MAX_FIELD_* 校验，与 Entry.from_dict 一致，
        # 避免 Entry(**kwargs) 绕过 from_dict 的校验逻辑导致超长字段入库。
        for internal_field, max_len in field_limits.items():
            if internal_field in col_map:
                value = kwargs.get(entry_key_map[internal_field], "")
                if len(value) > max_len:
                    raise ImportSizeError(
                        f"导入条目字段 {internal_field} 过长（最多 {max_len} 字符）"
                    )
        # totp_secret / url scheme 校验经模块级统一函数，与 JSON/Bitwarden 路径共享单一事实源
        kwargs["totp_secret"] = _sanitize_totp_secret(kwargs.get("totp_secret", ""))
        kwargs["url"] = sanitize_url_scheme(kwargs.get("url", ""))
        entries.append(Entry(**kwargs))
        entries_data.append(
            {
                "title": kwargs.get("title", ""),
                "username": kwargs.get("username", ""),
            }
        )
    return entries, entries_data, password_present


def _make_csv_merger(password_present: bool) -> Callable[[Entry, Entry], Entry]:
    """构造 CSV 类覆盖合并器，绑定解析期确定的 password_present 标志。

    source_has_password 在解析期才能确定（取决于 CSV 是否含 password 列），
    故用闭包捕获后返回稳定的合并器，供 ImportExportManager 在覆盖路径调用。
    """

    def _merge(entry: Entry, existing: Entry) -> Entry:
        return _merge_csv_secrets(entry, existing, password_present)

    return _merge


class _CsvLikeImporter:
    """CSV 类导入共享骨架：读文件、校验、列别名解析、构造合并器。

    CsvImporter 与 KeePassCsvImporter 仅列别名、Entry 字段映射与日志标签不同，
    共享文件读取与 _parse_csv_like 解析逻辑。覆盖合并器按「源是否含密码列」
    选择保留策略：源有密码列时导入密码优先、空才保留 existing；无密码列时
    无条件保留 existing（见 _merge_csv_secrets）。
    """

    def __init__(
        self,
        aliases: dict[str, tuple[str, ...]],
        entry_key_map: dict[str, str],
        source_label: str,
    ):
        self._aliases = aliases
        self._entry_key_map = entry_key_map
        self._source_label = source_label

    def parse(self, filepath: str) -> ParsedImport:
        # 限制 csv 解析器单字段最大长度（MAINT-009）：默认 128KB 与本项目逐项大小策略
        # 脱节，显式设为 MAX_ENTRY_PAYLOAD_SIZE 后单字段超 2MB 在解析阶段即抛 csv.Error，
        # 先于 ``list(reader)`` 物化整行进内存。csv.field_size_limit 是进程级全局设置，
        # 本应用导入串行执行，无负面影响。
        csv.field_size_limit(MAX_ENTRY_PAYLOAD_SIZE)
        with open(filepath, encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            # 先校验 header 列数（SEC-001），防止单行×数百万列在 ``list(reader)``
            # 物化时每行生成超长 dict 触发 OOM。空文件（无 header）按空导入处理。
            if reader.fieldnames is None:
                return ParsedImport(
                    entries=[],
                    entries_data=[],
                    overwrite_merger=_make_csv_merger(False),
                    source_label=self._source_label,
                )
            if len(reader.fieldnames) > MAX_CSV_COLUMNS:
                raise ImportSizeError(f"CSV 列数过多（最多 {MAX_CSV_COLUMNS} 列）")
            rows = list(reader)

        _validate_items(rows)

        entries, entries_data, password_present = _parse_csv_like(
            rows,
            self._aliases,
            self._entry_key_map,
        )
        return ParsedImport(
            entries=entries,
            entries_data=entries_data,
            overwrite_merger=_make_csv_merger(password_present),
            source_label=self._source_label,
        )


class CsvImporter(_CsvLikeImporter):
    """CipherBox / Chrome / Edge CSV 导入策略（支持多种列名格式）。"""

    def __init__(self) -> None:
        super().__init__(
            aliases=_CSV_COLUMN_ALIASES,
            entry_key_map={
                "title": "title",
                "username": "username",
                "password": "password",
                "url": "url",
                "tags": "tags",
                "notes": "notes",
                "totp_secret": "totp_secret",
                "category": "category_name",
            },
            source_label="CSV 导入",
        )


class KeePassCsvImporter(_CsvLikeImporter):
    """KeePass CSV 导入策略（常见列名 Title/UserName/Password/URL/Notes/Group）。"""

    def __init__(self) -> None:
        super().__init__(
            aliases=_KEEPASS_COLUMN_ALIASES,
            entry_key_map={
                "title": "title",
                "username": "username",
                "password": "password",
                "url": "url",
                "notes": "notes",
                "group": "category_name",
            },
            source_label="KeePass CSV 导入",
        )
