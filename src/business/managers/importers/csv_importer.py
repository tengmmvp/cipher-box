"""CSV / KeePass CSV 导入策略。

两者共享「列别名匹配 + 行解析」逻辑（``_CsvLikeImporter`` 基类），仅列别名、
Entry 字段映射与日志标签不同。Chrome/Edge CSV 与 CipherBox CSV 列名格式
相同，由 ``ImportExportManager.import_from_chrome_csv`` 委托 ``CsvImporter``
处理。
"""

import csv
from collections.abc import Callable
from typing import Any

from ....models import ENTRY_FIELD_LIMITS, MAX_ENTRY_PAYLOAD_SIZE, Entry
from .base import (
    ParsedImport,
    _merge_csv_secrets,
    _sanitize_totp_secret,
    _sanitize_url_scheme,
    _validate_items,
)

# 限制 csv 解析器单字段最大长度。Python csv 默认 field_size_limit=128KB，但该默认
# 值是隐式的且与本项目的逐项大小策略脱节。显式设为 MAX_ENTRY_PAYLOAD_SIZE 后，单字段
# 超过 2MB 会在 csv 解析阶段即抛 csv.Error，先于 ``list(reader)`` 把整行物化进内存——
# 否则攻击者可构造「单行无换行的巨大字段」文件（受 25MB 文件上限约束），在逐项校验
# 运行前就撑出一整段连续内存。csv.field_size_limit 是进程级全局设置，本应用导入
# 串行执行，设此防御性上限对其他 csv 路径无负面影响。
csv.field_size_limit(MAX_ENTRY_PAYLOAD_SIZE)

# CSV 导入列名别名映射：每个字段对应一组可能的列名，匹配时不区分大小写。
# 由 _parse_csv_like 经 _build_col_map 用于 CsvImporter。
_CSV_COLUMN_ALIASES: dict[str, tuple[str, ...]] = {
    'title':       ('title', 'Title', '名称', 'name'),
    'username':    ('username', 'Username', '用户名', 'login', 'user'),
    'password':    ('password', 'Password', '密码', 'login_password', 'pass'),
    'url':         ('url', 'URL', '网址', 'website', 'login_uri', 'uri', 'origin'),
    'tags':        ('tags', 'Tags', '标签'),
    'notes':       ('notes', 'Notes', '备注', 'note', 'comment'),
    'totp_secret': ('totp_secret', 'TOTP', 'totp'),
    'category':    ('category', 'Category', '分类', 'folder'),
}

# KeePass CSV 列名别名映射：键为内部字段名，值为 CSV 中可能的列名，均为小写用于匹配。
# 值统一为 tuple，与 _CSV_COLUMN_ALIASES 保持一致，利用不可变性避免误改。
_KEEPASS_COLUMN_ALIASES: dict[str, tuple[str, ...]] = {
    'title':    ('title',),
    'username': ('username',),
    'password': ('password',),
    'url':      ('url',),
    'notes':    ('notes',),
    'group':    ('group',),
}


def _build_col_map(
    headers: list[str], aliases: dict[str, tuple[str, ...]],
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
    password_present = 'password' in col_map
    # 长度受限字段的内部名→上限映射，单一事实源见 models.ENTRY_FIELD_LIMITS。
    # category_name 非长度受限字段，不在此校验；它对应 CSV 的 category 或 KeePass 的 group。
    field_limits = {name: limit for name, _label, limit in ENTRY_FIELD_LIMITS}
    entries: list[Entry] = []
    entries_data: list[dict[str, str]] = []
    for row in rows:
        kwargs: dict[str, Any] = {
            entry_key_map[field]: (row.get(col_map[field], '') or '').strip()
            for field in col_map
        }
        # 对长度受限字段做 MAX_FIELD_* 校验，与 Entry.from_dict 一致，
        # 避免 Entry(**kwargs) 绕过 from_dict 的校验逻辑导致超长字段入库。
        for internal_field, max_len in field_limits.items():
            if internal_field in col_map:
                value = kwargs.get(entry_key_map[internal_field], '')
                if len(value) > max_len:
                    raise ValueError(
                        f'导入条目字段 {internal_field} 过长（最多 {max_len} 字符）'
                    )
        # totp_secret / url scheme 校验经模块级统一函数，与 JSON/Bitwarden 路径共享单一来源
        kwargs['totp_secret'] = _sanitize_totp_secret(kwargs.get('totp_secret', ''))
        kwargs['url'] = _sanitize_url_scheme(kwargs.get('url', ''))
        entries.append(Entry(**kwargs))
        entries_data.append({
            'title': kwargs.get('title', ''),
            'username': kwargs.get('username', ''),
        })
    return entries, entries_data, password_present


def _make_csv_merger(password_present: bool) -> Callable[[Entry, Entry], None]:
    """构造 CSV 类覆盖合并器，绑定解析期确定的 password_present 标志。

    source_has_password 在解析期才能确定（取决于 CSV 是否含 password 列），
    故用闭包捕获后返回稳定的合并器，供 ImportExportManager 在覆盖路径调用。
    """
    def _merge(entry: Entry, existing: Entry) -> None:
        _merge_csv_secrets(entry, existing, password_present)
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
        with open(filepath, encoding='utf-8-sig', newline='') as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        _validate_items(rows)

        entries, entries_data, password_present = _parse_csv_like(
            rows, self._aliases, self._entry_key_map,
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
                'title': 'title', 'username': 'username', 'password': 'password',
                'url': 'url', 'tags': 'tags', 'notes': 'notes',
                'totp_secret': 'totp_secret', 'category': 'category_name',
            },
            source_label='CSV 导入',
        )


class KeePassCsvImporter(_CsvLikeImporter):
    """KeePass CSV 导入策略（常见列名 Title/UserName/Password/URL/Notes/Group）。"""

    def __init__(self) -> None:
        super().__init__(
            aliases=_KEEPASS_COLUMN_ALIASES,
            entry_key_map={
                'title': 'title', 'username': 'username', 'password': 'password',
                'url': 'url', 'notes': 'notes', 'group': 'category_name',
            },
            source_label='KeePass CSV 导入',
        )
