"""导入格式策略类的共享基础：数据卫生清洗、条目校验、覆盖合并器与策略接口。

各格式策略类（JSON/CSV/KeePass CSV/Bitwarden JSON）经此模块共享：
- ``_sanitize_url_scheme`` / ``_sanitize_totp_secret``：全部导入路径产出的字段
  统一不含危险 scheme 与无效 totp（渲染层为安全边界，此处为数据卫生一致性）。
- ``_validate_items``：逐项大小校验，防恶意构造的巨大字段撑爆内存。
- ``_retain_password_custom_fields`` / ``_merge_*_secrets``：覆盖导入时按格式
  语义合并已有条目的敏感字段。
- ``ParsedImport`` / ``FormatImporter``：解析结果容器与策略类接口。
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any, Protocol
from urllib.parse import urlparse

from ....crypto.totp import TOTPGenerator
from ....exceptions import ImportSizeError
from ....models import MAX_ENTRIES_LIMIT, MAX_ENTRY_PAYLOAD_SIZE, Entry

logger = logging.getLogger(__name__)

# url scheme 白名单：导入路径仅保留常见安全 scheme，避免 javascript:/data:/file: 等
# 被详情面板渲染为可点击链接导致钓鱼或协议注入。空 scheme（裸域名）允许通过。
_URL_SCHEME_ALLOWLIST = frozenset(
    {
        "http",
        "https",
        "ftp",
        "ftps",
        "ssh",
        "sftp",
        "telnet",
        "mailto",
    }
)


def _sanitize_url_scheme(url: str) -> str:
    """校验 url scheme，非白名单 scheme（javascript:/data:/file: 等）清空。

    非安全必需——url 的真正安全边界在 detail_panel._build_url_label（仅 http/https
    渲染为可点击链接，其余纯文本转义）。此处为「导入数据卫生」的一致性纵深防御：
    使各导入路径产出的 url 统一不含危险 scheme，防未来新增「打开/复制 url」功能时
    某路径数据漏网。空 scheme（裸域名）允许通过，UI 点击时按默认 http 处理。
    """
    if not url:
        return url
    scheme = urlparse(url).scheme.lower()
    if scheme and scheme not in _URL_SCHEME_ALLOWLIST:
        logger.warning("导入条目 url 含非白名单 scheme：%s，已清空该字段", scheme)
        return ""
    return url


def _sanitize_totp_secret(secret: str) -> str:
    """校验 totp_secret，非有效 base32/otpauth 时清空，保留条目其余字段。

    与 _sanitize_url_scheme 同属导入数据卫生的一致性纵深防御。损坏的 totp 入库后虽
    不崩溃（TOTPGenerator.generate 静默返回空串并告警），但用户难以察觉「验证码为何
    不显示」；全部导入路径统一经此清洗，损坏即清空并告警，使无效 totp 不落库。
    """
    if secret and not TOTPGenerator.validate_secret(secret):
        logger.warning("导入条目 totp_secret 非有效 base32，已清空该字段")
        return ""
    return secret


def _validate_items(items: list[dict[str, Any]]) -> None:
    """逐项验证导入数据大小。

    使用字段长度估算防止恶意构造的巨大字段在后续处理中引发内存问题。
    """
    if len(items) > MAX_ENTRIES_LIMIT:
        raise ImportSizeError(f"导入条目过多，最大允许 {MAX_ENTRIES_LIMIT} 条")
    for item in items:
        # 跳过非对象项（被污染导出中可能是数字/字符串）：各策略类的 parse 循环
        # 同样跳过非 dict item，此处不对其求大小，避免 item.values() 对非 dict
        # 抛 AttributeError 中断整个导入（单个畸形项导致的拒绝服务）。
        if not isinstance(item, dict):
            continue
        if (
            sum(
                len(v.encode("utf-8")) if isinstance(v, str) else len(str(v).encode("utf-8"))
                for v in item.values()
            )
            > MAX_ENTRY_PAYLOAD_SIZE
        ):
            raise ImportSizeError("导入条目字段过大")


def _retain_password_custom_fields(
    entry: Entry,
    existing: Entry,
    *,
    replace_all: bool = True,
) -> Entry:
    """合并密码型自定义字段：从 existing 中保留 entry 缺失的密码型字段。

    Args:
        entry: 导入条目（frozen，经 replace 返回新副本，非就地修改）。
        existing: 已有条目，用于读取敏感字段。
        replace_all: True 时用 existing 的全部密码型字段替换 entry 的字段，
            适用于 CSV 或非导出场景，源格式无法表达密码型字段。
            False 时按名称增量补充，适用于 Bitwarden JSON 等源格式可表达
            但可能不包含已有字段的场景。
    """
    if not isinstance(entry.custom_fields, list):
        return entry
    existing_pwd = [
        f
        for f in (existing.custom_fields if isinstance(existing.custom_fields, list) else [])
        if f.field_type == "password"
    ]
    if replace_all:
        # CSV / 非导出：源无法表达密码型字段，完全替换
        merged = [f for f in entry.custom_fields if f.field_type != "password"] + existing_pwd
    else:
        # Bitwarden JSON：按名称增量补充已有但导入中不存在的
        import_pwd_names = {f.name for f in entry.custom_fields if f.field_type == "password"}
        missing = [f for f in existing_pwd if f.name not in import_pwd_names]
        merged = entry.custom_fields + missing
    return replace(entry, custom_fields=merged)


def _merge_csv_secrets(entry: Entry, existing: Entry, source_has_password: bool) -> Entry:
    """CSV 覆盖导入的敏感字段合并。

    CSV 是不可靠的往返格式，密码型自定义字段无法可靠映射，因此对源文件
    未携带的敏感字段始终保留 existing 的值。返回合并后的新 Entry（frozen 不可变）。
    """
    password = (
        existing.password if (not source_has_password or not entry.password) else entry.password
    )
    totp_secret = existing.totp_secret if not entry.totp_secret else entry.totp_secret
    entry = replace(entry, password=password, totp_secret=totp_secret)
    return _retain_password_custom_fields(entry, existing, replace_all=True)


def _merge_bitwarden_secrets(entry: Entry, existing: Entry) -> Entry:
    """Bitwarden JSON 覆盖导入的敏感字段合并。

    Bitwarden JSON 可完整表达 password、totp_secret 和密码型自定义字段，
    因此信任导入数据。仅当导入值为空时保留已有值。返回合并后的新 Entry。
    """
    entry = replace(
        entry,
        password=entry.password or existing.password,
        totp_secret=entry.totp_secret or existing.totp_secret,
    )
    return _retain_password_custom_fields(entry, existing, replace_all=False)


def _merge_non_exported_secrets(entry: Entry, existing: Entry) -> Entry:
    """JSON 导出未包含敏感字段时的合并。

    ``secrets_included=False`` 路径下导入数据中 password/totp_secret 必为空，
    故复用 ``_merge_csv_secrets`` 传 ``source_has_password=False``：源无密码列
    时无条件保留 existing 的密码，totp_secret 仅在空时保留（此处数据流上等价
    于无条件保留，因导入值本就为空）。
    """
    return _merge_csv_secrets(entry, existing, source_has_password=False)


@dataclass
class ParsedImport:
    """格式策略类的解析结果：条目列表、去重摘要、覆盖合并器与日志标签。

    将格式特定的全部差异打包为单一返回值，使 ImportExportManager 的导入编排
    无需感知具体格式，仅按 ParsedImport 的字段统一驱动事务/去重/分类/写入。
    """

    entries: list[Entry]
    entries_data: list[dict[str, str]]
    overwrite_merger: Callable[[Entry, Entry], Entry]
    source_label: str


class FormatImporter(Protocol):
    """格式特定导入策略：文件解析为 ``ParsedImport``。

    各策略类实现 ``parse``，封装该格式的文件读取、字段映射与覆盖合并器构造。
    事务、去重、分类解析、写入等共享编排由 ``ImportExportManager`` 承担，
    策略类仅封装格式差异，新增格式只需新增策略类（无需显式继承，结构子类型即可）。
    """

    def parse(self, filepath: str) -> ParsedImport:
        """解析文件，返回含 entries/entries_data/merger/source_label 的结果。"""
        ...
