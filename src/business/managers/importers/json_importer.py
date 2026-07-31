"""CipherBox JSON 导入策略。"""

import json

from ....exceptions import ImportFormatError
from ....models import Entry
from .base import (
    ParsedImport,
    _merge_non_exported_secrets,
    _sanitize_totp_secret,
    _sanitize_url_scheme,
    _validate_items,
)

_SOURCE_LABEL = 'JSON 导入'


def _noop_merger(_entry: Entry, _existing: Entry) -> Entry:
    """secrets_included=True 时导入值完整，覆盖无需合并敏感字段。"""
    return _entry


class JsonImporter:
    """CipherBox JSON 导出文件的解析策略。

    支持完整（含密码）与不含密码两种导出。secrets_included=False 时主动清除
    导入数据中的 password/totp_secret 字段，使「导入值必为空」成为代码保证
    而非数据假设，避免覆盖路径误保留对抗构造的输入。此时覆盖合并器为
    ``_merge_non_exported_secrets``；secrets_included=True 时导入值完整，
    合并器为 no-op（不覆盖已有敏感字段）。
    """

    def parse(self, filepath: str) -> ParsedImport:
        with open(filepath, encoding='utf-8') as f:
            data = json.load(f)

        if not isinstance(data, dict) or data.get('app') != 'CipherBox':
            raise ImportFormatError('不是 CipherBox JSON 导出文件')
        # 注意：app 字段检查仅防止误导入错误格式的文件，不防恶意伪造。
        # 真实安全保护在于：导入数据会被重新加密到当前 vault 密钥下，
        # 恶意注入的数据仅能产生垃圾条目，无法获取已有密码。
        if type(data.get('secrets_included')) is not bool:
            raise ImportFormatError('CipherBox JSON 缺少敏感字段声明')
        items = data.get('entries', [])
        if not isinstance(items, list):
            raise ImportFormatError('JSON 导入结构无效')
        # 先校验每个元素为 dict，防止非 dict 触发 _validate_items 内 item.values()
        # 的 AttributeError（绕过下方的友好提示）。
        non_dict = [i for i, item in enumerate(items) if not isinstance(item, dict)]
        if non_dict:
            raise ImportFormatError(
                f'JSON 条目列表中第 {non_dict[0] + 1} 项不是有效的对象'
            )
        _validate_items(items)
        # 上方 type(...) is not bool 检查已保证 secrets_included 为 bool
        secrets_included = data['secrets_included']

        # secrets_included=False 时导出本就不含 password/totp_secret，但对抗性构造
        # 的文件可能仍带这些字段。主动清除，使“导入值必为空”成为代码保证而非
        # 数据假设，避免 _merge_non_exported_secrets 在覆盖路径误保留对抗输入的
        # totp_secret（原合并注释假设导入值为空，仅对正常文件成立）。
        if not secrets_included:
            for item in items:
                if isinstance(item, dict):
                    item.pop('password', None)
                    item.pop('totp_secret', None)

        # url scheme / totp_secret 校验：与 CSV/Bitwarden 路径共享模块级清洗函数，
        # 使全部导入路径产出的字段一致不含危险 scheme 与无效 totp（见 _sanitize_url_scheme
        # / _sanitize_totp_secret 的定位说明：渲染层为安全边界，此处为数据卫生一致性）。
        for item in items:
            if isinstance(item.get('url'), str):
                item['url'] = _sanitize_url_scheme(item['url'])
            if isinstance(item.get('totp_secret'), str):
                item['totp_secret'] = _sanitize_totp_secret(item['totp_secret'])
        entries = [Entry.from_dict(item) for item in items]
        # JSON 解析树与原始条目列表在 parse 返回后随局部变量一并释放，降低后续
        # 事务执行期间的内存峰值（导入在 worker 线程不阻塞 UI，但低配机仍受益）。
        entries_data = [{'title': e.title, 'username': e.username} for e in entries]

        merger = _merge_non_exported_secrets if not secrets_included else _noop_merger
        return ParsedImport(
            entries=entries,
            entries_data=entries_data,
            overwrite_merger=merger,
            source_label=_SOURCE_LABEL,
        )
