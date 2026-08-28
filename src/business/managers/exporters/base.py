"""导出格式策略类的共享基础：CSV 注入防护与密钥列豁免常量。

各导出格式策略（JSON/CSV）经此模块共享 CSV 安全转义；导出编排骨架（路径校验、
原子写入、进度回调契约）由 :class:`..import_export.ImportExportManager` 统一处理。
"""

from typing import Any

from ...services.url_hygiene import sanitize_formula_prefix

# CSV 导出中不做公式前缀转义的密钥类列（SEC-039）：与导入侧
# ``_sanitize_entry_formula_fields``「不清洗 password/totp_secret」（SEC-008）的决策
# 对称——导出侧转义（前置 ``'``）会静默破坏密钥值：用户从 CSV 复制得到错误秘密，
# 重导入把带 ``'`` 的值存为密码（往返损坏）。换行替换等保 CSV 结构完整的处理仍保留。
CSV_SECRET_COLUMNS = frozenset({"password", "totp_secret"})


def csv_safe(value: Any, *, escape_formula: bool = True) -> str:
    """防护 CSV 注入：转义危险前缀（复用 ``url_hygiene.sanitize_formula_prefix``），替换内部控制字符。

    ``escape_formula=False`` 供密钥类列（password/totp_secret）跳过公式前缀转义
    （SEC-039，见 csv_exporter 的密钥列豁免）：换行替换仍执行（防 CSV 行断裂），
    仅跳过会改变密钥值的 ``'`` 前缀转义。

    原 ``ImportExportManager._csv_safe`` 静态方法移入（ARCH-038 导出策略拆分）。
    """
    text = str(value) if value is not None else ""
    # 替换嵌入的换行符为空格，防止 CSV 行断裂
    text = text.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    return sanitize_formula_prefix(text) if escape_formula else text
