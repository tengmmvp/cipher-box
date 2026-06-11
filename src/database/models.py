"""向后兼容重导出 — 模型类已移至 src.models。

所有模型类（Entry、Category 等）和常量（ENTRY_TYPES、MAX_FIELD_*）
现已定义在 src/models.py（全局共享层），消除了 UI→Database 的跨层依赖。
此文件保留以兼容旧的 ``from ..database.models import ...`` 路径。
"""

from ..models import (  # noqa: F401 — 重导出
    ENTRY_TYPE_CARD,
    ENTRY_TYPE_IDENTITY,
    ENTRY_TYPE_LOGIN,
    ENTRY_TYPE_NOTE,
    ENTRY_TYPE_SERVER,
    ENTRY_TYPES,
    MAX_CUSTOM_FIELDS_PER_ENTRY,
    MAX_FIELD_NOTES,
    MAX_FIELD_PASSWORD,
    MAX_FIELD_TAGS,
    MAX_FIELD_TITLE,
    MAX_FIELD_TOTP_SECRET,
    MAX_FIELD_URL,
    MAX_FIELD_USERNAME,
    MAX_PASSWORD_HISTORY,
    Category,
    CustomField,
    Entry,
    PasswordHistory,
)
