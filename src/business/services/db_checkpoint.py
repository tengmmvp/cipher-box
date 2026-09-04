"""secure_checkpoint 的非致命降级助手 — 四处调用点 except 元组的单一事实源。"""

import logging

from ...database.types import VaultDataStore
from ...exceptions import DatabaseError

logger = logging.getLogger(__name__)


def safe_checkpoint(db: VaultDataStore, warning: str) -> bool:
    """执行 WAL 安全截断，声明面内失败降级为告警并返回 False，成功返回 True。

    声明面为 DatabaseError（SEC-010）与 ``_secure_database_files`` 的 OSError
    （QL-079）：元组外的编程错误照常响亮传播；收敛为单一助手正是为杜绝
    调用点手写元组时再漏写 OSError 的一半（清空回收站曾因此把「已物理删除
    却报硬错误」抛给用户）。
    """
    try:
        db.secure_checkpoint()
        return True
    except (DatabaseError, OSError):
        logger.warning(warning, exc_info=True)
        return False
