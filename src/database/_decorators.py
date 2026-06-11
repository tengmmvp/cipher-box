"""数据库层共享装饰器和工具函数。

将 ``_db_operation`` 从 db_manager.py 提取到独立模块，
避免 Repository 与 DatabaseManager 之间的循环导入。
"""

import functools
import logging

from ..exceptions import DatabaseError

logger = logging.getLogger(__name__)


def _db_operation(method):
    """数据库操作装饰器：获取 RLock 并校验连接状态。

    替代旧的 @_thread_safe 和手动连接检查。要求被装饰的实例
    拥有 ``_conn`` 和 ``_lock`` 属性。
    """
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        if self._conn is None:
            raise DatabaseError("数据库未连接")
        with self._lock:
            return method(self, *args, **kwargs)
    return wrapper
