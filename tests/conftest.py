"""共享测试 fixtures — 消除各测试文件中的重复辅助函数。"""

import pytest

from src.database.db_manager import DatabaseManager
from src.database.models import Entry

from tests.helpers import make_test_config


@pytest.fixture
def _disable_encrypted_assertions():
    """关闭 db_manager 的密文前缀断言。

    部分测试直接调用 db.add_entry 写入明文，绕过 EntryManager 加密层。
    通过猴子补丁 DatabaseManager.__init__，使本 fixture 活跃期间创建的
    实例默认 _enforce_encrypted_fields=False。
    需要此 fixture 的测试类/方法应使用 @pytest.mark.usefixtures 装饰器。
    生产环境断言仍生效（默认 _enforce_encrypted_fields=True）。
    """
    original_init = DatabaseManager.__init__

    def _patched_init(self, db_path):
        original_init(self, db_path)
        self._enforce_encrypted_fields = False

    DatabaseManager.__init__ = _patched_init
    yield
    DatabaseManager.__init__ = original_init


@pytest.fixture(scope='session')
def qapp():
    """确保测试会话中有一个 QApplication 实例。"""
    from PyQt6.QtWidgets import QApplication
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    yield app


@pytest.fixture
def vault_config(tmp_path):
    """创建一个使用临时目录的 ConfigManager，用于 VaultManager 测试。"""
    return make_test_config(tmp_path)


@pytest.fixture
def vault(vault_config):
    """已初始化的 VaultManager 实例。"""
    from src.business.vault_manager import VaultManager
    v = VaultManager(vault_config)
    v.initialize('TestPassword123!')
    yield v
    try:
        v.close()
    except Exception:
        pass


@pytest.fixture
def entry_mgr(vault):
    """已初始化的 EntryManager 实例。"""
    from src.business.entry_manager import EntryManager
    return EntryManager(vault)


@pytest.fixture
def make_entry():
    """创建测试用 Entry 的工厂 fixture。

    提供合理的默认值，调用方通过关键字参数覆盖所需字段。
    """
    def _make_entry(**overrides):
        defaults = dict(
            title='Test',
            username='user',
            password='Pass123!@#',
            url='',
            notes='',
            custom_fields='',
            tags='',
            entry_type='login',
            totp_secret='',
        )
        defaults.update(overrides)
        return Entry(**defaults)
    return _make_entry
