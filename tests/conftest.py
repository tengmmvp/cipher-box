"""共享测试 fixtures — 消除各测试文件中的重复辅助函数。"""

import dataclasses

import pytest

from src.crypto.master_key import KdfParams
from src.database.db_manager import DatabaseManager
from src.models import Entry
from tests.helpers import make_test_config


@pytest.fixture
def _disable_encrypted_assertions():
    """关闭 db_manager 的密文前缀断言。

    通过 monkey-patch DatabaseManager，使本 fixture 活跃期间创建的
    实例默认 test_mode=True，即 _enforce_encrypted_fields=False。
    需要此 fixture 的测试类或方法应使用 @pytest.mark.usefixtures 装饰器。
    生产环境断言仍生效，默认 _enforce_encrypted_fields=True。
    """
    original_init = DatabaseManager.__init__

    def _patched_init(self, db_path, *, test_mode=False):
        original_init(self, db_path, test_mode=True)

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


# 测试用弱化但合法的 Argon2id 参数（仍过 MasterKeyManager.validate_params 的安全
# 下限 time≥2 / mem≥16MB / par≥1），加速 vault fixture 的密钥派生。生产路径仍用
# DEFAULT_KDF_PARAMS（time=3 / 64MB / parallelism=4），仅此 fixture 与显式注入弱
# 参数的测试使用弱值；对真实 OWASP 参数的派生强度另有专门测试守护。
_TEST_KDF_PARAMS = KdfParams(time_cost=2, memory_cost=16 * 1024, parallelism=1)


@pytest.fixture(autouse=True)
def _weak_kdf_for_tests(monkeypatch):
    """测试全局注入弱 KDF，加速 vault_manager 的主密钥派生（initialize / change_master）。

    覆盖范围：仅 ``vault_manager.DEFAULT_KDF_PARAMS``（initialize / change_master
    经此派生）。**有意不覆盖** ``backup_restore.DEFAULT_KDF_PARAMS``——备份密码
    派生用 backup_restore 模块自有的导入副本，保持真实 OWASP 参数：
    ``test_rejects_downgraded_kdf_params`` 需创建真实参数备份再篡改为更弱值以验证
    防降级守卫；若一并弱化会使创建出的备份已是最低合法参数，无法测试降级拒绝。
    故涉及备份密码派生的少数测试较慢（真实 Argon2id 64MB），属可接受取舍。
    """
    from src.business.managers import vault_manager
    monkeypatch.setattr(vault_manager, 'DEFAULT_KDF_PARAMS', _TEST_KDF_PARAMS)


@pytest.fixture
def vault(vault_config):
    """已初始化的 VaultManager 实例。"""
    from src.business.managers.vault_manager import VaultManager
    v = VaultManager(vault_config)
    v.initialize('TestPassword123!', params=_TEST_KDF_PARAMS)
    yield v
    try:
        v.close()
    except Exception:
        pass


@pytest.fixture
def entry_mgr(vault):
    """已初始化的 EntryManager 实例。"""
    from src.business.managers.entry_manager import EntryManager
    return EntryManager(vault)


@pytest.fixture
def make_entry():
    """创建测试用 Entry 的工厂 fixture。

    提供合理的默认值，调用方通过关键字参数覆盖所需字段。
    """
    def _make_entry(**overrides):
        entry = Entry(
            title='Test',
            username='user',
            password='Pass123!@#',
            url='',
            notes='',
            custom_fields=[],
            tags='',
            entry_type='login',
            totp_secret='',
        )
        return dataclasses.replace(entry, **overrides)
    return _make_entry
