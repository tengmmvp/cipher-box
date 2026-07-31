"""共享测试 fixtures — 消除各测试文件中的重复辅助函数。"""

import dataclasses
import os

import pytest

from src.crypto.master_key import KdfParams
from src.models import Entry
from tests.helpers import make_test_config

# 显式标记测试环境：AutoLockController.setup_session_notification 据此跳过 WTS 注册——
# WTSRegisterSessionNotification 在无真实消息循环的测试窗口上触发 C 层 access violation
# （无法 try/except 捕获）。替代生产代码探测 'pytest' in sys.modules 的 prod/test 耦合
# （MAINT-1）：测试运行经此环境变量显式声明，生产路径不设置它，行为分支不再依赖
# 测试框架是否被加载。
os.environ.setdefault('CIPHERBOX_DISABLE_WTS', '1')


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
    """测试全局注入弱 KDF，加速保险库主密钥派生（initialize / change_master）。

    覆盖范围：仅 ``vault_lifecycle.DEFAULT_KDF_PARAMS``（initialize / change_master
    经此派生，生命周期流程已拆出至 vault_lifecycle）。**有意不覆盖**
    ``backup_restore.DEFAULT_KDF_PARAMS``——备份密码派生用 backup_restore 模块自有的
    导入副本，保持真实 OWASP 参数：``test_rejects_downgraded_kdf_params`` 需创建真实
    参数备份再篡改为更弱值以验证防降级守卫；若一并弱化会使创建出的备份已是最低合法
    参数，无法测试降级拒绝。故涉及备份密码派生的少数测试较慢（真实 Argon2id 64MB），
    属可接受取舍。
    """
    from src.business.managers import vault_lifecycle
    monkeypatch.setattr(vault_lifecycle, 'DEFAULT_KDF_PARAMS', _TEST_KDF_PARAMS)


@pytest.fixture
def vault(vault_config):
    """已初始化的 VaultManager 实例（经 build_vault 完整装配 db+signer+生命周期）。"""
    from tests.helpers import make_vault
    v = make_vault(vault_config, test_mode=True)
    v.initialize('TestPassword123!', params=_TEST_KDF_PARAMS)
    yield v
    try:
        v.close()
    except Exception:
        pass


@pytest.fixture
def entry_mgr(vault):
    """已初始化的 EntryManager 实例。"""
    from src.business.managers.entry_cache import EntryCacheManager
    from src.business.managers.entry_change_bus import EntryChangeBus
    from src.business.managers.entry_manager import EntryManager
    cache = EntryCacheManager(vault)
    return EntryManager(vault, cache, EntryChangeBus(cache))


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


@pytest.fixture(autouse=True)
def _reclaim_qt_widgets():
    """每个测试后回收 Qt 顶层 widget 的 C++ 对象，阻断全量测试累积崩溃。

    测试里 ``MainWindow``/``Dialog`` 经 ``close()`` 仅隐藏窗口，其底层 C++ 对象
    要等 Python GC 才释放。全量测试反复构造 ``MainWindow``（每实例持数百子 widget、
    controller 与去抖定时器），C++ 内存持续累积，Windows 下最终触发 C 层
    access violation（无法 try/except，进程直接崩溃）。teardown 阶段显式
    ``deleteLater`` 所有顶层 widget 并 ``processEvents`` 推进 DeferredDelete，
    及时回收，使每个测试在干净的 Qt 对象基线上运行。
    """
    yield
    from PyQt6.QtWidgets import QApplication
    app = QApplication.instance()
    # isinstance 同时排除 None 与非 QApplication（QGuiApplication/QCoreApplication
    # 无 topLevelWidgets），并窄化为 QApplication 以访问 topLevelWidgets/processEvents。
    if not isinstance(app, QApplication):
        return
    for widget in list(app.topLevelWidgets()):
        widget.deleteLater()
    # deleteLater 把对象排入下一轮事件循环的 DeferredDelete 队列；processEvents
    # 迭代事件循环完成析构。复杂 widget 树可能需额外一轮，故调用两次。
    app.processEvents()
    app.processEvents()
