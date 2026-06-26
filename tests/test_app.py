"""CipherBoxApp 生命周期的关键路径测试。

app.py 的完整状态机（登录→主窗口→锁定→重登录）依赖 QApplication 事件循环与
LoginWindow/MainWindow 的 GUI 交互，难以在无头测试中端到端驱动。此处聚焦可独立
验证的安全关键路径——崩溃/退出兜底 ``_emergency_cleanup``：它是密码管理器最不应
静默失效的安全路径，须确保未解锁时短路、解锁时尽力锁定。

通过 ``CipherBoxApp.__new__`` 绕过 ``__init__``（避免 QApplication/sys.excepthook
等副作用），手动注入 vault 与 main_window，隔离测试兜底逻辑本身。
"""

import tempfile

from src.app import CipherBoxApp
from tests.helpers import make_test_config, make_vault


def test_emergency_cleanup_noop_when_vault_locked(monkeypatch):
    """保险库未解锁时 _emergency_cleanup 应短路，不触碰任何清理路径。

    用 lock spy 验证短路：若误删首个 ``if not is_unlocked: return``，lock 会被
    再次调用（尽管幂等），spy 计数即暴露回归——单纯断言 is_unlocked 无法区分。
    """
    with tempfile.TemporaryDirectory() as root:
        config = make_test_config(root)
        vault = make_vault(config)
        assert vault.initialize('MasterPassword!2026')[0]
        vault.lock()
        lock_calls: list[int] = []
        original_lock = vault.lock

        def _spy_lock():
            lock_calls.append(1)
            return original_lock()

        monkeypatch.setattr(vault, 'lock', _spy_lock)
        app = CipherBoxApp.__new__(CipherBoxApp)
        app._vault = vault
        app._main_window = None
        # 未解锁：短路返回，不应抛异常，lock 不应被再次调用
        app._emergency_cleanup(full=True)
        assert lock_calls == []
        assert not vault.is_unlocked
        vault.close()


def test_emergency_cleanup_locks_unlocked_vault():
    """保险库解锁时 _emergency_cleanup 应尽力调用 lock() 收缩明文残留面。"""
    with tempfile.TemporaryDirectory() as root:
        config = make_test_config(root)
        vault = make_vault(config)
        assert vault.initialize('MasterPassword!2026')[0]
        assert vault.is_unlocked
        app = CipherBoxApp.__new__(CipherBoxApp)
        app._vault = vault
        app._main_window = None
        # 解锁态：兜底应 lock()，使密钥材料清零、is_unlocked 变 False
        app._emergency_cleanup(full=False)
        assert not vault.is_unlocked
        vault.close()


def test_emergency_cleanup_idempotent_across_repeated_calls():
    """_emergency_cleanup 幂等：closeEvent/aboutToQuit/excepthook 多路径可能重复
    调用，重复清理不应抛异常（vault 已锁定时再次短路）。"""
    with tempfile.TemporaryDirectory() as root:
        config = make_test_config(root)
        vault = make_vault(config)
        assert vault.initialize('MasterPassword!2026')[0]
        app = CipherBoxApp.__new__(CipherBoxApp)
        app._vault = vault
        app._main_window = None
        app._emergency_cleanup(full=False)
        app._emergency_cleanup(full=True)
        app._emergency_cleanup(full=False)
        assert not vault.is_unlocked
        vault.close()


def test_emergency_cleanup_swallows_main_window_errors():
    """main_window.prepare_for_lock/emergency_clear_clipboard 抛异常时，兜底路径
    仍须继续执行 vault.lock()——崩溃兜底绝不能因清理再次抛出。"""
    with tempfile.TemporaryDirectory() as root:
        config = make_test_config(root)
        vault = make_vault(config)
        assert vault.initialize('MasterPassword!2026')[0]

        class _BoomWindow:
            def prepare_for_lock(self):
                raise RuntimeError('prepare_for_lock 模拟失败')

            def emergency_clear_clipboard(self):
                raise RuntimeError('clear_clipboard 模拟失败')

        app = CipherBoxApp.__new__(CipherBoxApp)
        app._vault = vault
        app._main_window = _BoomWindow()  # type: ignore[assignment]
        # main_window 各清理方法抛异常，兜底仍应继续并最终 lock vault
        app._emergency_cleanup(full=True)
        assert not vault.is_unlocked
        vault.close()
