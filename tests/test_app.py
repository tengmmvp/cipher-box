"""CipherBoxApp 生命周期的关键路径测试。

app.py 的完整状态机（登录→主窗口→锁定→重登录）依赖 QApplication 事件循环与
LoginWindow/MainWindow 的 GUI 交互，难以在无头测试中端到端驱动。此处聚焦可独立
验证的安全关键路径——崩溃/退出兜底 ``_emergency_cleanup``：它是密码管理器最不应
静默失效的安全路径，须确保未解锁时短路、解锁时尽力锁定。

通过 ``CipherBoxApp.__new__`` 绕过 ``__init__``（避免 QApplication/sys.excepthook
等副作用），手动注入 vault 与 main_window，隔离测试兜底逻辑本身。
"""

import tempfile
from unittest.mock import MagicMock

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
        assert vault.initialize("MasterPassword!2026")[0]
        vault.lock()
        lock_calls: list[int] = []
        original_lock = vault.lock

        def _spy_lock():
            lock_calls.append(1)
            return original_lock()

        monkeypatch.setattr(vault, "lock", _spy_lock)
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
        assert vault.initialize("MasterPassword!2026")[0]
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
        assert vault.initialize("MasterPassword!2026")[0]
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
        assert vault.initialize("MasterPassword!2026")[0]

        class _BoomWindow:
            def prepare_for_lock(self):
                raise RuntimeError("prepare_for_lock 模拟失败")

            def emergency_clear_clipboard(self):
                raise RuntimeError("clear_clipboard 模拟失败")

        app = CipherBoxApp.__new__(CipherBoxApp)
        app._vault = vault
        app._main_window = _BoomWindow()  # type: ignore[assignment]
        app._emergency_cleanup(full=True)
        assert not vault.is_unlocked
        vault.close()


def test_main_window_construction_failure_rolls_back(monkeypatch):
    """MainWindow 构造抛异常时回滚：_main_window 置 None、提示用户、锁定保险库、退出。

    ``_show_login`` 的 ``on_login`` 回调内构造 MainWindow 涉及 UI 组件、托盘、定时器、
    WTS 注册等多个子系统，任一环节抛异常会留下半构造窗口与已连接的部分信号槽。
    捕获后须回滚引用为 None、向用户提示、锁定已解锁的保险库并退出，而非继续 show
    一个状态不一致的窗口——后者会让用户误以为应用就绪，但关键信号槽未连接。

    经 ``__new__`` 绕过 ``__init__``，手动注入 mock 状态；LoginWindow 替换为捕获
    ``login_success.connect`` 的桩，从中提取 ``on_login`` 闭包直接调用，避免驱动
    真实登录事件循环。MainWindow / build_business_context 分别替换为抛异常与桩上下文。
    """

    app = CipherBoxApp.__new__(CipherBoxApp)
    app._vault = MagicMock()
    app._config = MagicMock()
    app._app = MagicMock()
    app._main_window = None
    app._running = True

    captured: dict = {}

    class _FakeLogin:
        """LoginWindow 桩：捕获 login_success 信号注册的回调，exec 立即返回 Accepted。"""

        class DialogCode:
            Accepted = 1

        def __init__(self, vault, config):
            self.login_success = MagicMock()
            captured["login"] = self

        def exec(self):
            return _FakeLogin.DialogCode.Accepted

        def deleteLater(self):
            pass

    monkeypatch.setattr("src.app.LoginWindow", _FakeLogin)
    monkeypatch.setattr("src.app.build_business_context", lambda c, v: MagicMock())

    def _boom(_ctx):
        raise RuntimeError("construct fail")

    monkeypatch.setattr("src.app.MainWindow", _boom)

    critical_calls: list = []
    monkeypatch.setattr(
        "src.app.QMessageBox.critical",
        lambda *a, **k: critical_calls.append(a),
    )

    app._show_login()
    # on_login 经 login_success.connect 注册；手动触发模拟登录成功后进入主窗口构造
    on_login = captured["login"].login_success.connect.call_args[0][0]
    on_login()

    # 回滚：_main_window 归 None，未留半构造引用（信号槽半连接的不一致窗口）
    assert app._main_window is None
    # 用户可见的失败提示
    assert critical_calls
    # 已解锁的保险库被锁定，收缩明文密钥残留面
    app._vault.lock.assert_called_once()
    # 停止运行并退出事件循环
    assert app._running is False
    app._app.quit.assert_called_once()
