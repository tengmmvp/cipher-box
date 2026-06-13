"""应用主控 — 管理应用生命周期、登录流程和窗口切换"""

import sys

from PyQt6.QtCore import QLockFile, Qt
from PyQt6.QtWidgets import QApplication, QMessageBox

from . import __version__
from .business.managers.vault_manager import VaultManager
from .config import ConfigManager
from .logging_config import configure_logging
from .ui.dialogs.login_window import LoginWindow
from .ui.resources.styles import get_style
from .ui.windows.main_window import MainWindow


class CipherBoxApp:
    """CipherBox 应用主控"""

    def __init__(self):
        # sys.argv 传递给 QApplication 以支持 Qt 平台参数如 -style 和 -platform，
        # CipherBox 自身不处理命令行参数。
        self._app = QApplication.instance() or QApplication(sys.argv)
        self._config = ConfigManager()
        configure_logging(self._config.data_dir)
        self._vault = VaultManager(self._config)
        self._main_window: MainWindow | None = None
        self._running = False
        self._instance_lock = QLockFile(str(self._config.data_dir / 'cipherbox.lock'))
        # 崩溃/退出兜底：未捕获异常或绕过 closeEvent 的退出路径，也要锁定保险库、
        # 清空剪贴板，收缩明文密钥与明文密码在异常路径的内存残留面。
        self._install_crash_handlers()

    def _install_crash_handlers(self) -> None:
        """注册崩溃与退出兜底，收缩明文在异常/退出路径的内存残留面。

        覆盖范围与局限（重要）：
        - ``sys.excepthook``：仅覆盖**主线程非 slot 的未捕获异常**（进程将退出型崩溃）。
          PyQt6 信号槽（slot）回调内的异常默认被 Qt 捕获并打印、不传播到
          ``sys.excepthook``，且应用通常继续运行——slot 异常不应触发锁定（会过度
          反应），其明文清理依赖用户正常退出时的 ``closeEvent`` / ``aboutToQuit``。
          段错误、OS 强杀等 C 层崩溃无法由 Python 捕获，不在此兜底范围内。
        - ``QApplication.aboutToQuit``：事件循环正常结束时确保保险库已锁定、剪贴板
          已清空，覆盖 ``quit()``、最后一窗关闭等绕过 ``closeEvent`` 的退出路径；
          不等待 worker 以免阻塞退出。
        """
        original_excepthook = sys.excepthook

        def _excepthook(exc_type, exc_value, exc_tb):
            try:
                self._emergency_cleanup(full=True)
            except Exception:
                pass
            original_excepthook(exc_type, exc_value, exc_tb)

        sys.excepthook = _excepthook
        self._app.aboutToQuit.connect(lambda: self._emergency_cleanup(full=False))

    def _emergency_cleanup(self, *, full: bool = False) -> None:
        """紧急清理：尽力锁定保险库并清空剪贴板。

        全程吞掉异常——崩溃/退出兜底路径绝不能因清理再次抛出。``full=True``
        额外触发 ``prepare_for_lock`` 等待后台 worker（用于 ``excepthook``，
        进程仍存活）；``full=False`` 跳过 worker 等待（用于 ``aboutToQuit``，
        避免阻塞退出）。``lock()`` 与 ``clear_now()`` 均幂等；保险库已锁定时短路，
        避免 ``closeEvent``/``_quit_app`` 已先行清理后 ``aboutToQuit`` 对已关闭的
        vault 重复 ``lock()`` 触发回调访问已关闭 DB。
        """
        # 短路：保险库未解锁（已锁定/未登录）时无需清理，避免退出路径多处兜底
        # 对已 lock 的 vault 重复操作。is_unlocked 访问也吞异常以防 vault 异常态。
        try:
            if not self._vault.is_unlocked:
                return
        except Exception:
            pass
        if full and self._main_window is not None:
            try:
                self._main_window.prepare_for_lock()
            except Exception:
                pass
        clipboard = getattr(self._main_window, '_clipboard', None)
        if clipboard is not None:
            try:
                clipboard.clear_now()
            except Exception:
                pass
        try:
            self._vault.lock()
        except Exception:
            pass

    def run(self) -> int:
        """启动应用"""
        # 应用全局样式
        theme = self._config.get('theme', 'light')
        self._app.setStyleSheet(get_style(theme))  # type: ignore[attr-defined]

        # 设置应用属性
        self._app.setApplicationName('CipherBox')
        self._app.setOrganizationName('CipherBox')
        self._app.setApplicationVersion(__version__)

        if not self._instance_lock.tryLock(500):
            QMessageBox.warning(None, 'CipherBox', 'CipherBox 已在运行，请勿重复启动。')
            return 1

        self._running = True
        self._show_login()

        try:
            return self._app.exec()
        finally:
            self._instance_lock.unlock()

    def _show_login(self):
        """显示登录窗口"""
        if not self._running:
            return

        login = LoginWindow(self._vault)

        def on_login():
            first_show = self._main_window is None
            if self._main_window is None:
                self._main_window = MainWindow(self._config, self._vault)
                self._main_window.lock_requested.connect(self._on_lock)
            assert self._main_window is not None
            self._main_window.refresh_after_unlock()
            self._main_window.show()
            # 配置完整性校验失败时提示用户，首次显示时检查一次。
            # 区分签名不符（篡改）与签名缺失（更可疑：主动删除篡改痕迹）。
            if first_show and not self._config.check_integrity():
                reason = self._config.integrity_reason
                if reason == 'missing':
                    detail = '配置文件的完整性签名缺失（可能被主动删除以绕过校验）。'
                else:
                    detail = '配置文件完整性校验失败，可能已被篡改。'
                QMessageBox.warning(
                    self._main_window, '配置完整性警告',
                    f'{detail}\n异常或可疑的安全配置值已回退为安全默认值，'
                    '建议检查数据目录安全性。',
                )

        login.login_success.connect(on_login)

        result = login.exec()
        login.deleteLater()
        if result != LoginWindow.DialogCode.Accepted:
            self._running = False
            self._app.quit()

    def _on_lock(self):
        """锁定保险库"""
        if self._main_window:
            self._main_window.prepare_for_lock()
            self._main_window.hide()

        self._vault.lock()

        # 重新显示登录
        self._show_login()


def main():
    """应用入口"""
    # 高 DPI 支持
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough,
    )

    app = CipherBoxApp()
    sys.exit(app.run())
