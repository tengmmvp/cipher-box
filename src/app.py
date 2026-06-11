"""应用主控 - 管理应用生命周期、登录流程和窗口切换"""

import sys

from PyQt6.QtCore import QLockFile, Qt
from PyQt6.QtWidgets import QApplication, QMessageBox

from . import __version__
from .business.vault_manager import VaultManager
from .config import ConfigManager
from .logging_config import configure_logging
from .ui.login_window import LoginWindow
from .ui.main_window import MainWindow
from .ui.resources.styles import get_style


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
            # 配置完整性校验失败时提示用户，首次显示时检查一次
            if first_show and not self._config.check_integrity():
                QMessageBox.warning(
                    self._main_window, '配置完整性警告',
                    '检测到配置文件完整性校验失败，可能已被篡改或损坏。\n'
                    '异常配置值已回退为默认值，建议检查数据目录安全性。',
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
