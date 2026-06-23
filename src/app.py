"""应用主控 — 管理应用生命周期、登录流程和窗口切换。"""

import logging
import sys
from types import TracebackType
from typing import TYPE_CHECKING

from PyQt6.QtCore import QLockFile, Qt
from PyQt6.QtWidgets import QApplication, QMessageBox

if TYPE_CHECKING:
    from PyQt6.QtCore import QEvent, QObject

from . import __version__
from .business.composition import build_business_context
from .business.managers.vault_manager import VaultManager
from .config import ConfigManager
from .logging_config import configure_logging
from .ui.dialogs.login_window import LoginWindow
from .ui.resources.styles import get_style
from .ui.windows.main_window import MainWindow

logger = logging.getLogger(__name__)


class CipherBoxApplication(QApplication):
    """自定义 QApplication，捕获信号槽（slot）回调内的未捕获异常。

    PyQt6 默认捕获并打印 slot 内异常、不传播到 ``sys.excepthook``，应用继续运行。
    重写 ``notify`` 在 slot 异常时记录完整 traceback（默认仅打印摘要），使 slot
    异常不再静默，便于诊断 UI 不一致根因。不在此自动锁定/清理：单个 slot 异常
    触发锁定会过度反应，明文清理仍依赖 ``closeEvent`` / ``aboutToQuit`` 正常退出
    路径（见 ``_install_crash_handlers``）。
    """

    def notify(self, receiver: 'QObject | None', event: 'QEvent | None') -> bool:  # pyright: ignore[reportIncompatibleMethodOverride]
        # reportIncompatibleMethodOverride 根因：Qt 的 notify 在 typeshed 与 PyQt6 stub
        # 间签名存在已知差异（协变/参数标注），非真实方法冲突，待 stub 对齐后可移除此抑制。
        try:
            return super().notify(receiver, event)
        except Exception:
            logger.error("PyQt 信号槽回调内未捕获异常", exc_info=True)
            return False


class CipherBoxApp:
    """CipherBox 应用主控。"""

    def __init__(self) -> None:
        # sys.argv 传递给 QApplication 以支持 Qt 平台参数如 -style 和 -platform，
        # CipherBox 自身不处理命令行参数。
        self._app = QApplication.instance() or CipherBoxApplication(sys.argv)
        self._config = ConfigManager()
        configure_logging(self._config.data_dir)
        self._vault = VaultManager(self._config)
        # 启动时重试清理之前 purge 失败的恢复点（pre_restore_*.cbox，含恢复前全部
        # 条目明文），收缩历史明文泄漏面。恢复点是临时安全快照，恢复成功后应删除；
        # 之前因文件占用未删净的残留在此重试（重启后占用进程已释放）。
        try:
            self._vault.purge_restore_points()
        except Exception:
            logger.warning("启动清理恢复点失败", exc_info=True)
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

        def _excepthook(
            exc_type: type[BaseException],
            exc_value: BaseException,
            exc_tb: TracebackType | None,
        ) -> None:
            try:
                self._emergency_cleanup(full=True)
            except Exception:
                # 崩溃兜底绝不能再次抛出（会让进程状态进一步恶化），但记录 exc_info
                # 保留可审计性——崩溃清理静默失效是密码管理器最难诊断的安全路径。
                logger.warning("崩溃兜底清理失败", exc_info=True)
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

        每个兜底分支记录 ``exc_info`` 而非静默 ``pass``：崩溃/退出路径的清理失败
        事后无法复现，缺日志会让"锁屏/剪贴板清理在异常态静默失效"无从诊断。
        """
        # 短路：保险库未解锁（已锁定/未登录）时无需清理，避免退出路径多处兜底
        # 对已 lock 的 vault 重复操作。is_unlocked 访问也吞异常以防 vault 异常态。
        try:
            if not self._vault.is_unlocked:
                return
        except Exception:
            logger.warning("崩溃兜底：检查解锁状态失败", exc_info=True)
        if full and self._main_window is not None:
            try:
                self._main_window.prepare_for_lock()
            except Exception:
                logger.warning("崩溃兜底：prepare_for_lock 失败", exc_info=True)
        if self._main_window is not None:
            try:
                if not full:
                    # aboutToQuit 取消 worker 并短超时等待（400ms），让持密钥解密的
                    # worker 退出协作循环后再 lock 清零，收缩「已锁定」后明文残留窗口；
                    # 超时放弃不阻塞退出，与 _shutdown_workers 的长等待语义区分。
                    self._main_window.emergency_cancel_workers(wait_timeout_ms=400)
                # 经公共方法而非 getattr 访问 _clipboard 私有属性：崩溃兜底路径
                # 最不应静默失效，私有属性重命名时 getattr 返回 None 会无声错过清理。
                self._main_window.emergency_clear_clipboard()
            except Exception:
                logger.warning("崩溃兜底：清空剪贴板失败", exc_info=True)
        try:
            self._vault.lock()
        except Exception:
            logger.warning("崩溃兜底：锁定保险库失败", exc_info=True)

    def run(self) -> int:
        """启动应用。"""
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

    def _show_login(self) -> None:
        """显示登录窗口。"""
        if not self._running:
            return

        login = LoginWindow(self._vault)

        def on_login() -> None:
            first_show = self._main_window is None
            if self._main_window is None:
                # MainWindow 构造涉及 UI 组件、托盘、定时器、WTS 注册等多个子系统，
                # 任一环节抛异常会留下半构造窗口与已连接的部分信号槽。捕获后回滚
                # 引用为 None，提示用户重启而非继续 show 一个状态不一致的窗口。
                try:
                    self._main_window = MainWindow(build_business_context(self._config, self._vault))
                except Exception:
                    logger.error("主窗口构造失败，已回滚", exc_info=True)
                    self._main_window = None
                    QMessageBox.critical(
                        None, '启动失败',
                        '主窗口初始化失败，请重试或检查日志。保险库已解锁，'
                        '退出前将自动锁定。',
                    )
                    self._vault.lock()
                    self._running = False
                    self._app.quit()
                    return
                self._main_window.lock_requested.connect(self._on_lock)
            # 逻辑不可达：_main_window 为 None 时上方 if 分支已 return。
            # 显式检查替代 assert，确保 python -O 下仍捕获意外状态。
            if self._main_window is None:
                raise RuntimeError('主窗口未初始化')
            self._main_window.refresh_after_unlock()
            self._main_window.show()
            # 配置完整性校验失败时提示用户，首次显示时检查一次。
            # 区分签名不符（篡改）与签名缺失（更可疑：主动删除篡改痕迹）。
            if first_show and not self._config.check_integrity():
                reason = self._config.integrity_reason
                if reason == 'missing':
                    detail = '配置文件的完整性签名缺失。这可能是文件损坏，也可能是外部修改后删除了签名。'
                else:
                    detail = '配置文件完整性校验失败，文件可能已损坏或被外部修改。'
                # 措辞刻意弱化「篡改」：完整性 HMAC 密钥硬编码于源码，不防护有意篡改
                # （能改配置者通常也能重算签名），故对用户不暗示这是防篡改保证。
                QMessageBox.warning(
                    self._main_window, '配置完整性提示',
                    f'{detail}\n安全相关的配置值已回退为安全默认值，'
                    '建议检查数据目录安全性。',
                )

        login.login_success.connect(on_login)

        result = login.exec()
        login.deleteLater()
        if result != LoginWindow.DialogCode.Accepted:
            self._running = False
            self._app.quit()

    def _on_lock(self) -> None:
        """锁定保险库。"""
        if self._main_window:
            self._main_window.prepare_for_lock()
            self._main_window.hide()

        self._vault.lock()

        # 重新显示登录
        self._show_login()


def main() -> None:
    """应用入口。"""
    # 高 DPI 缩放在 Qt6 默认启用且无法关闭；此处仅设置取整策略为 PassThrough，
    # 避免半像素缩放导致的模糊。
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough,
    )

    app = CipherBoxApp()
    sys.exit(app.run())
