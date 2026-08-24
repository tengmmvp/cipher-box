"""应用主控 — 管理应用生命周期、登录流程和窗口切换。"""

import logging
import sys
from collections.abc import Callable
from types import TracebackType
from typing import TYPE_CHECKING

from PyQt6.QtCore import QLockFile, Qt
from PyQt6.QtWidgets import QApplication, QMessageBox

if TYPE_CHECKING:
    from PyQt6.QtCore import QEvent, QObject

from . import __version__
from .business.composition import build_business_context, build_vault
from .business.services.backup.purge import purge_restore_points
from .config import CFG_THEME, DEFAULT_THEME, ConfigManager
from .logging_config import configure_logging
from .ui.dialogs.login_window import LoginWindow
from .ui.resources.constants import ABOUT_TO_QUIT_WAIT_TIMEOUT_MS
from .ui.resources.font_loader import load_bundled_fonts
from .ui.resources.styles import get_style
from .ui.windows.main_window import MainWindow

logger = logging.getLogger(__name__)

# 单实例锁等待超时（ms）：QLockFile.tryLock 在另一实例持锁时等待此毫秒后放弃。
_SINGLE_INSTANCE_TIMEOUT_MS = 500


class CipherBoxApplication(QApplication):
    """自定义 QApplication，捕获信号槽（slot）回调内的未捕获异常。

    PyQt6 默认捕获并打印 slot 内异常、不传播到 ``sys.excepthook``。重写 ``notify``
    在 slot 异常时记录完整 traceback，使 slot 异常不再静默。不在此自动锁定/清理：
    单个 slot 异常触发锁定会过度反应，明文清理仍依赖 ``closeEvent``/``aboutToQuit``
    正常退出路径（见 ``_install_crash_handlers``）。
    """

    def notify(self, receiver: "QObject | None", event: "QEvent | None") -> bool:  # pyright: ignore[reportIncompatibleMethodOverride]
        # 根因：notify 在 typeshed 与 PyQt6 stub 间签名有已知差异，非真实方法冲突。
        try:
            return super().notify(receiver, event)
        except Exception:
            logger.error("PyQt 信号槽回调内未捕获异常", exc_info=True)
            return False


class CipherBoxApp:
    """CipherBox 应用主控。"""

    def __init__(self) -> None:
        # sys.argv 传给 QApplication 以支持 -style/-platform 等 Qt 平台参数；
        # CipherBox 自身不处理命令行参数。
        self._app = QApplication.instance() or CipherBoxApplication(sys.argv)
        self._main_window: MainWindow | None = None
        self._running = False
        # 崩溃/退出兜底：未捕获异常或绕过 closeEvent 的退出路径也要锁定保险库、
        # 清空剪贴板，收缩异常路径的明文残留面。安装点前移至 QApplication 创建后
        # 立即执行（QL-050）：excepthook 依赖的 aboutToQuit 信号挂在该实例上，而
        # 下方 ConfigManager/configure_logging/build_vault 等启动阶段异常自此即在
        # 兜底覆盖内。_emergency_cleanup 对 _vault/_main_window 的访问均有吞异常
        # 守卫，属性未就绪时按「无需清理」降级记录，不会因前移而崩溃。
        self._install_crash_handlers()
        self._config = ConfigManager()
        configure_logging(self._config.data_dir)
        # 打包 Inter 字体注册到 QFontDatabase；须在 QApplication 创建后、任何 widget
        # 构造前调用，否则首屏字面仍为回退字体。加载失败不阻塞（回退系统字体）。
        load_bundled_fonts()
        self._vault = build_vault(self._config)
        # 重试清理之前 purge 失败的恢复点（pre_restore_*.cbox，含恢复前全部明文）。
        # 恢复成功后应删除，之前因文件占用未删净的残留在此重试（重启后占用已释放）。
        try:
            purge_restore_points(self._config)
        except Exception:
            logger.warning("启动清理恢复点失败", exc_info=True)
        self._instance_lock = QLockFile(str(self._config.data_dir / "cipherbox.lock"))

    def _install_crash_handlers(self) -> None:
        """注册崩溃与退出兜底，收缩明文在异常/退出路径的内存残留面。

        覆盖范围与局限：
        - ``sys.excepthook``：仅覆盖**主线程非 slot 的未捕获异常**。slot 回调内异常
          默认被 Qt 捕获、不传播到 ``sys.excepthook`` 且应用继续运行——其明文清理依赖
          用户正常退出时的 ``closeEvent``/``aboutToQuit``。段错误、OS 强杀等 C 层崩溃
          无法由 Python 捕获，不在此兜底范围。
        - ``aboutToQuit``：事件循环正常结束时确保保险库锁定、剪贴板清空，覆盖
          ``quit()``、最后一窗关闭等绕过 ``closeEvent`` 的退出路径；不等待 worker 以免阻塞退出。
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
                # 崩溃兜底绝不能再抛出，但记录 exc_info 保留可审计性——静默失效最难诊断。
                logger.warning("崩溃兜底清理失败", exc_info=True)
            original_excepthook(exc_type, exc_value, exc_tb)

        sys.excepthook = _excepthook
        self._app.aboutToQuit.connect(lambda: self._emergency_cleanup(full=False))

    def _safe_cleanup(self, label: str, fn: Callable[[], None]) -> None:
        """执行一个崩溃/退出兜底清理步骤，吞异常并记录 exc_info。

        崩溃兜底路径绝不能因清理再次抛出；每步独立记录便于事后诊断哪个环节失效。
        """
        try:
            fn()
        except Exception:
            logger.warning(f"崩溃兜底：{label}失败", exc_info=True)

    def _emergency_cleanup(self, *, full: bool = False) -> None:
        """紧急清理：尽力锁定保险库并清空剪贴板。

        全程吞异常——崩溃/退出兜底绝不能因清理再次抛出。``full=True`` 额外触发
        ``prepare_for_lock`` 等待后台 worker（``excepthook``，进程仍存活）；
        ``full=False`` 跳过 worker 等待（``aboutToQuit``，避免阻塞退出）。``lock()``
        与 ``clear_now()`` 均幂等；保险库已锁定时短路，避免对已关闭 vault 重复
        ``lock()`` 触发回调访问已关闭 DB。各分支记 ``exc_info`` 而非静默 ``pass``：
        异常路径清理失败事后无法复现。
        """
        # 短路：保险库未解锁（已锁定/未登录）时无需清理，避免多处兜底对已 lock
        # 的 vault 重复操作。is_unlocked 访问吞异常以防 vault 异常态。
        try:
            if not self._vault.is_unlocked:
                return
        except Exception:
            logger.warning("崩溃兜底：检查解锁状态失败", exc_info=True)
        if full and self._main_window is not None:
            main_window = self._main_window
            self._safe_cleanup("prepare_for_lock", lambda: main_window.prepare_for_lock())
        if self._main_window is not None:
            main_window = self._main_window

            def _clear_clipboard() -> None:
                if not full:
                    # aboutToQuit 短超时等待 worker，让其退出后再 lock 清零，收缩
                    # 「已锁定」后明文残留窗口；超时放弃不阻塞退出。
                    main_window.emergency_cancel_workers(
                        wait_timeout_ms=ABOUT_TO_QUIT_WAIT_TIMEOUT_MS
                    )
                # 经公共方法而非 getattr 访问私有属性：重命名时 getattr 返回 None
                # 会无声错过清理，崩溃兜底最不应静默失效。
                main_window.emergency_clear_clipboard()

            self._safe_cleanup("清空剪贴板", _clear_clipboard)
        self._safe_cleanup("锁定保险库", lambda: self._vault.lock())

    def run(self) -> int:
        """启动应用。"""
        # 应用全局样式；显式激活主题，使运行时 c() 解析的颜色与样式表一致（ARCH-008）
        theme = self._config.get(CFG_THEME, DEFAULT_THEME)
        from .ui.resources.theme_colors import set_theme

        set_theme(theme)
        # 双重抑制：self._app 推断为 QCoreApplication 基类，mypy 与 pyright 均无法识别
        # QApplication.setStyleSheet（main_window 经 isinstance 收窄仅需 pyright 抑制）。
        self._app.setStyleSheet(get_style(theme))  # type: ignore[attr-defined]  # pyright: ignore[reportAttributeAccessIssue]

        # 设置应用属性
        self._app.setApplicationName("CipherBox")
        self._app.setOrganizationName("CipherBox")
        self._app.setApplicationVersion(__version__)

        if not self._instance_lock.tryLock(_SINGLE_INSTANCE_TIMEOUT_MS):
            QMessageBox.warning(None, "CipherBox", "CipherBox 已在运行，请勿重复启动。")
            return 1

        self._running = True
        self._show_login()

        try:
            return self._app.exec()
        except KeyboardInterrupt:
            # Ctrl+C (SIGINT) 抛 KeyboardInterrupt（BaseException 子类，notify 的
            # except Exception 捕获不到、不会发射 aboutToQuit）。显式执行紧急清理，
            # 清空剪贴板残留密码并锁定保险库，收缩信号退出的明文残留面。
            self._emergency_cleanup(full=False)
            return 1
        finally:
            self._instance_lock.unlock()

    def _show_login(self) -> None:
        """显示登录窗口。"""
        if not self._running:
            return

        login = LoginWindow(self._vault, self._config)

        def on_login() -> None:
            first_show = self._main_window is None
            if self._main_window is None:
                # MainWindow 构造涉及多个子系统，任一环节抛异常会留下半构造窗口。
                # 捕获后回滚引用为 None，提示重启而非 show 状态不一致的窗口。
                try:
                    self._main_window = MainWindow(
                        build_business_context(self._config, self._vault)
                    )
                except Exception:
                    logger.error("主窗口构造失败，已回滚", exc_info=True)
                    self._main_window = None
                    QMessageBox.critical(
                        None,
                        "启动失败",
                        "主窗口初始化失败，请重试或检查日志。保险库已解锁，退出前将自动锁定。",
                    )
                    self._vault.lock()
                    self._running = False
                    self._app.quit()
                    return
                self._main_window.lock_requested.connect(self._on_lock)
            # 逻辑不可达：_main_window 为 None 时上方 if 分支已 return。
            # 显式检查替代 assert，确保 python -O 下仍捕获意外状态。
            if self._main_window is None:
                raise RuntimeError("主窗口未初始化")
            self._main_window.refresh_after_unlock()
            self._main_window.show()
            # 首次显示时检查配置完整性，区分签名不符与签名缺失（更可疑：删除篡改痕迹）。
            if first_show and not self._config.check_integrity():
                reason = self._config.integrity_reason
                if reason == "missing":
                    detail = (
                        "配置文件的完整性签名缺失。这可能是文件损坏，也可能是外部修改后删除了签名。"
                    )
                else:
                    detail = "配置文件完整性校验失败，文件可能已损坏或被外部修改。"
                # 弱化「篡改」措辞：完整性 HMAC 密钥硬编码于源码，不防有意篡改
                # （能改配置者也能重算签名），故不暗示这是防篡改保证。
                QMessageBox.warning(
                    self._main_window,
                    "配置完整性提示",
                    f"{detail}\n安全相关的配置值已回退为安全默认值，建议检查数据目录安全性。",
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
            # 先隐藏主窗口：prepare_for_lock 关闭对话框时可能经 wait_worker_shutdown
            # 阻塞等待 worker（恢复/导入不可中断）。先 hide() 让窗口立即消失，配合
            # prepare_for_lock 内「先清明文 UI 再等 worker」收敛锁定请求到清零的暴露窗口。
            self._main_window.hide()
            self._main_window.prepare_for_lock()

        self._vault.lock()

        # 重新显示登录
        self._show_login()


def main() -> None:
    """应用入口。"""
    # 高 DPI 缩放在 Qt6 默认启用且无法关闭；此处仅设置取整策略为 PassThrough，避免模糊。
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough,
    )
    try:
        app = CipherBoxApp()
    except Exception:
        # 启动构造兜底（QL-050）：ConfigManager/configure_logging/build_vault 等阶段
        # 的异常若直接外溢，只在 stderr 留 traceback 后无声退出（QApplication 可能在
        # 弹窗前就已不可用）。configure_logging 可能未执行，先 basicConfig 兜底再
        # logger.critical（含 exc_info，同时覆盖「print 到 stderr」）；弹窗尽力而为，
        # 自身抛异常（无 QApplication/平台插件缺失）时吞掉，stderr 已留完整现场。
        logging.basicConfig(level=logging.ERROR)
        logger.critical("应用启动失败", exc_info=True)
        try:
            QMessageBox.critical(
                None,
                "CipherBox 启动失败",
                "应用初始化失败，请查看日志文件或重新安装。错误详情已输出到控制台。",
            )
        except Exception:
            pass
        sys.exit(1)
    # run() 阶段不在此兜底：此时 crash handler 已安装（__init__ 前移），运行期
    # 未捕获异常走 sys.excepthook → _emergency_cleanup 收缩明文残留面。
    sys.exit(app.run())
