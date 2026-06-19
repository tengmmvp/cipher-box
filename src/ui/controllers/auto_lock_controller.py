"""自动锁定控制器 — 从 MainWindow 抽离的空闲超时与系统锁屏联动。

持有自动锁定定时器与 Windows 会话锁屏事件过滤器，封装 ``auto_lock_minutes``
驱动的超时重置与 WTS 锁屏即时锁定。MainWindow 的 eventFilter/showEvent 等 Qt
重写检测到用户活动或窗口显示时委托本控制器，自身不再直接持有 ``_lock_timer``
与 ``_session_filter`` 状态。
"""

from __future__ import annotations

import logging
import sys
from collections.abc import Callable
from typing import TYPE_CHECKING

from PyQt6 import sip
from PyQt6.QtCore import QAbstractNativeEventFilter, QByteArray, QObject, QTimer
from PyQt6.QtWidgets import QApplication

if TYPE_CHECKING:
    from PyQt6.QtWidgets import QWidget

    from ...business.managers.vault_manager import VaultManager
    from ...config import ConfigManager

logger = logging.getLogger(__name__)

# Windows 会话锁屏通知消息常量。系统锁屏（Win+L）时立即锁定保险库（1Password/
# Bitwarden 等行业惯例），而非等应用内 QTimer 到期。非 Windows 平台不注册
# （setup_session_notification 以 sys.platform 短路），降级为仅超时锁定。
_WM_WTSSESSION_CHANGE = 0x02B1
_WTS_SESSION_LOCK = 0x7


class _SessionLockFilter(QAbstractNativeEventFilter):
    """Windows 会话锁屏事件过滤器，捕获 WM_WTSSESSION_CHANGE 触发保险库锁定。

    用 QAbstractNativeEventFilter 挂载 QApplication，而非重写 MainWindow.nativeEvent：
    后者在 MainWindow 多继承（FiltersMixin/MenuMixin/QMainWindow）MRO 下会触发
    C 层 access violation；独立过滤器规避该问题，是 Qt 推荐的原生消息拦截方式。
    """

    def __init__(self, on_lock: Callable[[], None]) -> None:
        super().__init__()
        self._on_lock = on_lock

    def nativeEventFilter(self, eventType: QByteArray | bytes, message: sip.voidptr) -> tuple[bool, int]:  # type: ignore[override]  # pyright: ignore[reportIncompatibleMethodOverride]
        try:
            if bytes(eventType) == b'windows_generic_MSG':  # type: ignore[arg-type]  # pyright: ignore[reportArgumentType]
                from ctypes import wintypes
                msg = wintypes.MSG.from_address(int(message))  # pyright: ignore[reportArgumentType]
                if msg.message == _WM_WTSSESSION_CHANGE and msg.wParam == _WTS_SESSION_LOCK:
                    self._on_lock()
        except Exception:
            logger.debug("会话锁屏过滤器处理消息失败", exc_info=True)
        return False, 0


class AutoLockController:
    """自动锁定定时器与会话锁屏联动的生命周期管理。"""

    def __init__(
        self,
        vault: VaultManager,
        config: ConfigManager,
        on_lock: Callable[[], None],
    ) -> None:
        self._vault = vault
        self._config = config
        self._on_lock = on_lock
        self._lock_timer: QTimer | None = None
        self._session_filter: _SessionLockFilter | None = None
        self._wts_setup_attempted = False
        self._wts_registered = False

    def setup(self, parent: QObject) -> None:
        """创建锁定定时器并立即按当前 auto_lock_minutes 启动一次重置。"""
        self._lock_timer = QTimer(parent)
        self._lock_timer.setSingleShot(True)
        self._lock_timer.timeout.connect(self._on_lock)
        self.reset_timer()

    def reset_timer(self) -> None:
        """按 auto_lock_minutes 重置定时器；未解锁或关闭时停止。"""
        if self._lock_timer is None:
            return
        minutes = self._config.get_safe('auto_lock_minutes', 5)
        if not self._vault.is_unlocked or minutes <= 0:
            self._lock_timer.stop()
            return
        self._lock_timer.start(minutes * 60 * 1000)

    def stop_timer(self) -> None:
        """锁定前停止定时器（prepare_for_lock 调用）。"""
        if self._lock_timer is not None:
            self._lock_timer.stop()

    def setup_session_notification(self, window: QWidget) -> None:
        """注册 Windows 会话锁屏通知，系统锁屏时立即触发锁定。

        仅 Windows 平台启用；注册失败（如远程会话、权限受限、wtsapi32 不可用）
        静默降级为仅 QTimer 超时锁定。须在窗口 show 后（HWND 有效）调用，
        故由 MainWindow.showEvent 首次触发。测试环境（pytest）跳过，不安装过滤器。
        """
        # WTS 注册须在窗口 show 后（HWND 有效）；__init__ 时未 show 会触发 C 层
        # access violation。_wts_setup_attempted 守卫使注册仅在实际显示时发生一次。
        if self._wts_setup_attempted:
            return
        self._wts_setup_attempted = True
        # 仅 Windows 交互会话注册。测试环境（pytest 驱动 QApplication）的窗口未进入
        # 真实消息循环，WTSRegisterSessionNotification 会触发 C 层 access violation
        # （无法 try/except 捕获）；真实交互运行时窗口进入消息循环，WTS 正常工作。
        if sys.platform != 'win32' or 'pytest' in sys.modules:
            return
        try:
            import ctypes
            from ctypes import wintypes
            # 显式声明 argtypes/restype：HWND 是指针类型，64 位下默认 c_int 推断会使
            # HWND 传参截断，触发 access violation（C 层崩溃，try/except 无法捕获）。
            wts = ctypes.windll.wtsapi32
            wts.WTSRegisterSessionNotification.argtypes = [
                wintypes.HWND, wintypes.DWORD,
            ]
            wts.WTSRegisterSessionNotification.restype = wintypes.BOOL
            hwnd = int(window.winId())
            # NOTIFY_FOR_THIS_SESSION = 0：仅当前会话的锁屏/解锁通知
            if wts.WTSRegisterSessionNotification(hwnd, 0):
                self._wts_registered = True
                self._session_filter = _SessionLockFilter(self._on_lock)
                app = QApplication.instance()
                if app is not None:
                    app.installNativeEventFilter(self._session_filter)
            else:
                logger.debug("WTSRegisterSessionNotification 返回 0，会话锁屏联动降级")
        except Exception:
            logger.debug("WTS 会话通知注册失败，降级为仅 QTimer 超时锁定", exc_info=True)

    def remove_session_filter(self) -> None:
        """退出/完全关闭时移除会话锁屏过滤器，解除 QApplication 对其闭包的引用。"""
        if self._session_filter is None:
            return
        app = QApplication.instance()
        if app is not None:
            app.removeNativeEventFilter(self._session_filter)
