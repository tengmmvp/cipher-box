"""字段行（敏感/普通）的共享构建逻辑。

DetailPanel 的敏感字段（含主密码）与普通字段、CustomFieldsRenderer 的自定义
字段与 PasswordHistoryWidget 的历史密码行共用此模块，消除多处重复的掩码标签、
显示/隐藏按钮、复制按钮与间接引用闭包逻辑（MAINT-103 收敛：掩码常量与
``sip.isdeleted`` 竞态守卫此前在 detail_panel 主密码分支与 password_history
各自平行实现；MAINT-113 收敛：普通字段行的复制按钮四件套此前在 detail_panel
与 custom_fields_renderer 近逐行双胞胎，且 renderer 侧复制闭包缺失守卫）。

两种自动掩码定时器模式：

- 默认（每行独立 QTimer）：各行独立计时、可同时揭示多行——自定义字段与
  密码历史行使用，定时器追加到 ``env.timers`` 由调用方统一停止；
- 共享单定时器（:class:`SharedHideTimer`）：多个字段行共用一个 QTimer 与
  「当前显式行」引用，任一新揭示先掩码上一显式行（同屏至多一行显式）——
  主密码字段使用，经 ``SecretFieldEnv.shared_hide`` 注入。
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Generic, TypeVar

from PyQt6 import sip
from PyQt6.QtCore import QObject, QTimer
from PyQt6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QWidget

from ...utils.memory import mark_secret_discarded
from ..resources.constants import BTN_COPY, PWD_MASK
from ..resources.icons import COPY, EYE, LOCK, set_icon
from .widgets import create_plain_text_label

_StoreKey = TypeVar("_StoreKey")


class RowValueStore:
    """int 行号键控的间接引用明文 holder（MAINT-115）：行号分配、存取与安全清零。

    detail_panel 的主条目普通字段与 custom_fields_renderer 的敏感/普通自定义字段
    此前各持「dict + 计数器 + mark_secret_discarded 清理块」三件套逐字重复——安全
    纪律（明文丢弃与计数复位须成对）的双份漂移面；收敛为单一 holder 后一处维护。
    行构建环境（PlainFieldEnv/SecretFieldEnv）经 :attr:`store` 持字典引用，清零仍
    须经 :meth:`clear` 收口（含计数复位）。
    """

    def __init__(self) -> None:
        self._values: dict[int, str] = {}
        self._next_row = 0

    @property
    def store(self) -> dict[int, str]:
        """间接引用字典本体（行构建环境注入用；清零须经 clear 收口，勿直改）。"""
        return self._values

    def next_key(self) -> int:
        """分配下一个行号（会话内单调递增，clear 后复位）。"""
        key = self._next_row
        self._next_row += 1
        return key

    def clear(self) -> None:
        """逐值 mark_secret_discarded 后清空并复位行号（切换条目/锁定时调用）。"""
        for key in list(self._values):
            mark_secret_discarded(self._values[key])
        self._values.clear()
        self._next_row = 0

    def __len__(self) -> int:
        return len(self._values)


def _make_icon_btn(tooltip: str, icon_name: str = COPY) -> QPushButton:
    """构造字段行的图标按钮（iconBtn + BTN_COPY 尺寸 + 图标 + 提示，MAINT-115）。

    敏感行的显示/隐藏与复制按钮、普通字段行的复制按钮三处同配方收敛（原三份
    逐字拷贝）；返回未连接 clicked 信号的按钮，由调用方按需连接。
    """
    btn = QPushButton()
    set_icon(btn, icon_name)
    btn.setObjectName("iconBtn")
    btn.setFixedSize(*BTN_COPY)
    btn.setToolTip(tooltip)
    return btn


def _make_guarded_copy(
    copy_btn: QPushButton,
    on_copy: Callable[[QPushButton, str], None],
    get_value: Callable[[], str],
) -> Callable[[], None]:
    """构造带 ``sip.isdeleted`` 竞态守卫的复制点击处理闭包（守卫单一事实源）。

    守卫对齐同工厂 ``_mask_row``/``_toggle`` 的形态：点击复制后同事件循环周期内
    按钮可能已被 ``deleteLater``（切换条目 force 重建/锁定清理），销毁窗口期内
    投递的挂起 ``clicked`` 事件仍会触发本处理函数——对已删 C++ 对象调用
    ``on_copy``（其内 ``set_icon`` 写反馈图标）抛 ``RuntimeError``，PyQt6 槽内
    未捕获异常直接 qFatal 中止应用。敏感行与普通字段行的复制按钮共用本工厂
    （MAINT-113：普通字段行原两份平行闭包中 renderer 侧缺失此守卫）。模块级
    工厂而非行内闭包：守卫行为需要测试直接驱动（按钮销毁后调用闭包不抛），
    行内闭包无外部引用不可达。
    """

    def _copy(_checked: bool = False) -> None:
        # 控件可能已被 `deleteLater`，挂起点击事件触发时用 `sip.isdeleted` 守卫跳过
        if sip.isdeleted(copy_btn):
            return
        on_copy(copy_btn, get_value())

    return _copy


def _make_copy_secret(
    env: SecretFieldEnv[_StoreKey],
    store_key: _StoreKey,
    copy_btn: QPushButton,
) -> Callable[[], None]:
    """构造敏感字段行复制按钮的点击处理闭包（MAINT-103，委托 :func:`_make_guarded_copy`）。

    模块级工厂而非行内闭包：守卫行为需要测试直接驱动（按钮销毁后调用闭包
    不抛），行内闭包无外部引用不可达。
    """
    return _make_guarded_copy(copy_btn, env.on_copy, lambda: env.store.get(store_key, ""))


class SharedHideTimer:
    """敏感字段行的共享单定时器显隐协调器。

    供「同屏至多一行显式」语义的字段族（如主密码——每条目仅一行）复用单个
    QTimer：任一行揭示时先掩码上一显式行，超时仅掩码当前行。``stop()`` 掩码
    当前显式行并停止定时器，供切换条目/锁定前收缩明文驻留。原 DetailPanel 的
    ``_pwd_hide_timer`` + ``_pwd_label_ref``/``_show_btn_ref`` 专属实现收敛于此
    （MAINT-103）。

    掩码回调由 :func:`make_secret_field_row` 构造（内置 ``sip.isdeleted`` 竞态
    守卫），本类只持有回调引用、不直接接触控件。
    """

    def __init__(self, parent: QObject) -> None:
        """Args:
        parent: 共享 QTimer 的父对象（承载定时器的 QObject，随父销毁）。
        """
        self._timer = QTimer(parent)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._on_timeout)
        self._current_mask: Callable[[], None] | None = None

    @property
    def is_active(self) -> bool:
        """共享定时器是否计时中（测试观察面，MAINT-095 先例）。"""
        return self._timer.isActive()

    def _on_timeout(self) -> None:
        """超时：掩码当前显式行并清空引用（槽位明文保留，支持再次揭示）。"""
        cb, self._current_mask = self._current_mask, None
        if cb is not None:
            cb()

    def reveal(self, mask_row: Callable[[], None], visible_ms: int) -> None:
        """揭示一行：先掩码上一显式行（单显式语义），重启共享定时器计时。"""
        prev, self._current_mask = self._current_mask, mask_row
        if prev is not None and prev is not mask_row:
            prev()
        self._timer.start(visible_ms)

    def conceal(self, mask_row: Callable[[], None]) -> None:
        """手动掩码：仅当前显式行的掩码停止计时，他行掩码不打断进行中的计时。"""
        if self._current_mask is mask_row:
            self._current_mask = None
            self._timer.stop()

    def stop(self) -> None:
        """掩码当前显式行并停止定时器（切换条目/锁定前收缩明文驻留）。

        掩码回调内置 ``sip.isdeleted`` 守卫，控件已销毁时安全跳过。
        """
        cb, self._current_mask = self._current_mask, None
        self._timer.stop()
        if cb is not None:
            cb()


@dataclass(frozen=True)
class SecretFieldEnv(Generic[_StoreKey]):
    """敏感字段行构建的共享环境（间接引用字典/定时器列表/回调）。

    聚合跨字段不变的依赖为单一参数，收敛 ``make_secret_field_row`` 的参数面。
    ``store`` / ``timers`` 由调用方持有以便锁定或切换条目时统一清零与停止；
    ``shared_hide`` 非 None 时该行走共享单定时器模式（``timers`` 不追加）。
    ``get_pwd_visible_ms`` 返回 None 表示该行不启动自动掩码（供回调未就位的
    降级路径，如 PasswordHistoryWidget 未注入回调时仍可揭示明文）。泛型
    ``_StoreKey`` 使 ``store`` 键类型与 ``store_key`` 参数保持一致
    （detail_panel 用 str 标签名，custom_fields_renderer/password_history 用
    int 行号）。
    """

    store: dict[_StoreKey, str]
    timers: list[QTimer]
    parent_widget: QObject
    get_pwd_visible_ms: Callable[[], int | None]
    on_copy: Callable[[QPushButton, str], None]
    on_copy_feedback: Callable[[], None]
    shared_hide: SharedHideTimer | None = None


def make_secret_field_row(
    env: SecretFieldEnv[_StoreKey],
    label_text: str,
    value: str,
    store_key: _StoreKey,
    *,
    name_label_style: str = "",
    val_label_style: str = "",
) -> tuple[QLabel, QWidget]:
    """构建一个敏感字段行：掩码标签 + 显示/隐藏按钮 + 复制按钮。

    明文经 ``env.store[store_key]`` 间接引用，闭包不直接捕获 value，便于调用方
    在切换条目或锁定时统一 ``mark_secret_discarded`` 清零。自动掩码定时器模式
    由环境决定：``env.shared_hide`` 非 None 走共享单定时器（同屏单显式），否则
    每行独立 QTimer 追加到 ``env.timers``，由调用方持有以便统一停止。

    Args:
        env: 跨字段共享的环境（间接引用字典、定时器列表、回调）。
        label_text: 字段显示名称。
        value: 字段明文值。
        store_key: ``env.store`` 中存储 value 的键，调用方保证唯一。
        name_label_style: 名称标签内联样式；为空则用 objectName ``fieldLabel`` 走 QSS。
        val_label_style: 值标签内联样式；为空则用 objectName ``secretValue`` 走 QSS。
    """
    # name/val 均可能承载用户数据（自定义字段名 / 揭示的敏感值），PlainText
    # 保证 `<` 开头的值按字面显示、与复制内容一致（SEC-030）。
    name_label = create_plain_text_label(f"{label_text}：")
    if name_label_style:
        name_label.setStyleSheet(name_label_style)
    else:
        name_label.setObjectName("fieldLabel")

    row_widget = QWidget()
    row_layout = QHBoxLayout(row_widget)
    row_layout.setContentsMargins(0, 0, 0, 0)

    val_label = create_plain_text_label(PWD_MASK)
    if val_label_style:
        val_label.setStyleSheet(val_label_style)
    else:
        val_label.setObjectName("secretValue")
    row_layout.addWidget(val_label, 1)

    show_btn = _make_icon_btn("显示/隐藏", EYE)

    env.store[store_key] = value

    # 掩码动作与竞态守卫收敛单处（MAINT-103）：调用方经 `deleteLater` 异步销毁
    # 控件，销毁窗口期内挂起的定时器/协调器回调仍可能触发，操作已删除的 C++
    # 对象会抛 `RuntimeError`——守卫先于此拦截（三处平行实现原先各写各的）。
    def _mask_row(lbl: QLabel = val_label, btn: QPushButton = show_btn) -> None:
        if sip.isdeleted(lbl) or sip.isdeleted(btn):
            return
        lbl.setText(PWD_MASK)
        set_icon(btn, EYE)

    # 两种定时器模式的启停策略：揭示侧启动计时、手动掩码侧停止计时。
    if env.shared_hide is not None:
        coordinator = env.shared_hide

        def _start_hide() -> None:
            visible_ms = env.get_pwd_visible_ms()
            if visible_ms is not None:
                coordinator.reveal(_mask_row, visible_ms)

        def _stop_hide() -> None:
            coordinator.conceal(_mask_row)

    else:
        field_timer = QTimer(env.parent_widget)
        field_timer.setSingleShot(True)
        field_timer.timeout.connect(_mask_row)
        env.timers.append(field_timer)

        def _start_hide() -> None:
            visible_ms = env.get_pwd_visible_ms()
            if visible_ms is not None:
                field_timer.start(visible_ms)

        def _stop_hide() -> None:
            field_timer.stop()

    def _toggle(
        _checked: bool = False,
        lbl: QLabel = val_label,
        btn: QPushButton = show_btn,
        key: _StoreKey = store_key,
    ) -> None:
        # 控件可能已被 `deleteLater`，异步回调（点击）触发时用 `sip.isdeleted` 守卫，避免访问已销毁控件抛 `RuntimeError`
        if sip.isdeleted(lbl) or sip.isdeleted(btn):
            return
        pwd = env.store.get(key, "")
        if lbl.text() == PWD_MASK:
            lbl.setText(pwd)
            set_icon(btn, LOCK)
            _start_hide()
        else:
            _mask_row()
            _stop_hide()

    show_btn.clicked.connect(_toggle)
    row_layout.addWidget(show_btn)

    copy_btn = _make_icon_btn("复制密码")

    copy_btn.clicked.connect(_make_copy_secret(env, store_key, copy_btn))
    copy_btn.clicked.connect(env.on_copy_feedback)
    row_layout.addWidget(copy_btn)

    return name_label, row_widget


@dataclass(frozen=True)
class PlainFieldEnv:
    """普通字段行构建的共享环境（间接引用字典/复制回调，MAINT-113）。

    与 :class:`SecretFieldEnv` 同构的最小聚合：``store`` 由调用方持有（两个构造点
    均为 :class:`RowValueStore` 的行号键控字典，MAINT-115），以便切换条目/锁定时
    统一 ``mark_secret_discarded`` 清零；``on_copy_feedback`` 为 None 时复制按钮
    不连线反馈信号（custom_fields_renderer 的普通自定义字段保持原「复制不提示」
    行为，detail_panel 主条目普通字段传入经状态栏提示）。不泛型化键型（MAINT-115）：
    两个构造点均为 ``dict[int, str]``，TypeVar 暗示的键型多样性不存在；敏感行
    :class:`SecretFieldEnv` 保持泛型（detail_panel 用 str 标签名键控）。
    """

    store: dict[int, str]
    on_copy: Callable[[QPushButton, str], None]
    on_copy_feedback: Callable[[], None] | None = None


def make_plain_field_row(
    env: PlainFieldEnv,
    label_text: str,
    value: str,
    store_key: int,
    *,
    copyable: bool = True,
) -> tuple[QLabel, QWidget]:
    """构建一个普通字段行：名称标签 + 明文值标签 + 可选复制按钮（MAINT-113）。

    原两份近逐行相同的实现（detail_panel 的账号行与 custom_fields_renderer 的
    非密码自定义字段行）收敛于此：明文经 ``env.store[store_key]`` 间接引用
    （与敏感字段行同构），复制处理闭包经 :func:`_make_guarded_copy` 带
    ``sip.isdeleted`` 竞态守卫——renderer 侧原闭包缺失守卫，按钮销毁窗口期内
    挂起 ``clicked`` 投递会直达 ``on_copy`` 内的反馈图标写入。

    Args:
        env: 跨行共享的环境（间接引用字典、复制回调）。
        label_text: 字段显示名称。
        value: 字段明文值。
        store_key: ``env.store`` 中存储 value 的行号键，调用方保证唯一。
        copyable: 是否附带复制按钮；仅 ``copyable and value`` 时写 store 并建按钮。
    """
    # 名称与值均可能承载用户/导入数据（字段名 / username 等明文），PlainText
    # 防富文本注入（SEC-030）
    name_label = create_plain_text_label(f"{label_text}：", "fieldLabel")

    row_widget = QWidget()
    row_layout = QHBoxLayout(row_widget)
    row_layout.setContentsMargins(0, 0, 0, 0)

    val_label = create_plain_text_label(value, "fieldValue", word_wrap=True)
    row_layout.addWidget(val_label, 1)

    if copyable and value:
        env.store[store_key] = value
        copy_btn = _make_icon_btn("复制")

        copy_btn.clicked.connect(
            _make_guarded_copy(copy_btn, env.on_copy, lambda: env.store.get(store_key, ""))
        )
        if env.on_copy_feedback is not None:
            copy_btn.clicked.connect(env.on_copy_feedback)
        row_layout.addWidget(copy_btn)

    return name_label, row_widget
