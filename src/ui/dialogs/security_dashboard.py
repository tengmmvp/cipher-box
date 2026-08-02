"""安全仪表盘，可视化展示保险库的安全概况。

后台线程汇总弱密码/重复/过期三类风险，以健康评分圆环、统计卡片与详细
列表呈现；用户请求修复时由信号携带 entry_id 上报主窗口。
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from PyQt6.QtCore import QRectF, Qt
from PyQt6.QtGui import QColor, QFont, QPainter, QPaintEvent, QPen
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLayout,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ...business.services.security_analyzer import SecurityAnalyzer
from ...config import CFG_OLD_PASSWORD_WARNING_DAYS
from ...utils.format import format_datetime
from ..components.widgets import (
    WorkerBackedDialog,
    clear_layout,
    finalize_worker_if_current,
    release_worker,
    setup_dialog_flags,
)
from ..components.workers import BackgroundWorker
from ..resources.constants import (
    BTN_DIALOG,
    BTN_FIX,
    DIALOG_SECURITY_DASHBOARD_MIN_SIZE,
    FONT_FAMILY_DISPLAY,
)
from ..resources.radius import RADIUS_TAG
from ..resources.strings import DLG_TITLE_ERROR
from ..resources.theme_colors import c, get_strength_color

if TYPE_CHECKING:
    from ...business.managers.entry_manager import EntryManager
    from ...config import ConfigManager
    from ...models import Entry

logger = logging.getLogger(__name__)

_BADGE_BG_ALPHA = 0.13


class _HealthScoreWidget(QWidget):
    """以圆环进度形式绘制安全健康评分的自定义组件。"""

    # `paintEvent` 绘制参数（QL-013，提取魔数）：圆环几何与 Qt `drawArc` 角度常量。
    _RING_PADDING_PX = 12  # 圆环与控件边缘的间距
    _RING_PEN_WIDTH = 10  # 圆环线条粗细（像素）
    _ANGLE_TICKS_PER_DEGREE = 16  # Qt drawArc 角度单位为 1/16 度
    _FULL_CIRCLE_DEG = 360
    _START_ANGLE_DEG = 90  # 起始角位于顶部

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._score = 100
        self.setFixedSize(160, 160)
        # 预创建字体，避免 `paintEvent` 每帧重复构造 `QFont`
        self._score_font = QFont(FONT_FAMILY_DISPLAY, 28, QFont.Weight.DemiBold)
        self._label_font = QFont(FONT_FAMILY_DISPLAY, 11)

    def set_score(self, score: int) -> None:
        self._score = max(0, min(100, score))
        self.update()

    def paintEvent(self, a0: QPaintEvent | None) -> None:
        painter = QPainter(self)
        try:
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            painter.save()

            side = min(self.width(), self.height())
            center_x = self.width() / 2
            center_y = self.height() / 2
            radius = side / 2 - self._RING_PADDING_PX
            pen_width = self._RING_PEN_WIDTH

            bg_pen = QPen(
                QColor(c("progress_bg")), pen_width, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap
            )
            painter.setPen(bg_pen)
            draw_rect = QRectF(
                center_x - radius,
                center_y - radius,
                radius * 2,
                radius * 2,
            )
            painter.drawArc(draw_rect, 0, self._FULL_CIRCLE_DEG * self._ANGLE_TICKS_PER_DEGREE)

            score_color = self._health_score_color(self._score)
            fg_pen = QPen(
                QColor(score_color), pen_width, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap
            )
            painter.setPen(fg_pen)
            span_angle = int(
                self._score / 100 * self._FULL_CIRCLE_DEG * self._ANGLE_TICKS_PER_DEGREE
            )
            start_angle = self._START_ANGLE_DEG * self._ANGLE_TICKS_PER_DEGREE
            painter.drawArc(draw_rect, start_angle, -span_angle)

            painter.setPen(QColor(c("text_primary")))
            painter.setFont(self._score_font)
            painter.drawText(draw_rect, Qt.AlignmentFlag.AlignCenter, str(self._score))

            painter.setFont(self._label_font)
            painter.setPen(QColor(c("text_secondary")))
            label_rect = QRectF(
                center_x - radius,
                center_y + 8,
                radius * 2,
                20,
            )
            painter.drawText(label_rect, Qt.AlignmentFlag.AlignCenter, "安全评分")

            painter.restore()
        finally:
            painter.end()

    @staticmethod
    def _health_score_color(score: int) -> str:
        """按健康评分区间映射颜色 token：≥80 success、≥60 warning、≥40 warning_orange、其余 danger。"""
        if score >= 80:
            return c("success")
        elif score >= 60:
            return c("warning")
        elif score >= 40:
            return c("warning_orange")
        else:
            return c("danger")


class _StatCard(QFrame):
    """安全仪表盘顶部统计卡片，展示单项风险计数并提供跳转/修复入口。"""

    def __init__(
        self, title: str, count: int, color: str, button_text: str, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self._setup_ui(title, count, color, button_text)

    def update_count(self, count: int) -> None:
        self._count_label.setText(str(count))

    def _setup_ui(self, title: str, count: int, color: str, button_text: str) -> None:
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setObjectName("statCard")

        layout = QVBoxLayout(self)
        layout.setSpacing(6)

        title_label = QLabel(title)
        title_label.setObjectName("statCardTitle")
        layout.addWidget(title_label)

        count_label = QLabel(str(count))
        count_label.setStyleSheet(f"font-size: 32px; font-weight: 600; color: {color};")
        self._count_label = count_label  # 保存引用供 update_count 刷新
        layout.addWidget(count_label)

        action_btn = QPushButton(button_text)
        action_btn.setObjectName("statActionBtn")
        action_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.action_button = action_btn
        layout.addWidget(action_btn)

        layout.addStretch()


class SecurityDashboard(WorkerBackedDialog):
    """安全仪表盘主对话框，展示风险概况并提供修复入口。

    后台线程加载报告避免阻塞 UI；关闭前等待 worker 结束，防止对已销毁
    部件发出信号。
    """

    def __init__(
        self,
        security_analyzer: SecurityAnalyzer,
        entry_manager: EntryManager,
        config: ConfigManager,
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self._pending_fix_id: int | None = None
        self._security = security_analyzer
        self._entry_mgr = entry_manager
        self._config = config
        self._weak_entries: list[Entry] = []
        self._duplicate_groups: list[list[Entry]] = []
        self._old_entries: list[Entry] = []
        self._status_hint: QLabel | None = None
        self._setup_ui()
        self._load_data()

    def _after_release(self) -> None:
        # 清空明文条目，缩短敏感数据在对话框关闭后的驻留时间
        self._weak_entries = []
        self._duplicate_groups = []
        self._old_entries = []

    def _setup_ui(self) -> None:
        self.setWindowTitle("安全仪表盘")
        self.setMinimumSize(*DIALOG_SECURITY_DASHBOARD_MIN_SIZE)
        setup_dialog_flags(self)

        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(16)

        # ===== 顶部区域：健康评分 + 统计卡片 =====
        top_layout = QHBoxLayout()
        top_layout.setSpacing(20)

        score_container = QVBoxLayout()
        score_container.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._health_widget = _HealthScoreWidget()
        score_container.addWidget(self._health_widget, alignment=Qt.AlignmentFlag.AlignCenter)
        top_layout.addLayout(score_container)

        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(12)

        self._weak_card = _StatCard("弱密码", 0, c("danger"), "立即修复", self)
        self._weak_card.action_button.clicked.connect(self._on_fix_weak)
        cards_layout.addWidget(self._weak_card)

        self._dup_card = _StatCard("重复密码组", 0, c("warning_orange"), "查看详情", self)
        self._dup_card.action_button.clicked.connect(lambda: self._tabs.setCurrentIndex(1))
        cards_layout.addWidget(self._dup_card)

        self._old_card = _StatCard("过期密码", 0, c("warning"), "查看详情", self)
        self._old_card.action_button.clicked.connect(lambda: self._tabs.setCurrentIndex(2))
        cards_layout.addWidget(self._old_card)

        top_layout.addLayout(cards_layout, stretch=1)
        main_layout.addLayout(top_layout)

        separator = QFrame()
        separator.setFixedHeight(1)
        separator.setObjectName("detailDivider")
        main_layout.addWidget(separator)

        # ===== 详细列表区域 =====
        self._tabs = QTabWidget()
        self._tabs.addTab(self._create_weak_tab(), "弱密码")
        self._tabs.addTab(self._create_duplicate_tab(), "重复密码")
        self._tabs.addTab(self._create_old_tab(), "过期密码")
        main_layout.addWidget(self._tabs, stretch=1)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        close_btn = QPushButton("关闭")
        close_btn.setFixedSize(*BTN_DIALOG)
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)
        main_layout.addLayout(btn_layout)

    def _create_weak_tab(self) -> QWidget:
        widget = QWidget()
        scroll = QScrollArea(widget)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        self._weak_container = QWidget()
        self._weak_layout = QVBoxLayout(self._weak_container)
        self._weak_layout.setSpacing(6)
        self._weak_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        scroll.setWidget(self._weak_container)

        outer = QVBoxLayout(widget)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)
        return widget

    def _create_duplicate_tab(self) -> QWidget:
        widget = QWidget()
        scroll = QScrollArea(widget)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        self._dup_container = QWidget()
        self._dup_layout = QVBoxLayout(self._dup_container)
        self._dup_layout.setSpacing(12)
        self._dup_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        scroll.setWidget(self._dup_container)

        outer = QVBoxLayout(widget)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)
        return widget

    def _create_old_tab(self) -> QWidget:
        widget = QWidget()
        scroll = QScrollArea(widget)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        self._old_container = QWidget()
        self._old_layout = QVBoxLayout(self._old_container)
        self._old_layout.setSpacing(6)
        self._old_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        scroll.setWidget(self._old_container)

        outer = QVBoxLayout(widget)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)
        return widget

    def _load_data(self) -> None:
        """在后台线程加载安全分析数据，避免冻结 UI。"""
        days = self._config.get(CFG_OLD_PASSWORD_WARNING_DAYS)

        self._health_widget.set_score(0)
        self._status_hint = QLabel("正在分析安全数据...")
        self._status_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status_hint.setObjectName("secStatusHint")
        self._weak_layout.addWidget(self._status_hint)

        worker = BackgroundWorker(
            lambda: self._security.get_or_compute_report(days, cancel_check=worker.cancel_check),
            parent=self,
        )
        self._worker = worker
        self._worker.finished.connect(self._on_data_loaded)
        self._worker.error.connect(self._on_data_error)
        self._worker.start()

    def _on_data_loaded(self, analysis: dict[str, Any]) -> None:
        """后台分析完成，更新 UI。"""
        # 校验回调来源仍是当前 worker，防止 reject 后旧 worker 回调访问已销毁控件
        if self.sender() is not self._worker:
            return
        # `_status_hint` 位于 `_weak_layout` 中，由后续 `_populate_weak_tab` 的 `_clear_layout`
        # 统一回收，此处仅清属性引用，避免 `deleteLater` 造成双重回收。
        self._status_hint = None

        import dataclasses

        def _project(e: Entry) -> Entry:
            # 清空敏感字段，仅保留展示所需，避免驻留完整明文 `Entry`
            return dataclasses.replace(
                e, password="", totp_secret="", notes="", url="", custom_fields=[]
            )

        try:
            self._weak_entries = [_project(e) for e in analysis["weak_entries"]]
            self._duplicate_groups = [
                [_project(e) for e in g] for g in analysis["duplicate_groups"]
            ]
            self._old_entries = [_project(e) for e in analysis["old_entries"]]
        except Exception as exc:
            logger.error("加载安全报告失败: %s", type(exc).__name__, exc_info=True)
            # 异常出口同样回收 `_status_hint`，避免提示残留
            self._clear_layout(self._weak_layout)
            self._status_hint = None
            QMessageBox.critical(self, DLG_TITLE_ERROR, "加载安全数据失败，请重试")
            return
        finally:
            # 成功与异常出口合并到 finally，避免漏调 `release_worker` 造成引用泄漏；
            # `_on_data_error`（`worker.error` 信号）是另一独立路径，自行 `release_worker`
            release_worker(self)

        weak_count = len(self._weak_entries)
        dup_count = len(self._duplicate_groups)
        old_count = len(self._old_entries)
        total = analysis.get("total", 0)

        score = SecurityAnalyzer.compute_health_score(weak_count, dup_count, old_count, total)

        self._health_widget.set_score(score)

        self._weak_card.update_count(weak_count)
        self._dup_card.update_count(dup_count)
        self._old_card.update_count(old_count)

        self._populate_weak_tab()
        self._populate_duplicate_tab()
        self._populate_old_tab()

    def _on_data_error(self, error_msg: str) -> None:
        """worker.error 信号路径，独立于 _on_data_loaded 的成功/异常出口。"""
        # 与 `_on_data_loaded` 对称，防止 reject 后旧 worker 回调访问已销毁控件
        if not finalize_worker_if_current(self):
            return
        self._clear_layout(self._weak_layout)
        self._status_hint = None
        logger.error("加载安全数据失败: %s", error_msg)
        QMessageBox.critical(self, DLG_TITLE_ERROR, "加载安全数据失败，请重试")

    def _populate_weak_tab(self) -> None:
        self._clear_layout(self._weak_layout)

        if not self._weak_entries:
            self._weak_layout.addWidget(self._create_empty_hint("没有发现弱密码，做得好！"))
            return

        for entry in self._weak_entries:
            if entry.id is None:
                continue
            row = self._create_entry_row(
                title=entry.title or "未命名",
                subtitle=f"用户名: {entry.username}" if entry.username else "",
                badge_text=f"强度 {entry.password_strength}",
                badge_color=get_strength_color(entry.password_strength),
                entry_id=entry.id,
            )
            self._weak_layout.addWidget(row)

    def _populate_duplicate_tab(self) -> None:
        self._clear_layout(self._dup_layout)

        if not self._duplicate_groups:
            self._dup_layout.addWidget(self._create_empty_hint("没有发现重复密码。"))
            return

        for group in self._duplicate_groups:
            group_widget = QFrame()
            group_widget.setObjectName("dupGroup")
            group_layout = QVBoxLayout(group_widget)
            group_layout.setSpacing(4)

            group_label = QLabel(f"同一密码被 {len(group)} 个条目使用")
            group_label.setObjectName("dupGroupLabel")
            group_layout.addWidget(group_label)

            for entry in group:
                if entry.id is None:
                    continue
                entry_row = self._create_entry_row(
                    title=entry.title or "未命名",
                    subtitle=f"用户名: {entry.username}" if entry.username else "",
                    badge_text="重复使用",
                    badge_color=c("warning_orange"),
                    entry_id=entry.id,
                )
                group_layout.addWidget(entry_row)

            self._dup_layout.addWidget(group_widget)

    def _populate_old_tab(self) -> None:
        self._clear_layout(self._old_layout)

        if not self._old_entries:
            self._old_layout.addWidget(self._create_empty_hint("没有过期密码。"))
            return

        days = self._config.get(CFG_OLD_PASSWORD_WARNING_DAYS)
        for entry in self._old_entries:
            if entry.id is None:
                continue
            updated = entry.password_changed_at or entry.updated_at or entry.created_at or "未知"
            # `format_datetime` 输出 ISO 8601（YYYY-MM-DD HH:MM:SS），前 10 字符恒为日期
            # 部分；若 `format_datetime` 改为非 ISO 格式须同步调整此切片。
            formatted = format_datetime(updated)[:10]
            row = self._create_entry_row(
                title=entry.title or "未命名",
                subtitle=f"上次更新: {formatted}",
                badge_text=f"> {days}天",
                badge_color=c("warning"),
                entry_id=entry.id,
            )
            self._old_layout.addWidget(row)

    def _create_entry_row(
        self,
        title: str,
        subtitle: str,
        badge_text: str,
        badge_color: str,
        entry_id: int,
    ) -> QWidget:
        """创建一条包含标题、副标题、徽章与修复按钮的条目行。"""
        row_widget = QWidget()
        row_widget.setObjectName("secEntryRow")
        # 启用 hover 属性，使 QSS 的 `QWidget#secEntryRow:hover` 生效
        row_widget.setAttribute(Qt.WidgetAttribute.WA_Hover)
        row_layout = QHBoxLayout(row_widget)
        row_layout.setContentsMargins(12, 8, 12, 8)

        info_layout = QVBoxLayout()
        info_layout.setSpacing(2)

        title_label = QLabel(title)
        title_label.setObjectName("secRowTitle")
        info_layout.addWidget(title_label)

        if subtitle:
            sub_label = QLabel(subtitle)
            sub_label.setObjectName("secRowSub")
            info_layout.addWidget(sub_label)

        row_layout.addLayout(info_layout, stretch=1)

        badge = QLabel(badge_text)
        bc = QColor(badge_color)
        bc.setAlpha(int(255 * _BADGE_BG_ALPHA))
        badge.setStyleSheet(
            f"background-color: rgba({bc.red()},{bc.green()},{bc.blue()},{bc.alpha()});"
            f"color: {badge_color};"
            f"border-radius: {RADIUS_TAG}px;"
            f"padding: 3px 10px;"
            f"font-size: 11px;"
            f"font-weight: 600;"
        )
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        row_layout.addWidget(badge)

        fix_btn = QPushButton("修复")
        fix_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        fix_btn.setFixedSize(*BTN_FIX)
        fix_btn.setObjectName("secFixBtn")
        fix_btn.clicked.connect(lambda checked, eid=entry_id: self._request_fix(eid))
        row_layout.addWidget(fix_btn)

        return row_widget

    def _create_empty_hint(self, text: str) -> QLabel:
        label = QLabel(text)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setObjectName("secEmptyHint")
        return label

    @staticmethod
    def _clear_layout(layout: QLayout) -> None:
        clear_layout(layout)

    def _on_fix_weak(self) -> None:
        self._tabs.setCurrentIndex(0)

    @property
    def pending_fix_id(self) -> int | None:
        """:meth:`_request_fix` 记录的待修复条目 id，供调用方 ``exec`` 返回后读取（M14）。"""
        return self._pending_fix_id

    def _request_fix(self, entry_id: int) -> None:
        # 记录待修复条目并 `accept` 退出仪表盘模态循环；`edit_entry` 由 `menu_controller`
        # 在 `exec()` 返回后同步调用（单层模态，无嵌套）。原实现经 `singleShot`(0) 延迟
        # emit `fix_requested`，但 dialog 随即 `deleteLater`，`singleShot` 触发时 dialog 可能
        # 已销毁致访问 `self.fix_requested` 崩溃（M14）；`pending_fix_id` 在 `exec` 返回后、
        # `deleteLater` 前由调用方读取，避免竞态。
        self._pending_fix_id = entry_id
        self.accept()
