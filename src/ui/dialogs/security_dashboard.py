"""安全仪表盘，可视化展示保险库的安全概况。

通过后台线程运行安全分析，汇总弱密码、重复密码与过期密码三类风险，
并以健康评分圆环、统计卡片与详细列表呈现。用户可针对具体条目请求
修复，由对话框发出携带 entry_id 的信号交由主窗口处理。
"""

import logging

from PyQt6.QtCore import QRectF, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QPainter, QPen
from PyQt6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ...utils.format import format_datetime
from ..components.widgets import clear_layout, release_worker, setup_dialog_flags
from ..components.workers import BackgroundWorker, wait_worker_shutdown
from ...business.services.security_analyzer import SecurityAnalyzer
from ..resources.constants import (
    BTN_DIALOG,
    BTN_FIX,
    DIALOG_SECURITY_DASHBOARD_MIN_SIZE,
    FONT_FAMILY_DISPLAY,
)
from ..resources.theme_colors import c, get_strength_color

logger = logging.getLogger(__name__)


class _HealthScoreWidget(QWidget):
    """以圆环进度形式绘制安全健康评分的自定义组件。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._score = 100
        self.setFixedSize(160, 160)
        # 预创建字体，避免 paintEvent 每帧重复构造 QFont
        self._score_font = QFont(FONT_FAMILY_DISPLAY, 28, QFont.Weight.Bold)
        self._label_font = QFont(FONT_FAMILY_DISPLAY, 9)

    def set_score(self, score: int):
        self._score = max(0, min(100, score))
        self.update()

    def paintEvent(self, a0):
        painter = QPainter(self)
        try:
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            painter.save()

            side = min(self.width(), self.height())
            center_x = self.width() / 2
            center_y = self.height() / 2
            radius = side / 2 - 12  # 12px 内边距，圆环与控件边缘的间距
            pen_width = 10  # 圆环线条粗细，单位为像素

            # 背景圆环
            bg_pen = QPen(QColor(c('progress_bg')), pen_width, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
            painter.setPen(bg_pen)
            draw_rect = QRectF(
                center_x - radius, center_y - radius,
                radius * 2, radius * 2,
            )
            painter.drawArc(draw_rect, 0, 360 * 16)

            # 进度圆环
            score_color = self._score_color(self._score)
            fg_pen = QPen(QColor(score_color), pen_width, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
            painter.setPen(fg_pen)
            span_angle = int(self._score / 100 * 360 * 16)
            start_angle = 90 * 16  # 起始角位于顶部，正值顺时针为 Qt 约定
            painter.drawArc(draw_rect, start_angle, -span_angle)

            # 中心文字 — 分数
            painter.setPen(QColor(c('text_primary')))
            painter.setFont(self._score_font)
            painter.drawText(draw_rect, Qt.AlignmentFlag.AlignCenter, str(self._score))

            # 底部小标签
            painter.setFont(self._label_font)
            painter.setPen(QColor(c('text_secondary')))
            label_rect = QRectF(
                center_x - radius, center_y + 8,
                radius * 2, 20,
            )
            painter.drawText(label_rect, Qt.AlignmentFlag.AlignCenter, '安全评分')

            painter.restore()
        finally:
            painter.end()

    @staticmethod
    def _score_color(score: int) -> str:
        if score >= 80:
            return c('success')
        elif score >= 60:
            return c('warning')
        elif score >= 40:
            return c('warning_orange')
        else:
            return c('danger')


class _StatCard(QFrame):
    """统计卡片。"""

    def __init__(self, title: str, count: int, color: str, button_text: str, parent=None):
        super().__init__(parent)
        self._setup_ui(title, count, color, button_text)

    def update_count(self, count: int):
        """更新卡片显示的数字。"""
        self._count_label.setText(str(count))

    def _setup_ui(self, title: str, count: int, color: str, button_text: str):
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setObjectName('statCard')

        layout = QVBoxLayout(self)
        layout.setSpacing(6)

        # 标题
        title_label = QLabel(title)
        title_label.setObjectName('statCardTitle')
        layout.addWidget(title_label)

        # 数字
        count_label = QLabel(str(count))
        count_label.setStyleSheet(
            f"font-size: 32px; font-weight: bold; color: {color};"
        )
        self._count_label = count_label  # 保存引用以便后续刷新数字
        layout.addWidget(count_label)

        # 操作按钮
        action_btn = QPushButton(button_text)
        action_btn.setObjectName('statActionBtn')
        action_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.action_button = action_btn
        layout.addWidget(action_btn)

        layout.addStretch()


class SecurityDashboard(QDialog):
    """安全仪表盘主对话框，展示风险概况并提供修复入口。

    后台线程加载安全报告，避免主线程长时间阻塞。关闭对话框前会等待
    分析 worker 结束，防止对已销毁部件发出信号。
    """

    fix_requested = pyqtSignal(int)  # 请求修复条目，参数为对应 entry_id

    def __init__(self, security_analyzer, entry_manager, config, parent=None):
        super().__init__(parent)
        self._analyzer = security_analyzer
        self._entry_manager = entry_manager
        self._config = config
        self._weak_entries = []
        self._duplicate_groups = []
        self._old_entries = []
        self._worker = None  # 预先声明，确保 reject 时可安全判空
        self._status_hint: QLabel | None = None
        self._setup_ui()
        self._load_data()

    def reject(self):
        """关闭前等待后台 worker 完成，并清空已解密的明文条目引用。"""
        wait_worker_shutdown(self._worker)
        release_worker(self)
        # 清空含明文密码的条目列表，与 DetailPanel/EntryDialog 主动清理策略一致，
        # 缩短敏感数据在对话框关闭后的驻留时间
        self._weak_entries = []
        self._duplicate_groups = []
        self._old_entries = []
        super().reject()

    def _setup_ui(self):
        self.setWindowTitle('安全仪表盘')
        self.setMinimumSize(*DIALOG_SECURITY_DASHBOARD_MIN_SIZE)
        setup_dialog_flags(self)

        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(16)

        # ===== 顶部区域：健康评分 + 统计卡片 =====
        top_layout = QHBoxLayout()
        top_layout.setSpacing(20)

        # 健康评分
        score_container = QVBoxLayout()
        score_container.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._health_widget = _HealthScoreWidget()
        score_container.addWidget(self._health_widget, alignment=Qt.AlignmentFlag.AlignCenter)
        top_layout.addLayout(score_container)

        # 三个统计卡片
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(12)

        self._weak_card = _StatCard('弱密码', 0, c('danger'), '立即修复', self)
        self._weak_card.action_button.clicked.connect(self._on_fix_weak)
        cards_layout.addWidget(self._weak_card)

        self._dup_card = _StatCard('重复密码组', 0, c('warning_orange'), '查看详情', self)
        self._dup_card.action_button.clicked.connect(lambda: self._tabs.setCurrentIndex(1))
        cards_layout.addWidget(self._dup_card)

        self._old_card = _StatCard('过期密码', 0, c('warning'), '查看详情', self)
        self._old_card.action_button.clicked.connect(lambda: self._tabs.setCurrentIndex(2))
        cards_layout.addWidget(self._old_card)

        top_layout.addLayout(cards_layout, stretch=1)
        main_layout.addLayout(top_layout)

        # 分隔线
        separator = QFrame()
        separator.setFixedHeight(1)
        separator.setObjectName('detailDivider')
        main_layout.addWidget(separator)

        # ===== 详细列表区域 =====
        self._tabs = QTabWidget()
        self._tabs.addTab(self._create_weak_tab(), '弱密码')
        self._tabs.addTab(self._create_duplicate_tab(), '重复密码')
        self._tabs.addTab(self._create_old_tab(), '过期密码')
        main_layout.addWidget(self._tabs, stretch=1)

        # 底部关闭按钮
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        close_btn = QPushButton('关闭')
        close_btn.setFixedSize(*BTN_DIALOG)
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)
        main_layout.addLayout(btn_layout)

    def _create_weak_tab(self) -> QWidget:
        """创建弱密码标签页容器。"""
        widget = QWidget()
        self._weak_layout = QVBoxLayout(widget)
        self._weak_layout.setSpacing(6)
        self._weak_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        return widget

    def _create_duplicate_tab(self) -> QWidget:
        """创建重复密码标签页容器，内含滚动区域。"""
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
        """创建过期密码标签页容器。"""
        widget = QWidget()
        self._old_layout = QVBoxLayout(widget)
        self._old_layout.setSpacing(6)
        self._old_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        return widget

    def _load_data(self):
        """在后台线程加载安全分析数据，避免冻结 UI。"""
        days = self._config.get('old_password_warning_days', 90)

        # 显示加载状态
        self._health_widget.set_score(0)
        self._status_hint = QLabel('正在分析安全数据...')
        self._status_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status_hint.setObjectName('secStatusHint')
        self._weak_layout.addWidget(self._status_hint)

        self._worker = BackgroundWorker(
            lambda: self._analyzer.get_or_compute_report(days),
            parent=self,
        )
        self._worker.finished.connect(self._on_data_loaded)
        self._worker.error.connect(self._on_data_error)
        self._worker.start()

    def _on_data_loaded(self, analysis):
        """后台分析完成，更新 UI。"""
        # 校验回调来源仍是当前 worker，防止 reject 后旧 worker 回调访问已销毁控件
        if self.sender() is not self._worker:
            return
        # 加载提示 _status_hint 位于 _weak_layout 中，由随后 _populate_weak_tab 的
        # _clear_layout 统一回收，此处仅清除属性引用，避免手动 deleteLater 造成双重回收。
        self._status_hint = None

        import dataclasses

        def _project(e):
            # 清空敏感字段，仅保留展示所需（title/username/strength/时间戳/id），
            # 避免仪表盘打开期间不必要地驻留完整明文 Entry。
            return dataclasses.replace(
                e, password='', totp_secret='', notes='', url='', custom_fields=[]
            )

        try:
            self._weak_entries = [_project(e) for e in analysis['weak_entries']]
            self._duplicate_groups = [
                [_project(e) for e in g] for g in analysis['duplicate_groups']
            ]
            self._old_entries = [_project(e) for e in analysis['old_entries']]
        except Exception as exc:
            logger.error("加载安全报告失败: %s", type(exc).__name__, exc_info=True)
            # 异常出口也用 _clear_layout 回收 _status_hint，与成功路径一致，
            # 避免"正在分析..."提示残留
            self._clear_layout(self._weak_layout)
            self._status_hint = None
            QMessageBox.critical(self, '错误', '加载安全数据失败，请重试')
            return
        finally:
            # 统一释放当前 worker：成功与异常两个出口合并到 finally，
            # 避免未来新增分支时漏调 release_worker 造成 worker 引用泄漏。
            # _on_data_error（worker.error 信号）是另一独立路径，自行 release。
            release_worker(self)

        weak_count = len(self._weak_entries)
        dup_count = len(self._duplicate_groups)
        old_count = len(self._old_entries)
        total = analysis.get('total', 0)

        score = SecurityAnalyzer.compute_health_score(weak_count, dup_count, old_count, total)

        # 更新评分圆环
        self._health_widget.set_score(score)

        # 更新统计卡片
        self._update_stat_card(self._weak_card, weak_count)
        self._update_stat_card(self._dup_card, dup_count)
        self._update_stat_card(self._old_card, old_count)

        # 填充详细列表
        self._populate_weak_tab()
        self._populate_duplicate_tab()
        self._populate_old_tab()

    def _on_data_error(self, error_msg: str):
        """后台分析失败（worker.error 信号路径，独立于 _on_data_loaded 的成功/异常出口）。"""
        release_worker(self)
        # 统一用 _clear_layout 回收 _status_hint，与 _on_data_loaded 出口一致
        self._clear_layout(self._weak_layout)
        self._status_hint = None
        logger.error("加载安全数据失败: %s", error_msg)
        QMessageBox.critical(self, '错误', '加载安全数据失败，请重试')

    def _update_stat_card(self, card: _StatCard, count: int):
        """更新统计卡片显示的数字。"""
        card.update_count(count)

    def _populate_weak_tab(self):
        """填充弱密码列表。"""
        self._clear_layout(self._weak_layout)

        if not self._weak_entries:
            self._weak_layout.addWidget(self._create_empty_hint('没有发现弱密码，做得好！'))
            return

        for entry in self._weak_entries:
            row = self._create_entry_row(
                title=entry.title or '未命名',
                subtitle=f'用户名: {entry.username}' if entry.username else '',
                badge_text=f'强度 {entry.password_strength}',
                badge_color=get_strength_color(entry.password_strength),
                entry_id=entry.id,
            )
            self._weak_layout.addWidget(row)

    def _populate_duplicate_tab(self):
        """填充重复密码分组列表。"""
        self._clear_layout(self._dup_layout)

        if not self._duplicate_groups:
            self._dup_layout.addWidget(self._create_empty_hint('没有发现重复密码。'))
            return

        for group in self._duplicate_groups:
            group_widget = QFrame()
            group_widget.setObjectName('dupGroup')
            group_layout = QVBoxLayout(group_widget)
            group_layout.setSpacing(4)

            # 组标题
            group_label = QLabel(f'同一密码被 {len(group)} 个条目使用')
            group_label.setObjectName('dupGroupLabel')
            group_layout.addWidget(group_label)

            # 组内条目
            for entry in group:
                entry_row = self._create_entry_row(
                    title=entry.title or '未命名',
                    subtitle=f'用户名: {entry.username}' if entry.username else '',
                    badge_text='重复使用',
                    badge_color=c('warning_orange'),
                    entry_id=entry.id,
                )
                group_layout.addWidget(entry_row)

            self._dup_layout.addWidget(group_widget)

    def _populate_old_tab(self):
        """填充过期密码列表。"""
        self._clear_layout(self._old_layout)

        if not self._old_entries:
            self._old_layout.addWidget(self._create_empty_hint('没有过期密码。'))
            return

        days = self._config.get('old_password_warning_days', 90)
        for entry in self._old_entries:
            updated = entry.password_changed_at or entry.updated_at or entry.created_at or '未知'
            # format_datetime 统一处理 naive/aware 时间戳，[:10] 取日期部分
            formatted = format_datetime(updated)[:10]
            row = self._create_entry_row(
                title=entry.title or '未命名',
                subtitle=f'上次更新: {formatted}',
                badge_text=f'> {days}天',
                badge_color=c('warning'),
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
        row_widget.setObjectName('secEntryRow')
        # 启用 hover 属性，使 QSS 的 QWidget#secEntryRow:hover 生效
        row_widget.setAttribute(Qt.WidgetAttribute.WA_Hover)
        row_layout = QHBoxLayout(row_widget)
        row_layout.setContentsMargins(12, 8, 12, 8)

        # 左侧：标题与副标题
        info_layout = QVBoxLayout()
        info_layout.setSpacing(2)

        title_label = QLabel(title)
        title_label.setObjectName('secRowTitle')
        info_layout.addWidget(title_label)

        if subtitle:
            sub_label = QLabel(subtitle)
            sub_label.setObjectName('secRowSub')
            info_layout.addWidget(sub_label)

        row_layout.addLayout(info_layout, stretch=1)

        # 徽章
        badge = QLabel(badge_text)
        bc = QColor(badge_color)
        bc.setAlpha(int(255 * 0.13))
        badge.setStyleSheet(
            f"background-color: rgba({bc.red()},{bc.green()},{bc.blue()},{bc.alpha()});"
            f"color: {badge_color};"
            f"border-radius: 10px;"
            f"padding: 3px 10px;"
            f"font-size: 11px;"
            f"font-weight: bold;"
        )
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        row_layout.addWidget(badge)

        # 操作按钮
        fix_btn = QPushButton('修复')
        fix_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        fix_btn.setFixedSize(*BTN_FIX)
        fix_btn.setObjectName('secFixBtn')
        fix_btn.clicked.connect(lambda checked, eid=entry_id: self._request_fix(eid))
        row_layout.addWidget(fix_btn)

        return row_widget

    def _create_empty_hint(self, text: str) -> QLabel:
        """创建居中显示的空状态提示标签。"""
        label = QLabel(text)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setObjectName('secEmptyHint')
        return label

    @staticmethod
    def _clear_layout(layout):
        clear_layout(layout)

    def _on_fix_weak(self):
        """点击弱密码卡片的立即修复按钮，切换到弱密码标签页。"""
        self._tabs.setCurrentIndex(0)

    def _request_fix(self, entry_id: int):
        # 先 accept 关闭仪表盘，再延迟到下一个事件循环 emit，确保仪表盘
        # 模态事件循环已退出，避免在其内嵌套打开编辑对话框形成双层模态。
        # emit 由 _show_security_dashboard 连接到 _edit_entry，在仪表盘关闭后打开。
        self.accept()
        QTimer.singleShot(0, lambda: self.fix_requested.emit(entry_id))
