"""安全仪表盘 - 可视化展示安全概况"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QWidget, QTabWidget, QScrollArea, QFrame,
    QMessageBox,
)
from PyQt6.QtCore import Qt, pyqtSignal, QRectF
from PyQt6.QtGui import QPainter, QColor, QPen, QFont

from ..ui.resources.theme_colors import c, get_strength_color


class _HealthScoreWidget(QWidget):
    """圆形健康评分绘制组件"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._score = 100
        self.setFixedSize(160, 160)

    def set_score(self, score: int):
        self._score = max(0, min(100, score))
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        side = min(self.width(), self.height())
        center_x = self.width() / 2
        center_y = self.height() / 2
        radius = side / 2 - 12
        pen_width = 10

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
        start_angle = 90 * 16  # 从顶部开始
        painter.drawArc(draw_rect, start_angle, -span_angle)

        # 中心文字 - 分数
        painter.setPen(QColor(c('text_primary')))
        font = QFont('Microsoft YaHei', 28, QFont.Weight.Bold)
        painter.setFont(font)
        painter.drawText(draw_rect, Qt.AlignmentFlag.AlignCenter, str(self._score))

        # 底部小标签
        font_small = QFont('Microsoft YaHei', 9)
        painter.setFont(font_small)
        painter.setPen(QColor(c('text_secondary')))
        label_rect = QRectF(
            center_x - radius, center_y + 8,
            radius * 2, 20,
        )
        painter.drawText(label_rect, Qt.AlignmentFlag.AlignCenter, '安全评分')

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
    """统计卡片"""

    def __init__(self, title: str, count: int, color: str, button_text: str, parent=None):
        super().__init__(parent)
        self._color = color
        self._count = count
        self._button_text = button_text
        self._setup_ui(title, count, color, button_text)

    def _setup_ui(self, title: str, count: int, color: str, button_text: str):
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setStyleSheet(
            f"QFrame {{"
            f"  background-color: {c('bg_card')};"
            f"  border: 1px solid {c('border_light')};"
            f"  border-radius: 8px;"
            f"  padding: 12px;"
            f"}}"
        )

        layout = QVBoxLayout(self)
        layout.setSpacing(6)

        # 标题
        title_label = QLabel(title)
        title_label.setStyleSheet(
            f"font-size: 12px; color: {c('text_secondary')};"
        )
        layout.addWidget(title_label)

        # 数字
        count_label = QLabel(str(count))
        count_label.setStyleSheet(
            f"font-size: 32px; font-weight: bold; color: {color};"
        )
        layout.addWidget(count_label)

        # 操作按钮
        action_btn = QPushButton(button_text)
        action_btn.setObjectName('statActionBtn')
        action_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        action_btn.setStyleSheet(
            f"QPushButton {{"
            f"  border: none;"
            f"  background: transparent;"
            f"  color: {c('accent_text')};"
            f"  font-size: 12px;"
            f"  padding: 2px 0;"
            f"  text-align: left;"
            f"}}"
            f"QPushButton:hover {{"
            f"  color: {c('accent_hover')};"
            f"}}"
        )
        self.action_button = action_btn
        layout.addWidget(action_btn)

        layout.addStretch()


class SecurityDashboard(QDialog):
    """安全仪表盘"""

    fix_requested = pyqtSignal(int)  # 请求编辑条目，参数为 entry_id

    def __init__(self, security_analyzer, entry_manager, config, parent=None):
        super().__init__(parent)
        self._analyzer = security_analyzer
        self._entry_manager = entry_manager
        self._config = config
        self._weak_entries = []
        self._duplicate_groups = []
        self._old_entries = []
        self._setup_ui()
        self._load_data()

    def _setup_ui(self):
        self.setWindowTitle('安全仪表盘')
        self.setMinimumSize(680, 580)
        self.setWindowFlags(
            self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint
        )

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
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setStyleSheet(f"color: {c('divider')};")
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
        close_btn.setFixedSize(90, 34)
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)
        main_layout.addLayout(btn_layout)

    def _create_weak_tab(self) -> QWidget:
        """弱密码标签页"""
        widget = QWidget()
        self._weak_layout = QVBoxLayout(widget)
        self._weak_layout.setSpacing(6)
        self._weak_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        return widget

    def _create_duplicate_tab(self) -> QWidget:
        """重复密码标签页"""
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
        """过期密码标签页"""
        widget = QWidget()
        self._old_layout = QVBoxLayout(widget)
        self._old_layout.setSpacing(6)
        self._old_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        return widget

    def _load_data(self):
        """加载安全分析数据"""
        try:
            days = self._config.get('old_password_warning_days', 90)
            analysis = self._analyzer.full_analysis(days)
            self._weak_entries = analysis['weak_entries']
            self._duplicate_groups = analysis['duplicate_groups']
            self._old_entries = analysis['old_entries']
        except Exception as e:
            QMessageBox.critical(self, '错误', f'加载安全数据失败：{e}')
            return

        weak_count = len(self._weak_entries)
        dup_count = len(self._duplicate_groups)
        old_count = len(self._old_entries)

        # 计算健康评分
        score = max(0, 100 - (weak_count * 15 + dup_count * 10 + old_count * 5))

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

    def _update_stat_card(self, card: _StatCard, count: int):
        """更新统计卡片的数字"""
        # 更新卡片内的 count QLabel（索引 1）
        layout = card.layout()
        if layout and layout.count() > 1:
            count_widget = layout.itemAt(1).widget()
            if isinstance(count_widget, QLabel):
                count_widget.setText(str(count))

    def _populate_weak_tab(self):
        """填充弱密码列表"""
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
        """填充重复密码分组列表"""
        self._clear_layout(self._dup_layout)

        if not self._duplicate_groups:
            self._dup_layout.addWidget(self._create_empty_hint('没有发现重复密码。'))
            return

        for group in self._duplicate_groups:
            group_widget = QFrame()
            group_widget.setStyleSheet(
                f"QFrame {{"
                f"  background-color: {c('bg_card')};"
                f"  border: 1px solid {c('border_light')};"
                f"  border-radius: 6px;"
                f"  padding: 8px;"
                f"}}"
            )
            group_layout = QVBoxLayout(group_widget)
            group_layout.setSpacing(4)

            # 组标题
            group_label = QLabel(f'同一密码被 {len(group)} 个条目使用')
            group_label.setStyleSheet(
                f"font-weight: bold; font-size: 13px; color: {c('warning_orange')};"
            )
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
        """填充过期密码列表"""
        self._clear_layout(self._old_layout)

        if not self._old_entries:
            self._old_layout.addWidget(self._create_empty_hint('没有过期密码。'))
            return

        days = self._config.get('old_password_warning_days', 90)
        for entry in self._old_entries:
            updated = entry.password_changed_at or entry.updated_at or entry.created_at or '未知'
            row = self._create_entry_row(
                title=entry.title or '未命名',
                subtitle=f'上次更新: {updated[:10]}',
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
        """创建条目行组件"""
        row_widget = QWidget()
        row_widget.setStyleSheet(
            f"QWidget {{"
            f"  background-color: {c('bg_card')};"
            f"  border: 1px solid {c('border_light')};"
            f"  border-radius: 6px;"
            f"}}"
            f"QWidget:hover {{"
            f"  background-color: {c('bg_card_hover')};"
            f"}}"
        )
        row_layout = QHBoxLayout(row_widget)
        row_layout.setContentsMargins(12, 8, 12, 8)

        # 左侧：标题与副标题
        info_layout = QVBoxLayout()
        info_layout.setSpacing(2)

        title_label = QLabel(title)
        title_label.setStyleSheet(
            f"font-size: 13px; font-weight: bold; color: {c('text_primary')};"
        )
        info_layout.addWidget(title_label)

        if subtitle:
            sub_label = QLabel(subtitle)
            sub_label.setStyleSheet(
                f"font-size: 11px; color: {c('text_secondary')};"
            )
            info_layout.addWidget(sub_label)

        row_layout.addLayout(info_layout, stretch=1)

        # 徽章
        badge = QLabel(badge_text)
        badge.setStyleSheet(
            f"background-color: {badge_color}22;"
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
        fix_btn.setFixedSize(56, 28)
        fix_btn.setStyleSheet(
            f"QPushButton {{"
            f"  background-color: {c('accent')};"
            f"  color: {c('text_on_accent')};"
            f"  border: none;"
            f"  border-radius: 4px;"
            f"  font-size: 12px;"
            f"}}"
            f"QPushButton:hover {{"
            f"  background-color: {c('accent_hover')};"
            f"}}"
        )
        fix_btn.clicked.connect(lambda checked, eid=entry_id: self._request_fix(eid))
        row_layout.addWidget(fix_btn)

        return row_widget

    def _create_empty_hint(self, text: str) -> QLabel:
        """创建空状态提示"""
        label = QLabel(text)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setStyleSheet(
            f"color: {c('text_muted')};"
            f"font-size: 14px;"
            f"padding: 32px;"
        )
        return label

    def _clear_layout(self, layout: QVBoxLayout):
        """清空布局中的所有子组件"""
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()
            child_layout = item.layout()
            if child_layout:
                self._clear_layout(child_layout)

    def _on_fix_weak(self):
        """点击弱密码的立即修复按钮，跳转到弱密码标签页"""
        self._tabs.setCurrentIndex(0)

    def _request_fix(self, entry_id: int):
        self.fix_requested.emit(entry_id)
        self.accept()
