"""分类管理对话框 - 新增/编辑分类"""

import logging

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QColorDialog,
    QComboBox,
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ..database.models import Category
from ..ui.resources.constants import BTN_DIALOG, DIALOG_CATEGORY_MIN_SIZE
from ..ui.resources.theme_colors import c
from ..ui.widgets import setup_dialog_flags

logger = logging.getLogger(__name__)


# 图标候选列表（单字符标识，用于分类视觉区分）
ICON_CANDIDATES = [
    '[CLIP]', '[DIR]', '[LIST]', '[ORG]', '[SOC]', '[CHAT]', '[MAIL]', '[WEB]',
    '[BANK]', '[COIN]', '[CART]', '[BAG]', '[WORK]', '[GOAL]', '[GAME]', '[DICE]',
    '[PC]', '[FILM]', '[BOOK]', '[MUSIC]', '[HOME]', '[FLY]', '[MED]', '[LOCK]',
    '[KEY]', '[IDEA]', '[GEAR]', '[BELL]', '[EDU]', '[LOVE]', '[STAR]', '[GYM]',
]

# 预设颜色（供 c() 包装使用）
PRESET_COLORS = [
    '#4CAF50', '#2196F3', '#F44336', '#FF9800',
    '#9C27B0', '#00BCD4', '#607D8B', '#E91E63',
]


class _ColorDotButton(QPushButton):
    """圆形颜色选择按钮"""

    def __init__(self, color: str, selected: bool = False, parent=None):
        super().__init__(parent)
        self._color = color
        self._selected = selected
        self.setFixedSize(32, 32)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip(color)
        self.clicked.connect(self._on_clicked)
        self._update_style()

    @property
    def color(self) -> str:
        return self._color

    @property
    def selected(self) -> bool:
        return self._selected

    @selected.setter
    def selected(self, value: bool):
        self._selected = value
        self._update_style()

    def _update_style(self):
        border_color = c('accent') if self._selected else 'transparent'
        border_width = 3 if self._selected else 0
        self.setStyleSheet(
            f"QPushButton {{"
            f"  background-color: {self._color};"
            f"  border: {border_width}px solid {border_color};"
            f"  border-radius: 14px;"
            f"  min-width: 28px; max-width: 28px;"
            f"  min-height: 28px; max-height: 28px;"
            f"}}"
            f"QPushButton:hover {{"
            f"  border: 2px solid {c('text_secondary')};"
            f"}}"
        )

    def _on_clicked(self):
        self.selected = True


class CategoryDialog(QDialog):
    """分类编辑对话框"""

    saved = pyqtSignal()

    def __init__(self, entry_manager, category=None, parent=None):
        super().__init__(parent)
        self._entry_mgr = entry_manager
        self._category = category  # None 表示新增，否则编辑
        self._selected_color = PRESET_COLORS[0]
        self._color_dots: list[_ColorDotButton] = []
        self._setup_ui()
        if category:
            self._load_category(category)

    def _setup_ui(self):
        is_edit = self._category is not None
        self.setWindowTitle('编辑分类' if is_edit else '新增分类')
        self.setMinimumSize(*DIALOG_CATEGORY_MIN_SIZE)
        setup_dialog_flags(self)

        layout = QVBoxLayout(self)
        layout.setSpacing(16)

        # 表单
        form = QFormLayout()
        form.setSpacing(12)

        # 名称
        self._name_edit = QLineEdit()
        self._name_edit.setPlaceholderText('请输入分类名称')
        form.addRow('名称 *：', self._name_edit)

        # 图标选择
        self._icon_combo = QComboBox()
        for icon in ICON_CANDIDATES:
            self._icon_combo.addItem(icon)
        self._icon_combo.setMaxVisibleItems(12)
        form.addRow('图标：', self._icon_combo)

        layout.addLayout(form)

        # 颜色选择区域
        color_label = QLabel('颜色：')
        color_label.setStyleSheet(f"font-weight: bold; color: {c('text_primary')};")
        layout.addWidget(color_label)

        color_row = QHBoxLayout()
        color_row.setSpacing(8)

        for i, color in enumerate(PRESET_COLORS):
            dot = _ColorDotButton(color, selected=(i == 0))
            dot.clicked.connect(lambda checked, idx=i: self._on_color_dot_clicked(idx))
            self._color_dots.append(dot)
            color_row.addWidget(dot)

        color_row.addStretch()

        # 自定义颜色按钮
        custom_color_btn = QPushButton('自定义…')
        custom_color_btn.setFixedHeight(32)
        custom_color_btn.setStyleSheet(
            f"QPushButton {{"
            f"  border: 1px dashed {c('border')};"
            f"  border-radius: 4px;"
            f"  padding: 4px 12px;"
            f"  color: {c('text_secondary')};"
            f"}}"
            f"QPushButton:hover {{"
            f"  border-color: {c('accent')};"
            f"  color: {c('accent_text')};"
            f"}}"
        )
        custom_color_btn.clicked.connect(self._on_custom_color)
        color_row.addWidget(custom_color_btn)

        layout.addLayout(color_row)

        # 颜色预览
        self._color_preview = QLabel()
        self._color_preview.setFixedHeight(4)
        self._color_preview.setStyleSheet(
            f"background-color: {self._selected_color}; border-radius: 2px;"
        )
        layout.addWidget(self._color_preview)

        # 分隔线
        separator = QLabel()
        separator.setFixedHeight(1)
        separator.setStyleSheet(f"background-color: {c('divider')};")
        layout.addWidget(separator)

        # 底部按钮
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        cancel_btn = QPushButton('取消')
        cancel_btn.setFixedSize(*BTN_DIALOG)
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)

        save_btn = QPushButton('保存')
        save_btn.setObjectName('primaryBtn')
        save_btn.setFixedSize(*BTN_DIALOG)
        save_btn.clicked.connect(self._on_save)
        btn_layout.addWidget(save_btn)

        layout.addLayout(btn_layout)

    def _load_category(self, category: Category):
        """加载分类数据"""
        self._name_edit.setText(category.name)

        # 设置图标
        idx = self._icon_combo.findText(category.icon_char)
        if idx >= 0:
            self._icon_combo.setCurrentIndex(idx)

        # 设置颜色
        if category.color:
            self._selected_color = category.color
            self._update_color_selection()
            self._color_preview.setStyleSheet(
                f"background-color: {self._selected_color}; border-radius: 2px;"
            )

    def _on_color_dot_clicked(self, index: int):
        """点击预设颜色圆点"""
        self._selected_color = PRESET_COLORS[index]
        self._update_color_selection()

    def _update_color_selection(self):
        """更新颜色圆点的选中状态"""
        for dot in self._color_dots:
            dot.selected = (dot.color == self._selected_color)
        self._color_preview.setStyleSheet(
            f"background-color: {self._selected_color}; border-radius: 2px;"
        )

    def _on_custom_color(self):
        """打开颜色选择器"""
        initial = QColor(self._selected_color)
        color = QColorDialog.getColor(initial, self, '选择自定义颜色')
        if color.isValid():
            self._selected_color = color.name()
            # 取消所有预设圆点的选中
            for dot in self._color_dots:
                dot.selected = False
            self._color_preview.setStyleSheet(
                f"background-color: {self._selected_color}; border-radius: 2px;"
            )

    def _on_save(self):
        """保存分类"""
        name = self._name_edit.text().strip()
        if not name:
            QMessageBox.warning(self, '提示', '请输入分类名称')
            return

        icon_char = self._icon_combo.currentText()

        try:
            if self._category:
                # 编辑模式
                self._category.name = name
                self._category.icon_char = icon_char
                self._category.color = self._selected_color
                self._entry_mgr.update_category(self._category)
            else:
                # 新增模式
                category = Category(
                    name=name,
                    icon_char=icon_char,
                    color=self._selected_color,
                )
                self._entry_mgr.add_category(category)

            self.saved.emit()
            self.accept()
        except Exception as exc:
            logger.error("保存分类失败: %s", type(exc).__name__, exc_info=True)
            QMessageBox.critical(self, '错误', '保存失败，请重试')
