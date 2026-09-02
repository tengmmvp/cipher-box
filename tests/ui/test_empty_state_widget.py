"""EmptyStateWidget 空状态提示组件测试（零覆盖补齐，浅冒烟 + 行为）。"""

from PyQt6.QtWidgets import QLabel, QPushButton

from src.ui.components.empty_state_widget import EmptyStateWidget
from src.ui.resources.constants import BTN_ACTION
from src.ui.resources.icons import EMPTY_GENERIC, SIZE_EMPTY


class TestEmptyStateWidget:
    """构造布局与操作按钮信号。"""

    def test_full_construction_layout(self, qapp):
        """全参构造：图标/标题/副标题/操作按钮齐备，按钮固定尺寸。"""
        widget = EmptyStateWidget(
            icon_name=EMPTY_GENERIC,
            title="还没有密码条目",
            subtitle="点击工具栏「新增」按钮开始添加",
            action_text="新增条目",
        )
        labels = widget.findChildren(QLabel)
        texts = [l.text() for l in labels]
        assert "还没有密码条目" in texts
        assert "点击工具栏「新增」按钮开始添加" in texts
        buttons = widget.findChildren(QPushButton)
        assert len(buttons) == 1
        assert buttons[0].text() == "新增条目"
        assert (buttons[0].width(), buttons[0].height()) == BTN_ACTION

    def test_minimal_construction_without_action(self, qapp):
        """无副标题/无操作按钮的最小构造不产生按钮与副标题。"""
        widget = EmptyStateWidget(title="暂无数据")
        assert widget.findChildren(QPushButton) == []
        # 图标 QLabel 的 text 为空串，文本标签仅有标题（无副标题/无按钮）
        texts = [l.text() for l in widget.findChildren(QLabel)]
        assert texts == ["", "暂无数据"]

    def test_action_button_emits_signal(self, qapp):
        """点击操作按钮发射 action_clicked 信号（空态操作的接线）。"""
        widget = EmptyStateWidget(title="t", action_text="新增条目")
        received: list[int] = []
        widget.action_clicked.connect(lambda: received.append(1))

        widget.findChildren(QPushButton)[0].click()

        assert received == [1]

    def test_icon_label_fixed_size(self, qapp):
        """图标标签固定 SIZE_EMPTY 见方（布局稳定性）。"""
        widget = EmptyStateWidget(title="t")
        icon_label = next(l for l in widget.findChildren(QLabel) if l.pixmap() is not None)
        assert icon_label.width() == SIZE_EMPTY
        assert icon_label.height() == SIZE_EMPTY
