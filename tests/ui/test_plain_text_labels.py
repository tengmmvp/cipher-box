"""承载用户/导入数据的 QLabel PlainText 渲染测试（SEC-030）。

QLabel 默认 AutoText，经 ``Qt::mightBeRichText`` 启发式可能走富文本引擎：条目
数据以 ``<`` 开头时被当作 markup 吞掉（显示≠复制），伪造标签可注入信任样式，
``<img src=...svg>`` 触达 Qt SVG 解析链。本文件守护统一的
``create_plain_text_label`` 工厂与各消费点（详情面板标题/备注/标签/字段值、
敏感字段揭示、密码历史、自定义字段、安全仪表盘行标签）的 PlainText 契约；
URL 标签的 RichText+转义白名单路径由 ``test_detail_panel`` 独立守护，不在本文件。
"""

from unittest.mock import MagicMock

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QLabel, QPushButton, QVBoxLayout, QWidget

from src.models import Entry
from src.ui.components.custom_fields_renderer import CustomFieldsRenderer
from src.ui.components.detail_panel import DetailPanel
from src.ui.components.secret_field import SecretFieldEnv, make_secret_field_row
from src.ui.components.widgets import create_plain_text_label


class TestCreatePlainTextLabel:
    """工厂本身的契约：PlainText 固定 + objectName/wordWrap 可选。"""

    def test_format_is_plain_text_and_text_literal(self, qapp):
        """工厂产出的 QLabel 为 PlainText，markup 字面保留。"""
        label = create_plain_text_label("<b>加粗</b>")
        assert label.textFormat() == Qt.TextFormat.PlainText
        assert label.text() == "<b>加粗</b>"

    def test_object_name_and_word_wrap_flags(self, qapp):
        """object_name / word_wrap 选项生效；object_name 空串时不设置。"""
        labeled = create_plain_text_label("x", "fieldValue", word_wrap=True)
        assert labeled.objectName() == "fieldValue"
        assert labeled.wordWrap() is True
        plain = create_plain_text_label("x")
        assert plain.objectName() == ""
        assert plain.wordWrap() is False

    def test_format_persists_across_set_text(self, qapp):
        """后续 setText 不改变渲染路径：揭示密码场景依赖此性质。"""
        label = create_plain_text_label("••••••••", "secretValue")
        label.setText("<script>alert(1)</script>abc")
        assert label.textFormat() == Qt.TextFormat.PlainText
        assert label.text() == "<script>alert(1)</script>abc"


def _bare_panel() -> DetailPanel:
    """构造跳过 __init__ 的 DetailPanel 裸实例（仅 _render_notes 需 _content_layout）。"""
    return DetailPanel.__new__(DetailPanel)


class TestDetailPanelPlainText:
    """详情面板各数据承载标签的 PlainText 契约。"""

    def test_notes_rendered_literally(self, qapp):
        """备注含 ``<b>加粗</b>`` 时按字面显示，不进富文本引擎。"""
        panel = _bare_panel()
        host = QWidget()
        panel._content_layout = QVBoxLayout(host)
        entry = Entry(id=1, title="t", notes="第一行\n<b>加粗</b>与<i>斜体</i>")

        panel._render_notes(entry)

        notes_label = host.findChildren(QLabel)[0]
        assert notes_label.textFormat() == Qt.TextFormat.PlainText
        assert notes_label.text() == "第一行\n<b>加粗</b>与<i>斜体</i>"

    def test_main_password_reveal_shows_full_markup_prefix(self, qapp):
        """主密码揭示：``<script>`` 开头的密码完整显示原文（显示与复制一致）。"""
        panel = DetailPanel(MagicMock())  # clipboard 以 mock 注入，不触真实剪贴板
        secret = "<script>alert(1)</script>P@ssw0rd!"
        _name, row = panel._make_field_row("密码", secret, secret=True, main_password=True)

        show_btn = next(
            btn for btn in row.findChildren(QPushButton) if btn.toolTip() == "显示/隐藏"
        )
        show_btn.click()

        val_label = row.findChildren(QLabel)[0]
        assert val_label.textFormat() == Qt.TextFormat.PlainText
        assert val_label.text() == secret

    def test_plain_field_value_literally_displayed(self, qapp):
        """普通字段行（如 username）的值标签 PlainText 字面显示。"""
        panel = DetailPanel(MagicMock())
        _name, row = panel._make_plain_field_row("账号", "<img src='x.svg'>alice")

        val_label = row.findChildren(QLabel)[0]
        assert val_label.textFormat() == Qt.TextFormat.PlainText
        assert val_label.text() == "<img src='x.svg'>alice"


class TestSecretFieldPlainText:
    """共享敏感字段行（detail_panel 非主密码字段 / 自定义密码字段）的揭示契约。"""

    def test_reveal_shows_full_markup_prefix(self, qapp):
        """揭示 ``<script>`` 开头的敏感值：完整原文显示。"""
        host = QWidget()
        store: dict[str, str] = {}
        env = SecretFieldEnv(
            store=store,
            timers=[],
            parent_widget=host,
            get_pwd_visible_ms=lambda: 60_000,
            on_copy=lambda btn, text: None,
            on_copy_feedback=lambda: None,
        )
        secret = "<script>nested</script>secret!"
        _name, row = make_secret_field_row(env, "API Key", secret, "api")

        show_btn = next(
            btn for btn in row.findChildren(QPushButton) if btn.toolTip() == "显示/隐藏"
        )
        show_btn.click()

        val_label = row.findChildren(QLabel)[0]
        assert val_label.textFormat() == Qt.TextFormat.PlainText
        assert val_label.text() == secret


class TestCustomFieldsPlainText:
    """自定义字段渲染器的字段名/字段值 PlainText 契约。"""

    def test_plain_field_name_and_value_literal(self, qapp):
        """自定义字段名与值含 markup 时字面渲染。"""
        renderer = CustomFieldsRenderer(
            copy_callback=lambda btn, text: None,
            copy_feedback_callback=lambda: None,
            hide_timer_callback=lambda: 60_000,
        )
        _name, row = renderer._make_plain_field_row("<b>字段名</b>", "<u>字段值</u>")

        labels = row.findChildren(QLabel)  # 行内仅值标签；名称标签是返回值第一项
        val_label = labels[0]
        assert val_label.textFormat() == Qt.TextFormat.PlainText
        assert val_label.text() == "<u>字段值</u>"


class TestPasswordHistoryPlainText:
    """密码历史揭示标签的 PlainText 契约（经构建器直驱，不依赖 EntryManager）。"""

    def test_history_password_label_is_plain_text(self, qapp):
        """历史密码 QLabel 创建即为 PlainText，揭示后 markup 前缀完整保留。"""
        from src.ui.components.password_history_widget import PasswordHistoryWidget

        widget = PasswordHistoryWidget()
        host = QWidget()
        layout = QVBoxLayout(host)
        widget._build_history(
            [{"changed_at": "2024-01-01 00:00:00", "password": "<svg/onload=x>old"}], layout
        )

        pwd_label = widget._pwd_labels[0]
        assert pwd_label.textFormat() == Qt.TextFormat.PlainText
        # 揭示路径经间接引用列表读取，直接模拟 toggle 显示分支
        pwd_label.setText(widget._history_passwords[0])
        assert pwd_label.text() == "<svg/onload=x>old"

    def test_history_timestamp_label_is_plain_text(self, qapp):
        """changed_at 时间标签同为 PlainText（SEC-030）：导入数据的时间戳可含 markup。"""
        from src.ui.components.password_history_widget import PasswordHistoryWidget

        widget = PasswordHistoryWidget()
        host = QWidget()
        layout = QVBoxLayout(host)
        widget._build_history([{"changed_at": "<i>2024-01-01</i>", "password": "old"}], layout)

        # 行内首个 QLabel 是 changed_at 时间标签（密码标签为第二个）
        time_label = host.findChildren(QLabel)[0]
        assert time_label.textFormat() == Qt.TextFormat.PlainText
        assert time_label.text() == "<i>2024-01-01</i>"


class TestMainWindowListTitlePlainText:
    """主窗口条目列表标题的 PlainText 契约（SEC-030 漏点收编）。"""

    def test_list_title_is_plain_text_and_survives_set_text(self, qapp):
        """列表标题创建即 PlainText；list_refresh_controller 以分类名 setText 后
        markup 字面保留（分类名可经导入携带富文本标记）。"""
        from PyQt6.QtWidgets import QSplitter

        from src.ui.windows.main_window import MainWindow

        mw = MainWindow.__new__(MainWindow)
        mw._splitter = QSplitter()
        mw._build_entry_list()

        title = mw._list_title
        assert title.objectName() == "sidebarListTitle"
        assert title.textFormat() == Qt.TextFormat.PlainText
        title.setText('<b style="color:red">工作</b><img src="x.svg">')
        assert title.textFormat() == Qt.TextFormat.PlainText
        assert title.text() == '<b style="color:red">工作</b><img src="x.svg">'


@pytest.mark.parametrize(
    "text",
    [
        "<b>加粗</b>",
        "<script>alert(1)</script>",
        '<img src="file:///C:/evil.svg">',
        "a < b 与 c > d 的普通不等号",
    ],
)
def test_detail_panel_title_tag_labels_are_plain(qapp, text):
    """详情面板标题/分类/标签标签为 PlainText（标题经工厂创建后 setText 保持格式）。"""
    label = create_plain_text_label("占位", "tag")
    label.setText(text)
    assert label.textFormat() == Qt.TextFormat.PlainText
    assert label.text() == text
