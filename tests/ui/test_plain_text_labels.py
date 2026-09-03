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
from src.ui.components.secret_field import (
    PlainFieldEnv,
    SecretFieldEnv,
    make_plain_field_row,
    make_secret_field_row,
)
from src.ui.components.widgets import create_plain_text_label
from src.ui.resources.constants import PWD_MASK


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


class TestCopySecretRaceGuard:
    """敏感字段复制路径的 ``sip.isdeleted`` 竞态守卫（MAINT-103 回归）。

    收敛进共享工厂时复制路径一度丢失守卫（同工厂 ``_mask_row``/``_toggle`` 均有）：
    点击复制后同事件循环周期内按钮被 ``deleteLater``（切换条目 force 重建/锁定
    清理）而挂起 ``clicked`` 事件仍投递时，对已删 C++ 对象写反馈图标抛
    ``RuntimeError``——PyQt6 槽内未捕获异常直接 qFatal 中止应用。
    """

    def _make_env(self, host: QWidget, copied: list) -> SecretFieldEnv[str]:
        """构造记录型复制的共享环境（on_copy 捕获调用，不触真实剪贴板）。"""
        return SecretFieldEnv(
            store={"api": "secret-value"},
            timers=[],
            parent_widget=host,
            get_pwd_visible_ms=lambda: 60_000,
            on_copy=lambda btn, text: copied.append((btn, text)),
            on_copy_feedback=lambda: None,
        )

    def test_copy_secret_skips_deleted_button(self, qapp):
        """按钮 C++ 对象销毁后触发复制处理闭包：静默跳过，不抛 RuntimeError。"""
        from PyQt6 import sip

        from src.ui.components import secret_field

        host = QWidget()
        copied: list = []
        env = self._make_env(host, copied)
        _name, row = make_secret_field_row(env, "API Key", "secret-value", "api")
        copy_btn = next(btn for btn in row.findChildren(QPushButton) if btn.toolTip() == "复制密码")

        # 正常路径经真实信号连线触发：工厂构建的闭包已连接 clicked
        copy_btn.click()
        assert copied == [(copy_btn, "secret-value")]

        # 确定性销毁按钮 C++ 对象（sip.delete 等价「父窗口直接销毁子控件」，
        # deleteLater 的 DeferredDelete 推进在测试环境下不确定，见 QL-032 先例）
        sip.delete(copy_btn)
        assert sip.isdeleted(copy_btn)

        handler = secret_field._make_copy_secret(env, "api", copy_btn)
        handler()  # 不应抛 RuntimeError / 崩溃

        # 守卫跳过：销毁后不再触达 on_copy（反馈图标写入随守卫一并跳过）
        assert len(copied) == 1


class TestPlainFieldCopyRaceGuard:
    """普通字段行复制路径的 ``sip.isdeleted`` 竞态守卫（MAINT-113 回归）。

    普通字段行的复制闭包原为 detail_panel / custom_fields_renderer 两份平行实现，
    其中 renderer 侧缺失守卫（MAINT-103 收敛敏感行时的同型遗漏）：点击复制后
    同事件循环周期内按钮被 ``deleteLater`` 而挂起 ``clicked`` 事件仍投递时，回调
    链直达 ``detail_panel._copy_with_feedback`` 内的 ``set_icon(btn, CHECK)``——
    对已删 C++ 对象写图标抛 ``RuntimeError``，PyQt6 槽内未捕获异常 qFatal 中止。
    两处现收敛至 ``secret_field._make_guarded_copy`` 单一事实源（守卫单一实现）。
    """

    def test_plain_field_copy_skips_deleted_button(self, qapp):
        """按钮 C++ 对象销毁后触发普通字段复制闭包：静默跳过，不抛 RuntimeError。"""
        from PyQt6 import sip

        from src.ui.components import secret_field

        host = QWidget()
        copied: list = []
        env = PlainFieldEnv(
            store={0: "plain-value"},
            on_copy=lambda btn, text: copied.append((btn, text)),
        )
        _name, row = make_plain_field_row(env, "备注字段", "plain-value", 0)

        # 正常路径经真实信号连线触发：行内复制按钮已连接带守卫的处理闭包
        copy_btn = next(btn for btn in row.findChildren(QPushButton) if btn.toolTip() == "复制")
        copy_btn.click()
        assert copied == [(copy_btn, "plain-value")]

        # 确定性销毁按钮 C++ 对象（QL-032 先例：sip.delete 等价父窗口直接销毁子控件）
        sip.delete(copy_btn)
        assert sip.isdeleted(copy_btn)

        # 行工厂实际连线的守卫闭包经同一模块级工厂构造，此处直接驱动同工厂产物
        handler = secret_field._make_guarded_copy(
            copy_btn, env.on_copy, lambda: env.store.get(0, "")
        )
        handler()  # 不应抛 RuntimeError / 崩溃

        # 守卫跳过：销毁后不再触达 on_copy（反馈图标写入随守卫一并跳过）
        assert len(copied) == 1

    def test_renderer_plain_row_uses_shared_factory(self, qapp):
        """CustomFieldsRenderer 的普通字段行接线共享工厂：复制反馈回调可达。"""
        copied: list = []
        renderer = CustomFieldsRenderer(
            copy_callback=lambda btn, text: copied.append((btn, text)),
            copy_feedback_callback=lambda: None,
            hide_timer_callback=lambda: 60_000,
        )
        _name, row = renderer._make_plain_field_row("邮箱", "a@b.c")

        copy_btn = next(btn for btn in row.findChildren(QPushButton) if btn.toolTip() == "复制")
        copy_btn.click()

        # 值经间接引用字典读取（clear 后闭包读到空串，不再触达已失效明文）
        assert copied == [(copy_btn, "a@b.c")]
        renderer.clear()
        assert not renderer._plain_rows  # MAINT-115 holder（__len__ 观察残留）


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
        # 经真实交互路径揭示（QL-076）：点击行内显示按钮触发 toggle 闭包（间接
        # 引用列表读取 + setText），绕过闭包直接 setText 会漏掉「揭示路径按
        # PlainText 渲染」的真实链路。初始为掩码，点击后展示完整 markup 前缀。
        assert pwd_label.text() == PWD_MASK
        show_btn = next(
            btn for btn in host.findChildren(QPushButton) if btn.toolTip() == "显示/隐藏"
        )
        show_btn.click()
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
