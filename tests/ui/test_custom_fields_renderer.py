"""CustomFieldsRenderer.render 的空值过滤与空分组抑制测试（QL-030）。

守护「值全为空的字段逐行跳过后，详情面板不得残留只有标题『自定义字段』的空
分组」：render 先收集待渲染行，有行才创建 QGroupBox 并挂载布局。同时守护
返回的掩码 QTimer 语义不变（password 型字段行构建即追加定时器，与是否挂载
分组无关）。

直接构造 CustomFieldsRenderer（回调以 lambda 桩替换），渲染到独立 QWidget 的
QVBoxLayout，经布局 itemAt/widget 断言分组挂载形态，不依赖 DetailPanel。
"""

from PyQt6.QtWidgets import QGroupBox, QVBoxLayout, QWidget

from src.models import CustomField, Entry
from src.ui.components.custom_fields_renderer import CustomFieldsRenderer


def _make_renderer() -> CustomFieldsRenderer:
    """构造回调全桩的渲染器：copy/反馈无操作，可见时长返回固定毫秒。"""
    return CustomFieldsRenderer(
        copy_callback=lambda btn, text: None,
        copy_feedback_callback=lambda: None,
        hide_timer_callback=lambda: 5000,
    )


def _render_into_host(qapp, fields: list[CustomField]):
    """把携带给定自定义字段的条目渲染进独立宿主，返回 (宿主, 定时器)。

    宿主 QWidget 由调用方持有至断言结束：无父控件的顶层 widget 被 GC 时连带
    删除其 C++ 布局对象，提前释放会使后续 layout 访问抛 RuntimeError。
    """
    entry = Entry(title="测试条目", custom_fields=fields)
    host = QWidget()
    layout = QVBoxLayout(host)
    renderer = _make_renderer()
    timers = renderer.render(entry, layout, host)
    return host, timers


def test_all_empty_values_render_no_group(qapp):
    """值全为空 → 目标布局不挂载任何分组（无空『自定义字段』标题壳）。"""
    host, timers = _render_into_host(
        qapp,
        [
            CustomField(name="备注1", value=""),
            CustomField(name="密钥", value="", field_type="password"),
            CustomField(name="链接", value="", field_type="url"),
        ],
    )
    layout = host.layout()
    assert layout is not None
    assert layout.count() == 0
    assert timers == []


def test_non_empty_values_render_group_with_rows(qapp):
    """存在非空值 → 挂载『自定义字段』分组，行数与非空字段数一致。"""
    host, _timers = _render_into_host(
        qapp,
        [
            CustomField(name="服务器", value="web-01"),
            CustomField(name="链接", value="https://example.com", field_type="url"),
        ],
    )
    layout = host.layout()
    assert layout is not None
    assert layout.count() == 1
    group = layout.itemAt(0).widget()
    assert isinstance(group, QGroupBox)
    assert group.title() == "自定义字段"
    form = group.layout()
    assert form is not None
    assert form.rowCount() == 2


def test_mixed_values_skip_empty_rows(qapp):
    """空值与非空值混排 → 仅非空字段成行，空值字段不出现在分组中。"""
    host, _timers = _render_into_host(
        qapp,
        [
            CustomField(name="空字段", value=""),
            CustomField(name="有效字段", value="value-1"),
        ],
    )
    layout = host.layout()
    assert layout is not None
    assert layout.count() == 1
    form = layout.itemAt(0).widget().layout()
    assert form is not None
    assert form.rowCount() == 1


def test_password_field_row_appends_mask_timer(qapp):
    """非空 password 型字段 → 行构建追加掩码 QTimer，分组挂载与否不影响该语义。"""
    host, timers = _render_into_host(
        qapp,
        [CustomField(name="API 密钥", value="sk-live-123", field_type="password")],
    )
    layout = host.layout()
    assert layout is not None
    assert layout.count() == 1
    assert len(timers) == 1


class TestRowValueStore:
    """共享间接引用 holder（MAINT-115）：行号分配、store 暴露与安全清零复位。

    detail_panel 与 renderer 的「dict + 计数器 + mark_secret_discarded 清理块」
    三件套收敛于此；clear 后行号复位（两轮渲染的键不跨轮次累积）与 store 字典
    引用共享（行构建环境写入即 holder 可见）是两类消费方的行为契约。
    """

    def test_next_key_monotonic_then_reset_by_clear(self):
        """行号单调递增；clear 清空值并复位行号（下一轮从 0 重新分配）。"""
        from src.ui.components.secret_field import RowValueStore

        holder = RowValueStore()
        holder.store[holder.next_key()] = "a"
        holder.store[holder.next_key()] = "b"

        assert holder.store == {0: "a", 1: "b"}
        assert len(holder) == 2

        holder.clear()

        assert holder.store == {}
        assert len(holder) == 0
        assert holder.next_key() == 0  # 计数随清零复位

    def test_store_dict_is_shared_reference(self):
        """store property 暴露内部字典本体：行构建环境写入即 holder 可见（清零收口前提）。"""
        from src.ui.components.secret_field import RowValueStore

        holder = RowValueStore()
        exposed = holder.store
        exposed[holder.next_key()] = "plain"

        assert holder.store is exposed
        assert holder.store == {0: "plain"}

    def test_renderer_clear_resets_both_holders(self, qapp):
        """renderer.clear 经 holder 收口：敏感/普通两个 store 一并清零复位。"""
        renderer = _make_renderer()
        renderer._plain_rows.store[renderer._plain_rows.next_key()] = "plain"
        renderer._secret_rows.store[renderer._secret_rows.next_key()] = "secret"

        renderer.clear()

        assert not renderer._plain_rows
        assert not renderer._secret_rows
        assert renderer._plain_rows.next_key() == 0
        assert renderer._secret_rows.next_key() == 0
