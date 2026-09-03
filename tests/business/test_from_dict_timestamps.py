"""Entry.from_dict 时间戳字段校验测试（QL-042）。

守护导入路径对 created_at/updated_at/password_changed_at 的 ISO 8601 可解析性
校验：非空且格式无效的值抛 EntryError（与恢复路径 backup/validator 的同款校验
对齐），防止无效时间戳入库导致 updated_at 字符串排序错乱与该条目永久退出
过期检测（_parse_changed_utc 返回 None）。
"""

import pytest

from src.exceptions import EntryError
from src.models import Entry


def _base_dict(**overrides):
    """构建 Entry.from_dict 的最小合法输入 dict，调用方经 kwargs 覆盖关注字段。"""
    d = dict(
        title="Test",
        username="user",
        password="pass",
    )
    d.update(overrides)
    return d


@pytest.mark.parametrize(
    "field",
    ["created_at", "updated_at", "password_changed_at"],
)
class TestTimestampRejection:
    """三个时间戳字段的非法值统一拒绝。"""

    @pytest.mark.parametrize(
        "bad_value",
        ["not-a-date", "2026-13-45", "T00:00:00", "abc 123"],
    )
    def test_invalid_timestamp_raises(self, field, bad_value):
        """非空且 fromisoformat 不可解析的时间戳抛 EntryError（IS ValueError）。"""
        with pytest.raises(EntryError, match=f"{field}格式无效"):
            Entry.from_dict(_base_dict(**{field: bad_value}))
        # EntryError 兼容 except ValueError 的既有处理范式
        with pytest.raises(ValueError, match=f"{field}格式无效"):
            Entry.from_dict(_base_dict(**{field: bad_value}))

    def test_non_string_type_raises(self, field):
        """int 等非字符串时间戳仍按类型校验拒绝（先于格式校验）。"""
        with pytest.raises(EntryError, match=f"{field}类型无效"):
            Entry.from_dict(_base_dict(**{field: 12345}))


@pytest.mark.parametrize(
    "good_value",
    [
        "2026-01-02T03:04:05",  # 无微秒
        "2026-01-02T03:04:05.123456",  # 含微秒
        "2026-01-02T03:04:05+00:00",  # 显式 UTC 偏移
    ],
)
def test_valid_iso_timestamps_pass(good_value):
    """合法 ISO 8601 扩展格式（T 分隔，含/不含微秒、+00:00）均通过并原样保留。"""
    entry = Entry.from_dict(
        _base_dict(
            created_at=good_value,
            updated_at=good_value,
            password_changed_at=good_value,
        )
    )
    assert entry.created_at == good_value
    assert entry.updated_at == good_value
    assert entry.password_changed_at == good_value


@pytest.mark.parametrize(
    "parseable_variant,normalized",
    [
        ("2026-01-02 03:04:05", "2026-01-02T03:04:05"),  # 空格分隔 → T 分隔（naive 保持 naive）
        ("2026-01-02", "2026-01-02T00:00:00"),  # 纯日期 → 补全时间
        ("20260102T030405", "2026-01-02T03:04:05"),  # 基本格式 → 扩展格式
        ("2026-01-02T03:04", "2026-01-02T03:04:00"),  # 截断时间 → 补全秒
        ("2026-01-02T03:04:05,123456", "2026-01-02T03:04:05.123456"),  # 逗号小数秒 → 点
        ("2026-01-02T03:04:05Z", "2026-01-02T03:04:05+00:00"),  # Z 后缀 → +00:00
        # 非零偏移统一转 UTC（QL-073）：钟面字面量随偏移归零改写为真实 UTC 时刻
        ("2026-01-02T11:04:05+08:00", "2026-01-02T03:04:05+00:00"),  # 东八区 → UTC
        ("2026-01-01T22:04:05-05:00", "2026-01-02T03:04:05+00:00"),  # 西五区 → UTC（跨日）
        ("2026-01-02T03:04:05+00:00", "2026-01-02T03:04:05+00:00"),  # 零偏移幂等
    ],
)
@pytest.mark.parametrize("field", ["created_at", "updated_at", "password_changed_at"])
def test_parseable_variants_normalized(field, parseable_variant, normalized):
    """可解析变体归一化为 UTC isoformat() 标准形态后落值（QL-060/073 守护）。

    fromisoformat 亦接受空格分隔/纯日期/基本格式/截断时间/逗号小数秒/Z 后缀等
    变体，与项目 isoformat() 产物混存时字符串排序不等于时间排序（空格 0x20 <
    'T' 0x54、',' 0x2C < '.' 0x2E、'Z' 与 '+00:00' 同刻异串）——QL-042/053 的
    拒绝式校验分别存在变体漏网与恢复路径绕过缺口，QL-060 改为归一化：不拒
    任何可解析输入，形态唯一使排序等价绝对成立；QL-073 进一步把非零偏移统一
    astimezone(UTC)——偏移原样保留时排序等价仅在全库统一偏移下成立（+08:00 的
    03:04 实为 UTC 前一日 19:04，字面序却排在 +00:00 的 02:04 之后）。
    """
    entry = Entry.from_dict(_base_dict(**{field: parseable_variant}))
    assert getattr(entry, field) == normalized


def test_utc_normalization_makes_string_order_absolute():
    """归一化后字符串排序==真实时间排序（QL-073 核心声明）。

    两时刻真实先后：01:04:05Z（源自 +02:00 的 03:04:05）早于 02:04:05Z。偏移
    原样保留的旧归一化按钟面字面比较得 03:04 > 02:04（错序，小时级）；转 UTC
    后字符串比较与真实时间序一致。
    """
    from src.models import normalized_iso_timestamp

    earlier = normalized_iso_timestamp("2026-01-02T03:04:05+02:00")
    later = normalized_iso_timestamp("2026-01-02T02:04:05+00:00")
    assert earlier < later
    assert earlier == "2026-01-02T01:04:05+00:00"


def test_naive_timestamp_kept_naive():
    """naive 输入（无偏移）保持 naive 形态落库（既有语义锁定）。

    无偏移信息不可转换（臆断 UTC/本地都会引入无依据的小时级改写）；消费侧对
    naive 统一按 UTC 解释（utils.format.format_datetime / security_analyzer），
    见 normalized_iso_timestamp 的 QL-073 注释。
    """
    from src.models import normalized_iso_timestamp

    assert normalized_iso_timestamp("2026-01-02T03:04:05") == "2026-01-02T03:04:05"
    assert normalized_iso_timestamp("2026-01-02T03:04:05.5") == "2026-01-02T03:04:05.500000"


def test_empty_and_missing_timestamps_pass():
    """空串与缺省（None 语义）通过：字段可选，不强制填充。"""
    entry = Entry.from_dict(_base_dict(created_at="", updated_at=""))
    assert entry.created_at == ""
    assert entry.updated_at == ""
    assert entry.password_changed_at == ""  # 缺省 → 默认空串


class TestCategoryFieldValidation:
    """Entry.from_dict 的 category 字段类型/长度校验（QL-049）。

    旧行为：``category_name=d.get("category", "")`` 无 isinstance——CSV 携带非 str
    （如 int）时在下游 ``_ensure_categories`` 的 ``.strip()`` 处裸 AttributeError
    中断导入且无友好文案。现与相邻字段范式一致在 from_dict 入口拒绝。
    """

    def test_non_string_category_raises(self):
        """int 等非字符串分类名抛 EntryError（IS ValueError），不再裸 AttributeError。"""
        with pytest.raises(EntryError, match="分类名称类型无效"):
            Entry.from_dict(_base_dict(category=12345))
        with pytest.raises(ValueError, match="分类名称类型无效"):
            Entry.from_dict(_base_dict(category=["工作"]))

    def test_overlong_category_raises(self):
        """超长分类名（>MAX_CATEGORY_NAME 字符）抛 EntryError，对齐 Category.from_dict。"""
        from src.models import MAX_CATEGORY_NAME

        with pytest.raises(EntryError, match="分类名称过长"):
            Entry.from_dict(_base_dict(category="分" * (MAX_CATEGORY_NAME + 1)))

    def test_valid_string_category_passes(self):
        """合法字符串分类名通过并原样保留；空串/缺省回退默认。"""
        entry = Entry.from_dict(_base_dict(category="工作"))
        assert entry.category_name == "工作"
        assert Entry.from_dict(_base_dict(category="")).category_name == ""
        assert Entry.from_dict(_base_dict()).category_name == ""


class TestCustomFieldsTypeValidation:
    """Entry.from_dict 的 custom_fields 类型校验（QL-054）。

    旧行为：``if isinstance(d["custom_fields"], list)`` 使 dict/str 等非 list
    形态静默置空，导入方丢字段无感知——与相邻字段「类型无效即 EntryError」
    范式不对称。现显式拒绝。
    """

    def test_non_list_custom_fields_raises(self):
        """dict/str 等非 list 形态抛 EntryError，不再静默置空。"""
        for bad in ({"name": "值"}, "字段", 12345):
            with pytest.raises(EntryError, match="custom_fields类型无效"):
                Entry.from_dict(_base_dict(custom_fields=bad))

    def test_list_custom_fields_pass(self):
        """合法 list 形态正常解析为 CustomField 列表；缺省回退空列表。"""
        entry = Entry.from_dict(_base_dict(custom_fields=[{"name": "备注", "value": "abc"}]))
        assert len(entry.custom_fields) == 1
        assert entry.custom_fields[0].name == "备注"
        assert Entry.from_dict(_base_dict()).custom_fields == []
