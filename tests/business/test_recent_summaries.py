"""EntryManager.get_recent_summaries「近期更新」视图契约测试。

守护公开 API 行为契约：按 ``updated_at`` 降序返回前 N 条（LIMIT 下推 SQL 的可观察
效果——条目数多于 limit 时只返回 limit 条，不拉全量再内存截断）、返回摘要不含密码
等敏感明文但展示字段齐全、非正 limit 归一为空列表。经真实 vault（加密落库 + 解密
读取）验证，注入互异的 ``updated_at`` 使排序确定化。
"""

from datetime import UTC, datetime

from src.models import CustomField, Entry

# 注入的基准时间：各条目按分钟递增，ISO 字典序与时间序一致，排序断言确定化。
_BASE = datetime(2026, 8, 20, 10, 0, 0, tzinfo=UTC)


def _iso_at(minute: int) -> str:
    return datetime(2026, 8, 20, 10, minute, 0, tzinfo=UTC).isoformat()


def _add_entry(entry_mgr, *, title: str, minute: int, **overrides) -> int:
    """添加带指定 updated_at 的条目（add_entry 对显式时间戳走 preserve_metadata 保留）。

    其余字段经 overrides 覆盖默认值（dict 合并而非 **kwargs 透传，避免与显式
    形参重复传参冲突）。
    """
    fields: dict = dict(
        username="user",
        password="Pass123!@#",
        url="https://example.com",
        tags="t1",
        notes="备注",
        entry_type="login",
        custom_fields=[],
    )
    fields.update(overrides)
    entry = Entry(
        title=title,
        created_at=_BASE.isoformat(),
        updated_at=_iso_at(minute),
        **fields,
    )
    return entry_mgr.add_entry(entry)


class TestGetRecentSummaries:
    """get_recent_summaries 的排序/LIMIT/摘要契约。"""

    def test_returns_entries_ordered_by_updated_desc(self, entry_mgr):
        """按 updated_at 降序返回：最新在前，且完整覆盖未超限的全部条目。"""
        # 条目按 minute 0..4 落库（时间递增），期望倒序
        for minute in range(5):
            _add_entry(entry_mgr, title=f"条目-{minute}", minute=minute)

        summaries = entry_mgr.get_recent_summaries(limit=10)

        assert [e.title for e in summaries] == [
            "条目-4",
            "条目-3",
            "条目-2",
            "条目-1",
            "条目-0",
        ]

    def test_limit_truncates_to_most_recent(self, entry_mgr):
        """条目数超过 limit 时只返回 limit 条最新条目（SQL 下推 LIMIT 的行为契约）。"""
        for minute in range(5):
            _add_entry(entry_mgr, title=f"截断-{minute}", minute=minute)

        summaries = entry_mgr.get_recent_summaries(limit=3)

        assert len(summaries) == 3
        assert [e.title for e in summaries] == ["截断-4", "截断-3", "截断-2"]

    def test_summaries_exclude_secrets_but_keep_display_fields(self, entry_mgr):
        """返回的是摘要：密码/TOTP/备注/自定义字段为空，标题/账号/网址/标签齐全。"""
        _add_entry(
            entry_mgr,
            title="摘要字段条目",
            minute=0,
            username="summary-user",
            password="SuperSecret-9!",
            url="https://example.com/summary",
            tags="tagA,tagB",
            notes="不应进入摘要的备注",
            totp_secret="JBSWY3DPEHPK3PXP",
            custom_fields=[CustomField("cf", "值", "password")],
        )

        summaries = entry_mgr.get_recent_summaries(limit=5)

        assert len(summaries) == 1
        s = summaries[0]
        assert s.password == ""
        assert s.totp_secret == ""
        assert s.notes == ""
        assert s.custom_fields == []
        assert s.title == "摘要字段条目"
        assert s.username == "summary-user"
        assert s.url == "https://example.com/summary"
        assert s.tags == "tagA,tagB"
        assert s.updated_at == _iso_at(0)

    def test_non_positive_limit_returns_empty(self, entry_mgr):
        """limit<=0 归一为空列表，不触发查询异常。"""
        _add_entry(entry_mgr, title="存在条目", minute=0)
        assert entry_mgr.get_recent_summaries(limit=0) == []
        assert entry_mgr.get_recent_summaries(limit=-3) == []


class TestInvalidateEpochOrdering:
    """get_recent_summaries 的 invalidate_if_epoch_changed 位置守护（ARCH-056）。

    原实现把 invalidate 放在读块**后**（锁外解密前），与 get_entry_summaries 的
    PERF-086 前移位置（读块前）模式分裂——本路径虽不消费投影行集缓存，读块后
    invalidate 的旧位置会误导后来者在新读路径复制；统一为读块前后，任何读路径
    首次调用的 epoch 重臂都不废自己刚回填的缓存。
    """

    def test_invalidate_precedes_db_fetch(self, entry_mgr, monkeypatch):
        """invalidate_if_epoch_changed 先于 db.get_entries 执行（位置对齐锁定）。"""
        events: list[str] = []
        cache = entry_mgr.cache
        real_invalidate = cache.invalidate_if_epoch_changed

        def _invalidate() -> None:
            events.append("invalidate")
            real_invalidate()

        monkeypatch.setattr(cache, "invalidate_if_epoch_changed", _invalidate)
        db = entry_mgr.db
        real_fetch = db.get_entries

        def _fetch(query):
            events.append("fetch")
            return real_fetch(query)

        monkeypatch.setattr(db, "get_entries", _fetch)

        assert entry_mgr.get_recent_summaries(limit=5) == []

        assert events == ["invalidate", "fetch"]

    def test_first_call_arms_cache_epoch_before_fetch(self, make_vault_env):
        """行为锚定：首次调用在读块前完成 epoch 重臂（cache_epoch == 当前 key_epoch）。

        位置前移后重臂发生在拉取之前，与 get_entry_summaries 首调行为一致；
        摘要构建的缓存回写（分类名等）世代与快照世代一致、可正常落缓存。
        """
        env = make_vault_env()
        mgr = env.entry_mgr
        _add_entry(mgr, title="仅有一条", minute=0)

        assert mgr.get_recent_summaries(limit=5) != []
        assert mgr.cache.cache_epoch == env.vault.key_epoch
