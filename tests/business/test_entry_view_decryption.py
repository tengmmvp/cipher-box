"""EntryViewDecryptor.decrypt_summary 的字段全等对照测试（PERF-063）。

decrypt_summary 由「build_entry_summary 全字段构造 + replace 覆盖 6 字段」两步
合并为单次 copy_entry_fields 构造（50k 次列表刷新实测省 ~300ms）。本文件用旧两步
参考实现逐字段对照，守护合并后字段语义零漂移：Entry 为 dataclass（全字段 __eq__），
单一相等断言即覆盖全部 24 个字段。
"""

import dataclasses

from src.business.services.entry_view_decryption import build_entry_summary


def _reference_two_step(decryptor, raw_entry):
    """旧两步参考实现：build_entry_summary + replace 覆盖（PERF-063 合并前行为）。"""
    title, username, url, tags = decryptor._cache.cached_search_metadata(raw_entry)
    summary = build_entry_summary(raw_entry, username)
    category_name = decryptor._cache.decrypt_category_name(
        raw_entry.category_id,
        raw_entry.category_name,
    )
    return dataclasses.replace(
        summary,
        title=title,
        url=url,
        tags=tags,
        category_name=category_name,
    )


class TestDecryptSummarySingleConstruction:
    """单次构造的 decrypt_summary 与旧两步参考实现输出完全一致。"""

    def test_plain_entry_matches_reference(self, entry_mgr, make_entry):
        """无分类/标签的最简条目：单次构造输出与两步参考全字段相等。"""
        entry_id = entry_mgr.add_entry(
            make_entry(title="T", username="u", url="https://x", password="Pass123!@#")
        )
        raw = entry_mgr.db.get_entry(entry_id)
        assert raw is not None
        decryptor = entry_mgr._view_decryptor

        assert decryptor.decrypt_summary(raw) == _reference_two_step(decryptor, raw)

    def test_entry_with_category_and_tags_matches_reference(self, entry_mgr, make_entry):
        """含分类与标签的条目：解密后的 title/url/tags/分类名均正确并入单次构造。"""
        from src.models import Category

        category_id = entry_mgr.categories.add_category(Category(name="自定义分类-唯一"))
        entry_id = entry_mgr.add_entry(
            make_entry(
                title="带分类",
                username="alice",
                url="https://example.com",
                tags="dev,work",
                password="Pass123!@#",
                category_id=category_id,
            )
        )
        raw = entry_mgr.db.get_entry(entry_id)
        assert raw is not None
        decryptor = entry_mgr._view_decryptor

        got = decryptor.decrypt_summary(raw)
        expected = _reference_two_step(decryptor, raw)
        assert got == expected
        # 关键覆盖字段抽样（防 __eq__ 因两侧同取默认值而虚过）：
        assert got.title == "带分类"
        assert got.url == "https://example.com"
        assert got.tags == "dev,work"
        assert got.category_name == "自定义分类-唯一"
        assert got.username == "alice"
        # 敏感字段不进入摘要（与 build_entry_summary 的契约一致）。
        assert got.password == ""
        assert got.notes == ""
        assert got.custom_fields == []
        assert got.totp_secret == ""
