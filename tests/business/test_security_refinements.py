"""验证安全与性能细化改动的针对性测试。

覆盖近期加固中不易被现有集成测试直接观察的内部契约：
- ``KeyManager`` 改密/恢复时对旧密钥 bytearray 的安全清零（收缩改密后旧密钥
  仍可被进程内存 dump 读取的窗口，与项目「轮换收缩泄漏面」设计意图对齐）。
- ``EntryRepository.get_entries`` 的 ``verify`` 参数：SKIP 跳过逐行 HMAC 验签、
  LENIENT 标记 ``integrity_error``，为列表路径的性能/语义权衡提供类型化开关。
"""

from src.business.services import key_manager as key_manager_module
from src.business.services.key_manager import KeyManager
from src.business.services.security_analyzer import DEFAULT_ANALYSIS_DAYS
from src.database.types import EntryQuery, VerifyMode
from src.exceptions import VaultIntegrityError
from src.models import Entry, RawEntry


class TestKeyManagerZeroing:
    """验证改密/恢复时旧密钥的内部 bytearray 副本被原地清零。

    _to_bytearray 总复制：KeyManager 持独立副本，update/activate 时经
    secure_zero_buffer 清零内部旧副本（外部传入对象不受影响）。用 spy 在清零前
    快照被清零对象，验证旧密钥副本确实经过清零路径且内容为旧密钥。
    """

    def test_update_key_zeroes_old_internal_copy(self, monkeypatch):
        """经 spy 捕获清零对象，验证 update_key 仅清零旧主密钥内部副本、不动 snapshot。"""
        km = KeyManager()
        km.activate(bytearray(b"x" * 32), bytearray(b"y" * 32), epoch=1)

        zeroed: list[bytearray] = []
        original = key_manager_module.secure_zero_buffer

        def spy(data: bytearray) -> None:
            zeroed.append(bytearray(data))  # 清零前快照
            original(data)

        monkeypatch.setattr(key_manager_module, "secure_zero_buffer", spy)
        km.update_key(bytearray(b"z" * 32))

        # 仅旧主密钥内部副本被清零（snapshot 未变，不应被清零）
        assert len(zeroed) == 1
        assert bytes(zeroed[0]) == b"x" * 32

    def test_update_snapshot_key_zeroes_old_internal_copy(self, monkeypatch):
        """经 spy 捕获清零对象，验证 update_snapshot_key 仅清零旧 snapshot 内部副本。"""
        km = KeyManager()
        km.activate(bytearray(b"k" * 32), bytearray(b"s" * 32), epoch=1)

        zeroed: list[bytearray] = []
        original = key_manager_module.secure_zero_buffer

        def spy(data: bytearray) -> None:
            zeroed.append(bytearray(data))
            original(data)

        monkeypatch.setattr(key_manager_module, "secure_zero_buffer", spy)
        km.update_snapshot_key(bytearray(b"n" * 32))

        assert len(zeroed) == 1
        assert bytes(zeroed[0]) == b"s" * 32

    def test_update_does_not_zero_caller_object(self):
        """总复制：update 清零 KeyManager 内部副本，调用方传入对象不受影响。"""
        km = KeyManager()
        key = bytearray(b"k" * 32)
        km.activate(key, bytearray(b"s" * 32), epoch=1)
        km.update_key(bytearray(b"new" * 10 + b"nn"))
        assert bytes(key) == b"k" * 32

    def test_activate_zeroes_previous_internal_keys(self, monkeypatch):
        """再次 activate（如恢复后重新激活）也清零上一组密钥的内部副本。"""
        km = KeyManager()
        km.activate(bytearray(b"a" * 32), bytearray(b"b" * 32), epoch=1)

        zeroed: list[bytearray] = []
        original = key_manager_module.secure_zero_buffer

        def spy(data: bytearray) -> None:
            zeroed.append(bytearray(data))
            original(data)

        monkeypatch.setattr(key_manager_module, "secure_zero_buffer", spy)
        km.activate(bytearray(b"c" * 32), bytearray(b"d" * 32), epoch=2)

        # 旧主密钥 + 旧 snapshot 内部副本均被清零
        assert len(zeroed) == 2
        contents = {bytes(buf) for buf in zeroed}
        assert b"a" * 32 in contents
        assert b"b" * 32 in contents


def test_get_entries_verify_modes(vault, entry_mgr):
    """verify=SKIP 跳过完整性验签（integrity_error 保持 False），
    LENIENT 调用 verifier 并在失败时标记 integrity_error。"""
    entry_mgr.add_entry(
        Entry(
            title="验证条目",
            username="u",
            password="p",
            entry_type="login",
        )
    )

    def bad_verifier(_entry: RawEntry):
        raise VaultIntegrityError("签名不匹配")

    original_verifier = vault.db._entry_verifier
    vault.db._entry_verifier = bad_verifier
    try:
        lenient = vault.db.get_entries(EntryQuery(verify=VerifyMode.LENIENT))
        assert lenient and lenient[0].integrity_error is True

        skipped = vault.db.get_entries(EntryQuery(verify=VerifyMode.SKIP))
        assert skipped and skipped[0].integrity_error is False
    finally:
        vault.db._entry_verifier = original_verifier


class TestGetCachedCounts:
    """get_cached_counts 轻量计数入口（PERF-2）：跳过 _refilter_cache 的 Entry 深拷贝。

    仅读计数的消费者（状态栏刷新、weak/duplicate 空态判定）经此入口避免无谓深拷贝。
    用 __new__ 绕过完整构造、手动填充缓存，聚焦计数提取与 days 影响 old 的逻辑。
    """

    @staticmethod
    def _analyzer(cache, *, days: int = DEFAULT_ANALYSIS_DAYS, ttl: int = 120, age: float = 0.0):
        import threading
        import time
        from types import SimpleNamespace

        from src.business.services.security_analyzer import SecurityAnalyzer

        analyzer = SecurityAnalyzer.__new__(SecurityAnalyzer)
        analyzer._analysis_cache = cache
        analyzer._analysis_cache_time = time.monotonic() - age
        analyzer._analysis_cache_days = days
        analyzer._cache_ttl_seconds = ttl
        analyzer._cache_lock = threading.Lock()
        # key_epoch 校验（SEC-002）：cache 不含 _key_epoch 时配 key_epoch=None 使校验通过。
        analyzer._vault = SimpleNamespace(key_epoch=None)
        return analyzer

    def test_returns_none_when_no_cache(self):
        assert self._analyzer(None).get_cached_counts() is None

    def test_returns_none_when_expired(self):
        analyzer = self._analyzer({"total": 1}, ttl=0, age=1.0)
        assert analyzer.get_cached_counts() is None

    def test_returns_counts_matching_cache_days(self):
        from src.business.services.security_analyzer import SecurityCounts

        cache = {"total": 10, "weak_count": 3, "duplicate_count": 2, "old": 1}
        counts = self._analyzer(cache, days=90).get_cached_counts(90)
        assert counts == SecurityCounts(10, 3, 2, 1)

    def test_old_recounted_when_days_differs(self):
        """days 与缓存 days 不同时按 days 重算 old 计数，不深拷贝 Entry。"""
        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)
        cache = {
            "total": 5,
            "weak_count": 0,
            "duplicate_count": 0,
            "old": 0,
            "_summaries_with_dates": [
                (
                    Entry(title="old", username="u", password="p", entry_type="login"),
                    now - timedelta(days=200),
                ),
                (
                    Entry(title="recent", username="u", password="p", entry_type="login"),
                    now - timedelta(days=10),
                ),
            ],
        }
        analyzer = self._analyzer(cache, days=90)
        # days=365：cutoff=now-365d，两条目(200d/10d前)均晚于 cutoff → 不过期
        assert analyzer.get_cached_counts(365).old == 0
        # days=100：cutoff=now-100d，old(200d前)早于 cutoff → 过期；recent(10d前)不过期
        assert analyzer.get_cached_counts(100).old == 1
