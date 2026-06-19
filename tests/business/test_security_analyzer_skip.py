"""安全分析器跳过损坏条目测试，验证部分条目损坏时分析继续。

SecurityAnalyzer 在 full_analysis 中遇到解密失败的条目时应跳过而非抛异常，
确保单个损坏条目不影响整体分析结果。
"""

from unittest.mock import MagicMock

import pytest

from src.business.managers.entry_cache import EntryCacheManager
from src.business.services.crypto_utils import encrypt_field
from src.business.services.security_analyzer import SecurityAnalyzer
from src.exceptions import VaultLockedError
from src.models import RawEntry


class TestSecurityAnalyzerSkipCorrupt:
    """验证 SecurityAnalyzer 遇到损坏条目时跳过并继续分析。"""

    def test_corrupt_entry_is_skipped_not_raised(self):
        """解密失败的损坏条目应被跳过，分析返回正常结果。"""
        vault = MagicMock()
        vault.key = b'\x00' * 32
        vault.is_unlocked = True
        vault.is_cancel_requested.return_value = False

        bad_entry = RawEntry(
            id=1,
            crypto_id='bad_crypto_id',
            title='损坏条目',
            username='enc_bad_user',
            password='enc_bad_pass',
            custom_fields='',
            notes='enc_bad_notes',
            totp_secret='',
            password_strength=0,
        )

        vault.db.get_entries.return_value = [bad_entry]

        analyzer = SecurityAnalyzer(vault, EntryCacheManager(vault))

        # bad_entry 的 title/username 为非密文明文（无 cb2: 前缀），经
        # EntryCacheManager.cached_search_metadata 解密时抛 ValueError →
        # _make_summary 检测 failed_fields 抛错 → full_analysis 跳过该条目，
        # 返回结果而非抛异常（复用 _make_summary 经 cache 解密的真实路径）。
        result = analyzer.full_analysis(90)

        assert isinstance(result, dict)
        assert result['total'] == 1  # 条目仍计入总数
        assert result['weak_count'] == 0  # 损坏条目不参与弱密码统计

    def test_all_entries_corrupt_returns_empty_results(self):
        """所有条目都损坏时，分析跳过全部条目但仍返回结果。"""
        vault = MagicMock()
        vault.key = b'\x00' * 32
        vault.is_unlocked = True
        vault.is_cancel_requested.return_value = False

        corrupt_entry = RawEntry(
            id=1,
            crypto_id='corrupt_crypto',
            title='损坏',
            username='enc',
            password='enc_pass',
            custom_fields='',
            password_strength=0,
        )

        vault.db.get_entries.return_value = [corrupt_entry]

        analyzer = SecurityAnalyzer(vault, EntryCacheManager(vault))

        # corrupt_entry 字段为明文，经 cache 解密失败 → _make_summary 抛错 → 跳过。
        result = analyzer.full_analysis(90)

        assert isinstance(result, dict)
        assert result['total'] == 1

    def test_normal_analysis_returns_dict(self):
        """正常分析应返回包含预期键的 dict。"""
        vault = MagicMock()
        vault.key = b'\x00' * 32
        vault.is_unlocked = True

        vault.db.get_entries.return_value = []

        analyzer = SecurityAnalyzer(vault, EntryCacheManager(vault))
        result = analyzer.full_analysis(90)

        assert isinstance(result, dict)
        assert 'total' in result
        assert 'weak_count' in result
        assert 'weak_entries' in result
        assert 'duplicate_groups' in result
        assert 'old_entries' in result
        assert result['total'] == 0
        assert result['weak_count'] == 0

    def test_naive_password_changed_at_does_not_crash(self):
        """naive 时间戳（无时区偏移）应视为 UTC，不抛 TypeError。

        回归守护：cutoff 为 aware UTC，naive 的 password_changed_at 与之比较
        会抛 TypeError 使整个分析崩溃。修复后 naive 视为 UTC，旧时间戳正确
        归入过期条目。
        """
        vault = MagicMock()
        vault.key = b'\x00' * 32
        vault.is_unlocked = True
        vault.is_cancel_requested.return_value = False

        entry = RawEntry(
            id=1,
            crypto_id='naive_crypto',
            title=encrypt_field('旧条目', vault.key, 'naive_crypto', 'title'),
            username='',
            password='',
            custom_fields='',
            # naive ISO 字符串，无 +00:00 偏移（模拟旧版或外部导入数据）
            password_changed_at='2020-01-01T00:00:00',
        )
        vault.db.get_entries.return_value = [entry]

        analyzer = SecurityAnalyzer(vault, EntryCacheManager(vault))
        result = analyzer.full_analysis(90)

        assert isinstance(result, dict)
        # 2020 远早于 now-90d，naive 视为 UTC 后应归入过期
        assert result['old'] == 1


def test_cached_analysis_returns_independent_copy():
    """_cached_analysis 返回独立副本，调用方修改不污染缓存本体。

    回归守护：miss 与 hit 两条出口路径都经 _refilter_cache 复制，
    防止调用方修改返回的列表/Entry 污染后续命中的缓存。
    """
    vault = MagicMock()
    vault.key = b'\x00' * 32
    vault.is_unlocked = True
    vault.key_epoch = 1
    vault.db.get_entries.return_value = []
    vault.db.get_entry_count.return_value = 0

    analyzer = SecurityAnalyzer(vault, EntryCacheManager(vault))
    result1 = analyzer._cached_analysis(90)
    # 模拟调用方修改返回对象（如 UI 排序/追加）
    result1['weak_entries'].append('polluted')

    result2 = analyzer._cached_analysis(90)
    assert 'polluted' not in result2['weak_entries']


def test_full_analysis_aborts_on_cancel_request():
    """锁定/取消请求到来时，full_analysis 主动中止抛 VaultLockedError。

    回归守护：用户点锁定时 lock() 阻塞等 vault 写锁，full_analysis 须周期性
    检查 is_cancel_requested 并主动抛出释放锁，避免 UI 冻结与明文驻留。
    抛出的 VaultLockedError 由 _cached_analysis 捕获返回空报告。
    """
    vault = MagicMock()
    vault.key = b'\x00' * 32
    vault.is_unlocked = True
    vault.is_cancel_requested.return_value = True  # 模拟锁定请求已到来

    entry = RawEntry(
        id=1, crypto_id='c', title='t', username='u',
        password='', custom_fields='',
    )
    vault.db.get_entries.return_value = [entry]

    analyzer = SecurityAnalyzer(vault, EntryCacheManager(vault))
    with pytest.raises(VaultLockedError):
        analyzer.full_analysis(90)
    vault.is_cancel_requested.assert_called()


def test_full_analysis_proceeds_when_not_cancelled():
    """无取消请求时 full_analysis 正常完成，不因取消检查而误中止。"""
    vault = MagicMock()
    vault.key = b'\x00' * 32
    vault.is_unlocked = True
    vault.is_cancel_requested.return_value = False

    vault.db.get_entries.return_value = []

    analyzer = SecurityAnalyzer(vault, EntryCacheManager(vault))
    result = analyzer.full_analysis(90)
    assert isinstance(result, dict)
    assert result['total'] == 0
