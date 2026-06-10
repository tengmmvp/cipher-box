"""安全分析器跳过损坏条目测试 — 验证部分条目损坏时分析继续"""

from unittest.mock import MagicMock, patch

import pytest

from src.business.security_analyzer import SecurityAnalyzer
from src.exceptions import EntryIntegrityError
from src.database.models import Entry


class TestSecurityAnalyzerSkipCorrupt:
    """验证 SecurityAnalyzer 遇到损坏条目时的行为。"""

    def test_corrupt_entry_raises_runtime_error(self):
        """损坏条目（解密失败）会抛出 EntryIntegrityError（兼容 RuntimeError）。"""
        vault = MagicMock()
        vault.key = b'\x00' * 32
        vault.is_unlocked = True

        # 创建损坏条目：_decrypt 解密时会触发异常
        bad_entry = Entry(
            id=1,
            crypto_id='bad_crypto_id',
            title='损坏条目',
            username='enc_bad_user',
            password='enc_bad_pass',
            custom_fields_enc='',
            notes='enc_bad_notes',
            totp_secret='',
            password_strength=0,
        )

        vault.db.get_entries.return_value = [bad_entry]

        analyzer = SecurityAnalyzer(vault)

        # _decrypt 对 bad_entry 抛出 ValueError（模拟解密失败），
        # full_analysis 会将 ValueError 包装为 EntryIntegrityError
        with patch.object(analyzer, '_decrypt', side_effect=ValueError("字段解密失败")):
            with pytest.raises(EntryIntegrityError, match='安全分析失败|数据可能已损坏'):
                analyzer.full_analysis(90)

    def test_all_entries_corrupt_raises_runtime_error(self):
        """所有条目都损坏时，分析抛出 EntryIntegrityError（兼容 RuntimeError）。"""
        vault = MagicMock()
        vault.key = b'\x00' * 32
        vault.is_unlocked = True

        corrupt_entry = Entry(
            id=1,
            crypto_id='corrupt_crypto',
            title='损坏',
            username='enc',
            password='enc_pass',
            custom_fields_enc='',
            password_strength=0,
        )

        vault.db.get_entries.return_value = [corrupt_entry]

        analyzer = SecurityAnalyzer(vault)

        with patch.object(analyzer, '_decrypt', side_effect=ValueError("解密失败")):
            with pytest.raises(EntryIntegrityError, match='安全分析失败|数据可能已损坏'):
                analyzer.full_analysis(90)

    def test_normal_analysis_returns_dict(self):
        """正常分析应返回包含预期键的 dict。"""
        vault = MagicMock()
        vault.key = b'\x00' * 32
        vault.is_unlocked = True

        vault.db.get_entries.return_value = []

        analyzer = SecurityAnalyzer(vault)
        result = analyzer.full_analysis(90)

        assert isinstance(result, dict)
        assert 'total' in result
        assert 'weak_count' in result
        assert 'weak_entries' in result
        assert 'duplicate_groups' in result
        assert 'old_entries' in result
        assert result['total'] == 0
        assert result['weak_count'] == 0
