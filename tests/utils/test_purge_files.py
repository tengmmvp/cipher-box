"""purge_files 模块测试 — 批量安全删除与计数工具。

覆盖 secure_purge 的全删/保留最新 N/失败收集 vs 仅日志/多目录多模式/目录不存在/
无匹配，以及 count_files 的计数与缺失目录返回 0。底层复用 secure_delete_file，
故这里既测真实删除（tmp_path 文件），也测失败收集（monkeypatch 抛 OSError）。
"""

from pathlib import Path

from src.utils import purge_files
from src.utils.purge_files import count_files, secure_purge


def _touch(directory: Path, name: str) -> Path:
    """在 directory 下创建名为 name 的空文件，返回其 Path。"""
    p = directory / name
    p.write_bytes(b'x')
    return p


class TestSecurePurge:
    """secure_purge 各场景。"""

    def test_delete_all(self, tmp_path):
        """keep=None 全删，目录被清空。"""
        f1 = _touch(tmp_path, 'a.cbox')
        f2 = _touch(tmp_path, 'b.cbox')
        failed = secure_purge([tmp_path], ['*.cbox'])
        assert failed == []
        assert not f1.exists()
        assert not f2.exists()

    def test_keep_n_preserves_newest_by_name_desc(self, tmp_path):
        """keep=N 按文件名降序保留最新 N 个，删除其余。"""
        for name in ['snap_001.cbox', 'snap_002.cbox', 'snap_003.cbox', 'snap_004.cbox']:
            _touch(tmp_path, name)
        failed = secure_purge([tmp_path], ['snap_*.cbox'], keep=2)
        assert failed == []
        # 降序：snap_004, snap_003 保留；snap_002, snap_001 删除
        assert (tmp_path / 'snap_004.cbox').exists()
        assert (tmp_path / 'snap_003.cbox').exists()
        assert not (tmp_path / 'snap_002.cbox').exists()
        assert not (tmp_path / 'snap_001.cbox').exists()

    def test_keep_zero_deletes_all(self, tmp_path):
        """keep=0 等价全删。"""
        files = [_touch(tmp_path, f'f{i}.cbox') for i in range(3)]
        secure_purge([tmp_path], ['f*.cbox'], keep=0)
        assert all(not f.exists() for f in files)

    def test_collect_failures_true(self, tmp_path, monkeypatch):
        """collect_failures=True 时 OSError 失败文件收集到返回列表。"""
        _touch(tmp_path, 'fail.cbox')
        _touch(tmp_path, 'ok.cbox')

        def raise_oserror(path):
            if path.name == 'fail.cbox':
                raise OSError('boom')
            # ok.cbox 走真实删除路径

        # 仅对 fail.cbox 模拟失败，ok.cbox 让真实实现处理
        original = purge_files.secure_delete_file

        def fake(path):
            if path.name == 'fail.cbox':
                raise OSError('boom')
            return original(path)

        monkeypatch.setattr(purge_files, 'secure_delete_file', fake)
        failed = secure_purge([tmp_path], ['*.cbox'], collect_failures=True)
        assert any(p.name == 'fail.cbox' for p in failed)
        # ok.cbox 已真实删除
        assert not (tmp_path / 'ok.cbox').exists()
        # fail.cbox 仍存在
        assert (tmp_path / 'fail.cbox').exists()

    def test_collect_failures_false_returns_empty(self, tmp_path, monkeypatch):
        """collect_failures=False 时失败仅记日志，返回空列表。"""
        _touch(tmp_path, 'fail.cbox')

        def fake(path):
            raise OSError('boom')

        monkeypatch.setattr(purge_files, 'secure_delete_file', fake)
        failed = secure_purge([tmp_path], ['*.cbox'], collect_failures=False)
        assert failed == []
        assert (tmp_path / 'fail.cbox').exists()  # 未删除

    def test_multiple_directories_and_patterns(self, tmp_path):
        """多目录 × 多模式分别匹配并删除。"""
        d1 = tmp_path / 'd1'
        d2 = tmp_path / 'd2'
        d1.mkdir()
        d2.mkdir()
        a = _touch(d1, 'pre_restore_a.cbox')
        b = _touch(d1, 'cipherbox_snapshot_b.cbox')
        c = _touch(d2, 'pre_restore_c.cbox')
        d = _touch(d2, 'unmatched.txt')
        failed = secure_purge(
            [d1, d2], ['pre_restore_*.cbox', 'cipherbox_snapshot_*.cbox'],
        )
        assert failed == []
        assert not a.exists() and not b.exists() and not c.exists()
        assert d.exists()  # 不匹配任何模式，保留

    def test_nonexistent_directory_skipped(self, tmp_path):
        """不存在的目录应静默跳过，返回空列表。"""
        missing = tmp_path / 'does-not-exist'
        failed = secure_purge([missing], ['*.cbox'])
        assert failed == []

    def test_no_match_returns_empty(self, tmp_path):
        """glob 无匹配应返回空。"""
        _touch(tmp_path, 'unrelated.txt')
        failed = secure_purge([tmp_path], ['*.cbox'])
        assert failed == []

    def test_keep_more_than_available(self, tmp_path):
        """keep 大于实际文件数时全部保留，删除空集。"""
        for name in ['x1.cbox', 'x2.cbox']:
            _touch(tmp_path, name)
        failed = secure_purge([tmp_path], ['x*.cbox'], keep=10)
        assert failed == []
        assert (tmp_path / 'x1.cbox').exists()
        assert (tmp_path / 'x2.cbox').exists()


class TestCountFiles:
    """count_files 计数。"""

    def test_counts_matches(self, tmp_path):
        d1 = tmp_path / 'd1'
        d1.mkdir()
        for name in ['a.cbox', 'b.cbox', 'c.txt']:
            _touch(d1, name)
        assert count_files([d1], ['*.cbox']) == 2
        assert count_files([d1], ['*.txt']) == 1
        assert count_files([d1], ['*.cbox', '*.txt']) == 3

    def test_multiple_directories(self, tmp_path):
        d1 = tmp_path / 'd1'
        d2 = tmp_path / 'd2'
        d1.mkdir()
        d2.mkdir()
        _touch(d1, 'a.cbox')
        _touch(d2, 'b.cbox')
        _touch(d2, 'c.cbox')
        assert count_files([d1, d2], ['*.cbox']) == 3

    def test_nonexistent_directory_returns_zero(self, tmp_path):
        assert count_files([tmp_path / 'missing'], ['*.cbox']) == 0

    def test_no_match_returns_zero(self, tmp_path):
        _touch(tmp_path, 'a.txt')
        assert count_files([tmp_path], ['*.cbox']) == 0


class TestKeepSemantics:
    """keep 保留语义在多目录/多模式下各自独立。"""

    def test_keep_applies_per_directory_pattern_combo(self, tmp_path):
        """keep=N 对每个 (directory, pattern) 组合独立生效。"""
        d1 = tmp_path / 'd1'
        d1.mkdir()
        d2 = tmp_path / 'd2'
        d2.mkdir()
        for name in ['p_1.cbox', 'p_2.cbox', 'p_3.cbox']:
            _touch(d1, name)
            _touch(d2, name)
        failed = secure_purge([d1, d2], ['p_*.cbox'], keep=1)
        assert failed == []
        # 每目录保留最新的 p_3.cbox
        assert (d1 / 'p_3.cbox').exists()
        assert (d2 / 'p_3.cbox').exists()
        assert not (d1 / 'p_1.cbox').exists()
        assert not (d2 / 'p_2.cbox').exists()
