"""file_security 模块测试。

覆盖文件与目录的权限加固、Windows ACL 限制、路径遍历防护，以及多次调用的
幂等性，验证跨平台权限设置不抛异常且符合安全下限。
"""

import os
import stat
from pathlib import Path

import pytest

from src.utils.file_security import secure_delete_file, secure_directory, secure_file


class TestSecureDeleteFile:
    """secure_delete_file 测试：随机覆写后 unlink，收缩明文取证还原面。"""

    def test_overwrites_then_deletes(self, tmp_path):
        target = tmp_path / 'secret.cbox'
        target.write_bytes(b'super-secret-plaintext')
        secure_delete_file(target)
        assert not target.exists()

    def test_nonexistent_is_noop(self, tmp_path):
        """文件不存在时视为已删除，静默返回不抛异常，避免中断批量清理循环
        （恢复点/快照清理）；单文件缺失不计入失败清单或误报为清理失败。"""
        secure_delete_file(tmp_path / 'missing.cbox')  # 不应抛异常

    def test_empty_file_deletes_without_overwrite(self, tmp_path):
        """size=0 时跳过覆写（无内容可覆写）仅 unlink。"""
        target = tmp_path / 'empty.cbox'
        target.write_bytes(b'')
        secure_delete_file(target)
        assert not target.exists()

    def test_overwrite_replaces_content_before_unlink(self, tmp_path):
        """覆写确实发生：覆写后、unlink 前内容应与原明文不同。

        通过 monkeypatch 让 unlink 失败（保留文件），读取覆写后的内容验证非原文。
        """
        target = tmp_path / 'probe.cbox'
        original = b'A' * 64
        target.write_bytes(original)

        real_unlink = Path.unlink

        def _keep(self, *args, **kwargs):
            pass

        Path.unlink = _keep  # type: ignore[method-assign]
        try:
            secure_delete_file(target)
            overwritten = target.read_bytes()
        finally:
            Path.unlink = real_unlink  # type: ignore[method-assign]
        assert overwritten != original
        assert len(overwritten) == len(original)
        # 清理：用真实 unlink 删除探测文件
        real_unlink(target)

    def test_overwrite_failure_logs_plaintext_residue(self, tmp_path, monkeypatch, caplog):
        """覆写失败时记录明文残留告警、抛 OSError，且 unlink 仍执行释放目录占用。"""
        import logging
        target = tmp_path / 'fragile.cbox'
        target.write_bytes(b'sensitive-plaintext')

        real_open = open

        def _fail_overwrite(path, *args, **kwargs):
            if args and args[0] == 'r+b':
                raise OSError('disk full')
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr('builtins.open', _fail_overwrite)
        with caplog.at_level(logging.ERROR):
            with pytest.raises(OSError, match='disk full'):
                secure_delete_file(target)
        assert '明文残留' in caplog.text
        # finally 仍 unlink，避免半成品文件残留于目录被直接打开
        assert not target.exists()


class TestSecureDirectory:
    """secure_directory 测试。"""

    def test_creates_directory(self, tmp_path):
        target = tmp_path / 'new_dir'
        result = secure_directory(target)
        assert target.is_dir()
        assert result == target

    def test_creates_nested_directory(self, tmp_path):
        target = tmp_path / 'a' / 'b' / 'c'
        secure_directory(target)
        assert target.is_dir()

    def test_existing_directory_no_error(self, tmp_path):
        """已存在的目录不应报错。"""
        secure_directory(tmp_path)
        secure_directory(tmp_path)  # 再次调用不应抛异常

    def test_sets_unix_permissions(self, tmp_path):
        """非 Windows 下应设置 0o700 权限。"""
        target = tmp_path / 'perm_dir'
        secure_directory(target)
        if os.name != 'nt':
            mode = stat.S_IMODE(target.stat().st_mode)
            assert mode & 0o700 == 0o700
            assert not (mode & 0o077)  # 其他用户无权限

    def test_returns_path(self, tmp_path):
        target = tmp_path / 'ret_dir'
        result = secure_directory(target)
        assert isinstance(result, Path)
        assert result == target


class TestSecureFile:
    """secure_file 测试。"""

    def test_existing_file_sets_permissions(self, tmp_path):
        target = tmp_path / 'test_file.dat'
        target.write_text('test', encoding='utf-8')
        result = secure_file(target)
        assert result == target
        if os.name != 'nt':
            mode = stat.S_IMODE(target.stat().st_mode)
            assert mode & 0o600 == 0o600
            assert not (mode & 0o177)  # 其他用户无权限

    def test_nonexistent_file_returns_path(self, tmp_path):
        target = tmp_path / 'nonexistent.dat'
        result = secure_file(target)
        assert result == target
        assert not target.exists()

    def test_returns_path_object(self, tmp_path):
        target = tmp_path / 'file.txt'
        target.write_text('data', encoding='utf-8')
        result = secure_file(target)
        assert isinstance(result, Path)

    def test_windows_acl_no_error(self, tmp_path):
        """Windows 下调用 ACL 限制不应报错。"""
        target = tmp_path / 'acl_test.txt'
        target.write_text('secret', encoding='utf-8')
        # 不应抛出异常
        secure_file(target)
        assert target.exists()

    def test_secure_directory_windows_acl(self, tmp_path):
        """Windows 下目录 ACL 限制不应报错。"""
        target = tmp_path / 'acl_dir'
        secure_directory(target)
        assert target.is_dir()

    def test_multiple_calls_idempotent(self, tmp_path):
        """多次调用同一文件不应报错。"""
        target = tmp_path / 'multi.txt'
        target.write_text('test', encoding='utf-8')
        secure_file(target)
        secure_file(target)
        secure_file(target)
        assert target.read_text(encoding='utf-8') == 'test'

    def test_strict_mode_propagates_permission_failure(self, tmp_path, monkeypatch):
        target = tmp_path / 'strict.txt'
        target.write_text('secret', encoding='utf-8')

        def _fail(*_args, **_kwargs):
            raise OSError('permission denied')

        if os.name == 'nt':
            monkeypatch.setattr(
                'src.utils.file_security._restrict_windows_acl', _fail
            )
        else:
            monkeypatch.setattr('src.utils.file_security.os.chmod', _fail)

        with pytest.raises(OSError, match='permission denied'):
            secure_file(target, strict=True)


class TestValidateFilePath:
    """validate_file_path 测试。"""

    def test_normal_path(self, tmp_path):
        """正常路径应通过验证。"""
        test_file = tmp_path / "test.txt"
        test_file.write_text("hello")
        # validate_file_path 对正常路径不应抛异常
        from src.utils.file_security import validate_file_path
        result = validate_file_path(str(test_file))
        assert isinstance(result, Path)

    def test_path_traversal_blocked(self, tmp_path):
        """包含 .. 的路径应被阻止。"""
        from src.utils.file_security import validate_file_path
        with pytest.raises(ValueError, match='非法遍历'):
            validate_file_path(str(tmp_path / ".." / ".." / "etc" / "passwd"))

    def test_resolved_path_returns_absolute(self, tmp_path):
        """返回值应为绝对路径。"""
        from src.utils.file_security import validate_file_path
        test_file = tmp_path / "subdir" / "file.dat"
        result = validate_file_path(str(test_file))
        assert result.is_absolute()
