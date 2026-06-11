"""file_security 模块测试 — 文件/目录权限控制"""

import os
import stat
from pathlib import Path

import pytest

from src.utils.file_security import secure_directory, secure_file


class TestSecureDirectory:
    """secure_directory 测试"""

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
        """已存在的目录不应报错"""
        secure_directory(tmp_path)
        secure_directory(tmp_path)  # 再次调用不应抛异常

    def test_sets_unix_permissions(self, tmp_path):
        """非 Windows 下应设置 0o700 权限"""
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
    """secure_file 测试"""

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
        """Windows 下调用 ACL 限制不应报错"""
        target = tmp_path / 'acl_test.txt'
        target.write_text('secret', encoding='utf-8')
        # 不应抛出异常
        secure_file(target)
        assert target.exists()

    def test_secure_directory_windows_acl(self, tmp_path):
        """Windows 下目录 ACL 限制不应报错"""
        target = tmp_path / 'acl_dir'
        secure_directory(target)
        assert target.is_dir()

    def test_multiple_calls_idempotent(self, tmp_path):
        """多次调用同一文件不应报错"""
        target = tmp_path / 'multi.txt'
        target.write_text('test', encoding='utf-8')
        secure_file(target)
        secure_file(target)
        secure_file(target)
        assert target.read_text(encoding='utf-8') == 'test'


class TestValidateFilePath:
    """validate_file_path 测试"""

    def test_normal_path(self, tmp_path):
        """正常路径应通过验证"""
        test_file = tmp_path / "test.txt"
        test_file.write_text("hello")
        # validate_file_path 对正常路径不应抛异常
        from src.utils.file_security import validate_file_path
        result = validate_file_path(str(test_file))
        assert isinstance(result, Path)

    def test_path_traversal_blocked(self, tmp_path):
        """包含 .. 的路径应被阻止"""
        from src.utils.file_security import validate_file_path
        with pytest.raises(ValueError, match='非法遍历'):
            validate_file_path(str(tmp_path / ".." / ".." / "etc" / "passwd"))

    def test_resolved_path_returns_absolute(self, tmp_path):
        """返回值应为绝对路径"""
        from src.utils.file_security import validate_file_path
        test_file = tmp_path / "subdir" / "file.dat"
        result = validate_file_path(str(test_file))
        assert result.is_absolute()
