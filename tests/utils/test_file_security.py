"""file_security 模块测试。

覆盖文件与目录的权限加固、Windows ACL 限制、路径遍历防护，以及多次调用的
幂等性，验证跨平台权限设置不抛异常且符合安全下限。
"""

import os
import stat
import sys
from pathlib import Path

import pytest

from src.utils.file_security import secure_delete_file, secure_directory, secure_file


class TestSecureDeleteFile:
    """secure_delete_file 测试：随机覆写后 unlink，收缩明文取证还原面。"""

    def test_overwrites_then_deletes(self, tmp_path):
        target = tmp_path / "secret.cbox"
        target.write_bytes(b"super-secret-plaintext")
        secure_delete_file(target)
        assert not target.exists()

    def test_nonexistent_is_noop(self, tmp_path):
        """文件不存在时视为已删除，静默返回不抛异常，避免中断批量清理循环
        （恢复点/快照清理）；单文件缺失不计入失败清单或误报为清理失败。"""
        secure_delete_file(tmp_path / "missing.cbox")  # 不应抛异常

    def test_empty_file_deletes_without_overwrite(self, tmp_path):
        """size=0 时跳过覆写（无内容可覆写）仅 unlink。"""
        target = tmp_path / "empty.cbox"
        target.write_bytes(b"")
        secure_delete_file(target)
        assert not target.exists()

    def test_overwrite_replaces_content_before_unlink(self, tmp_path, monkeypatch):
        """覆写确实发生：覆写后、unlink 前内容应与原明文不同。

        通过 monkeypatch 让 unlink 失败（保留文件），读取覆写后的内容验证非原文。
        monkeypatch 自动还原 Path.unlink，避免 try/finally 在赋值与 try 间被中断（如
        SIGINT）污染全局 Path.unlink 影响后续所有测试。
        """
        target = tmp_path / "probe.cbox"
        original = b"A" * 64
        target.write_bytes(original)

        real_unlink = Path.unlink

        def _keep(self, *args, **kwargs):
            pass

        monkeypatch.setattr(Path, "unlink", _keep)
        secure_delete_file(target)
        overwritten = target.read_bytes()
        assert overwritten != original
        assert len(overwritten) == len(original)
        # 清理：Path.unlink 仍被 monkeypatch，用保存的真实引用删除探测文件
        real_unlink(target)

    def test_overwrite_failure_logs_plaintext_residue(self, tmp_path, monkeypatch, caplog):
        """覆写失败时记录明文残留告警、抛 OSError，且 unlink 仍执行释放目录占用。"""
        import logging

        target = tmp_path / "fragile.cbox"
        target.write_bytes(b"sensitive-plaintext")

        real_open = open

        def _fail_overwrite(path, *args, **kwargs):
            if args and args[0] == "r+b":
                raise OSError("disk full")
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr("builtins.open", _fail_overwrite)
        with caplog.at_level(logging.ERROR):
            with pytest.raises(OSError, match="disk full"):
                secure_delete_file(target)
        assert "明文残留" in caplog.text
        # finally 仍 unlink，避免半成品文件残留于目录被直接打开
        assert not target.exists()

    def test_secure_delete_file_symlink_preserves_target(self, tmp_path):
        """真实符号链接：仅删链接本身，目标文件内容与存在性保持（SEC-014）。

        回归守护：secure_purge 经 glob 匹配，若 secure_delete_file 跟随符号链接覆写，
        攻击者在备份目录植入的恶意链接会诱导 purge 随机覆写链接指向的任意目标文件。
        """
        target = tmp_path / "real.cbox"
        original = b"sensitive-plaintext-target"
        target.write_bytes(original)
        link = tmp_path / "pre_restore_evil.cbox"
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError):
            pytest.skip("当前环境不支持创建符号链接")
        secure_delete_file(link)
        assert not link.exists()  # 链接被删除
        assert target.exists()  # 目标文件仍在
        assert target.read_bytes() == original  # 目标内容未被覆写

    def test_secure_delete_file_skips_overwrite_when_reparse(self, tmp_path, monkeypatch):
        """叶子判定为符号链接/reparse 时仅 unlink，不触发覆写 open（SEC-014）。

        monkeypatch 模拟重定向判定，不依赖真实符号链接创建权限，本地任意平台即可
        验证分支：命中即走 unlink-only 路径，绝不 open(path, 'r+b') 覆写。
        """
        from src.utils import file_security

        target = tmp_path / "link_like.cbox"
        target.write_bytes(b"data")
        monkeypatch.setattr(file_security, "_path_is_symlink_or_reparse", lambda p: True)

        overwritten = {"yes": False}
        real_open = open

        def _detect_overwrite(path, *args, **kwargs):
            if args and args[0] == "r+b":
                overwritten["yes"] = True
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr("builtins.open", _detect_overwrite)
        secure_delete_file(target)
        assert not target.exists()  # 被当作链接 unlink
        assert overwritten["yes"] is False  # 未发生覆写


class TestSecureDirectory:
    """secure_directory 的目录创建、嵌套创建、幂等性与权限设置测试。"""

    def test_creates_directory(self, tmp_path):
        target = tmp_path / "new_dir"
        result = secure_directory(target)
        assert target.is_dir()
        assert result == target

    def test_creates_nested_directory(self, tmp_path):
        """parents=True 行为：中间目录不存在时连同祖先一并创建。"""
        target = tmp_path / "a" / "b" / "c"
        secure_directory(target)
        assert target.is_dir()

    def test_existing_directory_no_error(self, tmp_path):
        """已存在的目录不应报错。"""
        secure_directory(tmp_path)
        secure_directory(tmp_path)  # 再次调用不应抛异常

    def test_sets_unix_permissions(self, tmp_path):
        """非 Windows 下应设置 0o700 权限。"""
        target = tmp_path / "perm_dir"
        secure_directory(target)
        if os.name != "nt":
            mode = stat.S_IMODE(target.stat().st_mode)
            assert mode & 0o700 == 0o700
            assert not (mode & 0o077)  # 其他用户无权限

    def test_returns_path(self, tmp_path):
        target = tmp_path / "ret_dir"
        result = secure_directory(target)
        assert isinstance(result, Path)
        assert result == target

    def test_strict_propagates_chmod_failure(self, tmp_path, monkeypatch):
        """secure_directory(strict=True) 在 chmod 失败时传播 OSError（非 Windows）。

        config.get_data_dir 用 strict=False 降级，strict=True 分支无回归守护（覆盖缺口）。
        Windows 忽略 POSIX chmod，跳过。
        """
        if os.name == "nt":
            pytest.skip("Windows 忽略 POSIX chmod")

        def _raise(*args, **kwargs):
            raise OSError("denied")

        monkeypatch.setattr(os, "chmod", _raise)
        with pytest.raises(OSError):
            secure_directory(tmp_path / "strict_dir", strict=True)


class TestSecureFile:
    """secure_file 的权限设置、Windows ACL、幂等性与 strict 失败传播测试。"""

    def test_existing_file_sets_permissions(self, tmp_path):
        target = tmp_path / "test_file.dat"
        target.write_text("test", encoding="utf-8")
        result = secure_file(target)
        assert result == target
        if os.name != "nt":
            mode = stat.S_IMODE(target.stat().st_mode)
            assert mode & 0o600 == 0o600
            assert not (mode & 0o177)  # 其他用户无权限

    def test_nonexistent_file_returns_path(self, tmp_path):
        """文件不存在时仍返回路径、不创建文件（atomic_write 目标 pre-check 依赖此契约）。"""
        target = tmp_path / "nonexistent.dat"
        result = secure_file(target)
        assert result == target
        assert not target.exists()

    def test_returns_path_object(self, tmp_path):
        target = tmp_path / "file.txt"
        target.write_text("data", encoding="utf-8")
        result = secure_file(target)
        assert isinstance(result, Path)

    def test_windows_acl_no_error(self, tmp_path):
        """Windows 下调用 ACL 限制不应报错。"""
        target = tmp_path / "acl_test.txt"
        target.write_text("secret", encoding="utf-8")
        secure_file(target)
        assert target.exists()

    def test_secure_directory_windows_acl(self, tmp_path):
        """Windows 下目录 ACL 限制不应报错。"""
        target = tmp_path / "acl_dir"
        secure_directory(target)
        assert target.is_dir()

    def test_multiple_calls_idempotent(self, tmp_path):
        """多次调用同一文件不应报错。"""
        target = tmp_path / "multi.txt"
        target.write_text("test", encoding="utf-8")
        secure_file(target)
        secure_file(target)
        secure_file(target)
        assert target.read_text(encoding="utf-8") == "test"

    def test_strict_mode_propagates_permission_failure(self, tmp_path, monkeypatch):
        """secure_file(strict=True) 在权限加固失败时传播 OSError（与 secure_directory 的 strict 分支对称）。"""
        target = tmp_path / "strict.txt"
        target.write_text("secret", encoding="utf-8")

        def _fail(*_args, **_kwargs):
            raise OSError("permission denied")

        if os.name == "nt":
            monkeypatch.setattr("src.utils.file_security._restrict_windows_acl", _fail)
        else:
            monkeypatch.setattr("src.utils.file_security.os.chmod", _fail)

        with pytest.raises(OSError, match="permission denied"):
            secure_file(target, strict=True)


class TestValidateFilePath:
    """validate_file_path 测试。"""

    def test_normal_path(self, tmp_path):
        """正常路径应通过验证。"""
        test_file = tmp_path / "test.txt"
        test_file.write_text("hello")
        from src.utils.file_security import validate_file_path

        result = validate_file_path(str(test_file))
        assert isinstance(result, Path)

    def test_path_traversal_blocked(self, tmp_path):
        """包含 .. 的路径应被阻止。"""
        from src.utils.file_security import validate_file_path

        with pytest.raises(ValueError, match="非法遍历"):
            validate_file_path(str(tmp_path / ".." / ".." / "etc" / "passwd"))

    def test_resolved_path_returns_absolute(self, tmp_path):
        """返回值应为绝对路径。"""
        from src.utils.file_security import validate_file_path

        test_file = tmp_path / "subdir" / "file.dat"
        result = validate_file_path(str(test_file))
        assert result.is_absolute()


class TestValidateFilePathReparse:
    """validate_file_path 的符号链接 / reparse point 重定向检测（平台分支）。

    回归守护两条不变量：
    1. 检测须在 ``resolve()`` 之前对原始路径 ``lstat``，否则经由 symlink/junction
       的重定向在解析后路径上 ``is_symlink()`` 恒为 False，检测静默失效。
    2. Unix 仅检测叶子、Windows 逐级检测——逐级检测在 Unix 会误伤系统符号链接
       （macOS ``/var``→``/private/var``），曾致 macOS CI 全部备份/导入测试失败。
    """

    def test_symlink_target_rejected(self, tmp_path):
        """目标本身（叶子）为符号链接时拒绝访问（跨平台，主要 TOCTOU 防御）。"""
        from src.utils.file_security import validate_file_path

        target = tmp_path / "real.txt"
        target.write_text("data")
        link = tmp_path / "link.txt"
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError):
            pytest.skip("当前环境不支持创建符号链接")
        with pytest.raises(ValueError, match="符号链接"):
            validate_file_path(str(link))

    def test_symlink_ancestor_unix_allows_windows_rejects(self, tmp_path):
        """祖先符号链接：Unix 放行（系统符号链接 /var 等），Windows 拒绝（重定向威胁）。

        回归守护：macOS CI 临时目录位于 /var/folders（/var→/private/var 系统符号链接），
        若 Unix 逐级拒绝祖先符号链接，所有经临时目录的备份/导入测试将全部失败。
        """
        from src.utils.file_security import validate_file_path

        real_dir = tmp_path / "real_dir"
        real_dir.mkdir()
        (real_dir / "file.txt").write_text("data")
        link_dir = tmp_path / "link_dir"
        try:
            os.symlink(real_dir, link_dir)
        except (OSError, NotImplementedError):
            pytest.skip("当前环境不支持创建符号链接")
        target = str(link_dir / "file.txt")
        if os.name == "nt":
            with pytest.raises(ValueError, match="符号链接"):
                validate_file_path(target)
        else:
            # Unix：祖先 link_dir 虽为符号链接，但叶子 file.txt 是普通文件 → 放行
            result = validate_file_path(target)
            assert result.is_absolute()

    @pytest.mark.skipif(os.name != "nt", reason="junction 为 Windows 特有")
    def test_junction_ancestor_rejected(self, tmp_path):
        """Windows junction（reparse point）祖先应被拒绝。

        junction 非符号链接，``is_symlink()`` 不识别，须靠
        ``st_file_attributes & 0x400`` 检测。
        """
        import subprocess

        from src.utils.file_security import validate_file_path

        real_dir = tmp_path / "real_dir"
        real_dir.mkdir()
        junction = tmp_path / "junction_dir"
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(junction), str(real_dir)],
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode != 0:
            pytest.skip("当前环境无法创建 junction")
        (junction / "file.txt").write_text("data")
        with pytest.raises(ValueError, match="reparse point|符号链接"):
            validate_file_path(str(junction / "file.txt"))

    def test_nonexistent_target_passes_when_ancestors_clean(self, tmp_path):
        """待写入的新文件本身不存在、祖先均无重定向时应通过（导入/备份目标常见）。"""
        from src.utils.file_security import validate_file_path

        target = tmp_path / "sub" / "new_import.json"
        result = validate_file_path(str(target))
        assert result.is_absolute()


class TestRejectReparseBranches:
    """``_reject_reparse_points`` 平台分支单元测试（monkeypatch ``IS_WINDOWS``）。

    本地（任意平台）即可验证 Unix「仅叶子」与 Windows「逐级」两分支的正确性，
    弥补 macOS ``/var`` 回归在 Windows 本地无法复现的盲区——逐级检测在 Unix 会
    误伤系统符号链接（``/var``→``/private/var``），曾致 macOS CI 全部备份/导入
    测试失败。
    """

    def test_unix_branch_does_not_traverse_ancestors(self, tmp_path, monkeypatch):
        """Unix 分支仅 lstat 叶子一次，不遍历祖先（避免误伤 /var 等系统符号链接）。"""
        from src.utils import file_security

        monkeypatch.setattr(file_security, "IS_WINDOWS", False)
        call_count = {"n": 0}
        real_lstat = Path.lstat

        def counting_lstat(self):
            call_count["n"] += 1
            return real_lstat(self)

        monkeypatch.setattr(Path, "lstat", counting_lstat)
        target = tmp_path / "sub" / "deep" / "file.txt"
        target.parent.mkdir(parents=True)
        target.write_text("x")
        file_security._reject_reparse_points(target)
        assert call_count["n"] == 1, "Unix 分支应仅 lstat 叶子，不遍历祖先"

    def test_unix_branch_rejects_leaf_symlink(self, tmp_path, monkeypatch):
        """Unix 分支：叶子 lstat 为符号链接时拒绝（主要 TOCTOU 防御保留）。"""
        from src.utils import file_security

        monkeypatch.setattr(file_security, "IS_WINDOWS", False)

        class _FakeStat:
            """模拟符号链接 st_mode 的 lstat 返回值桩。"""

            st_mode = stat.S_IFLNK

        target = tmp_path / "evil.txt"
        target.write_text("x")
        monkeypatch.setattr(Path, "lstat", lambda self: _FakeStat())
        with pytest.raises(ValueError, match="符号链接"):
            file_security._reject_reparse_points(target)

    def test_windows_branch_traverses_ancestors(self, tmp_path, monkeypatch):
        """Windows 分支逐级 lstat 整条路径（junction 重定向威胁需逐级检测）。"""
        from src.utils import file_security

        monkeypatch.setattr(file_security, "IS_WINDOWS", True)
        call_count = {"n": 0}
        real_lstat = Path.lstat

        def counting_lstat(self):
            call_count["n"] += 1
            return real_lstat(self)

        monkeypatch.setattr(Path, "lstat", counting_lstat)
        target = tmp_path / "sub" / "deep" / "file.txt"
        target.parent.mkdir(parents=True)
        target.write_text("x")
        file_security._reject_reparse_points(target)
        assert call_count["n"] > 1, "Windows 分支应逐级 lstat 祖先"


class TestValidateFilePathStrictAncestors:
    """``validate_file_path(check_ancestors=True)`` 祖先符号链接检测（S3）。

    默认 ``check_ancestors=False`` 保持 Unix 仅检测叶子（避开 macOS /var 误伤）；
    高敏感用户路径（backup_directory）显式 opt-in 后，Unix 逐级 lstat 祖先并拒绝
    非系统规范的符号链接，收缩「替换祖先为 symlink 重定向含明文写入」的威胁。
    """

    def test_strict_rejects_symlink_ancestor(self, tmp_path):
        """check_ancestors=True：非系统规范符号链接祖先应被拒绝（跨平台）。"""
        from src.utils.file_security import validate_file_path

        real_dir = tmp_path / "real_dir"
        real_dir.mkdir()
        (real_dir / "file.txt").write_text("data")
        link_dir = tmp_path / "link_dir"
        try:
            os.symlink(real_dir, link_dir)
        except (OSError, NotImplementedError):
            pytest.skip("当前环境不支持创建符号链接")
        # link_dir 是深层（非顶层 /private 规范）符号链接祖先 → 拒绝
        with pytest.raises(ValueError, match="符号链接"):
            validate_file_path(str(link_dir / "file.txt"), check_ancestors=True)

    def test_default_still_allows_symlink_ancestor_unix(self, tmp_path):
        """check_ancestors 默认 False：Unix 仍放行祖先符号链接（回归守护）。"""
        from src.utils.file_security import validate_file_path

        real_dir = tmp_path / "real_dir"
        real_dir.mkdir()
        (real_dir / "file.txt").write_text("data")
        link_dir = tmp_path / "link_dir"
        try:
            os.symlink(real_dir, link_dir)
        except (OSError, NotImplementedError):
            pytest.skip("当前环境不支持创建符号链接")
        if os.name == "nt":
            with pytest.raises(ValueError):
                validate_file_path(str(link_dir / "file.txt"))
        else:
            result = validate_file_path(str(link_dir / "file.txt"))
            assert result.is_absolute()

    def test_canonical_system_link_only_darwin_toplevel(self):
        """_is_canonical_system_link：仅 darwin 顶层 /x→/private/x 视为系统规范。"""
        from src.utils import file_security

        if sys.platform != "darwin":
            # 非 darwin：任何符号链接祖先即可疑（Linux 系统目录非符号链接）
            assert file_security._is_canonical_system_link(Path("/var")) is False
        else:
            # darwin：/var→/private/var、/tmp→/private/tmp 为系统规范链接（放行）
            assert file_security._is_canonical_system_link(Path("/var")) is True
            assert file_security._is_canonical_system_link(Path("/tmp")) is True
            # 深层路径不视作顶层系统规范链接（即便其存在）
            assert file_security._is_canonical_system_link(Path("/var/folders")) is False

    def test_strict_allows_macos_temp_path(self, tmp_path):
        """check_ancestors=True 经系统临时目录的合法路径不误伤（macOS /var 回归守护）。

        非 darwin 平台 tmp_path 无系统符号链接祖先，本测试平凡通过；macOS 上
        tmp_path 位于 /var/folders（/var→/private/var），验证系统规范链接被放行。
        """
        from src.utils.file_security import validate_file_path

        target = tmp_path / "sub" / "snapshot.cbox"
        target.parent.mkdir(parents=True)
        result = validate_file_path(str(target), check_ancestors=True)
        assert result.is_absolute()


class TestAtomicWritePermissions:
    """atomic_write 临时文件落地即 0600，消除明文临时文件世界可读窗口（SEC-015）。"""

    def test_open_file_restricted_creates_0600(self, tmp_path):
        """_open_file_restricted opener 以 0600 创建文件（Unix 验证 mode 位）。"""
        import stat as stat_mod

        from src.utils.file_security import _open_file_restricted

        path = tmp_path / "created.bin"
        fd = _open_file_restricted(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
        os.close(fd)
        if os.name == "nt":
            return  # Windows 忽略 POSIX mode 位，靠继承父目录 ACL
        mode = stat_mod.S_IMODE(path.stat().st_mode)
        assert mode == 0o600

    def test_atomic_write_uses_restricted_opener(self, tmp_path, monkeypatch):
        """atomic_write 把 _open_file_restricted 作为 opener 传给 open（SEC-015）。"""
        from src.utils import file_security
        from src.utils.file_security import atomic_write

        captured = {}
        real_open = open

        def _spy(file, mode="r", *args, **kwargs):
            captured["opener"] = kwargs.get("opener")
            return real_open(file, mode, *args, **kwargs)

        monkeypatch.setattr("builtins.open", _spy)
        target = tmp_path / "export.json"
        atomic_write(target, lambda f: (f.write(b"x"), True)[1], mode="wb")
        assert captured["opener"] is file_security._open_file_restricted

    def test_atomic_write_roundtrip_restricted(self, tmp_path):
        """atomic_write 完整写入后目标文件 0600 且内容正确（SEC-015 端到端）。"""
        import stat as stat_mod

        from src.utils.file_security import atomic_write

        target = tmp_path / "roundtrip.json"
        payload = b'{"secret":"value"}'
        ok = atomic_write(target, lambda f: (f.write(payload), True)[1], mode="wb")
        assert ok
        assert target.read_bytes() == payload
        if os.name == "nt":
            return
        mode = stat_mod.S_IMODE(target.stat().st_mode)
        assert mode == 0o600

    def test_atomic_write_cancel_returns_false_and_cleans_temp(self, tmp_path):
        """write_cb 返回 False 取消写入：返回 False、target 未创建、temp 已清理。

        import_export 取消导出经 atomic_write 返回值透传，该路径需守护（覆盖缺口）。
        """
        from src.utils.file_security import atomic_write

        target = tmp_path / "cancelled.json"
        result = atomic_write(target, lambda f: False, mode="wb")
        assert result is False
        assert not target.exists()
        # temp（target.name + .tmp）已清理，不残留
        assert not (tmp_path / "cancelled.json.tmp").exists()
