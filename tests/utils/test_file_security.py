"""file_security 模块测试（MAINT-117 拆分后保留的核心域）。

覆盖文件与目录的权限加固（secure_file/secure_directory）、安全覆写删除
（secure_delete_file）、独占临时文件与原子写入（atomic_write）及多次调用的
幂等性，验证跨平台权限设置不抛异常且符合安全下限。Win32 SID/ACL 链的测试见
test_win_acl.py，路径安全校验的测试见 test_path_validation.py。
"""

import os
import stat
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
        """已存在的目录不应报错（重复调用幂等，记录断言补强 MAINT-111）。"""
        secure_directory(tmp_path)
        # 再次调用幂等：不抛异常且同样返回目标路径（重复调用返回契约成立）
        assert secure_directory(tmp_path) == tmp_path

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
        临时文件名带随机后缀（SEC-028），断言经 glob 覆盖任意后缀形态。
        """
        from src.utils.file_security import atomic_write

        target = tmp_path / "cancelled.json"
        result = atomic_write(target, lambda f: False, mode="wb")
        assert result is False
        assert not target.exists()
        # 任意随机后缀的 temp 均已清理，不残留
        assert not list(tmp_path.glob("cancelled.json.*.tmp"))


class TestAtomicWriteExclusiveTemp:
    """atomic_write 临时文件独占创建（SEC-028）：随机后缀 + O_EXCL 关闭符号链接竞态。

    固定名 ``<name>.tmp`` + 先 unlink 再 open 存在竞态窗口：多用户可写目录中攻击者
    抢先在可预测路径植入符号链接即可重定向写入目标。守护两条不变量：
    1. 临时文件名不可预测（随机后缀）；
    2. 已存在的临时路径绝不被覆写/跟随（O_EXCL），碰撞换名重试后完成原子替换。
    """

    def test_temp_name_has_random_suffix(self, tmp_path):
        """临时文件名含随机 hex 后缀：两次写入不产生相同临时名（不可预测性）。"""
        from src.utils.file_security import atomic_write

        target = tmp_path / "predictable.csv"
        seen = []

        def _capture_name(f):
            # write_cb 收到的已打开文件即临时文件，f.name 即其路径
            seen.append(Path(f.name).name)
            f.write(b"x")
            return True

        atomic_write(target, _capture_name, mode="wb")
        atomic_write(target, _capture_name, mode="wb")
        assert len(seen) == 2
        assert seen[0] != seen[1], "两次写入的临时文件名应不同（随机后缀）"
        for name in seen:
            # 形如 predictable.csv.<12位hex>.tmp
            assert name.startswith("predictable.csv.")
            assert name.endswith(".tmp")
            middle = name[len("predictable.csv.") : -len(".tmp")]
            assert len(middle) == 12 and all(c in "0123456789abcdef" for c in middle)

    def test_existing_temp_not_overwritten_and_retries(self, tmp_path, monkeypatch):
        """预占第一个随机名的路径：O_EXCL 拒绝覆写既有文件，换名重试后写入成功。

        模拟攻击者在「清理扫描 → open」间隙植入文件/符号链接（预占路径会被
        _purge_stale_temp_files 先行清理，故本用例禁用清理以隔离 O_EXCL/重试机制，
        清理行为另有用例守护）：既有文件内容保持原样（未被覆写），atomic_write
        仍经新随机名完成原子替换。
        """
        from src.utils import file_security
        from src.utils.file_security import atomic_write

        monkeypatch.setattr(file_security, "_purge_stale_temp_files", lambda _target: None)
        # 固定随机序列：第一个名字被预占，第二个名字可用
        rand_values = iter([b"\xaa" * 6, b"\xbb" * 6])
        monkeypatch.setattr(file_security.os, "urandom", lambda n: next(rand_values))
        predicted = tmp_path / f"data.json.{(b'\xaa' * 6).hex()}.tmp"
        predicted.write_bytes(b"sentinel-must-survive")

        target = tmp_path / "data.json"
        ok = atomic_write(target, lambda f: (f.write(b"payload"), True)[1], mode="wb")
        assert ok is True
        assert target.read_bytes() == b"payload"
        # 预占文件未被覆写（O_EXCL 生效）；重试的新随机名 temp 已被 replace 消费
        assert predicted.read_bytes() == b"sentinel-must-survive"
        assert not (tmp_path / f"data.json.{(b'\xbb' * 6).hex()}.tmp").exists()

    def test_open_file_restricted_refuses_existing_path(self, tmp_path):
        """opener 叠加 O_EXCL：对已存在路径打开直接 FileExistsError，不覆写。"""
        from src.utils.file_security import _open_file_restricted

        existing = tmp_path / "occupied.tmp"
        existing.write_bytes(b"keep")
        with pytest.raises(FileExistsError):
            open(existing, "wb", opener=_open_file_restricted)
        assert existing.read_bytes() == b"keep"

    def test_stale_legacy_temp_cleaned_on_write(self, tmp_path):
        """硬崩溃残留的旧版固定名 tmp 在下次写入时被清理（随机名的副作用补偿）。"""
        from src.utils.file_security import atomic_write

        target = tmp_path / "config.json"
        legacy = tmp_path / "config.json.tmp"
        legacy.write_bytes(b"stale-plaintext-leftover")
        unrelated = tmp_path / "config.json.old.tmp"  # 无关同名前缀文件，不得误删
        unrelated.write_bytes(b"keep-me")

        ok = atomic_write(target, lambda f: (f.write(b"new"), True)[1], mode="wb")
        assert ok is True
        assert not legacy.exists(), "旧版固定名残留应被清理"
        assert unrelated.exists(), "非 hex 后缀的同前缀文件不应被误删"

    def test_stale_random_temp_cleaned_on_write(self, tmp_path):
        """随机名形态的崩溃残留同样在下次写入时被清理。"""
        from src.utils.file_security import atomic_write

        target = tmp_path / "config.json"
        stale = tmp_path / "config.json.deadbeef1234.tmp"
        stale.write_bytes(b"stale")
        ok = atomic_write(target, lambda f: (f.write(b"new"), True)[1], mode="wb")
        assert ok is True
        assert not stale.exists()
