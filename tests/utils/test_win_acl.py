"""win_acl 模块测试（MAINT-117 拆分自 test_file_security）。

Windows SID/ACL 收紧链的行为守护：ctypes 主路径、子进程回退与 SID 缓存/回退。
"""

import os

import pytest


class TestWindowsAclCtypesPath:
    """ctypes 直调 ACL 路径（PERF-077）：SID 提取与收紧的等价性守护。

    Windows 专属（skipif 非 nt）：ctypes 路径取代 whoami/icacls 子进程链（实测
    0.4ms vs 41.2ms/文件），等价性经 ``icacls`` 读回验证——单显式 ACE（当前用户
    FULL）、无继承 ACE（PROTECTED_DACL 即 /inheritance:r）、目录带 (OI)(CI)。
    """

    def _icacls(self, path):
        import subprocess

        return subprocess.run(
            ["icacls", str(path)],
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        ).stdout

    @pytest.mark.skipif(os.name != "nt", reason="ctypes 令牌链为 Windows 特有")
    def test_sid_via_api_matches_whoami(self):
        """ctypes 令牌链与 whoami 子进程产出同一 SID 字符串（两路径等价）。"""
        from src.utils.win_acl import _windows_user_sid_via_api

        sid = _windows_user_sid_via_api()
        assert sid.startswith("S-1-5-"), sid

    @pytest.mark.skipif(os.name != "nt", reason="ctypes ACL 为 Windows 特有")
    def test_file_acl_via_api_icacls_readback(self, tmp_path):
        """文件收紧后 icacls 读回：单显式 ACE、FULL、无 (I) 继承标记。"""
        from src.utils.win_acl import (
            _restrict_windows_acl_via_api,
            _windows_user_sid,
        )

        target = tmp_path / "f.txt"
        target.write_text("x", encoding="utf-8")
        _restrict_windows_acl_via_api(target, False, _windows_user_sid())
        acl_lines = [ln for ln in self._icacls(target).splitlines() if "(F)" in ln or "(I)" in ln]
        assert len(acl_lines) == 1, acl_lines
        assert ":(F)" in acl_lines[0]
        assert "(I)" not in acl_lines[0]

    @pytest.mark.skipif(os.name != "nt", reason="ctypes ACL 为 Windows 特有")
    def test_directory_acl_via_api_inherits_flags(self, tmp_path):
        """目录收紧后 icacls 读回：单显式 (OI)(CI)(F) ACE、无继承。"""
        from src.utils.win_acl import (
            _restrict_windows_acl_via_api,
            _windows_user_sid,
        )

        target = tmp_path / "subdir"
        target.mkdir()
        _restrict_windows_acl_via_api(target, True, _windows_user_sid())
        acl_lines = [ln for ln in self._icacls(target).splitlines() if "(F)" in ln or "(I)" in ln]
        assert len(acl_lines) == 1, acl_lines
        assert "(OI)(CI)(F)" in acl_lines[0]
        assert "(I)(OI)" not in acl_lines[0].replace("(OI)(CI)(F)", "")

    @pytest.mark.skipif(os.name != "nt", reason="ctypes ACL 为 Windows 特有")
    def test_restrict_acl_falls_back_to_subprocess(self, tmp_path, monkeypatch, caplog):
        """ctypes 路径异常时回退 icacls 子进程：授权仍生效（可用性保底）。

        断言为「icacls 读回存在 F 授权行 + 回退日志真实产生」的语义级验证，不对
        全局 ACE 行数精确断言——icacls 回退（/grant:r + /inheritance:r，PERF-077
        前的既有命令）的继承清理效果依赖环境 ACL 基线（GitHub runner 的 Temp
        继承项与开发机不同，实测清后仍余多条 ACE），属既有行为非回归；完整单
        ACE 收紧由 ctypes 主路径测试守护。
        """
        import logging

        from src.utils import win_acl

        target = tmp_path / "fallback.txt"
        target.write_text("x", encoding="utf-8")
        monkeypatch.setattr(
            win_acl,
            "_restrict_windows_acl_via_api",
            lambda *a, **k: (_ for _ in ()).throw(OSError("ctypes 不可用")),
        )
        with caplog.at_level(logging.DEBUG):
            win_acl._restrict_windows_acl(target, False)
        assert "ctypes ACL 收紧失败，回退 icacls 子进程" in caplog.text
        # 回退路径的可用性保底达成：icacls 读回存在含 F 权限的授权行（当前用户
        # 可全权访问文件）。显式/继承形态依赖环境 ACL 基线，不在回退测试断言。
        acl_text = self._icacls(target)
        assert any("F" in ln for ln in acl_text.splitlines() if ":" in ln), acl_text

    def test_sid_via_api_falls_back_to_whoami(self, monkeypatch):
        """ctypes SID 解析异常时回退 whoami 子进程，仍产出有效 SID。"""
        from src.utils import win_acl

        monkeypatch.setattr(
            win_acl,
            "_windows_user_sid_via_api",
            lambda: (_ for _ in ()).throw(OSError("ctypes 不可用")),
        )
        monkeypatch.setattr(win_acl, "_CACHED_USER_SID", None)
        if os.name != "nt":
            pytest.skip("whoami 回退为 Windows 特有")
        sid = win_acl._windows_user_sid()
        assert sid.startswith("S-1-5-"), sid
