"""path_validation 模块测试（MAINT-117 拆分自 test_file_security）。

覆盖 validate_file_path 的目录遍历/符号链接/reparse 重定向拒绝（平台分支）、
Windows 保留设备名与 ADS 冒号、``\\\\?\\`` verbatim 设备形态拒绝与合法形态放行，
验证中央路径安全边界的行为不变。
"""

import os
import stat
import sys
from pathlib import Path

import pytest


class TestValidateFilePath:
    """validate_file_path 测试。"""

    def test_normal_path(self, tmp_path):
        """正常路径应通过验证。"""
        test_file = tmp_path / "test.txt"
        test_file.write_text("hello")
        from src.utils.path_validation import validate_file_path

        result = validate_file_path(str(test_file))
        assert isinstance(result, Path)

    def test_path_traversal_blocked(self, tmp_path):
        """包含 .. 的路径应被阻止。"""
        from src.utils.path_validation import validate_file_path

        with pytest.raises(ValueError, match="非法遍历"):
            validate_file_path(str(tmp_path / ".." / ".." / "etc" / "passwd"))

    def test_resolved_path_returns_absolute(self, tmp_path):
        """返回值应为绝对路径。"""
        from src.utils.path_validation import validate_file_path

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
        from src.utils.path_validation import validate_file_path

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
        from src.utils.path_validation import validate_file_path

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

        from src.utils.path_validation import validate_file_path

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
        from src.utils.path_validation import validate_file_path

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
        from src.utils import path_validation

        monkeypatch.setattr(path_validation, "IS_WINDOWS", False)
        call_count = {"n": 0}
        real_lstat = Path.lstat

        def counting_lstat(self):
            call_count["n"] += 1
            return real_lstat(self)

        monkeypatch.setattr(Path, "lstat", counting_lstat)
        target = tmp_path / "sub" / "deep" / "file.txt"
        target.parent.mkdir(parents=True)
        target.write_text("x")
        path_validation._reject_reparse_points(target)
        assert call_count["n"] == 1, "Unix 分支应仅 lstat 叶子，不遍历祖先"

    def test_unix_branch_rejects_leaf_symlink(self, tmp_path, monkeypatch):
        """Unix 分支：叶子 lstat 为符号链接时拒绝（主要 TOCTOU 防御保留）。"""
        from src.utils import path_validation

        monkeypatch.setattr(path_validation, "IS_WINDOWS", False)

        class _FakeStat:
            """模拟符号链接 st_mode 的 lstat 返回值桩。"""

            st_mode = stat.S_IFLNK

        target = tmp_path / "evil.txt"
        target.write_text("x")
        monkeypatch.setattr(Path, "lstat", lambda self: _FakeStat())
        with pytest.raises(ValueError, match="符号链接"):
            path_validation._reject_reparse_points(target)

    def test_windows_branch_traverses_ancestors(self, tmp_path, monkeypatch):
        """Windows 分支逐级 lstat 整条路径（junction 重定向威胁需逐级检测）。"""
        from src.utils import path_validation

        monkeypatch.setattr(path_validation, "IS_WINDOWS", True)
        call_count = {"n": 0}
        real_lstat = Path.lstat

        def counting_lstat(self):
            call_count["n"] += 1
            return real_lstat(self)

        monkeypatch.setattr(Path, "lstat", counting_lstat)
        target = tmp_path / "sub" / "deep" / "file.txt"
        target.parent.mkdir(parents=True)
        target.write_text("x")
        path_validation._reject_reparse_points(target)
        assert call_count["n"] > 1, "Windows 分支应逐级 lstat 祖先"


class TestValidateFilePathStrictAncestors:
    """``validate_file_path(check_ancestors=True)`` 祖先符号链接检测（S3）。

    默认 ``check_ancestors=False`` 保持 Unix 仅检测叶子（避开 macOS /var 误伤）；
    高敏感用户路径（backup_directory）显式 opt-in 后，Unix 逐级 lstat 祖先并拒绝
    非系统规范的符号链接，收缩「替换祖先为 symlink 重定向含明文写入」的威胁。
    """

    def test_strict_rejects_symlink_ancestor(self, tmp_path):
        """check_ancestors=True：非系统规范符号链接祖先应被拒绝（跨平台）。"""
        from src.utils.path_validation import validate_file_path

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
        from src.utils.path_validation import validate_file_path

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
        from src.utils import path_validation

        if sys.platform != "darwin":
            # 非 darwin：任何符号链接祖先即可疑（Linux 系统目录非符号链接）
            assert path_validation._is_canonical_system_link(Path("/var")) is False
        else:
            # darwin：/var→/private/var、/tmp→/private/tmp 为系统规范链接（放行）
            assert path_validation._is_canonical_system_link(Path("/var")) is True
            assert path_validation._is_canonical_system_link(Path("/tmp")) is True
            # 深层路径不视作顶层系统规范链接（即便其存在）
            assert path_validation._is_canonical_system_link(Path("/var/folders")) is False

    def test_strict_allows_macos_temp_path(self, tmp_path):
        """check_ancestors=True 经系统临时目录的合法路径不误伤（macOS /var 回归守护）。

        非 darwin 平台 tmp_path 无系统符号链接祖先，本测试平凡通过；macOS 上
        tmp_path 位于 /var/folders（/var→/private/var），验证系统规范链接被放行。
        """
        from src.utils.path_validation import validate_file_path

        target = tmp_path / "sub" / "snapshot.cbox"
        target.parent.mkdir(parents=True)
        result = validate_file_path(str(target), check_ancestors=True)
        assert result.is_absolute()


class TestValidateFilePathWindowsReservedNames:
    """Windows 保留设备名与 NTFS 备用数据流（ADS）冒号拒绝（SEC-061）。

    当前所有到达路径为程序生成或用户经文件对话框自选（不可利用），但
    validate_file_path 是中央路径安全边界——「按条目名命名导出文件」类未来功能
    会经此缺口把条目数据变成设备名/数据流路径。字符串级分析使任意平台经
    monkeypatch ``IS_WINDOWS`` 即可验证 Windows 语义（参照 TestRejectReparseBranches）。
    """

    @pytest.mark.parametrize(
        "name",
        [
            "CON",
            "con",
            "CON.txt",
            "NUL.bin",
            "COM1",
            "com9.log",
            "LPT1",
            "aux.dat",
            "CON .txt",  # 尾随空格在 Windows 设备名判定中被忽略
            "NUL.",  # 尾随点同上
            "prn",  # 纯小写裸设备名
        ],
        ids=[
            "CON",
            "lower",
            "with-ext",
            "NUL-ext",
            "COM1",
            "com9",
            "LPT1",
            "aux",
            "trailing-space",
            "trailing-dot",
            "bare-lower",
        ],
    )
    def test_reserved_device_name_rejected(self, name):
        """任一路径组件的 stem 命中保留设备名（含带扩展名/大小写/尾随空格点形态）即拒绝。"""
        from src.utils import path_validation

        with pytest.raises(ValueError, match="保留设备名"):
            path_validation._reject_windows_device_names_and_ads(rf"C:\data\{name}")

    def test_reserved_name_in_intermediate_component_rejected(self):
        """保留名出现在中间目录组件同样拒绝（C:\\data\\CON\\file.txt）。"""
        from src.utils import path_validation

        with pytest.raises(ValueError, match="保留设备名"):
            path_validation._reject_windows_device_names_and_ads(r"C:\data\CON\file.txt")

    @pytest.mark.parametrize(
        "path",
        [
            r"C:\data\file.txt:hidden",
            r"C:\data\file.txt:$DATA",
            r"relative:stream",
            r"C:\data\sub\file:ads",
        ],
        ids=["ads", "ads-named-stream", "relative", "nested"],
    )
    def test_ads_colon_rejected(self, path):
        """盘符首个冒号之外的冒号（NTFS 备用数据流语法）即拒绝。"""
        from src.utils import path_validation

        with pytest.raises(ValueError, match="非法冒号"):
            path_validation._reject_windows_device_names_and_ads(path)

    @pytest.mark.parametrize(
        "path",
        [
            r"\\.\PhysicalDrive0",  # 物理磁盘设备（写即裸写整盘）
            r"\\.\Serial0",  # 串口设备对象
            r"\\.\C:",  # 裸卷设备本体（无后续路径组件）
            r"\\.\CdRom0",  # 光驱设备对象
            r"\\.\CON",  # 经设备命名空间寻址的保留设备名
        ],
        ids=["physical-drive", "serial", "bare-volume", "cdrom", "reserved-via-device"],
    )
    def test_device_namespace_object_rejected(self, path):
        """``\\\\.\\`` 设备命名空间下非「盘符+路径」形态即拒绝（SEC-061 补强）。

        该前缀直接寻址 Win32 设备对象：``\\\\.\\PhysicalDrive0``/``\\\\.\\\\Serial0``
        是无冒号设备名（剥前缀后残留冒号与保留名检查全放行）、``\\\\.\\\\C:``
        是卷设备本体——三者此前均通过全部检查；现要求首组件为盘符且带后续
        路径组件（``\\\\.\\\\C:\\data\\file.txt`` 文件系统形态有意放行）。
        """
        from src.utils import path_validation

        with pytest.raises(ValueError, match="设备命名空间"):
            path_validation._reject_windows_device_names_and_ads(path)

    @pytest.mark.parametrize(
        "path",
        [
            r"C:\Users\alice\config.json",
            r"C:\logs\cipherbox.log",
            r"C:\data\my.url",  # .url 扩展名的普通文件（stem 非保留名）
            r"C:\data\console_notes.txt",  # 含 "con" 子串但 stem 非整词保留名
            r"C:relative\config.json",  # 盘符相对路径（合法形态）
            "plain.txt",
            r"\\?\C:\data\file.txt",
            r"\\.\C:\data\file.txt",
            r"\\?\UNC\server\share\file.bin",
            r"\\server\share\backup.cbox",
        ],
        ids=[
            "drive",
            "drive-logs",
            "url-ext",
            "substring-not-word",
            "drive-relative",
            "bare-relative",
            "verbatim",
            "device-namespace",
            "verbatim-unc",
            "unc",
        ],
    )
    def test_legitimate_windows_paths_allowed(self, path):
        """合法 Windows 形态（盘符/UNC/verbatim 前缀/盘符相对）不误伤。"""
        from src.utils import path_validation

        # 返回 None 即放行（拒绝形态抛 ValueError，见相邻拒绝参数化组）；
        # 记录断言区分「校验完整执行后放行」与「校验未执行」（MAINT-111）
        assert path_validation._reject_windows_device_names_and_ads(path) is None

    def test_validate_file_path_integrates_windows_branch(self, tmp_path, monkeypatch):
        """validate_file_path 集成：IS_WINDOWS=True 时经主入口拒绝保留名与 ADS 形态。"""
        from src.utils import path_validation

        monkeypatch.setattr(path_validation, "IS_WINDOWS", True)
        with pytest.raises(ValueError, match="保留设备名"):
            path_validation.validate_file_path(str(tmp_path / "CON.txt"))
        with pytest.raises(ValueError, match="非法冒号"):
            path_validation.validate_file_path(str(tmp_path / "file.txt") + ":ads")
        # 同目录合法文件不受影响
        ok = path_validation.validate_file_path(str(tmp_path / "notes.txt"))
        assert ok.is_absolute()

    def test_non_windows_branch_skips_reserved_name_checks(self, tmp_path, monkeypatch):
        """非 Windows 分支不检查保留名/冒号（POSIX 合法文件名字符，跨平台语义分支）。"""
        from src.utils import path_validation

        monkeypatch.setattr(path_validation, "IS_WINDOWS", False)
        # POSIX 下 "CON.txt" 与含冒号名是合法文件名；validate_file_path 不因保留名拒绝
        ok = path_validation.validate_file_path(str(tmp_path / "CON.txt"))
        assert ok.is_absolute()


class TestVerbatimPrefixDeviceForms:
    r"""``\\?\`` verbatim 前缀的设备对象形态拒绝（SEC-066）。

    Win32 对象管理器把 ``\\?\`` 解析为 ``\??\``，与 ``\\.\`` 一样查 DOS 设备
    目录——``\\?\PhysicalDrive0``/``\\?\Serial0``/裸卷 ``\\?\C:`` 同为可达的
    设备对象，此前设备内容形态检查只挂 ``\\.\`` 分支致三者放行（SEC-061 的
    残留缺口）。修复后 ``\\?\`` 非 UNC 分支同样进入设备形态检查，仅放行
    「首组件盘符 + 后续路径」的文件系统形态；``\\?\UNC\`` 剥除后豁免。
    """

    @pytest.mark.parametrize(
        "path",
        [
            r"\\?\PhysicalDrive0",  # 物理磁盘设备（verbatim 形态）
            r"\\?\Serial0",  # 串口设备对象
            r"\\?\C:",  # 裸卷设备本体（无后续路径组件）
            r"\\?\CdRom0",  # 光驱设备对象
            r"\\?\GlobalRoot",  # 内核对象命名空间形态（无冒号首组件）
        ],
        ids=["physical-drive", "serial", "bare-volume", "cdrom", "globalroot"],
    )
    def test_verbatim_device_forms_rejected(self, path):
        r"""``\\?\`` 设备对象本体（无冒号/裸卷/内核对象）一律拒绝。"""
        from src.utils import path_validation

        with pytest.raises(ValueError, match="设备命名空间"):
            path_validation._reject_windows_device_names_and_ads(path)

    @pytest.mark.parametrize(
        "path",
        [
            r"\\?\C:\data\file.txt",  # 文件系统 verbatim 形态（长路径支持）
            r"\\?\C:" + "\\",  # 盘符根目录（同 \\.\C:\ 既有放行口径，拼接避开尾反斜杠转义）
            r"\\?\UNC\server\share\file.bin",  # UNC verbatim（剥前缀后纯共享路径，豁免）
        ],
        ids=["verbatim-fs", "verbatim-drive-root", "verbatim-unc"],
    )
    def test_verbatim_filesystem_forms_allowed(self, path):
        r"""``\\?\`` 的文件系统形态（盘符+路径 / UNC verbatim）不受影响。"""
        from src.utils import path_validation

        # 返回 None 即放行（拒绝形态抛 ValueError，见相邻拒绝参数化组，MAINT-111）
        assert path_validation._reject_windows_device_names_and_ads(path) is None
