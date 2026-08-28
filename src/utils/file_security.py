"""应用数据文件的最小权限控制 — 跨平台 ACL、原子写入、安全覆写删除与 DPAPI。

Unix 经 ``chmod`` 0600/0700，Windows 经 ctypes 进程内直调（进程令牌取 SID +
SetNamedSecurityInfoW，PERF-077）收紧为当前用户独占（icacls 子进程回退），含 ACL
缓存与 SID 解析；``atomic_write`` 经临时文件 + ``os.replace`` + 落地即 0600 实现原子写，
消除收紧前的世界可读窗口（SEC-015）；``secure_delete_file`` 覆写再 unlink 收缩取证还原面；
``validate_file_path`` 拒绝目录遍历与符号链接/reparse 重定向；DPAPI 封装敏感配置密钥。
"""

import csv
import io
import logging
import os
import stat
import subprocess
import sys
import threading
from collections import OrderedDict
from collections.abc import Callable
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# 平台判定单一常量（MAINT-012）：统一引用，避免 os.name=='nt' 与 sys.platform=='win32' 混用致跨平台漂移。
IS_WINDOWS = sys.platform == "win32"
_SECURED_WINDOWS_OBJECTS: OrderedDict[str, tuple[int, int]] = OrderedDict()
_SECURED_LOCK = threading.Lock()
_MAX_SECURED_CACHE = 256
# secure_delete_file 分块覆写粒度（1MB）：恢复点/快照可达数十 MB，一次性 os.urandom(size)
# 等量分配内存，批量清理峰值 N×文件大小可能 OOM；模块级常量避免每次调用重新求值。
_SECURE_DELETE_CHUNK_BYTES = 1024 * 1024

# 用户 SID 缓存：None=未解析，''=非 Windows（运行期不变），非空串=有效 SID。
# Windows 解析失败**不缓存**空串，否则一次瞬时失败会让整会话静默跳过 ACL 限制。
_CACHED_USER_SID: str | None = None
_SID_LOCK = threading.Lock()


def _run_no_window(
    cmd: list[str],
    *,
    timeout: int = 10,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    """运行子进程，抑制 Windows 控制台窗口（CREATE_NO_WINDOW），统一文本输出与超时。

    PERF-077 后仅承载 ctypes 路径的回退（whoami/icacls），不再处于默认路径。
    """
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=check,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        timeout=timeout,
    )


# ======== Windows 进程令牌与 ACL 的 ctypes 直调（PERF-077） ========
# 动机：whoami/icacls 子进程链实测每文件 41.5ms（icacls grant+inheritance 两次）+
# 首次 whoami 28.7ms，且 atomic_write 的 os.replace 换新 inode 后每次原子写都重付；
# 子进程另受企业策略禁用/EDR 拦截影响（原 whoami 路径自述脆弱性）。ctypes 直调
# advapi32/kernel32 进程内完成（实测见 _restrict_windows_acl_via_api 注释），
# 失败（非 Windows/ctypes 异常/API 失败）回退既有子进程路径，行为不劣化。


def _windows_user_sid_via_api() -> str:
    """ctypes 直调进程令牌取当前用户 SID 字符串（PERF-077），失败抛 OSError。

    链路：OpenProcessToken(GetCurrentProcess, TOKEN_QUERY) → GetTokenInformation
    (TokenUser) → ConvertSidToStringSidW。约 30 行进程内调用，替代 whoami 子进程
    （28.7ms → 亚毫秒），且不依赖外部可执行文件（受限环境自述脆弱性随之消除）。
    """
    import ctypes
    from ctypes import wintypes

    ctypes_any: Any = ctypes
    kernel32: Any = ctypes_any.WinDLL("kernel32", use_last_error=True)
    advapi32: Any = ctypes_any.WinDLL("advapi32", use_last_error=True)

    # 签名声明不可省（PERF-077 首版实测教训）：GetCurrentProcess 的伪句柄 -1 经
    # ctypes 默认 c_int 传参在 64 位下截断为 0x00000000FFFFFFFF 类非法句柄，
    # OpenProcessToken 直接失败——restype=HANDLE（指针宽度）保证 -1 全位表示。
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    # LocalFree 是 kernel32 导出（同 DPAPI 路径的用法），负责释放 SID 字符串缓冲。
    kernel32.LocalFree.argtypes = [wintypes.HANDLE]
    kernel32.LocalFree.restype = wintypes.HANDLE

    class _SidAndAttributes(ctypes.Structure):
        """SID_AND_ATTRIBUTES：GetTokenInformation(TokenUser) 输出的载体结构。"""

        _fields_ = [
            ("Sid", ctypes.c_void_p),
            ("Attributes", wintypes.DWORD),
        ]

    class _TokenUser(ctypes.Structure):
        """TOKEN_USER：GetTokenInformation(TokenUser) 的顶层结构（SID 随后）。"""

        _fields_ = [("User", _SidAndAttributes)]

    token_query = 0x0008
    token_user = 1
    h_token = wintypes.HANDLE()
    # GetCurrentProcess 返回伪句柄（-1），无需 CloseHandle；令牌句柄须关。
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), token_query, ctypes.byref(h_token)
    ):
        raise OSError("OpenProcessToken 失败")
    try:
        needed = wintypes.DWORD()
        # 两段式：首调取所需长度（缓冲传 None），次调取 TOKEN_USER+SID 完整载荷。
        if advapi32.GetTokenInformation(h_token, token_user, None, 0, ctypes.byref(needed)):
            raise OSError("GetTokenInformation 长度探测意外成功")
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(
            h_token, token_user, buffer, needed.value, ctypes.byref(needed)
        ):
            raise OSError("GetTokenInformation 失败")
        sid_ptr = ctypes.cast(buffer, ctypes.POINTER(_TokenUser)).contents.User.Sid
        if not sid_ptr:
            raise OSError("TokenUser 缺少 SID")
        sid_buf = ctypes.c_void_p()
        if not advapi32.ConvertSidToStringSidW(sid_ptr, ctypes.byref(sid_buf)):
            raise OSError("ConvertSidToStringSidW 失败")
        if not sid_buf.value:
            kernel32.LocalFree(sid_buf)
            raise OSError("ConvertSidToStringSidW 返回空缓冲")
        try:
            return ctypes.wstring_at(sid_buf.value)
        finally:
            kernel32.LocalFree(sid_buf)
    finally:
        kernel32.CloseHandle(h_token)


def _windows_user_sid() -> str:
    """获取当前 Windows 用户 SID，用于 ACL 权限设置。

    成功结果缓存；非 Windows 缓存空串；Windows 解析失败返回空串但**不缓存**以便重试。
    默认走 ctypes 进程令牌直调（PERF-077），ctypes 异常回退 ``whoami`` 子进程——
    两路径产出同一 S-1-5-… 字符串，回退仅损失性能不损失可用性。
    """
    global _CACHED_USER_SID
    cached = _CACHED_USER_SID
    if cached is not None:
        return cached
    if not IS_WINDOWS:
        with _SID_LOCK:
            _CACHED_USER_SID = ""
        return ""
    with _SID_LOCK:
        if _CACHED_USER_SID is not None:
            return _CACHED_USER_SID
        sid = ""
        try:
            sid = _windows_user_sid_via_api()
        except Exception:
            logger.debug("ctypes SID 解析失败，回退 whoami 子进程", exc_info=True)
            try:
                result = _run_no_window(
                    ["whoami", "/user", "/fo", "csv", "/nh"],
                    check=True,
                )
                # 用 csv 解析 whoami 输出，正确处理用户名含逗号的引号边界，避免 split(',') 误切。
                rows = list(csv.reader(io.StringIO(result.stdout.strip())))
                sid = rows[0][1] if rows and len(rows[0]) >= 2 else ""
            except (OSError, subprocess.SubprocessError, IndexError):
                logger.error("无法获取当前 Windows 用户 SID，本次跳过 ACL 限制", exc_info=True)
                return ""  # 不缓存，下次重试
        if sid:
            _CACHED_USER_SID = sid
        else:
            logger.error("SID 解析未返回有效值，本次跳过 ACL 限制")
        return sid


def _windows_object_identity(path: Path) -> tuple[int, int] | None:
    """获取文件的设备号和 inode，用于 ACL 缓存的唯一标识。"""
    try:
        # 命名 st 而非 stat：避免遮蔽模块级 import stat（同文件大量用 stat.S_ISLNK，
        # 若后续在此追加 mode 判定会静默拿到错误属性）。
        st = path.stat()
        return st.st_dev, st.st_ino
    except OSError:
        return None


def _restrict_windows_acl_via_api(path: Path, is_directory: bool, sid: str) -> None:
    """ctypes 直调 SetNamedSecurityInfoW 收紧 ACL（PERF-077），失败抛 OSError。

    等价 ``icacls /grant:r *SID:F(/OI)(CI) + /inheritance:r`` 两次子进程：
    ``SetEntriesInAclW`` 由 EXPLICIT_ACCESS（当前用户 FULL、目录带容器+对象继承）
    构造新 DACL，``SetNamedSecurityInfoW`` 带 ``PROTECTED_DACL`` 落盘——PROTECTED
    即 icacls ``/inheritance:r`` 的「移除继承 ACE」语义。实测（本机 Win11）：
    0.36-0.40ms/文件 vs 子进程 41-42ms/文件（~100 倍）；atomic_write 的
    os.replace 换新 inode 后每次原子写都重付该成本，config/导出/限流器状态均为
    高频路径。ACL 等价性经 icacls 读回验证：单显式 ACE（当前用户 FULL）、无
    继承 ACE、目录带 (OI)(CI)。

    注：SDK 的 BuildExplicitAccessWithNameW 是头文件内联宏而非导出函数，此处
    直接手工构造等价结构（TRUSTEE/EXPLICIT_ACCESS_W），与宏展开逐字段一致。
    """
    import ctypes
    from ctypes import wintypes

    ctypes_any: Any = ctypes
    advapi32: Any = ctypes_any.WinDLL("advapi32", use_last_error=True)
    # LocalFree 是 kernel32 导出（同 DPAPI 路径用法），释放 SetEntriesInAclW 的 ACL 缓冲。
    kernel32: Any = ctypes_any.WinDLL("kernel32", use_last_error=True)
    kernel32.LocalFree.argtypes = [wintypes.HANDLE]
    kernel32.LocalFree.restype = wintypes.HANDLE
    advapi32.SetEntriesInAclW.argtypes = [
        wintypes.ULONG,
        ctypes.c_void_p,  # PEXPLICIT_ACCESS_W 数组
        ctypes.c_void_p,  # 旧 ACL（None：全新构造）
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.SetEntriesInAclW.restype = wintypes.DWORD
    advapi32.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,  # SE_OBJECT_TYPE
        wintypes.DWORD,  # SECURITY_INFORMATION
        ctypes.c_void_p,  # psidOwner
        ctypes.c_void_p,  # psidGroup
        ctypes.c_void_p,  # pDacl
        ctypes.c_void_p,  # pSacl
    ]
    advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.ConvertStringSidToSidW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL

    class _TrusteeW(ctypes.Structure):
        """TRUSTEE_W：受托者描述（此处为二进制 PSID 形式的当前用户）。"""

        _fields_ = [
            ("pMultipleTrustee", ctypes.c_void_p),
            ("MultipleTrusteeOperation", wintypes.DWORD),
            ("TrusteeForm", wintypes.DWORD),  # TRUSTEE_IS_SID=0：ptstrName 为 PSID 指针
            ("TrusteeType", wintypes.DWORD),  # TRUSTEE_IS_USER=1
            ("ptstrName", ctypes.c_void_p),  # TrusteeForm=SID 时承载 PSID
        ]

    class _ExplicitAccessW(ctypes.Structure):
        """EXPLICIT_ACCESS_W：单条授权项（GRANT_ACCESS + FILE_ALL_ACCESS）。"""

        _fields_ = [
            ("grfAccessPermissions", wintypes.DWORD),  # FILE_ALL_ACCESS=0x1F01FF（icacls F）
            ("grfAccessMode", wintypes.DWORD),  # GRANT_ACCESS=1（替换式授权，icacls /grant:r）
            (
                "grfInheritance",
                wintypes.DWORD,
            ),  # 目录=SUB_CONTAINERS_AND_OBJECTS_INHERIT(3)=icacls (OI)(CI)
            ("pTrustee", _TrusteeW),
        ]

    # TrusteeForm 须取 TRUSTEE_IS_SID（0）+ 二进制 PSID（首版实测教训：TRUSTEE_IS_NAME
    # + SID 字符串触发 SetEntriesInAclW 内部 LookupAccountName → ERROR_NONE_MAPPED
    # 1332，SID 字符串不是账号名）；PSID 经 ConvertStringSidToSidW 从缓存的 SID
    # 字符串还原，免跨函数维护二进制 SID 副本。
    psid = ctypes.c_void_p()
    if not advapi32.ConvertStringSidToSidW(sid, ctypes.byref(psid)):
        # get_last_error 在非 Windows 平台的 typeshed 不暴露（win32-only API，本函数
        # 处于 sys.platform 守卫内不会执行）；type: ignore 须与调用表达式同线。
        raise OSError(
            f"ConvertStringSidToSidW 失败：{ctypes.get_last_error()}"  # type: ignore[attr-defined, unused-ignore]
        )
    new_dacl = ctypes.c_void_p()
    try:
        access = _ExplicitAccessW(
            grfAccessPermissions=0x1F01FF,
            grfAccessMode=1,  # GRANT_ACCESS
            grfInheritance=3 if is_directory else 0,  # (OI)(CI) / NO_INHERITANCE
            pTrustee=_TrusteeW(
                pMultipleTrustee=None,
                MultipleTrusteeOperation=0,  # NO_MULTIPLE_TRUSTEE
                TrusteeForm=0,  # TRUSTEE_IS_SID
                TrusteeType=1,  # TRUSTEE_IS_USER
                ptstrName=psid,
            ),
        )
        if (
            advapi32.SetEntriesInAclW(1, ctypes.byref(access), None, ctypes.byref(new_dacl)) != 0
        ):  # ERROR_SUCCESS=0；ignore 同线理由见上方 ConvertStringSidToSidW 处
            raise OSError(
                f"SetEntriesInAclW 失败：{ctypes.get_last_error()}"  # type: ignore[attr-defined, unused-ignore]
            )
        se_file_object = 1
        # DACL_SECURITY_INFORMATION(0x4) | PROTECTED_DACL_SECURITY_INFORMATION(0x80000000)：
        # 后者等价 icacls /inheritance:r——丢弃继承 ACE 仅保留显式 DACL。注意
        # PROTECTED_DACL 是高位标志（0x80000000），曾误取 0x1（OWNER flag）与
        # Owner=NULL 组合触发 ERROR_INVALID_PARAMETER(87)。
        security_info = 0x80000004
        if (
            advapi32.SetNamedSecurityInfoW(
                str(path),
                se_file_object,
                security_info,
                None,
                None,
                new_dacl,
                None,
            )
            != 0
        ):
            raise OSError(
                f"SetNamedSecurityInfoW 失败：{ctypes.get_last_error()}"  # type: ignore[attr-defined, unused-ignore]
            )
    finally:
        if new_dacl:
            kernel32.LocalFree(new_dacl)
        kernel32.LocalFree(psid)


def _restrict_windows_acl(
    path: Path,
    is_directory: bool,
    *,
    strict: bool = False,
) -> None:
    """限制文件或目录的 ACL 权限为当前用户独占访问（ctypes 优先，PERF-077）。"""
    sid = _windows_user_sid()
    if not sid:
        message = f"无法获取 Windows 用户 SID，无法限制 ACL：{path}"
        if strict:
            raise OSError(message)
        logger.warning(message)
        return
    cache_key = str(path.resolve())
    identity = _windows_object_identity(path)
    with _SECURED_LOCK:
        cached = _SECURED_WINDOWS_OBJECTS.get(cache_key)
        if identity is not None and cached == identity:
            # LRU：命中时更新为最近使用，避免常用路径被淘汰
            _SECURED_WINDOWS_OBJECTS.move_to_end(cache_key)
            return
    try:
        try:
            _restrict_windows_acl_via_api(path, is_directory, sid)
        except Exception:
            # ctypes 路径异常回退 icacls 子进程（PERF-077 的可用性保底）：仅损失
            # 性能不损失功能；AttributeError 覆盖非 Windows WinDLL 缺失场景。
            logger.debug("ctypes ACL 收紧失败，回退 icacls 子进程", exc_info=True)
            permission = "(OI)(CI)F" if is_directory else "F"
            grant = _run_no_window(
                ["icacls", str(path), "/grant:r", f"*{sid}:{permission}"],
            )
            if grant.returncode != 0:
                raise OSError(grant.stderr.strip() or "icacls grant failed") from None
            inherit = _run_no_window(
                ["icacls", str(path), "/inheritance:r"],
            )
            if inherit.returncode != 0:
                raise OSError(inherit.stderr.strip() or "icacls inheritance failed") from None
        if identity is not None:
            with _SECURED_LOCK:
                _SECURED_WINDOWS_OBJECTS[cache_key] = identity
                # LRU 淘汰合并到写入，避免分离锁段导致并发重复收紧
                while len(_SECURED_WINDOWS_OBJECTS) > _MAX_SECURED_CACHE:
                    _SECURED_WINDOWS_OBJECTS.popitem(last=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        if strict:
            raise OSError(f"无法限制文件 ACL：{path}") from exc
        logger.warning("无法限制文件 ACL：%s", path, exc_info=True)


def secure_directory(path: Path, *, strict: bool = False) -> Path:
    """创建目录并设置最小权限，仅当前用户可访问。

    ``strict=True`` 时权限设置失败抛异常，否则仅记录告警；返回 ``path`` 便于链式调用。
    """
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not IS_WINDOWS:
        try:
            os.chmod(path, 0o700)
        except OSError:
            if strict:
                raise
            logger.warning("无法限制目录权限：%s", path, exc_info=True)
    if IS_WINDOWS:
        _restrict_windows_acl(path, True, strict=strict)
    return path


def validate_file_path(
    path: str | Path,
    base_dir: Path | None = None,
    *,
    check_ancestors: bool = False,
) -> Path:
    """验证文件路径，拒绝目录遍历与路径重定向（符号链接/Windows reparse point）。

    调用方必须使用返回的 resolved 路径而非原始 path，以缩小 TOCTOU 竞态窗口。

    Note:
        reparse 检测具 TOCTOU 性质（检测与 open 间可被替换），仅本地威胁模型下有效。
        ``base_dir`` 经 ``resolve()`` + ``is_relative_to`` 约束解析后路径不逃逸受控根，
        但会跟随祖先符号链接，故**仅靠 base_dir 无法检测祖先被替换为 symlink**——
        backup_directory 等高敏感用户路径应传 ``check_ancestors=True`` 补齐。

    Args:
        path: 待验证的文件路径。
        base_dir: 可选基目录约束，解析后路径必须位于其下。
        check_ancestors: 是否对原始路径逐级检测祖先符号链接/reparse。默认 ``False``
            （Unix 仅检测叶子，避开 macOS 系统符号链接误伤）；高敏感路径传 ``True``
            （Unix 逐级 lstat 祖先拒绝非系统规范符号链接）。Windows 分支始终逐级检测。

    Returns:
        解析后的安全路径，调用方应使用此返回值。
    """
    raw = Path(path)
    if ".." in raw.parts:
        raise ValueError("文件路径包含非法遍历组件")
    # 必须在 resolve() 之前对原始路径逐级检测：resolve() 会展开并跟随符号链接与
    # junction，若先 resolve 再检测，原始输入中经由 junction 的重定向在解析后路径
    # 上 is_symlink() 恒为 False，检测将静默失效（该控制曾因此长期无效）。
    _reject_reparse_points(raw, check_ancestors=check_ancestors)
    resolved = raw.resolve()
    if base_dir is not None:
        base_resolved = Path(base_dir).resolve()
        if not resolved.is_relative_to(base_resolved):
            raise ValueError("文件路径超出允许的目录范围")
    return resolved


def _reject_reparse_points(path: Path, *, check_ancestors: bool = False) -> None:
    """拒绝路径上的符号链接 / Windows reparse point/junction，对抗路径重定向。

    按平台分支平衡安全与可用性：

    - **Windows**：逐级 ``lstat`` 检测符号链接与 junction（``st_file_attributes & 0x400``，
      Windows ``is_symlink`` 不识别 junction），系统目录通常不含 reparse，逐级不误伤。
    - **Unix**：默认仅检测叶子本身（系统目录普遍为符号链接——macOS ``/var``→``/private/var``、
      Linux ``/bin``→``/usr/bin``——逐级会大面积误伤）。叶子检测覆盖主要 TOCTOU 威胁
      （目标本身被替换为符号链接）。``check_ancestors=True`` 追加祖先符号链接检测，
      系统规范链接（见 :func:`_is_canonical_system_link`）放行，覆盖祖先被替为 symlink
      重定向含明文写入的威胁（高敏感用户路径用）。

    必须在 ``resolve()`` 之前检测——``resolve()`` 会跟随符号链接/junction，解析后路径
    ``is_symlink()`` 恒为 False 致检测静默失效。Unix 验证依赖 CI（macOS/Linux）。
    """
    if not IS_WINDOWS:
        # 叶子检测（覆盖主要 TOCTOU：目标本身被替换为符号链接）。
        try:
            st = path.lstat()
        except FileNotFoundError:
            pass  # 不存在的叶子（待写入新文件）视作非重定向，继续祖先检测
        except OSError:
            logger.debug("lstat 失败，跳过叶子重定向检测: %s", path, exc_info=True)
            pass
        else:
            if stat.S_ISLNK(st.st_mode):
                raise ValueError(f"目标是符号链接，拒绝访问: {path}")
        if not check_ancestors:
            # 默认仅检测叶子——祖先系统符号链接（/var、/tmp…）合法，逐级会大面积误伤。
            return
        # 高敏感路径追加祖先检测：逐级 lstat 祖先，拒绝非系统规范符号链接（系统规范链接经 _is_canonical_system_link 放行）。
        current = path.parent
        while True:
            try:
                cst = current.lstat()
            except OSError:
                # 含 FileNotFoundError（祖先组件不存在）与瞬时 IO；视作非重定向，跳过。
                cst = None
            if (
                cst is not None
                and stat.S_ISLNK(cst.st_mode)
                and not _is_canonical_system_link(current)
            ):
                raise ValueError(f"祖先目录是符号链接，拒绝访问: {current}")
            if current == current.parent:
                break
            current = current.parent
        return

    # Windows：逐级检测符号链接 + reparse point/junction。
    current = path
    while True:
        comp_st: os.stat_result | None = None
        try:
            comp_st = current.lstat()
        except FileNotFoundError:
            pass
        except OSError:
            logger.debug("lstat 失败，跳过该组件重定向检测: %s", current, exc_info=True)
        if comp_st is not None:
            if stat.S_ISLNK(comp_st.st_mode):
                raise ValueError(f"路径组件包含符号链接，拒绝访问: {current}")
            # st_file_attributes 为 Windows 专有属性，getattr 兜底跨平台访问
            attrs = getattr(comp_st, "st_file_attributes", 0)
            if attrs & 0x400:
                raise ValueError(f"路径组件包含 reparse point/junction，拒绝访问: {current}")
        if current == current.parent:
            break
        current = current.parent


def _is_canonical_system_link(path: Path) -> bool:
    """判断符号链接是否为 OS 维护的「规范重映射」（非攻击重定向），供祖先检测放行。

    macOS 把若干顶层目录符号链接到 ``/private`` 下（``/var``→``/private/var``、
    ``/tmp``→``/private/tmp``、``/etc``→``/private/etc``），系统稳定维护属合法；一律拒绝会
    误伤所有经系统临时目录的合法路径（曾致 macOS CI 备份/导入测试全失败）。深层符号链接、
    Linux 祖先符号链接一律视为可疑。判定仅依赖 darwin 平台与 ``resolve()``，无硬编码路径表。
    """
    if sys.platform != "darwin":
        return False
    parts = path.parts
    # 仅顶层单段绝对路径（('/','var')），避免误放深层重定向链接
    if len(parts) != 2 or not path.is_absolute():
        return False
    try:
        target = str(path.resolve(strict=False))
    except OSError:
        return False
    return target == "/" + "private" + "/" + parts[1]


def _path_is_symlink_or_reparse(path: Path) -> bool:
    """检测叶子本身是否为符号链接 / Windows reparse point/junction（``lstat`` 不跟随）。

    供 :func:`secure_delete_file` 覆写前判定：若是链接/reparse point 直接 ``unlink`` 链接本身，
    避免 purge 经恶意链接把覆写重定向到任意目标（SEC-014，与 :func:`validate_file_path` 同源）。
    """
    try:
        st = path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        logger.debug("lstat 失败，按非重定向处理: %s", path, exc_info=True)
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    if IS_WINDOWS:
        attrs = getattr(st, "st_file_attributes", 0)
        return bool(attrs & 0x400)
    return False


def secure_file(path: Path, *, strict: bool = False) -> Path:
    """设置文件最小权限，仅当前用户可读写。

    文件不存在时直接返回 ``path``；``strict=True`` 时权限设置失败抛异常，否则仅记录告警。
    """
    if not path.exists():
        return path
    if not IS_WINDOWS:
        try:
            os.chmod(path, 0o600)
        except OSError:
            if strict:
                raise
            logger.warning("无法限制文件权限：%s", path, exc_info=True)
    if IS_WINDOWS:
        _restrict_windows_acl(path, False, strict=strict)
    return path


def secure_delete_file(path: Path) -> None:
    """覆写删除文件：先以随机字节覆写再 unlink，收缩明文在 NTFS/ext4 上的取证还原面。

    用于含明文的敏感文件（恢复点 pre_restore_*.cbox、自动快照、临时备份），统一删除强度，
    避免敏感快照仅被 unlink 而明文扇区可被取证还原。文件不存在直接返回；SSD 磨损均衡下
    覆写非密码学保证但显著强于单纯 unlink。符号链接/reparse point 仅删链接不覆写目标（SEC-014）。
    """
    if _path_is_symlink_or_reparse(path):
        # 叶子是符号链接/reparse point：仅 unlink 链接本身，绝不覆写其目标（SEC-014），missing_ok 防 TOCTOU。
        path.unlink(missing_ok=True)
        return
    if not path.exists():
        # 文件不存在视为已删除，避免 stat 抛 FileNotFoundError 中断批量清理循环。
        return
    try:
        size = path.stat().st_size
        if size > 0:
            with open(path, "r+b") as fp:
                remaining = size
                while remaining > 0:
                    chunk = min(_SECURE_DELETE_CHUNK_BYTES, remaining)
                    fp.write(os.urandom(chunk))
                    remaining -= chunk
                fp.flush()
                os.fsync(fp.fileno())
    except OSError:
        # 覆写未完成：文件可能为「部分明文 + 部分随机」混合，明文残留未完全收缩。
        # 记 ERROR 让运维知晓（磁盘满/权限/IO），异常上抛供调用方计入 failed 列表反馈用户；
        # finally 仍 unlink 释放目录占用。
        logger.error(
            "安全覆写失败，文件 %s 可能含部分明文残留，建议检查磁盘空间与权限",
            path,
            exc_info=True,
        )
        raise
    finally:
        # missing_ok=True 防 stat 与 unlink 间 TOCTOU（文件被外部删除），避免中断清理循环。
        path.unlink(missing_ok=True)


def _open_file_restricted(name: str, flags: int) -> int:
    """``open()`` 的 opener 回调：以 0600 **独占**创建文件，供 :func:`atomic_write`。

    消除明文临时文件在 ``secure_file`` 收紧前的世界可读窗口（SEC-015）；叠加 O_EXCL
    （Windows/POSIX 均支持）使已存在路径（含预植符号链接）直接创建失败而非被跟随/
    覆写，关闭「unlink → open」间隙中植入符号链接重定向写入的竞态（SEC-028）；POSIX
    再叠加 O_NOFOLLOW（Windows 无此标志）拒绝链接本身。
    """
    exclusive_flags = flags | os.O_EXCL
    if not IS_WINDOWS:
        exclusive_flags |= getattr(os, "O_NOFOLLOW", 0)
    return os.open(name, exclusive_flags, 0o600)


# 临时文件随机后缀字节数与独占创建重试上限（SEC-028）：随机名 + O_EXCL 使攻击者
# 既无法预知也无法抢占临时文件路径；名字碰撞（含针对性抢占）时换新随机名重试，
# 耗尽视为异常环境，上抛而非降级为可预测名（降级会重新打开本要关闭的竞态窗口）。
_TEMP_RANDOM_BYTES = 6
_TEMP_CREATE_ATTEMPTS = 5


def _is_stale_temp_name(name: str, target_name: str) -> bool:
    """判断目录项是否为 ``target_name`` 对应 atomic_write 的残留临时文件。

    覆盖两种形态：旧版固定名 ``<target>.tmp`` 与新版随机名 ``<target>.<hex12>.tmp``
    （hex 严格校验，避免误删 ``<target>.old.tmp`` 等无关同名前缀文件）。经字符匹配
    而非 glob：文件名可含 ``[``/``*`` 等 glob 元字符，glob 语义会漏判或误判。
    """
    suffix = ".tmp"
    legacy = target_name + suffix
    if name == legacy:
        return True
    prefix = target_name + "."
    if not (name.startswith(prefix) and name.endswith(suffix)):
        return False
    middle = name[len(prefix) : -len(suffix)]
    return len(middle) == _TEMP_RANDOM_BYTES * 2 and all(
        char in "0123456789abcdefABCDEF" for char in middle
    )


def _purge_stale_temp_files(target: Path) -> None:
    """清理同目标残留的临时文件（上次进程硬崩溃遗留），尽力而为不阻断本次写入。

    旧实现临时文件名固定为 ``<name>.tmp``，下次同路径写入会先 unlink 再覆盖，天然
    完成清理；随机后缀（SEC-028）后不再有该副作用，须显式清理，避免含明文的临时
    文件（落地即 0600）长期驻留。仅 unlink 不覆写（与旧实现清理强度一致）；并发
    写入者的在途临时文件被误删时，POSIX 已打开句柄不受影响，Windows 因共享冲突
    unlink 失败被吞掉，均不破坏其最终 os.replace 的原子性。
    """
    try:
        entries = list(target.parent.iterdir())
    except OSError:
        logger.debug("扫描残留临时文件失败: %s", target.parent, exc_info=True)
        return
    for stale in entries:
        if not _is_stale_temp_name(stale.name, target.name):
            continue
        try:
            stale.unlink()
        except OSError:
            logger.debug("清理残留临时文件失败: %s", stale, exc_info=True)


def _create_exclusive_temp(
    target: Path,
    mode: str,
    open_kwargs: dict,
) -> tuple[Path, Any]:
    """创建带随机后缀、O_EXCL 独占的临时文件，返回 (路径, 已打开文件对象)。

    FileExistsError（随机名碰撞或路径被预植符号链接/文件）换新随机名重试至多
    ``_TEMP_CREATE_ATTEMPTS`` 次；耗尽抛 OSError 中止写入——安全优先于可用性。
    """
    for _ in range(_TEMP_CREATE_ATTEMPTS):
        candidate = target.with_name(f"{target.name}.{os.urandom(_TEMP_RANDOM_BYTES).hex()}.tmp")
        try:
            return candidate, open(candidate, mode, **open_kwargs)
        except FileExistsError:
            logger.debug("临时文件独占创建碰撞，换随机名重试: %s", candidate)
    raise OSError(f"临时文件独占创建失败（重试耗尽）：{target}")


def atomic_write(
    target: Path,
    write_cb: Callable[[Any], bool],
    *,
    mode: str = "wb",
    encoding: str | None = None,
    newline: str | None = None,
) -> bool:
    """原子写入文件：写临时文件 → fsync → secure_file → os.replace → secure_file。

    write_cb 接收已打开文件对象，返回 True 完成替换，False 取消（删临时文件不替换）。
    异常时删临时文件并重新抛出。临时文件名带随机后缀并以 O_EXCL 独占创建（SEC-028）：
    固定名 ``<name>.tmp`` + 先 unlink 再 open 在多用户可写目录（如导出明文 CSV/备份的
    目标目录）存在竞态窗口——攻击者抢先在可预测路径植入符号链接即可把写入重定向到
    任意目标；随机名不可预测，O_EXCL 保证「已存在即失败」（含符号链接，POSIX 叠加
    O_NOFOLLOW），失败换新随机名小次数重试。临时文件落地即 0600（经
    ``_open_file_restricted`` opener），消除「写明文 → 关闭 → secure_file 收紧」间的
    世界可读窗口（SEC-015）。Windows 忽略 POSIX mode 位，靠继承已收紧的父目录 ACL。
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    _purge_stale_temp_files(target)
    open_kwargs: dict = {"opener": _open_file_restricted}
    if encoding is not None:
        open_kwargs["encoding"] = encoding
    if newline is not None:
        open_kwargs["newline"] = newline
    temp, f = _create_exclusive_temp(target, mode, open_kwargs)
    try:
        with f:
            completed = write_cb(f)
            if completed:
                f.flush()
                os.fsync(f.fileno())
        if not completed:
            temp.unlink(missing_ok=True)
            return False
        secure_file(temp, strict=True)
        os.replace(temp, target)
        secure_file(target, strict=True)
        return True
    except BaseException:
        temp.unlink(missing_ok=True)
        raise


# ======== Windows DPAPI 封装 ========
# 用当前用户凭据封装敏感数据（如配置签名密钥），blob 即便被同权限进程读取也无法在别处
# 解密，收缩读取密钥文件后离线重算签名绕过完整性校验的攻击面。非 Windows 或失败回退 None，
# 调用方降级明文存储（靠文件权限保护），绝不阻断启动。


def protect_with_dpapi(data: bytes) -> bytes | None:
    """用 Windows DPAPI 封装数据，返回封装后的 blob；非 Windows 或失败返回 None。"""
    if not IS_WINDOWS:
        return None
    return _dpapi_crypt(data, protect=True)


def unprotect_with_dpapi(blob: bytes) -> bytes | None:
    """解封 DPAPI 封装的数据；非 Windows、非 DPAPI 格式或失败返回 None。

    返回 None 表示数据非 DPAPI 封装或解封失败，调用方据此尝试明文回退。
    """
    if not IS_WINDOWS:
        return None
    return _dpapi_crypt(blob, protect=False)


def _dpapi_crypt(data: bytes, *, protect: bool) -> bytes | None:
    """调用 CryptProtectData/CryptUnprotectData。返回 None 时调用方回退明文。

    异常分类告警，避免「敏感数据因 DPAPI 失败明文落盘」被静默掩盖：
    - 平台性失败（非 Windows 无 ``ctypes.WinDLL``）：静默回退，合法。
    - 调用性失败（crypt32 可用但 API 失败）：敏感数据明文落盘，ERROR 告警（安全降级须可见）。
    - 未预期异常（Structure/类型 bug）：ERROR 暴露而非掩盖。
    """
    try:
        import ctypes
        from ctypes import wintypes

        class _DataBlob(ctypes.Structure):
            """Windows CRYPT_DATA_BLOB 结构，DPAPI 输入/输出载体（长度 + 数据指针）。"""

            _fields_ = [
                ("cbData", wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char)),
            ]

        buffer = ctypes.create_string_buffer(data, len(data))
        blob_in = _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
        blob_out = _DataBlob()
        # ctypes 在非 Windows 既无 windll 也无 WinDLL；经 Any 访问避免平台 attr-defined。Linux 运行时 ctypes.WinDLL 抛 AttributeError → 下方 except 回退明文。
        ctypes_any: Any = ctypes
        crypt32: Any = ctypes_any.WinDLL("crypt32")
        if protect:
            ok = crypt32.CryptProtectData(
                ctypes.byref(blob_in),
                None,
                None,
                None,
                None,
                0,
                ctypes.byref(blob_out),
            )
        else:
            # ppszDataDescr 传 None 表示不接收描述字符串
            ok = crypt32.CryptUnprotectData(
                ctypes.byref(blob_in),
                None,
                None,
                None,
                None,
                0,
                ctypes.byref(blob_out),
            )
        if not ok:
            raise OSError("DPAPI 调用失败")
        try:
            result = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            kernel32: Any = ctypes_any.WinDLL("kernel32")
            kernel32.LocalFree(blob_out.pbData)
            # 清零输入侧 buffer 副本（封装前 data 的明文拷贝 / 解封前 blob 拷贝），收缩残留面
            ctypes.memset(buffer, 0, ctypes.sizeof(buffer))
        return result
    except AttributeError:
        # 平台性：非 Windows 无 ctypes.WinDLL/wintypes，DPAPI 不可用合法，静默回退明文。
        return None
    except OSError:
        # 调用性：crypt32 可用但 API 失败，敏感数据明文落盘，ERROR 告警避免静默掩盖安全降级。
        logger.error("DPAPI %s 调用失败，敏感数据将以明文存储", "封装" if protect else "解封")
        return None
    except Exception:
        # 未预期异常（Structure/类型 bug），ERROR 暴露而非掩盖。
        logger.error(
            "DPAPI %s 未预期异常，敏感数据将以明文存储",
            "封装" if protect else "解封",
            exc_info=True,
        )
        return None
