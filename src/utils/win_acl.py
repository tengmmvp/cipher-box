"""Windows SID 解析与 ACL 收紧 — 子进程封装与 ctypes 直调链（MAINT-117 拆分自 file_security）。

Unix 侧权限加固走 ``os.chmod``（见 :mod:`src.utils.file_security` 的
secure_file/secure_directory），本模块承载 Windows 侧收紧：``restrict_windows_acl``
把文件/目录收紧为当前用户独占，经 ``file_security`` 消费。默认路径为 ctypes 进程内
直调（进程令牌取 SID + SetNamedSecurityInfoW，PERF-077），whoami/icacls 子进程链
保留为失败回退；模块内含用户 SID 缓存与已收紧对象的 LRU 缓存（避免 atomic_write 的
os.replace 换新 inode 后每次重付收紧成本）。
"""

import csv
import io
import logging
import subprocess
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any

from ._platform import IS_WINDOWS

logger = logging.getLogger(__name__)

_SECURED_WINDOWS_OBJECTS: OrderedDict[str, tuple[int, int]] = OrderedDict()
_SECURED_LOCK = threading.Lock()
_MAX_SECURED_CACHE = 256

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
        # 命名 st 而非 stat：避免遮蔽模块级 import stat（若本模块后续引入 stat 模块，
        # 同文件大量 stat.S_ISLNK 场景下追加 mode 判定会静默拿到错误属性）。
        st = path.stat()
        return st.st_dev, st.st_ino
    except OSError:
        return None


def _declare_acl_api_signatures(advapi32: Any, kernel32: Any) -> None:
    """声明 ACL 收紧链路所需 ctypes API 的签名（argtypes/restype，MAINT-096）。

    签名声明不可省（PERF-077 首版实测教训，同 :func:`_windows_user_sid_via_api`）：
    缺省 ctypes 按默认 C int 传参/返回，指针宽度句柄在 64 位下截断致调用静默失败。
    """
    import ctypes
    from ctypes import wintypes

    # LocalFree 是 kernel32 导出（同 DPAPI 路径用法），释放 SetEntriesInAclW 的 ACL 缓冲。
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


def _string_sid_to_psid(sid: str, advapi32: Any) -> Any:
    """步骤一（取 SID）：ConvertStringSidToSidW 把缓存的 SID 字符串还原为二进制 PSID。

    免跨函数维护二进制 SID 副本；调用方负责 LocalFree 释放返回的 PSID（MAINT-096
    拆分自 _restrict_windows_acl_via_api，ctypes 调用序列零变化）。
    """
    import ctypes

    psid = ctypes.c_void_p()
    if not advapi32.ConvertStringSidToSidW(sid, ctypes.byref(psid)):
        # get_last_error 在非 Windows 平台的 typeshed 不暴露（win32-only API，本函数
        # 处于 sys.platform 守卫内不会执行）；type: ignore 须与调用表达式同线。
        raise OSError(
            f"ConvertStringSidToSidW 失败：{ctypes.get_last_error()}"  # type: ignore[attr-defined, unused-ignore]
        )
    return psid


def _build_owner_only_dacl(advapi32: Any, psid: Any, is_directory: bool) -> Any:
    """步骤二（构造 ACL）：SetEntriesInAclW 构造「当前用户独占」的新 DACL。

    由 EXPLICIT_ACCESS（当前用户 FULL、目录带容器+对象继承）构造，返回待落盘的
    DACL 缓冲，调用方负责 LocalFree 释放。注：SDK 的 BuildExplicitAccessWithNameW
    是头文件内联宏而非导出函数，此处直接手工构造等价结构
    （TRUSTEE/EXPLICIT_ACCESS_W），与宏展开逐字段一致。

    TrusteeForm 须取 TRUSTEE_IS_SID（0）+ 二进制 PSID（首版实测教训：TRUSTEE_IS_NAME
    + SID 字符串触发 SetEntriesInAclW 内部 LookupAccountName → ERROR_NONE_MAPPED
    1332，SID 字符串不是账号名）。
    """
    import ctypes
    from ctypes import wintypes

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
    new_dacl = ctypes.c_void_p()
    if (
        advapi32.SetEntriesInAclW(1, ctypes.byref(access), None, ctypes.byref(new_dacl)) != 0
    ):  # ERROR_SUCCESS=0；ignore 同线理由见 _string_sid_to_psid 处
        raise OSError(
            f"SetEntriesInAclW 失败：{ctypes.get_last_error()}"  # type: ignore[attr-defined, unused-ignore]
        )
    return new_dacl


def _apply_protected_dacl(advapi32: Any, path: Path, new_dacl: Any) -> None:
    """步骤三（应用）：SetNamedSecurityInfoW 带 PROTECTED_DACL 把新 DACL 落盘。

    DACL_SECURITY_INFORMATION(0x4) | PROTECTED_DACL_SECURITY_INFORMATION(0x80000000)：
    后者等价 icacls /inheritance:r——丢弃继承 ACE 仅保留显式 DACL。注意
    PROTECTED_DACL 是高位标志（0x80000000），曾误取 0x1（OWNER flag）与
    Owner=NULL 组合触发 ERROR_INVALID_PARAMETER(87)。
    """
    import ctypes

    se_file_object = 1
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

    编排（MAINT-096 三步拆分，ctypes 调用序列与拆分前零变化）：声明签名
    （:func:`_declare_acl_api_signatures`）→ 取 PSID（:func:`_string_sid_to_psid`）
    → 构造 DACL（:func:`_build_owner_only_dacl`）→ 应用
    （:func:`_apply_protected_dacl`）；PSID/DACL 缓冲经 LocalFree 在 finally 释放。
    """
    import ctypes

    ctypes_any: Any = ctypes
    advapi32: Any = ctypes_any.WinDLL("advapi32", use_last_error=True)
    kernel32: Any = ctypes_any.WinDLL("kernel32", use_last_error=True)
    _declare_acl_api_signatures(advapi32, kernel32)
    psid = _string_sid_to_psid(sid, advapi32)
    try:
        new_dacl = _build_owner_only_dacl(advapi32, psid, is_directory)
        try:
            _apply_protected_dacl(advapi32, path, new_dacl)
        finally:
            if new_dacl:
                kernel32.LocalFree(new_dacl)
    finally:
        kernel32.LocalFree(psid)


def restrict_windows_acl(
    path: Path,
    is_directory: bool,
    *,
    strict: bool = False,
) -> None:
    """限制文件或目录的 ACL 权限为当前用户独占访问（ctypes 优先，PERF-077）。

    供 :mod:`src.utils.file_security` 的 secure_file/secure_directory 消费。注入
    契约：file_security 经 ``from .win_acl import restrict_windows_acl`` 持有独立
    绑定——测试 file_security 链路须 patch 消费方名
    ``src.utils.file_security.restrict_windows_acl``，仅测试本模块内部分支（如
    ctypes 回退 icacls）时 patch 本模块名有效。本函数为无实例状态的模块级函数，
    无实例级替换面；名称无下划线前缀为跨模块公开契约（MAINT-124，对齐
    PERF-089 先例）。
    """
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
