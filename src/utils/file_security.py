"""应用数据文件的最小权限控制。"""

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

# 平台判定单一常量（MAINT-2）：统一引用，避免 os.name=='nt' 与 sys.platform=='win32' 混用致跨平台漂移。
IS_WINDOWS = sys.platform == "win32"
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

    收敛 whoami/icacls 公共参数，新增调用点复用即不漏 creationflags 致弹黑窗。
    """
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=check,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        timeout=timeout,
    )


def _windows_user_sid() -> str:
    """获取当前 Windows 用户 SID，用于 ACL 权限设置。

    成功结果缓存；非 Windows 缓存空串；Windows 解析失败返回空串但**不缓存**以便重试。
    依赖 ``whoami`` 子进程，受限环境（企业策略禁用/EDR 拦截）下会失败——记 ERROR 跳过
    ACL（本次）；彻底提升可靠性需改用 ctypes 调 GetUserNameEx，当前作为已知取舍保留。
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
            logger.error("whoami 未返回有效 SID，本次跳过 ACL 限制")
        return sid


def _windows_object_identity(path: Path) -> tuple[int, int] | None:
    """获取文件的设备号和 inode，用于 ACL 缓存的唯一标识。"""
    try:
        stat = path.stat()
        return stat.st_dev, stat.st_ino
    except OSError:
        return None


def _restrict_windows_acl(
    path: Path,
    is_directory: bool,
    *,
    strict: bool = False,
) -> None:
    """限制文件或目录的 ACL 权限为当前用户独占访问。"""
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
    permission = "(OI)(CI)F" if is_directory else "F"
    try:
        grant = _run_no_window(
            ["icacls", str(path), "/grant:r", f"*{sid}:{permission}"],
        )
        if grant.returncode != 0:
            raise OSError(grant.stderr.strip() or "icacls grant failed")
        inherit = _run_no_window(
            ["icacls", str(path), "/inheritance:r"],
        )
        if inherit.returncode != 0:
            raise OSError(inherit.stderr.strip() or "icacls inheritance failed")
        if identity is not None:
            with _SECURED_LOCK:
                _SECURED_WINDOWS_OBJECTS[cache_key] = identity
                # LRU 淘汰合并到写入，避免分离锁段导致并发重复 icacls
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
    避免 purge 经恶意链接把覆写重定向到任意目标（SEC-1，与 :func:`validate_file_path` 同源）。
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
    覆写非密码学保证但显著强于单纯 unlink。符号链接/reparse point 仅删链接不覆写目标（SEC-1）。
    """
    if _path_is_symlink_or_reparse(path):
        # 叶子是符号链接/reparse point：仅 unlink 链接本身，绝不覆写其目标（SEC-1），missing_ok 防 TOCTOU。
        path.unlink(missing_ok=True)
        return
    if not path.exists():
        # 文件不存在视为已删除，避免 stat 抛 FileNotFoundError 中断批量清理循环。
        return
    try:
        size = path.stat().st_size
        if size > 0:
            # 分块覆写（1MB）：恢复点/快照可达数十 MB，一次性 os.urandom(size) 等量分配内存，批量清理峰值 N×文件大小可能 OOM。
            _DELETE_CHUNK = 1024 * 1024
            with open(path, "r+b") as fp:
                remaining = size
                while remaining > 0:
                    chunk = min(_DELETE_CHUNK, remaining)
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
    """``open()`` 的 opener 回调：以 0600 创建文件，供 :func:`atomic_write` 消除明文临时文件在 ``secure_file`` 收紧前的世界可读窗口（SEC-2）。"""
    return os.open(name, flags, 0o600)


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
    异常时删临时文件并重新抛出。临时文件落地即 0600（经 ``_open_file_restricted`` opener），
    消除「写明文 → 关闭 → secure_file 收紧」间的世界可读窗口（SEC-2）。Windows 忽略 POSIX
    mode 位，靠继承已收紧的父目录 ACL。
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_name(target.name + ".tmp")
    # 清理上次进程硬崩溃（SIGKILL/断电，无法触发下方 except BaseException）残留的
    # .tmp（落地即 0600，但可能含明文配置），避免长期驻留至下次同路径写入才覆盖。
    temp.unlink(missing_ok=True)
    open_kwargs: dict = {"opener": _open_file_restricted}
    if encoding is not None:
        open_kwargs["encoding"] = encoding
    if newline is not None:
        open_kwargs["newline"] = newline
    try:
        with open(temp, mode, **open_kwargs) as f:
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
