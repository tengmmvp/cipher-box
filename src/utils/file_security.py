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
_SECURED_WINDOWS_OBJECTS: OrderedDict[str, tuple[int, int]] = OrderedDict()
_SECURED_LOCK = threading.Lock()
_MAX_SECURED_CACHE = 256

# 已解析的用户 SID 缓存：None=未解析；''=非 Windows 平台（运行期不变）；
# 非空串=有效 SID。Windows 下解析失败**不缓存空串**，否则一次瞬时失败
# （whoami 子进程受限/超时）会让整个会话静默跳过 ACL 限制。
_CACHED_USER_SID: str | None = None
_SID_LOCK = threading.Lock()


def _run_no_window(
    cmd: list[str], *, timeout: int = 10, check: bool = False,
) -> subprocess.CompletedProcess[str]:
    """运行子进程，抑制 Windows 控制台窗口（CREATE_NO_WINDOW），统一文本输出与超时。

    收敛 whoami / icacls 调用的公共参数（capture_output/text/creationflags/timeout），
    新增 icacls 调用点复用即不漏 creationflags 导致弹黑窗。
    """
    return subprocess.run(
        cmd, capture_output=True, text=True, check=check,
        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0), timeout=timeout,
    )


def _windows_user_sid() -> str:
    """获取当前 Windows 用户的 SID，用于 ACL 权限设置。

    成功解析的结果会被缓存；非 Windows 平台缓存空串。Windows 下解析失败时
    返回空串但**不缓存**——下次调用重新解析，避免瞬时失败导致整会话失效。

    已知限制：依赖 ``whoami`` 子进程，在受限环境（企业策略禁用 whoami、EDR 拦截
    子进程创建）下会失败——此时记 ERROR 并跳过 ACL（本次），不缓存以便下次重试。
    彻底提升可靠性需改用 ctypes 直接调 GetUserNameEx/GetTokenInformation 获取 SID，
    当前作为已知取舍保留（whoami 在标准 Windows 环境可靠且结果有缓存，首调外零成本）。
    """
    global _CACHED_USER_SID
    cached = _CACHED_USER_SID
    if cached is not None:
        return cached
    if os.name != 'nt':
        with _SID_LOCK:
            _CACHED_USER_SID = ''
        return ''
    with _SID_LOCK:
        if _CACHED_USER_SID is not None:
            return _CACHED_USER_SID
        sid = ''
        try:
            result = _run_no_window(
                ['whoami', '/user', '/fo', 'csv', '/nh'], check=True,
            )
            # 用 csv 解析 whoami 的 CSV 输出，正确处理用户名含逗号时的引号边界，
            # 避免 split(',') 在 "Doe, John" 场景误切导致 SID 解析错误。
            rows = list(csv.reader(io.StringIO(result.stdout.strip())))
            sid = rows[0][1] if rows and len(rows[0]) >= 2 else ''
        except (OSError, subprocess.SubprocessError, IndexError):
            logger.error('无法获取当前 Windows 用户 SID，本次跳过 ACL 限制', exc_info=True)
            return ''  # 不缓存，下次重试
        if sid:
            _CACHED_USER_SID = sid
        else:
            logger.error('whoami 未返回有效 SID，本次跳过 ACL 限制')
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
        message = f'无法获取 Windows 用户 SID，无法限制 ACL：{path}'
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
    permission = '(OI)(CI)F' if is_directory else 'F'
    try:
        grant = _run_no_window(
            ['icacls', str(path), '/grant:r', f'*{sid}:{permission}'],
        )
        if grant.returncode != 0:
            raise OSError(grant.stderr.strip() or 'icacls grant failed')
        inherit = _run_no_window(
            ['icacls', str(path), '/inheritance:r'],
        )
        if inherit.returncode != 0:
            raise OSError(inherit.stderr.strip() or 'icacls inheritance failed')
        if identity is not None:
            with _SECURED_LOCK:
                _SECURED_WINDOWS_OBJECTS[cache_key] = identity
                # LRU 淘汰合并到写入，避免分离锁段导致并发重复 icacls
                while len(_SECURED_WINDOWS_OBJECTS) > _MAX_SECURED_CACHE:
                    _SECURED_WINDOWS_OBJECTS.popitem(last=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        if strict:
            raise OSError(f'无法限制文件 ACL：{path}') from exc
        logger.warning('无法限制文件 ACL：%s', path, exc_info=True)


def secure_directory(path: Path, *, strict: bool = False) -> Path:
    """创建目录并设置最小权限，仅当前用户可访问。

    ``strict=True`` 时权限设置失败抛异常，否则仅记录告警；返回 ``path`` 便于链式调用。
    """
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if sys.platform != 'win32':
        try:
            os.chmod(path, 0o700)
        except OSError:
            if strict:
                raise
            logger.warning('无法限制目录权限：%s', path, exc_info=True)
    if os.name == 'nt':
        _restrict_windows_acl(path, True, strict=strict)
    return path


def validate_file_path(path: str | Path, base_dir: Path | None = None) -> Path:
    """验证文件路径，用于导入/导出/备份操作。

    解析路径并拒绝可能允许目录遍历或路径重定向的组件：拒绝 ``..`` 遍历；
    对**原始未解析路径**检测符号链接与 Windows reparse point/junction（平台分支
    策略详见 :func:`_reject_reparse_points`），作为对抗路径重定向（把写入重定向到
    敏感文件或攻击者可控位置）的纵深防御。

    调用方必须使用返回的 resolved 路径而非原始 path 参数，以缩小 TOCTOU 竞态窗口。

    Note:
        reparse point 检测具 TOCTOU 性质（检测与后续 open 间可被替换），仅在本地
        威胁模型下有效。对高敏感写入（备份/恢复）应显式提供 ``base_dir``，由
        ``resolve()`` + ``is_relative_to`` 提供更强的「不得逃逸受控根」保证。

    Args:
        path: 待验证的文件路径
        base_dir: 可选基目录约束，解析后的路径必须位于其下。

    Returns:
        解析后的安全路径，调用方应使用此返回值。
    """
    raw = Path(path)
    if '..' in raw.parts:
        raise ValueError('文件路径包含非法遍历组件')
    # 必须在 resolve() 之前对原始路径逐级检测：resolve() 会展开并跟随符号链接与
    # junction，若先 resolve 再检测，原始输入中经由 junction 的重定向在解析后路径
    # 上 is_symlink() 恒为 False，检测将静默失效（该控制曾因此长期无效）。
    _reject_reparse_points(raw)
    resolved = raw.resolve()
    if base_dir is not None:
        base_resolved = Path(base_dir).resolve()
        if not resolved.is_relative_to(base_resolved):
            raise ValueError('文件路径超出允许的目录范围')
    return resolved


def _reject_reparse_points(path: Path) -> None:
    """拒绝路径上的符号链接 / Windows reparse point/junction，对抗路径重定向。

    按平台分支以平衡安全与可用性：

    - **Windows**：逐级 ``lstat``（不跟随）检测整条路径——Windows 系统目录
      （``%APPDATA%``、``%USERPROFILE%``）通常不含 reparse point/junction，逐级检测
      不误伤系统路径，且能防御 junction 把祖先目录重定向到攻击者可控位置的威胁。
      符号链接用 ``S_ISLNK``，junction/挂载点用 Windows 专有 ``st_file_attributes & 0x400``
      补充——Windows 上 ``is_symlink`` 不识别 junction/reparse point。
    - **Unix**：仅检测**目标叶子本身**（``path``）是否为符号链接，不遍历祖先。Unix
      系统目录普遍为符号链接（macOS ``/var``→``/private/var``、``/tmp``→``/private/tmp``；
      Linux ``/bin``→``/usr/bin`` 等），逐级检测会误伤所有经系统临时目录的合法路径
      （曾导致 macOS CI 全部备份/导入测试失败）。叶子检测仍覆盖主要 TOCTOU 威胁——
      目标文件/目录本身被替换为符号链接；祖先被替换的前提是攻击者已控制该祖先目录，
      威胁等级已高，纵深防御的边际价值低于误伤成本。

    必须在 ``resolve()`` 之前对原始路径检测：``resolve()`` 会展开并跟随符号链接与
    junction，解析后路径上 ``is_symlink()`` 恒为 False，检测将静默失效。不存在的
    组件（如待写入的新文件）``lstat`` 抛 ``FileNotFoundError``，视为非重定向。
    """
    if sys.platform != 'win32':
        # Unix：仅检测叶子。祖先系统符号链接（/var、/tmp、/bin…）合法，逐级会大面积误伤。
        try:
            st = path.lstat()
        except FileNotFoundError:
            return
        except OSError:
            logger.debug('lstat 失败，跳过重定向检测: %s', path, exc_info=True)
            return
        if stat.S_ISLNK(st.st_mode):
            raise ValueError(f'目标是符号链接，拒绝访问: {path}')
        return

    # Windows：逐级检测符号链接 + reparse point/junction。
    current = path
    while True:
        try:
            st = current.lstat()
        except FileNotFoundError:
            st = None
        except OSError:
            logger.debug('lstat 失败，跳过该组件重定向检测: %s', current, exc_info=True)
            st = None
        if st is not None:
            if stat.S_ISLNK(st.st_mode):
                raise ValueError(f'路径组件包含符号链接，拒绝访问: {current}')
            # st_file_attributes 为 Windows 专有属性，getattr 兜底跨平台访问
            attrs = getattr(st, 'st_file_attributes', 0)
            if attrs & 0x400:
                raise ValueError(
                    f'路径组件包含 reparse point/junction，拒绝访问: {current}'
                )
        if current == current.parent:
            break
        current = current.parent


def secure_file(path: Path, *, strict: bool = False) -> Path:
    """设置文件最小权限，仅当前用户可读写。

    文件不存在时直接返回 ``path``；``strict=True`` 时权限设置失败抛异常，否则仅记录告警。
    """
    if not path.exists():
        return path
    if sys.platform != 'win32':
        try:
            os.chmod(path, 0o600)
        except OSError:
            if strict:
                raise
            logger.warning('无法限制文件权限：%s', path, exc_info=True)
    if os.name == 'nt':
        _restrict_windows_acl(path, False, strict=strict)
    return path


def secure_delete_file(path: Path) -> None:
    """覆盖删除文件：先以随机字节覆写内容再 unlink，收缩明文在支持数据恢复的
    文件系统（NTFS/ext4）上的取证还原面。

    用于含明文或历史明文的敏感文件（恢复点 pre_restore_*.cbox、自动快照
    cipherbox_snapshot_*.cbox、临时备份），统一改密路径与其它清理路径的删除强度，
    避免敏感快照仅被 unlink 而明文扇区可被取证工具还原。

    文件不存在时直接返回（视为已删除）；覆写采用随机字节，SSD 磨损均衡下并非
    密码学保证但显著强于单纯 unlink。unlink 使用 missing_ok 防御 TOCTOU。
    """
    if not path.exists():
        # 文件已不存在视为已删除，直接返回；避免 stat 抛 FileNotFoundError
        # 中断调用方的批量清理循环，单文件缺失不被误报为清理失败。
        return
    try:
        size = path.stat().st_size
        if size > 0:
            # 分块覆写（1MB）：恢复点/快照可达数十 MB，一次性 os.urandom(size)
            # 等量分配内存，批量清理峰值=N×文件大小可能 OOM。分块收缩峰值。
            _DELETE_CHUNK = 1024 * 1024
            with open(path, 'r+b') as fp:
                remaining = size
                while remaining > 0:
                    chunk = min(_DELETE_CHUNK, remaining)
                    fp.write(os.urandom(chunk))
                    remaining -= chunk
                fp.flush()
                os.fsync(fp.fileno())
    except OSError:
        # 覆写未完成：文件可能为「部分原始明文 + 部分随机字节」的混合，扇区上
        # 仍有明文残留，取证还原面未完全收缩。明确记录 error 让运维知晓风险
        # （磁盘满/权限/IO 错误），而非让异常被下方 finally 的 unlink 静默掩盖。
        # 异常继续向上抛：调用方（如改密/恢复 purge）据此将文件计入 failed 列表
        # 反馈用户；finally 仍 unlink 释放目录占用，避免半成品文件被直接打开。
        logger.error(
            "安全覆写失败，文件 %s 可能含部分明文残留，建议检查磁盘空间与权限",
            path, exc_info=True,
        )
        raise
    finally:
        # missing_ok=True 防御 stat 与 unlink 间的 TOCTOU（文件被外部删除），
        # 避免此时抛 FileNotFoundError 中断清理循环。
        path.unlink(missing_ok=True)


def atomic_write(
    target: Path,
    write_cb: Callable[[Any], bool],
    *,
    mode: str = 'wb',
    encoding: str | None = None,
    newline: str | None = None,
) -> bool:
    """原子写入文件：写临时文件 → fsync → secure_file → os.replace → secure_file。

    write_cb 接收已打开的文件对象，完成写入并返回 True；返回 False 表示取消
    （删除临时文件，不替换目标）。异常时删除临时文件并重新抛出。目标与临时
    文件都经 secure_file 收紧权限。统一导出 JSON/CSV 与备份二进制的原子写契约，
    消除三处逐字复制的「写临时 → fsync → replace → secure → 清理」模式。
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_name(target.name + '.tmp')
    open_kwargs: dict = {}
    if encoding is not None:
        open_kwargs['encoding'] = encoding
    if newline is not None:
        open_kwargs['newline'] = newline
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
# 用当前用户凭据封装敏感数据（如配置签名密钥），使封装后的 blob 即便被同权限
# 进程读取也无法在别处（不同用户/会话）解密，收缩本地攻击者读取密钥文件后离线
# 重算签名绕过完整性校验的攻击面。非 Windows 或调用失败时回退 None，由调用方
# 降级到明文存储（靠文件权限保护），绝不阻断启动。

def protect_with_dpapi(data: bytes) -> bytes | None:
    """用 Windows DPAPI 封装数据，返回封装后的 blob；非 Windows 或失败返回 None。"""
    if sys.platform != 'win32':
        return None
    return _dpapi_crypt(data, protect=True)


def unprotect_with_dpapi(blob: bytes) -> bytes | None:
    """解封 DPAPI 封装的数据；非 Windows、非 DPAPI 格式或失败返回 None。

    返回 None 表示数据非 DPAPI 封装或解封失败，调用方据此尝试明文回退。
    """
    if sys.platform != 'win32':
        return None
    return _dpapi_crypt(blob, protect=False)


def _dpapi_crypt(data: bytes, *, protect: bool) -> bytes | None:
    """调用 CryptProtectData/CryptUnprotectData。

    返回 None 时调用方回退明文。异常分类告警，避免「配置签名密钥因 DPAPI 调用
    失败而明文落盘」被静默掩盖：
    - 平台性失败（非 Windows 无 ``ctypes.WinDLL``）：静默回退，DPAPI 不可用属合法。
    - 调用性失败（crypt32 可用但 API 返回失败）：敏感数据将明文落盘，记 ERROR
      明确告警——此为安全降级，须可见。
    - 未预期异常（Structure/类型错误等编程 bug）：记 ERROR 暴露而非掩盖。
    """
    try:
        import ctypes
        from ctypes import wintypes

        class _DataBlob(ctypes.Structure):
            _fields_ = [
                ('cbData', wintypes.DWORD),
                ('pbData', ctypes.POINTER(ctypes.c_char)),
            ]

        buffer = ctypes.create_string_buffer(data, len(data))
        blob_in = _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
        blob_out = _DataBlob()
        # ctypes 在非 Windows 既无 windll 也无 WinDLL；经 Any 访问避免平台 attr-defined。
        # Linux 运行时 ctypes.WinDLL 抛 AttributeError → 由下方 except 回退明文。
        ctypes_any: Any = ctypes
        crypt32: Any = ctypes_any.WinDLL('crypt32')
        if protect:
            ok = crypt32.CryptProtectData(
                ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out),
            )
        else:
            # ppszDataDescr 传 None 表示不接收描述字符串
            ok = crypt32.CryptUnprotectData(
                ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out),
            )
        if not ok:
            raise OSError('DPAPI 调用失败')
        try:
            return ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            kernel32: Any = ctypes_any.WinDLL('kernel32')
            kernel32.LocalFree(blob_out.pbData)
    except AttributeError:
        # 平台性：非 Windows 无 ctypes.WinDLL/wintypes，DPAPI 不可用属合法，静默回退明文。
        return None
    except OSError:
        # 调用性：crypt32 可用但 API 失败，敏感数据将明文落盘，ERROR 明确告警
        # 便于察觉安全降级（而非静默 warning 掩盖）。
        logger.error("DPAPI %s 调用失败，敏感数据将以明文存储", '封装' if protect else '解封')
        return None
    except Exception:
        # 未预期异常（Structure/类型错误等编程 bug），ERROR 暴露而非掩盖。
        logger.error(
            "DPAPI %s 未预期异常，敏感数据将以明文存储",
            '封装' if protect else '解封', exc_info=True,
        )
        return None
