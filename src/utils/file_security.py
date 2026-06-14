"""应用数据文件的最小权限控制。"""

import csv
import io
import logging
import os
import subprocess
import sys
import threading
from collections import OrderedDict
from pathlib import Path

logger = logging.getLogger(__name__)
_SECURED_WINDOWS_OBJECTS: OrderedDict[str, tuple[int, int]] = OrderedDict()
_SECURED_LOCK = threading.Lock()
_MAX_SECURED_CACHE = 256

# 已解析的用户 SID 缓存：None=未解析；''=非 Windows 平台（运行期不变）；
# 非空串=有效 SID。Windows 下解析失败**不缓存空串**，否则一次瞬时失败
# （whoami 子进程受限/超时）会让整个会话静默跳过 ACL 限制。
_CACHED_USER_SID: str | None = None
_SID_LOCK = threading.Lock()


def _windows_user_sid() -> str:
    """获取当前 Windows 用户的 SID，用于 ACL 权限设置。

    成功解析的结果会被缓存；非 Windows 平台缓存空串。Windows 下解析失败时
    返回空串但**不缓存**——下次调用重新解析，避免瞬时失败导致整会话失效。
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
            result = subprocess.run(
                ['whoami', '/user', '/fo', 'csv', '/nh'],
                capture_output=True,
                text=True,
                check=True,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
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
        grant = subprocess.run(
            ['icacls', str(path), '/grant:r', f'*{sid}:{permission}'],
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
            timeout=10,
        )
        if grant.returncode != 0:
            raise OSError(grant.stderr.strip() or 'icacls grant failed')
        inherit = subprocess.run(
            ['icacls', str(path), '/inheritance:r'],
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
            timeout=10,
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
    """创建目录并设置最小权限，仅当前用户可访问。"""
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


def validate_file_path(path, base_dir: Path | None = None) -> Path:
    """验证文件路径，用于导入/导出/备份操作。

    解析路径并拒绝可能允许目录遍历的路径组件，
    包括通过符号链接解析到预期目录树之外的情况。

    调用方必须使用返回的 resolved 路径而非原始 path 参数，
    以避免 TOCTOU 竞态窗口。

    Note:
        Windows 上 ``is_symlink`` 不识别 junction/reparse point；高安全场景
        应显式提供 ``base_dir``，由 ``resolve()`` 展开 junction 后用
        ``is_relative_to`` 提供更强保证。

    Args:
        path: 待验证的文件路径
        base_dir: 可选的基目录约束。若提供，解析后的路径必须位于该目录下。

    Returns:
        解析后的安全路径，调用方应使用此返回值。
    """
    resolved = Path(path).resolve()
    # 拒绝含 '..' 组件的路径，防止目录遍历攻击
    parts = Path(path).parts
    if '..' in parts:
        raise ValueError('文件路径包含非法遍历组件')
    # 当未指定 base_dir 时，检测路径本身及各级父目录的符号链接作为纵深防御。
    # Windows 上 is_symlink 不识别 junction/reparse point，补充检测
    # FILE_ATTRIBUTE_REPARSE_POINT (0x400)，覆盖 junction 与挂载点重定向——
    # 本项目主平台为 Windows（数据目录 %APPDATA%），此补充关闭 is_symlink 的盲区。
    # 该检测具 TOCTOU 性质（检测与后续 open 间可被替换），仅在本地威胁模型下有效；
    # 高安全场景应显式提供 base_dir，由 resolve()+is_relative_to 提供更强保证。
    if base_dir is None:
        current = Path(path)
        while current != current.parent:  # 未到根目录
            if current.is_symlink():
                raise ValueError(f'路径组件包含符号链接，拒绝访问: {current}')
            if sys.platform == 'win32':
                try:
                    # st_file_attributes 为 Windows 专有属性，getattr 兜底跨平台访问
                    attrs = getattr(current.lstat(), 'st_file_attributes', 0)
                    if attrs & 0x400:
                        raise ValueError(
                            f'路径组件包含 reparse point/junction，拒绝访问: {current}'
                        )
                except OSError:
                    pass
            current = current.parent
    if base_dir is not None:
        base_resolved = Path(base_dir).resolve()
        if not resolved.is_relative_to(base_resolved):
            raise ValueError('文件路径超出允许的目录范围')
    return resolved


def secure_file(path: Path, *, strict: bool = False) -> Path:
    """设置文件最小权限，仅当前用户可读写。"""
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
    finally:
        # missing_ok=True 防御 stat 与 unlink 间的 TOCTOU（文件被外部删除），
        # 避免此时抛 FileNotFoundError 中断清理循环。
        path.unlink(missing_ok=True)
