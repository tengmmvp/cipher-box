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


def _restrict_windows_acl(path: Path, is_directory: bool):
    """限制文件或目录的 ACL 权限为当前用户独占访问。"""
    sid = _windows_user_sid()
    if not sid:
        logger.warning('无法获取 Windows 用户 SID，跳过 ACL 权限限制：%s', path)
        return
    cache_key = str(path.resolve())
    identity = _windows_object_identity(path)
    with _SECURED_LOCK:
        cached = _SECURED_WINDOWS_OBJECTS.get(cache_key)
        if identity is not None and cached == identity:
            # LRU：命中时更新为最近使用，避免常用路径被淘汰
            _SECURED_WINDOWS_OBJECTS.move_to_end(cache_key)
            return
    with _SECURED_LOCK:
        # LRU 淘汰最旧条目，而非全量清空，避免频繁重建反复调用 icacls
        while len(_SECURED_WINDOWS_OBJECTS) > _MAX_SECURED_CACHE:
            _SECURED_WINDOWS_OBJECTS.popitem(last=False)
    permission = '(OI)(CI)F' if is_directory else 'F'
    common = {
        'capture_output': True,
        'text': True,
        'creationflags': getattr(subprocess, 'CREATE_NO_WINDOW', 0),
    }
    try:
        grant = subprocess.run(
            ['icacls', str(path), '/grant:r', f'*{sid}:{permission}'],
            timeout=10,
            **common,
        )
        if grant.returncode != 0:
            raise OSError(grant.stderr.strip() or 'icacls grant failed')
        inherit = subprocess.run(
            ['icacls', str(path), '/inheritance:r'],
            timeout=10,
            **common,
        )
        if inherit.returncode != 0:
            raise OSError(inherit.stderr.strip() or 'icacls inheritance failed')
        if identity is not None:
            with _SECURED_LOCK:
                _SECURED_WINDOWS_OBJECTS[cache_key] = identity
    except (OSError, subprocess.TimeoutExpired):
        logger.warning('无法限制文件 ACL：%s', path, exc_info=True)


def secure_directory(path: Path) -> Path:
    """创建目录并设置最小权限，仅当前用户可访问。"""
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if sys.platform != 'win32':
        try:
            os.chmod(path, 0o700)
        except OSError:
            logger.warning('无法限制目录权限：%s', path, exc_info=True)
    if os.name == 'nt':
        _restrict_windows_acl(path, True)
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
    # 当未指定 base_dir 时，检测符号链接作为纵深防御。该检测基于 is_symlink()
    # 存在 TOCTOU 性质（检测与后续 open 之间可被替换），仅在本地威胁模型下有效；
    # 高安全场景应显式提供 base_dir，由 resolve()+is_relative_to 提供更强保证。
    if base_dir is None and Path(path).is_symlink():
        raise ValueError(f'检测到符号链接，拒绝访问: {path}')
    # 检查父目录中的符号链接
    if base_dir is None:
        current = Path(path).parent
        while current != current.parent:  # 未到根目录
            if current.is_symlink():
                raise ValueError(f'父目录包含符号链接，拒绝访问: {current}')
            current = current.parent
    if base_dir is not None:
        base_resolved = Path(base_dir).resolve()
        if not resolved.is_relative_to(base_resolved):
            raise ValueError('文件路径超出允许的目录范围')
    return resolved


def secure_file(path: Path) -> Path:
    """设置文件最小权限，仅当前用户可读写。"""
    if not path.exists():
        return path
    if sys.platform != 'win32':
        try:
            os.chmod(path, 0o600)
        except OSError:
            logger.warning('无法限制文件权限：%s', path, exc_info=True)
    if os.name == 'nt':
        _restrict_windows_acl(path, False)
    return path
