"""应用数据文件的最小权限控制。"""

import functools
import logging
import os
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger(__name__)
_SECURED_WINDOWS_OBJECTS: dict[str, tuple[int, int]] = {}
_MAX_SECURED_CACHE = 256


@functools.lru_cache(maxsize=1)
def _windows_user_sid() -> str:
    """获取当前 Windows 用户的 SID，用于 ACL 权限设置。"""
    if os.name != 'nt':
        return ''
    try:
        result = subprocess.run(
            ['whoami', '/user', '/fo', 'csv', '/nh'],
            capture_output=True,
            text=True,
            check=True,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
        )
        columns = [item.strip().strip('"') for item in result.stdout.split(',')]
        return columns[1] if len(columns) >= 2 else ''
    except (OSError, subprocess.SubprocessError, IndexError):
        logger.warning('无法获取当前 Windows 用户 SID', exc_info=True)
        return ''


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
    if identity is not None and _SECURED_WINDOWS_OBJECTS.get(cache_key) == identity:
        return
    if len(_SECURED_WINDOWS_OBJECTS) > _MAX_SECURED_CACHE:
        _SECURED_WINDOWS_OBJECTS.clear()
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
    # 当未指定 base_dir 时，检测符号链接并记录警告。
    # 指定了 base_dir 时，resolve() 已展开符号链接，is_relative_to 检查足够。
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
