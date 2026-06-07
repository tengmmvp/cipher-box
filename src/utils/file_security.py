"""应用数据文件的最小权限控制。"""

import functools
import logging
import os
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)
_SECURED_WINDOWS_OBJECTS: dict[str, tuple[int, int]] = {}


@functools.lru_cache(maxsize=1)
def _windows_user_sid() -> str:
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
    try:
        stat = path.stat()
        return stat.st_dev, stat.st_ino
    except OSError:
        return None


def _restrict_windows_acl(path: Path, is_directory: bool):
    sid = _windows_user_sid()
    if not sid:
        return
    cache_key = str(path.resolve())
    identity = _windows_object_identity(path)
    if identity is not None and _SECURED_WINDOWS_OBJECTS.get(cache_key) == identity:
        return
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
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(path, 0o700)
    except OSError:
        logger.warning('无法限制目录权限：%s', path, exc_info=True)
    if os.name == 'nt':
        _restrict_windows_acl(path, True)
    return path


def secure_file(path: Path) -> Path:
    if not path.exists():
        return path
    try:
        os.chmod(path, 0o600)
    except OSError:
        logger.warning('无法限制文件权限：%s', path, exc_info=True)
    if os.name == 'nt':
        _restrict_windows_acl(path, False)
    return path
