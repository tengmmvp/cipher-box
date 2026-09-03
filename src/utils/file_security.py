"""应用数据文件的最小权限控制与原子写入 — 文件权限、安全覆写删除、独占临时文件（MAINT-117 拆分后保留的核心域）。

Unix 经 ``chmod`` 0600/0700，Windows 经 ``win_acl`` 的 ctypes 直调链（进程令牌取
SID + SetNamedSecurityInfoW，PERF-077，icacls 子进程回退）收紧为当前用户独占；
``atomic_write`` 经临时文件 + ``os.replace`` + 落地即 0600 实现原子写，消除收紧前的
世界可读窗口（SEC-015）；``secure_delete_file`` 覆写再 unlink 收缩取证还原面。
Win32 SID/ACL 链见 :mod:`src.utils.win_acl`，路径安全校验（validate_file_path）见
:mod:`src.utils.path_validation`，DPAPI 封装见 :mod:`src.utils.dpapi`（MAINT-117
按关注域拆分，公开 API 函数名/签名零变化）。
"""

import logging
import os
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ._platform import IS_WINDOWS
from .win_acl import _restrict_windows_acl

logger = logging.getLogger(__name__)

# secure_delete_file 分块覆写粒度（1MB）：恢复点/快照可达数十 MB，一次性 os.urandom(size)
# 等量分配内存，批量清理峰值 N×文件大小可能 OOM；模块级常量避免每次调用重新求值。
_SECURE_DELETE_CHUNK_BYTES = 1024 * 1024


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


def _path_is_symlink_or_reparse(path: Path) -> bool:
    """检测叶子本身是否为符号链接 / Windows reparse point/junction（``lstat`` 不跟随）。

    供 :func:`secure_delete_file` 覆写前判定：若是链接/reparse point 直接 ``unlink`` 链接本身，
    避免 purge 经恶意链接把覆写重定向到任意目标（SEC-014，与
    ``path_validation.validate_file_path`` 同源）。
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
