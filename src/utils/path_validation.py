"""文件路径安全校验 — 目录遍历与 Windows 保留设备名/ADS/reparse 重定向拒绝（MAINT-117 拆分自 file_security）。

``validate_file_path`` 是中央路径安全边界：拒绝 ``..`` 遍历组件、Windows 保留设备名
（CON/PRN/COM1-9…，SEC-061）、NTFS 备用数据流冒号、``\\\\.\\``/``\\\\?\\`` 设备对象
形态（SEC-061 补强 + SEC-066 扩展）与符号链接/junction/reparse point 重定向，返回
resolved 路径供调用方使用（缩小 TOCTOU 竞态窗口）。保留设备名/ADS/设备命名空间
检查为纯字符串级分析（不依赖宿主 Path 的平台分段规则），任意平台经 monkeypatch
``IS_WINDOWS`` 即可验证 Windows 语义。
"""

import logging
import os
import re
import stat
import sys
from pathlib import Path

from ._platform import IS_WINDOWS

logger = logging.getLogger(__name__)

# Windows 保留设备名（大小写不敏感）：CON/PRN/AUX/NUL/COM1-9/LPT1-9。作为路径任一
# 组件的 stem（首个 '.' 之前的部分，含 CON.txt 带扩展名形态）出现时，Win32 文件 API
# 会将其重定向到设备而非磁盘文件——写路径静默落到设备、读路径读到设备内容。
_WINDOWS_RESERVED_DEVICE_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)

# 设备命名空间（`\\.\` 与 `\\?\`，SEC-066）下唯一放行的首组件形态：单盘符（`C:`）——
# 其后必须还有路径组件（`\\.\C:\data\file.txt`/`\\?\C:\data\file.txt`），设备对象
# 本体（裸 `\\.\C:`/`\\?\C:`）不放行。
_DRIVE_LETTER_COMPONENT = re.compile(r"^[A-Za-z]:$")


def _reject_windows_device_names_and_ads(path_text: str) -> None:
    """拒绝 Windows 保留设备名组件、NTFS 备用数据流（ADS）冒号与 ``\\\\.\\``/``\\\\?\\`` 设备对象（SEC-061）。

    仅 Windows 语义（经 ``IS_WINDOWS`` 分支调用，非 Windows 不检查：保留名是 DOS
    概念、冒号在 POSIX 是合法文件名字符）。字符串级分析而非依赖 Path 分段——宿主
    平台的 Path 按 POSIX 规则解析 Windows 形态（反斜杠是普通字符），跨平台测试经
    monkeypatch ``IS_WINDOWS`` 亦可验证本函数。

    - **保留设备名**：逐组件（按 ``\\``/``/`` 分隔）取 stem（首个 ``.`` 前、剥尾部
      空格与点，Windows 对设备名的判定在首个扩展点截断且忽略尾随空格/点）做大小写
      不敏感的整词匹配，覆盖 ``CON``/``con.txt``/``NUL.``/``COM1 `` 等形态。
    - **ADS 冒号**：剥离合法前缀（``\\\\?\\``/``\\\\.\\``/``\\\\?\\UNC\\``）与盘符
      首个冒号（``X:``）后，任何残留 ``:`` 均拒绝——``file.txt:stream`` 是 NTFS
      备用数据流语法，可借道把数据挂载到既有文件或设备名上。
    - **设备命名空间内容形态**（SEC-061 补强 + SEC-066 扩展到 ``\\\\?\\``）：
      ``\\\\.\\`` 前缀直接寻址 Win32 设备对象（无冒号形态 ``\\\\.\\PhysicalDrive0``/
      ``\\\\.\\Serial0``，裸卷 ``\\\\.\\C:`` 亦为卷设备本体），剥前缀后仅残留
      冒号/保留名检查全数放行——仅放行首组件为盘符且带后续路径的文件系统形态
      （``\\\\.\\C:\\data\\file.txt`` 有意放行），其余设备对象一律拒绝。
      ``\\\\?\\`` 文件系统 verbatim 前缀同样适用（SEC-066）：Win32 对象管理器把
      ``\\\\?\\`` 解析为 ``\\??\\``，后者与 ``\\\\.\\``（``\\??\\`` 的别名）一样查
      DOS 设备目录——``\\\\?\\PhysicalDrive0``/``\\\\?\\Serial0``/裸卷 ``\\\\?\\C:``
      同为可达的设备对象，此前仅 ``\\\\.\\`` 分支检查致三者放行。``\\\\?\\UNC\\``
      剥除前缀后是纯文件系统共享路径，豁免本检查。

    错误消息为固定文案，不回显用户输入原文（防路径形态本身经日志外泄）。
    """
    text = path_text.replace("/", "\\")
    # ---- ADS 冒号 ----
    colon_scope = text
    lowered = colon_scope.lower()
    device_scope: str | None = None
    if lowered.startswith("\\\\?\\unc\\"):
        colon_scope = colon_scope[8:]
    elif lowered.startswith("\\\\?\\"):
        colon_scope = colon_scope[4:]
        # \\?\ 同样进入设备内容形态检查（SEC-066）：\\?\ 经 \??\ 同样解析 DOS 设备
        # 目录，\\?\UNC\ 剥除后豁免（纯文件系统共享路径，无设备对象形态）。
        device_scope = colon_scope
    elif lowered.startswith("\\\\.\\"):
        colon_scope = colon_scope[4:]
        # 设备命名空间内容形态检查在其上进行（盘符冒号剥离会重绑 colon_scope，
        # 故在剥离前留存剥前缀后的范围）。
        device_scope = colon_scope
    if len(colon_scope) >= 2 and colon_scope[0].isalpha() and colon_scope[1] == ":":
        colon_scope = colon_scope[2:]
    if ":" in colon_scope:
        raise ValueError("文件路径包含非法冒号（NTFS 备用数据流或非法盘符形态）")
    # ---- 设备命名空间内容形态 ----
    if device_scope is not None:
        # 首组件必须为盘符（^X:$）且存在后续路径组件（`\\.\C:`/`\\?\C:` 裸卷是卷
        # 设备本体、`\\.\PhysicalDrive0`/`\\?\Serial0` 等无冒号首组件是设备对象，
        # 均拒绝）。
        sep = device_scope.find("\\")
        first_component = device_scope if sep < 0 else device_scope[:sep]
        if sep < 0 or _DRIVE_LETTER_COMPONENT.fullmatch(first_component) is None:
            raise ValueError("文件路径包含非法的 Windows 设备命名空间形态")
    # ---- 保留设备名 ----
    for component in text.split("\\"):
        if not component:
            continue
        stem = component.split(".", 1)[0].rstrip(" .").upper()
        if stem in _WINDOWS_RESERVED_DEVICE_NAMES:
            raise ValueError("文件路径包含 Windows 保留设备名")


def validate_file_path(
    path: str | Path,
    base_dir: Path | None = None,
    *,
    check_ancestors: bool = False,
) -> Path:
    """验证文件路径，拒绝目录遍历、路径重定向与 Windows 保留名/ADS 形态。

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
    # Windows 保留设备名与 ADS 冒号（SEC-061）：当前所有到达路径为程序生成或用户
    # 经文件对话框自选（不可利用），但本函数是中央路径安全边界——「按条目名命名
    # 导出文件」类未来功能会经此缺口把条目数据变成设备名/数据流路径。
    if IS_WINDOWS:
        _reject_windows_device_names_and_ads(str(raw))
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
