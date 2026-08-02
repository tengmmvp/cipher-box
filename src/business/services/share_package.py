"""限时加密共享包加密打包编排 — 无状态纯函数。

采集已解密条目为可移植 dict（复用 :meth:`Entry.to_dict`），AES-256-GCM 加密为
``.cboxshare`` 二进制（头纳入 GCM-AAD 防篡改，与备份格式对称），并随包写出
``decrypt.html`` 自包含浏览器解密器。

无状态：全入参注入，不持数据库连接或密钥状态，便于锁外调用与单元测试。``cancel_check``
触发时经 :class:`_ShareCancelled` 中止，编排层捕获后返回 None（不产出残缺文件）。

安全模型：每个 ``.cboxshare`` 用独立 32 字节 salt + 共享密码经 Argon2id + HKDF 域分离
派生 share 密钥；明文头（KDF 参数/过期时间/版本）纳入 GCM-AAD，使任何头篡改都致 payload
解密失败。过期时间为软限制——嵌入元数据供解密器诚实提示，无法防恶意接收方（解密即得明文）。
"""

import io
import json
import logging
import os
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import IO, Any

from ...crypto.encryption import EncryptionEngine
from ...crypto.master_key import DEFAULT_KDF_PARAMS
from ...exceptions import PayloadTooLargeError, ShareError
from ...models import Entry
from ...utils.file_security import atomic_write, validate_file_path
from ...utils.format import utc_now_iso
from ...utils.memory import secure_zero_buffer
from .password_service import PasswordService
from .share_header_codec import (
    EXPIRE_NEVER,
    MAX_SHARE_PAYLOAD_SIZE,
    SHARE_FORMAT,
    SHARE_SALT_SIZE,
    SHARE_VERSION,
    derive_share_key,
    header_aad,
    write_share_header,
)
from .share_paths import build_share_filenames
from .share_renderer import render_decrypter
from .url_hygiene import sanitize_url_scheme

logger = logging.getLogger(__name__)


class _ShareCancelled(Exception):
    """内部哨兵异常：cancel_check 触发时中止采集，编排层捕获后返回 None。

    用异常而非返回值传递「取消」，使加密核心保持单一返回类型（bytes）。
    """


def build_share_payload(
    entries: Sequence[Entry],
    *,
    include_secrets: bool,
    cancel_check: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """采集条目为可移植 payload dict。

    复用 :meth:`Entry.to_dict`：``include_secrets=False`` 时省略 password/totp_secret
    及 password 类型的 custom_fields（to_dict 内置过滤）。返回嵌套项值类型混合，故标注
    ``dict[str, Any]``（结构由解密器按 SHARE_VERSION 解释）。
    """
    items: list[dict[str, Any]] = []
    for entry in entries:
        if cancel_check and cancel_check():
            raise _ShareCancelled
        item = entry.to_dict(include_password=include_secrets)
        # URL scheme 清洗（纵深防御）：解密器仅 http/https 渲染 <a>，打包侧再清洗使
        # 共享包数据本身不含 javascript:/data: 等危险 scheme，与导入路径共用 url_hygiene。
        if "url" in item:
            item["url"] = sanitize_url_scheme(item["url"])
        items.append(item)
    return {
        "format": SHARE_FORMAT,
        "version": SHARE_VERSION,
        "created_at": utc_now_iso(),
        "entries": items,
    }


def _build_share_blob(
    entries: Sequence[Entry],
    password: str,
    *,
    include_secrets: bool,
    expire_at: int,
    created_at: int,
    cancel_check: Callable[[], bool] | None = None,
) -> bytes:
    """加密核心：返回完整 ``.cboxshare`` 字节（magic + 头 + salt + 密文块）。

    ``created_at`` 由调用方注入（便于测试确定性）；密钥派生后 try/finally 清零，
    确保异常路径不残留派生密钥。密文块为 :meth:`EncryptionEngine.encrypt_bytes` 输出
    （``CB2`` 前缀 + nonce + ct + tag，与备份格式及 WebCrypto AES-GCM 字节布局兼容）。
    """
    payload = build_share_payload(
        entries, include_secrets=include_secrets, cancel_check=cancel_check
    )
    payload_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    if len(payload_bytes) > MAX_SHARE_PAYLOAD_SIZE:
        raise PayloadTooLargeError("共享包数据过大")
    salt = _gen_salt()
    params = DEFAULT_KDF_PARAMS
    key = derive_share_key(password, salt, params)
    try:
        aad = header_aad(salt, params, expire_at, created_at)
        encrypted = EncryptionEngine.encrypt_bytes(payload_bytes, key, aad)
        buf = io.BytesIO()
        write_share_header(buf, salt, params, expire_at, created_at)
        buf.write(encrypted)
        return buf.getvalue()
    finally:
        secure_zero_buffer(key)


def _gen_salt() -> bytes:
    """生成 32 字节共享包 salt（独立函数便于测试 monkeypatch 固定值）。"""
    return os.urandom(SHARE_SALT_SIZE)


def _render_decrypter_html() -> str:
    """渲染解密器 HTML。

    顶层导入 share_renderer：两者无循环依赖（share_renderer 仅依赖 share_header_codec 的
    SHARE_VERSION，不反向引用本模块），且资源读取发生在 ``render_decrypter()`` 调用内而非
    模块加载期。保留为独立函数便于测试 monkeypatch 注入桩 HTML，避免触达真实资源。
    """
    return render_decrypter()


def create_share_package(
    entries: Sequence[Entry],
    password: str,
    *,
    include_secrets: bool,
    expire_at: int,
    output_dir: str | Path,
    cancel_check: Callable[[], bool] | None = None,
) -> tuple[Path, Path] | None:
    """创建限时加密共享包：写出 ``.cboxshare`` + ``decrypt.html`` 两文件。

    Args:
        entries: 已解密的待共享条目。
        password: 共享密码（接收方需凭此解密；应经独立渠道传递）。
        include_secrets: True 含 password/totp_secret，False 仅含非敏感字段。
        expire_at: 过期 Unix 秒（UTC）；``EXPIRE_NEVER``（0）表示永不过期。
        output_dir: 输出目录，两文件同名干、不同扩展名配对写入。
        cancel_check: 可选取消回调，返回 True 时中止并返回 None（不产出残缺文件）。

    Returns:
        成功返回 ``(share_path, decrypter_path)``；取消返回 None。密码强度不达标抛
        :class:`ShareError`，输出目录含符号链接/junction 重定向抛路径安全异常。
    """
    # 共享密码是离线攻击（窃取 .cboxshare 后暴力破解）的唯一屏障，业务层兜底防绕过
    # UI（与 create_backup 对称）。UI 已校验，此处拦截未来 CLI/自动化入口的极弱密码。
    valid, error = PasswordService.validate_master_password(password, label="共享密码")
    if not valid:
        raise ShareError(error)
    # 输出目录路径校验（与 maybe_auto_backup 对齐）：检测符号链接/junction 重定向。
    # include_secrets=True 时共享包含明文密码/TOTP，防目录被替换致明文重定向到攻击者位置。
    out = Path(str(validate_file_path(str(output_dir), check_ancestors=True)))

    created_at = int(time.time())
    try:
        blob = _build_share_blob(
            entries,
            password,
            include_secrets=include_secrets,
            expire_at=expire_at,
            created_at=created_at,
            cancel_check=cancel_check,
        )
    except _ShareCancelled:
        logger.info("共享包创建已取消")
        return None

    share_filename, decrypter_filename = build_share_filenames()
    share_path = out / share_filename
    decrypter_path = out / decrypter_filename
    decrypter_html = _render_decrypter_html()

    def _write_share(file: IO[bytes]) -> bool:
        file.write(blob)
        return True

    def _write_decrypter(file: IO[bytes]) -> bool:
        file.write(decrypter_html.encode("utf-8"))
        return True

    # 双文件原子写入：先写 .cboxshare，再写 decrypt.html；后者失败回滚删除前者，
    # 不留孤立半成品（接收方拿到无解密器的 .cboxshare 无法使用）。
    atomic_write(share_path, _write_share)
    try:
        atomic_write(decrypter_path, _write_decrypter)
    except BaseException:
        share_path.unlink(missing_ok=True)
        raise
    logger.info("共享包已创建：%s + %s", share_path.name, decrypter_path.name)
    return share_path, decrypter_path


__all__ = [
    "EXPIRE_NEVER",
    "build_share_payload",
    "create_share_package",
]
