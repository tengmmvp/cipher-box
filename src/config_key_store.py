"""安装级 HMAC 签名密钥的平台安全存储链 — DPAPI / keyring / 明文回退。

从 config.py 下沉的独立职责（MAINT-020）：签名密钥的加载/生成/存储仅依赖
``key_path`` 与 ``data_dir``，与配置读写无关。:class:`src.config.ConfigManager`
组合持有本存储；需要对本地状态文件做 HMAC 完整性签名的模块（如 RateLimiter）
亦复用同一密钥（经 ConfigManager 暴露的 ``integrity_key`` 注入，保持依赖方向
business→config 单向、不反向 import）。

平台链（收缩 SEC-003 篡改攻击面，使 config.key 被读取也无法在别处解密重算签名）：

- **Windows**：DPAPI（当前用户凭据）封装存于 config.key。
- **macOS / Linux**：经 keyring 存入系统密钥链（Keychain / Secret Service）。

降级语义（SEC-055，读侧只认平台安全存储形态）：

- **非 Windows**：keyring 不可用（headless Linux / CI 无 Secret Service、keyring
  未安装或后端失败）时回退明文 0600 config.key 并记 ERROR，使安全降级可见——读侧
  ``_load_plaintext_integrity_key`` 接受明文形态，回退链闭环。
- **Windows**：DPAPI protect 失败时**不落盘**（读侧只认 DPAPI 封装，明文文件下次
  启动必被判损坏），内存密钥仅本会话有效并记 CRITICAL；下次启动重新生成新密钥。
  绝不阻断启动。该会话级降级经 ``session_only`` 标记对外可见（SEC-057）：签名方
  （如 RateLimiter）据此拒绝以临时密钥签名落盘，避免下次启动签名失配误判。
- **写盘失败**（SEC-065）：密钥文件写入抛 OSError（磁盘满/只读介质——Windows 的
  DPAPI 封装写盘与非 Windows 的明文回退写盘两个分支）同样降级会话级（内存密钥 +
  CRITICAL + ``session_only``），绝不阻断启动——经 ``ConfigManager.__init__`` 的
  启动链此前对该异常全链无捕获，启动即崩。

非 Windows 的明文回退在 keyring 恢复可用后一次性回迁系统密钥链并清理明文文件
（SEC-003 粘滞修复），使平台安全存储保护对「keyring 曾故障」的安装重新生效；
keyring 记录损坏走新生成并成功写入后，明文残留同款清理覆盖该路径（SEC-070）。
"""

import base64
import hashlib
import logging
import os
from pathlib import Path
from typing import Any

from .utils._platform import IS_WINDOWS
from .utils.dpapi import protect_with_dpapi, unprotect_with_dpapi
from .utils.file_security import (
    atomic_write,
    secure_delete_file,
    secure_directory,
    secure_file,
)

logger = logging.getLogger(__name__)

# 签名密钥长度（AES-256 同级对称强度，HMAC-SHA256 密钥标准长度）。
_KEY_SIZE = 32
# keyring 服务名与条目名前缀（非 Windows 平台经系统密钥链存储签名密钥，SEC-003）。
# 条目名按安装目录派生（见 _keyring_entry_name），不同安装互不共享密钥。
_KEYRING_SERVICE = "CipherBox"
_KEYRING_KEY_PREFIX = "config-integrity-key"


class ConfigKeyStore:
    """安装级 HMAC 签名密钥的加载/生成与平台安全存储。

    构造入参仅 ``key_path``（明文回退/DPAPI 封装的密钥文件路径）与 ``data_dir``
    （keyring 条目名派生 + 权限加固目标），无配置读写依赖，供 ConfigManager
    与状态文件签名方共用同一安装级密钥。
    """

    def __init__(self, key_path: Path, data_dir: Path) -> None:
        self._key_path = key_path
        self._data_dir = data_dir
        # 会话级临时密钥标记（SEC-057）：三处持久化失败分支置位——Windows DPAPI
        # protect 失败（SEC-055）、平台安全存储写盘 OSError（SEC-065）、非 Windows
        # 明文回退写盘 OSError（SEC-065），统一经 _degrade_to_session_only 收口。
        self._session_only = False

    @property
    def key_path(self) -> Path:
        """明文回退 / DPAPI 封装形态的密钥文件路径（平台安全存储可用时不落此文件）。"""
        return self._key_path

    @property
    def session_only(self) -> bool:
        """当前密钥是否为平台安全存储不可用时的会话级临时密钥（SEC-057）。

        True 表示密钥未能持久化到任何持久位置——Windows DPAPI protect 失败
        （SEC-055 降级）或密钥文件写盘 OSError（SEC-065 的 DPAPI 封装写盘 /
        非 Windows 明文回退写盘两个分支）——本会话签名的任何内容下次启动都会
        因密钥重新生成而失配。签名落盘方（如 RateLimiter 状态文件）应据此拒绝
        落盘，改走仅内存路径；经 :class:`src.config.ConfigManager` 的
        ``session_only`` property 透出。
        """
        return self._session_only

    def load_or_create(self) -> bytes:
        """加载安装级签名密钥；缺失/损坏时原子生成新密钥。

        平台安全存储优先（收缩 SEC-003 篡改攻击面，使 config.key 被读取也无法在
        别处解密重算签名）：

        - **Windows**：DPAPI（当前用户凭据）封装存于 config.key。
        - **macOS / Linux**：经 keyring 存入系统密钥链（Keychain / Secret Service）。

        平台安全存储失败时的降级（SEC-055）：非 Windows 回退明文 0600 config.key
        并记 ERROR（读侧接受明文形态，回退链闭环）；Windows 读侧只认 DPAPI 封装
        （SEC-052），写明文文件 = 下次启动必被判损坏，故不落盘——内存密钥仅本会话
        有效并记 CRITICAL（``session_only`` 置位，SEC-057），下次启动重新生成。
        绝不阻断启动。
        """
        # strict=False：启动路径绝不阻断。Windows SID 解析失败（EDR/企业策略禁用
        # whoami）时 restrict_windows_acl 会抛 OSError 致启动崩溃，违背本方法
        # 「绝不阻断启动」契约。权限加固失败降级（warning）而非阻断启动。
        secure_directory(self._data_dir, strict=False)
        key = self._load_secure_integrity_key()
        if key is not None and len(key) == _KEY_SIZE:
            return key
        key = os.urandom(_KEY_SIZE)
        try:
            stored = self._store_secure_integrity_key(key)
        except OSError:
            # 平台安全存储写盘抛 OSError（SEC-065）：Windows 上 protect 成功但
            # _write_integrity_key_file 的 atomic_write（secure_file strict=True）
            # 在磁盘满/只读介质上抛出——沿调用链（ConfigManager.__init__ → 本方法）
            # 此前全链无捕获，启动即崩，违背「绝不阻断启动」契约。与 protect 失败
            # 同款降级：内存密钥本会话运行 + session_only 置位（签名落盘方拒以临时
            # 密钥签名，SEC-057），CRITICAL 如实暴露持久化失败。
            self._degrade_to_session_only(
                "签名密钥安全持久化写盘失败（磁盘满/只读介质），config.key 未写入"
            )
            return key
        if not stored:
            if IS_WINDOWS:
                # win32 明文回退名存实亡（SEC-055）：读侧只认 DPAPI 封装（SEC-052），
                # 「写明文 32 字节 + 下次判损坏」的组合会使用户看到假「配置文件完整
                # 性校验失败，可能已被篡改」告警、敏感键回退默认、RateLimiter 状态
                # 签名失配降级到最大锁定——根因却是本机 DPAPI 不可用而非篡改。改为
                # 不写任何文件：内存密钥运行本会话，CRITICAL 如实暴露「密钥未能安全
                # 持久化」；下次启动经「文件缺失 → 重新生成」路径，签名失配告警与
                # 本条日志共同构成可诊断的诚实信号。
                # session_only 置位（SEC-057）：限流状态等「签名落盘可失配」的消费方
                # 据此拒绝以临时密钥签名落盘——本会话落盘的状态文件下次启动必因密钥
                # 重新生成而验签失配，按 SEC-029 保守分支降级最高阶梯锁定（15 次 /
                # 600 秒），DPAPI 持续故障时用户每次启动都要白等 10 分钟。
                self._degrade_to_session_only(
                    "签名密钥未能经 DPAPI 安全持久化（protect 调用失败）：本次会话"
                    "以内存密钥运行、config.key 未写入。请检查系统 DPAPI 服务可用性"
                )
                return key
            # keyring 不可用（非 Windows）：回退明文 0600。本地有读权限者可重算签名
            # 伪造安全配置（SEC-003）。_write_integrity_key_file 经 atomic_write 创建
            # 即 0600，消除世界可读窗口（SEC-015）。ERROR 使降级可见，提示启用系统
            # 密钥链。
            try:
                self._write_integrity_key_file(key)
            except OSError:
                # 明文回退同样写盘失败（SEC-065，磁盘满/只读介质）：与平台安全存储
                # 写盘失败同款会话级降级，绝不因密钥持久化失败阻断启动。
                self._degrade_to_session_only(
                    "签名密钥明文回退写盘失败（磁盘满/只读介质），config.key 未写入"
                )
                return key
            logger.error(
                "签名密钥回退明文存储（平台安全存储不可用）：本地读权限者可重算"
                "签名篡改安全配置，建议启用系统密钥链（SEC-003）"
            )
            # 密钥最终形态为明文回退：刚写入的明文文件是其持久载体而非残留，
            # 清理前置条件（平台安全存储已供应）不成立，不得触发残留清理。
            return key
        # 新生成密钥已成功持久化到平台安全存储（stored=True）：明文残留统一清理
        # （SEC-070）——前置条件「密钥已由平台安全存储有效供应」成立（keyring 命中
        # 有效密钥或新生成已持久化，SEC-067），旧明文密钥已退役（新密钥生效，旧
        # 签名本就会失配告警并经下次保存自愈），删除无「销毁可能唯一有效回退」之
        # 虞。win32 豁免在 _purge_plaintext_key_residue 内评估一次（stored=True 时
        # key_path 刚被 DPAPI 封装写占、非明文残留，且 win32 无明文回退形态，
        # SEC-055），调用方不再各自重推导平台条件。
        self._purge_plaintext_key_residue("新生成密钥已写入系统密钥链，旧明文回退退役")
        return key

    def _degrade_to_session_only(self, reason: str) -> None:
        """密钥未能持久化时的会话级降级（SEC-055/057/065 统一收口）。

        三处降级共用：Windows protect 失败（SEC-055）、平台安全存储写盘 OSError
        （SEC-065）、非 Windows 明文回退写盘 OSError（SEC-065）——共同语义是密钥
        未落到任何持久位置、仅本会话有效。置位 ``session_only`` 使签名落盘方（如
        RateLimiter 状态文件）拒以临时密钥签名落盘（SEC-057：本会话签名的内容下次
        启动必因密钥重新生成而验签失配，按 SEC-029 保守分支降级最高阶梯锁定）；
        CRITICAL 如实暴露「密钥未能持久化」，下次启动重新生成，既有签名失配告警
        与本条日志共同构成可诊断的诚实信号。
        """
        self._session_only = True
        logger.critical(
            "%s：本次会话以内存密钥运行；下次启动将重新生成新密钥，既有 config/"
            "限流状态签名会如实报告失配",
            reason,
        )

    def _load_secure_integrity_key(self) -> bytes | None:
        """从平台安全存储读取签名密钥，损坏或缺失返回 None。"""
        if IS_WINDOWS:
            return self._load_dpapi_integrity_key()
        return self._load_keyring_integrity_key()

    def _store_secure_integrity_key(self, key: bytes) -> bool:
        """存入平台安全存储，成功返回 True。

        失败时调用方按平台降级（SEC-055）：非 Windows 回退明文文件；Windows 保持
        内存密钥运行本会话、不落盘（见 :meth:`load_or_create`）。
        """
        if IS_WINDOWS:
            return self._store_dpapi_integrity_key(key)
        return self._store_keyring_integrity_key(key)

    # ---- Windows DPAPI 文件存储 ----
    def _load_dpapi_integrity_key(self) -> bytes | None:
        if not self._key_path.exists():
            return None
        try:
            blob = self._key_path.read_bytes()
        except (FileNotFoundError, OSError):
            # exists() 与 read_bytes() 间 TOCTOU 或瞬时 IO 错误：与损坏分支一致 fall-through。
            logger.warning("读取签名密钥失败，将生成新密钥", exc_info=True)
            return None
        key = unprotect_with_dpapi(blob)
        if key is not None and len(key) == _KEY_SIZE:
            # strict=False：启动路径，权限加固失败降级而非崩溃。
            secure_file(self._key_path, strict=False)
            return key
        # 非 DPAPI 封装形态（含长度恰为 32 字节的明文）一律按损坏处理（SEC-052，
        # 退役 SEC-021 的一次性明文迁移分支）：项目未发布不存在 pre-SEC-003 遗留
        # 安装，「合法长度明文」这一特殊接受形态徒增审计解释成本。返回 None 走
        # 「生成新密钥 → 旧签名失效 → 完整性告警与敏感键回退」路径，Windows 上
        # config.key 仅认 DPAPI 封装一种合法形态。
        logger.warning("签名密钥损坏，将生成新密钥")
        return None

    def _store_dpapi_integrity_key(self, key: bytes) -> bool:
        """经 DPAPI 封装写入密钥文件；protect 失败不落盘、返回 False（SEC-055）。

        读侧（:meth:`_load_dpapi_integrity_key`）只认 DPAPI 封装形态（SEC-052），
        明文文件下次启动必被判损坏。故 protect 失败时绝不写明文兜底——返回 False
        交由 :meth:`load_or_create` 走显式降级（内存密钥会话级运行 + CRITICAL），
        而非「返回 True + 落一个下次必被判损坏的文件」的自欺组合。
        """
        stored = protect_with_dpapi(key)
        if stored is None:
            return False
        self._write_integrity_key_file(stored)
        return True

    # ---- 非 Windows keyring 存储（Keychain / Secret Service）----

    def _keyring_entry_name(self) -> str:
        """按安装目录派生 keyring 条目名，使不同安装互不共享签名密钥。

        条目名若全局固定，同一用户下多个安装（不同 data_dir）会读写同一条
        Keychain / Secret Service 记录——一处安装的签名密钥可用于伪造另一处
        安装的 config 签名，破坏「每安装独立密钥」前提。以 data_dir 解析后
        路径的哈希作后缀区分；未发布项目，旧固定条目不做迁移。
        """
        digest = hashlib.sha256(str(self._data_dir.resolve()).encode("utf-8")).hexdigest()[:16]
        return f"{_KEYRING_KEY_PREFIX}:{digest}"

    def _load_keyring_integrity_key(self) -> bytes | None:
        try:
            import keyring
        except ImportError:
            logger.error("keyring 未安装，签名密钥回退明文（SEC-003）")
            return self._load_plaintext_integrity_key()
        try:
            value = keyring.get_password(_KEYRING_SERVICE, self._keyring_entry_name())
        except Exception:
            # 后端不可用（headless Linux 无 Secret Service 等）：回退明文。
            logger.error("keyring 读取失败，回退明文存储（SEC-003）", exc_info=True)
            return self._load_plaintext_integrity_key()
        if value:
            try:
                key = base64.b64decode(value, validate=True)
            except ValueError:
                # binascii.Error IS-A ValueError
                logger.warning("keyring 中签名密钥损坏，将生成新密钥")
                return None
            if len(key) != _KEY_SIZE:
                # 可解码但长度错（SEC-067 修复）：按损坏记录处理走新生成——且清理
                # 明文残留文件的前置条件是「keyring 命中**有效**密钥」（长度校验须
                # 先于 secure_delete）。原实现先删明文文件再由 load_or_create 验长度，
                # keyring 值损坏（可解码但非 32 字节）时会把可能唯一有效的明文回退
                # 密钥一并销毁——K1 签名链锁死在断裂态（config 完整性告警 + 限流状态
                # 失配），且明文文件已删无自愈路径。
                logger.warning("keyring 中签名密钥长度异常，将生成新密钥")
                return None
            # keyring 命中（密钥有效）时的明文残留统一清理（SEC-067）：keyring 故障
            # 降级期写入的明文 config.key 在两个形态下残留——a) 降级期后 keyring 恢复、
            # 回迁成功但 secure_delete 失败（占用/权限），下次启动 keyring 直接命中，
            # 旧「迁移失败再清理」分支不再进入；b) keyring 记录损坏/重生成后新密钥已
            # 入 keyring，降级期明文文件遗留。密钥既已由 keyring 供应，明文文件只是
            # 「本地读权限者可重算签名」的暴露面（SEC-003），无论来源统一尝试覆写删除
            # （清理实现与新生成路径共用 _purge_plaintext_key_residue，SEC-070）。
            self._purge_plaintext_key_residue("密钥已由系统密钥链供应")
            return key
        # keyring 本会话可用但无记录：读明文回退密钥（keyring 故障期写入的形态）。
        # SEC-003 粘滞修复：原实现只回读明文文件、永不回写 keyring——keyring 恢复后
        # SEC-003 保护对该安装持续失效。改为一次性回迁：密钥写入 keyring 成功后
        # 清理明文 config.key（统一走 _purge_plaintext_key_residue chokepoint，
        # SEC-067/070 的第三处内联 secure_delete 收敛），收缩「本地读权限者可重算
        # 签名」的暴露面；迁移失败保持明文回退现状并记 ERROR，绝不阻断启动。
        plaintext_key = self._load_plaintext_integrity_key()
        if plaintext_key is None:
            return None
        if not self._store_keyring_integrity_key(plaintext_key):
            logger.error("keyring 已恢复可用但签名密钥回迁失败，继续使用明文回退（SEC-003）")
            return plaintext_key
        # 回迁成功即「密钥已由平台安全存储有效供应」：明文文件退役清理（失败由
        # chokepoint 记 ERROR 不阻断启动，下次启动 keyring 命中分支重试）。
        self._purge_plaintext_key_residue("明文回退密钥已回迁系统密钥链")
        return plaintext_key

    def _purge_plaintext_key_residue(self, reason: str) -> None:
        """清理明文密钥残留文件的单一 chokepoint（幂等，失败 ERROR 不阻断启动）。

        前置条件由调用方保证——密钥已由平台安全存储有效供应（keyring 命中有效
        密钥、明文回退回迁成功，或新生成密钥已成功持久化）。此时同盘的明文
        config.key 只是「本地读权限者可重算签名」的暴露面（SEC-003）：不存在即
        no-op；覆写删除失败记 ERROR 不阻断启动，下次启动重试。

        win32 豁免在本 chokepoint 内评估一次（SEC-070 演进：原先各调用方自带
        ``sys.platform != "win32"`` 前置重推导，且 SEC-003 迁移处存在内联
        secure_delete 的第三触发点）：win32 下 key_path 是 DPAPI 封装本体而非
        明文残留（stored=True 时刚被写占），且 win32 无明文回退形态（SEC-055），
        恒 no-op——平台判定经 IS_WINDOWS 常量（MAINT-012 单一事实源；测试打桩
        patch 本模块的 IS_WINDOWS 绑定，见 _platform docstring 的约定）。
        """
        if IS_WINDOWS or not self._key_path.exists():
            return
        try:
            secure_delete_file(self._key_path)
            logger.info("检测并清理明文密钥残留文件（%s）", reason)
        except OSError:
            logger.error(
                "明文密钥残留文件清理失败，建议手动删除该文件（SEC-067）",
                exc_info=True,
            )

    def _store_keyring_integrity_key(self, key: bytes) -> bool:
        try:
            import keyring

            keyring.set_password(
                _KEYRING_SERVICE,
                self._keyring_entry_name(),
                base64.b64encode(key).decode("ascii"),
            )
            return True
        except Exception:
            # 后端不可用或写入失败：调用方回退明文 0600。
            logger.warning("keyring 存储失败，将回退明文 0600（SEC-003）", exc_info=True)
            return False

    # ---- 明文回退（平台安全存储不可用时）----
    def _load_plaintext_integrity_key(self) -> bytes | None:
        if not self._key_path.exists():
            return None
        try:
            blob = self._key_path.read_bytes()
        except (FileNotFoundError, OSError):
            return None
        if len(blob) == _KEY_SIZE:
            secure_file(self._key_path, strict=False)
            return blob
        return None

    def _write_integrity_key_file(self, data: bytes) -> None:
        """经 atomic_write 落地即 0600 写入密钥文件（消除世界可读窗口，SEC-015）。"""

        def _write_key(f: Any) -> bool:
            f.write(data)
            return True

        atomic_write(self._key_path, _write_key, mode="wb")
