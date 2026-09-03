"""敏感操作速率限制策略，零 PyQt 依赖的业务层安全模块。

封装失败计数、锁定时间戳、过期重置等状态管理，采用递增退避策略。
经哨兵文件 + 签名 config 见证抵抗「删除状态文件即归零计数」绕过；状态文件
本体经 HMAC-SHA256 签名（SEC-029，与 config.json 同一安装级密钥体系），抵抗
「改写为格式合法内容」的篡改（归零计数绕过退避阶梯 / 伪造超大剩余秒数制造
长期锁定）；持久化剩余秒数（单调时钟）抵抗系统时钟回拨。供 UI 登录/改密
对话框及业务层调用方复用。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ...config import RATE_LIMITS
from ...utils.file_security import atomic_write, secure_file

if TYPE_CHECKING:
    from ...config import ConfigManager

logger = logging.getLogger(__name__)

# 状态文件签名行前缀：与 config.json 的 ``#__sig__:<hex>`` 同款格式（SEC-029），
# 复用同一心智模型与末行分离逻辑。
_STATE_SIG_PREFIX = "#__sig__:"

# 登录/改密限流器的状态文件名（ARCH-043 单一事实源）：状态文件须与哨兵 stem
# （``<stem>.json.sentinel``）及签名 config 的 ``security_sentinels`` 登记名（stem）
# 稳定对应，命名收归本模块，组合根（composition.build_*_rate_limiter）据此构造，
# UI 对话框不再散落文件名。stem 同时用作哨兵登记名，改名会使既有登记「孤儿化」
# （旧名见证仍在、新名按首次使用处理），勿轻改。
LOGIN_RATE_LIMIT_FILENAME = "login_rate_limit.json"
CHANGE_MASTER_RATE_LIMIT_FILENAME = "change_master_rate_limit.json"


def _split_state_signature(raw_text: str) -> tuple[str, str]:
    """分离状态文件末尾签名行，返回 (JSON 文本, 签名 hex)；无签名行返回 (原文, "")。

    按 splitlines 取末行判断（比 rsplit('\\n',1) 鲁棒——后者按最后一个换行盲切，
    JSON 体内若含签名前缀开头的行会误切），与 ConfigManager.load 的分离逻辑一致。
    """
    text = raw_text.rstrip()
    lines = text.splitlines()
    if len(lines) >= 2 and lines[-1].startswith(_STATE_SIG_PREFIX):
        return text[: -(len(lines[-1]) + 1)], lines[-1][len(_STATE_SIG_PREFIX) :]
    return raw_text, ""


def apply_rate_limit(fail_count: int) -> int:
    """根据失败次数计算锁定秒数，采用递增退避策略。

    阶梯表 ``RATE_LIMITS`` 定义于 config（(失败次数, 锁定秒数) 升序），逐档拉长
    锁定窗口提高在线暴破成本；最高阶梯同时作为状态文件删除/损坏时的降级锁定时长
    （``RATE_LIMITS[-1]``，见 :meth:`RateLimiter._load_state`），故调表须兼顾两端。

    Args:
        fail_count: 累计失败次数。

    Returns:
        应锁定的秒数，0 表示不锁定。
    """
    for threshold, seconds in reversed(RATE_LIMITS):
        if fail_count >= threshold:
            return seconds
    return 0


class RateLimiter:
    """登录/改密等敏感操作的速率限制器，采用递增退避策略。

    封装失败计数、锁定时间戳、过期重置等状态管理。

    Usage::

        limiter = RateLimiter()
        msg = limiter.check()          # None = 可继续，str = 锁定提示
        limiter.record_success()       # 重置计数
        secs = limiter.record_failure()  # 返回锁定秒数，0 表示不锁定
    """

    def __init__(
        self,
        state_path: str | Path | None = None,
        config: ConfigManager | None = None,
    ) -> None:
        self._fail_count: int = 0
        self._lock_until: float = 0.0
        self._state_path = Path(state_path) if state_path is not None else None
        self._config = config
        # 签名密钥构造期一次性解析缓存（SEC-029）：登录路径每次 check/record 都可能
        # 读写状态文件，签名/验签必须轻量（HMAC-SHA256，刻意不引入 Argon2 等耗时派生）。
        self._signing_key: bytes | None = self._resolve_signing_key()
        self._load_state()

    @property
    def fail_count(self) -> int:
        """当前累计失败次数（测试观察用只读面，MAINT-095；生产消费 check/record API）。"""
        return self._fail_count

    @property
    def state_path(self) -> Path | None:
        """限流状态文件路径（测试观察用只读面，MAINT-095；None 表示仅内存限流）。"""
        return self._state_path

    def _resolve_signing_key(self) -> bytes | None:
        """解析状态文件 HMAC 签名密钥（与 config.json 同一安装级密钥体系，SEC-029）。

        经注入的 ConfigManager 取 ``integrity_key``（ConfigKeyStore 加载的安装级
        密钥，MAINT-020），不直接感知密钥链。无 config（调用方未注入）或取密钥
        异常时退化为无签名旧格式——内存限流与哨兵删除检测仍生效，仅状态文件
        防篡改降级（与哨兵 config 见证的降级语义一致）。

        会话级临时密钥同样返回 None（SEC-057）：``config.session_only`` 表示密钥
        来自 DPAPI protect 失败的降级（SEC-055）——本会话签名落盘的状态文件下次
        启动必因密钥重新生成而验签失配，按 SEC-029 保守分支降级最高阶梯锁定
        （15 次 / 600 秒），DPAPI 持续故障时用户每次启动都误锁 10 分钟。返回 None
        走 SEC-042 既有不落盘路径（仅内存限流、不建哨兵，状态/哨兵成对缺失下次
        按首次使用处理）。
        """
        if self._config is None:
            return None
        try:
            if self._config.session_only:
                logger.warning("签名密钥为会话级临时密钥（DPAPI 降级），限流状态不落盘、仅内存生效")
                return None
            key = self._config.integrity_key
        except Exception:
            logger.warning("限流状态签名密钥获取失败，状态文件防篡改降级", exc_info=True)
            return None
        if isinstance(key, (bytes, bytearray)) and len(key) > 0:
            return bytes(key)
        return None

    @property
    def _sentinel_path(self) -> Path | None:
        """哨兵文件路径，与状态文件配对，标记限流系统已正常初始化过。

        用于区分状态文件「首次使用（哨兵缺失）」与「被恶意删除（哨兵存在）」，
        关闭「删除 login_rate_limit.json 即归零计数」的绕过路径。
        """
        if self._state_path is None:
            return None
        return self._state_path.with_name(self._state_path.name + ".sentinel")

    @property
    def _sentinel_name(self) -> str | None:
        """哨兵在签名 config 中的登记名（取状态文件 stem，如 ``login_rate_limit``）。

        供 :meth:`_register_sentinel_in_config` / :meth:`_sentinel_established_via_config`
        与签名 config 的 ``security_sentinels`` 登记对接。
        """
        if self._state_path is None:
            return None
        return self._state_path.stem

    def _ensure_sentinel(self) -> None:
        """首次成功持久化状态时创建哨兵，标记限流系统已初始化。

        创建失败仅告警不中断——哨兵为增强项，缺失仅退化为「无法检测删除」，
        不削弱限流本身。同时把哨兵登记到签名 config（幂等），使
        「状态文件 + 哨兵被同时删除」亦可经签名 config 检测。
        """
        sentinel = self._sentinel_path
        # 先登记到签名 config（幂等）：即便哨兵文件已存在（既有安装升级路径），
        # 也补登登记，避免升级后「同时删除」检测失效。登记失败不阻断——退化为
        # 仅哨兵文件配对检测，不削弱限流本身。
        self._register_sentinel_in_config()
        if sentinel is None or sentinel.exists():
            return
        try:
            sentinel.parent.mkdir(parents=True, exist_ok=True)
            sentinel.write_bytes(b"1")
            secure_file(sentinel)
        except OSError:
            logger.warning(
                "限流哨兵文件创建失败，删除检测将降级",
                exc_info=True,
            )

    def _register_sentinel_in_config(self) -> None:
        """把哨兵登记到签名 config（幂等）。无 config 时为无操作。"""
        cfg = self._config
        name = self._sentinel_name
        if cfg is None or name is None:
            return
        try:
            cfg.register_security_sentinel(name)
        except Exception:
            # config 写盘失败/校验失败等：不阻断限流，退化为仅哨兵文件配对检测。
            logger.warning(
                "限流哨兵签名登记失败，同时删除检测将降级",
                exc_info=True,
            )

    def _sentinel_established_via_config(self) -> bool:
        """经签名 config 判定哨兵是否曾建立（用于「状态+哨兵均缺失」分支）。

        - 无 config：返回 False（退回「首次使用」，不削弱保护）。
        - config 完整性失败：保守返回 True——签名 config 被篡改本身已可疑，按
          「恶意删除」降级锁定，而非采信可能被篡改的登记内容。
        - config 完整性通过：查 ``security_sentinels`` 登记记录。
        """
        cfg = self._config
        if cfg is None:
            return False
        try:
            if not cfg.check_integrity():
                return True
            name = self._sentinel_name
            return name is not None and cfg.is_security_sentinel_established(name)
        except Exception:
            # config 读取异常不阻断限流：退回「首次使用」最保守（不锁定），
            # 避免配置读取故障误锁用户；同时删除检测在此退化为仅哨兵文件配对。
            logger.warning(
                "限流哨兵签名见证读取失败，按首次使用处理",
                exc_info=True,
            )
            return False

    def _apply_max_lockdown(self) -> None:
        """降级到最高阶梯锁定（RATE_LIMITS[-1]）并持久化。

        供状态文件缺失/损坏等绕过嫌疑场景复用（QL-003，三处重复抽此方法）：最高阶梯
        既是暴破上限也是删除/损坏的降级锁定时长。
        """
        self._fail_count = RATE_LIMITS[-1][0]
        self._lock_until = time.monotonic() + RATE_LIMITS[-1][1]
        self._save_state()

    def _load_state(self) -> None:
        """加载持久化的限流状态；文件缺失/损坏/签名失败时降级最高阶梯锁定以抵抗绕过。"""
        if self._state_path is None:
            return
        if not self._state_path.exists():
            # 状态文件缺失：区分「首次使用」与「被恶意删除」。首次成功持久化
            # 状态时会同步写哨兵（见 _ensure_sentinel），故哨兵存在而状态文件
            # 缺失意味着状态被外部删除——降级到最高阶梯锁定，与「文件损坏」
            # 路径一致，避免删文件直接绕过限流。
            if self._sentinel_path is not None and self._sentinel_path.exists():
                logger.warning("限流状态文件缺失但哨兵存在，判定为被删除，降级最高阶梯锁定")
                self._apply_max_lockdown()
                return
            # 哨兵亦缺失：签名 config（HMAC）登记过哨兵建立——攻击者无法伪造签名
            # 抹除登记，故 config 记录已建立而两文件悉缺即判定为恶意删除，降级最高
            # 阶梯锁定，关闭「同时删两文件即归零计数」的绕过。无 config 见证（或读取
            # 异常）退回「首次使用」，不误伤新用户、不削弱既有保护。
            if self._sentinel_established_via_config():
                logger.warning(
                    "限流状态文件与哨兵均缺失但签名 config 记录已建立，"
                    "判定为被删除，降级最高阶梯锁定"
                )
                self._apply_max_lockdown()
            return
        try:
            raw_text = self._state_path.read_text(encoding="utf-8")
        except OSError:
            logger.warning("限流状态文件读取失败，按损坏降级最高阶梯锁定", exc_info=True)
            self._apply_max_lockdown()
            return
        json_text, stored_sig = _split_state_signature(raw_text)
        if self._signing_key is not None:
            expected_sig = hmac.new(
                self._signing_key,
                json_text.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            sig_ok = (
                bool(stored_sig)
                and stored_sig.isascii()  # compare_digest 对非 ASCII str 抛 TypeError
                and hmac.compare_digest(stored_sig, expected_sig)
            )
            if not sig_ok:
                # 状态文件被篡改（SEC-029）：哨兵/见证只防「删除」，不防「改写为格式
                # 合法内容」——改写 {"fail_count":0,...} 即归零计数绕过退避阶梯，伪造
                # 超大 remaining_seconds 可制造长期锁定。签名缺失与失配同等对待（剥离
                # 签名行是主动抹除篡改痕迹，比失配更可疑，与 config.json 完整性语义
                # 一致），按保守锁定处理，并经 _apply_max_lockdown 内的 _save_state
                # 以合法签名重建状态文件（自愈，后续加载不再重复触发本分支）。
                logger.warning("限流状态文件签名校验失败，判定为被篡改，降级最高阶梯锁定")
                self._apply_max_lockdown()
                return
        try:
            data = json.loads(json_text)
            fail_count = data.get("fail_count", 0)
            remaining_seconds = data.get("remaining_seconds", 0)
            if type(fail_count) is not int or fail_count < 0:
                raise ValueError("失败次数无效")
            if not isinstance(remaining_seconds, (int, float)) or remaining_seconds < 0:
                raise ValueError("剩余锁定时间无效")
            self._fail_count = fail_count
            # 经 remaining_seconds 在当前 monotonic 重算到期点，抵抗系统时钟回拨
            # （格式理据见 _save_state）。旧版以 time.time() 绝对时间戳持久化的状态
            # 文件无此字段，落入 except 分支降级最高阶梯锁定后以新格式重写。
            self._lock_until = (
                time.monotonic() + remaining_seconds if remaining_seconds > 0 else 0.0
            )
        except (OSError, ValueError, json.JSONDecodeError, AttributeError):
            # 状态损坏时按最高阶梯短暂锁定，避免删除/破坏状态文件直接绕过限流。
            self._apply_max_lockdown()

    def _save_state(self) -> None:
        """持久化失败计数与剩余锁定秒数（含 HMAC 签名行），经原子写入落地并补建哨兵。

        SEC-042：签名密钥不可用（``_signing_key is None``，如瞬时 keyring/DPAPI 故障）
        时**完全不落盘**，仅内存限流——若仍写无签名状态文件，下次会话密钥恢复后会按
        「签名被剥离」误判为篡改、降级最高阶梯锁定（SEC-029 的保守分支），对合法用户
        形成误锁。降级路径近乎不可达（密钥仅在构造期解析一次，无 config 的调用方本就
        不持久化），代价是跨会话计数丢失（可接受）；同时不创建哨兵，使状态文件与
        哨兵成对缺失，下次会话按首次使用处理，从根上消除「无签名状态文件」形态。
        """
        if self._state_path is None:
            return
        if self._signing_key is None:
            return
        # 持久化「剩余锁定秒数」而非绝对时间戳：单调时钟在进程间不连续，
        # 无法跨会话还原绝对到期点；存剩余秒数后加载时基于当前 monotonic 重算，
        # 既保留跨会话退避阶梯（fail_count 一并持久化），又抵抗系统时钟回拨绕过。
        remaining_seconds = (
            max(0.0, self._lock_until - time.monotonic()) if self._lock_until else 0.0
        )
        payload = json.dumps(
            {
                "fail_count": self._fail_count,
                "remaining_seconds": remaining_seconds,
            }
        )
        # 状态文件签名（SEC-029）：与 config.json 同一安装级密钥 + 同款末行签名格式，
        # 使 _load_state 可检测任何改写（含格式合法的归零/伪造锁定）。SEC-042 入口
        # 守卫保证到达此处必有签名密钥，落盘文件不存在无签名形态。
        sig = hmac.new(
            self._signing_key,
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        payload = f"{payload}\n{_STATE_SIG_PREFIX}{sig}"

        def _write_state(f: Any) -> bool:
            f.write(payload)
            return True

        try:
            # 经 atomic_write 落地即 0600（opener 回调）：消除「写入限流状态 → 关闭 →
            # secure_file 收紧」间的世界可读窗口（与 SEC-015 一致）。写盘失败（只读盘/
            # 磁盘满/权限）不中断登录流程：RateLimiter 是内存限流，持久化仅为跨会话
            # 保留；失败时内存状态仍生效，仅记日志。
            atomic_write(self._state_path, _write_state, mode="w", encoding="utf-8")
            # 状态已成功落盘：确保哨兵存在，使后续「状态文件被删除」可被检测。
            self._ensure_sentinel()
        except OSError:
            logger.warning("登录限流状态写盘失败，本次仅内存生效", exc_info=True)

    def check(self) -> str | None:
        """检查是否处于锁定状态。

        如果锁定已过期，自动重置计数。

        Returns:
            锁定提示消息，含剩余秒数；若可继续则返回 ``None``。
        """
        now = time.monotonic()
        if self._lock_until and now < self._lock_until:
            remaining = int(self._lock_until - now) + 1
            return f"尝试次数过多，请等待 {remaining} 秒后重试"
        if self._lock_until and now >= self._lock_until:
            # 锁定到期：允许重试，但保留 fail_count，使下一轮失败仍能爬升到更高
            # 退避档位。若到期即清零，攻击者每轮重置回最低档（3 次→10s→清零→…），
            # 递增退避名存实亡。保留计数后持续失败者逐档爬升；合法用户最终成功
            # 登录时由 record_success 清零，不受影响。
            self._lock_until = 0.0
            self._save_state()
        return None

    def record_success(self) -> None:
        """记录成功，重置失败计数。"""
        self._fail_count = 0
        self._lock_until = 0.0
        self._save_state()

    def record_failure(self) -> int:
        """记录失败并根据策略计算锁定秒数。

        Returns:
            锁定秒数，0 表示仅计数不锁定。
        """
        self._fail_count += 1
        lock_seconds = apply_rate_limit(self._fail_count)
        if lock_seconds > 0:
            self._lock_until = time.monotonic() + lock_seconds
        self._save_state()
        return lock_seconds
