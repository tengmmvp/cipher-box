"""TOTP 验证码生成器 — 基于 RFC 6238 实现。"""

import base64
import binascii
import hmac
import logging
import struct
import time
from urllib.parse import parse_qs, urlparse

from ..utils.memory import secure_zero_buffer

logger = logging.getLogger(__name__)

# Base32 标准化时一次性剥离的常见分隔符（空格、连字符、点、下划线）。
_BASE32_STRIP_TABLE = str.maketrans("", "", " -._")

# period 上限：超长 period（如 999999）会让 TOTP 几乎不变、退化为静态码，用户难
# 察觉异常。1–300 秒覆盖所有合法场景（RFC 默认 30s，少数 60s），拒绝极端值防退化。
_MAX_TOTP_PERIOD = 300


class TOTPGenerator:
    """基于时间的一次性密码 TOTP 生成器。"""

    DEFAULT_PERIOD = 30  # 时间步长，单位为秒
    DEFAULT_DIGITS = 6  # 验证码位数

    ALGO_MAP = {
        "SHA1": "sha1",
        "SHA256": "sha256",
        "SHA512": "sha512",
    }

    # 密钥前缀 -> 算法，从 ALGO_MAP 派生（新增算法自动跟随）。含 SHA1：与 SHA256/SHA512
    # 对称识别并剥离前缀，避免 ``SHA1:SECRET`` 因 ':' 残留致 base32 解码报错（SHA1 为
    # 默认算法，剥离后按默认处理，行为与无前缀一致）。
    _PREFIX_MAP = {f"{a}:": a for a in ALGO_MAP}

    @staticmethod
    def _parse_secret(secret: str) -> tuple[str, str]:
        """解析密钥字符串，提取算法和实际密钥。

        'SHA256:'/'SHA512:' 前缀触发对应算法，否则默认 SHA1。

        Args:
            secret: 可能带算法前缀的密钥字符串

        Returns:
            由算法名和去除前缀后的密钥组成的元组
        """
        secret = secret.strip()
        for prefix, algo in TOTPGenerator._PREFIX_MAP.items():
            if secret.upper().startswith(prefix):
                return algo, secret[len(prefix) :].strip()
        return "SHA1", secret

    @staticmethod
    def _parse_config(
        secret: str,
        algorithm: str,
        period: int,
        digits: int,
    ) -> tuple[str, str, int, int]:
        """解析 Base32、算法前缀或标准 otpauth URI。

        算法优先级（高 → 低）：secret 内嵌前缀 > otpauth URI ``algorithm`` 参数 >
        调用方传入的默认值。冲突时 secret 前缀胜出。
        """
        value = secret.strip()
        if value.lower().startswith("otpauth://"):
            parsed = urlparse(value)
            if parsed.netloc.lower() != "totp":
                raise ValueError("仅支持 TOTP URI")
            query = parse_qs(parsed.query)
            # parse_qs 已做百分号解码，勿再 unquote（双重解码会把 secret 中 %XX 当
            # 转义再次解码，损坏密钥）。
            value = query.get("secret", [""])[0].strip()
            if not value:
                raise ValueError("otpauth URI 中缺少 secret 参数")
            algorithm = query.get("algorithm", [algorithm])[0].upper()
            try:
                period = int(query.get("period", [period])[0])
            except (ValueError, TypeError) as exc:
                raise ValueError("TOTP period 必须为整数") from exc
            try:
                digits = int(query.get("digits", [digits])[0])
            except (ValueError, TypeError) as exc:
                raise ValueError("TOTP digits 必须为整数") from exc
        parsed_algo, value = TOTPGenerator._parse_secret(value)
        if parsed_algo != "SHA1":
            algorithm = parsed_algo
        if algorithm not in TOTPGenerator.ALGO_MAP:
            raise ValueError("不支持的算法")
        if not (1 <= period <= _MAX_TOTP_PERIOD) or digits not in (6, 7, 8):
            raise ValueError("TOTP 参数无效")
        return algorithm, value, period, digits

    @staticmethod
    def _compute_totp(
        key: bytes | bytearray,
        algo_name: str,
        period: int,
        digits: int,
        *,
        now: float | None = None,
    ) -> str:
        """核心 TOTP 计算：HMAC + 动态截断 + 取模。

        ``now`` 为可注入时钟（Unix 秒），供计数器边界测试精确控制时间步，无需
        monkeypatch 全局 ``time.time``；生产路径不传，保持实时取值。
        """
        # 防御 period<=0 除零：绕过 _parse_config 直接调用时（如未来重构）的守卫。
        if period <= 0:
            raise ValueError("TOTP period 必须为正数")
        counter = int(time.time() if now is None else now) // period
        msg = struct.pack(">Q", counter)
        hmac_hash = hmac.new(key, msg, algo_name).digest()
        offset = hmac_hash[-1] & 0x0F
        code = struct.unpack(">I", hmac_hash[offset : offset + 4])[0]
        code &= 0x7FFFFFFF
        code %= 10**digits
        return str(code).zfill(digits)

    @staticmethod
    def _generate_impl(
        secret: str,
        algorithm: str,
        period: int,
        digits: int,
        *,
        now: float | None = None,
    ) -> tuple[str, Exception | None]:
        """TOTP 生成的共享实现。

        ``now`` 透传至 :meth:`_compute_totp`，供计数器边界测试控制时间步；生产路径
        （:meth:`generate` / :meth:`generate_or_raise`）不传。

        Returns:
            由验证码和错误对象组成的元组。成功时错误对象为 None，失败时验证码为空字符串。
        """
        if not secret:
            return "", ValueError("TOTP 密钥不能为空")

        try:
            algorithm, raw_secret, period, digits = TOTPGenerator._parse_config(
                secret, algorithm, period, digits
            )
        except (TypeError, ValueError) as exc:
            return "", ValueError(f"TOTP 密钥格式无效: {exc}")

        algo_name = TOTPGenerator.ALGO_MAP.get(algorithm)
        if algo_name is None:
            # _parse_config 已校验 algorithm，此分支为纵深防御，防止绕过校验时 KeyError 冒泡。
            return "", ValueError("不支持的 TOTP 算法")

        try:
            # 解码为 bytearray 以便用毕原地清零（bytes 不可变只能清零副本）。
            # TOTP 种子是长效认证机密，与主密钥清零纪律对齐。
            key = bytearray(
                base64.b32decode(TOTPGenerator._normalize_base32(raw_secret), casefold=True)
            )
        except (binascii.Error, ValueError) as exc:
            return "", ValueError(f"TOTP Base32 解码失败: {exc}")

        try:
            return TOTPGenerator._compute_totp(key, algo_name, period, digits, now=now), None
        finally:
            # CPython 固有限制：hmac.new 内部构造的 ipad/opad 副本仍依赖 GC 回收，
            # 此处只收缩外部一份引用，非完全擦除。
            secure_zero_buffer(key)

    @staticmethod
    def generate(
        secret: str,
        algorithm: str = "SHA1",
        period: int = DEFAULT_PERIOD,
        digits: int = DEFAULT_DIGITS,
    ) -> str:
        """生成当前 TOTP 验证码。

        Args:
            secret: Base32 编码的密钥，支持 'SHA256:SECRET' 或 'SHA512:SECRET' 前缀
            algorithm: 哈希算法，取值 SHA1、SHA256 或 SHA512；当前缀存在时被覆盖
            period: 时间步长，单位为秒
            digits: 验证码位数

        Returns:
            TOTP 验证码字符串，失败时返回空字符串。

        Note:
            静默失败是有意设计：用于定时器刷新等非交互场景，弹出错误框会干扰用户。
            如需错误传播，使用 generate_or_raise()。
        """
        code, error = TOTPGenerator._generate_impl(secret, algorithm, period, digits)
        if error is not None:
            logger.warning("TOTP 生成失败: %s", error)
            return ""
        return code

    @staticmethod
    def generate_or_raise(
        secret: str,
        algorithm: str = "SHA1",
        period: int = DEFAULT_PERIOD,
        digits: int = DEFAULT_DIGITS,
    ) -> str:
        """生成当前 TOTP 验证码，失败时抛出异常而非静默返回空串。

        参数和返回值与 generate() 相同，适用于密钥验证等需向用户展示具体错误的场景。

        Raises:
            ValueError: 密钥格式无效或 Base32 解码失败
        """
        code, error = TOTPGenerator._generate_impl(secret, algorithm, period, digits)
        if error is not None:
            raise error
        return code

    @staticmethod
    def get_remaining_seconds(period: int = DEFAULT_PERIOD, secret: str = "") -> int:
        """获取当前时间步长剩余秒数。"""
        if secret:
            period = TOTPGenerator._extract_period(secret, period)
        # 防御 period<=0 导致取模除零或负倒计时，与 _extract_period 的正数校验对齐。
        if period <= 0:
            period = TOTPGenerator.DEFAULT_PERIOD
        return period - (int(time.time()) % period)

    @staticmethod
    def get_period(secret: str) -> int:
        """获取 TOTP 时间步长，优先从 otpauth URI 的 period 参数提取。"""
        return TOTPGenerator._extract_period(secret, TOTPGenerator.DEFAULT_PERIOD)

    @staticmethod
    def _extract_period(secret: str, default: int = DEFAULT_PERIOD) -> int:
        """从 otpauth URI 中提取 period，避免完整 _parse_config 的开销。

        与 _parse_config 复用同一合法区间 ``1 <= period <= _MAX_TOTP_PERIOD``：
        period<=0 会取模除零或返回负倒计时；超长 period 让 TOTP 退化为静态码（见
        :data:`_MAX_TOTP_PERIOD`）。
        """
        value = secret.strip()
        if value.lower().startswith("otpauth://"):
            try:
                query = parse_qs(urlparse(value).query)
                period = int(query.get("period", [str(default)])[0])
            except (ValueError, TypeError):
                return default
            return period if 0 < period <= _MAX_TOTP_PERIOD else default
        return default

    @staticmethod
    def _normalize_base32(raw: str) -> str:
        """标准化 Base32 密钥：大写、去除常见分隔符、自动补齐填充。"""
        cleaned = raw.upper().strip().translate(_BASE32_STRIP_TABLE)
        # 自动补齐 Base32 填充，兼容其他认证器导出的非标准填充密钥
        padding = (8 - len(cleaned) % 8) % 8
        if padding:
            cleaned += "=" * padding
        return cleaned

    @staticmethod
    def validate_secret(secret: str, algorithm: str = "SHA1") -> bool:
        """验证 Base32 密钥格式是否有效。

        支持带算法前缀的密钥格式，例如 'SHA256:BASE32SECRET'。
        前缀存在时自动提取算法并忽略 algorithm 参数。

        Args:
            secret: Base32 编码的密钥，可选带算法前缀
            algorithm: 哈希算法，取值 SHA1、SHA256 或 SHA512

        Returns:
            密钥是否有效
        """
        if not secret:
            return False

        try:
            algorithm, raw_secret, _, _ = TOTPGenerator._parse_config(
                secret, algorithm, TOTPGenerator.DEFAULT_PERIOD, TOTPGenerator.DEFAULT_DIGITS
            )
        except (TypeError, ValueError):
            logger.debug("TOTP 密钥验证失败", exc_info=True)
            return False

        try:
            # 解码为 bytearray 以便用毕原地清零（同 _generate_impl 的清零契约）。
            decoded = bytearray(
                base64.b32decode(TOTPGenerator._normalize_base32(raw_secret), casefold=True)
            )
        except (binascii.Error, ValueError):
            logger.debug("TOTP 密钥验证失败", exc_info=True)
            return False
        try:
            # 下限放宽到 10 字节：RFC 6238 建议 ≥20 字节，但 Google Authenticator 等
            # 广泛使用 10 字节（80 位）secret，30s 窗口下在线爆破仍不可行。仅拦截
            # 损坏/截断的极短输入（其生成的码永不匹配，用户难以察觉）。
            if len(decoded) < 10:
                logger.debug("TOTP 密钥解码后长度不足：%d 字节", len(decoded))
                return False
            return True
        finally:
            secure_zero_buffer(decoded)
