"""TOTP 验证码生成器 — 基于 RFC 6238 实现。"""

import base64
import binascii
import hmac
import logging
import struct
import time
from urllib.parse import parse_qs, unquote, urlparse

logger = logging.getLogger(__name__)


class TOTPGenerator:
    """基于时间的一次性密码 TOTP 生成器。"""

    DEFAULT_PERIOD = 30  # 时间步长，单位为秒
    DEFAULT_DIGITS = 6   # 验证码位数

    # 支持的哈希算法映射
    ALGO_MAP = {
        'SHA1': 'sha1',
        'SHA256': 'sha256',
        'SHA512': 'sha512',
    }

    # 密钥前缀 -> 算法。SHA1 不入表：它是默认算法，显式 ``SHA1:`` 前缀不被识别
    # （_parse_secret 对无匹配前缀的密钥返回默认 'SHA1'，由 URI/调用方 algorithm 生效）。
    # 注意：新增算法须同步 ALGO_MAP（上方）与此处，避免两表漂移。
    _PREFIX_MAP = {
        'SHA256:': 'SHA256',
        'SHA512:': 'SHA512',
    }

    @staticmethod
    def _parse_secret(secret: str) -> tuple[str, str]:
        """解析密钥字符串，提取算法和实际密钥

        如果 secret 以 'SHA256:' 或 'SHA512:' 开头，则自动提取算法和密钥；
        否则默认使用 SHA1。

        Args:
            secret: 可能带算法前缀的密钥字符串

        Returns:
            由算法名和去除前缀后的密钥组成的元组
        """
        secret = secret.strip()
        for prefix, algo in TOTPGenerator._PREFIX_MAP.items():
            if secret.upper().startswith(prefix):
                return algo, secret[len(prefix):].strip()
        return 'SHA1', secret

    @staticmethod
    def _parse_config(
        secret: str,
        algorithm: str,
        period: int,
        digits: int,
    ) -> tuple[str, str, int, int]:
        """解析 Base32、算法前缀或标准 otpauth URI。

        算法优先级（高 → 低）：secret 内嵌前缀（``SHA256:``/``SHA512:``） >
        otpauth URI 的 ``algorithm`` 参数 > 调用方传入的 ``algorithm`` 默认值。
        即当 secret 自带非 SHA1 前缀时，它覆盖 URI 与默认值；URI ``algorithm``
        覆盖默认值。冲突场景（如 URI ``algorithm=SHA1`` 但 secret 带 ``SHA256:``
        前缀）下，secret 前缀胜出。
        """
        value = secret.strip()
        if value.lower().startswith('otpauth://'):
            parsed = urlparse(value)
            if parsed.netloc.lower() != 'totp':
                raise ValueError('仅支持 TOTP URI')
            query = parse_qs(parsed.query)
            value = unquote(query.get('secret', [''])[0]).strip()
            if not value:
                raise ValueError('otpauth URI 中缺少 secret 参数')
            algorithm = query.get('algorithm', [algorithm])[0].upper()
            try:
                period = int(query.get('period', [period])[0])
            except (ValueError, TypeError) as exc:
                raise ValueError('TOTP period 必须为整数') from exc
            try:
                digits = int(query.get('digits', [digits])[0])
            except (ValueError, TypeError) as exc:
                raise ValueError('TOTP digits 必须为整数') from exc
        parsed_algo, value = TOTPGenerator._parse_secret(value)
        if parsed_algo != 'SHA1':
            algorithm = parsed_algo
        if algorithm not in TOTPGenerator.ALGO_MAP:
            raise ValueError('不支持的算法')
        if period <= 0 or digits not in (6, 7, 8):
            raise ValueError('TOTP 参数无效')
        return algorithm, value, period, digits

    @staticmethod
    def _compute_totp(key: bytes, algo_name: str, period: int, digits: int) -> str:
        """核心 TOTP 计算：HMAC + 动态截断 + 取模。"""
        counter = int(time.time()) // period
        msg = struct.pack('>Q', counter)
        hmac_hash = hmac.new(key, msg, algo_name).digest()
        offset = hmac_hash[-1] & 0x0F
        code = struct.unpack('>I', hmac_hash[offset:offset + 4])[0]
        code &= 0x7FFFFFFF
        code %= 10 ** digits
        return str(code).zfill(digits)

    @staticmethod
    def _generate_impl(secret: str, algorithm: str, period: int, digits: int) -> tuple[str, Exception | None]:
        """TOTP 生成的共享实现。

        Returns:
            由验证码和错误对象组成的元组。成功时错误对象为 None，失败时验证码为空字符串。
        """
        if not secret:
            return '', ValueError('TOTP 密钥不能为空')

        try:
            algorithm, raw_secret, period, digits = TOTPGenerator._parse_config(
                secret, algorithm, period, digits
            )
        except (TypeError, ValueError) as exc:
            return '', ValueError(f'TOTP 密钥格式无效: {exc}')

        algo_name = TOTPGenerator.ALGO_MAP.get(algorithm)
        if algo_name is None:
            # _parse_config 已校验 algorithm，此分支为纵深防御，防止未来校验
            # 逻辑改动或绕过 _parse_config 直接调用时 KeyError 冒泡至调用方。
            return '', ValueError('不支持的 TOTP 算法')

        try:
            key = base64.b32decode(TOTPGenerator._normalize_base32(raw_secret), casefold=True)
        except (binascii.Error, ValueError) as exc:
            return '', ValueError(f'TOTP Base32 解码失败: {exc}')

        return TOTPGenerator._compute_totp(key, algo_name, period, digits), None

    @staticmethod
    def generate(secret: str, algorithm: str = 'SHA1', period: int = DEFAULT_PERIOD, digits: int = DEFAULT_DIGITS) -> str:
        """生成当前 TOTP 验证码

        Args:
            secret: Base32 编码的密钥，支持 'SHA256:SECRET' 或 'SHA512:SECRET' 前缀
            algorithm: 哈希算法，取值 SHA1、SHA256 或 SHA512；当前缀存在时被覆盖
            period: 时间步长，单位为秒
            digits: 验证码位数

        Returns:
            TOTP 验证码字符串，失败时返回空字符串。

        Note:
            静默失败是有意设计：此方法用于定时器驱动的 TOTP 刷新等非交互场景，
            弹出错误框会干扰用户体验。如需错误传播，使用 generate_or_raise()。
        """
        code, error = TOTPGenerator._generate_impl(secret, algorithm, period, digits)
        if error is not None:
            logger.warning("TOTP 生成失败: %s", error)
            return ''
        return code

    @staticmethod
    def generate_or_raise(secret: str, algorithm: str = 'SHA1', period: int = DEFAULT_PERIOD, digits: int = DEFAULT_DIGITS) -> str:
        """生成当前 TOTP 验证码，失败时抛出异常而非静默返回空串。

        参数和返回值与 generate() 相同，但在密钥解析或解码失败时抛出 ValueError，
        而非记录警告并返回空字符串。适用于密钥验证等用户交互场景，
        使调用方能向用户展示具体错误信息。

        Raises:
            ValueError: 密钥格式无效或 Base32 解码失败
        """
        code, error = TOTPGenerator._generate_impl(secret, algorithm, period, digits)
        if error is not None:
            raise error
        return code

    @staticmethod
    def get_remaining_seconds(period: int = DEFAULT_PERIOD, secret: str = '') -> int:
        """获取当前时间步长剩余秒数。"""
        if secret:
            period = TOTPGenerator._extract_period(secret, period)
        return period - (int(time.time()) % period)

    @staticmethod
    def get_period(secret: str) -> int:
        """获取 TOTP 时间步长，优先从 otpauth URI 的 period 参数提取。"""
        return TOTPGenerator._extract_period(secret, TOTPGenerator.DEFAULT_PERIOD)

    @staticmethod
    def _extract_period(secret: str, default: int = DEFAULT_PERIOD) -> int:
        """从 otpauth URI 中提取 period，避免完整 _parse_config 的开销。

        对解析结果做正数校验，与 _parse_config 对齐，防止 period<=0 让
        get_remaining_seconds 取模抛 ZeroDivisionError 或返回负倒计时。
        """
        value = secret.strip()
        if value.lower().startswith('otpauth://'):
            try:
                query = parse_qs(urlparse(value).query)
                period = int(query.get('period', [str(default)])[0])
            except (ValueError, TypeError):
                return default
            return period if period > 0 else default
        return default

    @staticmethod
    def _normalize_base32(raw: str) -> str:
        """标准化 Base32 密钥：大写、去除常见分隔符、自动补齐填充。"""
        cleaned = raw.upper().strip().replace(' ', '').replace('-', '').replace('.', '').replace('_', '')
        # 自动补齐 Base32 填充，兼容其他认证器导出的非标准填充密钥
        padding = (8 - len(cleaned) % 8) % 8
        if padding:
            cleaned += '=' * padding
        return cleaned

    @staticmethod
    def validate_secret(secret: str, algorithm: str = 'SHA1') -> bool:
        """验证 Base32 密钥格式是否有效

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
            base64.b32decode(TOTPGenerator._normalize_base32(raw_secret), casefold=True)
            return True
        except (binascii.Error, ValueError):
            logger.debug("TOTP 密钥验证失败", exc_info=True)
            return False
