"""TOTP 验证码生成器 - 基于 RFC 6238 实现"""

import base64
import hmac
import struct
import time
from urllib.parse import parse_qs, unquote, urlparse


class TOTPGenerator:
    """TOTP (Time-based One-Time Password) 生成器"""

    DEFAULT_PERIOD = 30  # 时间步长（秒）
    DEFAULT_DIGITS = 6   # 验证码位数

    # 支持的哈希算法映射
    ALGO_MAP = {
        'SHA1': 'sha1',
        'SHA256': 'sha256',
        'SHA512': 'sha512',
    }

    # 密钥前缀 -> 算法
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
            (algorithm, raw_secret) 元组
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
        """解析 Base32、算法前缀或标准 otpauth URI。"""
        value = secret.strip()
        if value.lower().startswith('otpauth://'):
            parsed = urlparse(value)
            if parsed.netloc.lower() != 'totp':
                raise ValueError('仅支持 TOTP URI')
            query = parse_qs(parsed.query)
            value = unquote(query.get('secret', [''])[0]).strip()
            algorithm = query.get('algorithm', [algorithm])[0].upper()
            period = int(query.get('period', [period])[0])
            digits = int(query.get('digits', [digits])[0])
        parsed_algo, value = TOTPGenerator._parse_secret(value)
        if parsed_algo != 'SHA1':
            algorithm = parsed_algo
        if algorithm not in TOTPGenerator.ALGO_MAP:
            raise ValueError('不支持的算法')
        if period <= 0 or digits not in (6, 7, 8):
            raise ValueError('TOTP 参数无效')
        return algorithm, value, period, digits

    @staticmethod
    def generate(secret: str, algorithm: str = 'SHA1', period: int = DEFAULT_PERIOD, digits: int = DEFAULT_DIGITS) -> str:
        """生成当前 TOTP 验证码

        Args:
            secret: Base32 编码的密钥，支持 'SHA256:SECRET' 或 'SHA512:SECRET' 前缀
            algorithm: 哈希算法 ('SHA1', 'SHA256', 'SHA512')，当前缀存在时被覆盖
            period: 时间步长（秒）
            digits: 验证码位数

        Returns:
            TOTP 验证码字符串
        """
        if not secret:
            return ''

        # 解析前缀，前缀优先级高于 algorithm 参数
        try:
            algorithm, raw_secret, period, digits = TOTPGenerator._parse_config(
                secret, algorithm, period, digits
            )
        except (TypeError, ValueError):
            return ''

        algo_name = TOTPGenerator.ALGO_MAP.get(algorithm, 'sha1')

        try:
            key = base64.b32decode(raw_secret.upper().strip().replace(' ', ''), casefold=True)
        except Exception:
            return ''

        counter = int(time.time()) // period
        msg = struct.pack('>Q', counter)

        hmac_hash = hmac.new(key, msg, algo_name).digest()

        offset = hmac_hash[-1] & 0x0F
        code = struct.unpack('>I', hmac_hash[offset:offset + 4])[0]
        code &= 0x7FFFFFFF
        code %= 10 ** digits

        return str(code).zfill(digits)

    @staticmethod
    def get_remaining_seconds(period: int = DEFAULT_PERIOD, secret: str = '') -> int:
        """获取当前时间步长剩余秒数"""
        if secret:
            try:
                _, _, period, _ = TOTPGenerator._parse_config(
                    secret, 'SHA1', period, TOTPGenerator.DEFAULT_DIGITS
                )
            except (TypeError, ValueError):
                pass
        return period - (int(time.time()) % period)

    @staticmethod
    def get_period(secret: str) -> int:
        try:
            _, _, period, _ = TOTPGenerator._parse_config(
                secret, 'SHA1', TOTPGenerator.DEFAULT_PERIOD, TOTPGenerator.DEFAULT_DIGITS
            )
            return period
        except (TypeError, ValueError):
            return TOTPGenerator.DEFAULT_PERIOD

    @staticmethod
    def validate_secret(secret: str, algorithm: str = 'SHA1') -> bool:
        """验证 Base32 密钥格式是否有效

        支持带算法前缀的密钥格式（如 'SHA256:BASE32SECRET'），
        前缀存在时自动提取算法并忽略 algorithm 参数。

        Args:
            secret: Base32 编码的密钥，可选带算法前缀
            algorithm: 哈希算法 ('SHA1', 'SHA256', 'SHA512')

        Returns:
            密钥是否有效
        """
        if not secret:
            return False

        # 解析前缀
        try:
            algorithm, raw_secret, _, _ = TOTPGenerator._parse_config(
                secret, algorithm, TOTPGenerator.DEFAULT_PERIOD, TOTPGenerator.DEFAULT_DIGITS
            )
        except (TypeError, ValueError):
            return False

        try:
            base64.b32decode(raw_secret.upper().strip().replace(' ', ''), casefold=True)
            return True
        except Exception:
            return False
