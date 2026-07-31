"""TOTP 已知答案（RFC 6238）与边界测试。

覆盖 ``src/crypto/totp.py::TOTPGenerator``：
- SHA1/SHA256/SHA512 的 RFC 6238 Appendix B 已知答案向量（T=59 等，digits=8）。
- 计数器边界：T=30→counter 1 vs T=29→counter 0；T=30 与 T=59 共享 counter 1。
- ``generate_or_raise``：合法 secret 返回码、非法 secret 抛 ValueError（与静默的
  ``generate`` 区分）。
"""

import base64

import pytest

import src.crypto.totp as totp_module
from src.crypto.totp import TOTPGenerator

# RFC 6238 Appendix B 测试种子（ASCII 字节的 base32 编码）
_SHA1_SEED = base64.b32encode(b'12345678901234567890').decode()
_SHA256_SEED = base64.b32encode(b'12345678901234567890123456789012').decode()
_SHA512_SEED = base64.b32encode(
    b'1234567890123456789012345678901234567890123456789012345678901234'
).decode()


@pytest.fixture
def patched_time(monkeypatch):
    """返回一个设置 time.time() 的闭包，控制 TOTP 计数器。"""
    def _set(t: int) -> None:
        monkeypatch.setattr(totp_module.time, 'time', lambda: t)
    return _set


# ======== RFC 6238 已知答案向量 ========

@pytest.mark.parametrize('algorithm,prefix,seed,expected_t59', [
    ('SHA1', '', _SHA1_SEED, '94287082'),
    ('SHA256', 'SHA256:', _SHA256_SEED, '46119246'),
    ('SHA512', 'SHA512:', _SHA512_SEED, '90693936'),
])
def test_rfc6238_t59_vector(patched_time, algorithm, prefix, seed, expected_t59):
    """T=59（counter=1）的 RFC 6238 三种算法已知答案，digits=8。

    向量取自 RFC 6238 Appendix B：T=59 时 SHA1=94287082、SHA256=46119246、
    SHA512=90693936。SHA256/SHA512 经 secret 前缀（``SHA256:``/``SHA512:``）识别，
    SHA1 为默认算法（无前缀）。
    """
    patched_time(59)
    secret = prefix + seed
    code = TOTPGenerator.generate(secret, period=30, digits=8)
    assert code == expected_t59


def test_rfc6238_sha1_t1111111109_vector(patched_time):
    """第二个 RFC 6238 向量：T=1111111109 时 SHA1 = 07081804（digits=8）。"""
    patched_time(1111111109)
    code = TOTPGenerator.generate(_SHA1_SEED, period=30, digits=8)
    assert code == '07081804'


# ======== 计数器边界 ========

def test_counter_boundary_t30_and_t29_differ(patched_time):
    """T=30→counter 1、T=29→counter 0，相邻时间步的验证码必须不同。

    边界守护：counter = time // period，30s 周期下 T=29 与 T=30 跨越计数器边界。
    """
    patched_time(30)
    code_at_30 = TOTPGenerator.generate(_SHA1_SEED)
    patched_time(29)
    code_at_29 = TOTPGenerator.generate(_SHA1_SEED)
    assert code_at_30 != code_at_29


def test_counter_boundary_t30_and_t59_share_counter(patched_time):
    """T=30 与 T=59 同属 counter 1（30//30=1、59//30=1），验证码相同。"""
    patched_time(30)
    code_at_30 = TOTPGenerator.generate(_SHA1_SEED)
    patched_time(59)
    code_at_59 = TOTPGenerator.generate(_SHA1_SEED)
    assert code_at_30 == code_at_59


# ======== generate_or_raise ========

def test_generate_or_raise_returns_code_for_valid_secret(patched_time):
    """合法 secret 经 generate_or_raise 返回 6 位验证码。"""
    patched_time(1234567890)
    code = TOTPGenerator.generate_or_raise(_SHA1_SEED)
    assert len(code) == TOTPGenerator.DEFAULT_DIGITS
    assert code.isdigit()


def test_generate_or_raise_raises_for_invalid_secret():
    """非法 base32 secret 经 generate_or_raise 抛 ValueError（非静默空串）。

    与 ``generate`` 的静默返回 '' 区分：用户交互场景（如保存前校验）需显式错误传播。
    """
    with pytest.raises(ValueError):
        TOTPGenerator.generate_or_raise('!!!不是合法base32!!!')


def test_generate_or_raise_raises_for_empty_secret():
    """空 secret 抛 ValueError。"""
    with pytest.raises(ValueError):
        TOTPGenerator.generate_or_raise('')


def test_generate_silently_returns_empty_for_invalid_secret(patched_time):
    """对比：``generate`` 对非法 secret 静默返回 ''（不抛）。"""
    assert TOTPGenerator.generate('!!!invalid!!!') == ''


def test_generate_sha256_prefix_overrides_algorithm_param(patched_time):
    """secret 内嵌 ``SHA256:`` 前缀覆盖调用方传入的 algorithm 参数。

    _parse_config 优先级：secret 前缀 > algorithm 形参。即便传入 algorithm='SHA1'，
    带 SHA256 前缀的 secret 仍按 SHA256 计算。
    """
    patched_time(59)
    code = TOTPGenerator.generate('SHA256:' + _SHA256_SEED, algorithm='SHA1', digits=8)
    assert code == '46119246'
