"""Unicode 主密码回归测试。

守护 hmac.compare_digest 对含 Unicode（如中文）主密码的比较：compare_digest 对
str 仅接受 ASCII，主密码比较必须经 encode('utf-8')，否则新旧相同时抛 TypeError
走异常路径，而非返回「密码相同」友好提示。

建库经 make_vault_env 工厂（统一装配/回收）。
"""

import pytest

from src.exceptions import MasterPasswordPolicyError

_UNICODE_PWD = "主密码·Password·12345"  # 含中文与符号，18 字符 ≥ 15


def test_change_master_password_unicode_same_not_crash(make_vault_env):
    """新旧 Unicode 主密码相同应抛类型化策略异常（含「相同」文案），而非 TypeError。"""
    vault = make_vault_env(master_password=_UNICODE_PWD).vault
    # ARCH-042 契约：(False, ...) 仅表认证失败，策略失败类型化走异常通道
    with pytest.raises(MasterPasswordPolicyError, match="相同"):
        vault.change_master_password(_UNICODE_PWD, _UNICODE_PWD)


def test_change_master_password_unicode_change_succeeds(make_vault_env):
    """不同 Unicode 主密码改密应成功（encode 比较正确判定为「不相同」）。"""
    vault = make_vault_env(master_password=_UNICODE_PWD).vault
    ok, msg = vault.change_master_password(_UNICODE_PWD, "新主密码·Password·67890")
    assert ok, msg
