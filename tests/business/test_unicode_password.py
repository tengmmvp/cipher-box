"""Unicode 主密码回归测试。

守护 hmac.compare_digest 对含 Unicode（如中文）主密码的比较：compare_digest 对
str 仅接受 ASCII，主密码比较必须经 encode('utf-8')，否则新旧相同时抛 TypeError
走异常路径，而非返回「密码相同」友好提示。
"""

from tests.helpers import make_vault

_UNICODE_PWD = "主密码·Password·12345"  # 含中文与符号，18 字符 ≥ 15


def test_change_master_password_unicode_same_not_crash(vault_config):
    """新旧 Unicode 主密码相同应返回友好提示，而非抛 TypeError。"""
    vault = make_vault(vault_config)
    vault.initialize(_UNICODE_PWD)
    try:
        ok, msg = vault.change_master_password(_UNICODE_PWD, _UNICODE_PWD)
        assert not ok
        assert "相同" in msg
    finally:
        vault.close()


def test_change_master_password_unicode_change_succeeds(vault_config):
    """不同 Unicode 主密码改密应成功（encode 比较正确判定为「不相同」）。"""
    vault = make_vault(vault_config)
    vault.initialize(_UNICODE_PWD)
    try:
        ok, msg = vault.change_master_password(_UNICODE_PWD, "新主密码·Password·67890")
        assert ok, msg
    finally:
        vault.close()
