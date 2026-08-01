"""PasswordService 冒烟测试，验证静态方法代理正确性。"""

from src.business.services.password_service import PasswordService


class TestPasswordServiceProxy:
    """PasswordService 应将调用正确代理到底层 PasswordGenerator / TOTPGenerator。"""

    def test_generate_returns_string(self):
        result = PasswordService.generate(length=20)
        assert isinstance(result, str)
        assert len(result) == 20

    def test_check_strength_returns_object(self):
        result = PasswordService.check_strength("TestP@ssw0rd!")
        assert hasattr(result, "score")
        assert hasattr(result, "label")

    def test_validate_master_password_rejects_short(self):
        ok, msg = PasswordService.validate_master_password("abc", "主密码")
        assert not ok
        assert msg

    def test_validate_master_password_accepts_strong(self):
        ok, msg = PasswordService.validate_master_password("Str0ng!Pass#2024", "主密码")
        assert ok

    def test_validate_master_password_accepts_long_passphrase(self):
        ok, msg = PasswordService.validate_master_password("correct horse battery staple", "主密码")
        assert ok, msg

    def test_validate_master_password_rejects_repeated_characters(self):
        ok, msg = PasswordService.validate_master_password("a" * 30, "主密码")
        assert not ok
        assert "重复" in msg

    def test_validate_totp_secret_rejects_invalid(self):
        ok = PasswordService.validate_totp_secret("not-base32!")
        assert not ok

    def test_generate_totp_or_raise_with_valid_secret(self):
        import base64

        # 构造有效的 Base32 TOTP 密钥
        secret = base64.b32encode(b"test-secret-key-12345").decode()
        result = PasswordService.generate_totp_or_raise(secret)
        assert isinstance(result, str)
        assert len(result) == 6
        assert result.isdigit()
