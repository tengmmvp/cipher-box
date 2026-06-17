"""DPAPI 封装往返测试。

验证 protect_with_dpapi / unprotect_with_dpapi 的封装-解封往返正确性，
守护 config.key 的 DPAPI 保护机制（Windows 下用当前用户凭据封装签名密钥，
使 config.key 即便被同权限进程读取也无法在别处解密重算签名）。
"""
import sys

import pytest

from src.utils.file_security import protect_with_dpapi, unprotect_with_dpapi


@pytest.mark.skipif(sys.platform != 'win32', reason='DPAPI 仅 Windows 可用')
class TestDpapiRoundTrip:
    def test_protect_unprotect_roundtrip(self):
        data = b'x' * 32
        protected = protect_with_dpapi(data)
        if protected is None:
            pytest.skip('DPAPI 在当前测试环境不可用')
        assert protected != data  # 封装后非明文
        assert len(protected) > len(data)  # DPAPI blob 含头部，远大于明文
        assert unprotect_with_dpapi(protected) == data

    def test_unprotect_plain_returns_none(self):
        """非 DPAPI 封装的明文数据，unprotect 返回 None（供 config 明文回退判定）。"""
        assert unprotect_with_dpapi(b'y' * 32) is None
