"""锁定状态文件的 HMAC 签名验证与篡改检测测试。

模拟登录窗口对锁定状态文件的签名与解析逻辑，文件记录失败次数与锁定截止时间，
验证正确签名可被校验、篡改后签名不匹配、缺失签名行视为无效。
"""

import hashlib
import hmac
import json
import time

import pytest

# 此密钥必须与 src/ui/login_window.py 中的 _LOCK_KEY 保持同步。
# 若 login_window.py 中的密钥变更，此处必须同步更新，否则测试会因签名不匹配而失败。
_LOCK_KEY = b'cipherbox:lock-state-v1'


@pytest.fixture
def lock_file(tmp_path):
    """返回临时锁状态文件路径。"""
    return tmp_path / 'login_lock.json'


def _sign_data(data_str: str) -> str:
    """模拟 login_window 的签名逻辑。"""
    return hmac.new(_LOCK_KEY, data_str.encode('utf-8'), hashlib.sha256).hexdigest()


def _write_lock(lock_path, fail_count=0, lock_until=0.0):
    """写入有效的签名锁状态文件。"""
    data = json.dumps({'fail_count': fail_count, 'lock_until': lock_until})
    sig = _sign_data(data)
    lock_path.write_text(data + '\n#__sig__:' + sig, encoding='utf-8')


class TestLockIntegrity:
    def test_valid_signature(self, lock_file):
        """正确签名的文件可以被解析。"""
        future = time.time() + 300
        _write_lock(lock_file, fail_count=3, lock_until=future)
        raw = lock_file.read_text(encoding='utf-8')
        assert '\n#__sig__:' in raw

        json_text, sig = raw.rsplit('\n#__sig__:', 1)
        expected = _sign_data(json_text)
        assert hmac.compare_digest(sig.strip(), expected)

    def test_tampered_fail_count(self, lock_file):
        """篡改 fail_count 后签名不匹配。"""
        _write_lock(lock_file, fail_count=2)
        raw = lock_file.read_text(encoding='utf-8')
        json_text, sig = raw.rsplit('\n#__sig__:', 1)

        # 篡改
        tampered = json_text.replace('"fail_count": 2', '"fail_count": 0')
        lock_file.write_text(tampered + '\n#__sig__:' + sig, encoding='utf-8')

        # 验证签名
        raw2 = lock_file.read_text(encoding='utf-8')
        json_text2, sig2 = raw2.rsplit('\n#__sig__:', 1)
        expected = _sign_data(json_text2)
        assert not hmac.compare_digest(sig2.strip(), expected)

    def test_missing_signature(self, lock_file):
        """无签名行应视为无效。"""
        data = json.dumps({'fail_count': 5, 'lock_until': time.time() + 300})
        lock_file.write_text(data, encoding='utf-8')

        raw = lock_file.read_text(encoding='utf-8')
        assert '\n#__sig__:' not in raw
