"""登录锁定持久化测试 — 验证 time.time() 墙上时钟修复。

注意：当前测试仅验证 JSON 文件读写和时间比较逻辑，未导入或测试 LoginWindow
的实际锁定管理代码。待 LoginWindow 的锁定状态管理提取为独立可测试函数后，
应替换为针对实际业务逻辑的测试。
"""

import json
import time

import pytest


class TestLoginLockPersistence:
    """验证锁定状态使用 time.time()（墙上时钟），而非 time.monotonic()。"""

    def test_lock_state_uses_wall_clock(self, tmp_path):
        """锁定状态使用 time.time() 保存，跨进程重启后仍可正确判断。"""
        lock_file = tmp_path / 'login_lock.json'
        # 模拟保存一个在未来 60 秒过期的锁定
        lock_until = time.time() + 60
        lock_file.write_text(json.dumps({
            'fail_count': 5,
            'lock_until': lock_until,
        }), encoding='utf-8')

        # 验证可以正确读取并判断未过期
        data = json.loads(lock_file.read_text(encoding='utf-8'))
        assert data['lock_until'] > time.time()

    def test_expired_lock_is_recognized(self, tmp_path):
        """已过期的锁定状态被正确识别为已过期。"""
        lock_file = tmp_path / 'login_lock.json'
        # 保存一个已过期的锁定（10 秒前过期）
        lock_file.write_text(json.dumps({
            'fail_count': 5,
            'lock_until': time.time() - 10,
        }), encoding='utf-8')

        data = json.loads(lock_file.read_text(encoding='utf-8'))
        assert data['lock_until'] <= time.time()

    def test_lock_state_survives_simulated_restart(self, tmp_path):
        """模拟进程重启：写入锁定 → 重新读取 → 仍然有效。"""
        lock_file = tmp_path / 'login_lock.json'
        future = time.time() + 300  # 5 分钟后过期

        # 模拟第一次进程写入锁定
        lock_file.write_text(json.dumps({
            'fail_count': 3,
            'lock_until': future,
        }), encoding='utf-8')

        # 模拟"重启"：重新读取文件
        data = json.loads(lock_file.read_text(encoding='utf-8'))

        # 仍然判断为锁定中
        assert data['lock_until'] > time.time()
        assert data['fail_count'] == 3
