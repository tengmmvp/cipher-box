"""验证安全与性能细化改动的针对性测试。

覆盖近期加固中不易被现有集成测试直接观察的内部契约：
- ``KeyManager`` 改密/恢复时对旧密钥 bytearray 的安全清零（收缩改密后旧密钥
  仍可被进程内存 dump 读取的窗口，与项目「轮换收缩泄漏面」设计意图对齐）。
- ``EntryRepository.get_entries`` 的 ``verify`` 参数：SKIP 跳过逐行 HMAC 验签、
  LENIENT 标记 ``integrity_error``，为列表路径的性能/语义权衡提供类型化开关。
"""

from src.business.services.key_manager import KeyManager
from src.database.types import VerifyMode
from src.exceptions import VaultIntegrityError
from src.models import Entry, RawEntry


class TestKeyManagerZeroing:
    """验证改密/恢复时旧密钥 bytearray 被原地清零，而非等待 GC 回收。"""

    def test_update_key_zeroes_old_bytearray(self):
        km = KeyManager()
        old = bytearray(b'x' * 32)
        km.activate(old, bytearray(b'y' * 32), epoch=1)
        # _to_bytearray 对 bytearray 所有权转移：KeyManager 内部持有的正是该对象
        assert km._key is old
        km.update_key(bytearray(b'z' * 32))
        # 旧主密钥应被原地清零，消除改密后旧密钥驻留待 GC 的泄漏窗口
        assert bytes(old) == b'\x00' * 32

    def test_update_snapshot_key_zeroes_old_bytearray(self):
        km = KeyManager()
        old_snapshot = bytearray(b's' * 32)
        km.activate(bytearray(b'k' * 32), old_snapshot, epoch=1)
        assert km._snapshot_key is old_snapshot
        km.update_snapshot_key(bytearray(b'n' * 32))
        assert bytes(old_snapshot) == b'\x00' * 32

    def test_update_key_to_same_object_does_not_zero(self):
        """传入当前持有的同一 bytearray 不应清零（会清掉将要使用的值）。"""
        km = KeyManager()
        key = bytearray(b'k' * 32)
        km.activate(key, bytearray(b's' * 32), epoch=1)
        km.update_key(key)  # 同一对象，所有权转移，不应清零
        assert bytes(key) == b'k' * 32

    def test_activate_zeroes_previous_keys(self):
        """再次 activate（如恢复后重新激活）也应清零上一组密钥。"""
        km = KeyManager()
        old_key = bytearray(b'a' * 32)
        old_snapshot = bytearray(b'b' * 32)
        km.activate(old_key, old_snapshot, epoch=1)
        km.activate(bytearray(b'c' * 32), bytearray(b'd' * 32), epoch=2)
        assert bytes(old_key) == b'\x00' * 32
        assert bytes(old_snapshot) == b'\x00' * 32


def test_get_entries_verify_modes(vault, entry_mgr):
    """verify=SKIP 跳过完整性验签（integrity_error 保持 False），
    LENIENT 调用 verifier 并在失败时标记 integrity_error。"""
    entry_mgr.add_entry(Entry(
        title='验证条目', username='u', password='p', entry_type='login',
    ))

    def bad_verifier(_entry: RawEntry):
        raise VaultIntegrityError('签名不匹配')

    original_verifier = vault.db._entry_verifier
    vault.db._entry_verifier = bad_verifier
    try:
        lenient = vault.db.get_entries(verify=VerifyMode.LENIENT)
        assert lenient and lenient[0].integrity_error is True

        skipped = vault.db.get_entries(verify=VerifyMode.SKIP)
        assert skipped and skipped[0].integrity_error is False
    finally:
        vault.db._entry_verifier = original_verifier
