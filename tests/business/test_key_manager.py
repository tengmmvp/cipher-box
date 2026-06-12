"""KeyManager 单元测试。

验证从 VaultManager 拆出的密钥持有与清零职责：
- activate 原子设置 key/snapshot_key/key_epoch
- 单字段更新方法只改动目标字段，不影响其余字段
- clear 清零密钥材料并释放全部引用
- clear 真正调用 secure_zero_buffer 清零 bytearray 密钥
- 重复 activate→clear→activate 的状态转换
- 单字段置空（传入 None）
- key/snapshot_key property 返回 bytes 副本，不暴露内部 bytearray 身份
"""

import pytest

from src.business.services import key_manager as key_manager_module
from src.business.services.key_manager import KeyManager

# ---------------------------------------------------------------------------
# 辅助函数：生成 32 字节 bytearray 测试密钥，对应 AES-256 宽度，便于真实清零验证
# ---------------------------------------------------------------------------

def _make_bytearray_key(value: int = 0xAB) -> bytearray:
    """构造内容为 value 的 32 字节 bytearray 测试密钥。"""
    return bytearray([value] * 32)


# ---------------------------------------------------------------------------
# 1. activate 后三个属性正确返回传入值（property 返回 bytes 副本，值相等）
# ---------------------------------------------------------------------------

def test_activate_sets_all_three_fields():
    """activate 原子设置后，key/snapshot_key/key_epoch 返回各自传入值。"""
    km = KeyManager()
    key = _make_bytearray_key(0x11)
    snapshot = _make_bytearray_key(0x22)
    epoch = 7

    km.activate(key, snapshot, epoch)

    # property 返回 bytes 副本，值与传入 bytearray 相等
    assert km.key == key
    assert isinstance(km.key, bytes)
    assert km.snapshot_key == snapshot
    assert isinstance(km.snapshot_key, bytes)
    assert km.key_epoch == epoch


# ---------------------------------------------------------------------------
# 2. 单字段更新：update_key/update_snapshot_key/update_epoch
# ---------------------------------------------------------------------------

def test_update_key_changes_only_key():
    """update_key 仅替换 key，snapshot_key 与 key_epoch 保持不变。"""
    km = KeyManager()
    old_key = _make_bytearray_key(0x11)
    old_snapshot = _make_bytearray_key(0x22)
    km.activate(old_key, old_snapshot, 3)

    new_key = _make_bytearray_key(0x33)
    km.update_key(new_key)

    assert km.key == new_key
    assert km.snapshot_key == old_snapshot
    assert km.key_epoch == 3


def test_update_snapshot_key_changes_only_snapshot_key():
    """update_snapshot_key 仅替换 snapshot_key，key 与 key_epoch 保持不变。"""
    km = KeyManager()
    old_key = _make_bytearray_key(0x11)
    old_snapshot = _make_bytearray_key(0x22)
    km.activate(old_key, old_snapshot, 5)

    new_snapshot = _make_bytearray_key(0x44)
    km.update_snapshot_key(new_snapshot)

    assert km.key == old_key
    assert km.snapshot_key == new_snapshot
    assert km.key_epoch == 5


def test_update_epoch_changes_only_epoch():
    """update_epoch 仅替换 key_epoch，key 与 snapshot_key 保持不变。"""
    km = KeyManager()
    key = _make_bytearray_key(0x11)
    snapshot = _make_bytearray_key(0x22)
    km.activate(key, snapshot, 1)

    km.update_epoch(42)

    assert km.key == key
    assert km.snapshot_key == snapshot
    assert km.key_epoch == 42


# ---------------------------------------------------------------------------
# 3. clear 后三个属性均为 None
# ---------------------------------------------------------------------------

def test_clear_sets_all_fields_none():
    """clear 释放全部引用，key/snapshot_key/key_epoch 均为 None。"""
    km = KeyManager()
    km.activate(_make_bytearray_key(0x11), _make_bytearray_key(0x22), 9)

    km.clear()

    assert km.key is None
    assert km.snapshot_key is None
    assert km.key_epoch is None


# ---------------------------------------------------------------------------
# 4. clear 真正清零 bytearray 密钥，验证 secure_zero_buffer 被调用且内容归零
# ---------------------------------------------------------------------------

def test_clear_zeroes_bytearray_key_content():
    """clear 对 bytearray 主密钥真正清零：clear 后该 bytearray 内容全为 0。

    bytearray 是可变缓冲区，secure_zero_buffer 会通过 ctypes.memset 原地清零。
    KeyManager 内部以 bytearray 持有（_to_bytearray 对 bytearray 直接返回原对象），
    因此传入同一 bytearray 对象，clear 后其内容应变为全 0 字节。
    """
    km = KeyManager()
    key = _make_bytearray_key(0xAB)
    snapshot = _make_bytearray_key(0xCD)
    km.activate(key, snapshot, 1)

    km.clear()

    assert bytes(key) == b'\x00' * len(key)
    assert bytes(snapshot) == b'\x00' * len(snapshot)


def test_clear_invokes_secure_zero_buffer_for_each_secret(monkeypatch):
    """clear 对每个非空密钥调用 secure_zero_buffer 清零逻辑。

    通过 monkeypatch 替换 secure_zero_buffer，记录被调用时传入的对象身份，
    确保主密钥与快照密钥均经过清零路径，且清零发生在属性被置 None 之前。
    KeyManager 内部持有传入的 bytearray（身份共享），故 id 与传入对象一致。
    """
    km = KeyManager()
    key = _make_bytearray_key(0x11)
    snapshot = _make_bytearray_key(0x22)
    km.activate(key, snapshot, 1)

    called_with: list[int] = []
    original = key_manager_module.secure_zero_buffer

    def spy(data):
        # 记录被清零对象的 id，并委托原函数完成真实清零
        called_with.append(id(data))
        original(data)

    monkeypatch.setattr(key_manager_module, 'secure_zero_buffer', spy)

    km.clear()

    assert id(key) in called_with
    assert id(snapshot) in called_with
    assert len(called_with) == 2


# ---------------------------------------------------------------------------
# 5. 重复 activate→clear→activate 的状态转换
# ---------------------------------------------------------------------------

def test_repeated_activate_clear_cycle():
    """activate→clear→activate 状态转换：clear 后能正确激活一组全新密钥材料。"""
    km = KeyManager()

    key1 = _make_bytearray_key(0x11)
    snapshot1 = _make_bytearray_key(0x22)
    km.activate(key1, snapshot1, 1)
    assert km.key == key1 and km.snapshot_key == snapshot1 and km.key_epoch == 1

    km.clear()
    assert km.key is None and km.snapshot_key is None and km.key_epoch is None

    key2 = _make_bytearray_key(0x33)
    snapshot2 = _make_bytearray_key(0x44)
    km.activate(key2, snapshot2, 2)
    assert km.key == key2
    assert km.snapshot_key == snapshot2
    assert km.key_epoch == 2


# ---------------------------------------------------------------------------
# 6. 单字段置空，传入 None
# ---------------------------------------------------------------------------

def test_update_key_none():
    """update_key(None) 将主密钥置空，其余字段不受影响。"""
    km = KeyManager()
    snapshot = _make_bytearray_key(0x22)
    km.activate(_make_bytearray_key(0x11), snapshot, 4)

    km.update_key(None)

    assert km.key is None
    assert km.snapshot_key == snapshot
    assert km.key_epoch == 4


def test_update_snapshot_key_none():
    """update_snapshot_key(None) 将快照密钥置空，其余字段不受影响。"""
    km = KeyManager()
    key = _make_bytearray_key(0x11)
    km.activate(key, _make_bytearray_key(0x22), 4)

    km.update_snapshot_key(None)

    assert km.key == key
    assert km.snapshot_key is None
    assert km.key_epoch == 4


def test_update_epoch_none():
    """update_epoch(None) 将密钥版本置空，其余字段不受影响。"""
    km = KeyManager()
    key = _make_bytearray_key(0x11)
    snapshot = _make_bytearray_key(0x22)
    km.activate(key, snapshot, 4)

    km.update_epoch(None)

    assert km.key == key
    assert km.snapshot_key == snapshot
    assert km.key_epoch is None


def test_clear_on_empty_manager_is_noop_safe():
    """对未激活的 KeyManager 调用 clear 应安全无副作用，三属性保持 None。"""
    km = KeyManager()
    # 初始即未设置任何密钥
    assert km.key is None and km.snapshot_key is None and km.key_epoch is None

    km.clear()

    assert km.key is None
    assert km.snapshot_key is None
    assert km.key_epoch is None


# ---------------------------------------------------------------------------
# 7. property 返回 bytes 副本，不暴露内部 bytearray 身份
# ---------------------------------------------------------------------------

def test_key_property_returns_independent_copy():
    """key property 返回 bytes 副本，clear 内部 bytearray 不影响已发出的副本。

    这是 P0#3 修复的核心：调用方持有的密钥副本不受 lock()/clear() 原地清零
    内部对象的影响，消除密钥身份暴露导致的并发清零风险。
    """
    km = KeyManager()
    km.activate(_make_bytearray_key(0x11), _make_bytearray_key(0x22), 1)

    key_copy = km.key
    assert key_copy == bytes([0x11] * 32)

    # 清零内部 bytearray 后，先前发出的副本内容不变
    km.clear()
    assert key_copy == bytes([0x11] * 32)
