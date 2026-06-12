"""KeyManager 单元测试。

验证从 VaultManager 拆出的密钥持有与清零职责：
- activate 原子设置 key/snapshot_key/key_epoch
- 单字段更新方法只改动目标字段，不影响其余字段
- clear 清零密钥材料并释放全部引用
- clear 真正调用 secure_zero_buffer 清零 bytearray 密钥
- 重复 activate→clear→activate 的状态转换
- 单字段置空（传入 None）
"""

import pytest

from src.business.services import key_manager as key_manager_module
from src.business.services.key_manager import KeyManager

# ---------------------------------------------------------------------------
# 辅助函数：生成 32 字节 bytearray 测试密钥（AES-256 宽度，便于真实清零验证）
# ---------------------------------------------------------------------------

def _make_bytearray_key(value: int = 0xAB) -> bytearray:
    """构造内容为 value 的 32 字节 bytearray 测试密钥。"""
    return bytearray([value] * 32)


# ---------------------------------------------------------------------------
# 1. activate 后三个属性正确返回传入值
# ---------------------------------------------------------------------------

def test_activate_sets_all_three_fields():
    """activate 原子设置后，key/snapshot_key/key_epoch 返回各自传入值。"""
    km = KeyManager()
    key = _make_bytearray_key(0x11)
    snapshot = _make_bytearray_key(0x22)
    epoch = 7

    km.activate(key, snapshot, epoch)

    assert km.key is key
    assert km.snapshot_key is snapshot
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

    assert km.key is new_key
    assert km.snapshot_key is old_snapshot
    assert km.key_epoch == 3


def test_update_snapshot_key_changes_only_snapshot_key():
    """update_snapshot_key 仅替换 snapshot_key，key 与 key_epoch 保持不变。"""
    km = KeyManager()
    old_key = _make_bytearray_key(0x11)
    old_snapshot = _make_bytearray_key(0x22)
    km.activate(old_key, old_snapshot, 5)

    new_snapshot = _make_bytearray_key(0x44)
    km.update_snapshot_key(new_snapshot)

    assert km.key is old_key
    assert km.snapshot_key is new_snapshot
    assert km.key_epoch == 5


def test_update_epoch_changes_only_epoch():
    """update_epoch 仅替换 key_epoch，key 与 snapshot_key 保持不变。"""
    km = KeyManager()
    key = _make_bytearray_key(0x11)
    snapshot = _make_bytearray_key(0x22)
    km.activate(key, snapshot, 1)

    km.update_epoch(42)

    assert km.key is key
    assert km.snapshot_key is snapshot
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
# 4. clear 真正清零 bytearray 密钥（验证 secure_zero_buffer 被调用 + 内容归零）
# ---------------------------------------------------------------------------

def test_clear_zeroes_bytearray_key_content():
    """clear 对 bytearray 主密钥真正清零：clear 后该 bytearray 内容全为 0。

    bytearray 是可变缓冲区，secure_zero_buffer 会通过 ctypes.memset 原地清零，
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
    assert km.key is key1 and km.snapshot_key is snapshot1 and km.key_epoch == 1

    km.clear()
    assert km.key is None and km.snapshot_key is None and km.key_epoch is None

    key2 = _make_bytearray_key(0x33)
    snapshot2 = _make_bytearray_key(0x44)
    km.activate(key2, snapshot2, 2)
    assert km.key is key2
    assert km.snapshot_key is snapshot2
    assert km.key_epoch == 2


# ---------------------------------------------------------------------------
# 6. 单字段置空（传入 None）
# ---------------------------------------------------------------------------

def test_update_key_none():
    """update_key(None) 将主密钥置空，其余字段不受影响。"""
    km = KeyManager()
    snapshot = _make_bytearray_key(0x22)
    km.activate(_make_bytearray_key(0x11), snapshot, 4)

    km.update_key(None)

    assert km.key is None
    assert km.snapshot_key is snapshot
    assert km.key_epoch == 4


def test_update_snapshot_key_none():
    """update_snapshot_key(None) 将快照密钥置空，其余字段不受影响。"""
    km = KeyManager()
    key = _make_bytearray_key(0x11)
    km.activate(key, _make_bytearray_key(0x22), 4)

    km.update_snapshot_key(None)

    assert km.key is key
    assert km.snapshot_key is None
    assert km.key_epoch == 4


def test_update_epoch_none():
    """update_epoch(None) 将密钥版本置空，其余字段不受影响。"""
    km = KeyManager()
    key = _make_bytearray_key(0x11)
    snapshot = _make_bytearray_key(0x22)
    km.activate(key, snapshot, 4)

    km.update_epoch(None)

    assert km.key is key
    assert km.snapshot_key is snapshot
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
