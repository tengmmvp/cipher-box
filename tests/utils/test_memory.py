"""utils.memory 安全清零工具测试。

secure_zero_buffer 是密钥清零的核心安全原语。覆盖 bytearray
原地清零、bytes 误传仅告警（原对象不变）、空输入短路、mark_secret_discarded
语义占位不抛异常（CPython str 不可变，无原地擦除）。
"""

import logging

from src.utils.memory import mark_secret_discarded, secure_zero_buffer


class TestSecureZeroBuffer:
    """secure_zero_buffer 的 bytearray 原地清零、空输入短路与 bytes 误传告警测试。"""

    def test_bytearray_zeroed_in_place(self):
        """可变 bytearray 经 secure_zero_buffer 后内容原地置零。"""
        buf = bytearray(b"sensitive_key_data_123")
        secure_zero_buffer(buf)
        assert bytes(buf) == b"\x00" * len(buf)

    def test_empty_input_short_circuits(self):
        """空 bytearray / bytes 短路返回，不抛异常。"""
        secure_zero_buffer(bytearray())
        secure_zero_buffer(b"")

    def test_bytes_not_zeroed_but_warns(self, caplog):
        data = b"secret_value"
        with caplog.at_level(logging.WARNING, logger="src.utils.memory"):
            secure_zero_buffer(data)
        # bytes 不可变：原对象内容不变（假清零）
        assert data == b"secret_value"
        # 应留下可见告警，使「安全清零实际空转」隐患可见而非静默
        assert any("bytes" in r.message for r in caplog.records)


class TestMarkSecretDiscarded:
    """mark_secret_discarded 的语义占位行为：不抛异常、不修改入参。"""

    def test_empty_string_noop(self):
        mark_secret_discarded("")

    def test_non_empty_does_not_raise(self):
        # 纯语义占位（M2）：CPython str 不可变，函数无原地擦除，仅承载「已弃用」契约；
        # 真正释放由调用方置空引用 + GC，此处仅验证不抛异常。
        mark_secret_discarded("some_secret_token")
