"""utils.memory 安全清零工具测试。

secure_zero_buffer 是密钥清零的核心安全原语。覆盖 bytearray
原地清零、bytes 误传仅告警（原对象不变）、空输入短路、mark_secret_discarded
对临时副本清零不抛异常。
"""

import logging

from src.utils.memory import mark_secret_discarded, secure_zero_buffer


class TestSecureZeroBuffer:
    """secure_zero_buffer 的 bytearray 原地清零、空输入短路与 bytes 误传告警测试。"""

    def test_bytearray_zeroed_in_place(self):
        buf = bytearray(b"sensitive_key_data_123")
        secure_zero_buffer(buf)
        assert bytes(buf) == b"\x00" * len(buf)

    def test_empty_input_short_circuits(self):
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
    """mark_secret_discarded 对空字符串与临时副本清零的边界行为测试。"""

    def test_empty_string_noop(self):
        mark_secret_discarded("")

    def test_non_empty_does_not_raise(self):
        # 仅清零 UTF-16 临时副本，不应抛异常（语义占位，非原地擦除）
        mark_secret_discarded("some_secret_token")
