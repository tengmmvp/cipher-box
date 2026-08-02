"""share_paths 文件名配对契约测试。

钉住「两文件同名干 + 不同扩展名」契约，避免日后误改 ``_SHARE_NAME_TS_FORMAT`` 或
扩展名常量时仅靠 create_share_package 慢路径捕获。
"""

from src.business.services.share_paths import (
    DECRYPTER_EXT,
    SHARE_EXT,
    build_share_filenames,
)


def test_build_share_filenames_pair_extension_and_same_stem():
    """两文件同名干、扩展名分别为 .cboxshare/.html，便于接收方配对识别。"""
    share, decrypter = build_share_filenames()
    assert share.endswith(SHARE_EXT)
    assert decrypter.endswith(DECRYPTER_EXT)
    # 同干（去扩展名后一致）
    assert share[: -len(SHARE_EXT)] == decrypter[: -len(DECRYPTER_EXT)]


def test_build_share_filenames_unique_per_call():
    """两次构造文件名不同（UTC 时间戳 + 随机后缀）。"""
    a = build_share_filenames()
    b = build_share_filenames()
    assert a != b
