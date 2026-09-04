"""限时加密共享包文件命名约定。

集中扩展名与文件名构造，使 .cboxshare 数据包与配套 decrypt.html 解密器同名干 +
不同扩展名，便于接收方配对识别。
"""

from ....utils.format import timestamped_suffix

SHARE_EXT = ".cboxshare"
DECRYPTER_EXT = ".html"


def build_share_filenames(prefix: str = "cipherbox_share_") -> tuple[str, str]:
    """构造带 UTC 时间戳与随机后缀的共享包与解密器文件名对。

    返回 ``(share_filename, decrypter_filename)``，两者共用时间戳+随机干、不同扩展名，
    便于发送方一次生成、接收方配对识别；后缀干经共享
    :func:`src.utils.format.timestamped_suffix` 构造（QL-082）。
    """
    base = f"{prefix}{timestamped_suffix()}"
    return f"{base}{SHARE_EXT}", f"{base}{DECRYPTER_EXT}"
