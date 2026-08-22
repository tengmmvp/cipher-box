"""限时加密共享包文件命名约定。

集中扩展名与文件名构造，使 .cboxshare 数据包与配套 decrypt.html 解密器同名干 +
不同扩展名，便于接收方配对识别。
"""

import uuid
from datetime import UTC, datetime

SHARE_EXT = ".cboxshare"
DECRYPTER_EXT = ".html"

# 共享包文件名时间戳格式，单一事实源。
_SHARE_NAME_TS_FORMAT = "%Y%m%d_%H%M%S_%f"


def build_share_filenames(prefix: str = "cipherbox_share_") -> tuple[str, str]:
    """构造带 UTC 时间戳与随机后缀的共享包与解密器文件名对。

    返回 ``(share_filename, decrypter_filename)``，两者共用时间戳+随机干、不同扩展名，
    便于发送方一次生成、接收方配对识别。
    """
    stamp = datetime.now(UTC).strftime(_SHARE_NAME_TS_FORMAT)
    suffix = uuid.uuid4().hex[:8]
    base = f"{prefix}{stamp}_{suffix}"
    return f"{base}{SHARE_EXT}", f"{base}{DECRYPTER_EXT}"
