"""异常到用户友好消息的统一翻译层（UI 入口，re-export 自业务层）。

实际翻译逻辑集中在上层 :mod:`src.business.services.error_messages`，使业务层
（``backup_restore`` / ``vault_lifecycle``）与 UI 层共享单一翻译源，避免同一异常
在不同入口呈现不一致文案（如 ``DecryptionError`` 在备份入口透传 ``crypto_id`` 而
UI 层归一为「解密失败」）。本模块仅作 UI 层的稳定导入入口
（``from ..error_messages import to_user_message``），使 UI 调用方无需感知业务层
模块路径，且保持 UI→Business 的依赖方向。
"""

from ..business.services.error_messages import to_user_message

__all__ = ['to_user_message']
