"""数据模型定义 — 全局共享层。

Entry、Category 等模型类与字段常量是纯数据结构，不依赖任何
数据库或加密实现。放在 src 顶层使 UI、Business、Database 三层
均可安全引用，无需跨层依赖。

与 src/exceptions.py 类似，此模块是零依赖的共享基础设施。
"""

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# 字段最大长度常量，作为单一事实来源。
# 明文长度上限（密文不受此限，base64 后更长）：这些常量约束加密前的明文输入，
# 加密后存储的密文经 base64 编码 + nonce + tag，长度会显著超出上限。
MAX_FIELD_TITLE = 1024
MAX_FIELD_USERNAME = 1024
MAX_FIELD_URL = 2048
MAX_FIELD_PASSWORD = 4096
MAX_FIELD_NOTES = 65536
MAX_FIELD_TAGS = 4096
MAX_FIELD_TOTP_SECRET = 2048
MAX_CUSTOM_FIELDS_PER_ENTRY = 100
MAX_CUSTOM_FIELD_NAME = 1024
MAX_CUSTOM_FIELD_VALUE = 65536
MAX_CATEGORY_NAME = 256
MAX_PASSWORD_HISTORY = 10

# 条目类型常量
ENTRY_TYPE_LOGIN = 'login'
ENTRY_TYPE_CARD = 'card'
ENTRY_TYPE_IDENTITY = 'identity'
ENTRY_TYPE_NOTE = 'note'
ENTRY_TYPE_SERVER = 'server'

ENTRY_TYPES = {
    ENTRY_TYPE_LOGIN: {'label': '登录凭证', 'icon': '[KEY]'},
    ENTRY_TYPE_CARD: {'label': '信用卡', 'icon': '[CARD]'},
    ENTRY_TYPE_IDENTITY: {'label': '身份信息', 'icon': '[ID]'},
    ENTRY_TYPE_NOTE: {'label': '安全笔记', 'icon': '[NOTE]'},
    ENTRY_TYPE_SERVER: {'label': '服务器', 'icon': '[SRV]'},
}


@dataclass
class CustomField:
    """自定义字段。"""
    name: str
    value: str
    field_type: str = 'text'  # text, password, url, email

    # 允许的自定义字段类型
    _VALID_FIELD_TYPES = frozenset({'text', 'password', 'url', 'email'})

    def to_dict(self) -> dict:
        return {
            'name': self.name,
            'value': self.value,
            'field_type': self.field_type,
        }

    @classmethod
    def from_dict(cls, d: dict, *, strict: bool = False) -> 'CustomField':
        """从字典创建 CustomField。

        Args:
            d: 字典数据。
            strict: True 时为导入路径做严格校验，非法 field_type 或超长
                name/value 抛出 ValueError；False（默认）容错，用于解密
                读取已有数据，非法类型降级为 text 并记日志，避免崩溃。
        """
        name = d.get('name', '')
        value = d.get('value', '')
        if strict:
            if not isinstance(name, str) or len(name) > MAX_CUSTOM_FIELD_NAME:
                raise ValueError('自定义字段名称无效或过长')
            if not isinstance(value, str) or len(value) > MAX_CUSTOM_FIELD_VALUE:
                raise ValueError('自定义字段值无效或过长')
        field_type = d.get('field_type', 'text')
        if field_type not in cls._VALID_FIELD_TYPES:
            if strict:
                raise ValueError(f'无效的自定义字段类型: {field_type}')
            logger.debug("自定义字段类型 %r 非法，降级为 text", field_type)
            field_type = 'text'
        return cls(
            name=name,
            value=value,
            field_type=field_type,
        )


class Sensitive(str):
    """敏感字符串标记类型。

    透明继承 ``str``，序列化、加密、比较等行为与普通字符串完全一致，仅供 UI 渲染层通过
    ``isinstance`` 检测，使敏感字段自动以密码框渲染，避免调用方遗忘
    ``secret=True`` 导致明文 QLabel 渲染。仅由 EntryManager.decrypt_entry 在
    解密输出时包装，不影响持久化与加密。
    """

    __slots__ = ()


@dataclass
class Category:
    """密码分类。"""
    id: int | None = None
    name: str = ''
    icon_char: str = '[DIR]'
    color: str = '#666666'
    sort_order: int = 0
    created_at: str = ''

    def to_dict(self) -> dict:
        return {
            'id': self.id,
            'name': self.name,
            'icon_char': self.icon_char,
            'color': self.color,
            'sort_order': self.sort_order,
            'created_at': self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'Category':
        """从字典创建 Category，与 to_dict 对称。

        对文本字段做长度校验，作为导入/恢复路径的纵深防御；
        上游备份恢复的 _validate_categories 已做更严格的结构校验。
        """
        name = data.get('name', '')
        if not isinstance(name, str):
            raise ValueError('分类名称类型无效，必须为字符串')
        name = name.strip()
        if len(name) > MAX_CATEGORY_NAME:
            raise ValueError(f'分类名称过长（最多 {MAX_CATEGORY_NAME} 字符）')
        icon_char = data.get('icon_char', '[DIR]')
        if not isinstance(icon_char, str):
            raise ValueError('分类图标类型无效')
        if len(icon_char) > 32:
            raise ValueError('分类图标过长')
        color = data.get('color', '#666666')
        if not isinstance(color, str):
            raise ValueError('分类颜色类型无效')
        if len(color) > 32:
            raise ValueError('分类颜色过长')
        sort_order = data.get('sort_order', 0)
        # 排除 bool（bool 是 int 子类），与 Entry.from_dict 的严格类型校验风格对齐
        if not isinstance(sort_order, int) or isinstance(sort_order, bool):
            raise ValueError('分类排序值类型无效，必须为整数')
        return cls(
            id=data.get('id'),
            name=name,
            icon_char=icon_char,
            color=color,
            sort_order=sort_order,
            created_at=data.get('created_at', ''),
        )


@dataclass
class PasswordHistory:
    """密码历史记录。"""
    id: int | None = None
    entry_id: int = 0
    old_password_enc: str = ''  # 加密后的旧密码
    changed_at: str = ''
    entry_crypto_id: str = ''

    def to_dict(self) -> dict:
        """转换为字典，用于调试和日志输出。

        注意：此方法故意不导出 old_password_enc，避免泄漏加密密文。
        备份/恢复使用专用二进制路径 BackupRestoreManager，不经过此方法。
        此方法与 Entry.to_dict/from_dict 不同，不构成完整的序列化往返对。
        如需序列化密码历史，应使用 BackupRestoreManager 的二进制备份格式。
        """
        return {
            'id': self.id,
            'entry_id': self.entry_id,
            'changed_at': self.changed_at,
            'entry_crypto_id': self.entry_crypto_id,
        }


@dataclass
class Entry:
    """密码条目（明文态）。

    custom_fields 为已解密的 list[CustomField]。数据库密文态由独立的 RawEntry 表示，
    经 EntryManager.decrypt_entry 解密后得到本类。is_decrypted 恒为 True。签名/写库
    等需密文的场景操作 RawEntry（其 custom_fields 即密文）。
    """

    id: int | None = None
    crypto_id: str = ''
    title: str = ''
    username: str = ''
    password: str = ''
    url: str = ''
    category_id: int | None = None
    category_name: str = ''
    tags: str = ''
    notes: str = ''
    custom_fields: list[CustomField] = field(default_factory=list)
    is_favorite: bool = False
    is_deleted: bool = False
    password_strength: int = 0
    entry_type: str = ENTRY_TYPE_LOGIN  # login, card, identity, note, server
    totp_secret: str = ''  # 加密后的 TOTP 密钥，空字符串表示未设置
    created_at: str = ''
    updated_at: str = ''
    deleted_at: str = ''
    password_changed_at: str = ''
    metadata_mac: str = ''
    # 运行时字段
    integrity_error: bool = False
    integrity_message: str = ''
    # password_present / totp_present 由 crypto_utils.copy_entry_fields 设置，
    # 标记原始数据库条目中该字段是否包含非空密文。解密后若值为空则
    # 表示"已加密但内容为空字符串"，而非"从未存储过"。
    password_present: bool = False
    totp_present: bool = False

    @property
    def is_decrypted(self) -> bool:
        """custom_fields 是否已解密为 list[CustomField]。"""
        return isinstance(self.custom_fields, list)

    def assert_decrypted(self) -> None:
        """断言条目已解密，否则抛出 ValueError。

        供 to_dict() 等需要已解密状态的方法在入口处做防御性检查，
        避免意外将密文当作明文输出。
        """
        if not self.is_decrypted:
            raise ValueError(
                f'Entry (id={self.id}, title={self.title!r}) 尚未解密，'
                f'custom_fields 类型为 {type(self.custom_fields).__name__}'
            )

    @property
    def type_icon(self) -> str:
        """获取条目类型图标。"""
        return ENTRY_TYPES.get(self.entry_type, ENTRY_TYPES[ENTRY_TYPE_LOGIN])['icon']

    @property
    def type_label(self) -> str:
        """获取条目类型标签。"""
        return ENTRY_TYPES.get(self.entry_type, ENTRY_TYPES[ENTRY_TYPE_LOGIN])['label']

    @property
    def has_totp(self) -> bool:
        """是否配置了 TOTP。"""
        return self.totp_present or bool(self.totp_secret)

    def get_tag_list(self) -> list[str]:
        """获取标签列表。"""
        if not self.tags:
            return []
        return [t.strip() for t in self.tags.split(',') if t.strip()]

    def to_dict(self, include_password: bool = False) -> dict:
        """转换为字典，供导出流程使用。

        非持久化字段不参与导出，包括 id、crypto_id、is_deleted、deleted_at、
        integrity_error、integrity_message、password_present 与 totp_present，
        导入时由 from_dict 重新生成或使用默认值。

        Raises:
            ValueError: 条目未解密时调用，防止泄漏加密密文。
        """
        self.assert_decrypted()
        custom_fields = self.custom_fields
        # assert_decrypted 已保证已解密；isinstance 兼作类型收窄（供静态分析）
        # 与运行时防御（不受 python -O 影响，替代原 assert）。
        if not isinstance(custom_fields, list):
            raise TypeError('custom_fields 必须为已解密的列表')
        d = {
            'title': self.title,
            'username': self.username,
            'url': self.url,
            'category': self.category_name,
            'tags': self.tags,
            'notes': self.notes,
            'custom_fields': [
                f.to_dict() for f in custom_fields
                if include_password or f.field_type != 'password'
            ],
            'is_favorite': self.is_favorite,
            'password_strength': self.password_strength,
            'entry_type': self.entry_type,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'password_changed_at': self.password_changed_at,
        }
        if include_password:
            d['password'] = self.password
            d['totp_secret'] = self.totp_secret
        return d

    @classmethod
    def from_dict(cls, d: dict) -> 'Entry':
        """从字典创建，供导入流程使用。

        仅恢复用户可见字段；数据库元数据如 id、crypto_id、时间戳、is_deleted 等
        在导入流程中由 EntryManager 或 BackupRestoreManager 单独处理，
        不从此字典读取。
        """
        entry_type = d.get('entry_type', ENTRY_TYPE_LOGIN)
        if entry_type not in ENTRY_TYPES:
            raise ValueError(f'无效的条目类型: {entry_type}')

        # 表驱动长度校验，单一循环替代 7 段重复的 if len > MAX 模板
        field_limits = [
            ('title', '标题', MAX_FIELD_TITLE),
            ('url', 'URL', MAX_FIELD_URL),
            ('notes', '备注', MAX_FIELD_NOTES),
            ('username', '用户名', MAX_FIELD_USERNAME),
            ('password', '密码', MAX_FIELD_PASSWORD),
            ('tags', '标签', MAX_FIELD_TAGS),
            ('totp_secret', 'TOTP 密钥', MAX_FIELD_TOTP_SECRET),
        ]
        values = {}
        for key, label, max_len in field_limits:
            value = d.get(key, '')
            if not isinstance(value, str):
                raise ValueError(f'{label}类型无效，必须为字符串')
            if len(value) > max_len:
                raise ValueError(f'{label}过长（最多 {max_len} 字符）')
            values[key] = value
        title = values['title']
        url = values['url']
        notes = values['notes']
        username = values['username']
        password = values['password']
        tags = values['tags']
        totp_secret = values['totp_secret']

        custom_fields = []
        if 'custom_fields' in d and isinstance(d['custom_fields'], list):
            # strict=True：导入路径拒绝非法类型与超长字段，避免静默降级掩盖损坏数据
            custom_fields = [CustomField.from_dict(f, strict=True) for f in d['custom_fields']]
        # 限制单条目自定义字段数量，防御恶意或异常导入数据。
        # 与 backup _validate_entries 的结构校验保持一致的防御意图。
        if len(custom_fields) > MAX_CUSTOM_FIELDS_PER_ENTRY:
            raise ValueError('自定义字段数量过多（最多 100 个）')

        return cls(
            title=title,
            username=username,
            password=password,
            url=url,
            category_name=d.get('category', ''),
            tags=tags,
            notes=notes,
            custom_fields=custom_fields,
            is_favorite=d.get('is_favorite') is True,
            entry_type=entry_type,
            totp_secret=totp_secret,
            created_at=d.get('created_at', ''),
            updated_at=d.get('updated_at', ''),
            password_changed_at=d.get('password_changed_at', ''),
        )


@dataclass
class RawEntry:
    """从数据库读取的密文态条目。

    加密字段（username/password/notes/totp_secret/custom_fields）为密文字符串；
    ``custom_fields`` 为密文 JSON 字符串（区别于明文态 :class:`Entry` 的
    ``list[CustomField]``）。经 ``EntryManager.decrypt_entry`` /
    ``build_entry_summary`` 解密为明文 Entry。

    ``is_decrypted`` 恒为 False；``custom_fields_db_value`` 返回 ``custom_fields``
    （密文），供签名、重加密、备份等需要密文的场景。与 Entry 共享字段名以便显式
    转换，但 ``custom_fields`` 类型不同（str vs list），编译期可分辨，消除原先
    同名字段双语义（DB-raw 密文 str / 解密 list 共存于 Entry）导致的误用风险——
    对 RawEntry 误调用 list 方法、或对明文 Entry 误当密文，都会被类型检查捕获。
    """

    id: int | None = None
    crypto_id: str = ''
    title: str = ''
    username: str = ''
    password: str = ''
    url: str = ''
    category_id: int | None = None
    category_name: str = ''
    tags: str = ''
    notes: str = ''
    custom_fields: str = ''
    is_favorite: bool = False
    is_deleted: bool = False
    password_strength: int = 0
    entry_type: str = ENTRY_TYPE_LOGIN
    totp_secret: str = ''
    created_at: str = ''
    updated_at: str = ''
    deleted_at: str = ''
    password_changed_at: str = ''
    metadata_mac: str = ''
    # 运行时字段（_row_to_entry 在 LENIENT 校验失败时设置）
    integrity_error: bool = False
    integrity_message: str = ''
    password_present: bool = False
    totp_present: bool = False

    @property
    def is_decrypted(self) -> bool:
        """RawEntry 恒为密文态。"""
        return False

    def assert_decrypted(self) -> None:
        """RawEntry 是密文态，调用此方法说明误把密文当明文使用。"""
        raise ValueError(
            f'RawEntry (id={self.id}, title={self.title!r}) 是密文态，'
            f'需先经 EntryManager.decrypt_entry 解密为 Entry'
        )

    @property
    def custom_fields_db_value(self) -> str:
        """密文 custom_fields，直接用于 DB 存储/签名/重加密。"""
        return self.custom_fields

    @property
    def type_icon(self) -> str:
        return ENTRY_TYPES.get(self.entry_type, ENTRY_TYPES[ENTRY_TYPE_LOGIN])['icon']

    @property
    def type_label(self) -> str:
        return ENTRY_TYPES.get(self.entry_type, ENTRY_TYPES[ENTRY_TYPE_LOGIN])['label']

    @property
    def has_totp(self) -> bool:
        return self.totp_present or bool(self.totp_secret)

    def get_tag_list(self) -> list[str]:
        if not self.tags:
            return []
        return [t.strip() for t in self.tags.split(',') if t.strip()]
