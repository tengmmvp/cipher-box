"""数据模型定义 — 全局共享层。

模型类（Entry、Category 等）和字段常量是纯数据结构，不依赖任何
数据库或加密实现。放在 src 顶层使 UI、Business、Database 三层
均可安全引用，无需跨层依赖。

与 src/exceptions.py 类似，此模块是零依赖的共享基础设施。
"""

from dataclasses import dataclass, field

# 字段最大长度常量，作为单一事实来源
MAX_FIELD_TITLE = 1024
MAX_FIELD_USERNAME = 1024
MAX_FIELD_URL = 2048
MAX_FIELD_PASSWORD = 4096
MAX_FIELD_NOTES = 65536
MAX_FIELD_TAGS = 4096
MAX_FIELD_TOTP_SECRET = 2048
MAX_CUSTOM_FIELDS_PER_ENTRY = 100
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
    """自定义字段"""
    name: str
    value: str
    field_type: str = 'text'  # text, password, url, email

    def to_dict(self) -> dict:
        return {
            'name': self.name,
            'value': self.value,
            'field_type': self.field_type,
        }

    # 允许的自定义字段类型
    _VALID_FIELD_TYPES = frozenset({'text', 'password', 'url', 'email'})

    @classmethod
    def from_dict(cls, d: dict) -> 'CustomField':
        field_type = d.get('field_type', 'text')
        if field_type not in cls._VALID_FIELD_TYPES:
            field_type = 'text'
        return cls(
            name=d.get('name', ''),
            value=d.get('value', ''),
            field_type=field_type,
        )


class Sensitive(str):
    """敏感字符串标记类型。

    透明继承 ``str``（序列化、加密、比较等行为完全一致），仅供 UI 渲染层通过
    ``isinstance`` 检测，使敏感字段自动以密码框渲染，避免调用方遗忘
    ``secret=True`` 导致明文 QLabel 渲染。仅由 EntryManager.decrypt_entry 在
    解密输出时包装，不影响持久化与加密。
    """

    __slots__ = ()


@dataclass
class Category:
    """密码分类"""
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
        """从字典创建 Category，与 to_dict 对称。"""
        return cls(
            id=data.get('id'),
            name=data.get('name', '').strip(),
            icon_char=data.get('icon_char', '[DIR]'),
            color=data.get('color', '#666666'),
            sort_order=data.get('sort_order', 0),
            created_at=data.get('created_at', ''),
        )


@dataclass
class PasswordHistory:
    """密码历史记录"""
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
    """密码条目

    custom_fields 双重类型状态机：
    - DB-raw 状态：从数据库读取后为 str（加密密文），custom_fields_enc 与之相同
    - Decrypted 状态：经 EntryManager.decrypt_entry() 解密后为 list[CustomField]
    - 消费者可通过 is_decrypted 属性检查当前状态
    - 使用 custom_fields_db_value 属性可安全获取用于 DB 存储的密文值
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
    custom_fields_enc: str = ''
    custom_fields: list[CustomField] | str = field(default_factory=list)
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
        """custom_fields 是否已解密（为 list[CustomField]）。"""
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
    def custom_fields_db_value(self) -> str:
        """返回用于数据库存储的加密字符串。

        当 custom_fields 为 str（原始密文）时直接返回；
        当 custom_fields 为 list（已解密）时回退到 custom_fields_enc。
        """
        return self.custom_fields if isinstance(self.custom_fields, str) else self.custom_fields_enc

    @property
    def type_icon(self) -> str:
        """获取条目类型图标"""
        return ENTRY_TYPES.get(self.entry_type, ENTRY_TYPES[ENTRY_TYPE_LOGIN])['icon']

    @property
    def type_label(self) -> str:
        """获取条目类型标签"""
        return ENTRY_TYPES.get(self.entry_type, ENTRY_TYPES[ENTRY_TYPE_LOGIN])['label']

    @property
    def has_totp(self) -> bool:
        """是否配置了 TOTP"""
        return self.totp_present or bool(self.totp_secret)

    def get_tag_list(self) -> list[str]:
        """获取标签列表"""
        if not self.tags:
            return []
        return [t.strip() for t in self.tags.split(',') if t.strip()]

    def to_dict(self, include_password: bool = False) -> dict:
        """转换为字典（用于导出）。

        非持久化字段（id、crypto_id、is_deleted、deleted_at、
        integrity_error、integrity_message、
        password_present、totp_present）不参与导出，
        导入时由 from_dict 重新生成或使用默认值。

        Raises:
            ValueError: 条目未解密时调用，防止泄漏加密密文。
        """
        self.assert_decrypted()
        custom_fields = self.custom_fields
        assert isinstance(custom_fields, list)
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
        """从字典创建（用于导入）。

        仅恢复用户可见字段；数据库元数据（id、crypto_id、时间戳、
        is_deleted 等）在导入流程中由 EntryManager 或 BackupRestoreManager
        单独处理，不从此字典读取。
        """
        entry_type = d.get('entry_type', ENTRY_TYPE_LOGIN)
        if entry_type not in ENTRY_TYPES:
            raise ValueError(f'无效的条目类型: {entry_type}')

        title = d.get('title', '')
        if len(title) > MAX_FIELD_TITLE:
            raise ValueError(f'标题过长（最多 {MAX_FIELD_TITLE} 字符）')
        url = d.get('url', '')
        if len(url) > MAX_FIELD_URL:
            raise ValueError(f'URL 过长（最多 {MAX_FIELD_URL} 字符）')
        notes = d.get('notes', '')
        if len(notes) > MAX_FIELD_NOTES:
            raise ValueError(f'备注过长（最多 {MAX_FIELD_NOTES} 字符）')

        username = d.get('username', '')
        if len(username) > MAX_FIELD_USERNAME:
            raise ValueError(f'用户名过长（最多 {MAX_FIELD_USERNAME} 字符）')
        password = d.get('password', '')
        if len(password) > MAX_FIELD_PASSWORD:
            raise ValueError(f'密码过长（最多 {MAX_FIELD_PASSWORD} 字符）')
        tags = d.get('tags', '')
        if len(tags) > MAX_FIELD_TAGS:
            raise ValueError(f'标签过长（最多 {MAX_FIELD_TAGS} 字符）')
        totp_secret = d.get('totp_secret', '')
        if len(totp_secret) > MAX_FIELD_TOTP_SECRET:
            raise ValueError(f'TOTP 密钥过长（最多 {MAX_FIELD_TOTP_SECRET} 字符）')

        custom_fields = []
        if 'custom_fields' in d and isinstance(d['custom_fields'], list):
            custom_fields = [CustomField.from_dict(f) for f in d['custom_fields']]
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
            is_favorite=d.get('is_favorite', False),
            entry_type=entry_type,
            totp_secret=totp_secret,
            created_at=d.get('created_at', ''),
            updated_at=d.get('updated_at', ''),
            password_changed_at=d.get('password_changed_at', ''),
        )
