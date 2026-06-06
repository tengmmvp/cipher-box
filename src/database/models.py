"""数据模型定义"""

from dataclasses import dataclass, field


# 条目类型常量
ENTRY_TYPE_LOGIN = 'login'
ENTRY_TYPE_CARD = 'card'
ENTRY_TYPE_IDENTITY = 'identity'
ENTRY_TYPE_NOTE = 'note'
ENTRY_TYPE_SERVER = 'server'

ENTRY_TYPES = {
    ENTRY_TYPE_LOGIN: {'label': '登录凭证', 'icon': '🔑'},
    ENTRY_TYPE_CARD: {'label': '信用卡', 'icon': '💳'},
    ENTRY_TYPE_IDENTITY: {'label': '身份信息', 'icon': '🪪'},
    ENTRY_TYPE_NOTE: {'label': '安全笔记', 'icon': '📝'},
    ENTRY_TYPE_SERVER: {'label': '服务器', 'icon': '🖥️'},
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

    @classmethod
    def from_dict(cls, d: dict) -> 'CustomField':
        return cls(
            name=d.get('name', ''),
            value=d.get('value', ''),
            field_type=d.get('field_type', 'text'),
        )


@dataclass
class Category:
    """密码分类"""
    id: int | None = None
    name: str = ''
    icon_char: str = '📁'
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


@dataclass
class PasswordHistory:
    """密码历史记录"""
    id: int | None = None
    entry_id: int = 0
    old_password_enc: str = ''  # 加密后的旧密码
    changed_at: str = ''


@dataclass
class Entry:
    """密码条目"""
    id: int | None = None
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
    totp_secret: str = ''  # 加密后的 TOTP 密钥（空字符串表示未设置）
    created_at: str = ''
    updated_at: str = ''
    deleted_at: str = ''
    password_changed_at: str = ''
    integrity_error: bool = False
    integrity_message: str = ''

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
        return bool(self.totp_secret)

    def get_tag_list(self) -> list[str]:
        """获取标签列表"""
        if not self.tags:
            return []
        return [t.strip() for t in self.tags.split(',') if t.strip()]

    def to_dict(self, include_password: bool = True) -> dict:
        """转换为字典（用于导出）"""
        d = {
            'title': self.title,
            'username': self.username,
            'url': self.url,
            'category': self.category_name,
            'tags': self.tags,
            'notes': self.notes,
            'custom_fields': [f.to_dict() for f in self.custom_fields],
            'is_favorite': self.is_favorite,
            'password_strength': self.password_strength,
            'entry_type': self.entry_type,
            'totp_secret': self.totp_secret if include_password else '',
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'password_changed_at': self.password_changed_at,
        }
        if include_password:
            d['password'] = self.password
        return d

    @classmethod
    def from_dict(cls, d: dict) -> 'Entry':
        """从字典创建（用于导入）"""
        custom_fields = []
        if 'custom_fields' in d and isinstance(d['custom_fields'], list):
            custom_fields = [CustomField.from_dict(f) for f in d['custom_fields']]

        return cls(
            title=d.get('title', ''),
            username=d.get('username', ''),
            password=d.get('password', ''),
            url=d.get('url', ''),
            category_name=d.get('category', ''),
            tags=d.get('tags', ''),
            notes=d.get('notes', ''),
            custom_fields=custom_fields,
            is_favorite=d.get('is_favorite', False),
            entry_type=d.get('entry_type', ENTRY_TYPE_LOGIN),
            totp_secret=d.get('totp_secret', ''),
            created_at=d.get('created_at', ''),
            updated_at=d.get('updated_at', ''),
            password_changed_at=d.get('password_changed_at', ''),
        )


@dataclass
class VaultMeta:
    """保险库元数据"""
    key: str = ''
    value: str = ''
