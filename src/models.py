"""数据模型定义 — 全局共享层。

纯数据结构（Entry/Category 等）与字段常量，不依赖数据库或加密实现；
置于 src 顶层供 UI/Business/Data 三层引用，无跨层依赖。
"""

import logging
from dataclasses import dataclass, field, fields
from types import MappingProxyType
from typing import Any

from .exceptions import EntryError

logger = logging.getLogger(__name__)


def is_real_int(value: object) -> bool:
    """判断是否为真正的 int，排除 bool（bool 是 int 子类）。

    供 models / backup_restore 等多处复用，避免 ``isinstance(x, int) or isinstance(x, bool)``
    重复与笔误。
    """
    return isinstance(value, int) and not isinstance(value, bool)


# 字段最大长度常量。约束加密前的明文输入；密文经 base64+nonce+tag 后显著更长，
# 故密文不受此限。
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

# 导入/备份共享的条目数与单条目载荷上限，供 import_export 与 backup_validator 复用，
# 避免两处独立声明漂移产生「能导入却无法备份」的边界。
MAX_ENTRIES_LIMIT = 50_000
MAX_ENTRY_PAYLOAD_SIZE = 2 * 1024 * 1024

# 加密密文格式前缀，跨层单一事实源：EncryptionEngine、db_manager._assert_encrypted
# 与日志脱敏正则均引用此处。格式升级时字面量散落多处会静默漂移——脱敏正则失效会
# 致密文明文落入日志文件。
CIPHERTEXT_PREFIX = 'cb2:'
CIPHERTEXT_BYTES_PREFIX = b'CB2'

# 字段名 → (中文标签, 最大字符数)，表驱动长度校验单一事实源，供 from_dict /
# validate_plain_entry / CSV 导入复用。仅含长度受限的字符串型字段。
ENTRY_FIELD_LIMITS: tuple[tuple[str, str, int], ...] = (
    ('title', '标题', MAX_FIELD_TITLE),
    ('username', '用户名', MAX_FIELD_USERNAME),
    ('password', '密码', MAX_FIELD_PASSWORD),
    ('url', 'URL', MAX_FIELD_URL),
    ('tags', '标签', MAX_FIELD_TAGS),
    ('notes', '备注', MAX_FIELD_NOTES),
    ('totp_secret', 'TOTP 密钥', MAX_FIELD_TOTP_SECRET),
)

# 条目类型常量
ENTRY_TYPE_LOGIN = 'login'
ENTRY_TYPE_CARD = 'card'
ENTRY_TYPE_IDENTITY = 'identity'
ENTRY_TYPE_NOTE = 'note'
ENTRY_TYPE_SERVER = 'server'

# 只读映射：MappingProxyType 使误用 ``ENTRY_TYPES[k] = ...`` / ``.pop()`` 等原地突变
# 在运行时即抛 TypeError，防止模块级常量被无意改写（ARCH-024）。读取路径
#（``in`` / ``[]`` / ``.items()`` / ``.get()``）与原 dict 完全一致。
ENTRY_TYPES = MappingProxyType({
    ENTRY_TYPE_LOGIN: {'label': '登录凭证', 'icon': '[KEY]'},
    ENTRY_TYPE_CARD: {'label': '信用卡', 'icon': '[CARD]'},
    ENTRY_TYPE_IDENTITY: {'label': '身份信息', 'icon': '[ID]'},
    ENTRY_TYPE_NOTE: {'label': '安全笔记', 'icon': '[NOTE]'},
    ENTRY_TYPE_SERVER: {'label': '服务器', 'icon': '[SRV]'},
})

# 专用字段 storage_name（带 ``_`` 前缀命名空间，与用户自定义字段隔离）。
# entry_dialog 的 ``_SPECIAL_SCHEMA`` 与 import_export 的 Bitwarden/CSV 导入共用
# 此单一事实源，防止字段重命名时导入路径写出与 UI schema 不匹配的 storage_name，
# 导致导入的卡片/身份/服务器条目在编辑对话框无法回填（_ALL_SPECIAL_BY_STORAGE
# 按 storage_name 精确匹配）。
SPECIAL_FIELD_CARD_HOLDER = '_card_holder'
SPECIAL_FIELD_CARD_NUMBER = '_card_number'
SPECIAL_FIELD_CARD_EXPIRY = '_card_expiry'
SPECIAL_FIELD_CARD_CVV = '_card_cvv'
SPECIAL_FIELD_ID_FULLNAME = '_id_fullname'
SPECIAL_FIELD_ID_EMAIL = '_id_email'
SPECIAL_FIELD_ID_PHONE = '_id_phone'
SPECIAL_FIELD_ID_ADDRESS = '_id_address'
SPECIAL_FIELD_SERVER_HOST = '_server_host'
SPECIAL_FIELD_SERVER_PORT = '_server_port'
SPECIAL_FIELD_SERVER_PROTOCOL = '_server_protocol'


@dataclass(repr=False, frozen=True)
class CustomField:
    """自定义字段。"""
    name: str
    value: str
    field_type: str = 'text'  # text, password, url, email

    # 允许的自定义字段类型
    _VALID_FIELD_TYPES = frozenset({'text', 'password', 'url', 'email'})

    def __repr__(self) -> str:
        return (
            f'CustomField(name={self.name!r}, value=<redacted>, '
            f'field_type={self.field_type!r})'
        )

    def to_dict(self) -> dict[str, Any]:
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
                raise EntryError('自定义字段名称无效或过长')
            if not isinstance(value, str) or len(value) > MAX_CUSTOM_FIELD_VALUE:
                raise EntryError('自定义字段值无效或过长')
        field_type = d.get('field_type', 'text')
        if field_type not in cls._VALID_FIELD_TYPES:
            if strict:
                raise EntryError(f'无效的自定义字段类型: {field_type}')
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

    def __repr__(self) -> str:
        return "Sensitive('<redacted>')"


@dataclass(frozen=True)
class Category:
    """密码分类。"""
    id: int | None = None
    name: str = ''
    icon_char: str = '[DIR]'
    color: str = '#666666'
    sort_order: int = 0
    created_at: str = ''
    metadata_mac: str = ''  # 元数据完整性 HMAC 签名（与 Entry.metadata_mac 对称）
    # 运行时完整性标志（不入库、不序列化，to_dict 不含）：LENIENT 验签失败时置 True，
    # 供 UI 提示。与 RawEntry.integrity_error 对称，使分类元数据篡改（icon/color/
    # sort_order 等非加密字段）对用户可见——原先仅记日志，用户无法察觉分类层 HMAC
    # 失败（分类名密文仍由 GCM 认证兜底，但元数据篡改可静默通过）。
    integrity_error: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            'id': self.id,
            'name': self.name,
            'icon_char': self.icon_char,
            'color': self.color,
            'sort_order': self.sort_order,
            'created_at': self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> 'Category':
        """从字典创建 Category，与 to_dict 对称。

        对文本字段做长度校验，作为导入/恢复路径的纵深防御；
        上游备份恢复的 _validate_categories 已做更严格的结构校验。
        """
        name = data.get('name', '')
        if not isinstance(name, str):
            raise EntryError('分类名称类型无效，必须为字符串')
        name = name.strip()
        if len(name) > MAX_CATEGORY_NAME:
            raise EntryError(f'分类名称过长（最多 {MAX_CATEGORY_NAME} 字符）')
        icon_char = data.get('icon_char', '[DIR]')
        if not isinstance(icon_char, str):
            raise EntryError('分类图标类型无效')
        if len(icon_char) > 32:
            raise EntryError('分类图标过长')
        color = data.get('color', '#666666')
        if not isinstance(color, str):
            raise EntryError('分类颜色类型无效')
        if len(color) > 32:
            raise EntryError('分类颜色过长')
        sort_order = data.get('sort_order', 0)
        # 排除 bool（bool 是 int 子类），与 Entry.from_dict 的严格类型校验风格对齐
        if not is_real_int(sort_order):
            raise EntryError('分类排序值类型无效，必须为整数')
        return cls(
            id=data.get('id'),
            name=name,
            icon_char=icon_char,
            color=color,
            sort_order=sort_order,
            created_at=data.get('created_at', ''),
        )


@dataclass(frozen=True)
class PasswordHistory:
    """密码历史记录。"""
    id: int | None = None
    entry_id: int = 0
    old_password_enc: str = ''  # 加密后的旧密码
    changed_at: str = ''
    entry_crypto_id: str = ''

    def to_dict(self) -> dict[str, Any]:
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


def _entry_type_icon(entry_type: str) -> str:
    """条目类型图标（未知类型回退 login）。"""
    return ENTRY_TYPES.get(entry_type, ENTRY_TYPES[ENTRY_TYPE_LOGIN])['icon']


def _entry_type_label(entry_type: str) -> str:
    """条目类型标签（未知类型回退 login）。"""
    return ENTRY_TYPES.get(entry_type, ENTRY_TYPES[ENTRY_TYPE_LOGIN])['label']


def _entry_has_totp(totp_present: bool, totp_secret: str) -> bool:
    """是否配置了 TOTP（显式标记或存在 secret）。"""
    return totp_present or bool(totp_secret)


def _parse_tag_list(tags: str) -> list[str]:
    """逗号分隔的 tags 字符串解析为去空白、去空的标签列表。"""
    if not tags:
        return []
    return [t.strip() for t in tags.split(',') if t.strip()]


@dataclass(repr=False, frozen=True)
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

    def __repr__(self) -> str:
        return (
            f'Entry(id={self.id!r}, title={self.title!r}, '
            f'entry_type={self.entry_type!r}, integrity_error={self.integrity_error!r})'
        )

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
        return _entry_type_icon(self.entry_type)

    @property
    def type_label(self) -> str:
        """获取条目类型标签。"""
        return _entry_type_label(self.entry_type)

    @property
    def has_totp(self) -> bool:
        """是否配置了 TOTP。"""
        return _entry_has_totp(self.totp_present, self.totp_secret)

    def get_tag_list(self) -> list[str]:
        """获取标签列表。"""
        return _parse_tag_list(self.tags)

    def to_dict(self, include_password: bool = False) -> dict[str, Any]:
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
            raise EntryError(f'无效的条目类型: {entry_type}')

        # 表驱动长度校验，单一事实源见 models.ENTRY_FIELD_LIMITS
        field_limits = ENTRY_FIELD_LIMITS
        values = {}
        for key, label, max_len in field_limits:
            value = d.get(key, '')
            if not isinstance(value, str):
                raise EntryError(f'{label}类型无效，必须为字符串')
            if len(value) > max_len:
                raise EntryError(f'{label}过长（最多 {max_len} 字符）')
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
            raise EntryError('自定义字段数量过多（最多 100 个）')

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


@dataclass(frozen=True)
class RawEntry:
    """从数据库读取的密文态条目。

    以下字段（title/username/password/url/tags/notes/totp_secret/custom_fields）
    为密文字符串——这些是 RawEntry/Entry 共享的逻辑字段名，DB 层对应 ``*_enc`` 列；
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
            '需先经 EntryManager.decrypt_entry 解密为 Entry'
        )

    @property
    def custom_fields_db_value(self) -> str:
        """密文 custom_fields，直接用于 DB 存储/签名/重加密。"""
        return self.custom_fields

    @property
    def type_icon(self) -> str:
        """获取条目类型图标。"""
        return _entry_type_icon(self.entry_type)

    @property
    def type_label(self) -> str:
        """获取条目类型标签。"""
        return _entry_type_label(self.entry_type)

    @property
    def has_totp(self) -> bool:
        """是否配置了 TOTP。"""
        return _entry_has_totp(self.totp_present, self.totp_secret)

    def get_tag_list(self) -> list[str]:
        """获取标签列表。"""
        return _parse_tag_list(self.tags)


# 运行时守护：RawEntry（DB 密文态）与 Entry（明文态）字段名集合必须一致
# （custom_fields 仅类型不同：str vs list[CustomField]，字段名相同）。任一方新增
# 字段而另一方漏更将导致 DB 读写丢失字段——模块加载时即捕获，仿 entry_repository
# 对 _RE_ENCRYPT_COLUMNS 的字段集断言模式。
if {f.name for f in fields(RawEntry)} != {f.name for f in fields(Entry)}:
    raise RuntimeError('RawEntry 与 Entry 字段集不一致，DB 读写可能丢失字段')
