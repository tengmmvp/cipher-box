"""条目管理器，负责密码条目的加密 CRUD 操作。

架构说明：EntryManager 直接依赖 crypto_utils 的 encrypt_field 与 decrypt_field，
这属于 Business → Crypto 的同层依赖，符合架构约束。UI 层通过 EntryManager
间接访问这些加密原语，不直接导入 crypto 模块。
"""

import json
import logging
import threading
import uuid
from typing import TYPE_CHECKING, Callable, Optional

if TYPE_CHECKING:
    from .vault_manager import VaultManager

from ...crypto.password_generator import PasswordGenerator
from ...crypto.totp import TOTPGenerator
from ...exceptions import DecryptionError, EntryIntegrityError, VaultKeyEpochMismatchError
from ...models import (
    ENTRY_TYPES,
    MAX_CUSTOM_FIELDS_PER_ENTRY,
    MAX_FIELD_NOTES,
    MAX_FIELD_PASSWORD,
    MAX_FIELD_TAGS,
    MAX_FIELD_TITLE,
    MAX_FIELD_TOTP_SECRET,
    MAX_FIELD_URL,
    MAX_FIELD_USERNAME,
    Category,
    CustomField,
    Entry,
    PasswordHistory,
    RawEntry,
    Sensitive,
)
from ...utils.format import format_datetime, utc_now_iso
from ..services.crypto_utils import (
    build_entry_summary,
    copy_entry_fields,
    decrypt_field as _decrypt_field_impl,
    encrypt_field as _encrypt_field_impl,
    matches_search,
    matches_tag as _matches_tag_impl,
    require_vault_key,
)

logger = logging.getLogger(__name__)


class EntryManager:
    """管理密码条目的加密、解密和 CRUD 操作。"""

    def __init__(self, vault_manager: 'VaultManager'):
        self._vault = vault_manager
        # 搜索摘要缓存保存 title/username/url/tags 明文，减少重复搜索解密。
        self._search_metadata_cache: dict[str, tuple[str, str, str, str]] = {}
        self._search_metadata_failed: dict[str, set[str]] = {}
        self._category_name_cache: dict[int, str] = {}
        self._cache_epoch: str | None = None
        # TOTP secret 明文缓存，entry_id → 解密 totp_secret。
        # 仅供 generate_totp_cached 复用，避免定时器每秒查 DB + AESGCM 解密。
        # 生命周期与搜索摘要缓存一致：key_epoch 因改密或锁定而变化时即清空，
        # 条目更新修改 totp_secret 时按 entry_id 失效，详见 update_entry。
        # TOTP secret 用于生成验证码，属敏感凭据，但与 username 同属会话内
        # 必需明文，缓存窗口与 username 缓存等价。
        self._totp_secret_cache: dict[int, str] = {}
        # 标签计数缓存，避免侧边栏每次刷新都全表解密 tags 并内存聚合。
        # 失效条件：条目增删改经 _notify_entry_change 触发，锁定或改密使 epoch 变化。
        self._tags_cache: list[tuple[str, int]] | None = None
        # 缓存锁：保护搜索摘要/TOTP/标签缓存及 _cache_epoch
        # 的结构性读写，消除 TOTP 定时器线程与锁定 invalidate_caches 并发时的竞态。
        # 约定：锁内不调用数据库方法或变更回调，避免与 db 事务锁构成顺序反转死锁。
        self._cache_lock = threading.RLock()
        # 条目变更回调列表，用于事件驱动的缓存失效，如 SecurityAnalyzer。
        self._on_entry_change_callbacks: list = []

    def register_on_change(self, callback):
        """注册条目变更时自动调用的回调，用于缓存失效等。"""
        self._on_entry_change_callbacks.append(callback)

    @property
    def db(self):
        return self._vault.db

    @property
    def key_epoch(self) -> str | None:
        """当前密钥版本，委托 vault。

        供 ImportExportManager 等跨管理器操作做 epoch 守卫，避免直接穿透
        ``_vault`` 私有属性。EntryManager 内部（``_invalidate_if_epoch_changed``）
        本就经此路径访问 key_epoch。
        """
        return self._vault.key_epoch

    @property
    def _key(self) -> bytes:
        return require_vault_key(self._vault)

    def _build_encrypted_entry(
        self,
        entry: Entry,
        crypto_id: str,
        now: str,
        *,
        created_at: str | None = None,
        updated_at: str | None = None,
        password_override: str | None = None,
        entry_id: int | None = None,
    ) -> RawEntry:
        """构建加密 RawEntry 对象，统一处理字段加密逻辑。

        add_entry 和 update_entry 共用此方法，避免加密字段遗漏。返回密文态
        RawEntry（custom_fields 为密文 str），供 EntryRepository 写入数据库。
        password_override: 若提供，视为已加密的密文，直接赋值，不再重复加密。
        """
        # password_override 已是密文，即 update_entry 场景，直接赋值；
        # 否则加密明文密码，即 add_entry 场景。
        encrypted_pwd = (
            password_override
            if password_override is not None
            else self._encrypt_field(entry.password, crypto_id, 'password')
        )
        custom_fields_cipher = self._encrypt_custom_fields(entry.custom_fields, crypto_id)
        return RawEntry(
            id=entry_id,
            crypto_id=crypto_id,
            title=self._encrypt_field(entry.title, crypto_id, 'title'),
            username=self._encrypt_field(entry.username, crypto_id, 'username'),
            password=encrypted_pwd,
            url=self._encrypt_field(entry.url, crypto_id, 'url'),
            category_id=entry.category_id,
            tags=self._encrypt_field(entry.tags, crypto_id, 'tags'),
            notes=self._encrypt_field(entry.notes, crypto_id, 'notes'),
            custom_fields=custom_fields_cipher,
            is_favorite=entry.is_favorite,
            password_strength=entry.password_strength,
            entry_type=entry.entry_type,
            totp_secret=self._encrypt_field(entry.totp_secret, crypto_id, 'totp_secret'),
            created_at=created_at or now,
            updated_at=updated_at or now,
            password_changed_at=entry.password_changed_at or now,
        )

    def _encrypt_field(self, plaintext: str, crypto_id: str, field_name: str) -> str:
        """加密单个字段，委托给 crypto_utils.encrypt_field。"""
        return _encrypt_field_impl(plaintext, self._key, crypto_id, field_name)

    def _decrypt_field(
        self,
        encrypted: str,
        crypto_id: str,
        field_name: str,
        strict: bool = False,
    ) -> str:
        """解密单个字段，委托给 crypto_utils.decrypt_field。"""
        return _decrypt_field_impl(
            encrypted, self._key, crypto_id, field_name, strict=strict,
        )

    def _cached_search_metadata(
        self, raw_entry: RawEntry,
    ) -> tuple[str, str, str, str]:
        """解密并缓存列表/搜索所需的 title、username、url、tags。"""
        self._invalidate_if_epoch_changed()
        cid = raw_entry.crypto_id
        with self._cache_lock:
            cached = self._search_metadata_cache.get(cid)
            if cached is not None:
                return cached
            entry_epoch = self._cache_epoch

        values: list[str] = []
        failed: set[str] = set()
        for field_name, encrypted in (
            ('title', raw_entry.title),
            ('username', raw_entry.username),
            ('url', raw_entry.url),
            ('tags', raw_entry.tags),
        ):
            try:
                value = self._decrypt_field(
                    encrypted, cid, field_name, strict=True,
                )
            except ValueError:
                value = ''
                failed.add(field_name)
            values.append(value)
        result = (values[0], values[1], values[2], values[3])
        with self._cache_lock:
            if self._cache_epoch == entry_epoch:
                self._search_metadata_cache[cid] = result
                if failed:
                    self._search_metadata_failed[cid] = failed
        return result

    @staticmethod
    def _category_crypto_id(category_id: int) -> str:
        return f'category-{category_id}'

    def _decrypt_category_name(self, category_id: int | None, value: str) -> str:
        if category_id is None or not value:
            return ''
        with self._cache_lock:
            cached = self._category_name_cache.get(category_id)
        if cached is not None:
            return cached
        name = self._decrypt_field(
            value,
            self._category_crypto_id(category_id),
            'category_name',
            strict=True,
        )
        with self._cache_lock:
            self._category_name_cache[category_id] = name
        return name

    def _invalidate_if_epoch_changed(self):
        """检测 vault.key_epoch 变化，变化则清空所有明文缓存。

        当 key_epoch 变为 None 时，即保险库已锁定或 epoch 不匹配强制清除，
        无论 _cache_epoch 是否也为 None，都应清空缓存。
        """
        current = self._vault.key_epoch
        if current is None or current != self._cache_epoch:
            with self._cache_lock:
                # 持锁后再次确认，避免与并发 invalidate 重复执行清空序列
                current = self._vault.key_epoch
                if current is None or current != self._cache_epoch:
                    self._search_metadata_cache.clear()
                    self._search_metadata_failed.clear()
                    self._category_name_cache.clear()
                    self._totp_secret_cache.clear()
                    self._tags_cache = None
                    self._cache_epoch = current

    def invalidate_caches(self):
        """外部调用：锁定或改密后显式清空明文缓存。"""
        with self._cache_lock:
            self._search_metadata_cache.clear()
            self._search_metadata_failed.clear()
            self._category_name_cache.clear()
            self._totp_secret_cache.clear()
            self._tags_cache = None
            self._cache_epoch = None

    def _notify_entry_change(
        self,
        password_changed: bool = True,
        *,
        crypto_id: str | None = None,
        tags_changed: bool = True,
        category_changed: bool = False,
        clear_summaries: bool = True,
    ):
        """通知所有注册的条目变更回调，事件驱动缓存失效。

        password_changed 为 False，如仅修改标题或 URL 时，不涉及密码的分析维度，
        即弱密码、重复、过期结果不变，订阅方可据此跳过昂贵的缓存重算。
        增删条目等结构性变更保持默认 True，因其改变 total 与重复分组。

        缓存失效粒度（避免单条编辑触发全量重解密）：
        - crypto_id 提供（单条更新）：仅 pop 该条目的搜索摘要缓存，而非全清。
        - crypto_id 为 None 且 clear_summaries=True（增删/批量）：清空全部摘要缓存。
        - crypto_id 为 None 且 clear_summaries=False（分类 CRUD）：保留摘要缓存，
          因分类变更不改变条目的 title/username/url/tags 摘要内容。
        - tags_changed：仅当 tags 字段或条目增删改变标签分布时失效 _tags_cache，
          标题/URL/密码等非 tags 编辑不再触发标签侧边栏无谓重算。
        - category_changed：仅分类增删改改变分类名时失效 _category_name_cache；
          普通条目变更不应清空分类名缓存。
        """
        with self._cache_lock:
            if crypto_id is not None:
                self._search_metadata_cache.pop(crypto_id, None)
                self._search_metadata_failed.pop(crypto_id, None)
            elif clear_summaries:
                self._search_metadata_cache.clear()
                self._search_metadata_failed.clear()
            if tags_changed:
                self._tags_cache = None
            if category_changed:
                self._category_name_cache.clear()
        # 回调在锁外执行，避免回调重入 EntryManager 缓存方法时与持锁线程竞争
        for cb in self._on_entry_change_callbacks:
            try:
                cb(password_changed)
            except Exception:
                logger.debug("条目变更回调执行失败", exc_info=True)

    def notify_batch_change(self, password_changed: bool = True):
        """批量变更后的统一通知入口，供导入等批量操作在全部完成后触发一次。

        与单条 ``_notify_entry_change`` 一致地失效缓存并通知回调，但作为公共 API
        暴露，避免跨管理器（如 ImportExportManager）直接访问带下划线的私有方法
        ``_notify_entry_change``，使内部缓存失效机制不致成为跨模块契约的一部分。
        """
        self._notify_entry_change(password_changed)

    def _encrypt_custom_fields(
        self,
        fields: list[CustomField] | str,
        crypto_id: str,
    ) -> str:
        """加密自定义字段列表。"""
        if not fields:
            return ''
        if not isinstance(fields, list) or not all(
            isinstance(field, CustomField) for field in fields
        ):
            raise ValueError('自定义字段必须是 CustomField 列表')
        data = json.dumps([f.to_dict() for f in fields], ensure_ascii=False)
        return self._encrypt_field(data, crypto_id, 'custom_fields')

    def _decrypt_custom_fields(self, encrypted: str, crypto_id: str) -> list[CustomField]:
        """解密自定义字段列表。"""
        if not encrypted:
            return []
        data = self._decrypt_field(
            encrypted, crypto_id, 'custom_fields', strict=True
        )
        items = json.loads(data)
        if not isinstance(items, list) or not all(
            isinstance(item, dict) for item in items
        ):
            raise ValueError('自定义字段结构无效')
        return [CustomField.from_dict(item) for item in items]

    def decrypt_entry(self, raw_entry: RawEntry) -> Entry:
        """解密条目的所有敏感字段，返回新的 Entry 对象。"""
        integrity_errors = []
        if raw_entry.integrity_error:
            integrity_errors.append(raw_entry.integrity_message or '元数据')

        def decrypt(name: str, value: str) -> str:
            try:
                return self._decrypt_field(
                    value, raw_entry.crypto_id, name, strict=True
                )
            except ValueError:
                integrity_errors.append(name)
                return ''

        try:
            custom_fields = self._decrypt_custom_fields(
                raw_entry.custom_fields_db_value,
                raw_entry.crypto_id,
            )
        except ValueError:
            integrity_errors.append('自定义字段')
            custom_fields = []

        return copy_entry_fields(
            raw_entry,
            title=decrypt('title', raw_entry.title),
            username=decrypt('username', raw_entry.username),
            password=Sensitive(decrypt('password', raw_entry.password)),
            url=decrypt('url', raw_entry.url),
            category_name=self._decrypt_category_name(
                raw_entry.category_id, raw_entry.category_name,
            ),
            tags=decrypt('tags', raw_entry.tags),
            notes=decrypt('notes', raw_entry.notes),
            custom_fields=custom_fields,
            totp_secret=Sensitive(decrypt('totp_secret', raw_entry.totp_secret)),
            integrity_error=bool(integrity_errors),
            integrity_message='、'.join(dict.fromkeys(integrity_errors)),
        )

    def decrypt_entry_for_export(
        self,
        raw_entry: RawEntry,
        include_secrets: bool = False,
    ) -> Entry:
        """仅解密导出所需字段，默认不让密码与 TOTP 进入内存结果。"""
        if raw_entry.integrity_error:
            raise DecryptionError(
                f'条目 {raw_entry.id} 元数据完整性校验失败，已拒绝导出'
            )
        try:
            custom_fields = self._decrypt_custom_fields(
                raw_entry.custom_fields_db_value,
                raw_entry.crypto_id,
            )
            return copy_entry_fields(
                raw_entry,
                title=self._decrypt_field(
                    raw_entry.title, raw_entry.crypto_id, 'title', strict=True
                ),
                username=self._decrypt_field(
                    raw_entry.username, raw_entry.crypto_id, 'username', strict=True
                ),
                password=(
                    self._decrypt_field(
                        raw_entry.password, raw_entry.crypto_id, 'password', strict=True
                    ) if include_secrets else ''
                ),
                url=self._decrypt_field(
                    raw_entry.url, raw_entry.crypto_id, 'url', strict=True
                ),
                category_name=self._decrypt_category_name(
                    raw_entry.category_id, raw_entry.category_name,
                ),
                tags=self._decrypt_field(
                    raw_entry.tags, raw_entry.crypto_id, 'tags', strict=True
                ),
                notes=self._decrypt_field(
                    raw_entry.notes, raw_entry.crypto_id, 'notes', strict=True
                ),
                custom_fields=custom_fields,
                totp_secret=(
                    self._decrypt_field(
                        raw_entry.totp_secret, raw_entry.crypto_id, 'totp_secret', strict=True
                    ) if include_secrets else ''
                ),
            )
        except ValueError as exc:
            raise DecryptionError(
                f'条目 {raw_entry.id} 导出失败，数据可能已损坏'
            ) from exc

    def _decrypt_summary(self, raw_entry: RawEntry) -> Entry:
        """仅解密列表展示所需字段，不让密码等明文进入列表模型。

        title/username/url/tags 经统一摘要缓存复用，避免列表与搜索重复解密。
        摘要不包含 password/totp_secret/notes/custom_fields 等高敏字段；
        epoch 变化、锁定或条目更新时缓存立即失效。
        """
        title, username, url, tags = self._cached_search_metadata(raw_entry)
        with self._cache_lock:
            # 锁内采样失败字段集，避免与并发 invalidate_caches/_notify_entry_change
            # 的 .clear() 竞态导致完整性标志被瞬时错误清除（语义竞态）。
            failed = self._search_metadata_failed.get(raw_entry.crypto_id, set())
        summary = build_entry_summary(raw_entry, username)
        summary.title = title
        summary.url = url
        summary.tags = tags
        try:
            summary.category_name = self._decrypt_category_name(
                raw_entry.category_id, raw_entry.category_name,
            )
        except ValueError:
            failed = set(failed)
            failed.add('category')
        summary.integrity_error = raw_entry.integrity_error or bool(failed)
        messages = []
        if raw_entry.integrity_error:
            messages.append(raw_entry.integrity_message or '元数据')
        label_map = {
            'title': '标题', 'username': '账号', 'url': 'URL',
            'tags': '标签', 'category': '分类',
        }
        messages.extend(label_map[name] for name in failed)
        summary.integrity_message = '、'.join(dict.fromkeys(messages))
        return summary

    def _encrypt_plaintext_category_names(self) -> None:
        """加密 data 层以明文写入的默认分类名。

        init_tables 建表时插入默认分类（如"未分类"），但 data 层不持密钥无法
        加密；首次初始化后在 business 层补加密，使全部 category.name 以密文
        存储，满足改密时 re_encrypt_categories 的解密契约。已加密（cb2: 前缀）
        的分类跳过，故重复调用幂等。
        """
        with self.db.transaction():
            for category in self.db.get_categories():
                if category.id is None or category.name.startswith('cb2:'):
                    continue
                category.name = self._encrypt_field(
                    category.name,
                    self._category_crypto_id(category.id),
                    'category_name',
                )
                self.db.update_category(category)

    def add_entry(
        self, entry: Entry, *, notify: bool = True, skip_validation: bool = False,
    ) -> int:
        """添加新条目，自动加密并检测强度。

        Args:
            entry: 待添加的明文条目。
            notify: 是否触发条目变更通知。
            skip_validation: 导入路径已由 Entry.from_dict 校验，传 True 跳过重复长度校验。
        """
        if not skip_validation:
            self._validate_plain_entry(entry)
        strength = PasswordGenerator.check_strength(entry.password)
        entry.password_strength = strength.score
        crypto_id = entry.crypto_id or uuid.uuid4().hex

        now = utc_now_iso()
        enc_entry = self._build_encrypted_entry(
            entry, crypto_id, now,
            created_at=entry.created_at or now,
            updated_at=entry.updated_at or now,
        )
        result = self._vault.db.add_entry(
            enc_entry,
            preserve_metadata=bool(entry.created_at or entry.updated_at),
        )
        if notify:
            self._notify_entry_change()
        return result

    def update_entry(self, entry: Entry, *, preserve_password_changed_at: bool = False, notify: bool = True):
        """更新条目，自动加密并记录密码历史。

        线程安全说明：此方法采用 read-modify-write 模式，先读取旧密码，
        比较后再写入，未使用锁保护。在单用户桌面应用中，同一时刻只有
        一个 UI 操作会修改同一条目，竞态窗口极小，可接受。若未来引入
        并发写入场景，需在此方法外加锁。
        """
        self._validate_plain_entry(entry)
        if entry.integrity_error:
            raise EntryIntegrityError(
                f"条目存在无法解密的字段（{entry.integrity_message}），为避免数据丢失已禁止保存"
            )
        if entry.id is None:
            return
        # read 前快照 key_epoch，事务内复查，防止 read-modify-write 期间改密
        # 导致 add_password_history 写入旧密钥密文到已被重写的历史表。
        pre_epoch = self.key_epoch
        raw = self.db.get_entry(entry.id)
        if raw is None:
            return

        # 条目更新可能修改 totp_secret，失效该条目的 TOTP secret 缓存，
        # 下次 get_totp_state / generate_totp_cached 重新解密。
        with self._cache_lock:
            self._totp_secret_cache.pop(entry.id, None)

        # 检测密码变更，归档旧密码
        old_pwd_enc = raw.password
        # 安全-性能权衡：此处必须解密旧密码与明文比较来检测变更。
        # AES-256-GCM 每次加密使用随机 nonce，相同明文产生不同密文，
        # 因此密文比较不可行。HMAC 指纹方案需要在数据库中额外存储指纹
        # 字段，这会要求 schema 变更，当前解密比较是无需迁移的合理选择。
        old_password = self._decrypt_field(
            old_pwd_enc, raw.crypto_id, 'password', strict=True
        ) if old_pwd_enc else ''
        new_pwd_enc = self._encrypt_field(entry.password, raw.crypto_id, 'password')
        password_changed = (old_password != entry.password)
        del old_password  # 尽快释放明文引用
        if preserve_password_changed_at:
            # 导入覆盖等同步场景：保留原 password_changed_at，避免批量导入
            # 把"久未修改"条目重置为"刚修改"从而绕过过期检测
            password_changed_at = entry.password_changed_at or raw.password_changed_at
        elif password_changed:
            password_changed_at = utc_now_iso()
        else:
            password_changed_at = raw.password_changed_at

        strength = PasswordGenerator.check_strength(entry.password)
        entry.password_strength = strength.score

        now = utc_now_iso()
        enc_entry = self._build_encrypted_entry(
            entry, raw.crypto_id, now,
            created_at=raw.created_at,
            updated_at=now,
            password_override=new_pwd_enc,
            entry_id=entry.id,
        )
        enc_entry.password_changed_at = password_changed_at
        with self.db.transaction():
            # epoch 复查：_enforce_key_epoch 事务内跳过，单条写路径须自行复查，
            # 防止 read（事务外）到 commit（事务内）期间改密导致写入旧密钥密文。
            if self.key_epoch != pre_epoch:
                raise VaultKeyEpochMismatchError(
                    '更新期间检测到密钥变更（改密/锁定），已中止以防写入旧密钥密文'
                )
            if old_pwd_enc and password_changed and entry.id is not None:
                # 用与条目一致的 password_changed_at 作为历史 changed_at，
                # 避免两次独立 utc_now_iso() 产生的微秒级时序倒置
                self.db.add_password_history(
                    entry.id, old_pwd_enc, changed_at=password_changed_at,
                )
            self.db.update_entry(enc_entry)
        if notify:
            # 检测 tags 是否变更以决定是否失效标签缓存；摘要缓存按 crypto_id 单条
            # 精细失效，避免标题/URL 编辑触发全量重解密。raw.tags 解密失败时保守
            # 视为 tags 已变（None != 任意字符串），仍失效标签缓存。
            try:
                old_tags = self._decrypt_field(
                    raw.tags, raw.crypto_id, 'tags', strict=True,
                ) if raw.tags else ''
            except Exception:
                old_tags = None
            self._notify_entry_change(
                password_changed,
                crypto_id=raw.crypto_id,
                tags_changed=(old_tags != entry.tags),
            )

    def delete_entry(self, entry_id: int) -> bool:
        """软删除条目，移入回收站。返回是否实际执行（条目存在）。"""
        if not self._vault.db.soft_delete_entry(entry_id):
            return False
        with self._cache_lock:
            self._totp_secret_cache.pop(entry_id, None)
        self._notify_entry_change()
        return True

    def restore_entry(self, entry_id: int) -> bool:
        """恢复条目。返回是否实际执行（条目存在）。"""
        if not self._vault.db.restore_entry(entry_id):
            return False
        self._notify_entry_change()
        return True

    def permanent_delete_entry(self, entry_id: int):
        """永久删除条目。"""
        self._vault.db.permanent_delete_entry(entry_id)
        with self._cache_lock:
            self._totp_secret_cache.pop(entry_id, None)
        self._notify_entry_change()

    def empty_trash(self):
        """清空回收站。"""
        self._vault.db.empty_trash()
        with self._cache_lock:
            self._totp_secret_cache.clear()
        self._notify_entry_change()

    def get_entries(
        self,
        deleted_only: bool = False,
        include_deleted: bool = False,
        category_id: Optional[int] = None,
        favorite_only: bool = False,
    ) -> list[Entry]:
        """获取并解密全部条目（含 password/totp_secret 等敏感字段）。

        列表展示等不需要密码的场景应使用 :meth:`get_entry_summaries`；
        按关键词过滤使用 ``get_entry_summaries(search=...)``。
        """
        raw_entries = self._vault.db.get_entries(
            deleted_only=deleted_only,
            include_deleted=include_deleted,
            category_id=category_id,
            favorite_only=favorite_only,
        )

        decrypted = [self.decrypt_entry(e) for e in raw_entries]

        # 检查解密失败的条目并记录警告
        for dec_entry in decrypted:
            if dec_entry.integrity_error:
                logger.warning("条目 %d 解密存在异常", dec_entry.id)

        return decrypted

    def get_entry(self, entry_id: int) -> Optional[Entry]:
        """获取并解密单个条目。"""
        raw = self._vault.db.get_entry(entry_id)
        if raw is None:
            return None
        return self.decrypt_entry(raw)

    def get_entry_summaries(
        self,
        deleted_only: bool = False,
        category_id: Optional[int] = None,
        favorite_only: bool = False,
        search: str = '',
        limit: int | None = None,
        cancel_check: Callable[[], bool] | None = None,
    ) -> list[Entry]:
        """获取不含密码等敏感明文的列表摘要。

        Note:
            ``limit`` 的生效方式取决于 ``search``：
            - ``search`` 为空时，``limit`` 在 SQL 层生效（LIMIT 子句），高效截断。
            - ``search`` 非空时，因摘要字段已加密，必须先全量解密搜索摘要再过滤。
              此时 ``limit`` 不下推到 SQL（否则会先
              截断再过滤，导致搜索命中远少于实际），由调用方在内存过滤后自行截断。
              即当 search 非空时本方法忽略 limit，返回全部命中结果。
        """
        # search 非空时不向 SQL 下推 limit，避免「先截断后过滤」导致命中失真。
        sql_limit = limit if not search else None
        raw_entries = self.db.get_entries(
            deleted_only=deleted_only,
            category_id=category_id,
            favorite_only=favorite_only,
            limit=sql_limit,
        )
        if search:
            # 摘要字段首次搜索后进入会话缓存，后续搜索无重复解密成本。
            summaries = []
            for raw in raw_entries:
                if cancel_check and cancel_check():
                    break
                summary = self._decrypt_summary(raw)
                if matches_search(summary, search):
                    summaries.append(summary)
            # search 时 limit 未下推 SQL，此处截断以兑现 limit 契约
            if limit:
                summaries = summaries[:limit]
        else:
            summaries = []
            for raw in raw_entries:
                if cancel_check and cancel_check():
                    break
                summaries.append(self._decrypt_summary(raw))
        return summaries

    def get_recent_summaries(self, limit: int = 20) -> list[Entry]:
        """获取最近更新的条目摘要，供「近期更新」视图。

        相较 ``get_entry_summaries``（按 is_favorite DESC, updated_at DESC 排序），
        本方法仅按 updated_at DESC 排序并下推 LIMIT 到 SQL，避免拉全量内存排序
        再截断，消除大库下「近期更新」切换的全量解密与内存驻留开销。

        Args:
            limit: 返回条目数上限。
        """
        if limit <= 0:
            return []
        raw_entries = self.db.get_entries(sort_by_updated=True, limit=limit)
        return [self._decrypt_summary(entry) for entry in raw_entries]

    def get_entries_for_export(
        self,
        include_secrets: bool = False,
        cancel_check: Callable[[], bool] | None = None,
    ) -> list[Entry]:
        raw_entries = self.db.get_entries(include_deleted=False)
        entries = []
        for raw_entry in raw_entries:
            if cancel_check and cancel_check():
                break
            entries.append(
                self.decrypt_entry_for_export(raw_entry, include_secrets)
            )
        return entries

    # ==================== 委托方法 ====================
    # 以下方法直接委托给 DatabaseManager，无额外业务逻辑。
    # 委托层存在的理由：为 UI 层提供单一入口点，允许未来在此层添加
    # 验证或日志逻辑，防止 UI 直接依赖 DatabaseManager。
    def get_categories(self) -> list[Category]:
        categories = self._vault.db.get_categories()
        for category in categories:
            if category.id is not None:
                category.name = self._decrypt_category_name(
                    category.id, category.name,
                )
        return sorted(categories, key=lambda item: (item.sort_order, item.name.casefold()))

    def get_category(self, category_id: int) -> Category | None:
        category = self._vault.db.get_category(category_id)
        if category is not None:
            category.name = self._decrypt_category_name(category_id, category.name)
        return category

    # DELEGATE: see DatabaseManager.get_category_entry_count
    def get_category_entry_count(self, category_id: int) -> int:
        return self._vault.db.get_category_entry_count(category_id)

    # DELEGATE: see DatabaseManager.get_category_entry_counts
    def get_category_entry_counts(self) -> dict[int, int]:
        return self._vault.db.get_category_entry_counts()

    def add_category(self, category: Category, *, notify: bool = True) -> int:
        if not category.name.strip():
            raise ValueError('分类名称不能为空')
        if any(
            existing.name.casefold() == category.name.strip().casefold()
            for existing in self.get_categories()
        ):
            raise ValueError('分类名称已存在')
        plaintext_name = category.name.strip()
        pending_id = f'category-pending-{uuid.uuid4().hex}'
        stored = Category(
            name=self._encrypt_field(plaintext_name, pending_id, 'category_name'),
            icon_char=category.icon_char,
            color=category.color,
            sort_order=category.sort_order,
            created_at=category.created_at,
        )
        with self.db.transaction():
            result = self.db.add_category(stored)
            stored.id = result
            stored.name = self._encrypt_field(
                plaintext_name,
                self._category_crypto_id(result),
                'category_name',
            )
            self.db.update_category(stored)
        category.id = result
        category.name = plaintext_name
        # 分类变更不改条目摘要内容（title/url/tags 不变），保留搜索摘要缓存；
        # 仅失效分类名缓存并通知回调刷新侧边栏分类列表。
        if notify:
            self._notify_entry_change(
                password_changed=False, tags_changed=False,
                category_changed=True, clear_summaries=False,
            )
        return result

    def update_category(self, category: Category) -> None:
        if category.id is None:
            raise ValueError('分类 ID 不能为空')
        plaintext_name = category.name.strip()
        stored = Category(
            id=category.id,
            name=self._encrypt_field(
                plaintext_name,
                self._category_crypto_id(category.id),
                'category_name',
            ),
            icon_char=category.icon_char,
            color=category.color,
            sort_order=category.sort_order,
            created_at=category.created_at,
        )
        self._vault.db.update_category(stored)
        # 分类名/icon 变更不影响条目摘要内容，仅失效分类名缓存。
        self._notify_entry_change(
            password_changed=False, tags_changed=False,
            category_changed=True, clear_summaries=False,
        )

    # DELEGATE: see DatabaseManager.delete_category
    def delete_category(self, category_id: int) -> None:
        self._vault.db.delete_category(category_id)
        # 删除分类后关联条目 category_id 置 NULL，分类名缓存需失效；条目摘要
        # 内容（title/url/tags）不变，保留搜索摘要缓存避免全量重解密。
        self._notify_entry_change(
            password_changed=False, tags_changed=False,
            category_changed=True, clear_summaries=False,
        )

    def toggle_favorite(self, entry_id: int) -> bool | None:
        """切换收藏状态，返回新的收藏状态；条目不存在时返回 None。

        在单个事务内完成读-改-写，避免 TOCTOU 竞态。
        update_entry 会自动重签 metadata_mac，保证元数据完整性。
        """
        pre_epoch = self.key_epoch
        with self._vault.db.transaction():
            if self.key_epoch != pre_epoch:
                raise VaultKeyEpochMismatchError(
                    '切换收藏期间检测到密钥变更（改密/锁定），已中止'
                )
            raw = self._vault.db.get_entry(entry_id)
            if raw is None:
                return None
            raw.is_favorite = not raw.is_favorite
            self._vault.db.update_entry(raw)
            result = raw.is_favorite
        # 收藏切换不影响密码相关分析维度，传 False 避免 SecurityAnalyzer 缓存
        # 无谓失效触发整库重算。is_favorite 不在摘要/标签/分类名缓存中，按
        # crypto_id 单条 pop 摘要缓存并跳过标签失效，避免全量重解密。
        self._notify_entry_change(
            password_changed=False, crypto_id=raw.crypto_id, tags_changed=False,
        )
        return result

    # DELEGATE: see DatabaseManager.get_entry_count
    def get_entry_count(self, include_deleted: bool = False) -> int:
        return self._vault.db.get_entry_count(include_deleted)

    # DELEGATE: see DatabaseManager.get_password_history
    def get_password_history(self, entry_id: int) -> list[PasswordHistory]:
        return self._vault.db.get_password_history(entry_id)

    # DELEGATE: see DatabaseManager.get_password_history_count
    def get_password_history_count(self, entry_id: int) -> int:
        return self.db.get_password_history_count(entry_id)

    def decrypt_password_history(self, history: list[PasswordHistory]) -> list[dict]:
        """解密密码历史，返回字典列表，每个字典含变更时间 changed_at 与密码 password。"""
        result = []
        for h in history:
            pwd = self._decrypt_field(
                h.old_password_enc, h.entry_crypto_id, 'password'
            )
            if pwd:
                result.append({
                    'changed_at': format_datetime(h.changed_at),
                    'password': pwd,
                })
            else:
                # 解密失败（损坏记录）静默丢弃会掩盖数据问题，记录告警便于排查
                logger.warning(
                    "密码历史解密失败 entry_crypto_id=%s，已跳过", h.entry_crypto_id,
                )
        return result

    # ==================== TOTP 生成 ====================
    # UI→Business 迁移，调用方不接触明文 TOTP secret

    def generate_totp(self, entry_id: int) -> str | None:
        """生成指定条目的 TOTP 验证码。

        仅解密 totp_secret 字段，避免触发 password/notes/custom_fields
        等其他敏感字段的不必要解密。

        解密逻辑复用 generate_totp_cached 的单一解密路径，避免两份独立的
        解密与空值判断逻辑漂移。与 generate_totp_cached 的区别：本方法
        不写入会话内 totp_secret 缓存（调用方按需自行预热）。

        Returns:
            6 位验证码字符串，条目不存在或无 TOTP 密钥时返回 None。
        """
        secret = self._resolve_totp_secret(entry_id)
        if not secret:
            return None
        return TOTPGenerator.generate(secret)

    def generate_totp_cached(self, entry_id: int) -> str | None:
        """生成指定条目的 TOTP 验证码，复用会话内缓存的 totp_secret。

        与 generate_totp 的区别：缓存命中时跳过 DB 查询与 AESGCM 解密，
        仅做纯 HOTP 计算，供 TOTP 定时器每秒刷新调用。缓存以 entry_id 为键，
        由以下途径失效：
        - key_epoch 变化（改密/锁定）：整体清空（_invalidate_if_epoch_changed）。
        - 条目更新修改 totp_secret：按 entry_id 失效（update_entry）。
        - 条目删除：按 entry_id 失效（delete_entry / permanent_delete_entry）。
        get_totp_state 在条目首次展示时预热缓存，此后定时器全程命中缓存。

        解密逻辑复用 _resolve_totp_secret 的单一解密路径，避免与 generate_totp
        两份独立的解密与空值判断逻辑漂移。

        Returns:
            6 位验证码字符串，条目不存在或无 TOTP 密钥时返回 None。
        """
        self._invalidate_if_epoch_changed()
        secret = self._resolve_totp_secret(entry_id, use_cache=True)
        if not secret:
            return None
        return TOTPGenerator.generate(secret)

    def _resolve_totp_secret(
        self, entry_id: int, *, use_cache: bool = False,
    ) -> str | None:
        """解析条目的 totp_secret 明文，单一解密路径供 TOTP 方法复用。

        Args:
            entry_id: 条目 ID。
            use_cache: 是否读写会话内 totp_secret 缓存。generate_totp_cached
                传 True 复用缓存；generate_totp 传 False 仅解密不落缓存，
                保持其「不写缓存」语义。
        """
        if use_cache:
            with self._cache_lock:
                secret = self._totp_secret_cache.get(entry_id)
            if secret is not None:
                return secret
        # DB 查询与解密在锁外，避免持锁阻塞并发缓存访问
        raw = self.db.get_entry(entry_id)
        if raw is None or not raw.totp_secret:
            return None
        secret = self._decrypt_field(
            raw.totp_secret, raw.crypto_id, 'totp_secret',
        )
        if not secret:
            return None
        if use_cache:
            with self._cache_lock:
                self._totp_secret_cache[entry_id] = secret
        return secret

    def get_totp_state(self, entry_id: int) -> dict | None:
        """获取指定条目的 TOTP 完整状态，含验证码、倒计时和周期。

        仅解密 totp_secret 字段，供 detail_panel 的 TOTP 显示和刷新定时器使用。
        首次调用时将解密后的 secret 写入 _totp_secret_cache，使后续
        generate_totp_cached 命中缓存，避免定时器每秒重复解密。

        Returns:
            包含验证码 code、剩余秒数 remaining、周期 period 三个键的字典；
            条目不存在或无 TOTP 密钥时返回 None。
        """
        self._invalidate_if_epoch_changed()
        raw = self.db.get_entry(entry_id)
        if raw is None or not raw.totp_secret:
            return None
        secret = self._decrypt_field(raw.totp_secret, raw.crypto_id, 'totp_secret')
        if not secret:
            return None
        # 预热缓存，供 generate_totp_cached 复用。
        with self._cache_lock:
            self._totp_secret_cache[entry_id] = secret
        return {
            'code': TOTPGenerator.generate(secret),
            'remaining': TOTPGenerator.get_remaining_seconds(secret=secret),
            'period': TOTPGenerator.get_period(secret),
        }

    def get_all_tags(self) -> list[tuple[str, int]]:
        """获取所有标签及其使用频率。

        结果在会话内缓存，避免侧边栏每次刷新都全表解密 tags 并聚合。
        缓存于条目增删改与锁定/改密时失效。
        """
        self._invalidate_if_epoch_changed()
        with self._cache_lock:
            cached = self._tags_cache
        if cached is not None:
            return cached
        tag_count: dict[str, int] = {}
        # 标签列为密文，逐条解密摘要字段后聚合；结果在会话内缓存。
        for raw in self.db.get_entries(include_deleted=False):
            tags_str = self._cached_search_metadata(raw)[3]
            for tag in (t.strip() for t in tags_str.split(',') if t.strip()):
                tag_count[tag] = tag_count.get(tag, 0) + 1
        result = sorted(tag_count.items(), key=lambda x: -x[1])
        with self._cache_lock:
            # 双重检查：期间可能已被并发填充，优先用已存在的缓存保证一致性
            if self._tags_cache is not None:
                return self._tags_cache
            self._tags_cache = result
            return result

    @staticmethod
    def _validate_plain_entry(entry: Entry):
        if entry.entry_type not in ENTRY_TYPES:
            raise ValueError('条目类型无效')
        for field_name in (
            'title', 'username', 'password', 'url', 'tags', 'notes', 'totp_secret'
        ):
            if not isinstance(getattr(entry, field_name), str):
                raise ValueError(f'条目字段 {field_name} 类型无效')
        field_limits = {
            'title': MAX_FIELD_TITLE, 'username': MAX_FIELD_USERNAME,
            'password': MAX_FIELD_PASSWORD, 'url': MAX_FIELD_URL,
            'tags': MAX_FIELD_TAGS, 'notes': MAX_FIELD_NOTES,
            'totp_secret': MAX_FIELD_TOTP_SECRET,
        }
        for field_name, max_len in field_limits.items():
            if len(getattr(entry, field_name)) > max_len:
                raise ValueError(f'条目字段 {field_name} 过长（最多 {max_len} 字符）')
        # 此方法仅用于 add_entry/update_entry 路径的明文条目校验。
        # custom_fields 必须为已解密的 list[CustomField]。
        # DB 原始条目的 custom_fields 为 str 类型的密文，不经过此校验。
        entry.assert_decrypted()
        if not isinstance(entry.custom_fields, list) or not all(
            isinstance(field, CustomField) for field in entry.custom_fields
        ):
            raise ValueError('自定义字段结构无效')
        if len(entry.custom_fields) > MAX_CUSTOM_FIELDS_PER_ENTRY:
            raise ValueError(
                f'自定义字段过多（最多 {MAX_CUSTOM_FIELDS_PER_ENTRY} 个）'
            )

    @staticmethod
    def matches_search(entry, query: str) -> bool:
        """检查条目是否匹配搜索关键词，大小写不敏感，匹配 title、username、url、tags。

        此方法作为 EntryManager 的公共 API 委托给 ``crypto_utils.matches_search``，
        供 UI 层使用，避免 UI 直接依赖 ``business.crypto_utils`` 模块，
        同时消除两份相同实现必须手动同步的维护负担。

        Note:
            内部实现委托给 ``crypto_utils.matches_search``。UI 层应通过
            此公共方法调用，避免直接依赖 ``crypto_utils`` 模块。
        """
        return matches_search(entry, query)

    @staticmethod
    def matches_tag(entry, tag: str) -> bool:
        """检查条目是否包含指定标签。

        标签匹配为大小写不敏感的精确匹配：条目 tags 字段以逗号分隔后，
        逐个与目标 tag 比对。即 ``tag="work"`` 匹配 ``"Work,Personal"``
        但不匹配 ``"network"``。

        此方法作为 EntryManager 的公共 API 委托给 ``crypto_utils.matches_tag``，
        供 UI 层使用，避免 UI 直接依赖 ``crypto_utils`` 模块。
        """
        return _matches_tag_impl(entry, tag)
