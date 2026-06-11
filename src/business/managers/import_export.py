"""导入导出管理器 - CSV/JSON 导入导出 + 浏览器密码导入"""

import csv
import json
import logging
import os
from functools import wraps
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional

from ...utils.format import utc_now_iso

if TYPE_CHECKING:
    from .entry_manager import EntryManager

from ...database.models import (
    ENTRY_TYPE_CARD,
    ENTRY_TYPE_IDENTITY,
    ENTRY_TYPE_NOTE,
    Category,
    CustomField,
    Entry,
)
from ...utils.file_security import secure_file, validate_file_path
from ..exceptions import EntryError

logger = logging.getLogger(__name__)

MAX_IMPORT_FILE_SIZE = 25 * 1024 * 1024
MAX_IMPORT_ENTRIES = 50_000
MAX_IMPORT_ENTRY_SIZE = 2 * 1024 * 1024

# CSV 导入列名别名映射：每个字段对应一组可能的列名，匹配时不区分大小写。
# 用于 import_from_csv 的 _get_val 调用和密码列检测。
_CSV_COLUMN_ALIASES = {
    'title':       ('title', 'Title', '名称', 'name'),
    'username':    ('username', 'Username', '用户名', 'login', 'user'),
    'password':    ('password', 'Password', '密码', 'login_password', 'pass'),
    'url':         ('url', 'URL', '网址', 'website', 'login_uri', 'uri', 'origin'),
    'tags':        ('tags', 'Tags', '标签'),
    'notes':       ('notes', 'Notes', '备注', 'note', 'comment'),
    'totp_secret': ('totp_secret', 'TOTP', 'totp'),
    'category':    ('category', 'Category', '分类', 'folder'),
}

# 密码列的别名集合，均为小写形式，用于检测 CSV 是否包含密码列。
_PASSWORD_COLUMN_NAMES = {'password', '密码', 'login_password', 'pass'}

# KeePass CSV 列名别名映射：键为内部字段名，值为 CSV 中可能的列名，均为小写用于匹配。
_KEE_PASS_COLUMN_ALIASES = {
    'title':    ['title'],
    'username': ['username'],
    'password': ['password'],
    'url':      ['url'],
    'notes':    ['notes'],
    'group':    ['group'],
}


def _transactional_import(method):
    """确保一次导入要么全部成功，要么完全回滚。

    约定：filepath 为被装饰方法的第二个位置参数，即 self 之后的第一个参数。

    在事务开始前捕获当前 key_epoch，事务开始后验证未变化，
    防止导入期间并发改密导致数据用旧密钥加密但 epoch 已更新。
    """
    @wraps(method)
    def wrapper(self, filepath, *args, **kwargs):
        self._validate_import_path(filepath)
        try:
            # 事务前快照 epoch，防止并发改密导致密钥不一致
            pre_epoch = self._entry_mgr._vault.key_epoch
            with self._entry_mgr.db.transaction():
                current_epoch = self._entry_mgr._vault.key_epoch
                if pre_epoch != current_epoch:
                    raise RuntimeError('导入期间检测到密钥变更，已中止导入')
                return method(self, filepath, *args, **kwargs)
        except UnicodeDecodeError:
            raise ValueError(
                '文件编码不支持：请确保 CSV 文件使用 UTF-8 编码保存。'
                '若文件来自其他密码管理器，请先以 UTF-8 编码重新保存。'
            ) from None
    return wrapper


class ImportExportManager:
    """密码条目的导入和导出"""

    def __init__(self, entry_manager: 'EntryManager'):
        self._entry_mgr = entry_manager

    @staticmethod
    def _validate_import_path(filepath: str):
        validate_file_path(filepath)
        size = Path(filepath).stat().st_size
        if size > MAX_IMPORT_FILE_SIZE:
            raise ValueError('导入文件过大，最大允许 25 MB')

    @staticmethod
    def _validate_items(items: list):
        """逐项验证导入数据大小。使用字段长度估算防止恶意构造的巨大字段
        在后续处理中引发内存问题。"""
        if len(items) > MAX_IMPORT_ENTRIES:
            raise ValueError(f'导入条目过多，最大允许 {MAX_IMPORT_ENTRIES} 条')
        for item in items:
            if sum(len(str(v).encode('utf-8')) for v in item.values()) > MAX_IMPORT_ENTRY_SIZE:
                raise ValueError('导入条目字段过大')

    @staticmethod
    def _atomic_target(filepath: str) -> tuple[Path, Path]:
        target = Path(filepath)
        target.parent.mkdir(parents=True, exist_ok=True)
        return target, target.with_name(target.name + '.tmp')

    @staticmethod
    def _csv_safe(value):
        """防护 CSV 注入：转义危险前缀，替换内部控制字符"""
        text = str(value) if value is not None else ''
        # 替换嵌入的换行符为空格，防止 CSV 行断裂
        text = text.replace('\r\n', ' ').replace('\r', ' ').replace('\n', ' ')
        if text.startswith(('=', '+', '-', '@', '\t')):
            return "'" + text
        return text

    @staticmethod
    def _retain_password_custom_fields(
        entry: Entry,
        existing: Entry,
        *,
        replace_all: bool = True,
    ) -> None:
        """合并密码型自定义字段：从 existing 中保留 entry 缺失的密码型字段。

        Args:
            entry: 导入条目，就地修改。
            existing: 已有条目，用于读取敏感字段。
            replace_all: True 时用 existing 的全部密码型字段替换 entry 的
                适用于 CSV/非导出场景，源格式无法表达密码型字段。
                False 时按名称增量补充，适用于 Bitwarden JSON 等源格式可表达
                但可能不包含已有字段的场景。
        """
        if not isinstance(entry.custom_fields, list):
            return
        existing_pwd = [
            f for f in (existing.custom_fields if isinstance(existing.custom_fields, list) else [])
            if f.field_type == 'password'
        ]
        if replace_all:
            # CSV / 非导出：源无法表达密码型字段，完全替换
            entry.custom_fields = [
                f for f in entry.custom_fields if f.field_type != 'password'
            ] + existing_pwd
        else:
            # Bitwarden JSON：按名称增量补充已有但导入中不存在的
            import_pwd_names = {f.name for f in entry.custom_fields if f.field_type == 'password'}
            missing = [f for f in existing_pwd if f.name not in import_pwd_names]
            entry.custom_fields = entry.custom_fields + missing

    @staticmethod
    def _merge_bitwarden_secrets(entry: Entry, existing: Entry):
        """Bitwarden JSON 覆盖导入的敏感字段合并。

        Bitwarden JSON 可完整表达 password、totp_secret 和密码型自定义字段，
        因此信任导入数据。仅当导入值为空时保留已有值。
        """
        if not entry.password:
            entry.password = existing.password
        if not entry.totp_secret:
            entry.totp_secret = existing.totp_secret
        ImportExportManager._retain_password_custom_fields(
            entry, existing, replace_all=False,
        )

    @staticmethod
    def _merge_non_exported_secrets(entry: Entry, existing: Entry):
        entry.password = existing.password
        entry.totp_secret = existing.totp_secret
        ImportExportManager._retain_password_custom_fields(
            entry, existing, replace_all=True,
        )

    @staticmethod
    def _merge_csv_secrets(entry: Entry, existing: Entry, source_has_password: bool):
        """CSV 覆盖导入的敏感字段合并。

        CSV 是不可靠的往返格式，密码型自定义字段无法可靠映射，因此对源文件
        未携带的敏感字段始终保留 existing 的值。
        """
        if not source_has_password or not entry.password:
            entry.password = existing.password
        if not entry.totp_secret:
            entry.totp_secret = existing.totp_secret
        ImportExportManager._retain_password_custom_fields(
            entry, existing, replace_all=True,
        )

    def _duplicate_plan(
        self,
        entries_data: list[dict],
        duplicate_action: str,
        source_label: str,
        existing_entries: list | None = None,
    ) -> tuple[set[int], dict[int, Entry]]:
        if duplicate_action not in {'import_all', 'skip', 'overwrite'}:
            raise ValueError('无效的重复项处理策略')
        if duplicate_action == 'import_all':
            return set(), {}

        if existing_entries is None:
            existing_entries = self._entry_mgr.get_entry_summaries()
        existing_by_key = {
            (entry.title.casefold(), entry.username.casefold()): entry
            for entry in existing_entries
            if entry.title
        }
        matched = {}
        for index, item in enumerate(entries_data):
            key = (
                str(item.get('title') or '').strip().casefold(),
                str(item.get('username') or '').strip().casefold(),
            )
            if key in existing_by_key:
                matched[index] = existing_by_key[key]
        if duplicate_action == 'skip':
            logger.info('%s: 检测到 %d 个重复项，将跳过', source_label, len(matched))
            return set(matched), {}
        logger.info('%s: 检测到 %d 个重复项，将覆盖', source_label, len(matched))
        return set(), matched

    def _prepare_overwrite_map(self, overwrite: dict[int, Entry]) -> dict[int, Entry]:
        """批量加载待覆盖条目的完整解密数据，使用单次 SQL 查询替代 N+1 模式。"""
        # 收集所有需要加载的 summary ID
        ids_by_idx: dict[int, int] = {}
        for idx, summary in overwrite.items():
            if summary.id is not None:
                ids_by_idx[idx] = summary.id
        if not ids_by_idx:
            return {}
        # 批量查询 + 批量解密
        raw_entries = self._entry_mgr.db.get_entries_by_ids(list(ids_by_idx.values()))
        entries_by_id = {e.id: e for e in raw_entries}
        result: dict[int, Entry] = {}
        for idx, entry_id in ids_by_idx.items():
            raw = entries_by_id.get(entry_id)
            if raw is None:
                raise EntryError(f'待覆盖条目 {entry_id} 已不存在')
            entry = self._entry_mgr.decrypt_entry(raw)
            result[idx] = entry
        return result

    def _resolve_category(
        self,
        name: str,
        categories: dict,
        default_category_id: Optional[int],
    ) -> Optional[int]:
        """匹配来源分类；不存在时创建，尽量保留导入结构。"""
        clean_name = (name or '').strip()
        if not clean_name:
            return default_category_id
        key = clean_name.casefold()
        if key in categories:
            return categories[key].id
        category = Category(name=clean_name, icon_char='[IMPORT]', color='#0f766e')
        category.id = self._entry_mgr.db.add_category(category)
        categories[key] = category
        return category.id

    # ======== 导出 ========

    def export_to_json(
        self,
        filepath: str,
        entries: list[Entry],
        include_password: bool = False,
    ):
        """导出为 JSON 文件"""
        data = {
            'app': 'CipherBox',
            'exported_at': self._now(),
            'secrets_included': include_password,
            'entries': [e.to_dict(include_password=include_password) for e in entries],
        }
        target, temp = self._atomic_target(filepath)
        try:
            with open(temp, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            secure_file(temp)
            os.replace(temp, target)
            secure_file(target)
        finally:
            temp.unlink(missing_ok=True)

    def export_to_csv(
        self,
        filepath: str,
        entries: list[Entry],
        include_password: bool = False,
    ):
        """导出为 CSV 文件"""
        fieldnames = ['title', 'username', 'password', 'totp_secret', 'url',
                       'category', 'tags', 'notes', 'is_favorite',
                       'created_at', 'updated_at']
        if not include_password:
            fieldnames.remove('password')
            fieldnames.remove('totp_secret')

        target, temp = self._atomic_target(filepath)
        try:
            with open(temp, 'w', encoding='utf-8-sig', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                for entry in entries:
                    if not entry.is_decrypted:
                        continue
                    row = entry.to_dict(include_password=include_password)
                    cf = entry.custom_fields
                    if not isinstance(cf, list):
                        continue
                    exported_fields = [
                        field for field in cf
                        if include_password or field.field_type != 'password'
                    ]
                    cf_str = '; '.join(f"{f.name}={f.value}" for f in exported_fields)
                    if row.get('notes'):
                        if cf_str:
                            row['notes'] += f'\n[自定义字段] {cf_str}'
                    elif cf_str:
                        row['notes'] = f'[自定义字段] {cf_str}'
                    writer.writerow({key: self._csv_safe(value) for key, value in row.items()})
                f.flush()
                os.fsync(f.fileno())
            secure_file(temp)
            os.replace(temp, target)
            secure_file(target)
        finally:
            temp.unlink(missing_ok=True)

    # ======== 导入辅助 ========

    def _import_entries(
        self,
        entries: list[Entry],
        entries_data: list[dict],
        categories: dict,
        default_category_id: Optional[int],
        duplicate_action: str,
        source_label: str,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        overwrite_merger: Optional[Callable[[Entry, Entry], None]] = None,
    ) -> int:
        """统一的导入循环：去重、分类解析、覆盖/新增、进度回调。

        Args:
            entries: 已解析好的 Entry 对象列表，与 entries_data 一一对应
            entries_data: 用于去重检测的摘要列表，每项含 title/username
            categories: 已有分类的 casefold 名称映射
            default_category_id: 默认分类 ID
            duplicate_action: 重复处理策略 ('import_all' / 'skip' / 'overwrite')
            source_label: 日志中标识来源，例如 'JSON 导入'
            progress_callback: 进度回调
            overwrite_merger: 可选的覆盖合并回调 ``(new_entry, existing_entry) -> None``，
                在设置 id/created_at 之后、写入数据库之前调用。
                若为 None 则直接用 new_entry 覆盖。
        """
        if not entries:
            return 0

        duplicate_indices, overwrite_map = self._duplicate_plan(
            entries_data, duplicate_action, source_label
        )
        overwrite_entries = self._prepare_overwrite_map(overwrite_map) if overwrite_map else {}

        count = 0
        skipped = 0
        total = len(entries)
        for i, entry in enumerate(entries):
            if i in duplicate_indices:
                continue

            entry.category_id = self._resolve_category(
                entry.category_name, categories, default_category_id
            )

            try:
                if i in overwrite_entries:
                    existing = overwrite_entries[i]
                    entry.id = existing.id
                    entry.created_at = existing.created_at
                    if overwrite_merger is not None:
                        overwrite_merger(entry, existing)
                    self._entry_mgr.update_entry(entry)
                else:
                    self._entry_mgr.add_entry(entry)
            except ValueError as exc:
                # 字段长度违规等校验错误，跳过该条目而非回滚整个导入
                skipped += 1
                logger.warning(
                    "跳过条目 '%s': %s",
                    entry.title[:50] if entry.title else '(无标题)',
                    exc,
                )
                continue

            count += 1
            if progress_callback:
                progress_callback(i + 1, total)

        if skipped:
            logger.info("%s: 跳过 %d 条无效条目", source_label, skipped)

        return count

    # ======== 导入 ========

    @staticmethod
    def check_duplicates(
        entries_data: list[dict],
        existing_entries: list[Entry],
    ) -> list[dict]:
        """检测待导入条目与已有条目的重复

        以 (title, username) 为匹配键。

        Args:
            entries_data: 待导入的条目列表，每个元素含 title/username 等字段
            existing_entries: 现有已解密条目

        Returns:
            重复项列表，每项包含 {index, title, username, existing_title}
        """
        existing_keys = {
            (e.title.casefold(), e.username.casefold()): e
            for e in existing_entries
            if e.title
        }

        duplicates = []
        for i, item in enumerate(entries_data):
            title = (item.get('title') or '').strip()
            username = (item.get('username') or '').strip()
            key = (title.casefold(), username.casefold())
            if key in existing_keys:
                existing = existing_keys[key]
                duplicates.append({
                    'index': i,
                    'title': title,
                    'username': username,
                    'existing_title': existing.title,
                })

        return duplicates

    @_transactional_import
    def import_from_json(
        self,
        filepath: str,
        default_category_id: Optional[int] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        duplicate_action: str = 'import_all',
    ) -> int:
        """从 JSON 文件导入

        Args:
            filepath: 文件路径
            default_category_id: 默认分类 ID
            progress_callback: 进度回调
            duplicate_action: 重复处理策略
                - 'skip': 跳过重复项
                - 'overwrite': 覆盖匹配的已有条目
                - 'import_all': 全部导入，默认行为
        """
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        if not isinstance(data, dict) or data.get('app') != 'CipherBox':
            raise ValueError('不是 CipherBox JSON 导出文件')
        # 注意：app 字段检查仅防止误导入错误格式的文件，不防恶意伪造。
        # 真实安全保护在于：导入数据会被重新加密到当前 vault 密钥下，
        # 恶意注入的数据仅能产生垃圾条目，无法获取已有密码。
        if type(data.get('secrets_included')) is not bool:
            raise ValueError('CipherBox JSON 缺少敏感字段声明')
        items = data.get('entries', [])
        if not isinstance(items, list):
            raise ValueError('JSON 导入结构无效')
        self._validate_items(items)
        if not items:
            return 0
        # 校验每个元素是否为 dict，防止非 dict 类型触发难以定位的 AttributeError。
        non_dict = [i for i, item in enumerate(items) if not isinstance(item, dict)]
        if non_dict:
            raise ValueError(
                f'JSON 条目列表中第 {non_dict[0] + 1} 项不是有效的对象'
            )
        secrets_included = data.get('secrets_included', True) is not False

        entries = [Entry.from_dict(item) for item in items]
        entries_data = [{'title': e.title, 'username': e.username} for e in entries]
        categories = {c.name.casefold(): c for c in self._entry_mgr.get_categories()}

        def _merge(entry: Entry, existing: Entry):
            if not secrets_included:
                self._merge_non_exported_secrets(entry, existing)

        return self._import_entries(
            entries, entries_data, categories, default_category_id,
            duplicate_action, 'JSON 导入', progress_callback,
            overwrite_merger=_merge,
        )

    @_transactional_import
    def import_from_csv(
        self,
        filepath: str,
        default_category_id: Optional[int] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        duplicate_action: str = 'import_all',
    ) -> int:
        """从 CSV 文件导入，支持多种列名格式

        Args:
            filepath: 文件路径
            default_category_id: 默认分类 ID
            progress_callback: 进度回调
            duplicate_action: 重复处理策略
                - 'skip': 跳过重复项
                - 'overwrite': 覆盖匹配的已有条目
                - 'import_all': 全部导入，默认行为
        """
        with open(filepath, 'r', encoding='utf-8-sig', newline='') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            headers = reader.fieldnames or []

        self._validate_items(rows)
        password_present = any(
            header.lower().strip() in _PASSWORD_COLUMN_NAMES
            for header in headers
        )

        if not rows:
            return 0

        categories = {c.name.casefold(): c for c in self._entry_mgr.get_categories()}

        # 将 rows 转换为统一格式用于去重检测，同时构建 Entry 对象
        entries = []
        entries_data = []
        for row in rows:
            rl = {k.lower(): v for k, v in row.items()}
            title = self._get_val(row, *_CSV_COLUMN_ALIASES['title'], _row_lower=rl)
            username = self._get_val(row, *_CSV_COLUMN_ALIASES['username'], _row_lower=rl)
            entry = Entry(
                title=title,
                username=username,
                password=self._get_val(row, *_CSV_COLUMN_ALIASES['password'], _row_lower=rl),
                url=self._get_val(row, *_CSV_COLUMN_ALIASES['url'], _row_lower=rl),
                tags=self._get_val(row, *_CSV_COLUMN_ALIASES['tags'], _row_lower=rl),
                notes=self._get_val(row, *_CSV_COLUMN_ALIASES['notes'], _row_lower=rl),
                totp_secret=self._get_val(row, *_CSV_COLUMN_ALIASES['totp_secret'], _row_lower=rl),
                category_name=self._get_val(row, *_CSV_COLUMN_ALIASES['category'], _row_lower=rl),
            )
            entries.append(entry)
            entries_data.append({'title': title, 'username': username})

        def _merge(entry: Entry, existing: Entry):
            self._merge_csv_secrets(entry, existing, password_present)

        return self._import_entries(
            entries, entries_data, categories, default_category_id,
            duplicate_action, 'CSV 导入', progress_callback,
            overwrite_merger=_merge,
        )

    # 注意：Chrome/Edge CSV 与 CipherBox CSV 共享相同的列名格式，即 name/url/username/password 等，
    # 因此直接委托给 import_from_csv。不添加 @_transactional_import 装饰器，
    # 因为事务由 import_from_csv 内部处理。
    def import_from_chrome_csv(
        self,
        filepath: str,
        default_category_id: Optional[int] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        duplicate_action: str = 'import_all',
    ) -> int:
        """从 Chrome/Edge 导出的 CSV 导入

        Args:
            filepath: 文件路径
            default_category_id: 默认分类 ID
            progress_callback: 进度回调
            duplicate_action: 重复处理策略
                - 'skip': 跳过重复项
                - 'overwrite': 覆盖匹配的已有条目
                - 'import_all': 全部导入，默认行为
        """
        return self.import_from_csv(filepath, default_category_id, progress_callback, duplicate_action)

    @_transactional_import
    def import_from_keepass_csv(
        self,
        filepath: str,
        default_category_id: Optional[int] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        duplicate_action: str = 'import_all',
    ) -> int:
        """从 KeePass 导出的 CSV 文件导入

        KeePass CSV 常见列名: Title, UserName, Password, URL, Notes, Group

        Args:
            filepath: 文件路径
            default_category_id: 默认分类 ID
            progress_callback: 进度回调
            duplicate_action: 重复处理策略
                - 'skip': 跳过重复项
                - 'overwrite': 覆盖匹配的已有条目
                - 'import_all': 全部导入，默认行为
        """
        with open(filepath, 'r', encoding='utf-8-sig', newline='') as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        self._validate_items(rows)

        if not rows:
            return 0

        # 自动检测列名大小写：构建实际列名映射
        # KeePass 常见列: Title, UserName, Password, URL, Notes, Group
        field_aliases = _KEE_PASS_COLUMN_ALIASES

        # 获取 CSV 实际列名，原样保留
        actual_headers = list(rows[0].keys())

        # 为每个内部字段名找到 CSV 中匹配的列名
        col_map: dict[str, str] = {}
        for internal, aliases in field_aliases.items():
            for alias in aliases:
                for header in actual_headers:
                    if header.lower().strip() == alias.lower():
                        col_map[internal] = header
                        break
                if internal in col_map:
                    break
        password_present = 'password' in col_map

        categories = {c.name.casefold(): c for c in self._entry_mgr.get_categories()}

        # 构建 Entry 对象和去重检测数据
        entries = []
        entries_data = []
        for row in rows:
            title = row.get(col_map.get('title', ''), '').strip()
            username = row.get(col_map.get('username', ''), '').strip()
            entry = Entry(
                title=title,
                username=username,
                password=row.get(col_map.get('password', ''), '').strip(),
                url=row.get(col_map.get('url', ''), '').strip(),
                notes=row.get(col_map.get('notes', ''), '').strip(),
                category_name=row.get(col_map.get('group', ''), '').strip(),
            )
            entries.append(entry)
            entries_data.append({'title': title, 'username': username})

        def _merge(entry: Entry, existing: Entry):
            self._merge_csv_secrets(entry, existing, password_present)

        return self._import_entries(
            entries, entries_data, categories, default_category_id,
            duplicate_action, 'KeePass CSV 导入', progress_callback,
            overwrite_merger=_merge,
        )

    @_transactional_import
    def import_from_bitwarden_json(
        self,
        filepath: str,
        default_category_id: Optional[int] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        duplicate_action: str = 'import_all',
    ) -> int:
        """从 Bitwarden JSON 导出文件导入

        Args:
            filepath: 文件路径
            default_category_id: 默认分类 ID
            progress_callback: 进度回调
            duplicate_action: 重复处理策略
                - 'skip': 跳过重复项
                - 'overwrite': 覆盖匹配的已有条目
                - 'import_all': 全部导入，默认行为
        """
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        items = data.get('items', [])
        if not isinstance(items, list):
            raise ValueError('Bitwarden 导入结构无效')
        self._validate_items(items)
        if not items:
            return 0

        categories = {c.name.casefold(): c for c in self._entry_mgr.get_categories()}
        folder_map = {
            folder.get('id'): folder.get('name', '')
            for folder in data.get('folders', [])
            if folder.get('id')
        }

        # 解析 Bitwarden 条目
        entries = []
        entries_data = []
        for item in items:
            login = item.get('login', {})
            item_type = item.get('type', 1)
            custom_fields = [
                CustomField(
                    name=field.get('name') or '自定义字段',
                    value=str(field.get('value') or ''),
                    field_type='password' if field.get('type') == 1 else 'text',
                )
                for field in item.get('fields', [])
                if field.get('value') is not None
            ]
            entry_type = 'login'
            if item_type == 2:
                entry_type = ENTRY_TYPE_NOTE
            elif item_type == 3:
                entry_type = ENTRY_TYPE_CARD
                card = item.get('card', {})
                exp_year = str(card.get('expYear', ''))
                exp_month = str(card.get('expMonth', ''))
                if exp_month:
                    exp_month = exp_month.zfill(2)
                # 截断为两位年份以匹配卡片常见的 MM/YY 显示格式
                if len(exp_year) == 4:
                    exp_year = exp_year[-2:]
                custom_fields.extend([
                    CustomField('_card_holder', card.get('cardholderName', '')),
                    CustomField('_card_number', card.get('number', ''), 'password'),
                    CustomField(
                        '_card_expiry',
                        '/'.join(filter(None, [exp_month, exp_year])),
                    ),
                    CustomField('_card_cvv', card.get('code', ''), 'password'),
                ])
            elif item_type == 4:
                entry_type = ENTRY_TYPE_IDENTITY
                identity = item.get('identity', {})
                fullname = ' '.join(filter(None, [
                    identity.get('firstName', ''), identity.get('middleName', ''),
                    identity.get('lastName', ''),
                ]))
                custom_fields.extend([
                    CustomField('_id_fullname', fullname),
                    CustomField('_id_email', identity.get('email', '')),
                    CustomField('_id_phone', identity.get('phone', '')),
                    CustomField('_id_address', ' '.join(filter(None, [
                        identity.get('address1', ''), identity.get('address2', ''),
                        identity.get('city', ''), identity.get('state', ''),
                        identity.get('postalCode', ''), identity.get('country', ''),
                    ]))),
                ])
            folder_name = folder_map.get(item.get('folderId'), '')
            uris = login.get('uris') or []
            url = uris[0].get('uri', '') if uris else ''
            entry = Entry(
                title=item.get('name', ''),
                username=login.get('username', ''),
                password=login.get('password', ''),
                url=url,
                notes=item.get('notes', ''),
                custom_fields=custom_fields,
                entry_type=entry_type,
                totp_secret=login.get('totp', ''),
                is_favorite=item.get('favorite', False),
                category_name=folder_name,
            )
            entries.append(entry)
            entries_data.append({
                'title': item.get('name', ''),
                'username': login.get('username', ''),
            })

        return self._import_entries(
            entries, entries_data, categories, default_category_id,
            duplicate_action, 'Bitwarden 导入', progress_callback,
            overwrite_merger=self._merge_bitwarden_secrets,
        )

    @staticmethod
    def _get_val(row: dict, *keys: str, _row_lower: dict | None = None) -> str:
        """从行数据中按多个候选键名获取值，精确匹配优先，大小写不敏感回退。

        Args:
            row: CSV 行数据。
            *keys: 候选键名，按优先级排序。
            _row_lower: 可选的预计算小写键字典，避免同一行多次调用时重复构建。
        """
        for key in keys:
            val = row.get(key, '')
            # 注意：空字符串被视为"未提供"而非"有意清空"。这是 CSV 导入的设计
            # 决策——CSV 空单元格通常意味着列不存在或源不包含该数据，而非用户
            # 主动清除字段值。若需支持"有意清空"语义，需引入显式空值标记。
            if val:
                return val
        # 大小写不敏感回退
        rl = _row_lower or {k.lower(): v for k, v in row.items()}
        for key in keys:
            val = rl.get(key.lower(), '')
            if val:
                return val
        return ''

    @staticmethod
    def _now() -> str:
        return utc_now_iso()
