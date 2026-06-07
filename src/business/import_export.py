"""导入导出管理器 - CSV/JSON 导入导出 + 浏览器密码导入"""

import csv
import json
import logging
import os
from functools import wraps
from pathlib import Path
from typing import Callable, Optional

from ..database.models import (
    Category, CustomField, Entry,
    ENTRY_TYPE_CARD, ENTRY_TYPE_IDENTITY, ENTRY_TYPE_NOTE,
)
from ..utils.file_security import secure_file

logger = logging.getLogger(__name__)

MAX_IMPORT_FILE_SIZE = 25 * 1024 * 1024
MAX_IMPORT_ENTRIES = 50_000
MAX_IMPORT_ENTRY_SIZE = 2 * 1024 * 1024


def _transactional_import(method):
    """确保一次导入要么全部成功，要么完全回滚。"""
    @wraps(method)
    def wrapper(self, *args, **kwargs):
        if args:
            self._validate_import_path(args[0])
        with self._entry_mgr.db.transaction():
            return method(self, *args, **kwargs)
    return wrapper


class ImportExportManager:
    """密码条目的导入和导出"""

    def __init__(self, entry_manager):
        self._entry_mgr = entry_manager

    @staticmethod
    def _validate_import_path(filepath: str):
        size = Path(filepath).stat().st_size
        if size > MAX_IMPORT_FILE_SIZE:
            raise ValueError('导入文件过大，最大允许 25 MB')

    @staticmethod
    def _validate_items(items: list):
        if len(items) > MAX_IMPORT_ENTRIES:
            raise ValueError(f'导入条目过多，最大允许 {MAX_IMPORT_ENTRIES} 条')
        for item in items:
            if len(json.dumps(item, ensure_ascii=False).encode('utf-8')) > MAX_IMPORT_ENTRY_SIZE:
                raise ValueError('导入条目字段过大')

    @staticmethod
    def _atomic_target(filepath: str) -> tuple[Path, Path]:
        target = Path(filepath)
        target.parent.mkdir(parents=True, exist_ok=True)
        return target, target.with_name(target.name + '.tmp')

    @staticmethod
    def _csv_safe(value):
        text = str(value) if value is not None else ''
        return "'" + text if text.startswith(('=', '+', '-', '@')) else text

    @staticmethod
    def _merge_non_exported_secrets(entry: Entry, existing: Entry):
        entry.password = existing.password
        entry.totp_secret = existing.totp_secret
        sensitive = [field for field in existing.custom_fields if field.field_type == 'password']
        entry.custom_fields = [
            field for field in entry.custom_fields if field.field_type != 'password'
        ] + sensitive

    def _duplicate_plan(
        self,
        entries_data: list[dict],
        duplicate_action: str,
        source_label: str,
    ) -> tuple[set[int], dict[int, Entry]]:
        if duplicate_action not in {'import_all', 'skip', 'overwrite'}:
            raise ValueError('无效的重复项处理策略')
        if duplicate_action == 'import_all':
            return set(), {}

        existing_entries = self._entry_mgr.get_entry_summaries()
        existing_by_key = {
            (entry.title.casefold(), entry.username.casefold()): entry
            for entry in existing_entries
            if entry.title
        }
        matched = {
            index: existing_by_key[key]
            for index, item in enumerate(entries_data)
            if (
                key := (
                    str(item.get('title') or '').strip().casefold(),
                    str(item.get('username') or '').strip().casefold(),
                )
            ) in existing_by_key
        }
        if duplicate_action == 'skip':
            logger.info('%s: 检测到 %d 个重复项，将跳过', source_label, len(matched))
            return set(matched), {}
        logger.info('%s: 检测到 %d 个重复项，将覆盖', source_label, len(matched))
        return set(), matched

    def _load_overwrite_entry(self, summary: Entry) -> Entry:
        entry = self._entry_mgr.get_entry(summary.id)
        if entry is None:
            raise RuntimeError('待覆盖条目已不存在')
        return entry

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
        category = Category(name=clean_name, icon_char='📥', color='#0f766e')
        category.id = self._entry_mgr.db.add_category(category)
        categories[key] = category
        return category.id

    # ========== 导出 ==========

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
        fieldnames = ['title', 'username', 'password', 'url', 'category',
                       'tags', 'notes', 'is_favorite', 'created_at', 'updated_at']
        if not include_password:
            fieldnames.remove('password')

        target, temp = self._atomic_target(filepath)
        try:
            with open(temp, 'w', encoding='utf-8-sig', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                for entry in entries:
                    row = entry.to_dict(include_password=include_password)
                    exported_fields = [
                        field for field in entry.custom_fields
                        if include_password or field.field_type != 'password'
                    ]
                    cf_str = '; '.join(f"{cf.name}={cf.value}" for cf in exported_fields)
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

    # ========== 导入 ==========

    @staticmethod
    def check_duplicates(
        entries_data: list[dict],
        existing_entries: list[Entry],
    ) -> list[dict]:
        """检测待导入条目与已有条目的重复

        以 (title, username) 为匹配键。

        Args:
            entries_data: 待导入的条目列表（每个有 title/username 等字段）
            existing_entries: 现有已解密条目

        Returns:
            重复项列表，每项包含 {index, title, username, existing_title}
        """
        existing_keys = {
            (e.title.lower(), e.username.lower()): e
            for e in existing_entries
            if e.title
        }

        duplicates = []
        for i, item in enumerate(entries_data):
            title = (item.get('title') or '').strip()
            username = (item.get('username') or '').strip()
            key = (title.lower(), username.lower())
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
                - 'import_all': 全部导入（默认）
        """
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        if not isinstance(data, dict) or data.get('app') != 'CipherBox':
            raise ValueError('不是 CipherBox JSON 导出文件')
        if type(data.get('secrets_included')) is not bool:
            raise ValueError('CipherBox JSON 缺少敏感字段声明')
        entries_data = data.get('entries', [])
        if not isinstance(entries_data, list):
            raise ValueError('JSON 导入结构无效')
        self._validate_items(entries_data)
        if not entries_data:
            return 0
        secrets_included = data.get('secrets_included', True) is not False

        categories = {c.name.casefold(): c for c in self._entry_mgr.get_categories()}
        duplicate_indices, overwrite_map = self._duplicate_plan(
            entries_data, duplicate_action, 'JSON 导入'
        )

        count = 0
        total = len(entries_data)
        for i, item in enumerate(entries_data):
            # 跳过重复项
            if i in duplicate_indices:
                continue

            entry = Entry.from_dict(item)
            entry.category_id = self._resolve_category(
                entry.category_name, categories, default_category_id
            )

            # 覆盖已有条目
            if i in overwrite_map:
                existing = self._load_overwrite_entry(overwrite_map[i])
                entry.id = existing.id
                entry.created_at = existing.created_at
                if not secrets_included:
                    self._merge_non_exported_secrets(entry, existing)
                self._entry_mgr.update_entry(entry)
            else:
                self._entry_mgr.add_entry(entry)

            count += 1
            if progress_callback:
                progress_callback(i + 1, total)

        return count

    @_transactional_import
    def import_from_csv(
        self,
        filepath: str,
        default_category_id: Optional[int] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        duplicate_action: str = 'import_all',
    ) -> int:
        """从 CSV 文件导入（支持多种列名格式）

        Args:
            filepath: 文件路径
            default_category_id: 默认分类 ID
            progress_callback: 进度回调
            duplicate_action: 重复处理策略
                - 'skip': 跳过重复项
                - 'overwrite': 覆盖匹配的已有条目
                - 'import_all': 全部导入（默认）
        """
        with open(filepath, 'r', encoding='utf-8-sig', newline='') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            headers = reader.fieldnames or []

        self._validate_items(rows)
        password_present = any(
            header.lower().strip() in {'password', '密码', 'login_password', 'pass'}
            for header in headers
        )

        if not rows:
            return 0

        categories = {c.name.casefold(): c for c in self._entry_mgr.get_categories()}

        # 将 rows 转换为统一格式用于去重检测
        entries_data = [
            {
                'title': self._get_val(row, 'title', 'Title', '名称', 'name'),
                'username': self._get_val(row, 'username', 'Username', '用户名', 'login', 'user'),
            }
            for row in rows
        ]

        duplicate_indices, overwrite_map = self._duplicate_plan(
            entries_data, duplicate_action, 'CSV 导入'
        )

        count = 0
        total = len(rows)
        for i, row in enumerate(rows):
            # 跳过重复项
            if i in duplicate_indices:
                continue

            entry = Entry(
                title=entries_data[i]['title'],
                username=entries_data[i]['username'],
                password=self._get_val(row, 'password', 'Password', '密码', 'login_password', 'pass'),
                url=self._get_val(row, 'url', 'URL', '网址', 'website', 'login_uri', 'uri', 'origin'),
                tags=self._get_val(row, 'tags', 'Tags', '标签'),
                notes=self._get_val(row, 'notes', 'Notes', '备注', 'note', 'comment'),
            )
            cat_name = self._get_val(row, 'category', 'Category', '分类', 'folder')
            entry.category_id = self._resolve_category(
                cat_name, categories, default_category_id
            )

            # 覆盖已有条目
            if i in overwrite_map:
                existing = self._load_overwrite_entry(overwrite_map[i])
                entry.id = existing.id
                entry.created_at = existing.created_at
                if not password_present:
                    entry.password = existing.password
                self._entry_mgr.update_entry(entry)
            else:
                self._entry_mgr.add_entry(entry)

            count += 1
            if progress_callback:
                progress_callback(i + 1, total)

        return count

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
                - 'import_all': 全部导入（默认）
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
                - 'import_all': 全部导入（默认）
        """
        with open(filepath, 'r', encoding='utf-8-sig', newline='') as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        self._validate_items(rows)

        if not rows:
            return 0

        # 自动检测列名大小写：构建实际列名映射
        # KeePass 常见列: Title, UserName, Password, URL, Notes, Group
        field_aliases = {
            'title':    ['title'],
            'username': ['username'],
            'password': ['password'],
            'url':      ['url'],
            'notes':    ['notes'],
            'group':    ['group'],
        }

        # 获取 CSV 实际列名（原样保留）
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

        # 将 rows 转换为统一格式用于去重检测
        entries_data = [
            {
                'title': row.get(col_map.get('title', ''), '').strip(),
                'username': row.get(col_map.get('username', ''), '').strip(),
            }
            for row in rows
        ]

        duplicate_indices, overwrite_map = self._duplicate_plan(
            entries_data, duplicate_action, 'KeePass CSV 导入'
        )

        count = 0
        total = len(rows)
        for i, row in enumerate(rows):
            # 跳过重复项
            if i in duplicate_indices:
                continue

            entry = Entry(
                title=entries_data[i]['title'],
                username=entries_data[i]['username'],
                password=row.get(col_map.get('password', ''), '').strip(),
                url=row.get(col_map.get('url', ''), '').strip(),
                notes=row.get(col_map.get('notes', ''), '').strip(),
            )

            # Group 列值作为分类名
            group_name = row.get(col_map.get('group', ''), '').strip()
            entry.category_id = self._resolve_category(
                group_name, categories, default_category_id
            )

            # 覆盖已有条目
            if i in overwrite_map:
                existing = self._load_overwrite_entry(overwrite_map[i])
                entry.id = existing.id
                entry.created_at = existing.created_at
                if not password_present:
                    entry.password = existing.password
                self._entry_mgr.update_entry(entry)
            else:
                self._entry_mgr.add_entry(entry)

            count += 1
            if progress_callback:
                progress_callback(i + 1, total)

        return count

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
                - 'import_all': 全部导入（默认）
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
        # 预构建条目数据用于去重检测
        entries_data = []
        for item in items:
            login = item.get('login', {})
            entries_data.append({
                'title': item.get('name', ''),
                'username': login.get('username', ''),
            })

        duplicate_indices, overwrite_map = self._duplicate_plan(
            entries_data, duplicate_action, 'Bitwarden 导入'
        )

        count = 0
        total = len(items)
        for i, item in enumerate(items):
            # 跳过重复项
            if i in duplicate_indices:
                continue

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
            entry = Entry(
                title=item.get('name', ''),
                username=login.get('username', ''),
                password=login.get('password', ''),
                url=login.get('uris', [{}])[0].get('uri', '') if login.get('uris') else '',
                notes=item.get('notes', ''),
                custom_fields=custom_fields,
                entry_type=entry_type,
                totp_secret=login.get('totp', ''),
                is_favorite=item.get('favorite', False),
            )
            folder_name = folder_map.get(item.get('folderId'), '')
            entry.category_id = self._resolve_category(
                folder_name, categories, default_category_id
            )

            # 覆盖已有条目
            if i in overwrite_map:
                existing = self._load_overwrite_entry(overwrite_map[i])
                entry.id = existing.id
                entry.created_at = existing.created_at
                self._entry_mgr.update_entry(entry)
            else:
                self._entry_mgr.add_entry(entry)

            count += 1
            if progress_callback:
                progress_callback(i + 1, total)

        return count

    @staticmethod
    def _get_val(row: dict, *keys: str) -> str:
        """从行数据中按多个候选键名获取值"""
        for key in keys:
            val = row.get(key, '')
            if val:
                if isinstance(val, str) and len(val) > 1 and val[0] == "'" and val[1] in '=+-@':
                    return val[1:]
                return val
        return ''

    @staticmethod
    def _now() -> str:
        from datetime import datetime
        return datetime.now().isoformat()
