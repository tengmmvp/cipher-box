"""导入导出管理器，负责 CSV、JSON 导入导出及浏览器密码导入。"""

import csv
import inspect
import json
import logging
import os
from functools import wraps
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Optional

from ...crypto.totp import TOTPGenerator
from ...utils.format import utc_now_iso

if TYPE_CHECKING:
    from .entry_manager import EntryManager

from ...exceptions import EntryError, EntryIntegrityError, VaultKeyEpochMismatchError
from ...models import (
    ENTRY_TYPE_CARD,
    ENTRY_TYPE_IDENTITY,
    ENTRY_TYPE_LOGIN,
    ENTRY_TYPE_NOTE,
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
)
from ...utils.file_security import secure_file, validate_file_path

logger = logging.getLogger(__name__)

MAX_IMPORT_FILE_SIZE = 25 * 1024 * 1024
MAX_IMPORT_ENTRIES = 50_000
MAX_IMPORT_ENTRY_SIZE = 2 * 1024 * 1024

# CSV 导入列名别名映射：每个字段对应一组可能的列名，匹配时不区分大小写。
# 由 _parse_csv_like 经 _build_col_map 用于 import_from_csv。
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

# KeePass CSV 列名别名映射：键为内部字段名，值为 CSV 中可能的列名，均为小写用于匹配。
# 值统一为 tuple，与 _CSV_COLUMN_ALIASES 保持一致，利用不可变性避免误改。
_KEE_PASS_COLUMN_ALIASES = {
    'title':    ('title',),
    'username': ('username',),
    'password': ('password',),
    'url':      ('url',),
    'notes':    ('notes',),
    'group':    ('group',),
}


def _transactional_import(method):
    """导入路径校验装饰器。

    通过 inspect 绑定被装饰方法的签名，从任意调用方式（位置或关键字）稳健
    提取 filepath 参数，校验并替换为 resolved 路径（避免校验后原始路径被
    替换为符号链接的 TOCTOU 窗口）。

    文件读取与解析在方法体内、事务之外完成；事务与 epoch 守卫由
    ``_run_import_transaction`` 在写入阶段开启。这样大文件导入的 I/O 与解析
    不持有 db_lock，避免阻塞 TOTP 定时器等其他数据库访问。UnicodeDecodeError
    仅可能发生在事务外的读取阶段，此处统一替换为友好提示。
    """
    method_sig = inspect.signature(method)
    # 装饰器应用即校验被装饰方法含 filepath 参数，让重命名/漏参在导入时立即暴露，
    # 而非延迟到运行时 bound.arguments['filepath'] 抛 KeyError（栈帧远离原因）。
    assert 'filepath' in method_sig.parameters, (
        f'@_transactional_import 装饰的方法 {method.__qualname__} 必须含 filepath 参数'
    )

    @wraps(method)
    def wrapper(self, *args, **kwargs):
        # 按方法签名绑定参数，无论位置或关键字调用都能正确定位 filepath
        bound = method_sig.bind(self, *args, **kwargs)
        bound.apply_defaults()
        filepath = bound.arguments['filepath']
        resolved = self._validate_import_path(filepath)
        bound.arguments['filepath'] = resolved
        try:
            return method(*bound.args, **bound.kwargs)
        except UnicodeDecodeError:
            raise ValueError(
                '文件编码不支持：请确保 CSV 文件使用 UTF-8 编码保存。'
                '若文件来自其他密码管理器，请先以 UTF-8 编码重新保存。'
            ) from None  # 有意隐藏 UnicodeDecodeError，替换消息已自足
    return wrapper


class ImportExportManager:
    """密码条目的导入和导出"""

    def __init__(self, entry_manager: 'EntryManager'):
        self._entry_mgr = entry_manager

    @staticmethod
    def _validate_import_path(filepath: str) -> str:
        resolved = str(validate_file_path(filepath))
        size = Path(resolved).stat().st_size
        if size > MAX_IMPORT_FILE_SIZE:
            raise ValueError('导入文件过大，最大允许 25 MB')
        return resolved

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
            replace_all: True 时用 existing 的全部密码型字段替换 entry 的字段，
                适用于 CSV 或非导出场景，源格式无法表达密码型字段。
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
            entries: 已解析好的 Entry 对象列表，与 entries_data 一一对应。
            entries_data: 用于去重检测的摘要列表，每项含 title/username。
            categories: 已有分类的 casefold 名称映射。
            default_category_id: 默认分类 ID。
            duplicate_action: 重复处理策略，取值 import_all、skip 或 overwrite。
            source_label: 日志中标识来源，例如 'JSON 导入'。
            progress_callback: 进度回调。
            overwrite_merger: 可选的覆盖合并回调，接收新条目与已有条目两个参数，
                无返回值。在设置 id 与 created_at 之后、写入数据库之前调用；
                若为 None 则直接用新条目覆盖。
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
                    # 导入覆盖保留原 password_changed_at，避免批量导入把"久未
                    # 修改"条目重置为"刚修改"从而绕过过期检测
                    entry.password_changed_at = existing.password_changed_at
                    self._entry_mgr.update_entry(
                        entry, preserve_password_changed_at=True, notify=False,
                    )
                else:
                    self._entry_mgr.add_entry(entry, notify=False)
            except (ValueError, EntryIntegrityError) as exc:
                # 字段长度违规或完整性错误，跳过该条目而非回滚整个导入
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

        # 批量导入统一通知一次（add/update 已传 notify=False 避免逐条回调）
        self._entry_mgr.notify_batch_change()

        if skipped:
            logger.info("%s: 跳过 %d 条无效条目", source_label, skipped)

        return count

    def _run_import_transaction(self, importer: Callable[[], int]) -> int:
        """在事务内执行导入写入，含 epoch 守卫。

        文件读取与解析须在调用本方法之前完成（事务外）。本方法在事务开始前
        快照 key_epoch，事务开始后验证未变化，防止导入期间并发改密导致数据
        用旧密钥加密但 epoch 已更新。

        Args:
            importer: 在事务内调用的写入回调，通常为 ``_import_entries`` 的
                部分应用。返回导入条目数。
        """
        # epoch 守卫是冗余的防御层：真正的串行化由 db.transaction() 持有的数据库锁
        # 保证（改密 _re_encrypt_all 同样经该锁串行），不会与导入并发写库。此处二次
        # 校验 epoch 是纵深防御，避免未来若移除事务锁时静默引入竞态——切勿据此
        # 误以为去掉事务锁后仅靠此守卫仍安全。
        pre_epoch = self._entry_mgr.key_epoch
        with self._entry_mgr.db.transaction():
            current_epoch = self._entry_mgr.key_epoch
            if pre_epoch != current_epoch:
                raise VaultKeyEpochMismatchError('导入期间检测到密钥变更，已中止导入')
            return importer()

    # ======== 导入 ========

    @_transactional_import
    def import_from_json(
        self,
        filepath: str,
        default_category_id: Optional[int] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        duplicate_action: str = 'import_all',
    ) -> int:
        """从 JSON 文件导入。

        Args:
            filepath: 文件路径。
            default_category_id: 默认分类 ID。
            progress_callback: 进度回调。
            duplicate_action: 重复处理策略。
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
        # 先校验每个元素为 dict，防止非 dict 触发 _validate_items 内 item.values()
        # 的 AttributeError（绕过下方的友好提示）。
        non_dict = [i for i, item in enumerate(items) if not isinstance(item, dict)]
        if non_dict:
            raise ValueError(
                f'JSON 条目列表中第 {non_dict[0] + 1} 项不是有效的对象'
            )
        self._validate_items(items)
        if not items:
            return 0
        # 上方 type(...) is not bool 检查已保证 secrets_included 为 bool
        secrets_included = data['secrets_included']

        entries = [Entry.from_dict(item) for item in items]
        entries_data = [{'title': e.title, 'username': e.username} for e in entries]
        categories = {c.name.casefold(): c for c in self._entry_mgr.get_categories()}

        def _merge(entry: Entry, existing: Entry):
            if not secrets_included:
                self._merge_non_exported_secrets(entry, existing)

        return self._run_import_transaction(lambda: self._import_entries(
            entries, entries_data, categories, default_category_id,
            duplicate_action, 'JSON 导入', progress_callback,
            overwrite_merger=_merge,
        ))

    @_transactional_import
    def import_from_csv(
        self,
        filepath: str,
        default_category_id: Optional[int] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        duplicate_action: str = 'import_all',
    ) -> int:
        """从 CSV 文件导入，支持多种列名格式。

        Args:
            filepath: 文件路径。
            default_category_id: 默认分类 ID。
            progress_callback: 进度回调。
            duplicate_action: 重复处理策略。
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

        categories = {c.name.casefold(): c for c in self._entry_mgr.get_categories()}

        entries, entries_data, password_present = self._parse_csv_like(
            rows,
            _CSV_COLUMN_ALIASES,
            {
                'title': 'title', 'username': 'username', 'password': 'password',
                'url': 'url', 'tags': 'tags', 'notes': 'notes',
                'totp_secret': 'totp_secret', 'category': 'category_name',
            },
        )

        def _merge(entry: Entry, existing: Entry):
            self._merge_csv_secrets(entry, existing, password_present)

        return self._run_import_transaction(lambda: self._import_entries(
            entries, entries_data, categories, default_category_id,
            duplicate_action, 'CSV 导入', progress_callback,
            overwrite_merger=_merge,
        ))

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
        """从 Chrome/Edge 导出的 CSV 导入。

        Args:
            filepath: 文件路径。
            default_category_id: 默认分类 ID。
            progress_callback: 进度回调。
            duplicate_action: 重复处理策略。
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
        """从 KeePass 导出的 CSV 文件导入。

        KeePass CSV 常见列名: Title, UserName, Password, URL, Notes, Group。

        Args:
            filepath: 文件路径。
            default_category_id: 默认分类 ID。
            progress_callback: 进度回调。
            duplicate_action: 重复处理策略。
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

        categories = {c.name.casefold(): c for c in self._entry_mgr.get_categories()}

        entries, entries_data, password_present = self._parse_csv_like(
            rows,
            _KEE_PASS_COLUMN_ALIASES,
            {
                'title': 'title', 'username': 'username', 'password': 'password',
                'url': 'url', 'notes': 'notes', 'group': 'category_name',
            },
        )

        def _merge(entry: Entry, existing: Entry):
            self._merge_csv_secrets(entry, existing, password_present)

        return self._run_import_transaction(lambda: self._import_entries(
            entries, entries_data, categories, default_category_id,
            duplicate_action, 'KeePass CSV 导入', progress_callback,
            overwrite_merger=_merge,
        ))

    @staticmethod
    def _bitwarden_entry_fields(item: dict) -> 'tuple[str, list[CustomField]]':
        """解析 Bitwarden item 的条目类型与自定义字段。

        item_type: 1=login, 2=note, 3=card, 4=identity；未知类型按 login。
        """
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
        if item_type == 2:
            return ENTRY_TYPE_NOTE, custom_fields
        if item_type == 3:
            card = item.get('card', {})
            exp_year = str(card.get('expYear', ''))
            exp_month = str(card.get('expMonth', ''))
            if exp_month:
                exp_month = exp_month.zfill(2)
            # 截断为两位年份以匹配卡片常见的 MM/YY 显示格式
            if len(exp_year) == 4:
                exp_year = exp_year[-2:]
            custom_fields.extend([
                CustomField('_card_holder', str(card.get('cardholderName') or '')),
                CustomField('_card_number', str(card.get('number') or ''), 'password'),
                CustomField(
                    '_card_expiry',
                    '/'.join(filter(None, [exp_month, exp_year])),
                ),
                CustomField('_card_cvv', str(card.get('code') or ''), 'password'),
            ])
            return ENTRY_TYPE_CARD, custom_fields
        if item_type == 4:
            identity = item.get('identity', {})
            fullname = ' '.join(filter(None, [
                str(identity.get('firstName') or ''), str(identity.get('middleName') or ''),
                str(identity.get('lastName') or ''),
            ]))
            custom_fields.extend([
                CustomField('_id_fullname', fullname),
                CustomField('_id_email', str(identity.get('email') or '')),
                CustomField('_id_phone', str(identity.get('phone') or '')),
                CustomField('_id_address', ' '.join(filter(None, [
                    str(identity.get('address1') or ''), str(identity.get('address2') or ''),
                    str(identity.get('city') or ''), str(identity.get('state') or ''),
                    str(identity.get('postalCode') or ''), str(identity.get('country') or ''),
                ]))),
            ])
            return ENTRY_TYPE_IDENTITY, custom_fields
        return ENTRY_TYPE_LOGIN, custom_fields

    @_transactional_import
    def import_from_bitwarden_json(
        self,
        filepath: str,
        default_category_id: Optional[int] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        duplicate_action: str = 'import_all',
    ) -> int:
        """从 Bitwarden JSON 导出文件导入。

        Args:
            filepath: 文件路径。
            default_category_id: 默认分类 ID。
            progress_callback: 进度回调。
            duplicate_action: 重复处理策略。
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
            entry_type, custom_fields = self._bitwarden_entry_fields(item)
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

        return self._run_import_transaction(lambda: self._import_entries(
            entries, entries_data, categories, default_category_id,
            duplicate_action, 'Bitwarden 导入', progress_callback,
            overwrite_merger=self._merge_bitwarden_secrets,
        ))

    @staticmethod
    def _build_col_map(headers: list, aliases: dict) -> dict[str, str]:
        """构建内部字段名到 CSV 实际列名的映射，大小写不敏感匹配。

        aliases 的值为候选列名可迭代对象，按声明顺序匹配，首个命中即确定。
        供 CSV 与 KeePass 等表格类导入共享，消除两套并列的列名匹配机制。
        """
        normalized = {str(h).lower().strip(): h for h in headers}
        col_map: dict[str, str] = {}
        for internal, alias_list in aliases.items():
            for alias in alias_list:
                actual = normalized.get(alias.lower())
                if actual is not None:
                    col_map[internal] = actual
                    break
        return col_map

    def _parse_csv_like(
        self,
        rows: list,
        aliases: dict,
        entry_key_map: dict[str, str],
    ) -> tuple[list, list, bool]:
        """统一的 CSV 类行解析：列名别名匹配后构建 Entry 与去重数据。

        Args:
            rows: csv.DictReader 的行列表。
            aliases: 内部字段名到候选列名列表的映射。
            entry_key_map: 内部字段名到 Entry 构造关键字的映射，允许同一
                Entry 字段接收不同来源列，例如分类字段对应 CSV 的 category
                与 KeePass 的 group。

        Returns:
            由条目列表、去重摘要列表、是否存在密码列标志组成的三元组。
        """
        headers = list(rows[0].keys())
        col_map = self._build_col_map(headers, aliases)
        password_present = 'password' in col_map
        # 内部字段名到最大长度的映射，与 Entry.from_dict 的 MAX_FIELD_* 校验一致。
        # category_name 非长度受限字段，不在此校验；它对应 CSV 的 category 或 KeePass 的 group。
        field_limits = {
            'title': MAX_FIELD_TITLE,
            'username': MAX_FIELD_USERNAME,
            'password': MAX_FIELD_PASSWORD,
            'url': MAX_FIELD_URL,
            'tags': MAX_FIELD_TAGS,
            'notes': MAX_FIELD_NOTES,
            'totp_secret': MAX_FIELD_TOTP_SECRET,
        }
        entries: list = []
        entries_data: list = []
        for row in rows:
            kwargs: dict[str, Any] = {
                entry_key_map[field]: (row.get(col_map[field], '') or '').strip()
                for field in col_map
            }
            # 对长度受限字段做 MAX_FIELD_* 校验，与 Entry.from_dict 一致，
            # 避免 Entry(**kwargs) 绕过 from_dict 的校验逻辑导致超长字段入库。
            for internal_field, max_len in field_limits.items():
                if internal_field in col_map:
                    value = kwargs.get(entry_key_map[internal_field], '')
                    if len(value) > max_len:
                        raise ValueError(
                            f'导入条目字段 {internal_field} 过长（最多 {max_len} 字符）'
                        )
            # totp_secret 校验：非空时须为有效 base32，损坏密钥静默入库会导致后续
            # TOTP 验证码生成失败且用户无反馈。损坏则清空并告警，保留条目其余字段。
            totp_value = kwargs.get('totp_secret', '')
            if totp_value and not TOTPGenerator.validate_secret(totp_value):
                logger.warning("导入条目 totp_secret 非有效 base32，已清空该字段")
                kwargs['totp_secret'] = ''
            entries.append(Entry(**kwargs))
            entries_data.append({
                'title': kwargs.get('title', ''),
                'username': kwargs.get('username', ''),
            })
        return entries, entries_data, password_present

    @staticmethod
    def _now() -> str:
        return utc_now_iso()
