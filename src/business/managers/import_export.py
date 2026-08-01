"""导入导出管理器，负责 CSV、JSON 导入导出及浏览器密码导入。

格式特定的文件解析与覆盖合并器拆分至 :mod:`.importers` 策略类包；本模块仅保留
公开导入/导出 API 与共享编排（文件路径校验、去重判定、分类解析、覆盖写入、
事务与 epoch 守卫、CSV 注入防护）。
"""

import csv
import inspect
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, replace
from functools import wraps
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any, NamedTuple, TypeVar

from ...exceptions import (
    DatabaseError,
    DecryptionError,
    EntryError,
    EntryIntegrityError,
    ImportFormatError,
    ImportSizeError,
)
from ...models import MAX_CATEGORY_NAME, Category, Entry, RawEntry
from ...utils.file_security import atomic_write, validate_file_path
from ...utils.format import utc_now_iso
from .entry_manager import BatchUpdateItem
from .importers import (
    BitwardenImporter,
    CsvImporter,
    FormatImporter,
    JsonImporter,
    KeePassCsvImporter,
)

if TYPE_CHECKING:
    from .entry_manager import EntryManager

logger = logging.getLogger(__name__)

# 导入方法返回类型 TypeVar：用 TypeVar 透传返回类型，保留装饰器的通用透传契约。
T = TypeVar('T')

MAX_IMPORT_FILE_SIZE = 25 * 1024 * 1024


def _sanitize_formula_prefix(value: str) -> str:
    """转义 CSV/表格公式注入危险前缀（= +/-/@/制表符），供入库与导出共享。

    把清洗点前移到入库边界（SEC-008）：导入阶段统一对受影响文本字段转义，使后续
    剪贴板复制、JSON 导出等外流路径无需各自防护即可避免表格软件公式执行。导出路径
    （:meth:`ImportExportManager._csv_safe`）复用同一逻辑作为纵深防御（覆盖非导入
    来源、如用户手建的危险前缀条目）。
    """
    if value.startswith(('=', '+', '-', '@', '\t')):
        return "'" + value
    return value


def _sanitize_entry_formula_fields(entry: Entry) -> Entry:
    """对条目受公式注入影响的文本字段转义（SEC-008 入库边界清洗）。

    仅清洗会外流至表格软件的文本字段；password/totp_secret 为不外流至表格的密钥，
    不清洗（转义会破坏密钥有效性）。字段集在此显式声明为单一事实源。
    """
    return replace(
        entry,
        title=_sanitize_formula_prefix(entry.title),
        username=_sanitize_formula_prefix(entry.username),
        url=_sanitize_formula_prefix(entry.url),
        tags=_sanitize_formula_prefix(entry.tags),
        notes=_sanitize_formula_prefix(entry.notes),
    )


@dataclass(frozen=True)
class ImportContext:
    """导入写入编排的上下文（去重/分类所需的不变配置）。

    收敛 ``_import_entries`` / ``_dedupe_and_classify`` 的 categories/
    default_category_id/duplicate_action/source_label 参数（MAINT-009），使方法签名
    收为 (entries, ctx, callbacks)，降低参数个数与调用点对齐负担。

    字段含义：
        categories: 现有分类的 casefold 名 → Category 映射（``_categories_by_folded_name``
            构造），按名匹配避免重复创建同名分类。
        default_category_id: 来源未指定分类时落入的默认分类；None 表示不指定。
        duplicate_action: 重复处理策略 ``'import_all'``/``'skip'``/``'overwrite'``。
        source_label: 日志/用户提示中标识来源的文案（如「CSV 导入」）。
    """
    categories: dict[str, Category]
    default_category_id: int | None
    duplicate_action: str
    source_label: str


@dataclass(frozen=True)
class ImportCallbacks:
    """导入写入编排的回调（进度/取消/覆盖合并）。

    与 :class:`ImportContext` 分离：前者为不变配置，本类为可选的进度/取消探针与
    格式特定的合并器（MAINT-009）。

    字段含义：
        progress_callback: ``(current, total)`` 进度回调，total 为待处理条目总数
            （含重复/跳过项，确保进度能到 100%）。
        cancel_check: 取消探针，返回真值时中止分类循环（已分类部分随事务提交，
            构成部分导入）。
        overwrite_merger: 覆盖合并器 ``(导入条目, 已有条目) → 合并后条目``，由各
            格式策略类提供（如 CSV 保留源未携带的密码型字段）；None 表示不合并。
    """
    progress_callback: Callable[[int, int], None] | None = None
    cancel_check: Callable[[], bool] | None = None
    overwrite_merger: Callable[[Entry, Entry], Entry] | None = None


class OverwritePlan(NamedTuple):
    """覆盖计划项：源序号、合并后条目、待覆盖条目密文 raw。

    old_password 不在计划中收集（SEC-014）：延迟到 :meth:`_apply_overwrites` 写入前
    逐条解密提取，避免分类阶段全量收集旧密码明文随导入规模线性驻留。
    """
    source_idx: int
    entry: Entry
    raw: RawEntry


def _validate_import_input(method: Callable[..., T]) -> Callable[..., T]:
    """导入路径校验装饰器。

    通过 inspect 绑定方法签名，从任意调用方式稳健提取 filepath 参数，校验并
    替换为 resolved 路径（避免校验后原始路径被替换为符号链接的 TOCTOU 窗口）。

    文件读取与解析在事务外完成；事务与 epoch 守卫由 ``_run_import_transaction``
    在写入阶段开启，使大文件 I/O 与解析不持有 db_lock，避免阻塞 TOTP 定时器等。
    """
    method_sig = inspect.signature(method)
    # 装饰器应用即校验被装饰方法含 filepath 参数，让重命名/漏参在导入时立即暴露，
    # 而非延迟到运行时 bound.arguments['filepath'] 抛 KeyError（栈帧远离原因）。
    if 'filepath' not in method_sig.parameters:
        raise TypeError(
            f'@_validate_import_input 装饰的方法 {method.__qualname__} 必须含 filepath 参数'
        )

    @wraps(method)
    def wrapper(self: 'ImportExportManager', *args: Any, **kwargs: Any) -> T:
        # 按方法签名绑定参数，无论位置或关键字调用都能正确定位 filepath
        bound = method_sig.bind(self, *args, **kwargs)
        bound.apply_defaults()
        filepath = bound.arguments['filepath']
        resolved = self._validate_import_path(filepath)
        bound.arguments['filepath'] = resolved
        default_category_id = bound.arguments.get('default_category_id')
        if (
            default_category_id is not None
            and self._entry_mgr.categories.get_category(default_category_id) is None
        ):
            raise ImportFormatError('默认分类不存在或已被删除')
        try:
            return method(*bound.args, **bound.kwargs)
        except UnicodeDecodeError:
            raise ImportFormatError(
                '文件编码不支持：请确保文件以 UTF-8 编码保存'
                '（从其他密码管理器导出时，请先以 UTF-8 重新保存）。'
            ) from None  # 有意隐藏 UnicodeDecodeError，替换消息已自足
    return wrapper


class ImportExportManager:
    """密码条目的导入和导出。

    格式特定的解析与合并由 :mod:`.importers` 策略类承担；本类负责共享编排：
    文件路径/大小校验、去重判定、分类解析、覆盖写入、事务与 epoch 守卫，
    以及 CSV/JSON 导出与 CSV 注入防护。
    """

    def __init__(self, entry_manager: 'EntryManager'):
        self._entry_mgr = entry_manager

    @staticmethod
    def _validate_import_path(filepath: str) -> str:
        resolved = str(validate_file_path(filepath))
        size = Path(resolved).stat().st_size
        if size > MAX_IMPORT_FILE_SIZE:
            raise ImportSizeError('导入文件过大，最大允许 25 MB')
        return resolved

    @staticmethod
    def _csv_safe(value: Any) -> str:
        """防护 CSV 注入：转义危险前缀（复用 :func:`_sanitize_formula_prefix`），替换内部控制字符。"""
        text = str(value) if value is not None else ''
        # 替换嵌入的换行符为空格，防止 CSV 行断裂
        text = text.replace('\r\n', ' ').replace('\r', ' ').replace('\n', ' ')
        return _sanitize_formula_prefix(text)

    def _duplicate_plan(
        self,
        entries_data: list[dict[str, Any]],
        duplicate_action: str,
        source_label: str,
        existing_entries: list[Entry] | None = None,
    ) -> tuple[set[int], dict[int, Entry]]:
        """按重复策略生成导入计划，返回 ``(跳过索引集, 覆盖映射)``。

        按 ``(title, username)`` casefold 匹配已有条目，策略决定返回语义：
        - ``import_all``：两者均空，全部作为新增。
        - ``skip``：重复项索引收入跳过集，覆盖映射为空。
        - ``overwrite``：重复项 ``索引 → 已有条目`` 收入覆盖映射，跳过集为空。
        """
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

    def _prepare_overwrite_map(
        self, overwrite: dict[int, Entry],
    ) -> dict[int, RawEntry]:
        """批量预读待覆盖条目的密文 raw（不解密），单次 SQL 查询替代 N+1。

        仅预读密文，解密推迟到覆盖循环逐条执行并立即清零，使任一时刻仅 1 条
        覆盖目标的完整明文驻留内存，与单条路径的「用毕即清」纪律一致。raw 供
        ``update_entry`` 经 ``preloaded_raw`` 复用（跳过重复 ``get_entry``）。
        """
        ids_by_idx: dict[int, int] = {}
        for idx, summary in overwrite.items():
            if summary.id is not None:
                ids_by_idx[idx] = summary.id
        if not ids_by_idx:
            return {}
        raw_entries = self._entry_mgr.db.get_entries_by_ids(list(ids_by_idx.values()))
        entries_by_id = {e.id: e for e in raw_entries}
        result: dict[int, RawEntry] = {}
        for idx, entry_id in ids_by_idx.items():
            raw = entries_by_id.get(entry_id)
            if raw is None:
                raise EntryError(f'待覆盖条目 {entry_id} 已不存在')
            result[idx] = raw
        return result

    def _resolve_category(
        self,
        name: str,
        categories: dict[str, Category],
        default_category_id: int | None,
    ) -> int | None:
        """匹配来源分类；不存在时创建，尽量保留导入结构。"""
        clean_name = (name or '').strip()
        if not clean_name:
            return default_category_id
        if len(clean_name) > MAX_CATEGORY_NAME:
            raise ImportFormatError(f'分类名称过长（最多 {MAX_CATEGORY_NAME} 字符）')
        key = clean_name.casefold()
        if key in categories:
            return categories[key].id
        category = Category(name=clean_name, icon_char='[IMPORT]', color='#0f766e')
        new_id = self._entry_mgr.categories.add_category(category, notify=False)
        category = replace(category, id=new_id)
        categories[key] = category
        return category.id

    # ======== 导出 ========

    def export_to_json(
        self,
        filepath: str,
        entries: list[Entry],
        include_password: bool = False,
        cancel_check: Callable[[], bool] | None = None,
    ) -> bool:
        """导出为 JSON 文件。

        导出前经 :func:`validate_file_path` 校验路径（SEC-003），与导入侧
        :meth:`_validate_import_path` 对齐，拒绝目录遍历与符号链接重定向。
        """
        resolved = validate_file_path(filepath, check_ancestors=True)
        def write_cb(f: IO[str]) -> bool:
            header = {
                'app': 'CipherBox',
                'exported_at': utc_now_iso(),
                'secrets_included': include_password,
            }
            f.write('{\n')
            for key, value in header.items():
                comma = ','  # header 后必跟 entries 数组，故每项后都加逗号
                f.write(
                    f'  {json.dumps(key)}: '
                    f'{json.dumps(value, ensure_ascii=False)}{comma}\n'
                )
            f.write('  "entries": [')
            first = True
            for entry in entries:
                if cancel_check and cancel_check():
                    return False
                if not first:
                    f.write(',')
                f.write('\n')
                serialized = json.dumps(
                    entry.to_dict(include_password=include_password),
                    indent=2,
                    ensure_ascii=False,
                )
                f.write('\n'.join(f'    {line}' for line in serialized.splitlines()))
                first = False
            if not first:
                f.write('\n')
            f.write('  ]\n}\n')
            return True
        return atomic_write(resolved, write_cb, mode='w', encoding='utf-8')

    def export_to_csv(
        self,
        filepath: str,
        entries: list[Entry],
        include_password: bool = False,
        cancel_check: Callable[[], bool] | None = None,
    ) -> bool:
        """导出为 CSV 文件。

        导出前经 :func:`validate_file_path` 校验路径（SEC-003），与导入侧对齐。
        """
        resolved = validate_file_path(filepath, check_ancestors=True)
        fieldnames = ['title', 'username', 'password', 'totp_secret', 'url',
                       'category', 'tags', 'notes', 'is_favorite',
                       'created_at', 'updated_at']
        if not include_password:
            fieldnames.remove('password')
            fieldnames.remove('totp_secret')

        def write_cb(f: IO[str]) -> bool:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            for entry in entries:
                if cancel_check and cancel_check():
                    return False
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
            return True
        return atomic_write(
            resolved, write_cb, mode='w', encoding='utf-8-sig', newline='',
        )

    # ======== 导入编排 ========

    def _import_entries(
        self,
        entries: list[Entry],
        entries_data: list[dict[str, Any]],
        ctx: ImportContext,
        callbacks: ImportCallbacks,
    ) -> int:
        """统一的导入写入编排：去重、分类、批量新增、批量覆盖、进度回调。

        事务边界由 ``_run_import_transaction`` 的 epoch 守卫包裹；本方法仅编排
        写入阶段，按「入库清洗 → 去重计划 → 分类(含覆盖合并) → 批量新增 →
        批量覆盖 → 统一通知」顺序流转，各阶段职责拆至下方私有方法。

        Args:
            entries: 已解析好的 Entry 对象列表，与 entries_data 一一对应。
            entries_data: 用于去重检测的摘要列表，每项含 title/username。
            ctx: 导入上下文（分类/去重配置，见 :class:`ImportContext`）。
            callbacks: 进度/取消/覆盖合并回调（见 :class:`ImportCallbacks`）。
        """
        if not entries:
            return 0

        # 入库边界统一清洗公式注入前缀（SEC-008）：对受影响文本字段转义危险前缀，
        # 使后续剪贴板/JSON 导出等外流路径无需各自防护。密码/TOTP 不外流至表格，不清洗。
        entries = [_sanitize_entry_formula_fields(e) for e in entries]

        duplicate_indices, overwrite_map = self._duplicate_plan(
            entries_data, ctx.duplicate_action, ctx.source_label
        )
        overwrite_raws = self._prepare_overwrite_map(overwrite_map) if overwrite_map else {}

        new_entries, overwrite_plans, classify_skipped = self._dedupe_and_classify(
            entries, duplicate_indices, overwrite_raws, ctx, callbacks,
        )

        new_count, new_skipped = self._batch_insert_new(new_entries, ctx.source_label)
        overwrite_count, overwrite_skipped = self._apply_overwrites(
            overwrite_plans, ctx.source_label
        )

        skipped = classify_skipped + new_skipped + overwrite_skipped
        count = new_count + overwrite_count

        # 批量导入统一通知一次（add/update 已传 notify=False 避免逐条回调）
        self._entry_mgr.notify_batch_change()

        if skipped:
            logger.info("%s: 跳过 %d 条无效条目", ctx.source_label, skipped)

        return count

    def _dedupe_and_classify(
        self,
        entries: list[Entry],
        duplicate_indices: set[int],
        overwrite_raws: dict[int, RawEntry],
        ctx: ImportContext,
        callbacks: ImportCallbacks,
    ) -> tuple[list[Entry], list[OverwritePlan], int]:
        """遍历 entries 分类，返回 ``(new_entries, overwrite_plans, skipped)``。

        按重复策略判定跳过/覆盖/新增：``duplicate_indices`` 命中则跳过，
        ``overwrite_raws`` 命中则走 :meth:`_merge_overwrite_entry` 覆盖合并，
        否则收入 ``new_entries``。

        分类解析（``_resolve_category``）在 try 之外调用：其抛出
        :class:`ImportFormatError`（分类名过长等）向上传播中止整个导入事务，
        而非逐条跳过——保留原语义。覆盖路径的解密/合并错误则在 try 内被捕获，
        逐条跳过。
        """
        total = len(entries)
        new_entries: list[Entry] = []
        # OverwritePlan(source_idx, entry, raw)：old_password 延迟到 _apply_overwrites
        # 写入前逐条解密（SEC-014），不在分类阶段收集，避免旧密码明文随导入规模线性驻留。
        overwrite_plans: list[OverwritePlan] = []
        skipped = 0

        for i, entry in enumerate(entries):
            if callbacks.cancel_check and callbacks.cancel_check():
                # 用户取消：中止分类，已分类条目随后批量/逐条写入（部分导入随事务提交）。
                # 使 worker.cancel() 真正生效而非空转冻结 UI。
                break
            # 每条都推进进度（含 duplicate/skip/overwrite）：total 含全部条目，进度应
            # 到 total，避免 duplicate/skip 跳过 progress_callback 导致进度条永远到
            # 不了 100%（原 progress 仅在成功处理后调用，被 continue 跳过）。
            if callbacks.progress_callback:
                callbacks.progress_callback(i + 1, total)
            if i in duplicate_indices:
                continue

            entry = replace(
                entry,
                category_id=self._resolve_category(
                    entry.category_name, ctx.categories, ctx.default_category_id
                ),
            )

            try:
                if i in overwrite_raws:
                    raw = overwrite_raws[i]
                    # 逐条解密覆盖目标并合并：用毕即清（password/totp_secret 置零 + 删引用），
                    # 任一时刻仅 1 条覆盖目标完整明文驻留，与单条路径纪律一致。
                    # old_password 不在此提取（SEC-014），延迟到 _apply_overwrites 写入时刻。
                    entry = self._merge_overwrite_entry(
                        entry, raw, callbacks.overwrite_merger
                    )
                    overwrite_plans.append(OverwritePlan(i, entry, raw))
                else:
                    new_entries.append(entry)
            except (ImportError, EntryError, EntryIntegrityError) as exc:
                # 覆盖路径抛出校验错误（解密结构损坏 EntryIntegrityError / 合并器
                # ImportError·EntryError），跳过该条目而非回滚整个导入。
                # 不打印 title：标题可能含敏感信息，落入日志会扩大泄漏面。
                # 用条目序号（导入数据中的位置）替代，便于排查又不暴露内容。
                skipped += 1
                logger.warning(
                    "%s: 跳过第 %d 个条目（crypto_id=%s）: %s",
                    ctx.source_label,
                    i + 1,
                    entry.crypto_id or '(未生成)',
                    exc,
                )
                continue

        return new_entries, overwrite_plans, skipped

    def _merge_overwrite_entry(
        self,
        entry: Entry,
        raw: RawEntry,
        overwrite_merger: Callable[[Entry, Entry], Entry] | None,
    ) -> Entry:
        """覆盖单条：解密 existing、合并、保留 password_changed_at、用毕即清。

        返回合并后的 entry（不含 old_password——延迟到 :meth:`_apply_overwrites` 写入
        时刻逐条解密提取，SEC-014）。解密/合并异常向上传播，由
        :meth:`_dedupe_and_classify` 捕获（GCM 认证失败的 :class:`DecryptionError` 不在
        该捕获范围，向上中止导入）。

        ``existing`` 用毕即清：明文 password/totp_secret 经 replace 重新绑定到空串，
        旧明文 str 失去引用由 GC 回收。任一时刻仅 1 条覆盖目标完整明文驻留内存，
        与单条路径的「用毕即清」纪律一致。raw 供 ``update_entry`` 经 ``preloaded_raw``
        复用（跳过重复 ``get_entry``）。
        """
        existing = self._entry_mgr.decrypt_entry(raw)
        try:
            entry = replace(
                entry, id=existing.id, created_at=existing.created_at,
            )
            if overwrite_merger is not None:
                entry = overwrite_merger(entry, existing)
            # 导入覆盖保留原 password_changed_at，避免批量导入把"久未
            # 修改"条目重置为"刚修改"从而绕过过期检测
            entry = replace(
                entry, password_changed_at=existing.password_changed_at,
            )
        finally:
            # 用毕即清：明文 password/totp_secret 重新绑定到空串，旧明文由 GC 回收。
            existing = replace(existing, password='', totp_secret='')
            del existing
        return entry

    def _batch_insert_new(
        self,
        new_entries: list[Entry],
        source_label: str,
    ) -> tuple[int, int]:
        """批量写入新条目，返回 ``(成功数, 跳过数)``。

        用 executemany 替代逐条 INSERT，缩短导入事务持 db_lock 的时间。
        ``add_entries`` 原子写入（全成功或全回滚），失败时整批计为跳过。
        """
        if not new_entries:
            return 0, 0
        try:
            self._entry_mgr.add_entries(new_entries, notify=False)
            return len(new_entries), 0
        except (EntryError, EntryIntegrityError, DatabaseError) as exc:
            logger.warning(
                "%s: 批量写入 %d 个新条目失败: %s",
                source_label, len(new_entries), exc,
            )
            return 0, len(new_entries)

    def _apply_overwrites(
        self,
        overwrite_plans: list[OverwritePlan],
        source_label: str,
    ) -> tuple[int, int]:
        """批量执行覆盖更新，返回 ``(成功数, 跳过数)``。

        收敛逐条 ``update_entry`` 的 per-item SAVEPOINT/epoch 复查开销。
        ``preloaded_raw`` 复用预读跳过重复 ``get_entry``。

        old_password 延迟提取（SEC-014）：分类阶段不收集旧密码明文，此处写入前逐条
        经 :meth:`EntryManager.decrypt_password` 解密，收敛明文驻留面（不在新条目批量
        插入期间驻留）。

        per-item 错误隔离：验证/解密错误跳过单条，写/epoch 错误向上中止。
        ``batch_failures`` 索引对齐 ``overwrite_plans``（同序），取原 source idx 记日志，
        不打印标题（可能含敏感信息）。
        """
        if not overwrite_plans:
            return 0, 0
        # 写入前逐条解密旧密码：用毕由 update_entries_batch_with_history 的 _prepare_password_update
        # del 清零。延迟至此使旧密码不在新条目批量插入期间驻留（SEC-014）。
        batch_items: list[BatchUpdateItem] = [
            BatchUpdateItem(plan.entry, plan.raw, self._entry_mgr.decrypt_password(plan.raw))
            for plan in overwrite_plans
        ]
        success, batch_failures = (
            self._entry_mgr.update_entries_batch_with_history(
                batch_items, preserve_password_changed_at=True,
            )
        )
        skipped = 0
        # batch_failures 索引对齐 batch_items（与 overwrite_plans 同序）；
        # 取原 source idx 记日志，不打印标题（可能含敏感信息）。
        for batch_idx, failure_exc in batch_failures:
            plan = overwrite_plans[batch_idx]
            # 防御性：decrypt_password 容错返回空串使批量路径跳过旧密码解密异常，理论上
            # 不抛 DecryptionError；保留区分仅为语义清晰（解密损坏用 ERROR，校验失败用 WARNING）。
            if isinstance(failure_exc, DecryptionError):
                skipped += 1
                logger.error(
                    "%s: 第 %d 个条目覆盖失败——目标条目 crypto_id=%s 已有数据损坏: %s",
                    source_label,
                    plan.source_idx + 1,
                    plan.entry.crypto_id or '(未生成)',
                    failure_exc,
                )
            else:
                skipped += 1
                logger.warning(
                    "%s: 跳过覆盖第 %d 个条目（crypto_id=%s）: %s",
                    source_label,
                    plan.source_idx + 1,
                    plan.entry.crypto_id or '(未生成)',
                    failure_exc,
                )
        return success, skipped

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
        with self._entry_mgr.epoch_guarded_transaction(operation='导入'):
            return importer()

    def _categories_by_folded_name(self) -> dict[str, Category]:
        """构造分类名 casefold 映射，供导入按名匹配分类（大小写不敏感）。"""
        return {
            c.name.casefold(): c
            for c in self._entry_mgr.categories.get_categories()
        }

    def _run_importer(
        self,
        importer: FormatImporter,
        filepath: str,
        default_category_id: int | None,
        duplicate_action: str,
        progress_callback: Callable[[int, int], None] | None,
        cancel_check: Callable[[], bool] | None,
    ) -> int:
        """统一执行格式策略：解析文件后在 epoch 守卫事务内写入。

        import_file 入口共享此骨架，仅传入的 importer 不同，消除事务/分类/
        写入编排的重复。文件解析在事务外完成（importer.parse），大文件 I/O 与
        解析不持 db_lock。

        parse 外层统一归一解析异常（SEC-009）：JSON 损坏（json.JSONDecodeError）、
        深嵌套（RecursionError）、CSV 格式错误（csv.Error）一律转
        :class:`ImportFormatError`；UnicodeDecodeError 由上层装饰器归一为编码提示。
        """
        try:
            parsed = importer.parse(filepath)
        except (json.JSONDecodeError, RecursionError, csv.Error) as exc:
            raise ImportFormatError(
                f'文件解析失败，文件可能已损坏：{exc}'
            ) from exc
        categories = self._categories_by_folded_name()
        ctx = ImportContext(
            categories=categories,
            default_category_id=default_category_id,
            duplicate_action=duplicate_action,
            source_label=parsed.source_label,
        )
        callbacks = ImportCallbacks(
            progress_callback=progress_callback,
            cancel_check=cancel_check,
            overwrite_merger=parsed.overwrite_merger,
        )
        return self._run_import_transaction(
            lambda: self._import_entries(parsed.entries, parsed.entries_data, ctx, callbacks)
        )

    # ======== 导入入口 ========

    # 格式键 → 策略类注册表：新增格式只需新增策略类并在此注册，import_file 据此
    # 单一 dispatch，无需为每格式编写独立方法。chrome_csv 复用 CsvImporter
    # （Chrome/Edge 与 CipherBox CSV 共享列名格式）。
    _IMPORTERS: dict[str, type[FormatImporter]] = {
        'json': JsonImporter,
        'csv': CsvImporter,
        'chrome_csv': CsvImporter,
        'keepass_csv': KeePassCsvImporter,
        'bitwarden_json': BitwardenImporter,
    }

    @_validate_import_input
    def import_file(
        self,
        filepath: str,
        format_key: str,
        default_category_id: int | None = None,
        progress_callback: Callable[[int, int], None] | None = None,
        duplicate_action: str = 'import_all',
        cancel_check: Callable[[], bool] | None = None,
    ) -> int:
        """按格式键导入：单一 dispatch 入口，依 _IMPORTERS 注册表分发到策略类。

        新增格式只需新增策略类并在 _IMPORTERS 注册，即可经此入口导入，无需为每
        格式编写独立方法。

        Args:
            filepath: 文件路径。
            format_key: _IMPORTERS 中的格式键（'json'/'csv'/'chrome_csv'/
                'keepass_csv'/'bitwarden_json'）。
            default_category_id: 默认分类 ID。
            progress_callback: 进度回调。
            duplicate_action: 重复处理策略。
                - 'skip': 跳过重复项
                - 'overwrite': 覆盖匹配的已有条目
                - 'import_all': 全部导入，默认行为
            cancel_check: 取消检查回调。
        """
        importer_cls = self._IMPORTERS.get(format_key)
        if importer_cls is None:
            raise ImportFormatError(f'不支持的导入格式：{format_key}')
        return self._run_importer(
            importer_cls(), filepath, default_category_id,
            duplicate_action, progress_callback, cancel_check,
        )
