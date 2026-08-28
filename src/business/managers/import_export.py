"""导入导出管理器，负责多种格式（CSV/JSON/KeePass CSV/Bitwarden JSON）导入与 CSV/JSON 导出。

格式特定的文件解析与覆盖合并器拆分至 :mod:`.importers` 策略类包，导出序列化
拆分至 :mod:`.exporters` 策略函数包（ARCH-038）；本模块仅保留公开导入/导出 API
与共享编排（文件路径校验、去重判定、分类解析、覆盖写入、事务与 epoch 守卫、
公式注入的入库边界清洗）。
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
    DecryptionError,
    EntryError,
    EntryIntegrityError,
    ImportDataError,
    ImportFormatError,
    ImportSizeError,
)
from ...models import MAX_CATEGORY_NAME, MAX_IMPORT_FILE_SIZE, Category, Entry, RawEntry
from ...utils.file_security import atomic_write, validate_file_path
from ..services.entry_batch_writer import (
    PROGRESS_REPORT_EVERY,
    BatchUpdateItem,
    PreparedUpdate,
    encrypt_new_entries,
    prepare_overwrite_updates,
    write_new_entries,
    write_overwrite_updates,
)
from ..services.url_hygiene import sanitize_formula_prefix
from .exporters import write_csv_entries, write_json_entries
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

# 装饰器 _validate_import_input 的返回类型透传 TypeVar。
T = TypeVar("T")

# ======== 导入加权总进度刻度（PERF-065）========
# 50k CSV 端到端实测 8.43s 中加密 3.29s + 写入 2.85s 占 ~73%，而原 progress_callback
# 只在分类阶段（0.61s，7%）逐条上报——进度条先冲 100% 再长冻。改为加权总进度：
# 各阶段按实测耗时占比映射到 [0,100]，用户感知与实际剩余时间一致。
_IMPORT_PROGRESS_TOTAL = 100
# parse 完成里程碑（文件解析，粗粒度单点上报）。
_PROGRESS_PARSE_DONE = 5
# sanitize 完成里程碑（公式注入清洗，粗粒度单点上报）。
_PROGRESS_SANITIZE_DONE = 10
# 去重计划 + 覆盖目标密文预读完成里程碑（PERF-069：此前该段无任何上报）。
_PROGRESS_PLAN_DONE = 12
# classify 阶段跨度：12 → 15（PERF-069：每 PROGRESS_REPORT_EVERY 行节流上报，
# 终值恒上报——50k 行逐条上报的跨线程信号发射开销反超分类本身）。
_PROGRESS_CLASSIFY_SPAN = 3
# encrypt 阶段：15 → 70（耗时主导，行级细粒度；新条目与覆盖条目合并计量，PERF-069）。
_PROGRESS_ENCRYPT_BASE = 15
_PROGRESS_ENCRYPT_SPAN = 55
# write 阶段：70 → 100（次主导，分块细粒度；新增与覆盖写入合并计量，PERF-069）。
_PROGRESS_WRITE_BASE = 70
_PROGRESS_WRITE_SPAN = 30

# ======== 导出加权总进度刻度（PERF-070）========
# 50k 实测导出 = 解密 5.1s + 写文件 1.9s（≈ 73%/27%），全程原为不确定旋转。
# 解密阶段（get_entries_for_export 按条目节流）映射 0 → 70，写文件阶段（export_to_*
# 按已写条目节流）映射 70 → 100；百分比映射由 UI 调用方（import_export_dialog）完成，
# 业务函数只上报原始 (done, total) 条目计数。
_EXPORT_DECRYPT_SPAN = 70
_EXPORT_WRITE_BASE = 70
_EXPORT_WRITE_SPAN = 30


def _phase_progress(base: int, span: int, done: int, total: int) -> int:
    """把阶段内进度 ``(done/total)`` 映射为加权总进度百分比。

    ``done >= total`` 时取满 ``base + span``；``total <= 0``（空阶段）同样取满，
    保持进度单调不减。整数下取整使连续上报值单调不降。
    """
    if total <= 0 or done >= total:
        return base + span
    return base + span * done // total


def _emit_milestone(callbacks: "ImportCallbacks", value: int) -> None:
    """粗粒度阶段里程碑上报（parse/sanitize/plan/终值）：单点 ``(value, 100)``。"""
    if callbacks.progress_callback is not None:
        callbacks.progress_callback(value, _IMPORT_PROGRESS_TOTAL)


def export_decrypt_percent(done: int, total: int) -> int:
    """导出解密阶段 ``(done, total)`` → 加权总进度百分比 0→70（PERF-070）。

    供 UI（import_export_dialog）把 ``get_entries_for_export`` 的原始条目计数上报
    映射为总进度；50k 实测解密 5.1s / 写文件 1.9s，按 73/27 取整为 70/30 刻度。
    """
    return _phase_progress(0, _EXPORT_DECRYPT_SPAN, done, total)


def export_write_percent(done: int, total: int) -> int:
    """导出写文件阶段 ``(done, total)`` → 加权总进度百分比 70→100（PERF-070）。

    与 :func:`export_decrypt_percent` 同一刻度连续；``_phase_progress`` 的空阶段
    取满语义使零条目导出亦上报 100（进度不留悬挂）。
    """
    return _phase_progress(_EXPORT_WRITE_BASE, _EXPORT_WRITE_SPAN, done, total)


def _sanitize_entry_formula_fields(entry: Entry) -> Entry:
    """对条目受公式注入影响的文本字段转义（SEC-008 入库边界清洗）。

    仅清洗会外流至表格软件的文本字段；password/totp_secret 为不外流至表格的密钥，
    不清洗（转义会破坏密钥有效性）。字段集在此显式声明为单一事实源。

    custom_fields 的 name/value（SEC-045）：非 password 类型字段的值经详情面板
    「一键复制」外流且 CSV 导出拼入 notes（``name=value``），原样入库会使
    ``=cmd|...`` 类公式值直达粘贴执行；非 password 类型字段的 name/value 统一
    清洗。password 类型字段的值豁免——密钥完整性优先，与 SEC-008/SEC-039 的
    「不清洗密钥字段」决策一致（对其 name 亦不清洗，字段名仅作显示标签且非
    复制目标，保持该豁免简单可陈述）。
    """
    custom_fields = entry.custom_fields
    sanitized_fields = [
        (
            replace(
                field,
                name=sanitize_formula_prefix(field.name),
                value=sanitize_formula_prefix(field.value),
            )
            if field.field_type != "password"
            else field
        )
        for field in custom_fields
    ]
    return replace(
        entry,
        title=sanitize_formula_prefix(entry.title),
        username=sanitize_formula_prefix(entry.username),
        url=sanitize_formula_prefix(entry.url),
        tags=sanitize_formula_prefix(entry.tags),
        notes=sanitize_formula_prefix(entry.notes),
        custom_fields=sanitized_fields,
    )


@dataclass(frozen=True)
class ImportContext:
    """导入写入编排的上下文（去重/分类所需的不变配置）。

    收敛 ``_import_entries`` / ``_dedupe_and_classify`` 的 categories/
    default_category_id/duplicate_action/source_label 参数（MAINT-007），使方法签名
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
    格式特定的合并器（MAINT-007）。

    字段含义：
        progress_callback: ``(current, total)`` 进度回调，加权总进度语义（PERF-065）：
            ``total`` 恒为 100，``current`` 为各阶段按实测耗时占比映射的百分比
            （parse 5 / sanitize 10 / plan 12 / classify 12→15 / encrypt 15→70 /
            write 70→100），单调不减且终值 100。各阶段均按 ``PROGRESS_REPORT_EVERY``
            行节流上报、阶段终值恒上报（PERF-069：classify 亦节流，50k 行逐条跨
            线程信号发射的开销反超阶段本身）；encrypt/write 两阶段合并计量新条目
            与覆盖条目（纯覆盖导入不再全程冻结在 15%）。
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

    old_password 不在计划中收集（SEC-013）：延迟到 :meth:`_prepare_overwrite_batch` 写入前
    逐条解密提取，避免分类阶段全量收集旧密码明文随导入规模线性驻留。
    """

    source_idx: int
    entry: Entry
    raw: RawEntry


def _validate_import_input(method: Callable[..., T]) -> Callable[..., T]:
    """导入路径校验装饰器。

    通过 inspect 绑定方法签名，从任意调用方式稳健提取 filepath 参数，校验并
    替换为 resolved 路径（避免校验后原始路径被替换为符号链接的 TOCTOU 窗口）。

    文件读取与解析在事务外完成；事务与 epoch 守卫由 :meth:`_import_entries` 在
    写入阶段开启，使大文件 I/O 与解析不持有 db_lock，避免阻塞 TOTP 定时器等。
    """
    method_sig = inspect.signature(method)
    # 装饰器应用即校验被装饰方法含 filepath 参数，让重命名/漏参在导入时立即暴露，
    # 而非延迟到运行时 bound.arguments['filepath'] 抛 KeyError（栈帧远离原因）。
    if "filepath" not in method_sig.parameters:
        raise TypeError(
            f"@_validate_import_input 装饰的方法 {method.__qualname__} 必须含 filepath 参数"
        )

    @wraps(method)
    def wrapper(self: "ImportExportManager", *args: Any, **kwargs: Any) -> T:
        # 按方法签名绑定参数，无论位置或关键字调用都能正确定位 filepath
        bound = method_sig.bind(self, *args, **kwargs)
        bound.apply_defaults()
        filepath = bound.arguments["filepath"]
        resolved = self._validate_import_path(filepath)
        bound.arguments["filepath"] = resolved
        default_category_id = bound.arguments.get("default_category_id")
        if (
            default_category_id is not None
            and self._entry_mgr.categories.get_category(default_category_id) is None
        ):
            raise ImportFormatError("默认分类不存在或已被删除")
        try:
            return method(*bound.args, **bound.kwargs)
        except UnicodeDecodeError:
            raise ImportFormatError(
                "文件编码不支持：请确保文件以 UTF-8 编码保存"
                "（从其他密码管理器导出时，请先以 UTF-8 重新保存）。"
            ) from None  # 有意隐藏 UnicodeDecodeError，替换消息已自足

    return wrapper


class ImportExportManager:
    """密码条目的导入和导出。

    格式特定的解析与合并由 :mod:`.importers` 策略类承担；本类负责共享编排：
    文件路径/大小校验、去重判定、分类解析、覆盖写入、事务与 epoch 守卫，
    以及 CSV/JSON 导出与 CSV 注入防护。
    """

    def __init__(self, entry_manager: "EntryManager"):
        self._entry_mgr = entry_manager

    @staticmethod
    def _validate_import_path(filepath: str) -> str:
        """导入路径校验（manager 入口第一道）：路径安全解析 + 大小前置拒绝。

        上限单一事实源为 ``models.MAX_IMPORT_FILE_SIZE``（SEC-048 消双源：本模块
        原有本地 25MB 上限与 models 常量同名异值，且 25MB 拒绝满配自导出文件
        ——50k 条 JSON 导出 ≈35-38MB 的「能导出不能导入」断层）；importer 层的
        ``_check_import_file_size`` 为第二道（防绕过 manager 直接调 parse）。
        """
        resolved = str(validate_file_path(filepath))
        size = Path(resolved).stat().st_size
        if size > MAX_IMPORT_FILE_SIZE:
            raise ImportSizeError(
                f"导入文件过大，最大允许 {MAX_IMPORT_FILE_SIZE // (1024 * 1024)} MB"
            )
        return resolved

    def _duplicate_plan(
        self,
        entries_data: list[dict[str, Any]],
        duplicate_action: str,
        source_label: str,
    ) -> tuple[set[int], dict[int, int]]:
        """按重复策略生成导入计划，返回 ``(跳过索引集, 覆盖目标 id 映射)``。

        按 ``(title, username)`` casefold 匹配已有条目，策略决定返回语义：
        - ``import_all``：两者均空，全部作为新增。
        - ``skip``：重复项索引收入跳过集，覆盖映射为空。
        - ``overwrite``：重复项 ``索引 → 已有条目 id`` 收入覆盖映射，跳过集为空。

        去重对照经 :meth:`EntryManager.get_entry_dedup_index`（PERF-075）：窄投影 +
        摘要缓存取 (title, username, id)，替代原 ``get_entry_summaries()`` 全量摘要
        构建——覆盖策略只需 id 供 :meth:`_prepare_overwrite_map` 回查密文，完整
        existing 摘要纯属浪费（50k 冷缓存 1834ms → 窄投影约半）。
        """
        if duplicate_action not in {"import_all", "skip", "overwrite"}:
            raise ValueError("无效的重复项处理策略")
        if duplicate_action == "import_all":
            return set(), {}

        existing_by_key = {
            (title.casefold(), username.casefold()): entry_id
            for title, username, entry_id in self._entry_mgr.get_entry_dedup_index()
            if title
        }
        matched = {}
        for index, item in enumerate(entries_data):
            key = (
                str(item.get("title") or "").strip().casefold(),
                str(item.get("username") or "").strip().casefold(),
            )
            if key in existing_by_key:
                matched[index] = existing_by_key[key]
        if duplicate_action == "skip":
            logger.info("%s: 检测到 %d 个重复项，将跳过", source_label, len(matched))
            return set(matched), {}
        logger.info("%s: 检测到 %d 个重复项，将覆盖", source_label, len(matched))
        return set(), matched

    def _prepare_overwrite_map(
        self,
        overwrite: dict[int, int],
    ) -> dict[int, RawEntry]:
        """批量预读待覆盖条目的密文 raw（不解密），单次 SQL 查询替代 N+1。

        仅预读密文，解密推迟到覆盖循环逐条执行并立即清零，使任一时刻仅 1 条
        覆盖目标的完整明文驻留内存，与单条路径的「用毕即清」纪律一致。raw 流向
        :class:`OverwritePlan` → :class:`BatchUpdateItem`，由
        :func:`entry_batch_writer.prepare_overwrite_updates` 在锁外预处理阶段消费
        （取密文做旧密码解密比对与新密文构建，MAINT-004）。

        ``overwrite`` 为 ``导入索引 → 已有条目 id``（PERF-075：原为摘要 Entry，
        仅 id 被消费，窄投影化后直接传 id）。
        """
        if not overwrite:
            return {}
        raw_entries = self._entry_mgr.db.get_entries_by_ids(list(overwrite.values()))
        entries_by_id = {e.id: e for e in raw_entries}
        result: dict[int, RawEntry] = {}
        for idx, entry_id in overwrite.items():
            raw = entries_by_id.get(entry_id)
            if raw is None:
                raise EntryError(f"待覆盖条目 {entry_id} 已不存在")
            result[idx] = raw
        return result

    def _ensure_categories(
        self,
        entries: list[Entry],
        duplicate_indices: set[int],
        ctx: ImportContext,
        cancel_check: Callable[[], bool] | None,
    ) -> None:
        """预扫描条目分类名，批量创建缺失分类并回填 ctx.categories（ARCH-001）。

        逐条 ``add_category`` 每次触发 ``get_categories`` 全表解密查重，N 个新分类致
        O(N×M)；此处导入前一次性收集所有缺失分类名，经 ``add_categories_batch`` 单事务
        批量两阶段加密创建。``ctx.categories`` 已含现有分类 casefold 映射，据此判别真正
        缺失者；批创建不查重（与恢复路径同款），因预扫描已对现有分类与自身去重。

        与逐条实现一致：duplicate 条目跳过（不为被跳过条目创建空分类）；分类名超长
        抛 ``ImportFormatError`` 中止导入；cancel 后停止收集。

        Note:
            MAINT-004 后分类创建在 epoch 守卫写入事务**外**（加密亦移出 db_lock），经
            ``add_categories_batch`` 独立提交，后续条目写入失败时**不随回滚**——可能留下
            空分类（无害，用户可删；重导时按 casefold 名复用，不重复创建）。强求回滚须把
            分类创建移回写入事务，致分类解析与加密重新落入 db_lock，与 MAINT-004 相悖。
        """
        pending: dict[str, str] = {}  # casefold_key -> 原始拼写（去重，保留首次）
        for i, entry in enumerate(entries):
            if cancel_check and cancel_check():
                break
            if i in duplicate_indices:
                continue
            name = (entry.category_name or "").strip()
            if not name:
                continue
            if len(name) > MAX_CATEGORY_NAME:
                raise ImportFormatError(f"分类名称过长（最多 {MAX_CATEGORY_NAME} 字符）")
            key = name.casefold()
            if key not in ctx.categories and key not in pending:
                pending[key] = name
        if not pending:
            return
        new_cats = [
            Category(name=orig, icon_char="[IMPORT]", color="#0f766e") for orig in pending.values()
        ]
        new_ids = self._entry_mgr.categories.add_categories_batch(new_cats, notify=False)
        for cat, new_id in zip(new_cats, new_ids, strict=True):
            if new_id:
                ctx.categories[cat.name.casefold()] = replace(cat, id=new_id)

    def _resolve_category(
        self,
        name: str,
        categories: dict[str, Category],
        default_category_id: int | None,
    ) -> int | None:
        """按名匹配分类；缺失时回退默认（创建由 :meth:`_ensure_categories` 预完成）。

        ARCH-001：分类批量预创建后，本方法仅查内存映射，不再逐条 ``add_category``。
        正常不应到达「缺失」分支；防御性回退默认分类，避免 KeyError 中断导入。
        """
        clean_name = (name or "").strip()
        if not clean_name:
            return default_category_id
        key = clean_name.casefold()
        category = categories.get(key)
        if category is not None and category.id is not None:
            return category.id
        return default_category_id

    # ======== 导出 ========

    def export_to_json(
        self,
        filepath: str,
        entries: list[Entry],
        include_password: bool = False,
        cancel_check: Callable[[], bool] | None = None,
        progress: Callable[[int, int], None] | None = None,
    ) -> bool:
        """导出为 JSON 文件。

        导出前经 :func:`validate_file_path` 校验路径（SEC-003），与导入侧
        :meth:`_validate_import_path` 对齐，拒绝目录遍历与符号链接重定向。

        序列化格式逻辑在 :func:`.exporters.write_json_entries`（ARCH-038 拆分）；
        本方法保留编排骨架（路径校验 + 原子写入）。

        ``progress``（PERF-070）：提供时按已写条目数上报 ``(written, total)``，每
        ``PROGRESS_REPORT_EVERY`` 条节流、终值恒上报——50k 条写文件实测 1.9s，此前
        该阶段与解密阶段（5.1s）全程不确定旋转。百分比映射由 UI 调用方完成。
        """
        resolved = validate_file_path(filepath, check_ancestors=True)

        def write_cb(f: IO[str]) -> bool:
            return write_json_entries(f, entries, include_password, cancel_check, progress)

        return atomic_write(resolved, write_cb, mode="w", encoding="utf-8")

    def export_to_csv(
        self,
        filepath: str,
        entries: list[Entry],
        include_password: bool = False,
        cancel_check: Callable[[], bool] | None = None,
        progress: Callable[[int, int], None] | None = None,
    ) -> bool:
        """导出为 CSV 文件。

        导出前经 :func:`validate_file_path` 校验路径（SEC-003），与导入侧对齐。

        行构造/公式转义/自定义字段内联在 :func:`.exporters.write_csv_entries`
        （ARCH-038 拆分），含密钥列豁免转义决策（SEC-039，与导入侧「不清洗密钥
        字段」SEC-008 对称）；本方法保留编排骨架（路径校验 + 原子写入）。

        ``progress``（PERF-070）：提供时按已写条目数上报 ``(written, total)``（与
        :meth:`export_to_json` 同款节流与终值语义），百分比映射由 UI 调用方完成。
        """
        resolved = validate_file_path(filepath, check_ancestors=True)

        def write_cb(f: IO[str]) -> bool:
            return write_csv_entries(f, entries, include_password, cancel_check, progress)

        return atomic_write(
            resolved,
            write_cb,
            mode="w",
            encoding="utf-8-sig",
            newline="",
        )

    # ======== 导入编排 ========

    def _import_entries(
        self,
        entries: list[Entry],
        entries_data: list[dict[str, Any]],
        ctx: ImportContext,
        callbacks: ImportCallbacks,
    ) -> int:
        """统一的导入写入编排：去重、分类、加密、写入、进度回调。

        MAINT-004 事务边界：CPU 密集的加密移出 db_lock——「清洗 → 去重 → 分类 →
        加密」在 epoch 守卫事务外完成（各 db 读/写用各自短事务），仅「裸写入」在
        ``epoch_guarded_transaction(pre_epoch=...)`` 内。``pre_epoch`` 在加密前快照，
        供写入事务复查：若「加密后→开事务前」发生改密（epoch 已变），复查不等则中止
        回滚，旧密钥密文不落库。

        Args:
            entries: 已解析好的 Entry 对象列表，与 entries_data 一一对应。
            entries_data: 用于去重检测的摘要列表，每项含 title/username。
            ctx: 导入上下文（分类/去重配置，见 :class:`ImportContext`）。
            callbacks: 进度/取消/覆盖合并回调（见 :class:`ImportCallbacks`）。
        """
        if not entries:
            _emit_milestone(callbacks, _IMPORT_PROGRESS_TOTAL)
            return 0

        # ---- 锁外：清洗 → 去重 → 分类 → 加密 ----
        # 入库边界统一清洗公式注入前缀（SEC-008）：对受影响文本字段转义危险前缀，
        # 使后续剪贴板/JSON 导出等外流路径无需各自防护。密码/TOTP 不外流至表格，不清洗。
        entries = [_sanitize_entry_formula_fields(e) for e in entries]
        _emit_milestone(callbacks, _PROGRESS_SANITIZE_DONE)

        duplicate_indices, overwrite_map = self._duplicate_plan(
            entries_data, ctx.duplicate_action, ctx.source_label
        )
        overwrite_raws = self._prepare_overwrite_map(overwrite_map) if overwrite_map else {}

        # ARCH-001：预扫描批量创建缺失分类，替代 _dedupe_and_classify 内逐条
        # _resolve_category→add_category 的 O(N×M) 全表解密查重。
        self._ensure_categories(entries, duplicate_indices, ctx, callbacks.cancel_check)
        # 去重计划 + 覆盖目标预读 + 分类预扫描完成里程碑（PERF-069：该段此前无上报，
        # 与 sanitize 里程碑首尾相接覆盖 10%→12% 档）。
        _emit_milestone(callbacks, _PROGRESS_PLAN_DONE)

        new_entries, overwrite_plans, classify_skipped = self._dedupe_and_classify(
            entries,
            duplicate_indices,
            overwrite_raws,
            ctx,
            callbacks,
        )

        # 锁外加密（MAINT-004）：加密前快照 pre_epoch，供写入事务复查防「加密后改密」。
        # 加密进度经加权映射上报 15%→70%（PERF-065）；新条目与覆盖条目两个子批合并
        # 计量同一刻度（PERF-069）——纯覆盖导入（duplicate_action=overwrite 全命中）的
        # 加密预处理是耗时主导，此前全程冻结在 15%。
        pre_epoch = self._entry_mgr.key_epoch
        encrypt_total = len(new_entries) + len(overwrite_plans)
        encrypt_adapter = self._offset_phase_reporter(
            callbacks, _PROGRESS_ENCRYPT_BASE, _PROGRESS_ENCRYPT_SPAN, encrypt_total
        )
        enc_new, preserve, new_skipped = self._encrypt_new_batch(
            new_entries,
            ctx.source_label,
            progress=encrypt_adapter(offset=0, sub_total=len(new_entries)),
        )
        overwrite_prepared, overwrite_skipped = self._prepare_overwrite_batch(
            overwrite_plans,
            ctx.source_label,
            progress=encrypt_adapter(offset=len(new_entries), sub_total=len(overwrite_plans)),
        )

        # ---- 锁内：epoch 守卫事务内裸写入 ----
        # epoch 守卫是冗余防御层：真正的串行化由 db.transaction() 持有的数据库锁保证
        # （改密 _re_encrypt_all 同样经该锁串行），不会与导入并发写库。pre_epoch 复查是
        # 纵深防御——加密已移出 db_lock（MAINT-004），复查确保「加密后→写入前」未发生改密。
        # 写入进度经分块上报 70%→100%（PERF-065，事务内分块不破坏原子性）；新增与
        # 覆盖写入合并计量（PERF-069）。
        write_total = len(enc_new) + len(overwrite_prepared)
        write_adapter = self._offset_phase_reporter(
            callbacks, _PROGRESS_WRITE_BASE, _PROGRESS_WRITE_SPAN, write_total
        )
        with self._entry_mgr.epoch_guarded_transaction(operation="导入", pre_epoch=pre_epoch):
            write_new_entries(
                self._entry_mgr,
                enc_new,
                preserve=preserve,
                progress=write_adapter(offset=0, sub_total=len(enc_new)),
            )
            overwrite_count = write_overwrite_updates(
                self._entry_mgr,
                overwrite_prepared,
                pre_epoch,
                progress=write_adapter(offset=len(enc_new), sub_total=len(overwrite_prepared)),
            )

        _emit_milestone(callbacks, _IMPORT_PROGRESS_TOTAL)

        # 批量导入统一通知一次（写入已传 notify=False 避免逐条回调）。
        # 摘要缓存保留（PERF-022）：纯新增不改变既有条目摘要，clear_summaries=False
        # 免全量重解密（与 add_entry / write_new_entries 的声明语义对齐）；含覆盖时对
        # 被覆盖条目按 crypto_id 精细 pop（同单条 update_entry 的失效粒度），先失效
        # 后通知以兑现 change_bus「先失效缓存、后跑回调」的顺序约束。
        if overwrite_count:
            self._entry_mgr.invalidate_entry_summaries(
                {item.raw.crypto_id for item in overwrite_prepared}
            )
        self._entry_mgr.notify_batch_change(clear_summaries=False)

        skipped = classify_skipped + new_skipped + overwrite_skipped
        count = len(enc_new) + overwrite_count
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

        分类解析经 ``_resolve_category`` 查内存映射（缺失回退默认分类，不抛异常）；
        分类名超长等格式错误由 :meth:`_ensure_categories` 在分类预扫描阶段抛
        :class:`ImportFormatError` 向上传播中止整个导入事务，而非逐条跳过。覆盖路径
        的解密/合并错误则在 try 内被捕获，逐条跳过。
        """
        total = len(entries)
        new_entries: list[Entry] = []
        # OverwritePlan(source_idx, entry, raw)：old_password 延迟到 _prepare_overwrite_batch
        # 写入前逐条解密（SEC-013），不在分类阶段收集，避免旧密码明文随导入规模线性驻留。
        overwrite_plans: list[OverwritePlan] = []
        skipped = 0

        for i, entry in enumerate(entries):
            if callbacks.cancel_check and callbacks.cancel_check():
                # 用户取消：中止分类，已分类条目随后批量/逐条写入（部分导入随事务提交）。
                # 使 worker.cancel() 真正生效而非空转冻结 UI。
                break
            # 进度按 PROGRESS_REPORT_EVERY 节流上报、终值恒上报（PERF-069：50k 行
            # 逐条上报的跨线程信号发射开销反超分类本身，与 entry_batch_writer 的
            # 加密/写入阶段同款节流纪律；进度语义不变——total 含全部条目，单调不减，
            # 后续阶段不突跳）。加权映射到总进度 12%→15%。
            if callbacks.progress_callback is not None and (
                (i + 1) % PROGRESS_REPORT_EVERY == 0 or i + 1 == total
            ):
                callbacks.progress_callback(
                    _phase_progress(_PROGRESS_PLAN_DONE, _PROGRESS_CLASSIFY_SPAN, i + 1, total),
                    _IMPORT_PROGRESS_TOTAL,
                )
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
                    # old_password 不在此提取（SEC-013），延迟到 _prepare_overwrite_batch 写入时刻。
                    entry = self._merge_overwrite_entry(entry, raw, callbacks.overwrite_merger)
                    overwrite_plans.append(OverwritePlan(i, entry, raw))
                else:
                    new_entries.append(entry)
            except (ImportDataError, EntryError, EntryIntegrityError) as exc:
                # 覆盖路径抛出校验错误（解密结构损坏 EntryIntegrityError / 合并器
                # ImportDataError·EntryError），跳过该条目而非回滚整个导入。
                # 不打印 title：标题可能含敏感信息，落入日志会扩大泄漏面。
                # 用条目序号（导入数据中的位置）替代，便于排查又不暴露内容。
                skipped += 1
                logger.warning(
                    "%s: 跳过第 %d 个条目（crypto_id=%s）: %s",
                    ctx.source_label,
                    i + 1,
                    entry.crypto_id or "(未生成)",
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

        返回合并后的 entry（不含 old_password——延迟到 :meth:`_prepare_overwrite_batch` 写入
        时刻逐条解密提取，SEC-013）。解密/合并异常向上传播，由
        :meth:`_dedupe_and_classify` 捕获（GCM 认证失败的 :class:`DecryptionError` 不在
        该捕获范围，向上中止导入）。

        ``existing`` 用毕即清：明文 password/totp_secret 经 replace 重新绑定到空串，
        旧明文 str 失去引用由 GC 回收。任一时刻仅 1 条覆盖目标完整明文驻留内存，
        与单条路径的「用毕即清」纪律一致。raw 随 :class:`OverwritePlan` 流向
        :class:`BatchUpdateItem`，由 :func:`entry_batch_writer.prepare_overwrite_updates`
        在锁外预处理阶段消费（MAINT-004）。
        """
        existing = self._entry_mgr.decrypt_entry(raw)
        try:
            entry = replace(
                entry,
                id=existing.id,
                created_at=existing.created_at,
            )
            if overwrite_merger is not None:
                entry = overwrite_merger(entry, existing)
            # 导入覆盖保留原 password_changed_at，避免批量导入把"久未
            # 修改"条目重置为"刚修改"从而绕过过期检测
            entry = replace(
                entry,
                password_changed_at=existing.password_changed_at,
            )
        finally:
            # 用毕即清：明文 password/totp_secret 重新绑定到空串，旧明文由 GC 回收。
            existing = replace(existing, password="", totp_secret="")
            del existing
        return entry

    def _encrypt_new_batch(
        self,
        new_entries: list[Entry],
        source_label: str,
        *,
        progress: Callable[[int, int], None] | None = None,
    ) -> tuple[list[RawEntry], bool, int]:
        """锁外加密新条目（MAINT-004），返回 ``(enc_entries, preserve, skipped)``。

        加密在 db_lock 外完成（CPU 密集不阻塞 db 读），写入由调用方在 epoch 守卫事务内
        经 :func:`entry_batch_writer.write_new_entries` 执行。数据问题（字段非法/损坏）跳过整批。
        ``progress`` 透传 :func:`entry_batch_writer.encrypt_new_entries` 供加密阶段
        进度上报（PERF-065）。
        """
        if not new_entries:
            return [], False, 0
        try:
            enc_entries, preserve = encrypt_new_entries(
                self._entry_mgr, new_entries, progress=progress
            )
            return enc_entries, preserve, 0
        except (EntryError, EntryIntegrityError) as exc:
            logger.warning(
                "%s: 批量加密 %d 个新条目失败: %s",
                source_label,
                len(new_entries),
                exc,
            )
            return [], False, len(new_entries)

    def _prepare_overwrite_batch(
        self,
        overwrite_plans: list[OverwritePlan],
        source_label: str,
        progress: Callable[[int, int], None] | None = None,
    ) -> tuple[list[PreparedUpdate], int]:
        """锁外 prepare 覆盖项（MAINT-004），返回 ``(prepared, skipped)``。

        验证/解密/加密在 db_lock 外完成，写入由调用方在 epoch 守卫事务内经
        :func:`entry_batch_writer.write_overwrite_updates` 执行。per-item 错误隔离：验证/解密
        错误跳过单条（收集到 failures），写/epoch 错误由 write_overwrite_updates 向上中止。

        old_password 延迟提取（SEC-013/PERF-006）：留 None 由 prepare_overwrite_updates
        的 prepared 阶段逐条解密、比对即 del，避免全部旧密码同刻驻留。
        ``failures`` 索引对齐 ``overwrite_plans``（同序），取原 source idx 记日志，
        不打印标题（可能含敏感信息）。``progress`` 透传 prepare_overwrite_updates
        供覆盖加密阶段上报（PERF-069）。
        """
        if not overwrite_plans:
            return [], 0
        # old_password 留 None（PERF-006）：不在批量收集阶段预解密全部旧密码（同刻驻留），
        # 由 prepare_overwrite_updates 的 prepared 阶段逐条解密、prepare_password_update
        # 比对即 del 清零。
        batch_items: list[BatchUpdateItem] = [
            BatchUpdateItem(plan.entry, plan.raw, None) for plan in overwrite_plans
        ]
        prepared, batch_failures = prepare_overwrite_updates(
            self._entry_mgr,
            batch_items,
            preserve_password_changed_at=True,
            progress=progress,
        )
        skipped = 0
        # batch_failures 索引对齐 batch_items（与 overwrite_plans 同序）；
        # 取原 source idx 记日志，不打印标题（可能含敏感信息）。
        for batch_idx, failure_exc in batch_failures:
            plan = overwrite_plans[batch_idx]
            # old_password 解密容错回退 ''（PERF-006，在 prepare_password_update 内），不抛
            # DecryptionError；failures 主要含 EntryError/EntryIntegrityError。保留 ERROR/WARNING
            # 区分仅为语义清晰。
            if isinstance(failure_exc, DecryptionError):
                skipped += 1
                logger.error(
                    "%s: 第 %d 个条目覆盖失败——目标条目 crypto_id=%s 已有数据损坏: %s",
                    source_label,
                    plan.source_idx + 1,
                    plan.entry.crypto_id or "(未生成)",
                    failure_exc,
                )
            else:
                skipped += 1
                logger.warning(
                    "%s: 跳过覆盖第 %d 个条目（crypto_id=%s）: %s",
                    source_label,
                    plan.source_idx + 1,
                    plan.entry.crypto_id or "(未生成)",
                    failure_exc,
                )
        return prepared, skipped

    @staticmethod
    def _offset_phase_reporter(
        callbacks: ImportCallbacks,
        base: int,
        span: int,
        grand_total: int,
    ) -> Callable[..., Callable[[int, int], None] | None]:
        """构造带偏移的阶段进度适配器工厂（PERF-069）。

        一个阶段（encrypt/write）由两个子批构成（新条目 + 覆盖条目），各自上报
        子批内 ``(done, sub_total)``；本工厂按 ``_make(offset, sub_total)`` 生成子批
        适配器，把子批进度折算为 ``offset + done``（子批 done 即子批条目数，与全阶段
        ``grand_total`` 同单位）后经 ``_phase_progress`` 映射到加权总进度。空子批返回
        None（下游跳过上报）；用户未提供 progress_callback 或 grand_total<=0 时工厂
        恒返回 None 适配器（下游保持原单次批量路径）。
        """

        def _make(offset: int, sub_total: int) -> Callable[[int, int], None] | None:
            user_callback = callbacks.progress_callback
            if user_callback is None or grand_total <= 0 or sub_total <= 0:
                return None

            def _report(done: int, _total: int) -> None:
                # min 钳制防 offset+done 溢出 grand_total 致阶段刻度越界。
                overall = min(offset + done, grand_total)
                user_callback(
                    _phase_progress(base, span, overall, grand_total), _IMPORT_PROGRESS_TOTAL
                )

            return _report

        return _make

    def _categories_by_folded_name(self) -> dict[str, Category]:
        """构造分类名 casefold 映射，供导入按名匹配分类（大小写不敏感）。"""
        return {c.name.casefold(): c for c in self._entry_mgr.categories.get_categories()}

    def _run_importer(
        self,
        importer: FormatImporter,
        filepath: str,
        default_category_id: int | None,
        duplicate_action: str,
        progress_callback: Callable[[int, int], None] | None,
        cancel_check: Callable[[], bool] | None,
    ) -> int:
        """统一执行格式策略：解析文件后委托 ``_import_entries`` 写入。

        import_file 入口共享此骨架，仅传入的 importer 不同，消除分类/写入编排的重复。
        文件解析在事务外完成（importer.parse），大文件 I/O 与解析不持 db_lock；epoch
        守卫与加密/写入边界由 ``_import_entries`` 内部管理（MAINT-004）。

        parse 外层统一归一解析异常（SEC-009）：JSON 损坏（json.JSONDecodeError）、
        深嵌套（RecursionError）、CSV 格式错误（csv.Error）一律转
        :class:`ImportFormatError`；UnicodeDecodeError 由上层装饰器归一为编码提示。
        """
        try:
            parsed = importer.parse(filepath)
        except (json.JSONDecodeError, RecursionError, csv.Error) as exc:
            raise ImportFormatError(f"文件解析失败，文件可能已损坏：{exc}") from exc
        # parse 完成里程碑（PERF-065）：解析阶段无行级回调（I/O 密集且通常 <1s），
        # 单点上报 5% 后进入清洗/分类/加密/写入的细粒度阶段。
        if progress_callback is not None:
            progress_callback(_PROGRESS_PARSE_DONE, _IMPORT_PROGRESS_TOTAL)
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
        return self._import_entries(parsed.entries, parsed.entries_data, ctx, callbacks)

    # ======== 导入入口 ========

    # 格式键 → 策略类注册表：新增格式只需新增策略类并在此注册，import_file 据此
    # 单一 dispatch，无需为每格式编写独立方法。chrome_csv 复用 CsvImporter
    # （Chrome/Edge 与 CipherBox CSV 共享列名格式）。
    _IMPORTERS: dict[str, type[FormatImporter]] = {
        "json": JsonImporter,
        "csv": CsvImporter,
        "chrome_csv": CsvImporter,
        "keepass_csv": KeePassCsvImporter,
        "bitwarden_json": BitwardenImporter,
    }

    @_validate_import_input
    def import_file(
        self,
        filepath: str,
        format_key: str,
        default_category_id: int | None = None,
        progress_callback: Callable[[int, int], None] | None = None,
        duplicate_action: str = "import_all",
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
            raise ImportFormatError(f"不支持的导入格式：{format_key}")
        return self._run_importer(
            importer_cls(),
            filepath,
            default_category_id,
            duplicate_action,
            progress_callback,
            cancel_check,
        )
