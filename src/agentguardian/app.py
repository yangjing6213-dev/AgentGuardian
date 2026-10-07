import json
import os
import re
import stat
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from itertools import islice
from math import ceil
from pathlib import Path

from PySide6.QtCore import (
    QDateTime,
    QObject,
    QSettings,
    Qt,
    QThread,
    QTimer,
    QTimeZone,
    Signal,
    Slot,
)
from PySide6.QtGui import QColor, QIcon, QPixmap, QResizeEvent
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox as _QCheckBox,
    QComboBox as _QComboBox,
    QDateTimeEdit,
    QDialog as _QDialog,
    QDialogButtonBox,
    QFileDialog as _QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QInputDialog as _QInputDialog,
    QLabel as _QLabel,
    QLineEdit,
    QMainWindow as _QMainWindow,
    QMessageBox as _QMessageBox,
    QPushButton as _QPushButton,
    QScrollArea,
    QStackedWidget,
    QStyle,
    QTableWidget as _QTableWidget,
    QTableWidgetItem as _QTableWidgetItem,
    QTextBrowser as _QTextBrowser,
    QVBoxLayout,
    QWidget,
)


from .audit_service import (
    AuditOutcome,
    FindingSourceContext,
    _DispositionContext,
    _generate_key,
    _is_unc_path,
    _read_limited_json,
    _utc_now,
    _validated_audit_preview,
    _validated_disposition_context,
    _validated_evaluation_time,
    run_clipboard_audit,
    run_file_audit as _run_audit,
)
from .detectors import load_rules
from .browser_audit import BrowserKind, audit_browser_database
from .share_verification import verify_public_share
from .discovery import known_config_roots
from .dispositions import (
    DispositionRecord,
    DispositionStatus,
    disposition_index,
    evaluate_disposition,
    parse_utc,
    reviewed_findings,
    upsert_disposition,
    withdraw_disposition,
)
from .domain import (
    MAX_REPORT_EVIDENCE,
    MAX_REPORT_FINDINGS,
    Finding,
    RiskDomain,
    Score,
    Severity,
    validate_safe_annotation,
)
from .evidence_state import (
    MAX_STATE_EVIDENCE,
    MAX_STATE_FINDINGS,
    EvidenceReference,
    EvidenceSnapshot,
    FindingReference,
    ScanMetadata,
    build_snapshot,
)
from .guidance import guidance_for
from .report_comparison import (
    ReportComparison,
    compare_report_summaries,
    load_report_summary,
    parse_report_summary,
)
from .reporting import render_html, render_json
from .remediation import (
    RemediationStatus,
    apply_openai_base_url_replacement,
    preview_openai_base_url_replacement,
    rollback_fixed_replacement,
)
from .scoring import score
from .state_store import (
    StateStoreError,
    load_protected_state,
    purge_protected_state,
    save_protected_state,
)
from .workflow import (
    COVERAGE_LIMIT_LABELS,
    COVERAGE_STATE_LABELS,
    CoverageState,
    FindingFilters,
    ScopeConsent,
    ScopePreview,
    bind_scope_consent,
    build_scope_preview,
    classify_coverage,
    filter_findings,
    scope_consent_matches,
)


_TRANSLATION_DATA = json.loads(
    (Path(__file__).resolve().parent / "assets" / "translations.json").read_text(
        encoding="utf-8"
    )
)
_ENGLISH = _TRANSLATION_DATA["en"]
_CHINESE = _TRANSLATION_DATA["zh"]

_DYNAMIC = (
    (
        re.compile(r"^所属应用：(.+)$"),
        lambda match: f"Application: {_translate_display_parts(match.group(1))}",
    ),
    (
        re.compile(r"^程序识别：(.+)$"),
        lambda match: f"Program identification: {translate(match.group(1), 'en')}",
    ),
    (
        re.compile(r"^来源文件：(.+)$"),
        lambda match: f"Source file: {match.group(1)}",
    ),
    (
        re.compile(r"^所在审计范围：(.+)$"),
        lambda match: f"Audit scope: {match.group(1)}",
    ),
    (
        re.compile(r"^风险域：(.+)$"),
        lambda match: f"Risk area: {translate(match.group(1), 'en')}",
    ),
    (
        re.compile(r"^规则：(.+)$"),
        lambda match: f"Rule: {match.group(1)}",
    ),
    (
        re.compile(r"^严重性：(.+)$"),
        lambda match: f"Severity: {translate(match.group(1), 'en')}",
    ),
    (
        re.compile(r"^已掩码证据：(.+)$"),
        lambda match: f"Masked evidence: {match.group(1)}",
    ),
    (
        re.compile(r"^处理位置：在 (.+)中核对 (.+)；处理后请回到原应用重新审计。$"),
        lambda match: (
            f"Where to handle: Review {match.group(2)} in "
            f"{_translate_display_parts(match.group(1))}; "
            "return to the original application and audit again after remediation."
        ),
    ),
    (
        re.compile(r"^(\d+) 个本地根目录$"),
        lambda match: f"{match.group(1)} local root folders",
    ),
    (
        re.compile(r"^范围：(\d+) 个根目录（(.*)）$"),
        lambda match: f"Scope: {match.group(1)} root folder(s) ({match.group(2)})",
    ),
    (
        re.compile(r"^显示 (\d+) / 共 (\d+) 项发现$"),
        lambda match: f"Showing {match.group(1)} of {match.group(2)} findings",
    ),
    (
        re.compile(r"^发现 (\d+) 项风险$"),
        lambda match: f"Found {match.group(1)} finding(s)",
    ),
    (
        re.compile(r"^审计完成：发现 (\d+) 项风险。$"),
        lambda match: f"Audit complete: {match.group(1)} finding(s) found.",
    ),
    (
        re.compile(r"^审计未完整：(.+)，覆盖率 (\d+%)；不能判定为安全。$"),
        lambda match: f"Audit incomplete: {translate(match.group(1), 'en')}, {match.group(2)} coverage; this does not establish safety.",
    ),
    (
        re.compile(r"^审计完成：未发现风险。$"),
        lambda _match: "Audit complete: no findings.",
    ),
    (
        re.compile(r"^支持后缀：(.+)；支持精确文件名：(.+)$"),
        lambda match: f"Supported extensions: {match.group(1)}; exact file names: {match.group(2)}",
    ),
    (
        re.compile(r"^上限：文件 ([0-9,]+)；目录条目 ([0-9,]+)；读取 ([0-9,]+) 字节；风险发现 ([0-9,]+)；证据 ([0-9,]+)$"),
        lambda match: f"Limits: {match.group(1)} files; {match.group(2)} directory entries; {match.group(3)} bytes read; {match.group(4)} findings; {match.group(5)} evidence items",
    ),
    (
        re.compile(r"^规则版本：(.+)$"),
        lambda match: f"Rule version: {match.group(1)}",
    ),
    (
        re.compile(r"^已添加 (\d+) 个已知本地 AI 配置目录；请核对范围并明确同意后开始审计。$"),
        lambda match: f"Added {match.group(1)} known local AI configuration folder(s); review the scope and give explicit consent before auditing.",
    ),
    (
        re.compile(r"^浏览器元数据审计完成：历史 (\d+)，访问记录 (\d+)。$"),
        lambda match: f"Browser metadata audit complete: {match.group(1)} history entries, {match.group(2)} visit records.",
    ),
    (
        re.compile(r"^剪贴板一次性审计完成：发现 (\d+) 项。$"),
        lambda match: f"One-time clipboard audit complete: {match.group(1)} finding(s).",
    ),
    (
        re.compile(r"^联网分享验证完成：(.+)，HTTP (\d+)，读取 ([0-9,]+) 字节。$"),
        lambda match: f"Public-link check complete: {match.group(1)}, HTTP {match.group(2)}, {match.group(3)} bytes read.",
    ),
    (
        re.compile(r"^覆盖状态：(已完成|覆盖受限|无支持文件)；覆盖率 (\d+%)(?:；原因：(.+?))?；(.+)$"),
        lambda match: _coverage_status(match),
    ),
    (
        re.compile(r"^固定修复已应用：(.*)；请重新审计。$"),
        lambda match: f"Fixed repair was applied: {match.group(1)}; run the audit again.",
    ),
    (
        re.compile(r"^基线：(.*)$"),
        lambda match: f"Baseline: {match.group(1)}",
    ),
    (
        re.compile(r"^固定修复未执行：(.+)。$"),
        lambda match: f"Fixed repair was not applied: {match.group(1)}.",
    ),
    (
        re.compile(r"^固定修复已回滚：(.*)。$"),
        lambda match: f"Fixed repair was undone: {match.group(1)}.",
    ),
    (
        re.compile(r"^固定修复未回滚：(.*)。$"),
        lambda match: f"Fixed repair was not undone: {match.group(1)}.",
    ),
    (
        re.compile(r"^固定修复已应用：(.*)$"),
        lambda match: f"Fixed repair was applied: {match.group(1)}",
    ),
    (
        re.compile(r"^固定修复已回滚：(.*)$"),
        lambda match: f"Fixed repair was undone: {match.group(1)}",
    ),
    (
        re.compile(r"^固定修复未回滚：(.*)$"),
        lambda match: f"Fixed repair was not undone: {match.group(1)}",
    ),
    (
        re.compile(r"^(技术分|审阅分)：基线 (\d+) \| 当前 (\d+) \| 差值 ([+-]\d+)$"),
        lambda match: f"{translate(match.group(1), 'en')}: baseline {match.group(2)} | current {match.group(3)} | delta {match.group(4)}",
    ),
    (
        re.compile(r"^覆盖率：基线 ([0-9.]+%) \| 当前 ([0-9.]+%) \| 差值 ([+-][0-9.]+%)$"),
        lambda match: f"Coverage: baseline {match.group(1)} | current {match.group(2)} | delta {match.group(3)}",
    ),
    (
        re.compile(r"^覆盖状态：基线 (.+) \| 当前 (.+)$"),
        lambda match: f"Coverage: baseline {translate(match.group(1), 'en')} | current {translate(match.group(2), 'en')}",
    ),
    (
        re.compile(r"^发现数：基线 (\d+) \| 当前 (\d+) \| 差值 ([+-]\d+)$"),
        lambda match: f"Finding count: baseline {match.group(1)} | current {match.group(2)} | delta {match.group(3)}",
    ),
    (
        re.compile(r"^(.+): 基线 (\d+) \| 当前 (\d+) \| 差值 ([+-]\d+)$"),
        lambda match: f"{translate(match.group(1), 'en')}: baseline {match.group(2)} | current {match.group(3)} | delta {match.group(4)}",
    ),
    (
        re.compile(r"^新增限制：(.*)$"),
        lambda match: "New limits: " + ", ".join(
            translate(limit, "en") for limit in match.group(1).split("、")
        ),
    ),
    (
        re.compile(r"^已解除限制：(.*)$"),
        lambda match: "Resolved limits: " + ", ".join(
            translate(limit, "en") for limit in match.group(1).split("、")
        ),
    ),
)


def _coverage_status(match: re.Match[str]) -> str:
    state = translate(match.group(1), "en")
    reasons = match.group(3)
    reason_text = "" if reasons is None else "; reasons: " + ", ".join(
        translate(reason, "en") for reason in reasons.split("、")
    )
    ending = translate(match.group(4), "en")
    return f"Coverage: {state}; {match.group(2)}{reason_text}; {ending}"


def _translate_display_parts(value: str) -> str:
    return " / ".join(translate(part.strip(), "en") for part in value.split("、"))


def _translate_english_line(text: str) -> str:
    translated = _ENGLISH.get(text)
    if translated is not None:
        return translated
    for pattern, render in _DYNAMIC:
        match = pattern.fullmatch(text)
        if match is not None:
            return render(match)
    return text


def translate(text: str, language: str = "zh") -> str:
    if not isinstance(text, str):
        return text
    if language != "en":
        if language != "zh":
            return text
        if text in _CHINESE:
            return _CHINESE[text]
        lines = text.splitlines()
        if len(lines) > 1 or any(line in _CHINESE for line in lines):
            translated_lines = []
            for line in lines:
                if not line:
                    translated_lines.append("")
                    continue
                numbered = re.fullmatch(r"(\d+\. )(.*)", line)
                if numbered is None:
                    translated_lines.append(_CHINESE.get(line, line))
                else:
                    translated_lines.append(
                        numbered.group(1)
                        + _CHINESE.get(numbered.group(2), numbered.group(2))
                    )
            return "\n".join(translated_lines)
        return text
    translated = _ENGLISH.get(text)
    if translated is not None:
        return translated
    lines = text.splitlines()
    if len(lines) > 1 or any(pattern.fullmatch(text) for pattern, _ in _DYNAMIC):
        translated_lines = []
        for line in lines:
            if not line:
                translated_lines.append("")
                continue
            numbered = re.fullmatch(r"(\d+\. )(.*)", line)
            if numbered is None:
                translated_lines.append(_translate_english_line(line))
            else:
                translated_lines.append(
                    numbered.group(1) + _translate_english_line(numbered.group(2))
                )
        return "\n".join(translated_lines)
    return _translate_english_line(text)


_translate = translate

_CURRENT_LANGUAGE = "zh"


class _LocalizedTextMixin:
    def __init__(self, *args, **kwargs):
        source_text = args[0] if args and isinstance(args[0], str) else None
        if source_text is None and isinstance(kwargs.get("text"), str):
            source_text = kwargs["text"]
            kwargs["text"] = _translate(source_text, _CURRENT_LANGUAGE)
        elif source_text is not None:
            args = (_translate(source_text, _CURRENT_LANGUAGE), *args[1:])
        super().__init__(*args, **kwargs)
        self._localized_source_text = source_text
        self._localized_source_tooltip = None
        self._localized_source_accessible_description = None

    def setText(self, text):
        self._localized_source_text = text if isinstance(text, str) else None
        super().setText(
            _translate(text, _CURRENT_LANGUAGE)
            if self._localized_source_text is not None
            else text
        )

    def setToolTip(self, text):
        self._localized_source_tooltip = text if isinstance(text, str) else None
        super().setToolTip(
            _translate(text, _CURRENT_LANGUAGE)
            if self._localized_source_tooltip is not None
            else text
        )

    def setAccessibleDescription(self, text):
        self._localized_source_accessible_description = (
            text if isinstance(text, str) else None
        )
        super().setAccessibleDescription(
            _translate(text, _CURRENT_LANGUAGE)
            if self._localized_source_accessible_description is not None
            else text
        )

    def retranslate(self):
        if self._localized_source_text is not None:
            self.setText(self._localized_source_text)
        if self._localized_source_tooltip is not None:
            self.setToolTip(self._localized_source_tooltip)
        if self._localized_source_accessible_description is not None:
            self.setAccessibleDescription(
                self._localized_source_accessible_description
            )

    def setUntranslatedText(self, text: str) -> None:
        self._localized_source_text = None
        super().setText(text)


class QLabel(_LocalizedTextMixin, _QLabel):
    pass


class QPushButton(_LocalizedTextMixin, _QPushButton):
    pass


class QCheckBox(_LocalizedTextMixin, _QCheckBox):
    pass


class QDialog(_LocalizedTextMixin, _QDialog):
    def setWindowTitle(self, title):
        self._localized_source_title = title
        super().setWindowTitle(_translate(title, _CURRENT_LANGUAGE))

    def retranslate(self):
        super().retranslate()
        title = getattr(self, "_localized_source_title", None)
        if title is not None:
            self.setWindowTitle(title)


class QComboBox(_QComboBox):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._localized_items: list[str | None] = []

    def addItem(self, *args, **kwargs):
        if args and isinstance(args[0], str):
            source = args[0]
            super().addItem(_translate(source, _CURRENT_LANGUAGE), *args[1:], **kwargs)
            self._localized_items.append(source)
            return
        super().addItem(*args, **kwargs)
        self._localized_items.append(None)

    def addItems(self, texts):
        for text in texts:
            self.addItem(text)

    def insertItem(self, index, *args, **kwargs):
        if args and isinstance(args[0], str):
            source = args[0]
            super().insertItem(
                index, _translate(source, _CURRENT_LANGUAGE), *args[1:], **kwargs
            )
            self._localized_items.insert(index, source)
            return
        super().insertItem(index, *args, **kwargs)
        self._localized_items.insert(index, None)

    def setItemText(self, index, text):
        super().setItemText(index, _translate(text, _CURRENT_LANGUAGE))
        if 0 <= index < len(self._localized_items):
            self._localized_items[index] = text

    def clear(self):
        super().clear()
        self._localized_items.clear()

    def retranslate(self):
        for index, source in enumerate(self._localized_items):
            if source is not None and index < self.count():
                _QComboBox.setItemText(
                    self, index, _translate(source, _CURRENT_LANGUAGE)
                )


class QTableWidget(_QTableWidget):
    def setHorizontalHeaderLabels(self, labels):
        self._localized_header_labels = tuple(labels)
        super().setHorizontalHeaderLabels(
            [_translate(label, _CURRENT_LANGUAGE) for label in labels]
        )

    def retranslate(self):
        labels = getattr(self, "_localized_header_labels", None)
        if labels is not None:
            self.setHorizontalHeaderLabels(labels)


QTableWidgetItem = _QTableWidgetItem


class QTextBrowser(_LocalizedTextMixin, _QTextBrowser):
    def setPlainText(self, text):
        self._localized_source_plain_text = text
        super().setPlainText(_translate(text, _CURRENT_LANGUAGE))

    def setHtml(self, text):
        self._localized_source_html = text
        super().setHtml(_translate(text, _CURRENT_LANGUAGE))

    def retranslate(self):
        super().retranslate()
        if hasattr(self, "_localized_source_plain_text"):
            self.setPlainText(self._localized_source_plain_text)
        if hasattr(self, "_localized_source_html"):
            self.setHtml(self._localized_source_html)


class QFileDialog(_QFileDialog):
    @staticmethod
    def _call(name, *args, **kwargs):
        localized_args = list(args)
        if len(localized_args) > 1 and isinstance(localized_args[1], str):
            localized_args[1] = _translate(localized_args[1], _CURRENT_LANGUAGE)
        return getattr(_QFileDialog, name)(*localized_args, **kwargs)

    getExistingDirectory = staticmethod(
        lambda *args, **kwargs: QFileDialog._call(
            "getExistingDirectory", *args, **kwargs
        )
    )
    getOpenFileName = staticmethod(
        lambda *args, **kwargs: QFileDialog._call(
            "getOpenFileName", *args, **kwargs
        )
    )
    getSaveFileName = staticmethod(
        lambda *args, **kwargs: QFileDialog._call(
            "getSaveFileName", *args, **kwargs
        )
    )


class QMessageBox(_QMessageBox):
    @staticmethod
    def _call(name, *args, **kwargs):
        localized_args = list(args)
        for index in (1, 2):
            if len(localized_args) > index and isinstance(localized_args[index], str):
                localized_args[index] = _translate(
                    localized_args[index], _CURRENT_LANGUAGE
                )
        return getattr(_QMessageBox, name)(*localized_args, **kwargs)

    information = staticmethod(
        lambda *args, **kwargs: QMessageBox._call(
            "information", *args, **kwargs
        )
    )
    question = staticmethod(
        lambda *args, **kwargs: QMessageBox._call("question", *args, **kwargs)
    )
    warning = staticmethod(
        lambda *args, **kwargs: QMessageBox._call("warning", *args, **kwargs)
    )


class QInputDialog(_QInputDialog):
    @staticmethod
    def getText(*args, **kwargs):
        localized_args = list(args)
        for index in (1, 2):
            if len(localized_args) > index and isinstance(localized_args[index], str):
                localized_args[index] = _translate(
                    localized_args[index], _CURRENT_LANGUAGE
                )
        return _QInputDialog.getText(*localized_args, **kwargs)

COLOR_TOKENS = {
    "obsidian": "#0B1220",
    "surface": "#121D2E",
    "border": "#2B3B52",
    "cloud": "#F3F6FB",
    "trust": "#29C994",
    "muted": "#A7B4C6",
    "warning": "#F3BE59",
    "critical": "#F17373",
}
SUPPORTED_SUFFIXES = (
    ".env",
    ".json",
    ".log",
    ".md",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
)
MAX_AUDIT_FINDINGS = MAX_REPORT_FINDINGS
MAX_AUDIT_EVIDENCE = MAX_REPORT_EVIDENCE
MAX_AUDIT_FILES = 10_000
MAX_AUDIT_ENTRIES = 50_000
MAX_AUDIT_BYTES = 512 * 1024 * 1024
_FIXED_REMEDIATION_RULES = frozenset({"OPENAI_BASE_URL_OVERRIDE"})
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
_CONTEXT_ERROR = "invalid disposition context"
_SAVE_FAILURE_TITLE = "保存失败"
_SAVE_FAILURE_MESSAGE = "无法保存加密状态。"
_EXPIRY_TIMER_CAP_MS = 86_400_000
_EXPIRY_RETRY_MS = 60_000
_STATUS_REFRESH_FALLBACK = "状态待刷新"
_REPORT_REFRESH_FALLBACK = "报告已更新，界面暂时无法刷新。"
_SAVED_REFRESH_FAILURE = "处置已保存，界面刷新受限。"
_TIMER_REFRESH_FAILURE = "处置状态刷新受限，请复核当前界面状态。"


def _language_preferences_path() -> Path:
    root = os.environ.get("LOCALAPPDATA")
    if root:
        return Path(root) / "AgentGuardian" / "ui-preferences.ini"
    return Path.home() / ".config" / "AgentGuardian" / "ui-preferences.ini"


def _load_language_preference() -> str:
    settings = QSettings(str(_language_preferences_path()), QSettings.Format.IniFormat)
    settings.setFallbacksEnabled(False)
    value = settings.value("interface/language", "zh")
    return value if value in {"zh", "en"} else "zh"


def _save_language_preference(language: str) -> None:
    path = _language_preferences_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    settings = QSettings(str(path), QSettings.Format.IniFormat)
    settings.setFallbacksEnabled(False)
    settings.setValue("interface/language", language)
    settings.sync()


_STATUS_LABELS = {
    "open": "待处理",
    "false_positive": "误报",
    "accepted_risk": "已接受风险",
    "expired": "已过期",
}
_SEVERITY_FILTER_LABELS = {
    Severity.CRITICAL: "严重",
    Severity.HIGH: "高",
    Severity.MEDIUM: "中",
    Severity.LOW: "低",
}
_DOMAIN_FILTER_LABELS = {
    RiskDomain.EXPOSURE: "暴露",
    RiskDomain.PRIVACY: "隐私",
    RiskDomain.CREDENTIALS: "凭据",
    RiskDomain.PERMISSIONS: "权限",
    RiskDomain.RETENTION: "保留",
    RiskDomain.SUPPLY_CHAIN: "供应链",
}
_SOURCE_APPLICATION_LABELS = {
    "codex": "Codex 配置",
    "claude": "Claude 配置",
    "cursor": "Cursor 配置",
    "windsurf": "Windsurf 配置",
    "openai": "OpenAI 配置",
    "custom": "自选目录（无法确认具体应用）",
    "clipboard": "一次性剪贴板输入",
}
_FILTER_EMPTY_MESSAGE = "当前筛选条件下无匹配风险发现。"
_FILTER_ERROR_MESSAGE = "无法筛选风险发现，请重试。"
_FINDING_SELECTION_MESSAGE = "选择一项风险以查看人工步骤。"
_COMPARISON_ERROR_TITLE = "基线报告错误"
_COMPARISON_ERROR_MESSAGE = "无法读取基线报告。"
_COMPARISON_EMPTY_MESSAGE = "尚未选择基线报告。"


class _FindingFilterCallbackError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class _ComparisonState:
    baseline_name: str
    comparison: ReportComparison


def _canonical_utc_seconds(value: datetime) -> str:
    normalized = _validated_evaluation_time(value).replace(microsecond=0)
    return normalized.strftime("%Y-%m-%dT%H:%M:%SZ")


def _audit_status_text(outcome: AuditOutcome) -> str:
    if outcome.score.incomplete:
        coverage = f"{outcome.score.coverage:.0%}"
        finding_summary = (
            f"发现 {len(outcome.findings)} 项风险" if outcome.findings else "未发现风险"
        )
        return f"审计未完整：{finding_summary}，覆盖率 {coverage}；不能判定为安全。"
    if outcome.findings:
        return f"审计完成：发现 {len(outcome.findings)} 项风险。"
    return "审计完成：未发现风险。"


def _scope_preview_for(roots: tuple[Path, ...]) -> ScopePreview:
    return build_scope_preview(
        roots,
        SUPPORTED_SUFFIXES,
        max_files=MAX_AUDIT_FILES,
        max_entries=MAX_AUDIT_ENTRIES,
        max_bytes=MAX_AUDIT_BYTES,
        max_findings=MAX_AUDIT_FINDINGS,
        max_evidence=MAX_AUDIT_EVIDENCE,
    )


def _dedupe_scope_roots(roots: Iterable[Path]) -> tuple[Path, ...]:
    unique: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        path = Path(root)
        key = os.path.normcase(os.path.abspath(path))
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return tuple(unique)


def _coverage_status_text(audit_score: Score) -> str:
    state = classify_coverage(audit_score)
    parts = [
        f"覆盖状态：{COVERAGE_STATE_LABELS[state]}",
        f"覆盖率 {audit_score.coverage:.0%}",
    ]
    if audit_score.limits:
        reasons = "、".join(
            COVERAGE_LIMIT_LABELS[limit] for limit in audit_score.limits
        )
        parts.append(f"原因：{reasons}")
    if state is CoverageState.COMPLETE:
        parts.append("已完成配置范围扫描。")
    else:
        parts.append("本次结果不能证明系统、账户、提供商或端点安全。")
    return "；".join(parts)


def _comparison_text(comparison: ReportComparison, language: str = "zh") -> str:
    def category_lines(
        title: str,
        baseline_values: tuple[tuple[str, int], ...],
        current_values: tuple[tuple[str, int], ...],
        deltas: tuple[tuple[str, int], ...],
        labels: dict[str, str] | None = None,
    ) -> list[str]:
        baseline_counts = dict(baseline_values)
        current_counts = dict(current_values)
        lines = [title]
        lines.extend(
            (
                f"{labels.get(name, name) if labels else name}: "
                f"基线 {baseline_counts.get(name, 0)} | "
                f"当前 {current_counts.get(name, 0)} | 差值 {delta:+d}"
            )
            for name, delta in deltas
        )
        if len(lines) == 1:
            lines.append("无")
        return lines

    baseline = comparison.baseline
    current = comparison.current
    severity_labels = {
        severity.value: _SEVERITY_FILTER_LABELS[severity] for severity in Severity
    }
    added_limits = "、".join(
        COVERAGE_LIMIT_LABELS[limit] for limit in comparison.added_limits
    ) or "无"
    resolved_limits = "、".join(
        COVERAGE_LIMIT_LABELS[limit] for limit in comparison.resolved_limits
    ) or "无"
    lines = [
        "差值（当前 - 基线）",
        (
            f"技术分：基线 {baseline.technical_score} | "
            f"当前 {current.technical_score} | "
            f"差值 {comparison.technical_score_delta:+d}"
        ),
        (
            f"审阅分：基线 {baseline.reviewed_score} | "
            f"当前 {current.reviewed_score} | "
            f"差值 {comparison.reviewed_score_delta:+d}"
        ),
        (
            f"覆盖率：基线 {baseline.coverage:.1%} | "
            f"当前 {current.coverage:.1%} | "
            f"差值 {comparison.coverage_delta:+.1%}"
        ),
        (
            f"覆盖状态：基线 {COVERAGE_STATE_LABELS[baseline.coverage_state]} | "
            f"当前 {COVERAGE_STATE_LABELS[current.coverage_state]}"
        ),
        (
            f"发现数：基线 {baseline.finding_count} | "
            f"当前 {current.finding_count} | "
            f"差值 {comparison.finding_count_delta:+d}"
        ),
        *category_lines(
            "规则数量差值",
            baseline.rule_counts,
            current.rule_counts,
            comparison.rule_count_deltas,
        ),
        *category_lines(
            "严重性数量差值",
            baseline.severity_counts,
            current.severity_counts,
            comparison.severity_count_deltas,
            severity_labels,
        ),
        *category_lines(
            "处置状态数量差值",
            baseline.disposition_counts,
            current.disposition_counts,
            comparison.disposition_count_deltas,
            _STATUS_LABELS,
        ),
        f"新增限制：{added_limits}",
        f"已解除限制：{resolved_limits}",
    ]
    if not comparison.baseline.supported_use_boundary_verified:
        lines.insert(1, "历史基线未声明 Personal 边界；仅比较聚合数据。")
    return "\n".join(_translate(line, language) for line in lines)


class _DispositionDialog(QDialog):
    def __init__(
        self,
        parent: QWidget | None,
        status: DispositionStatus,
        now: datetime,
        *,
        time_zone: QTimeZone | None = None,
    ) -> None:
        super().__init__(parent)
        self._now = _validated_evaluation_time(now)
        zone = QTimeZone.systemTimeZone() if time_zone is None else QTimeZone(time_zone)
        if not zone.isValid():
            raise ValueError("DISPOSITION_INVALID")
        self.setWindowTitle("风险发现处置")
        self.setModal(True)
        self.setMinimumWidth(420)

        layout = QFormLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(10)
        self.status_combo = QComboBox()
        self.status_combo.addItem(
            "误报", DispositionStatus.FALSE_POSITIVE.value
        )
        self.status_combo.addItem(
            "接受风险", DispositionStatus.ACCEPTED_RISK.value
        )
        self.status_combo.setCurrentIndex(
            0 if status is DispositionStatus.FALSE_POSITIVE else 1
        )
        self.reason_edit = QLineEdit()
        self.reason_edit.setMaxLength(240)
        self.reviewer_edit = QLineEdit()
        self.reviewer_edit.setMaxLength(80)
        self.expiry_edit = QDateTimeEdit()
        self.expiry_edit.setCalendarPopup(True)
        self.expiry_edit.setDisplayFormat("yyyy-MM-dd HH:mm:ss t")
        self.expiry_edit.setTimeZone(zone)
        opened_at = QDateTime.fromMSecsSinceEpoch(
            int(self._now.timestamp() * 1000),
            zone,
        )
        self.expiry_edit.setDateTime(opened_at.addDays(30))
        layout.addRow("状态", self.status_combo)
        layout.addRow("原因", self.reason_edit)
        layout.addRow("复核人", self.reviewer_edit)
        layout.addRow("本地到期时间", self.expiry_edit)

        self.button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
        )
        self.button_box.button(QDialogButtonBox.StandardButton.Ok).setText(
            _translate("确定", _CURRENT_LANGUAGE)
        )
        self.button_box.button(QDialogButtonBox.StandardButton.Cancel).setText(
            _translate("取消", _CURRENT_LANGUAGE)
        )
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        layout.addRow(self.button_box)
        self.reason_edit.textChanged.connect(self._update_validity)
        self.reviewer_edit.textChanged.connect(self._update_validity)
        self.status_combo.currentIndexChanged.connect(self._update_validity)
        self.expiry_edit.dateTimeChanged.connect(self._update_validity)
        self._update_validity()

    def values(self) -> tuple[DispositionStatus, str, str, str]:
        status = DispositionStatus(self.status_combo.currentData())
        reason = validate_safe_annotation("reason", self.reason_edit.text(), 240)
        reviewer = validate_safe_annotation(
            "reviewer", self.reviewer_edit.text(), 80
        )
        expiry = self.expiry_edit.dateTime().toUTC().toPython()
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        expiry = _validated_evaluation_time(expiry)
        if not self._now < expiry or expiry - self._now > timedelta(days=366):
            raise ValueError("DISPOSITION_INVALID")
        return status, reason, reviewer, _canonical_utc_seconds(expiry)

    def _update_validity(self, *_args: object) -> None:
        try:
            self.values()
            valid = True
        except Exception:  # noqa: BLE001 - validation must keep the dialog inert
            valid = False
        self.button_box.button(QDialogButtonBox.StandardButton.Ok).setEnabled(valid)


def _deeply_revalidated_snapshot(snapshot: object) -> EvidenceSnapshot:
    try:
        if type(snapshot) is not EvidenceSnapshot:
            raise ValueError
        schema_version = snapshot.schema_version
        captured_at = snapshot.captured_at
        product_version = snapshot.product_version
        rule_version = snapshot.rule_version
        scan = snapshot.scan
        findings_source = snapshot.findings
        disposition_key = snapshot.disposition_key
        dispositions = snapshot.dispositions
        if type(scan) is not ScanMetadata:
            raise ValueError
        scan_fields = (
            scan.coverage,
            scan.confidence,
            scan.incomplete,
            scan.limits,
        )
        findings = tuple(islice(findings_source, MAX_STATE_FINDINGS + 1))
        if len(findings) > MAX_STATE_FINDINGS:
            raise ValueError
        captured_findings = []
        evidence_count = 0
        for finding in findings:
            if type(finding) is not FindingReference:
                raise ValueError
            rule_id = finding.rule_id
            root_fingerprint = finding.root_hmac_fingerprint
            remaining = MAX_STATE_EVIDENCE - evidence_count
            evidence = tuple(islice(finding.evidence, remaining + 1))
            if len(evidence) > remaining:
                raise ValueError
            evidence_fields = []
            for item in evidence:
                if type(item) is not EvidenceReference:
                    raise ValueError
                evidence_fields.append((item.hmac_fingerprint, item.masked))
            evidence_count += len(evidence_fields)
            captured_findings.append(
                (rule_id, root_fingerprint, tuple(evidence_fields))
            )
        rebuilt_finding_fields = []
        for rule_id, root_fingerprint, evidence_fields in captured_findings:
            rebuilt_finding_fields.append(
                (
                    rule_id,
                    root_fingerprint,
                    tuple(
                        EvidenceReference(*fields) for fields in evidence_fields
                    ),
                )
            )
        rebuilt_findings = tuple(
            FindingReference(*fields) for fields in rebuilt_finding_fields
        )
        rebuilt_scan = ScanMetadata(*scan_fields)
        return EvidenceSnapshot(
            schema_version=schema_version,
            captured_at=captured_at,
            product_version=product_version,
            rule_version=rule_version,
            scan=rebuilt_scan,
            findings=rebuilt_findings,
            disposition_key=disposition_key,
            dispositions=dispositions,
        )
    except Exception:
        pass
    raise ValueError(_CONTEXT_ERROR) from None


def _load_disposition_context() -> _DispositionContext:
    try:
        snapshot = load_protected_state()
    except StateStoreError as error:
        invalid_state = error.args != ("PROTECTED_STATE_UNAVAILABLE",)
    except Exception:  # noqa: BLE001 - protected state must fail closed
        invalid_state = True
    else:
        try:
            snapshot = _deeply_revalidated_snapshot(snapshot)
            schema_version = snapshot.schema_version
            if type(schema_version) is not int:
                raise ValueError
            if schema_version == 2:
                return _validated_disposition_context(
                    snapshot.disposition_key,
                    snapshot.dispositions,
                )
            invalid_state = schema_version != 1
        except Exception:
            invalid_state = True
    return _DispositionContext(_generate_key(), (), invalid_state)


def export_new_report(
    path: str | Path,
    content: str,
    scanned_roots: Iterable[str | Path],
) -> None:
    """Create a report assuming a stable destination directory during open.

    Founder Alpha does not provide a handle sandbox against an active local
    reparse replacement race between the final resolution and exclusive open.
    """
    roots = tuple(scanned_roots)
    if _is_unc_path(path) or any(_is_unc_path(root) for root in roots):
        raise ValueError("UNC paths are not allowed")
    target = Path(path)
    if _is_reparse(target):
        raise ValueError("report destination is a reparse point")
    if not target.parent.is_dir():
        raise FileNotFoundError("parent directory does not exist")
    resolved_roots = tuple(Path(root).resolve(strict=False) for root in roots)
    resolved_parent = target.parent.resolve(strict=True)
    resolved_target = target.resolve(strict=False)
    if resolved_target.parent != resolved_parent:
        raise ValueError("report destination parent changed")
    for resolved_root in resolved_roots:
        if resolved_target == resolved_root or resolved_target.is_relative_to(
            resolved_root
        ):
            raise ValueError("report destination is inside a scanned root")

    if _is_reparse(target):
        raise ValueError("report destination is a reparse point")
    if not target.parent.is_dir():
        raise FileNotFoundError("parent directory does not exist")
    final_parent = target.parent.resolve(strict=True)
    final_target = target.resolve(strict=False)
    if final_parent != resolved_parent or final_target != resolved_target:
        raise OSError("report destination changed")
    if final_target.parent != final_parent:
        raise ValueError("report destination parent changed")
    for resolved_root in resolved_roots:
        if final_target == resolved_root or final_target.is_relative_to(resolved_root):
            raise ValueError("report destination is inside a scanned root")
    with open(final_target, "x", encoding="utf-8", newline="\n") as stream:
        stream.write(content)


def _is_reparse(path: Path) -> bool:
    try:
        path_stat = os.lstat(path)
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(path_stat.st_mode) or bool(
        getattr(path_stat, "st_file_attributes", 0) & _REPARSE_POINT
    )


class AuditWorker(QObject):
    completed = Signal(object)
    failed = Signal(str)

    def __init__(
        self,
        roots: tuple[Path, ...],
        scope_preview: ScopePreview,
        disposition_key: bytes,
        dispositions: Iterable[DispositionRecord],
    ) -> None:
        super().__init__()
        self._roots = tuple(roots)
        self._scope_preview = _validated_audit_preview(
            self._roots,
            scope_preview,
        )
        self._disposition_key = disposition_key
        self._dispositions = tuple(dispositions)

    @Slot()
    def run(self) -> None:
        try:
            self.completed.emit(
                _run_audit(
                    self._roots,
                    scope_preview=self._scope_preview,
                    disposition_key=self._disposition_key,
                    dispositions=self._dispositions,
                )
            )
        except Exception:  # noqa: BLE001 - fixed worker failure boundary
            self.failed.emit("scan_failed")


class AgentGuardianWindow(_QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        global _CURRENT_LANGUAGE
        self._language = _load_language_preference()
        _CURRENT_LANGUAGE = self._language
        disposition_context = _load_disposition_context()
        self.setWindowTitle(_translate("AgentGuardian", self._language))
        icon_path = Path(__file__).parent / "assets" / "agentguardian.ico"
        if icon_path.is_file():
            self.setWindowIcon(QIcon(str(icon_path)))
        self.setMinimumSize(960, 640)
        self._roots: tuple[Path, ...] = ()
        self._report_roots: tuple[Path, ...] = ()
        self._thread: QThread | None = None
        self._worker: AuditWorker | None = None
        self._row_findings: list[Finding] = []
        self._audit_outcome: AuditOutcome | None = None
        self._scope_preview: ScopePreview | None = None
        self._scope_consent: ScopeConsent | None = None
        self._disposition_key = disposition_context.key
        self._dispositions = disposition_context.records
        self._protected_state_invalid = disposition_context.invalid_state
        self.is_scanning = False
        self.report_json = ""
        self.report_html = ""
        self._comparison_state: _ComparisonState | None = None
        self._refresh_failure_notified = False
        self._last_remediation: tuple[Path, str] | None = None
        self._expiry_timer = QTimer(self)
        self._expiry_timer.setSingleShot(True)
        self._expiry_timer.timeout.connect(self._handle_expiry_timeout)
        self._build_ui()
        self.setStyleSheet(_stylesheet())

    def _language_changed(self, index: int) -> None:
        language = self.language_combo.itemData(index)
        if language not in {"zh", "en"} or language == self._language:
            return
        global _CURRENT_LANGUAGE
        self._language = language
        _CURRENT_LANGUAGE = language
        _save_language_preference(language)
        self.setWindowTitle(_translate("AgentGuardian", language))
        for widget in self.findChildren(QWidget):
            retranslate = getattr(widget, "retranslate", None)
            if callable(retranslate):
                retranslate()
        if self._audit_outcome is not None:
            selected = self._current_row_finding()
            try:
                self._refresh_finding_view(
                    self._audit_outcome.evaluated_at,
                    selected_finding=selected,
                )
            except Exception:
                self._show_filter_failure()
        if self._audit_outcome is not None:
            self.report_html = self._localized_report_html(self._audit_outcome)
        if self._comparison_state is not None:
            self._render_baseline_name(self._comparison_state.baseline_name)
            self._render_comparison(self._comparison_state)
        self._refresh_report()

    def _localized_report_html(self, outcome: AuditOutcome) -> str:
        return render_html(
            outcome.score,
            outcome.findings,
            rule_version=outcome.rule_version,
            reviewed_score=outcome.reviewed_score,
            dispositions=self._dispositions,
            evaluated_at=outcome.evaluated_at,
            language=self._language,
        )

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        if self._comparison_state is not None and hasattr(
            self, "baseline_name_label"
        ):
            try:
                self._render_baseline_name(self._comparison_state.baseline_name)
            except Exception:
                pass

    def _build_ui(self) -> None:
        central = QWidget()
        central.setObjectName("mainContent")
        shell = QHBoxLayout(central)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)
        self.setCentralWidget(central)

        self.sidebar = QFrame()
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setFixedWidth(188)
        sidebar_layout = QVBoxLayout(self.sidebar)
        sidebar_layout.setContentsMargins(12, 14, 12, 14)
        sidebar_layout.setSpacing(6)
        brand = QLabel("AG  AgentGuardian")
        brand.setObjectName("brand")
        sidebar_layout.addWidget(brand)

        self.navigation_buttons: list[QPushButton] = []
        for index, text in enumerate(
            ("审计范围", "风险发现", "审计报告", "解决方案", "关于作者")
        ):
            button = QPushButton(text)
            button.setObjectName("navigation")
            button.setCheckable(True)
            button.setMinimumHeight(36)
            button.clicked.connect(
                lambda checked=False, page=index: self._switch_view(page)
            )
            sidebar_layout.addWidget(button)
            self.navigation_buttons.append(button)
        sidebar_layout.addStretch()
        self.language_label = QLabel("界面语言")
        self.language_label.setObjectName("languageLabel")
        sidebar_layout.addWidget(self.language_label)
        self.language_combo = QComboBox()
        self.language_combo.setObjectName("languageSelector")
        self.language_combo.addItem("简体中文", "zh")
        self.language_combo.addItem("English", "en")
        self.language_combo.setCurrentIndex(
            max(0, self.language_combo.findData(self._language))
        )
        self.language_combo.currentIndexChanged.connect(self._language_changed)
        sidebar_layout.addWidget(self.language_combo)
        shell.addWidget(self.sidebar)

        self.content_panel = QFrame()
        content_layout = QVBoxLayout(self.content_panel)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)
        shell.addWidget(self.content_panel, 1)

        self.trust_strip = QFrame()
        self.trust_strip.setObjectName("trustStrip")
        self.trust_strip.setFixedHeight(42)
        trust_layout = QHBoxLayout(self.trust_strip)
        trust_layout.setContentsMargins(20, 0, 20, 0)
        trust_layout.setSpacing(18)
        self.local_mode_label = QLabel("本地路径模式")
        self.local_mode_label.setObjectName("localMode")
        self.local_mode_label.setToolTip(
            "拒绝 UNC 路径；映射网络盘无法可靠识别，仍属残余风险。"
        )
        network_scope_label = QLabel("包源码网络能力：未发现")
        network_scope_label.setToolTip("仅静态扫描包源码；不证明依赖或二进制无网络能力。")
        rule_version = load_rules().version
        self.trust_labels = [
            self.local_mode_label,
            network_scope_label,
            QLabel(f"规则版本：{rule_version}"),
            QLabel("Founder Alpha"),
        ]
        for label in self.trust_labels:
            trust_layout.addWidget(label)
        trust_layout.addStretch()
        content_layout.addWidget(self.trust_strip)

        self.stack = QStackedWidget()
        self.stack.addWidget(self._scope_page())
        self.stack.addWidget(self._findings_page())
        self.stack.addWidget(self._report_page())
        self.stack.addWidget(self._solution_page())
        self.stack.addWidget(self._about_page())
        content_layout.addWidget(self.stack, 1)
        self._switch_view(0)

    def _scope_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 22, 24, 22)
        layout.setSpacing(12)
        layout.addWidget(_heading("审计范围"))
        layout.addWidget(QLabel("所选根目录"))
        self.root_display_label = QLabel("尚未选择")
        self.root_display_label.setObjectName("rootDisplay")
        self.root_display_label.setMinimumHeight(38)
        layout.addWidget(self.root_display_label)

        self.scope_roots_label = QLabel("范围：尚未选择")
        self.scope_roots_label.setWordWrap(True)
        self.scope_selectors_label = QLabel(
            "支持后缀：.env, .json, .log, .md, .toml, .txt, .yaml, .yml；"
            "支持精确文件名：.env"
        )
        self.scope_limits_label = QLabel(
            "上限：文件 10,000；目录条目 50,000；读取 536,870,912 字节；"
            "风险发现 2,000；证据 4,000"
        )
        self.scope_exclusions_label = QLabel(
            "排除：拒绝 UNC 和驱动器根目录；排除重解析路径。"
        )
        self.scope_mode_label = QLabel(
            "模式：仅本地、只读检测和人工指引；不调用 OpenAI 或第三方 API。"
        )
        for label in (
            self.scope_roots_label,
            self.scope_selectors_label,
            self.scope_limits_label,
            self.scope_exclusions_label,
            self.scope_mode_label,
        ):
            label.setWordWrap(True)
            layout.addWidget(label)

        self.supported_data_checkbox = QCheckBox(
            "我确认数据符合个人非受监管配置边界"
        )
        supported_data_description = (
            "仅支持个人非受监管配置；不含医疗、金融、身份/生物识别、"
            "法律特权、客户数据集、国家秘密或同等高敏感真实数据。"
        )
        self.supported_data_checkbox.setToolTip(supported_data_description)
        self.supported_data_checkbox.setAccessibleDescription(
            supported_data_description
        )
        self.supported_data_checkbox.toggled.connect(
            self._supported_data_consent_changed
        )
        layout.addWidget(self.supported_data_checkbox)

        unsupported_data_disclosure = (
            "不支持医疗、金融、身份/生物识别、法律特权、客户数据、国家秘密，"
            "以及其他受监管或高敏感真实数据。"
        )
        self.supported_data_disclosure_label = QLabel(
            unsupported_data_disclosure
        )
        self.supported_data_disclosure_label.setObjectName(
            "supportedDataDisclosure"
        )
        self.supported_data_disclosure_label.setWordWrap(True)
        self.supported_data_disclosure_label.setAccessibleName(
            "不支持的数据类别"
        )
        self.supported_data_disclosure_label.setAccessibleDescription(
            unsupported_data_disclosure
        )
        layout.addWidget(self.supported_data_disclosure_label)

        self.scope_consent_checkbox = QCheckBox(
            "我已核对并同意仅扫描当前显示范围"
        )
        self.scope_consent_checkbox.setAccessibleDescription(
            "同意当前短名范围的本地只读扫描"
        )
        self.scope_consent_checkbox.setEnabled(False)
        self.scope_consent_checkbox.toggled.connect(
            self._scope_consent_changed
        )
        layout.addWidget(self.scope_consent_checkbox)

        actions = QHBoxLayout()
        actions.setSpacing(8)
        self.folder_button = QPushButton("选择文件夹")
        self.folder_button.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_DirOpenIcon)
        )
        self.folder_button.clicked.connect(self._select_folder)
        self.known_config_button = QPushButton("添加已知配置")
        self.known_config_button.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_DirOpenIcon)
        )
        self.known_config_button.setToolTip(
            "将允许列表中已存在的本地 AI 配置目录加入当前审计范围"
        )
        self.known_config_button.clicked.connect(self._add_known_config_roots)
        self.scan_button = QPushButton("开始审计")
        self.scan_button.setObjectName("primaryAction")
        self.scan_button.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPlay)
        )
        self.scan_button.setToolTip("对所选文件夹执行只读本地审计")
        self.scan_button.setEnabled(False)
        self.scan_button.clicked.connect(self._start_scan)
        actions.addWidget(self.folder_button)
        actions.addWidget(self.known_config_button)
        actions.addWidget(self.scan_button)
        actions.addStretch()
        layout.addLayout(actions)

        optional_actions = QHBoxLayout()
        optional_actions.setSpacing(8)
        self.browser_kind_combo = QComboBox()
        self.browser_kind_combo.addItem("Chrome", BrowserKind.CHROME)
        self.browser_kind_combo.addItem("Edge", BrowserKind.EDGE)
        self.browser_kind_combo.addItem("Firefox", BrowserKind.FIREFOX)
        self.browser_kind_combo.setToolTip("选择要读取固定元数据的浏览器数据库格式")
        self.browser_button = QPushButton("审计浏览器数据库")
        self.browser_button.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogContentsView)
        )
        self.browser_button.setToolTip(
            "仅在点击后读取用户选定的数据库副本；不读取 URL、Cookie 或密码。"
        )
        self.browser_button.setEnabled(False)
        self.browser_button.clicked.connect(self._select_browser_database)
        self.clipboard_button = QPushButton("一次性审计剪贴板")
        self.clipboard_button.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_DialogApplyButton)
        )
        self.clipboard_button.setToolTip(
            "仅在点击后读取一次剪贴板并在内存中检测，不写回、不保存原文。"
        )
        self.clipboard_button.setEnabled(False)
        self.clipboard_button.clicked.connect(self._scan_clipboard_once)
        self.share_button = QPushButton("验证联网分享")
        self.share_button.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_DialogYesButton)
        )
        self.share_button.setToolTip(
            "仅验证用户输入的公开 URL；不上传扫描文件、凭据或聊天内容。"
        )
        self.share_button.clicked.connect(self._verify_share)
        optional_actions.addWidget(self.browser_kind_combo)
        optional_actions.addWidget(self.browser_button)
        optional_actions.addWidget(self.clipboard_button)
        optional_actions.addWidget(self.share_button)
        optional_actions.addStretch()
        layout.addLayout(optional_actions)

        self.status_label = QLabel("请选择审计文件夹。")
        self.status_label.setObjectName("status")
        layout.addWidget(self.status_label)
        self.coverage_status_label = QLabel("覆盖状态：尚无结果。")
        self.coverage_status_label.setWordWrap(True)
        layout.addWidget(self.coverage_status_label)
        layout.addStretch()
        return page

    def _findings_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 22, 24, 22)
        layout.setSpacing(10)
        layout.addWidget(_heading("风险发现"))
        filters = QHBoxLayout()
        filters.setSpacing(8)
        self.severity_filter_combo = QComboBox()
        self.severity_filter_combo.addItem("全部严重性", None)
        for severity in Severity:
            self.severity_filter_combo.addItem(
                _SEVERITY_FILTER_LABELS[severity], severity
            )
        self.domain_filter_combo = QComboBox()
        self.domain_filter_combo.addItem("全部风险域", None)
        for domain in RiskDomain:
            self.domain_filter_combo.addItem(_DOMAIN_FILTER_LABELS[domain], domain)
        self.disposition_filter_combo = QComboBox()
        self.disposition_filter_combo.addItem("全部处置", None)
        for state in ("open", "false_positive", "accepted_risk", "expired"):
            self.disposition_filter_combo.addItem(_STATUS_LABELS[state], state)
        for combo in (
            self.severity_filter_combo,
            self.domain_filter_combo,
            self.disposition_filter_combo,
        ):
            combo.setFixedSize(140, 32)
            combo.currentIndexChanged.connect(self._finding_filters_changed)
            filters.addWidget(combo)
        filters.addStretch()
        self.findings_count_label = QLabel("显示 0 / 共 0 项发现")
        self.findings_count_label.setAlignment(
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        )
        self.findings_count_label.setFixedSize(184, 32)
        filters.addWidget(self.findings_count_label)
        layout.addLayout(filters)
        self.findings_table = QTableWidget(0, 5)
        self.findings_table.setHorizontalHeaderLabels(
            ["严重性", "规则", "来源", "已掩码证据", "处置状态"]
        )
        self.findings_table.setTextElideMode(Qt.TextElideMode.ElideRight)
        self.findings_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.findings_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.findings_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.findings_table.verticalHeader().setVisible(False)
        header = self.findings_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        self.findings_table.setColumnWidth(0, 72)
        self.findings_table.setColumnWidth(1, 150)
        self.findings_table.setColumnWidth(2, 130)
        self.findings_table.setColumnWidth(4, 140)
        self.findings_table.itemSelectionChanged.connect(self._selection_changed)
        layout.addWidget(self.findings_table, 1)

        disposition_actions = QHBoxLayout()
        disposition_actions.setSpacing(8)
        self.false_positive_button = QPushButton("标记误报")
        self.false_positive_button.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_DialogDiscardButton)
        )
        self.false_positive_button.setToolTip(
            "创建或替换误报处置"
        )
        self.false_positive_button.clicked.connect(
            lambda: self._set_disposition(DispositionStatus.FALSE_POSITIVE)
        )
        self.accepted_risk_button = QPushButton("接受风险")
        self.accepted_risk_button.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_DialogApplyButton)
        )
        self.accepted_risk_button.setToolTip(
            "创建或替换接受风险处置"
        )
        self.accepted_risk_button.clicked.connect(
            lambda: self._set_disposition(DispositionStatus.ACCEPTED_RISK)
        )
        self.withdraw_button = QPushButton("撤销处置")
        self.withdraw_button.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_DialogResetButton)
        )
        self.withdraw_button.setToolTip("撤销此风险发现的处置")
        self.withdraw_button.clicked.connect(self._withdraw_disposition)
        for button in (
            self.false_positive_button,
            self.accepted_risk_button,
            self.withdraw_button,
        ):
            button.setMinimumWidth(132)
            button.setFixedHeight(32)
            button.setEnabled(False)
            disposition_actions.addWidget(button)
        disposition_actions.addStretch()
        layout.addLayout(disposition_actions)
        remediation_actions = QHBoxLayout()
        remediation_actions.setSpacing(8)
        self.remediation_button = QPushButton("执行固定修复")
        self.remediation_button.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_DialogApplyButton)
        )
        self.remediation_button.setToolTip(
            "仅对允许的 OpenAI 地址规则执行固定替换；先预览，再二次确认"
        )
        self.remediation_button.clicked.connect(self._apply_fixed_remediation)
        self.rollback_button = QPushButton("回滚固定修复")
        self.rollback_button.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_DialogResetButton)
        )
        self.rollback_button.setToolTip("仅回滚本次会话中已应用且未被改动的固定替换")
        self.rollback_button.clicked.connect(self._rollback_fixed_remediation)
        self.remediation_button.setFixedHeight(32)
        self.rollback_button.setFixedHeight(32)
        self.remediation_button.setEnabled(False)
        self.rollback_button.setEnabled(False)
        remediation_actions.addWidget(self.remediation_button)
        remediation_actions.addWidget(self.rollback_button)
        remediation_actions.addStretch()
        layout.addLayout(remediation_actions)
        layout.addWidget(QLabel("风险详情与人工处理步骤"))
        self.guidance_browser = QTextBrowser()
        self.guidance_browser.setMinimumHeight(150)
        self.guidance_browser.setMaximumHeight(230)
        self.guidance_browser.setPlainText(_FINDING_SELECTION_MESSAGE)
        layout.addWidget(self.guidance_browser)
        return page

    def _report_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 22, 24, 22)
        layout.setSpacing(10)
        layout.addWidget(_heading("审计报告"))
        controls = QHBoxLayout()
        controls.setSpacing(8)
        self.report_mode_combo = QComboBox()
        self.report_mode_combo.addItems(["HTML", "JSON"])
        self.report_mode_combo.currentTextChanged.connect(self._refresh_report)
        self.review_button = QPushButton("审阅修复方案")
        self.review_button.clicked.connect(self._review_guidance)
        self.save_button = QPushButton("保存报告")
        self.save_button.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_DialogSaveButton)
        )
        self.save_button.setToolTip("导出一份新的审计报告")
        self.save_button.setEnabled(False)
        self.save_button.clicked.connect(self._export_report)
        self.protected_state_button = QPushButton("保存加密状态")
        self.protected_state_button.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_DialogSaveButton)
        )
        self.protected_state_button.setToolTip("保存当前用户范围的 DPAPI 加密状态")
        self.protected_state_button.setEnabled(False)
        self.protected_state_button.clicked.connect(self._save_protected_state)
        controls.addWidget(self.report_mode_combo)
        controls.addStretch()
        controls.addWidget(self.review_button)
        controls.addWidget(self.protected_state_button)
        controls.addWidget(self.save_button)
        layout.addLayout(controls)

        comparison_controls = QHBoxLayout()
        comparison_controls.setSpacing(8)
        self.comparison_select_button = QPushButton("选择基线 JSON")
        self.comparison_select_button.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_DialogOpenButton)
        )
        self.comparison_select_button.setToolTip("选择一份本地 AgentGuardian JSON 报告")
        self.comparison_select_button.setFixedHeight(32)
        self.comparison_select_button.setEnabled(False)
        self.comparison_select_button.clicked.connect(self._select_baseline_report)
        self.comparison_clear_button = QPushButton("清除基线")
        self.comparison_clear_button.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_DialogResetButton)
        )
        self.comparison_clear_button.setToolTip("清除当前基线与聚合比较")
        self.comparison_clear_button.setFixedHeight(32)
        self.comparison_clear_button.setEnabled(False)
        self.comparison_clear_button.clicked.connect(self._clear_comparison_callback)
        self.baseline_name_label = QLabel("基线：未选择")
        self.baseline_name_label.setMinimumWidth(0)
        self.baseline_name_label.setFixedHeight(32)
        comparison_controls.addWidget(self.comparison_select_button)
        comparison_controls.addWidget(self.comparison_clear_button)
        comparison_controls.addWidget(self.baseline_name_label, 1)
        layout.addLayout(comparison_controls)

        self.report_browser = QTextBrowser()
        self.report_browser.setHtml("<p>尚无审计报告。</p>")
        layout.addWidget(self.report_browser, 1)
        self.comparison_browser = QTextBrowser()
        self.comparison_browser.setFrameShape(QFrame.Shape.NoFrame)
        self.comparison_browser.setMinimumHeight(116)
        self.comparison_browser.setMaximumHeight(170)
        self.comparison_browser.setPlainText(_COMPARISON_EMPTY_MESSAGE)
        layout.addWidget(self.comparison_browser)
        return page

    def _solution_page(self) -> QWidget:
        page = QWidget()
        page_layout = QVBoxLayout(page)
        page_layout.setContentsMargins(24, 22, 24, 22)
        page_layout.setSpacing(12)
        page_layout.addWidget(_heading("风险处理方案"))

        intro = QFrame()
        intro.setObjectName("solutionIntro")
        intro_layout = QVBoxLayout(intro)
        intro_layout.setContentsMargins(18, 14, 18, 14)
        intro_layout.setSpacing(5)
        intro_title = QLabel("先确认事实，再处理风险")
        intro_title.setObjectName("solutionIntroTitle")
        intro_layout.addWidget(intro_title)
        intro_text = QLabel(
            "逐条核实发现，再按风险类型处理。规则匹配是核查线索，不代表数据已经泄露。"
        )
        intro_text.setWordWrap(True)
        intro_text.setObjectName("solutionIntroText")
        intro_layout.addWidget(intro_text)
        page_layout.addWidget(intro)

        scroll = QScrollArea()
        scroll.setObjectName("solutionScrollArea")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        content = QWidget()
        content.setObjectName("solutionContent")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 4, 0)
        content_layout.setSpacing(9)

        steps = (
            (
                "复核并确定优先级",
                "先查看严重和高风险项目。打开单条发现，核对规则、来源和已掩码证据；不要复制完整密钥、邮箱或手机号到报告、聊天或工单。",
            ),
            (
                "凭据与 API Key",
                "确认是有效凭据后，先到对应服务撤销或停用旧密钥，再生成新密钥并更新获准的应用配置。随后检查使用记录；若密钥曾公开，先撤销轮换，再清理可访问的副本。",
            ),
            (
                "邮箱、手机号等个人信息",
                "确认数据是否仍有保留必要。不需要时，在原应用或配置中删除或遮盖；确需保留时，按组织规则记录原因、责任人和复核期限。",
            ),
            (
                "端点、MCP 与权限设置",
                "核实端点和服务由谁运营、是否获准。对不确定的 MCP 服务，先暂停使用，再按实际需要收紧命令、文件写入和网络权限；在原应用或配置中修改后重新审计。",
            ),
            (
                "使用处置按钮",
                "标记误报：仅在确认规则不适用时使用，并说明原因。接受风险：仅用于真实但获准暂时保留的风险，需记录理由、复核人和到期时间；这不会消除风险或改写原文件。撤销处置会让该项重新进入待处理。",
            ),
            (
                "固定修复与回滚",
                "固定修复目前仅支持获准的 OpenAI API 地址配置；先检查预览，再决定是否继续。执行前会创建同目录备份。回滚仅适用于本次会话已应用且之后未被改动的文件。其他风险请按人工修复步骤处理。",
            ),
            (
                "复审并留存",
                "完成处理后，对相同范围重新执行只读审计，查看剩余发现和覆盖状态。确认风险已消除或处置记录仍有效，再保存新报告并由负责人复核。",
            ),
        )
        for index, (title_text, body_text) in enumerate(steps, start=1):
            card = QFrame()
            card.setObjectName("solutionCard")
            card_layout = QHBoxLayout(card)
            card_layout.setContentsMargins(14, 12, 16, 12)
            card_layout.setSpacing(14)

            number = QLabel(f"{index:02d}")
            number.setObjectName("solutionStepNumber")
            number.setAlignment(Qt.AlignmentFlag.AlignCenter)
            number.setFixedSize(38, 38)
            card_layout.addWidget(number, 0, Qt.AlignmentFlag.AlignTop)

            detail_layout = QVBoxLayout()
            detail_layout.setContentsMargins(0, 0, 0, 0)
            detail_layout.setSpacing(5)
            title = QLabel(title_text)
            title.setObjectName("solutionStepTitle")
            detail_layout.addWidget(title)
            body = QLabel(body_text)
            body.setObjectName("solutionStepBody")
            body.setWordWrap(True)
            detail_layout.addWidget(body)
            card_layout.addLayout(detail_layout, 1)
            content_layout.addWidget(card)
        content_layout.addStretch()
        scroll.setWidget(content)
        page_layout.addWidget(scroll, 1)
        return page

    def _about_page(self) -> QWidget:
        page = QWidget()
        page_layout = QVBoxLayout(page)
        page_layout.setContentsMargins(24, 22, 24, 22)
        page_layout.setSpacing(12)
        page_layout.addWidget(_heading("关于作者"))

        scroll = QScrollArea()
        scroll.setObjectName("aboutScrollArea")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        content = QWidget()
        content.setObjectName("aboutContent")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 4, 0)
        content_layout.setSpacing(14)

        hero = QFrame()
        hero.setObjectName("aboutHero")
        hero_layout = QHBoxLayout(hero)
        hero_layout.setContentsMargins(20, 20, 22, 20)
        hero_layout.setSpacing(22)
        poster = QLabel()
        poster.setObjectName("aboutPoster")
        poster.setAlignment(Qt.AlignmentFlag.AlignCenter)
        poster.setAccessibleDescription(
            _translate("ENHE 作者介绍海报", self._language)
        )
        poster.setFixedSize(360, 240)
        poster_path = Path(__file__).parent / "assets" / "author-poster.jpg"
        if poster_path.is_file():
            pixmap = QPixmap(str(poster_path))
            if not pixmap.isNull():
                poster.setPixmap(
                    pixmap.scaled(
                        poster.size(),
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation,
                    )
                )
        hero_layout.addWidget(poster)

        identity = QVBoxLayout()
        identity.setSpacing(10)
        eyebrow = QLabel("创作者档案")
        eyebrow.setObjectName("authorEyebrow")
        identity.addWidget(eyebrow)
        name = QLabel("Enhe (恩禾)")
        name.setObjectName("authorName")
        identity.addWidget(name)
        subtitle = QLabel("产品设计师 · 一人公司实践者 · AI Builder")
        subtitle.setObjectName("authorSubtitle")
        subtitle.setWordWrap(True)
        identity.addWidget(subtitle)
        tagline = QLabel("用 AI 打造一个人公司")
        tagline.setObjectName("authorTagline")
        tagline.setWordWrap(True)
        identity.addWidget(tagline)
        identity.addWidget(QLabel("创作者与实践者"))
        identity.addStretch()
        hero_layout.addLayout(identity, 1)
        content_layout.addWidget(hero)

        contact_card = QFrame()
        contact_card.setObjectName("aboutCard")
        contact_layout = QVBoxLayout(contact_card)
        contact_layout.setContentsMargins(20, 16, 20, 16)
        contact_layout.setSpacing(8)
        contact_heading = QLabel("联系方式")
        contact_heading.setObjectName("contactCardTitle")
        contact_layout.addWidget(contact_heading)
        contacts = (
            ("GitHub", "yangjing6213-dev", "https://github.com/yangjing6213-dev"),
            ("X / Twitter", "Amenenhe_ai", "https://x.com/Amenenhe_ai"),
            ("网站", "www.enhe-tech.com.cn", "https://www.enhe-tech.com.cn/"),
            ("微信", "ENHE-AI", None),
            ("邮箱", "amen.enhe@gmail.com", "mailto:amen.enhe@gmail.com"),
        )
        for label_text, value, href in contacts:
            row_layout = QHBoxLayout()
            row_layout.setSpacing(18)
            label = QLabel(label_text)
            label.setObjectName("contactLabel")
            label.setFixedWidth(104)
            value_label = QLabel(
                value
                if href is None
                else (
                    f'<a href="{href}" style="color:#79C8FF; text-decoration:none;">'
                    f"{value}</a>"
                )
            )
            value_label.setObjectName("contactValue")
            value_label.setTextFormat(Qt.TextFormat.RichText)
            value_label.setOpenExternalLinks(href is not None)
            value_label.setWordWrap(True)
            value_label.setMinimumWidth(0)
            row_layout.addWidget(label)
            row_layout.addWidget(value_label, 1)
            contact_layout.addLayout(row_layout)
        content_layout.addWidget(contact_card)
        content_layout.addStretch()
        scroll.setWidget(content)
        page_layout.addWidget(scroll, 1)
        return page

    def _switch_view(self, index: int) -> None:
        self.stack.setCurrentIndex(index)
        for button_index, button in enumerate(self.navigation_buttons):
            button.setChecked(button_index == index)

    def _select_folder(self) -> None:
        selected = QFileDialog.getExistingDirectory(self, "选择审计文件夹")
        if not selected:
            self._clear_scope("未选择有效的审计范围。")
            return
        if _is_unc_path(selected):
            self._clear_scope("不支持 UNC 路径；映射网络盘无法可靠识别。")
            return
        try:
            root = Path(selected)
            self._set_scope_roots(
                (root,),
                status="请核对范围并明确同意后开始审计。",
            )
        except Exception:  # noqa: BLE001 - fixed folder-selection boundary
            self._clear_scope("无法建立有效的审计范围。")
            return

    def _select_browser_database(self) -> None:
        if not self._personal_scope_ready():
            self.status_label.setText("请先确认产品边界并同意当前审计范围。")
            return
        answer = QMessageBox.question(
            self,
            "浏览器元数据审计",
            "仅统计固定浏览器元数据，不读取 URL、Cookie、密码或正文。"
            "我确认所选数据库不含医疗、金融、身份/生物识别、法律特权、"
            "客户数据集、国家秘密或同等高敏感真实数据，并符合个人不受监管配置边界。"
            "继续吗？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            self.status_label.setText("浏览器数据库审计已取消。")
            return
        if not self._personal_scope_ready():
            return
        selected, _selected_filter = QFileDialog.getOpenFileName(
            self,
            "选择浏览器数据库",
            "",
            "Chrome History;Edge History;Firefox places.sqlite",
        )
        if not selected:
            return
        if not self._personal_scope_ready():
            return
        try:
            browser = BrowserKind(self.browser_kind_combo.currentData())
            result = audit_browser_database(Path(selected), browser)
        except (OSError, TypeError, ValueError):
            self.status_label.setText("浏览器数据库检查未执行。")
            self.coverage_status_label.setText(
                "浏览器数据库检查失败；未生成报告。"
            )
            return
        self._invalidate_report()
        history_count = dict(result.counts).get("history_entries", 0)
        visit_count = dict(result.counts).get("visit_entries", 0)
        self.status_label.setText(
            f"浏览器元数据审计完成：历史 {history_count}，访问记录 {visit_count}。"
        )
        self.coverage_status_label.setText(
            "仅统计固定元数据；未读取 URL、Cookie、密码或页面正文。"
        )
        self.guidance_browser.setPlainText(
            "浏览器检查只提供选定数据库的固定计数，不能证明浏览器、账号或网站安全。"
        )

    def _scan_clipboard_once(self) -> None:
        if not self._personal_scope_ready():
            self.status_label.setText("请先确认产品边界并同意当前审计范围。")
            return
        answer = QMessageBox.question(
            self,
            "剪贴板一次性审计",
            "仅在内存中读取剪贴板一次且不保存原文。"
            "我确认剪贴板不含医疗、金融、身份/生物识别、法律特权、客户数据集、"
            "国家秘密或同等高敏感真实数据，并符合个人不受监管配置边界。继续吗？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            self.status_label.setText("Clipboard audit cancelled.")
            return
        if not self._personal_scope_ready():
            return
        try:
            result, outcome = run_clipboard_audit(
                lambda: QApplication.clipboard().text(),
                disposition_key=self._disposition_key,
                dispositions=self._dispositions,
            )
        except Exception:  # noqa: BLE001 - fixed clipboard boundary
            self._invalidate_report()
            self.status_label.setText("剪贴板检查未执行。")
            self.coverage_status_label.setText("剪贴板读取失败；未生成报告。")
            return
        if not result.scanned or outcome is None:
            self._invalidate_report()
            self.status_label.setText("剪贴板检查未执行。")
            self.coverage_status_label.setText(
                "剪贴板内容未进入审计；未生成报告。"
            )
            return
        self._scan_completed(outcome)
        if self._audit_outcome is not outcome:
            return
        self.status_label.setText(
            f"剪贴板一次性审计完成：发现 {len(result.findings)} 项。"
        )
        self.coverage_status_label.setText(
            "剪贴板仅在本次点击中读取一次；报告不包含剪贴板原文。"
        )

    def _verify_share(self) -> None:
        if self.is_scanning:
            return
        url, accepted = QInputDialog.getText(
            self,
            "验证联网分享",
            "输入公开 HTTP(S) URL：",
        )
        if not accepted or not url.strip():
            return
        answer = QMessageBox.question(
            self,
            "确认公共网络访问",
            "这是公共网络 I/O。\n"
            "不会发送本地扫描数据或凭据。\n"
            "通过 MCP 调用时，可能将脱敏元数据放入 Codex 上下文。\n"
            "不支持受监管或高度敏感的真实数据。继续吗？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            result = verify_public_share(url.strip())
        except (OSError, TypeError, ValueError):
            self.status_label.setText("联网分享验证未执行。")
            self.coverage_status_label.setText(
                "URL 不符合公开分享验证边界；未发送本地数据。"
            )
            return
        if not result.reachable:
            self.status_label.setText("联网分享验证未完成。")
            self.coverage_status_label.setText(
                "未获得符合限制的公开响应；未发送本地数据。"
            )
            return
        self.status_label.setText(
            f"联网分享验证完成：{result.address}，HTTP {result.status_code}，"
            f"读取 {result.bytes_read} 字节。"
        )
        self.coverage_status_label.setText(
            "仅验证公开响应可达性；未上传扫描文件、凭据或聊天内容。"
        )
        self.guidance_browser.setPlainText(
            "联网分享验证不代表链接内容、分享权限或搜索引擎收录结果安全。"
        )

    def _add_known_config_roots(self) -> None:
        if self.is_scanning:
            return
        try:
            known_roots = tuple(known_config_roots(os.environ))
            merged_roots = _dedupe_scope_roots((*self._roots, *known_roots))
        except Exception:  # noqa: BLE001 - fixed allowlist boundary
            self.status_label.setText("无法读取已知本地 AI 配置范围。")
            return
        if merged_roots == self._roots:
            self.status_label.setText("当前范围已包含可用的已知 AI 配置目录。")
            return
        try:
            added_count = len(merged_roots) - len(self._roots)
            self._set_scope_roots(
                merged_roots,
                status=(
                    f"已添加 {added_count} 个已知本地 AI 配置目录；"
                    "请核对范围并明确同意后开始审计。"
                ),
            )
        except Exception:  # noqa: BLE001 - fixed allowlist boundary
            self._revoke_confirmations()
            self.status_label.setText("无法建立已知本地 AI 配置范围。")

    def _set_scope_roots(self, roots: Iterable[Path], *, status: str) -> None:
        normalized_roots = _dedupe_scope_roots(roots)
        if not normalized_roots:
            raise ValueError("scope roots must not be empty")
        try:
            preview = _scope_preview_for(normalized_roots)
        except Exception:
            self._revoke_confirmations()
            raise
        self._invalidate_report()
        self._clear_comparison_if_present()
        self._revoke_confirmations()
        self._roots = normalized_roots
        self._scope_preview = preview
        if preview.root_count == 1:
            self.root_display_label.setUntranslatedText(preview.root_names[0])
        else:
            self.root_display_label.setText(f"{preview.root_count} 个本地根目录")
        self._render_scope_preview(preview)
        self.scope_consent_checkbox.setEnabled(True)
        self._update_scan_enabled()
        self.status_label.setText(status)

    def _render_scope_preview(self, preview: ScopePreview) -> None:
        selectors = ", ".join(preview.selectors)
        self.scope_roots_label.setText(
            f"范围：{preview.root_count} 个根目录（{', '.join(preview.root_names)}）"
        )
        self.scope_selectors_label.setText(
            f"支持后缀：{selectors}；支持精确文件名：{selectors}"
        )
        self.scope_limits_label.setText(
            f"上限：文件 {preview.max_files:,}；目录条目 {preview.max_entries:,}；"
            f"读取 {preview.max_bytes:,} 字节；风险发现 {preview.max_findings:,}；"
            f"证据 {preview.max_evidence:,}"
        )
        self.scope_exclusions_label.setText(
            "排除：拒绝 UNC 和驱动器根目录；排除重解析路径。"
        )
        self.scope_mode_label.setText(
            "模式：仅本地、只读检测和人工指引；不调用 OpenAI 或第三方 API。"
        )

    def _scope_consent_changed(self, checked: bool) -> None:
        self._scope_consent = None
        if checked:
            try:
                if self._scope_preview is None:
                    raise ValueError
                self._scope_consent = bind_scope_consent(self._scope_preview)
            except Exception:  # noqa: BLE001 - fixed consent callback boundary
                self.scope_consent_checkbox.blockSignals(True)
                self.scope_consent_checkbox.setChecked(False)
                self.scope_consent_checkbox.blockSignals(False)
                self.status_label.setText("请重新核对并同意当前审计范围。")
        self._update_optional_audit_enabled()
        self._update_scan_enabled()

    def _supported_data_consent_changed(self, checked: bool) -> None:
        if not checked:
            self._revoke_scope_consent()
        self._update_optional_audit_enabled()
        self._update_scan_enabled()

    def _revoke_scope_consent(self) -> None:
        self._scope_consent = None
        self.scope_consent_checkbox.blockSignals(True)
        self.scope_consent_checkbox.setChecked(False)
        self.scope_consent_checkbox.blockSignals(False)
        self._update_optional_audit_enabled()
        self._update_scan_enabled()

    def _revoke_confirmations(self) -> None:
        self.supported_data_checkbox.blockSignals(True)
        self.supported_data_checkbox.setChecked(False)
        self.supported_data_checkbox.blockSignals(False)
        self._revoke_scope_consent()
        self._update_optional_audit_enabled()

    def _update_optional_audit_enabled(self) -> None:
        enabled = self._personal_scope_ready()
        self.browser_button.setEnabled(enabled)
        self.clipboard_button.setEnabled(enabled)

    def _personal_scope_ready(self) -> bool:
        try:
            preview = self._scope_preview
            consent = self._scope_consent
            expected_preview = _scope_preview_for(self._roots)
            return (
                not self.is_scanning
                and self.supported_data_checkbox.isChecked() is True
                and self.scope_consent_checkbox.isChecked() is True
                and preview is not None
                and consent is not None
                and type(preview) is ScopePreview
                and preview == expected_preview
                and scope_consent_matches(consent, preview)
            )
        except Exception:
            return False

    def _update_scan_enabled(self) -> None:
        self.scan_button.setEnabled(self._personal_scope_ready())

    def _clear_scope(self, status: str) -> None:
        self._invalidate_report()
        self._clear_comparison_if_present()
        self._roots = ()
        self._scope_preview = None
        self._revoke_confirmations()
        self.scope_consent_checkbox.setEnabled(False)
        self.root_display_label.setText("尚未选择")
        self.scope_roots_label.setText("范围：尚未选择")
        self.status_label.setText(status)

    def _clear_comparison_if_present(self) -> None:
        self._comparison_state = None
        if not hasattr(self, "baseline_name_label"):
            return
        try:
            self.baseline_name_label.setText("基线：未选择")
        except Exception:
            pass
        try:
            self.baseline_name_label.setToolTip("")
        except Exception:
            pass
        try:
            self.comparison_browser.setPlainText(_COMPARISON_EMPTY_MESSAGE)
        except Exception:
            pass
        self._sync_comparison_commands()

    def _clear_comparison_callback(self) -> None:
        try:
            self._clear_comparison_if_present()
        except Exception:  # noqa: BLE001 - fixed Qt callback boundary
            self._comparison_state = None

    def _sync_comparison_commands(self) -> None:
        if not hasattr(self, "comparison_select_button"):
            return
        valid_current = (
            not self.is_scanning
            and self._audit_outcome is not None
            and bool(self.report_json)
        )
        if valid_current:
            try:
                parse_report_summary(self.report_json)
            except Exception:
                valid_current = False
        try:
            self.comparison_select_button.setEnabled(valid_current)
        except Exception:
            pass
        try:
            self.comparison_clear_button.setEnabled(
                self._comparison_state is not None
            )
        except Exception:
            pass

    def _render_comparison(self, state: _ComparisonState) -> None:
        text = _comparison_text(state.comparison, self._language)
        self._comparison_state = state
        self._render_baseline_name(state.baseline_name)
        self.comparison_browser.setPlainText(text)
        self._sync_comparison_commands()

    def _render_baseline_name(self, basename: str) -> None:
        label = self.baseline_name_label
        visible = label.fontMetrics().elidedText(
            f"基线：{basename}",
            Qt.TextElideMode.ElideRight,
            max(0, label.contentsRect().width()),
        )
        label.setText(visible)
        label.setToolTip(basename)

    def _show_comparison_failure(self) -> None:
        try:
            self._clear_comparison_if_present()
        except Exception:
            self._comparison_state = None
        try:
            QMessageBox.warning(
                self,
                _COMPARISON_ERROR_TITLE,
                _COMPARISON_ERROR_MESSAGE,
            )
        except Exception:
            pass

    def _select_baseline_report(self) -> None:
        try:
            selected, _selected_filter = QFileDialog.getOpenFileName(
                self,
                "选择基线报告",
                "",
                "JSON (*.json)",
            )
            if not selected:
                return
            if self._audit_outcome is None or not self.report_json:
                raise ValueError
            baseline = load_report_summary(selected)
            current = parse_report_summary(self.report_json)
            comparison = compare_report_summaries(baseline, current)
            state = _ComparisonState(Path(selected).name, comparison)
            self._render_comparison(state)
        except Exception:  # noqa: BLE001 - fixed baseline callback boundary
            self._show_comparison_failure()

    def _refresh_comparison_for_current_report(self) -> None:
        state = self._comparison_state
        if state is None:
            return
        try:
            current = parse_report_summary(self.report_json)
            comparison = compare_report_summaries(
                state.comparison.baseline,
                current,
            )
            self._render_comparison(
                _ComparisonState(state.baseline_name, comparison)
            )
        except Exception:  # noqa: BLE001 - fixed comparison refresh boundary
            self._show_comparison_failure()

    def _start_scan(self) -> None:
        try:
            if not self._personal_scope_ready():
                raise ValueError
            expected_preview = _scope_preview_for(self._roots)
        except Exception:  # noqa: BLE001 - fixed scan-consent boundary
            self._revoke_confirmations()
            self.status_label.setText("请重新核对并同意当前审计范围。")
            return

        self._scope_preview = expected_preview
        self._clear_comparison_if_present()
        self.is_scanning = True
        self._update_optional_audit_enabled()
        self._set_scope_controls_enabled(False)
        self.scan_button.setEnabled(False)
        self.scan_button.setText("审计中...")
        self.status_label.setText("正在执行只读本地审计。")
        try:
            self._invalidate_report()
            self.guidance_browser.setPlainText("等待审计结果。")

            self._thread = QThread(self)
            self._worker = AuditWorker(
                self._roots,
                expected_preview,
                self._disposition_key,
                self._dispositions,
            )
            self._worker.moveToThread(self._thread)
            self._thread.started.connect(self._worker.run)
            self._worker.completed.connect(self._scan_completed)
            self._worker.failed.connect(self._scan_failed)
            self._worker.completed.connect(self._thread.quit)
            self._worker.failed.connect(self._thread.quit)
            self._worker.completed.connect(self._worker.deleteLater)
            self._worker.failed.connect(self._worker.deleteLater)
            self._thread.finished.connect(self._thread.deleteLater)
            self._thread.finished.connect(self._thread_finished)
            self._thread.start()
        except Exception:  # noqa: BLE001 - fixed scan-start callback boundary
            self.is_scanning = False
            self._thread = None
            self._worker = None
            self._set_scope_controls_enabled(True)
            self.scan_button.setText("开始审计")
            self._update_optional_audit_enabled()
            self._update_scan_enabled()
            self._invalidate_report()
            self.status_label.setText("审计失败。")
            self.guidance_browser.setPlainText("无法生成修复步骤。")

    @Slot(object)
    def _scan_completed(self, outcome: AuditOutcome) -> None:
        try:
            coverage_status = _coverage_status_text(outcome.score)
        except Exception:  # noqa: BLE001 - fixed coverage callback boundary
            self._scan_failed("scan_failed")
            return
        self._audit_outcome = outcome
        self.report_json = outcome.report_json
        self.report_html = self._localized_report_html(outcome)
        self._report_roots = outcome.scanned_roots
        try:
            self._refresh_finding_view(outcome.evaluated_at)
        except Exception:  # noqa: BLE001 - preserve valid audit at UI boundary
            self._show_filter_failure()
        self._refresh_report()
        self._schedule_expiry_timer(outcome.evaluated_at)
        self.save_button.setEnabled(True)
        self.protected_state_button.setEnabled(True)
        self.status_label.setText(_audit_status_text(outcome))
        self.coverage_status_label.setText(coverage_status)
        self._sync_comparison_commands()

    @Slot(str)
    def _scan_failed(self, _code: str) -> None:
        self._invalidate_report()
        self.status_label.setText("审计失败。")
        self.guidance_browser.setPlainText("无法生成修复步骤。")

    def _invalidate_report(self, *, preserve_remediation: bool = False) -> None:
        self._expiry_timer.stop()
        self._audit_outcome = None
        self.report_json = ""
        self.report_html = ""
        self._report_roots = ()
        self.findings_table.setRowCount(0)
        self._row_findings.clear()
        self.findings_count_label.setText("显示 0 / 共 0 项发现")
        self.guidance_browser.setPlainText(_FINDING_SELECTION_MESSAGE)
        self.save_button.setEnabled(False)
        self.protected_state_button.setEnabled(False)
        self.coverage_status_label.setText("覆盖状态：尚无结果。")
        if not preserve_remediation:
            self._last_remediation = None
        self._update_disposition_commands()
        self._refresh_report()
        self._clear_comparison_if_present()

    @Slot()
    def _thread_finished(self) -> None:
        self.is_scanning = False
        self.scan_button.setText("开始审计")
        self._set_scope_controls_enabled(True)
        self._thread = None
        self._worker = None
        self._update_optional_audit_enabled()
        self._update_scan_enabled()
        self._sync_comparison_commands()

    def _set_scope_controls_enabled(self, enabled: bool) -> None:
        self.folder_button.setEnabled(enabled)
        self.known_config_button.setEnabled(enabled)
        self.supported_data_checkbox.setEnabled(enabled)
        self.scope_consent_checkbox.setEnabled(
            enabled and self._scope_preview is not None
        )

    def _populate_findings(
        self,
        findings: tuple[Finding, ...],
        *,
        now: datetime | None = None,
    ) -> None:
        rows = sum(len(finding.evidence) for finding in findings)
        self.findings_table.clearSelection()
        self.findings_table.setCurrentCell(-1, -1)
        self._row_findings.clear()
        self.findings_table.setRowCount(rows)
        row = 0
        for finding in findings:
            for evidence in finding.evidence:
                values = (
                    _translate(
                        _SEVERITY_FILTER_LABELS[finding.severity], self._language
                    ),
                    finding.rule_id,
                    evidence.source,
                    evidence.masked,
                    "",
                )
                for column, value in enumerate(values):
                    item = QTableWidgetItem(value)
                    if column in {1, 2, 3}:
                        item.setToolTip(value)
                    if finding.severity is Severity.CRITICAL:
                        item.setForeground(QColor(COLOR_TOKENS["critical"]))
                    elif finding.severity in {Severity.HIGH, Severity.MEDIUM}:
                        item.setForeground(QColor(COLOR_TOKENS["warning"]))
                    self.findings_table.setItem(row, column, item)
                self._row_findings.append(finding)
                row += 1
        evaluation_time = (
            now
            if now is not None
            else (
                self._audit_outcome.evaluated_at
                if self._audit_outcome is not None
                else _utc_now()
            )
        )
        self._refresh_disposition_ui(evaluation_time)

    def _current_finding_filters(self) -> FindingFilters:
        severity = self.severity_filter_combo.currentData()
        domain = self.domain_filter_combo.currentData()
        return FindingFilters(
            severity=None if severity is None else Severity(severity),
            domain=None if domain is None else RiskDomain(domain),
            disposition_state=self.disposition_filter_combo.currentData(),
        )

    def _current_row_finding(self) -> Finding | None:
        row = self.findings_table.currentRow()
        if not 0 <= row < len(self._row_findings):
            return None
        return self._row_findings[row]

    def _refresh_finding_view(
        self,
        now: datetime,
        *,
        selected_finding: Finding | None = None,
        restore_selection: bool = True,
    ) -> None:
        outcome = self._audit_outcome
        if outcome is None:
            self.findings_table.setRowCount(0)
            self._row_findings.clear()
            self.findings_count_label.setText("显示 0 / 共 0 项发现")
            self.guidance_browser.setPlainText(_FINDING_SELECTION_MESSAGE)
            self._update_disposition_commands()
            return
        evaluation_time = _validated_evaluation_time(now)
        previous_selection = (
            self._current_row_finding()
            if selected_finding is None
            else selected_finding
        )
        filter_failed = False
        try:
            visible = filter_findings(
                outcome.findings,
                self._dispositions,
                self._current_finding_filters(),
                now=evaluation_time,
            )
        except Exception:
            filter_failed = True
        if filter_failed:
            raise _FindingFilterCallbackError
        self._populate_findings(visible, now=evaluation_time)
        self.findings_count_label.setText(
            f"显示 {len(visible)} / 共 {len(outcome.findings)} 项发现"
        )
        if not visible:
            self.guidance_browser.setPlainText(_FILTER_EMPTY_MESSAGE)
            self._update_disposition_commands()
            return
        if restore_selection and previous_selection is not None:
            for row, finding in enumerate(self._row_findings):
                if finding is previous_selection:
                    self.findings_table.selectRow(row)
                    return
        self.guidance_browser.setPlainText(_FINDING_SELECTION_MESSAGE)
        self._update_disposition_commands()

    @Slot(int)
    def _finding_filters_changed(self, _index: int) -> None:
        try:
            outcome = self._audit_outcome
            if outcome is None:
                self._refresh_finding_view(_utc_now())
                return
            self._refresh_finding_view(outcome.evaluated_at)
        except Exception:  # noqa: BLE001 - fixed filter callback boundary
            self._show_filter_failure()

    def _show_filter_failure(self) -> None:
        self.findings_table.setRowCount(0)
        self._row_findings.clear()
        self.findings_count_label.setText(_FILTER_ERROR_MESSAGE)
        self.guidance_browser.setPlainText(_FILTER_ERROR_MESSAGE)
        self._update_disposition_commands()

    def _selection_changed(self) -> None:
        self._show_guidance()
        self._update_disposition_commands()

    def _selected_finding(self) -> Finding | None:
        if not self.findings_table.selectionModel().hasSelection():
            return None
        finding = self._current_row_finding()
        if finding is None:
            return None
        return finding if finding.disposition_ref is not None else None

    def _selected_remediation_finding(self) -> Finding | None:
        if self._audit_outcome is None or not self.findings_table.selectionModel().hasSelection():
            return None
        finding = self._current_row_finding()
        if finding is None or finding.rule_id not in _FIXED_REMEDIATION_RULES:
            return None
        return finding

    def _update_disposition_commands(self) -> None:
        finding = self._selected_finding()
        selectable = finding is not None and self._audit_outcome is not None
        self.false_positive_button.setEnabled(selectable)
        self.accepted_risk_button.setEnabled(selectable)
        matching = False
        if selectable:
            record = disposition_index(self._dispositions).get(
                finding.disposition_ref
            )
            matching = record is not None and record.rule_id == finding.rule_id
        self.withdraw_button.setEnabled(matching)
        if hasattr(self, "remediation_button"):
            self.remediation_button.setEnabled(
                self._selected_remediation_finding() is not None
            )
        if hasattr(self, "rollback_button"):
            self.rollback_button.setEnabled(self._last_remediation is not None)

    def _remediation_target_is_in_scope(
        self,
        target: Path,
        finding: Finding,
    ) -> bool:
        if _is_unc_path(target) or _is_reparse(target):
            return False
        allowed_names = {evidence.source for evidence in finding.evidence}
        if target.name not in allowed_names:
            return False
        try:
            resolved_target = target.resolve(strict=False)
            resolved_roots = tuple(root.resolve(strict=True) for root in self._report_roots)
        except OSError:
            return False
        return any(
            resolved_target.is_relative_to(root)
            for root in resolved_roots
        )

    def _apply_fixed_remediation(self) -> None:
        finding = self._selected_remediation_finding()
        if finding is None:
            return
        selected, _selected_filter = QFileDialog.getOpenFileName(
            self,
            "选择已审计的 OpenAI 配置文件",
            "",
            "Configuration (*.env *.toml *.txt);;All files (*)",
        )
        if not selected:
            return
        target = Path(selected)
        if not self._remediation_target_is_in_scope(target, finding):
            self.status_label.setText("固定修复未执行：目标不在本次审计范围内。")
            return
        try:
            preview = preview_openai_base_url_replacement(target)
        except (OSError, TypeError, ValueError):
            self.status_label.setText("固定修复预览失败：目标不是允许的 OpenAI 地址配置。")
            return
        answer = QMessageBox.question(
            self,
            "确认固定修复",
            (
                f"目标文件：{preview.target_name}\n"
                f"原始 SHA-256：{preview.target_sha256}\n"
                f"替换 SHA-256：{preview.replacement_sha256}\n"
                "将创建同目录备份并原子替换。是否继续？"
            ),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        result = apply_openai_base_url_replacement(
            target,
            expected_sha256=preview.target_sha256,
            confirmed=True,
        )
        if result.status is not RemediationStatus.APPLIED:
            limits = "、".join(result.limits) or "unknown"
            self.status_label.setText(f"固定修复未执行：{limits}。")
            return
        if result.resulting_sha256 is None:
            self.status_label.setText("固定修复未执行：结果校验缺失。")
            return
        self._last_remediation = (target, result.resulting_sha256)
        self._invalidate_report(preserve_remediation=True)
        self.status_label.setText(
            f"固定修复已应用：{result.target_name}；请重新审计。"
        )
        self.coverage_status_label.setText(
            "原报告已失效；仅可回滚本次会话中未被改动的固定替换。"
        )
        self._update_disposition_commands()

    def _rollback_fixed_remediation(self) -> None:
        state = self._last_remediation
        if state is None:
            return
        target, expected_replacement_sha256 = state
        answer = QMessageBox.question(
            self,
            "确认回滚固定修复",
            "将恢复同目录备份；如果目标文件已被改动，回滚会被拒绝。是否继续？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        result = rollback_fixed_replacement(
            target,
            expected_replacement_sha256=expected_replacement_sha256,
        )
        if result.status is RemediationStatus.ROLLED_BACK:
            self._last_remediation = None
            self.rollback_button.setEnabled(False)
            self.status_label.setText(f"固定修复已回滚：{result.target_name}。")
            self.coverage_status_label.setText("请重新审计以生成新的报告。")
            return
        limits = "、".join(result.limits) or "unknown"
        self.status_label.setText(f"固定修复未回滚：{limits}。")

    def _refresh_disposition_ui(self, now: datetime) -> None:
        evaluation_time = _validated_evaluation_time(now)
        records = disposition_index(self._dispositions)
        for row, finding in enumerate(self._row_findings):
            state = evaluate_disposition(
                finding,
                records,
                now=evaluation_time,
            ).state
            item = self.findings_table.item(row, 4)
            if item is None:
                item = QTableWidgetItem()
                self.findings_table.setItem(row, 4, item)
            item.setText(_translate(_STATUS_LABELS[state], self._language))
        self._update_disposition_commands()

    def _finding_source_contexts(self) -> dict[tuple[str, str], FindingSourceContext]:
        outcome = self._audit_outcome
        if outcome is None:
            return {}
        return {
            (context.root_fingerprint, context.evidence_fingerprint): context
            for context in outcome.source_contexts
        }

    def _finding_detail_lines(self, finding: Finding) -> list[str]:
        context_index = self._finding_source_contexts()
        applications: list[str] = []
        roots: list[str] = []
        source_files: list[str] = []
        masked_evidence: list[str] = []
        identification = "无法仅凭所选目录确认具体应用；请根据来源文件在原应用中核对。"
        for evidence in finding.evidence:
            masked_evidence.append(evidence.masked)
            context = context_index.get(
                (finding.root_fingerprint, evidence.fingerprint)
            )
            if context is None:
                applications.append(_SOURCE_APPLICATION_LABELS["custom"])
                roots.append("未提供")
                source_files.append(evidence.source)
                continue
            applications.append(
                _SOURCE_APPLICATION_LABELS.get(
                    context.application_key,
                    _SOURCE_APPLICATION_LABELS["custom"],
                )
            )
            roots.append(context.root_name)
            source_files.append(context.source_file)
            if context.application_key not in {"custom", "clipboard"}:
                identification = "根据审计根目录识别；仍需在原应用中确认。"
            elif context.application_key == "clipboard":
                identification = "一次性剪贴板输入，不对应本地应用配置。"

        def unique(values: Iterable[str]) -> tuple[str, ...]:
            return tuple(dict.fromkeys(values))

        applications_unique = unique(applications) or (
            _SOURCE_APPLICATION_LABELS["custom"],
        )
        roots_unique = unique(roots) or ("未提供",)
        files_unique = unique(source_files) or tuple(
            evidence.source for evidence in finding.evidence
        )
        evidence_unique = unique(masked_evidence)
        application_text = "、".join(applications_unique)
        source_text = "、".join(files_unique)
        evidence_text = "、".join(evidence_unique)
        primary_application = applications_unique[0]
        primary_source = files_unique[0] if files_unique else "未知文件"
        return [
            "风险详情",
            f"所属应用：{application_text}",
            f"程序识别：{identification}",
            f"来源文件：{source_text}",
            f"所在审计范围：{'、'.join(roots_unique)}",
            f"规则：{finding.rule_id}",
            f"风险域：{_DOMAIN_FILTER_LABELS[finding.domain]}",
            f"严重性：{_SEVERITY_FILTER_LABELS[finding.severity]}",
            f"已掩码证据：{evidence_text}",
            f"处理位置：在 {primary_application}中核对 {primary_source}；处理后请回到原应用重新审计。",
            "出于隐私保护，界面不显示完整本地路径。",
            "",
        ]

    def _show_guidance(self) -> None:
        row = self.findings_table.currentRow()
        if not 0 <= row < len(self._row_findings):
            if self.findings_count_label.text() == _FILTER_ERROR_MESSAGE:
                message = _FILTER_ERROR_MESSAGE
            elif (
                self._audit_outcome is not None
                and self._audit_outcome.findings
                and self.findings_table.rowCount() == 0
            ):
                message = _FILTER_EMPTY_MESSAGE
            else:
                message = _FINDING_SELECTION_MESSAGE
            self.guidance_browser.setPlainText(message)
            return
        finding = self._row_findings[row]
        try:
            provider = "openai" if finding.rule_id.startswith("OPENAI_") else None
            plan = guidance_for(
                finding.rule_id,
                finding.root_fingerprint,
                provider=provider,
            )
        except (TypeError, ValueError):
            self.guidance_browser.setPlainText("无法生成修复步骤。")
            return
        lines = [
            *self._finding_detail_lines(finding),
            "人工修复步骤",
            "",
            *(f"{index}. {step}" for index, step in enumerate(plan.steps, 1)),
            "",
            "验证：",
            *plan.verification_steps,
        ]
        self.guidance_browser.setPlainText("\n".join(lines))

    def _review_guidance(self) -> None:
        self._switch_view(1)
        if self.findings_table.rowCount() and self.findings_table.currentRow() < 0:
            self.findings_table.selectRow(0)
        self.findings_table.setFocus(Qt.FocusReason.OtherFocusReason)
        self._show_guidance()

    def _set_disposition(self, preselected: DispositionStatus) -> None:
        try:
            finding = self._selected_finding()
            if finding is None or self._audit_outcome is None:
                return
            dialog_opened_at = _validated_evaluation_time(_utc_now())
            dialog = _DispositionDialog(self, preselected, dialog_opened_at)
            if dialog.exec() != QDialog.DialogCode.Accepted:
                return
            status, reason, reviewer, expires_at = dialog.values()
            if not self._confirm_invalid_state_replacement():
                return
            commit_now = _validated_evaluation_time(_utc_now())
            expiry = parse_utc(expires_at)
            if (
                not commit_now < expiry
                or expiry - commit_now > timedelta(days=366)
            ):
                raise ValueError
            record = DispositionRecord(
                disposition_ref=finding.disposition_ref,
                rule_id=finding.rule_id,
                status=status,
                reason=reason,
                reviewer=reviewer,
                created_at=_canonical_utc_seconds(commit_now),
                expires_at=expires_at,
            )
            candidate = upsert_disposition(self._dispositions, record)
        except Exception:  # noqa: BLE001 - fixed user callback boundary
            self._show_save_failure()
            return
        self._save_and_commit_dispositions(candidate, commit_now)

    def _withdraw_disposition(self) -> None:
        try:
            finding = self._selected_finding()
            if finding is None or self._audit_outcome is None:
                return
            record = disposition_index(self._dispositions).get(finding.disposition_ref)
            if record is None or record.rule_id != finding.rule_id:
                return
            answer = QMessageBox.question(
                self,
                "撤销处置",
                "是否撤销此风险发现的处置记录？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
            if not self._confirm_invalid_state_replacement():
                return
            commit_now = _validated_evaluation_time(_utc_now())
            candidate = withdraw_disposition(
                self._dispositions,
                finding.disposition_ref,
            )
        except Exception:  # noqa: BLE001 - fixed user callback boundary
            self._show_save_failure()
            return
        self._save_and_commit_dispositions(candidate, commit_now)

    def _save_and_commit_dispositions(
        self,
        candidate: tuple[DispositionRecord, ...],
        now: datetime,
    ) -> None:
        try:
            outcome, snapshot, selected_row = self._prepare_disposition_transaction(
                candidate,
                now,
            )
            save_protected_state(snapshot)
        except Exception:  # noqa: BLE001 - persistence failure boundary ends here
            self._show_save_failure()
            return
        # A successful protected save is authoritative before any fallible UI work.
        self._dispositions = candidate
        self._protected_state_invalid = False
        self._audit_outcome = outcome
        self.report_json = outcome.report_json
        self.report_html = outcome.report_html
        try:
            self._refresh_reviewed_ui_no_throw(
                outcome.evaluated_at,
                selected_row,
                failure_message=_SAVED_REFRESH_FAILURE,
            )
        except Exception:
            pass

    def _prepare_disposition_transaction(
        self,
        candidate: tuple[DispositionRecord, ...],
        now: datetime,
    ) -> tuple[AuditOutcome, EvidenceSnapshot, int]:
        outcome = self._reviewed_outcome(candidate, now)
        snapshot = self._build_protected_snapshot(candidate, now)
        return outcome, snapshot, self.findings_table.currentRow()

    def _build_protected_snapshot(
        self,
        records: tuple[DispositionRecord, ...],
        now: datetime,
    ) -> EvidenceSnapshot:
        outcome = self._audit_outcome
        if outcome is None:
            raise ValueError(_CONTEXT_ERROR)
        return build_snapshot(
            outcome.findings,
            outcome.score,
            rule_version=outcome.rule_version,
            captured_at=now,
            disposition_key=self._disposition_key,
            dispositions=records,
        )

    def _confirm_invalid_state_replacement(self) -> bool:
        if not self._protected_state_invalid:
            return True
        answer = QMessageBox.question(
            self,
            "替换无效状态",
            "是否用当前审计状态替换无效的加密状态？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        return answer == QMessageBox.StandardButton.Yes

    def _show_save_failure(self) -> None:
        QMessageBox.warning(self, _SAVE_FAILURE_TITLE, _SAVE_FAILURE_MESSAGE)

    def _reviewed_outcome(
        self,
        records: tuple[DispositionRecord, ...],
        now: datetime,
    ) -> AuditOutcome:
        outcome = self._audit_outcome
        if outcome is None:
            raise ValueError(_CONTEXT_ERROR)
        evaluation_time = _validated_evaluation_time(now)
        reviewed_score = score(
            reviewed_findings(
                outcome.findings,
                disposition_index(records),
                now=evaluation_time,
            ),
            coverage=outcome.score.coverage,
            confidence=outcome.score.confidence,
            limits=outcome.score.limits,
        )
        report_json = render_json(
            outcome.score,
            outcome.findings,
            rule_version=outcome.rule_version,
            reviewed_score=reviewed_score,
            dispositions=records,
            evaluated_at=evaluation_time,
        )
        report_html = render_html(
            outcome.score,
            outcome.findings,
            rule_version=outcome.rule_version,
            reviewed_score=reviewed_score,
            dispositions=records,
            evaluated_at=evaluation_time,
            language=self._language,
        )
        return AuditOutcome(
            findings=outcome.findings,
            score=outcome.score,
            reviewed_score=reviewed_score,
            evaluated_at=evaluation_time,
            rule_version=outcome.rule_version,
            report_json=report_json,
            report_html=report_html,
            scanned_roots=outcome.scanned_roots,
            source_contexts=outcome.source_contexts,
        )

    def _refresh_reviewed_ui_no_throw(
        self,
        now: datetime,
        selected_row: int,
        *,
        failure_message: str,
    ) -> None:
        failed = False
        selected_finding = (
            self._row_findings[selected_row]
            if 0 <= selected_row < len(self._row_findings)
            else None
        )
        try:
            self._refresh_finding_view(
                now,
                selected_finding=selected_finding,
                restore_selection=False,
            )
        except _FindingFilterCallbackError:
            failed = True
            try:
                self._show_filter_failure()
            except Exception:
                pass
        except Exception:  # noqa: BLE001 - independent status fallback
            failed = True
            try:
                for row in range(self.findings_table.rowCount()):
                    self.findings_table.item(row, 4).setText(_STATUS_REFRESH_FALLBACK)
                self._update_disposition_commands()
            except Exception:
                pass
        try:
            self._refresh_report()
        except Exception:  # noqa: BLE001 - independent report fallback
            failed = True
            try:
                self.report_browser.setPlainText(_REPORT_REFRESH_FALLBACK)
            except Exception:
                pass
        self._refresh_comparison_for_current_report()
        try:
            if (
                selected_finding is not None
                and any(
                    finding is selected_finding for finding in self._row_findings
                )
            ):
                selected_row = next(
                    row
                    for row, finding in enumerate(self._row_findings)
                    if finding is selected_finding
                )
                self.findings_table.selectRow(selected_row)
        except Exception:  # noqa: BLE001 - preserve the existing selection
            failed = True
        try:
            self._schedule_expiry_timer(now)
        except Exception:  # noqa: BLE001 - bounded timer fallback
            failed = True
            self._start_expiry_retry_no_throw()
        if failed:
            self._indicate_refresh_failure_no_throw(failure_message)
        else:
            if self._refresh_failure_notified and self._audit_outcome is not None:
                try:
                    self.status_label.setText(_audit_status_text(self._audit_outcome))
                except Exception:
                    return
            self._refresh_failure_notified = False

    def _start_expiry_retry_no_throw(self) -> None:
        try:
            self._expiry_timer.stop()
        except Exception:
            pass
        try:
            self._expiry_timer.start(_EXPIRY_RETRY_MS)
        except Exception:
            pass

    def _indicate_refresh_failure_no_throw(self, message: str) -> None:
        if self._refresh_failure_notified:
            return
        self._refresh_failure_notified = True
        try:
            self.status_label.setText(message)
        except Exception:
            pass

    def _schedule_expiry_timer(self, now: datetime | None = None) -> None:
        self._expiry_timer.stop()
        if self._audit_outcome is None:
            return
        evaluation_time = _validated_evaluation_time(
            _utc_now() if now is None else now
        )
        records = disposition_index(self._dispositions)
        expiries = []
        for finding in self._audit_outcome.findings:
            evaluation = evaluate_disposition(
                finding,
                records,
                now=evaluation_time,
            )
            if evaluation.state in {
                DispositionStatus.FALSE_POSITIVE.value,
                DispositionStatus.ACCEPTED_RISK.value,
            }:
                expiries.append(parse_utc(evaluation.record.expires_at))
        if not expiries:
            return
        remaining_ms = ceil(
            (min(expiries) - evaluation_time).total_seconds() * 1000
        )
        self._expiry_timer.start(
            max(1, min(remaining_ms, _EXPIRY_TIMER_CAP_MS))
        )

    @Slot()
    def _handle_expiry_timeout(self) -> None:
        try:
            if self._audit_outcome is None:
                try:
                    self._expiry_timer.stop()
                except Exception:
                    pass
                return
            now = _validated_evaluation_time(_utc_now())
            selected_row = self.findings_table.currentRow()
            outcome = self._reviewed_outcome(self._dispositions, now)
        except Exception:  # noqa: BLE001 - fixed timer callback boundary
            self._start_expiry_retry_no_throw()
            self._indicate_refresh_failure_no_throw(_TIMER_REFRESH_FAILURE)
            return
        self._audit_outcome = outcome
        self.report_json = outcome.report_json
        self.report_html = self._localized_report_html(outcome)
        try:
            self._refresh_reviewed_ui_no_throw(
                outcome.evaluated_at,
                selected_row,
                failure_message=_TIMER_REFRESH_FAILURE,
            )
        except Exception:
            pass

    def _refresh_report(self) -> None:
        if self.report_mode_combo.currentText() == "JSON":
            self.report_browser.setPlainText(self.report_json or "尚无审计报告。")
        else:
            self.report_browser.setHtml(self.report_html or "<p>尚无审计报告。</p>")

    def _export_report(self) -> None:
        mode = self.report_mode_combo.currentText()
        suffix = "json" if mode == "JSON" else "html"
        path, _selected_filter = QFileDialog.getSaveFileName(
            self,
            "导出新报告",
            f"agentguardian-report.{suffix}",
            f"{mode} (*.{suffix})",
        )
        if not path:
            return
        content = self.report_json if mode == "JSON" else self.report_html
        try:
            export_new_report(path, content, self._report_roots)
        except (OSError, PermissionError, TypeError, ValueError):
            QMessageBox.warning(self, "导出失败", "无法导出报告。")
            return
        QMessageBox.information(self, "导出完成", "报告已导出。")

    def _save_protected_state(self) -> None:
        try:
            if self._audit_outcome is None:
                return
            if not self._confirm_invalid_state_replacement():
                return
            commit_now = _validated_evaluation_time(_utc_now())
            snapshot = self._build_protected_snapshot(
                self._dispositions,
                commit_now,
            )
            save_protected_state(snapshot)
        except Exception:  # noqa: BLE001 - fixed user callback boundary
            self._show_save_failure()
            return
        self._protected_state_invalid = False
        QMessageBox.information(
            self,
            "保存完成",
            "加密状态已保存到当前 Windows 用户。",
        )

    def closeEvent(self, event) -> None:
        if self._thread is not None and self._thread.isRunning():
            self.status_label.setText("审计仍在进行，请等待完成。")
            event.ignore()
            return
        self._expiry_timer.stop()
        super().closeEvent(event)


def _heading(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("heading")
    return label


def _stylesheet() -> str:
    return f"""
        QMainWindow {{
            background: {COLOR_TOKENS["obsidian"]};
            color: {COLOR_TOKENS["cloud"]};
            font-family: "Microsoft YaHei";
            font-size: 12px;
            letter-spacing: 0px;
        }}
        QWidget {{
            color: {COLOR_TOKENS["cloud"]};
            font-family: "Microsoft YaHei";
            font-size: 12px;
            letter-spacing: 0px;
        }}
        QWidget#mainContent {{ background: {COLOR_TOKENS["obsidian"]}; }}
        QFrame#sidebar {{
            background: #101827;
            border-right: 1px solid {COLOR_TOKENS["border"]};
        }}
        QLabel#brand {{
            color: {COLOR_TOKENS["cloud"]};
            font-size: 14px;
            font-weight: 700;
            padding: 8px 6px 16px 6px;
        }}
        QPushButton {{
            background: #172235;
            border: 1px solid {COLOR_TOKENS["border"]};
            border-radius: 7px;
            color: {COLOR_TOKENS["cloud"]};
            min-height: 34px;
            padding: 4px 12px;
        }}
        QPushButton:hover {{ background: #1B2A40; border-color: #55708D; }}
        QPushButton:disabled {{ color: {COLOR_TOKENS["muted"]}; }}
        QPushButton#navigation {{
            border: 0;
            border-radius: 7px;
            text-align: left;
            padding-left: 12px;
            min-height: 40px;
        }}
        QPushButton#navigation:checked {{
            background: #20344D;
            color: {COLOR_TOKENS["cloud"]};
            border-left: 3px solid #57B9FF;
        }}
        QPushButton#primaryAction {{
            background: {COLOR_TOKENS["trust"]};
            border-color: {COLOR_TOKENS["trust"]};
            color: #071B17;
            font-weight: 600;
        }}
        QFrame#trustStrip {{
            background: #101827;
            border-bottom: 1px solid {COLOR_TOKENS["border"]};
        }}
        QFrame#trustStrip QLabel {{ color: {COLOR_TOKENS["muted"]}; font-size: 11px; }}
        QLabel#localMode {{ color: {COLOR_TOKENS["trust"]}; font-weight: 600; }}
        QLabel#heading {{ font-size: 22px; font-weight: 700; padding-bottom: 3px; }}
        QLabel#rootDisplay, QLabel#status {{
            background: {COLOR_TOKENS["surface"]};
            border: 1px solid {COLOR_TOKENS["border"]};
            border-radius: 8px;
            color: {COLOR_TOKENS["cloud"]};
            padding: 9px 12px;
        }}
        QTableWidget, QTextBrowser, QComboBox, QLineEdit, QDateTimeEdit {{
            background: {COLOR_TOKENS["surface"]};
            border: 1px solid {COLOR_TOKENS["border"]};
            border-radius: 7px;
            color: {COLOR_TOKENS["cloud"]};
            selection-background-color: {COLOR_TOKENS["border"]};
        }}
        QTableWidget::item {{ padding: 7px; }}
        QHeaderView::section {{
            background: #18253A;
            border: 0;
            border-bottom: 1px solid {COLOR_TOKENS["border"]};
            color: {COLOR_TOKENS["muted"]};
            padding: 8px;
        }}
        QComboBox {{ min-width: 92px; min-height: 28px; padding: 4px 9px; }}
        QComboBox QAbstractItemView {{
            background: {COLOR_TOKENS["surface"]};
            color: {COLOR_TOKENS["cloud"]};
            selection-background-color: {COLOR_TOKENS["border"]};
        }}
        QCheckBox {{ spacing: 9px; }}
        QCheckBox::indicator {{ width: 17px; height: 17px; }}
        QCheckBox::indicator:checked {{ background: #258DCA; border: 1px solid #64C5FF; border-radius: 4px; }}
        QScrollArea {{ border: 0; background: {COLOR_TOKENS["obsidian"]}; }}
        QWidget#aboutContent {{ background: {COLOR_TOKENS["obsidian"]}; }}
        QWidget#solutionContent {{ background: {COLOR_TOKENS["obsidian"]}; }}
        QFrame#solutionIntro {{ background: #14243A; border: 1px solid #315273; border-radius: 12px; }}
        QFrame#solutionCard {{ background: {COLOR_TOKENS["surface"]}; border: 1px solid {COLOR_TOKENS["border"]}; border-radius: 10px; }}
        QLabel#solutionStepNumber {{ background: #173C5B; border: 1px solid #3A78A5; border-radius: 19px; color: #8BD5FF; font-weight: 700; }}
        QLabel#solutionStepTitle {{ color: {COLOR_TOKENS["cloud"]}; font-size: 14px; font-weight: 700; }}
        QLabel#solutionStepBody, QLabel#solutionIntroText {{ color: #B8C7D9; }}
        QLabel#solutionIntroTitle {{ color: {COLOR_TOKENS["cloud"]}; font-size: 15px; font-weight: 700; }}
        QScrollArea#solutionScrollArea QScrollBar:vertical {{ background: #101827; width: 8px; margin: 2px; }}
        QScrollArea#solutionScrollArea QScrollBar::handle:vertical {{ background: #405875; border-radius: 4px; min-height: 30px; }}
        QScrollArea#solutionScrollArea QScrollBar::add-line:vertical, QScrollArea#solutionScrollArea QScrollBar::sub-line:vertical {{ height: 0; }}
        QFrame#aboutHero {{ background: #14243A; border: 1px solid #29425F; border-radius: 14px; }}
        QFrame#aboutCard {{ background: {COLOR_TOKENS["surface"]}; border: 1px solid {COLOR_TOKENS["border"]}; border-radius: 12px; }}
        QLabel#aboutPoster {{ background: #0D1421; border: 1px solid {COLOR_TOKENS["border"]}; border-radius: 8px; }}
        QLabel#authorEyebrow {{ color: #6FC5FF; font-size: 11px; font-weight: 700; }}
        QLabel#authorName {{ font-size: 30px; font-weight: 700; color: {COLOR_TOKENS["cloud"]}; }}
        QLabel#authorSubtitle {{ color: #B3C3D6; font-size: 14px; }}
        QLabel#authorTagline {{ font-size: 19px; font-weight: 700; color: #73CAFF; padding-top: 5px; }}
        QLabel#contactCardTitle {{ color: {COLOR_TOKENS["cloud"]}; font-size: 14px; font-weight: 700; padding-bottom: 3px; }}
        QLabel#contactLabel, QLabel#languageLabel {{ color: {COLOR_TOKENS["muted"]}; font-weight: 600; }}
        QLabel#contactValue {{ color: #E6EDF7; font-size: 14px; }}
        QLabel#contactValue a {{ color: #79C8FF; text-decoration: none; }}
        QComboBox#languageSelector {{ min-width: 132px; }}
    """


def create_window() -> AgentGuardianWindow:
    return AgentGuardianWindow()


def run_maintenance_command(arguments: list[str]) -> int | None:
    if arguments != ["--purge-protected-state"]:
        return None
    try:
        removed = purge_protected_state()
    except StateStoreError:
        if sys.stdout is not None:
            sys.stdout.write(
                '{"error":"PROTECTED_STATE_PURGE_FAILED","status":"fail"}\n'
            )
        return 1
    result = "removed" if removed else "absent"
    if sys.stdout is not None:
        sys.stdout.write(f'{{"result":"{result}","status":"pass"}}\n')
    return 0


def main() -> int:
    maintenance_status = run_maintenance_command(sys.argv[1:])
    if maintenance_status is not None:
        return maintenance_status
    application = QApplication.instance() or QApplication(sys.argv)
    window = create_window()
    window.show()
    return application.exec()
