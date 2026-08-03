import json
import os
import secrets
import stat
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from itertools import islice
from math import ceil
from pathlib import Path

from PySide6.QtCore import (
    QDateTime,
    QObject,
    Qt,
    QThread,
    QTimeZone,
    QTimer,
    Signal,
    Slot,
)
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDateTimeEdit,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QStyle,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from .detectors import MAX_FILE_BYTES, detect_file, detect_mcp_config, load_rules
from .discovery import discover_files
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
from .domain import Finding, RiskDomain, Score, Severity, validate_safe_annotation
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
from .reporting import render_html, render_json
from .scoring import score
from .state_store import StateStoreError, load_protected_state, save_protected_state
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

COLOR_TOKENS = {
    "obsidian": "#0F1215",
    "surface": "#171C20",
    "border": "#394149",
    "cloud": "#F4F6F7",
    "trust": "#21C786",
    "muted": "#AAB4BB",
    "warning": "#F0BD5C",
    "critical": "#EF7167",
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
MAX_AUDIT_FINDINGS = 2000
MAX_AUDIT_EVIDENCE = 4000
MAX_AUDIT_FILES = 10_000
MAX_AUDIT_ENTRIES = 50_000
MAX_AUDIT_BYTES = 512 * 1024 * 1024
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
_FILTER_EMPTY_MESSAGE = "当前筛选条件下无匹配风险发现。"
_FILTER_ERROR_MESSAGE = "无法筛选风险发现，请重试。"
_FINDING_SELECTION_MESSAGE = "选择一项风险以查看人工步骤。"


class _FindingFilterCallbackError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class _DispositionContext:
    key: bytes = field(repr=False)
    records: tuple[DispositionRecord, ...]
    invalid_state: bool


@dataclass(frozen=True, slots=True)
class AuditOutcome:
    findings: tuple[Finding, ...]
    score: Score
    reviewed_score: Score
    evaluated_at: datetime
    rule_version: str
    report_json: str
    report_html: str
    scanned_roots: tuple[Path, ...] = field(repr=False)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


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


def _validated_audit_preview(
    roots: tuple[Path, ...],
    preview: object,
) -> ScopePreview:
    try:
        if type(preview) is not ScopePreview:
            raise ValueError
        rebuilt = build_scope_preview(
            roots,
            preview.selectors,
            max_files=preview.max_files,
            max_entries=preview.max_entries,
            max_bytes=preview.max_bytes,
            max_findings=preview.max_findings,
            max_evidence=preview.max_evidence,
        )
        if preview != rebuilt:
            raise ValueError
        return preview
    except Exception:
        pass
    raise ValueError("SCOPE_PREVIEW_INVALID") from None


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
        self.button_box.button(QDialogButtonBox.StandardButton.Ok).setText("确定")
        self.button_box.button(QDialogButtonBox.StandardButton.Cancel).setText("取消")
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


def _generate_key() -> bytes:
    try:
        key = secrets.token_bytes(32)
        if type(key) is not bytes or len(key) != 32:
            raise ValueError
        return key
    except Exception:
        pass
    raise ValueError(_CONTEXT_ERROR) from None


def _validated_disposition_context(
    key: object,
    records: Iterable[DispositionRecord],
    *,
    max_records: int = MAX_AUDIT_FINDINGS,
) -> _DispositionContext:
    try:
        if (
            type(key) is not bytes
            or len(key) != 32
            or type(max_records) is not int
            or max_records <= 0
        ):
            raise ValueError
        items = tuple(islice(records, max_records + 1))
        if len(items) > max_records:
            raise ValueError
        rebuilt = []
        for record in items:
            if type(record) is not DispositionRecord:
                raise ValueError
            rebuilt.append(
                DispositionRecord(
                    record.disposition_ref,
                    record.rule_id,
                    record.status,
                    record.reason,
                    record.reviewer,
                    record.created_at,
                    record.expires_at,
                )
            )
        ordered = tuple(disposition_index(rebuilt).values())
        return _DispositionContext(key, ordered, False)
    except Exception:
        pass
    raise ValueError(_CONTEXT_ERROR) from None


def _validated_evaluation_time(value: datetime | None) -> datetime:
    try:
        evaluated_at = datetime.now(timezone.utc) if value is None else value
        if type(evaluated_at) is not datetime or evaluated_at.tzinfo is None:
            raise ValueError
        offset = evaluated_at.utcoffset()
        if type(offset) is not timedelta or offset != timedelta(0):
            raise ValueError
        return evaluated_at.replace(tzinfo=timezone.utc)
    except Exception:
        pass
    raise ValueError(_CONTEXT_ERROR) from None


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


def _is_unc_path(path: str | Path) -> bool:
    value = os.fspath(path)
    return value.startswith(("\\\\", "//"))


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


def _read_limited_json(path: Path) -> object:
    with open(path, "rb") as stream:
        data = stream.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise ValueError("JSON file limit exceeded")
    return json.loads(data)


def _append_finding_batch(
    aggregate: list[Finding],
    seen: set[Finding],
    batch: Iterable[Finding],
    evidence_count: int,
    *,
    max_findings: int,
    max_evidence: int,
) -> tuple[int, bool]:
    for finding in batch:
        if finding in seen:
            continue
        next_evidence_count = evidence_count + len(finding.evidence)
        if (
            len(aggregate) >= max_findings
            or next_evidence_count > max_evidence
        ):
            return evidence_count, False
        aggregate.append(finding)
        seen.add(finding)
        evidence_count = next_evidence_count
    return evidence_count, True


def _run_audit(
    roots: tuple[Path, ...],
    *,
    scope_preview: ScopePreview,
    disposition_key: bytes,
    dispositions: Iterable[DispositionRecord] = (),
    evaluated_at: datetime | None = None,
) -> AuditOutcome:
    frozen_roots = tuple(Path(os.path.abspath(root)) for root in roots)
    if any(_is_unc_path(root) for root in frozen_roots):
        raise ValueError("UNC scan roots are not allowed")
    accepted_preview = _validated_audit_preview(frozen_roots, scope_preview)
    evaluation_time = (
        _validated_evaluation_time(evaluated_at)
        if evaluated_at is not None
        else None
    )
    disposition_context = _validated_disposition_context(
        disposition_key,
        dispositions,
        max_records=accepted_preview.max_findings,
    )
    local_disposition_key = disposition_context.key
    frozen_dispositions = disposition_context.records
    disposition_records = {
        record.disposition_ref: record for record in frozen_dispositions
    }
    scan_key = _generate_key()
    discovery = discover_files(
        list(frozen_roots),
        accepted_preview.selectors,
        max_files=accepted_preview.max_files,
        max_entries=accepted_preview.max_entries,
    )
    files = list(discovery.files)
    findings: list[Finding] = []
    seen_findings: set[Finding] = set()
    limits = list(discovery.limits)
    scanned = 0
    scanned_bytes = 0
    evidence_count = 0

    for candidate in files:
        path = Path(os.path.abspath(candidate))
        try:
            file_bytes = path.stat().st_size
        except OSError:
            limits.append("file_scan_limited")
            continue
        if scanned_bytes + file_bytes > accepted_preview.max_bytes:
            limits.append("byte_limit_reached")
            break
        scanned_bytes += file_bytes
        try:
            result = detect_file(
                path,
                scan_key=scan_key,
                disposition_key=local_disposition_key,
            )
        except Exception:  # noqa: BLE001 - never expose scan exception text
            limits.append("file_scan_limited")
            continue
        evidence_count, batch_complete = _append_finding_batch(
            findings,
            seen_findings,
            result.findings,
            evidence_count,
            max_findings=accepted_preview.max_findings,
            max_evidence=accepted_preview.max_evidence,
        )
        if not batch_complete:
            limits.append("finding_limit_reached")
            break
        limits.extend(result.limits)
        if "finding_limit_reached" in result.limits:
            break
        if not result.scanned:
            continue
        if path.suffix.lower() == ".json" and result.scanned:
            try:
                config = _read_limited_json(path)
                mcp_findings = detect_mcp_config(
                    config,
                    str(path),
                    scan_key=scan_key,
                    disposition_key=local_disposition_key,
                )
            except Exception:  # noqa: BLE001 - never expose parser exception text
                limits.append("mcp_config_scan_limited")
                continue
            evidence_count, batch_complete = _append_finding_batch(
                findings,
                seen_findings,
                mcp_findings,
                evidence_count,
                max_findings=accepted_preview.max_findings,
                max_evidence=accepted_preview.max_evidence,
            )
            if not batch_complete:
                limits.append("finding_limit_reached")
                break
        scanned += 1

    if evaluation_time is None:
        evaluation_time = _validated_evaluation_time(_utc_now())

    coverage_denominator = len(files) + bool(discovery.limits)
    if coverage_denominator:
        coverage = scanned / coverage_denominator
    else:
        coverage = 0.0
        limits.append("no_supported_files")
    unique_limits = tuple(dict.fromkeys(limits))
    frozen_findings = tuple(findings)
    confidence = 1.0
    audit_score = score(
        frozen_findings,
        coverage=coverage,
        confidence=confidence,
        limits=unique_limits,
    )
    rule_version = load_rules().version
    reviewed_score = score(
        reviewed_findings(
            frozen_findings,
            disposition_records,
            now=evaluation_time,
        ),
        coverage=coverage,
        confidence=confidence,
        limits=unique_limits,
    )
    return AuditOutcome(
        findings=frozen_findings,
        score=audit_score,
        reviewed_score=reviewed_score,
        evaluated_at=evaluation_time,
        rule_version=rule_version,
        report_json=render_json(
            audit_score,
            frozen_findings,
            rule_version=rule_version,
            reviewed_score=reviewed_score,
            dispositions=frozen_dispositions,
            evaluated_at=evaluation_time,
        ),
        report_html=render_html(
            audit_score,
            frozen_findings,
            rule_version=rule_version,
            reviewed_score=reviewed_score,
            dispositions=frozen_dispositions,
            evaluated_at=evaluation_time,
        ),
        scanned_roots=frozen_roots,
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


class AgentGuardianWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        disposition_context = _load_disposition_context()
        self.setWindowTitle("AgentGuardian")
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
        self._refresh_failure_notified = False
        self._expiry_timer = QTimer(self)
        self._expiry_timer.setSingleShot(True)
        self._expiry_timer.timeout.connect(self._handle_expiry_timeout)
        self._build_ui()
        self.setStyleSheet(_stylesheet())

    def _build_ui(self) -> None:
        central = QWidget()
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
        for index, text in enumerate(("审计范围", "风险发现", "审计报告")):
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
        self.scan_button = QPushButton("开始审计")
        self.scan_button.setObjectName("primaryAction")
        self.scan_button.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPlay)
        )
        self.scan_button.setToolTip("对所选文件夹执行只读本地审计")
        self.scan_button.setEnabled(False)
        self.scan_button.clicked.connect(self._start_scan)
        actions.addWidget(self.folder_button)
        actions.addWidget(self.scan_button)
        actions.addStretch()
        layout.addLayout(actions)

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
        layout.addWidget(QLabel("人工修复步骤"))
        self.guidance_browser = QTextBrowser()
        self.guidance_browser.setMinimumHeight(120)
        self.guidance_browser.setMaximumHeight(170)
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
        self.report_browser = QTextBrowser()
        self.report_browser.setHtml("<p>尚无审计报告。</p>")
        layout.addWidget(self.report_browser, 1)
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
            preview = _scope_preview_for((root,))
        except Exception:  # noqa: BLE001 - fixed folder-selection boundary
            self._clear_scope("无法建立有效的审计范围。")
            return
        self._invalidate_report()
        self._clear_comparison_if_present()
        self._revoke_scope_consent()
        self._roots = (root,)
        self._scope_preview = preview
        self.root_display_label.setText(root.name or "所选文件夹")
        self._render_scope_preview(preview)
        self.scope_consent_checkbox.setEnabled(True)
        self._update_scan_enabled()
        self.status_label.setText("请核对范围并明确同意后开始审计。")

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
        self._update_scan_enabled()

    def _revoke_scope_consent(self) -> None:
        self._scope_consent = None
        self.scope_consent_checkbox.blockSignals(True)
        self.scope_consent_checkbox.setChecked(False)
        self.scope_consent_checkbox.blockSignals(False)
        self._update_scan_enabled()

    def _update_scan_enabled(self) -> None:
        enabled = False
        try:
            expected_preview = _scope_preview_for(self._roots)
            enabled = (
                not self.is_scanning
                and self.scope_consent_checkbox.isChecked()
                and type(self._scope_preview) is ScopePreview
                and self._scope_preview == expected_preview
                and scope_consent_matches(
                    self._scope_consent,
                    expected_preview,
                )
            )
        except Exception:
            enabled = False
        self.scan_button.setEnabled(enabled)

    def _clear_scope(self, status: str) -> None:
        self._invalidate_report()
        self._clear_comparison_if_present()
        self._roots = ()
        self._scope_preview = None
        self._revoke_scope_consent()
        self.scope_consent_checkbox.setEnabled(False)
        self.root_display_label.setText("尚未选择")
        self.scope_roots_label.setText("范围：尚未选择")
        self.status_label.setText(status)

    def _clear_comparison_if_present(self) -> None:
        if "_comparison_state" in self.__dict__:
            self._comparison_state = None

    def _start_scan(self) -> None:
        try:
            expected_preview = _scope_preview_for(self._roots)
            if (
                self.is_scanning
                or not self.scope_consent_checkbox.isChecked()
                or type(self._scope_preview) is not ScopePreview
                or self._scope_preview != expected_preview
                or not scope_consent_matches(
                    self._scope_consent,
                    expected_preview,
                )
            ):
                raise ValueError
        except Exception:  # noqa: BLE001 - fixed scan-consent boundary
            self._revoke_scope_consent()
            self.status_label.setText("请重新核对并同意当前审计范围。")
            return

        self._scope_preview = expected_preview
        self._revoke_scope_consent()
        self._clear_comparison_if_present()
        self.is_scanning = True
        self.scan_button.setEnabled(False)
        self.folder_button.setEnabled(False)
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
            self.folder_button.setEnabled(True)
            self.scan_button.setText("开始审计")
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
        self.report_html = outcome.report_html
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

    @Slot(str)
    def _scan_failed(self, _code: str) -> None:
        self._invalidate_report()
        self.status_label.setText("审计失败。")
        self.guidance_browser.setPlainText("无法生成修复步骤。")

    def _invalidate_report(self) -> None:
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
        self._update_disposition_commands()
        self._refresh_report()

    @Slot()
    def _thread_finished(self) -> None:
        self.is_scanning = False
        self.scan_button.setText("开始审计")
        self.folder_button.setEnabled(True)
        self._thread = None
        self._worker = None
        self._update_scan_enabled()

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
                    finding.severity.value,
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
            item.setText(_STATUS_LABELS[state])
        self._update_disposition_commands()

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
        self.report_html = outcome.report_html
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
        except (OSError, TypeError, ValueError):
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
        QMainWindow, QWidget {{
            background: {COLOR_TOKENS["obsidian"]};
            color: {COLOR_TOKENS["cloud"]};
            font-family: "Segoe UI", "Noto Sans SC";
            font-size: 13px;
            letter-spacing: 0px;
        }}
        QFrame#sidebar {{
            background: {COLOR_TOKENS["surface"]};
            border-right: 1px solid {COLOR_TOKENS["border"]};
        }}
        QLabel#brand {{
            color: {COLOR_TOKENS["cloud"]};
            font-size: 15px;
            font-weight: 600;
            padding: 5px 4px 12px 4px;
        }}
        QPushButton {{
            background: {COLOR_TOKENS["surface"]};
            border: 1px solid {COLOR_TOKENS["border"]};
            border-radius: 4px;
            color: {COLOR_TOKENS["cloud"]};
            min-height: 30px;
            padding: 3px 10px;
        }}
        QPushButton:hover {{ border-color: {COLOR_TOKENS["muted"]}; }}
        QPushButton:disabled {{ color: {COLOR_TOKENS["muted"]}; }}
        QPushButton#navigation {{
            border: 0;
            border-radius: 4px;
            text-align: left;
            padding-left: 10px;
        }}
        QPushButton#navigation:checked {{
            background: {COLOR_TOKENS["border"]};
            color: {COLOR_TOKENS["cloud"]};
        }}
        QPushButton#primaryAction {{
            background: {COLOR_TOKENS["trust"]};
            border-color: {COLOR_TOKENS["trust"]};
            color: {COLOR_TOKENS["obsidian"]};
            font-weight: 600;
        }}
        QFrame#trustStrip {{
            background: {COLOR_TOKENS["surface"]};
            border-bottom: 1px solid {COLOR_TOKENS["border"]};
        }}
        QFrame#trustStrip QLabel {{ color: {COLOR_TOKENS["muted"]}; }}
        QLabel#localMode {{ color: {COLOR_TOKENS["trust"]}; font-weight: 600; }}
        QLabel#heading {{ font-size: 20px; font-weight: 600; }}
        QLabel#rootDisplay, QLabel#status {{
            background: {COLOR_TOKENS["surface"]};
            border: 1px solid {COLOR_TOKENS["border"]};
            border-radius: 6px;
            color: {COLOR_TOKENS["muted"]};
            padding: 8px 10px;
        }}
        QTableWidget, QTextBrowser, QComboBox, QLineEdit, QDateTimeEdit {{
            background: {COLOR_TOKENS["surface"]};
            border: 1px solid {COLOR_TOKENS["border"]};
            border-radius: 4px;
            color: {COLOR_TOKENS["cloud"]};
            selection-background-color: {COLOR_TOKENS["border"]};
        }}
        QTableWidget::item {{ padding: 5px; }}
        QHeaderView::section {{
            background: {COLOR_TOKENS["surface"]};
            border: 0;
            border-bottom: 1px solid {COLOR_TOKENS["border"]};
            color: {COLOR_TOKENS["muted"]};
            padding: 6px;
        }}
        QComboBox {{ min-width: 92px; padding: 4px 8px; }}
        QComboBox QAbstractItemView {{
            background: {COLOR_TOKENS["surface"]};
            color: {COLOR_TOKENS["cloud"]};
            selection-background-color: {COLOR_TOKENS["border"]};
        }}
    """


def create_window() -> AgentGuardianWindow:
    return AgentGuardianWindow()


def main() -> int:
    application = QApplication.instance() or QApplication(sys.argv)
    window = create_window()
    window.show()
    return application.exec()
