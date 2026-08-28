import json
import os
import secrets
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from itertools import islice
from pathlib import Path

from .clipboard_audit import ClipboardAuditResult, audit_clipboard_once
from .detectors import MAX_FILE_BYTES, detect_file, detect_mcp_config, load_rules
from .discovery import discover_files
from .dispositions import (
    DispositionRecord,
    disposition_index,
    reviewed_findings,
)
from .domain import MAX_REPORT_EVIDENCE, MAX_REPORT_FINDINGS, Finding, Score
from .reporting import render_html, render_json
from .scoring import score
from .workflow import ScopePreview, build_scope_preview

MAX_AUDIT_FINDINGS = MAX_REPORT_FINDINGS
MAX_AUDIT_EVIDENCE = MAX_REPORT_EVIDENCE
_CONTEXT_ERROR = "invalid disposition context"


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
        return evaluated_at.replace(tzinfo=timezone.utc, microsecond=0)
    except Exception:
        pass
    raise ValueError(_CONTEXT_ERROR) from None


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


def _is_unc_path(path: str | Path) -> bool:
    value = os.fspath(path)
    return value.startswith(("\\\\", "//"))


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


def run_file_audit(
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


def run_clipboard_audit(
    reader: Callable[[], str],
    *,
    disposition_key: bytes,
    dispositions: Iterable[DispositionRecord] = (),
    evaluated_at: datetime | None = None,
) -> tuple[ClipboardAuditResult, AuditOutcome | None]:
    evaluation_time = (
        _validated_evaluation_time(evaluated_at)
        if evaluated_at is not None
        else None
    )
    context = _validated_disposition_context(
        disposition_key,
        dispositions,
        max_records=MAX_AUDIT_FINDINGS,
    )
    result = audit_clipboard_once(
        reader,
        scan_key=_generate_key(),
        disposition_key=context.key,
    )
    if not result.scanned:
        return result, None
    if evaluation_time is None:
        evaluation_time = _validated_evaluation_time(_utc_now())
    audit_score = score(
        result.findings,
        coverage=1.0,
        confidence=1.0,
        limits=result.limits,
    )
    records = {record.disposition_ref: record for record in context.records}
    reviewed_score = score(
        reviewed_findings(result.findings, records, now=evaluation_time),
        coverage=1.0,
        confidence=1.0,
        limits=result.limits,
    )
    rule_version = load_rules().version
    outcome = AuditOutcome(
        findings=result.findings,
        score=audit_score,
        reviewed_score=reviewed_score,
        evaluated_at=evaluation_time,
        rule_version=rule_version,
        report_json=render_json(
            audit_score,
            result.findings,
            rule_version=rule_version,
            reviewed_score=reviewed_score,
            dispositions=context.records,
            evaluated_at=evaluation_time,
        ),
        report_html=render_html(
            audit_score,
            result.findings,
            rule_version=rule_version,
            reviewed_score=reviewed_score,
            dispositions=context.records,
            evaluated_at=evaluation_time,
        ),
        scanned_roots=(),
    )
    return result, outcome
