import json
import os
import re
import stat
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from math import isfinite
from pathlib import Path, PureWindowsPath
from typing import Callable, TypeVar

from .dispositions import (
    DispositionRecord,
    DispositionStatus,
    evaluate_disposition,
    parse_utc,
)
from .domain import (
    MAX_REPORT_EVIDENCE,
    MAX_REPORT_FINDINGS,
    MAX_REPORT_JSON_BYTES,
    Evidence,
    Finding,
    RiskDomain,
    Score,
    Severity,
    validate_rule_id,
    validate_safe_annotation,
)
from .scoring import score as calculate_score
from .workflow import (
    COVERAGE_LIMIT_LABELS,
    SUPPORTED_USE_BOUNDARY,
    CoverageState,
    classify_coverage,
)

_ERROR = "REPORT_COMPARISON_INVALID"
_PRODUCT = "AgentGuardian"
_MAX_SCORE_ITEMS = 2_000
_PATH_TYPE = type(Path())
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
_WINDOWS_DRIVE = re.compile(r"[A-Za-z]:")
_WINDOWS_RESERVED_DEVICE_NAMES = frozenset(
    {"con", "nul", "prn", "aux", "conin$", "conout$"}
    | {f"com{number}" for number in range(1, 10)}
    | {f"lpt{number}" for number in range(1, 10)}
    | {f"{prefix}{number}" for prefix in ("com", "lpt") for number in "¹²³"}
)
_DISPOSITION_STATES = frozenset(
    ("open", "false_positive", "accepted_risk", "expired")
)
_T = TypeVar("_T")


class _InvalidReport(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ReportSummary:
    technical_score: int
    reviewed_score: int
    coverage: float
    coverage_state: CoverageState
    finding_count: int
    rule_counts: tuple[tuple[str, int], ...]
    severity_counts: tuple[tuple[str, int], ...]
    disposition_counts: tuple[tuple[str, int], ...]
    limits: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ReportComparison:
    baseline: ReportSummary
    current: ReportSummary
    technical_score_delta: int
    reviewed_score_delta: int
    coverage_delta: float
    finding_count_delta: int
    rule_count_deltas: tuple[tuple[str, int], ...]
    severity_count_deltas: tuple[tuple[str, int], ...]
    disposition_count_deltas: tuple[tuple[str, int], ...]
    added_limits: tuple[str, ...]
    resolved_limits: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _ParsedScore:
    score: Score
    coverage_state: CoverageState


def parse_report_summary(json_text: str) -> ReportSummary:
    if type(json_text) is not str:
        raise ValueError(_ERROR)
    encoding_failed = False
    try:
        encoded_size = len(json_text.encode("utf-8"))
    except UnicodeEncodeError:
        encoding_failed = True
    if encoding_failed:
        raise ValueError(_ERROR)
    if encoded_size > MAX_REPORT_JSON_BYTES:
        raise ValueError(_ERROR)
    parse_failed = False
    try:
        payload = json.loads(
            json_text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except UnicodeError:
        raise
    except (ValueError, RecursionError):
        parse_failed = True
    if parse_failed:
        raise ValueError(_ERROR)
    invalid_report = False
    try:
        return _report_summary(payload)
    except _InvalidReport:
        invalid_report = True
    if invalid_report:
        raise ValueError(_ERROR)
    raise AssertionError("unreachable")


def load_report_summary(path: str | Path) -> ReportSummary:
    """Load one bounded local report.

    Portable Python on Windows cannot fully close the residual same-user
    path-replacement race between the final path check and later use.
    """
    load_failed = False
    try:
        text = _load_report_text(path)
    except ValueError:
        load_failed = True
    if load_failed:
        raise ValueError(_ERROR)

    parse_failed = False
    try:
        return parse_report_summary(text)
    except UnicodeError:
        raise
    except ValueError:
        parse_failed = True
    if parse_failed:
        raise ValueError(_ERROR)
    raise AssertionError("unreachable")


def compare_report_summaries(
    baseline: ReportSummary,
    current: ReportSummary,
) -> ReportComparison:
    failed = False
    try:
        _validate_summary(baseline)
        _validate_summary(current)
    except _InvalidReport:
        failed = True
    if failed:
        raise ValueError(_ERROR)
    return ReportComparison(
        baseline=baseline,
        current=current,
        technical_score_delta=current.technical_score - baseline.technical_score,
        reviewed_score_delta=current.reviewed_score - baseline.reviewed_score,
        coverage_delta=current.coverage - baseline.coverage,
        finding_count_delta=current.finding_count - baseline.finding_count,
        rule_count_deltas=_count_deltas(baseline.rule_counts, current.rule_counts),
        severity_count_deltas=_count_deltas(
            baseline.severity_counts, current.severity_counts
        ),
        disposition_count_deltas=_count_deltas(
            baseline.disposition_counts, current.disposition_counts
        ),
        added_limits=tuple(sorted(set(current.limits) - set(baseline.limits))),
        resolved_limits=tuple(sorted(set(baseline.limits) - set(current.limits))),
    )


def _load_report_text(path: str | Path) -> str:
    failed = False
    try:
        target = _validated_baseline_path(path)
        initial = _checked_file_state(target)
        with open(target, "rb") as stream:
            opened = os.fstat(stream.fileno())
            _validate_open_file(initial, opened)
            data = stream.read(MAX_REPORT_JSON_BYTES + 1)
            final_opened = os.fstat(stream.fileno())
        if type(data) is not bytes or len(data) > MAX_REPORT_JSON_BYTES:
            raise _InvalidReport
        _validate_open_file(initial, final_opened, expected_size=len(data))
        final_path = _checked_file_state(target)
        if not _same_file(initial, final_path) or final_path.st_size != len(data):
            raise _InvalidReport
        return data.decode("utf-8", errors="strict")
    except (OSError, UnicodeError, _InvalidReport):
        failed = True
    if failed:
        raise _InvalidReport
    raise AssertionError("unreachable")


def _validated_baseline_path(path: object) -> Path:
    if type(path) not in (str, _PATH_TYPE):
        raise _InvalidReport
    value = os.fspath(path)
    windows_path = PureWindowsPath(value)
    if (
        value.startswith(("\\\\", "//"))
        or windows_path.drive.startswith("\\\\")
        or _WINDOWS_DRIVE.fullmatch(windows_path.drive) is None
        or not windows_path.is_absolute()
        or windows_path.suffix.casefold() != ".json"
    ):
        raise _InvalidReport
    for component in windows_path.parts[1:]:
        device_name = component.partition(".")[0].rstrip(" .").casefold()
        if (
            not component
            or component.endswith((" ", "."))
            or any(character in component for character in '/\\:*?"<>|')
            or any(not character.isprintable() for character in component)
            or device_name in _WINDOWS_RESERVED_DEVICE_NAMES
        ):
            raise _InvalidReport
    return Path(path)


def _checked_file_state(path: Path) -> os.stat_result:
    path_state: os.stat_result | None = None
    for component in (*reversed(path.parents), path):
        component_state = os.lstat(component)
        if _is_reparse(component_state):
            raise _InvalidReport
        path_state = component_state
    if path_state is None:
        raise _InvalidReport
    _validate_regular_file(path_state)
    return path_state


def _validate_open_file(
    expected: os.stat_result,
    actual: os.stat_result,
    *,
    expected_size: int | None = None,
) -> None:
    _validate_regular_file(actual)
    if not _same_file(expected, actual):
        raise _InvalidReport
    if expected_size is not None and actual.st_size != expected_size:
        raise _InvalidReport


def _validate_regular_file(path_state: os.stat_result) -> None:
    if (
        not stat.S_ISREG(path_state.st_mode)
        or _is_reparse(path_state)
        or type(path_state.st_size) is not int
        or not 0 <= path_state.st_size <= MAX_REPORT_JSON_BYTES
    ):
        raise _InvalidReport


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
    )


def _is_reparse(path_state: os.stat_result) -> bool:
    return stat.S_ISLNK(path_state.st_mode) or bool(
        getattr(path_state, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _report_summary(payload: object) -> ReportSummary:
    common_keys = {
        "product",
        "version",
        "rule_version",
        "score",
        "reviewed_score",
        "findings",
    }
    if type(payload) is not dict:
        raise _InvalidReport
    if set(payload) == common_keys | {
        "report_schema",
        "supported_use_boundary",
        "evaluated_at",
    }:
        current = True
        legacy = False
        evaluated_at = _domain_call(parse_utc, payload["evaluated_at"])
    elif set(payload) == common_keys | {"report_schema", "evaluated_at"}:
        current = False
        legacy = False
        evaluated_at = _domain_call(parse_utc, payload["evaluated_at"])
    elif set(payload) == common_keys | {"report_schema"}:
        current = False
        legacy = False
        evaluated_at = None
    elif set(payload) == common_keys:
        current = False
        legacy = True
        evaluated_at = None
    else:
        raise _InvalidReport
    report = payload
    if (
        type(report["product"]) is not str
        or report["product"] != _PRODUCT
        or (
            not legacy
            and (
                type(report["report_schema"]) is not int
                or report["report_schema"] != 1
            )
        )
        or (
            current
            and (
                type(report["supported_use_boundary"]) is not str
                or report["supported_use_boundary"] != SUPPORTED_USE_BOUNDARY
            )
        )
    ):
        raise _InvalidReport
    _safe_annotation(report["version"], 32)
    _safe_annotation(report["rule_version"], 32)
    technical = _validated_score(report["score"], legacy=legacy)
    reviewed = _validated_score(report["reviewed_score"], legacy=legacy)
    technical_score = technical.score
    reviewed_score = reviewed.score
    if (
        technical_score.coverage != reviewed_score.coverage
        or technical_score.confidence != reviewed_score.confidence
        or technical_score.incomplete is not reviewed_score.incomplete
        or technical_score.limits != reviewed_score.limits
        or technical.coverage_state is not reviewed.coverage_state
    ):
        raise _InvalidReport
    finding_count, rules, severities, dispositions = _aggregate_findings(
        report["findings"],
        technical_score,
        reviewed_score,
        evaluated_at,
    )
    return ReportSummary(
        technical_score=technical_score.total,
        reviewed_score=reviewed_score.total,
        coverage=float(technical_score.coverage),
        coverage_state=technical.coverage_state,
        finding_count=finding_count,
        rule_counts=tuple(sorted(rules.items())),
        severity_counts=tuple(sorted(severities.items())),
        disposition_counts=tuple(sorted(dispositions.items())),
        limits=tuple(sorted(technical_score.limits)),
    )


def _validated_score(value: object, *, legacy: bool) -> _ParsedScore:
    keys = {
        "total",
        "deductions",
        "cap_reason",
        "coverage",
        "confidence",
        "incomplete",
        "limits",
    }
    if not legacy:
        keys.add("coverage_state")
    score = _exact_object(value, keys)
    total = _exact_int(score["total"], minimum=0, maximum=100)
    deductions = _exact_list(score["deductions"], _MAX_SCORE_ITEMS)
    parsed_deductions: list[tuple[RiskDomain, int]] = []
    for deduction_value in deductions:
        deduction = _exact_object(deduction_value, {"domain", "amount"})
        domain = _enum_value(RiskDomain, deduction["domain"])
        amount = _exact_int(deduction["amount"], minimum=0)
        parsed_deductions.append((domain, amount))
    cap_reason = score["cap_reason"]
    if cap_reason is not None:
        _safe_annotation(cap_reason, 80)
    coverage = _ratio(score["coverage"])
    confidence = _ratio(score["confidence"])
    if type(score["incomplete"]) is not bool:
        raise _InvalidReport
    incomplete = score["incomplete"]
    raw_limits = _exact_list(score["limits"], len(COVERAGE_LIMIT_LABELS))
    limits: list[str] = []
    for limit in raw_limits:
        if type(limit) is not str or limit not in COVERAGE_LIMIT_LABELS:
            raise _InvalidReport
        limits.append(limit)
    if len(set(limits)) != len(limits):
        raise _InvalidReport
    domain_score = _domain_call(
        Score,
        total,
        tuple(parsed_deductions),
        cap_reason,
        coverage,
        confidence,
        tuple(limits),
        incomplete,
    )
    coverage_state = _domain_call(classify_coverage, domain_score)
    if legacy:
        reported_state = coverage_state
    else:
        reported_state = _enum_value(CoverageState, score["coverage_state"])
        if reported_state is not coverage_state:
            raise _InvalidReport
    return _ParsedScore(
        score=domain_score,
        coverage_state=reported_state,
    )


def _aggregate_findings(
    value: object,
    technical_score: Score,
    reviewed_score: Score,
    evaluated_at: object,
) -> tuple[int, Counter[str], Counter[str], Counter[str]]:
    findings = _exact_list(value, MAX_REPORT_FINDINGS)
    rules: Counter[str] = Counter()
    severities: Counter[str] = Counter()
    dispositions: Counter[str] = Counter()
    technical_findings: list[Finding] = []
    reviewed_findings: list[Finding] = []
    evidence_count = 0
    for value in findings:
        finding = _exact_object(
            value,
            {
                "rule_id",
                "domain",
                "severity",
                "root_hmac_fingerprint",
                "evidence",
                "disposition",
            },
        )
        rule_id = _domain_call(validate_rule_id, finding["rule_id"])
        domain = _enum_value(RiskDomain, finding["domain"])
        severity = _enum_value(Severity, finding["severity"])
        root_fingerprint = finding["root_hmac_fingerprint"]
        if type(root_fingerprint) is not str:
            raise _InvalidReport
        evidence_values = _exact_list(finding["evidence"], MAX_REPORT_EVIDENCE)
        evidence_count += len(evidence_values)
        if evidence_count > MAX_REPORT_EVIDENCE:
            raise _InvalidReport
        evidence_items: list[Evidence] = []
        for evidence_value in evidence_values:
            evidence = _exact_object(
                evidence_value,
                {"source", "hmac_fingerprint", "masked"},
            )
            if any(
                type(evidence[key]) is not str
                for key in ("source", "hmac_fingerprint", "masked")
            ):
                raise _InvalidReport
            evidence_items.append(
                _domain_call(
                    Evidence,
                    evidence["source"],
                    evidence["hmac_fingerprint"],
                    evidence["masked"],
                )
            )
        validated_finding = _domain_call(
            Finding,
            rule_id,
            domain,
            severity,
            root_fingerprint,
            tuple(evidence_items),
        )
        disposition_state = _validated_disposition(
            finding["disposition"], validated_finding, evaluated_at
        )
        technical_findings.append(validated_finding)
        if disposition_state != DispositionStatus.FALSE_POSITIVE.value:
            reviewed_findings.append(validated_finding)
        rules[rule_id] += 1
        severities[severity.value] += 1
        dispositions[disposition_state] += 1
    recomputed_technical = calculate_score(
        tuple(technical_findings),
        coverage=technical_score.coverage,
        confidence=technical_score.confidence,
        limits=technical_score.limits,
    )
    recomputed_reviewed = calculate_score(
        tuple(reviewed_findings),
        coverage=reviewed_score.coverage,
        confidence=reviewed_score.confidence,
        limits=reviewed_score.limits,
    )
    if (
        technical_score != recomputed_technical
        or reviewed_score != recomputed_reviewed
    ):
        raise _InvalidReport
    return len(findings), rules, severities, dispositions


def _validated_disposition(
    value: object,
    finding: Finding,
    evaluated_at: object,
) -> str:
    if type(value) is not dict:
        raise _InvalidReport
    status = value.get("status")
    if type(status) is not str or status not in _DISPOSITION_STATES:
        raise _InvalidReport
    if status == "open":
        _exact_object(value, {"status"})
        return status
    if type(evaluated_at) is not datetime:
        raise _InvalidReport
    keys = {"status", "reason", "reviewer", "created_at", "expires_at"}
    if status == "expired":
        keys.add("last_status")
    disposition = _exact_object(value, keys)
    for name in ("reason", "reviewer", "created_at", "expires_at"):
        if type(disposition[name]) is not str:
            raise _InvalidReport
    raw_status = disposition.get("last_status", status)
    record_status = _enum_value(DispositionStatus, raw_status)
    disposition_ref = "0" * 64
    record = _domain_call(
        DispositionRecord,
        disposition_ref,
        finding.rule_id,
        record_status,
        disposition["reason"],
        disposition["reviewer"],
        disposition["created_at"],
        disposition["expires_at"],
    )
    evaluated_finding = _domain_call(
        Finding,
        finding.rule_id,
        finding.domain,
        finding.severity,
        finding.root_fingerprint,
        finding.evidence,
        disposition_ref,
    )
    evaluation = _domain_call(
        evaluate_disposition,
        evaluated_finding,
        {disposition_ref: record},
        now=evaluated_at,
    )
    if evaluation.state != status or evaluation.record is not record:
        raise _InvalidReport
    return status


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _InvalidReport
        result[key] = value
    return result


def _reject_constant(_value: str) -> object:
    raise _InvalidReport


def _exact_object(value: object, keys: set[str]) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise _InvalidReport
    return value


def _exact_list(value: object, maximum: int) -> list[object]:
    if type(value) is not list or len(value) > maximum:
        raise _InvalidReport
    return value


def _exact_int(
    value: object,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    if (
        type(value) is not int
        or (minimum is not None and value < minimum)
        or (maximum is not None and value > maximum)
    ):
        raise _InvalidReport
    return value


def _ratio(value: object) -> int | float:
    if (
        type(value) not in (int, float)
        or not isfinite(value)
        or not 0 <= value <= 1
    ):
        raise _InvalidReport
    return value


def _safe_annotation(value: object, maximum: int) -> str:
    return _domain_call(validate_safe_annotation, "report value", value, maximum)


def _enum_value(enum_type: Callable[[object], _T], value: object) -> _T:
    if type(value) is not str:
        raise _InvalidReport
    return _domain_call(enum_type, value)


def _domain_call(
    call: Callable[..., _T],
    *args: object,
    **kwargs: object,
) -> _T:
    failed = False
    try:
        return call(*args, **kwargs)
    except UnicodeError:
        raise
    except ValueError:
        failed = True
    if failed:
        raise _InvalidReport
    raise AssertionError("unreachable")


def _validate_summary(value: object) -> None:
    if type(value) is not ReportSummary:
        raise _InvalidReport
    missing = False
    try:
        technical_score = value.technical_score
        reviewed_score = value.reviewed_score
        coverage = value.coverage
        coverage_state = value.coverage_state
        finding_count = value.finding_count
        rule_counts = value.rule_counts
        severity_counts = value.severity_counts
        disposition_counts = value.disposition_counts
        limits = value.limits
    except AttributeError:
        missing = True
    if missing:
        raise _InvalidReport
    if (
        type(technical_score) is not int
        or not 0 <= technical_score <= 100
        or type(reviewed_score) is not int
        or not 0 <= reviewed_score <= 100
        or type(coverage) is not float
        or not isfinite(coverage)
        or not 0 <= coverage <= 1
        or type(coverage_state) is not CoverageState
        or type(finding_count) is not int
        or not 0 <= finding_count <= MAX_REPORT_FINDINGS
    ):
        raise _InvalidReport
    _validate_counts(rule_counts, _valid_rule_id, finding_count)
    _validate_counts(severity_counts, _valid_severity, finding_count)
    _validate_counts(
        disposition_counts,
        lambda item: item in _DISPOSITION_STATES,
        finding_count,
    )
    validated_limits = _validated_summary_limits(limits)
    summary_score = _domain_call(
        Score,
        technical_score,
        (),
        None,
        coverage,
        1.0,
        validated_limits,
        coverage_state is not CoverageState.COMPLETE,
    )
    if _domain_call(classify_coverage, summary_score) is not coverage_state:
        raise _InvalidReport


def _validated_summary_limits(value: object) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise _InvalidReport
    limits: list[str] = []
    for limit in value:
        if type(limit) is not str or limit not in COVERAGE_LIMIT_LABELS:
            raise _InvalidReport
        limits.append(limit)
    if len(set(limits)) != len(limits) or limits != sorted(limits):
        raise _InvalidReport
    return tuple(limits)


def _validate_counts(
    counts: object,
    valid_key: Callable[[str], bool],
    finding_count: int,
) -> None:
    if type(counts) is not tuple:
        raise _InvalidReport
    captured: list[tuple[str, int]] = []
    for item in counts:
        if type(item) is not tuple or len(item) != 2:
            raise _InvalidReport
        key, count = item
        if (
            type(key) is not str
            or not valid_key(key)
            or type(count) is not int
            or count <= 0
        ):
            raise _InvalidReport
        captured.append((key, count))
    if tuple(captured) != tuple(sorted(captured)) or len(dict(captured)) != len(captured):
        raise _InvalidReport
    if sum(count for _, count in captured) != finding_count:
        raise _InvalidReport


def _valid_rule_id(value: str) -> bool:
    try:
        return validate_rule_id(value) == value
    except ValueError:
        return False


def _valid_severity(value: str) -> bool:
    return value in {severity.value for severity in Severity}


def _count_deltas(
    baseline: tuple[tuple[str, int], ...],
    current: tuple[tuple[str, int], ...],
) -> tuple[tuple[str, int], ...]:
    baseline_counts = dict(baseline)
    current_counts = dict(current)
    return tuple(
        (key, current_counts.get(key, 0) - baseline_counts.get(key, 0))
        for key in sorted(baseline_counts.keys() | current_counts.keys())
    )
