from collections import Counter
from dataclasses import dataclass
import json
from math import isfinite
import re
from typing import Callable, TypeVar

from .dispositions import DispositionRecord, DispositionStatus
from .domain import (
    Evidence,
    Finding,
    RiskDomain,
    Score,
    Severity,
    validate_safe_annotation,
)
from .workflow import (
    COVERAGE_LIMIT_LABELS,
    CoverageState,
    classify_coverage,
)


_ERROR = "REPORT_COMPARISON_INVALID"
_PRODUCT = "AgentGuardian"
_MAX_FINDINGS = 2_000
_MAX_EVIDENCE = 4_000
_MAX_SCORE_ITEMS = 2_000
_RULE_ID = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
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
    total: int
    coverage: float
    confidence: float
    incomplete: bool
    limits: tuple[str, ...]
    coverage_state: CoverageState


def parse_report_summary(json_text: str) -> ReportSummary:
    failed = False
    try:
        if type(json_text) is not str:
            raise _InvalidReport
        payload = json.loads(
            json_text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        return _report_summary(payload)
    except (ValueError, RecursionError):
        failed = True
    if failed:
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
    if set(payload) == common_keys | {"report_schema"}:
        legacy = False
    elif set(payload) == common_keys:
        legacy = True
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
    ):
        raise _InvalidReport
    _safe_annotation(report["version"], 32)
    _safe_annotation(report["rule_version"], 32)
    technical = _validated_score(report["score"], legacy=legacy)
    reviewed = _validated_score(report["reviewed_score"], legacy=legacy)
    if (
        technical.coverage != reviewed.coverage
        or technical.confidence != reviewed.confidence
        or technical.incomplete is not reviewed.incomplete
        or technical.limits != reviewed.limits
        or technical.coverage_state is not reviewed.coverage_state
    ):
        raise _InvalidReport
    finding_count, rules, severities, dispositions = _aggregate_findings(
        report["findings"]
    )
    return ReportSummary(
        technical_score=technical.total,
        reviewed_score=reviewed.total,
        coverage=technical.coverage,
        coverage_state=technical.coverage_state,
        finding_count=finding_count,
        rule_counts=tuple(sorted(rules.items())),
        severity_counts=tuple(sorted(severities.items())),
        disposition_counts=tuple(sorted(dispositions.items())),
        limits=tuple(sorted(technical.limits)),
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
        total=total,
        coverage=float(coverage),
        confidence=float(confidence),
        incomplete=incomplete,
        limits=tuple(limits),
        coverage_state=reported_state,
    )


def _aggregate_findings(
    value: object,
) -> tuple[int, Counter[str], Counter[str], Counter[str]]:
    findings = _exact_list(value, _MAX_FINDINGS)
    rules: Counter[str] = Counter()
    severities: Counter[str] = Counter()
    dispositions: Counter[str] = Counter()
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
        rule_id = finding["rule_id"]
        if type(rule_id) is not str or _RULE_ID.fullmatch(rule_id) is None:
            raise _InvalidReport
        domain = _enum_value(RiskDomain, finding["domain"])
        severity = _enum_value(Severity, finding["severity"])
        root_fingerprint = finding["root_hmac_fingerprint"]
        if type(root_fingerprint) is not str:
            raise _InvalidReport
        evidence_values = _exact_list(finding["evidence"], _MAX_EVIDENCE)
        evidence_count += len(evidence_values)
        if evidence_count > _MAX_EVIDENCE:
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
        _domain_call(
            Finding,
            rule_id,
            domain,
            severity,
            root_fingerprint,
            tuple(evidence_items),
        )
        disposition_state = _validated_disposition(
            finding["disposition"], rule_id
        )
        rules[rule_id] += 1
        severities[severity.value] += 1
        dispositions[disposition_state] += 1
    return len(findings), rules, severities, dispositions


def _validated_disposition(value: object, rule_id: str) -> str:
    if type(value) is not dict:
        raise _InvalidReport
    status = value.get("status")
    if type(status) is not str or status not in _DISPOSITION_STATES:
        raise _InvalidReport
    if status == "open":
        _exact_object(value, {"status"})
        return status
    keys = {"status", "reason", "reviewer", "created_at", "expires_at"}
    if status == "expired":
        keys.add("last_status")
    disposition = _exact_object(value, keys)
    for name in ("reason", "reviewer", "created_at", "expires_at"):
        if type(disposition[name]) is not str:
            raise _InvalidReport
    raw_status = disposition.get("last_status", status)
    record_status = _enum_value(DispositionStatus, raw_status)
    _domain_call(
        DispositionRecord,
        "0" * 64,
        rule_id,
        record_status,
        disposition["reason"],
        disposition["reviewer"],
        disposition["created_at"],
        disposition["expires_at"],
    )
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


def _domain_call(call: Callable[..., _T], *args: object) -> _T:
    failed = False
    try:
        return call(*args)
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
        or not 0 <= finding_count <= _MAX_FINDINGS
    ):
        raise _InvalidReport
    _validate_counts(rule_counts, _valid_rule_id, finding_count)
    _validate_counts(severity_counts, _valid_severity, finding_count)
    _validate_counts(
        disposition_counts,
        lambda item: item in _DISPOSITION_STATES,
        finding_count,
    )
    if (
        type(limits) is not tuple
        or limits != tuple(sorted(limits))
        or len(set(limits)) != len(limits)
        or any(
            type(limit) is not str or limit not in COVERAGE_LIMIT_LABELS
            for limit in limits
        )
    ):
        raise _InvalidReport
    if coverage_state is CoverageState.COMPLETE:
        valid_state = coverage == 1 and not limits
    elif coverage_state is CoverageState.NO_SUPPORTED_FILES:
        valid_state = coverage == 0 and limits == ("no_supported_files",)
    else:
        valid_state = not (coverage == 1 and not limits)
    if not valid_state:
        raise _InvalidReport


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
    return _RULE_ID.fullmatch(value) is not None


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
