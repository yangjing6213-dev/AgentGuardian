import json
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from html import escape

from . import __version__
from .dispositions import (
    DispositionRecord,
    disposition_index,
    evaluate_disposition,
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
    COVERAGE_STATE_LABELS,
    SUPPORTED_USE_BOUNDARY,
    CoverageState,
    classify_coverage,
)

_PRODUCT = "AgentGuardian"
_ERROR = "REPORT_INVALID"

_CanonicalEvidence = tuple[str, str, str]
_CanonicalFinding = tuple[
    str,
    str,
    str,
    str,
    tuple[_CanonicalEvidence, ...],
]
_PreparedFinding = tuple[_CanonicalFinding, dict[str, str]]


def render_json(
    score: Score,
    findings: Iterable[Finding],
    *,
    rule_version: str,
    reviewed_score: Score | None = None,
    dispositions: Iterable[DispositionRecord] = (),
    evaluated_at: datetime,
) -> str:
    try:
        rule_version, evaluated_timestamp, technical, reviewed, prepared = _prepare_report(
            score,
            findings,
            rule_version=rule_version,
            reviewed_score=reviewed_score,
            dispositions=dispositions,
            evaluated_at=evaluated_at,
        )
        report = {
            "product": _PRODUCT,
            "version": __version__,
            "report_schema": 2,
            "supported_use_boundary": SUPPORTED_USE_BOUNDARY,
            "evaluated_at": evaluated_timestamp,
            "rule_version": rule_version,
            "score": technical,
            "reviewed_score": reviewed,
            "findings": [
                _finding_data(finding, disposition)
                for finding, disposition in prepared
            ],
        }
        rendered = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False)
        if len(rendered.encode("utf-8")) > MAX_REPORT_JSON_BYTES:
            raise ValueError(_ERROR)
        return rendered
    except Exception:
        pass
    raise ValueError(_ERROR) from None


def render_html(
    score: Score,
    findings: Iterable[Finding],
    *,
    rule_version: str,
    reviewed_score: Score | None = None,
    dispositions: Iterable[DispositionRecord] = (),
    evaluated_at: datetime,
) -> str:
    try:
        rule_version, evaluated_timestamp, technical, reviewed, prepared = _prepare_report(
            score,
            findings,
            rule_version=rule_version,
            reviewed_score=reviewed_score,
            dispositions=dispositions,
            evaluated_at=evaluated_at,
        )
        parts = [
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            f"<title>{_text(_PRODUCT)} {_text(__version__)}</title>",
            "</head>",
            "<body>",
            f"<h1>{_text(_PRODUCT)}</h1>",
            f"<p>Version: {_text(__version__)}</p>",
            "<p>Supported use boundary: "
            f"{_text(SUPPORTED_USE_BOUNDARY)} "
            "(personal non-regulated configuration only).</p>",
            f"<p>Rule version: {_text(rule_version)}</p>",
            f"<p>Evaluated at: {_text(evaluated_timestamp)}</p>",
        ]
        for label, current_score in (
            ("Technical", technical),
            ("Reviewed", reviewed),
        ):
            cap_reason = current_score["cap_reason"]
            if cap_reason is None:
                cap_reason = "None"
            coverage_state = CoverageState(current_score["coverage_state"])
            parts.extend(
                (
                    f"<h2>{label} score</h2>",
                    f"<p>Total: {_text(current_score['total'])}</p>",
                    "<h3>Domain deductions</h3>",
                    "<ul>",
                )
            )
            for deduction in current_score["deductions"]:
                parts.append(
                    f"<li>{_text(deduction['domain'])}: "
                    f"{_text(deduction['amount'])}</li>"
                )
            parts.extend(
                (
                    "</ul>",
                    f"<p>Cap reason: {_text(cap_reason)}</p>",
                    f"<p>Coverage: {_text(current_score['coverage'])}</p>",
                    f"<p>Confidence: {_text(current_score['confidence'])}</p>",
                    "<p>Incomplete: "
                    f"{_text(str(current_score['incomplete']).lower())}</p>",
                    f"<p>Coverage state: {_text(coverage_state.value)}</p>",
                    "<p>Coverage state label: "
                    f"{_text(COVERAGE_STATE_LABELS[coverage_state])}</p>",
                    "<h3>Limits</h3>",
                    "<ul>",
                )
            )
            for limit in current_score["limits"]:
                parts.append(f"<li>{_text(COVERAGE_LIMIT_LABELS[limit])}</li>")
            parts.append("</ul>")
            if coverage_state is CoverageState.COMPLETE:
                parts.append("<p>已完成配置范围扫描。</p>")
            else:
                parts.append(
                    "<p>本次结果不能证明系统、账户、提供商或端点安全。</p>"
                )
        parts.append("<h2>Findings</h2>")

        for finding, disposition in prepared:
            parts.extend(
                (
                    "<section>",
                    f"<h3>{_text(finding[0])}</h3>",
                    f"<p>Domain: {_text(finding[1])}</p>",
                    f"<p>Severity: {_text(finding[2])}</p>",
                    f"<p>Root HMAC fingerprint: {_text(finding[3])}</p>",
                    f"<p>Disposition status: {_text(disposition['status'])}</p>",
                )
            )
            if disposition["status"] == "expired":
                parts.append(
                    "<p>Last disposition status: "
                    f"{_text(disposition['last_status'])}</p>"
                )
            if disposition["status"] != "open":
                parts.extend(
                    (
                        f"<p>Disposition reason: {_text(disposition['reason'])}</p>",
                        "<p>Disposition reviewer: "
                        f"{_text(disposition['reviewer'])}</p>",
                        "<p>Disposition created at: "
                        f"{_text(disposition['created_at'])}</p>",
                        "<p>Disposition expires at: "
                        f"{_text(disposition['expires_at'])}</p>",
                    )
                )
            parts.append("<ul>")
            for source, fingerprint, masked in finding[4]:
                parts.append(
                    "<li>"
                    f"Source: {_text(source)}; "
                    f"HMAC fingerprint: {_text(fingerprint)}; "
                    f"Masked evidence: {_text(masked)}"
                    "</li>"
                )
            parts.extend(("</ul>", "</section>"))

        parts.extend(("</body>", "</html>"))
        return "\n".join(parts)
    except Exception:
        pass
    raise ValueError(_ERROR) from None


def _prepare_report(
    score: Score,
    findings: Iterable[Finding],
    *,
    rule_version: str,
    reviewed_score: Score | None,
    dispositions: Iterable[DispositionRecord],
    evaluated_at: datetime,
) -> tuple[
    str,
    str,
    dict[str, object],
    dict[str, object],
    tuple[_PreparedFinding, ...],
]:
    rule_version = validate_safe_annotation("rule_version", rule_version, 32)
    now = _validated_report_time(evaluated_at)
    records = disposition_index(
        _validated_dispositions(_bounded_items(dispositions, MAX_REPORT_FINDINGS))
    )
    prepared: list[_PreparedFinding] = []
    validated_findings: list[Finding] = []
    reviewed_findings: list[Finding] = []
    evidence_count = 0
    for candidate in _bounded_items(findings, MAX_REPORT_FINDINGS):
        validated_finding, canonical = _validated_finding(
            candidate,
            MAX_REPORT_EVIDENCE - evidence_count,
        )
        evidence_count += len(canonical[4])
        disposition = _disposition_data(validated_finding, records, now)
        validated_findings.append(validated_finding)
        if disposition["status"] != "false_positive":
            reviewed_findings.append(validated_finding)
        prepared.append((canonical, disposition))

    _validated_score_data(score)
    expected_technical = calculate_score(
        tuple(validated_findings),
        coverage=score.coverage,
        confidence=score.confidence,
        limits=score.limits,
    )
    if score != expected_technical:
        raise ValueError(_ERROR)
    technical = _validated_score_data(expected_technical)

    expected_reviewed = calculate_score(
        tuple(reviewed_findings),
        coverage=score.coverage,
        confidence=score.confidence,
        limits=score.limits,
    )
    if reviewed_score is not None:
        _validated_score_data(reviewed_score)
        if reviewed_score != expected_reviewed:
            raise ValueError(_ERROR)
    reviewed = _validated_score_data(expected_reviewed)
    if (
        technical["coverage"] != reviewed["coverage"]
        or technical["confidence"] != reviewed["confidence"]
        or technical["incomplete"] != reviewed["incomplete"]
        or technical["limits"] != reviewed["limits"]
        or technical["coverage_state"] != reviewed["coverage_state"]
    ):
        raise ValueError(_ERROR)
    return (
        rule_version,
        now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        technical,
        reviewed,
        tuple(
            sorted(
                prepared,
                key=lambda pair: (
                    pair[0][0],
                    pair[0][1],
                    pair[0][2],
                    pair[0][3],
                    tuple(
                        (item[1], item[0], item[2]) for item in pair[0][4]
                    ),
                    _disposition_sort_key(pair[1]),
                ),
            )
        ),
    )


def _validated_score_data(score: Score) -> dict[str, object]:
    if type(score) is not Score:
        raise ValueError(_ERROR)
    deductions = score.deductions
    expected_domains = tuple(RiskDomain)
    if type(deductions) is not tuple or len(deductions) != len(expected_domains):
        raise ValueError(_ERROR)
    position = 0
    for deduction in deductions:
        if type(deduction) is not tuple or len(deduction) != 2:
            raise ValueError(_ERROR)
        domain, amount = deduction
        if (
            domain is not expected_domains[position]
            or type(amount) is not int
            or amount < 0
        ):
            raise ValueError(_ERROR)
        position += 1

    coverage_state = classify_coverage(score)
    total = score.total
    cap_reason = score.cap_reason
    coverage = score.coverage
    confidence = score.confidence
    limits = score.limits
    incomplete = score.incomplete
    deduction_data: list[dict[str, object]] = []
    if cap_reason is not None:
        cap_reason = validate_safe_annotation("cap_reason", cap_reason, 80)
    for deduction in deductions:
        domain, amount = deduction
        deduction_data.append({"domain": domain.value, "amount": amount})
    return {
        "total": total,
        "deductions": deduction_data,
        "cap_reason": cap_reason,
        "coverage": coverage,
        "confidence": confidence,
        "incomplete": incomplete,
        "limits": [limit for limit in limits],
        "coverage_state": coverage_state.value,
    }


def _validated_report_time(evaluated_at: datetime) -> datetime:
    if type(evaluated_at) is not datetime:
        raise ValueError(_ERROR)
    offset = evaluated_at.utcoffset()
    if (
        type(offset) is not timedelta
        or offset != timedelta(0)
        or evaluated_at.microsecond != 0
    ):
        raise ValueError(_ERROR)
    return evaluated_at.replace(tzinfo=timezone.utc)


def _bounded_items(
    values: Iterable[object],
    maximum: int,
) -> Iterable[object]:
    count = 0
    for item in values:
        if count >= maximum:
            raise ValueError(_ERROR)
        count += 1
        yield item


def _validated_dispositions(
    records: Iterable[object],
) -> Iterable[DispositionRecord]:
    for record in records:
        if type(record) is not DispositionRecord:
            raise ValueError(_ERROR)
        disposition_ref = record.disposition_ref
        rule_id = record.rule_id
        status = record.status
        reason = record.reason
        reviewer = record.reviewer
        created_at = record.created_at
        expires_at = record.expires_at
        yield DispositionRecord(
            disposition_ref,
            rule_id,
            status,
            reason,
            reviewer,
            created_at,
            expires_at,
        )


def _validated_finding(
    finding: object,
    remaining_evidence: int,
) -> tuple[Finding, _CanonicalFinding]:
    if type(finding) is not Finding:
        raise ValueError(_ERROR)
    rule_id = validate_rule_id(finding.rule_id)
    domain = finding.domain
    severity = finding.severity
    root_fingerprint = finding.root_fingerprint
    evidence = finding.evidence
    disposition_ref = finding.disposition_ref
    if (
        type(domain) is not RiskDomain
        or type(severity) is not Severity
        or type(root_fingerprint) is not str
        or type(evidence) is not tuple
        or (
            disposition_ref is not None
            and type(disposition_ref) is not str
        )
    ):
        raise ValueError(_ERROR)
    if len(evidence) > remaining_evidence:
        raise ValueError(_ERROR)
    captured_evidence: list[_CanonicalEvidence] = []
    for item in evidence:
        if type(item) is not Evidence:
            raise ValueError(_ERROR)
        source = item.source
        fingerprint = item.fingerprint
        masked = item.masked
        if (
            type(source) is not str
            or type(fingerprint) is not str
            or type(masked) is not str
        ):
            raise ValueError(_ERROR)
        captured_evidence.append((source, fingerprint, masked))
    validated_evidence = tuple(
        Evidence(source, fingerprint, masked)
        for source, fingerprint, masked in captured_evidence
    )
    validated = Finding(
        rule_id,
        domain,
        severity,
        root_fingerprint,
        validated_evidence,
        disposition_ref,
    )
    canonical_evidence = tuple(
        sorted(
            captured_evidence,
            key=lambda item: (item[1], item[0], item[2]),
        )
    )
    return (
        validated,
        (
            rule_id,
            domain.value,
            severity.value,
            root_fingerprint,
            canonical_evidence,
        ),
    )


def _disposition_data(
    finding: Finding,
    records: dict[str, DispositionRecord],
    evaluated_at: datetime,
) -> dict[str, str]:
    evaluation = evaluate_disposition(finding, records, now=evaluated_at)
    if evaluation.record is None:
        return {"status": "open"}
    record = evaluation.record
    state = evaluation.state
    if type(record) is not DispositionRecord or type(state) is not str:
        raise ValueError(_ERROR)
    reason = record.reason
    reviewer = record.reviewer
    created_at = record.created_at
    expires_at = record.expires_at
    if (
        state not in ("false_positive", "accepted_risk", "expired")
        or type(reason) is not str
        or type(reviewer) is not str
        or type(created_at) is not str
        or type(expires_at) is not str
    ):
        raise ValueError(_ERROR)
    if state == "expired":
        last_status = record.status.value
        if type(last_status) is not str:
            raise ValueError(_ERROR)
        return {
            "status": "expired",
            "last_status": last_status,
            "reason": reason,
            "reviewer": reviewer,
            "created_at": created_at,
            "expires_at": expires_at,
        }
    return {
        "status": state,
        "reason": reason,
        "reviewer": reviewer,
        "created_at": created_at,
        "expires_at": expires_at,
    }


def _disposition_sort_key(disposition: dict[str, str]) -> tuple[str, ...]:
    return tuple(
        disposition[field] if field in disposition else ""
        for field in (
            "status",
            "last_status",
            "reason",
            "reviewer",
            "created_at",
            "expires_at",
        )
    )


def _finding_data(
    finding: _CanonicalFinding,
    disposition: dict[str, str],
) -> dict[str, object]:
    return {
        "rule_id": finding[0],
        "domain": finding[1],
        "severity": finding[2],
        "root_hmac_fingerprint": finding[3],
        "evidence": [
            {
                "source": source,
                "hmac_fingerprint": fingerprint,
                "masked": masked,
            }
            for source, fingerprint, masked in finding[4]
        ],
        "disposition": disposition,
    }


def _text(value: object) -> str:
    return escape(str(value), quote=True)
