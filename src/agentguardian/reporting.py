from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from html import escape
import json
from math import isfinite

from . import __version__
from .dispositions import (
    DispositionRecord,
    disposition_index,
    evaluate_disposition,
)
from .domain import Evidence, Finding, RiskDomain, Score, Severity


_PRODUCT = "AgentGuardian"
_ERROR = "REPORT_INVALID"
_MAX_REPORT_ITEMS = 2_000

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
    evaluated_at: datetime | None = None,
) -> str:
    try:
        rule_version, technical, reviewed, prepared = _prepare_report(
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
            "rule_version": rule_version,
            "score": technical,
            "reviewed_score": reviewed,
            "findings": [
                _finding_data(finding, disposition)
                for finding, disposition in prepared
            ],
        }
        return json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False)
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
    evaluated_at: datetime | None = None,
) -> str:
    try:
        rule_version, technical, reviewed, prepared = _prepare_report(
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
            f"<p>Rule version: {_text(rule_version)}</p>",
        ]
        for label, current_score in (
            ("Technical", technical),
            ("Reviewed", reviewed),
        ):
            cap_reason = current_score["cap_reason"]
            if cap_reason is None:
                cap_reason = "None"
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
                    "<h3>Limits</h3>",
                    "<ul>",
                )
            )
            for limit in current_score["limits"]:
                parts.append(f"<li>{_text(limit)}</li>")
            parts.append("</ul>")
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
    evaluated_at: datetime | None,
) -> tuple[
    str,
    dict[str, object],
    dict[str, object],
    tuple[_PreparedFinding, ...],
]:
    technical = _validated_score_data(score)
    reviewed = (
        technical
        if reviewed_score is None
        else _validated_score_data(reviewed_score)
    )
    if type(rule_version) is not str:
        raise ValueError(_ERROR)
    now = _validated_time(evaluated_at)
    records = disposition_index(_bounded_items(dispositions))
    prepared: list[_PreparedFinding] = []
    for candidate in _bounded_items(findings):
        validated_finding, canonical = _validated_finding(candidate)
        disposition = _disposition_data(validated_finding, records, now)
        prepared.append((canonical, disposition))
    return (
        rule_version,
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
    total = score.total
    deductions = score.deductions
    cap_reason = score.cap_reason
    coverage = score.coverage
    confidence = score.confidence
    limits = score.limits
    incomplete = score.incomplete
    if type(total) is not int or not 0 <= total <= 100:
        raise ValueError(_ERROR)
    if type(deductions) is not tuple:
        raise ValueError(_ERROR)
    deduction_data: list[dict[str, object]] = []
    for deduction in deductions:
        if type(deduction) is not tuple:
            raise ValueError(_ERROR)
        domain, amount = deduction
        if (
            type(domain) is not RiskDomain
            or type(amount) is not int
            or amount < 0
        ):
            raise ValueError(_ERROR)
        deduction_data.append({"domain": domain.value, "amount": amount})
    if cap_reason is not None and type(cap_reason) is not str:
        raise ValueError(_ERROR)
    for ratio in (coverage, confidence):
        if (
            (type(ratio) is not int and type(ratio) is not float)
            or not isfinite(ratio)
            or not 0 <= ratio <= 1
        ):
            raise ValueError(_ERROR)
    if type(limits) is not tuple:
        raise ValueError(_ERROR)
    limit_data: list[str] = []
    for limit in limits:
        if type(limit) is not str:
            raise ValueError(_ERROR)
        limit_data.append(limit)
    if type(incomplete) is not bool:
        raise ValueError(_ERROR)
    return {
        "total": total,
        "deductions": deduction_data,
        "cap_reason": cap_reason,
        "coverage": coverage,
        "confidence": confidence,
        "incomplete": incomplete,
        "limits": limit_data,
    }


def _validated_time(evaluated_at: datetime | None) -> datetime:
    now = (
        datetime.now(timezone.utc)
        if evaluated_at is None
        else evaluated_at
    )
    if type(now) is not datetime:
        raise ValueError(_ERROR)
    offset = now.utcoffset()
    if type(offset) is not timedelta or offset != timedelta(0):
        raise ValueError(_ERROR)
    return now.replace(tzinfo=timezone.utc)


def _bounded_items(values: Iterable[object]) -> tuple[object, ...]:
    items: list[object] = []
    count = 0
    for item in values:
        if count >= _MAX_REPORT_ITEMS:
            raise ValueError(_ERROR)
        items.append(item)
        count += 1
    return tuple(items)


def _validated_finding(
    finding: object,
) -> tuple[Finding, _CanonicalFinding]:
    if type(finding) is not Finding:
        raise ValueError(_ERROR)
    rule_id = finding.rule_id
    domain = finding.domain
    severity = finding.severity
    root_fingerprint = finding.root_fingerprint
    evidence = finding.evidence
    disposition_ref = finding.disposition_ref
    if (
        type(rule_id) is not str
        or type(domain) is not RiskDomain
        or type(severity) is not Severity
        or type(root_fingerprint) is not str
        or type(evidence) is not tuple
        or (
            disposition_ref is not None
            and type(disposition_ref) is not str
        )
    ):
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
