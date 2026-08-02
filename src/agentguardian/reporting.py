from collections.abc import Iterable
from datetime import datetime, timezone
from html import escape
import json

from . import __version__
from .dispositions import (
    DispositionRecord,
    disposition_index,
    evaluate_disposition,
)
from .domain import Evidence, Finding, Score


_PRODUCT = "AgentGuardian"


def render_json(
    score: Score,
    findings: Iterable[Finding],
    *,
    rule_version: str,
    reviewed_score: Score | None = None,
    dispositions: Iterable[DispositionRecord] = (),
    evaluated_at: datetime | None = None,
) -> str:
    frozen_findings = tuple(findings)
    records = disposition_index(tuple(dispositions))
    now = evaluated_at if evaluated_at is not None else datetime.now(timezone.utc)
    reviewed_score = score if reviewed_score is None else reviewed_score
    report = {
        "product": _PRODUCT,
        "version": __version__,
        "rule_version": rule_version,
        "score": _score_data(score),
        "reviewed_score": _score_data(reviewed_score),
        "findings": [
            _finding_data(finding, _disposition_data(finding, records, now))
            for finding in _sorted_findings(frozen_findings)
        ],
    }
    return json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False)


def render_html(
    score: Score,
    findings: Iterable[Finding],
    *,
    rule_version: str,
    reviewed_score: Score | None = None,
    dispositions: Iterable[DispositionRecord] = (),
    evaluated_at: datetime | None = None,
) -> str:
    frozen_findings = tuple(findings)
    records = disposition_index(tuple(dispositions))
    now = evaluated_at if evaluated_at is not None else datetime.now(timezone.utc)
    reviewed_score = score if reviewed_score is None else reviewed_score
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
        ("Technical", score),
        ("Reviewed", reviewed_score),
    ):
        cap_reason = (
            current_score.cap_reason
            if current_score.cap_reason is not None
            else "None"
        )
        parts.extend(
            (
                f"<h2>{label} score</h2>",
                f"<p>Total: {_text(current_score.total)}</p>",
                "<h3>Domain deductions</h3>",
                "<ul>",
            )
        )
        parts.extend(
            f"<li>{_text(domain.value)}: {_text(amount)}</li>"
            for domain, amount in current_score.deductions
        )
        parts.extend(
            (
                "</ul>",
                f"<p>Cap reason: {_text(cap_reason)}</p>",
                f"<p>Coverage: {_text(current_score.coverage)}</p>",
                f"<p>Confidence: {_text(current_score.confidence)}</p>",
                "<p>Incomplete: "
                f"{_text(str(current_score.incomplete).lower())}</p>",
                "<h3>Limits</h3>",
                "<ul>",
            )
        )
        parts.extend(f"<li>{_text(limit)}</li>" for limit in current_score.limits)
        parts.append("</ul>")
    parts.append("<h2>Findings</h2>")

    for finding in _sorted_findings(frozen_findings):
        disposition = _disposition_data(finding, records, now)
        parts.extend(
            (
                "<section>",
                f"<h3>{_text(finding.rule_id)}</h3>",
                f"<p>Domain: {_text(finding.domain.value)}</p>",
                f"<p>Severity: {_text(finding.severity.value)}</p>",
                f"<p>Root HMAC fingerprint: {_text(finding.root_fingerprint)}</p>",
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
        for evidence in _sorted_evidence(finding.evidence):
            parts.append(
                "<li>"
                f"Source: {_text(evidence.source)}; "
                f"HMAC fingerprint: {_text(evidence.fingerprint)}; "
                f"Masked evidence: {_text(evidence.masked)}"
                "</li>"
            )
        parts.extend(("</ul>", "</section>"))

    parts.extend(("</body>", "</html>"))
    return "\n".join(parts)


def _score_data(score: Score) -> dict[str, object]:
    return {
        "total": score.total,
        "deductions": [
            {"domain": domain.value, "amount": amount}
            for domain, amount in score.deductions
        ],
        "cap_reason": score.cap_reason,
        "coverage": score.coverage,
        "confidence": score.confidence,
        "incomplete": score.incomplete,
        "limits": list(score.limits),
    }


def _disposition_data(
    finding: Finding,
    records: dict[str, DispositionRecord],
    evaluated_at: datetime,
) -> dict[str, str]:
    evaluation = evaluate_disposition(finding, records, now=evaluated_at)
    if evaluation.record is None:
        return {"status": "open"}
    record = evaluation.record
    if evaluation.state == "expired":
        return {
            "status": "expired",
            "last_status": record.status.value,
            "reason": record.reason,
            "reviewer": record.reviewer,
            "created_at": record.created_at,
            "expires_at": record.expires_at,
        }
    return {
        "status": evaluation.state,
        "reason": record.reason,
        "reviewer": record.reviewer,
        "created_at": record.created_at,
        "expires_at": record.expires_at,
    }


def _finding_data(
    finding: Finding, disposition: dict[str, str]
) -> dict[str, object]:
    return {
        "rule_id": finding.rule_id,
        "domain": finding.domain.value,
        "severity": finding.severity.value,
        "root_hmac_fingerprint": finding.root_fingerprint,
        "evidence": [
            {
                "source": evidence.source,
                "hmac_fingerprint": evidence.fingerprint,
                "masked": evidence.masked,
            }
            for evidence in _sorted_evidence(finding.evidence)
        ],
        "disposition": disposition,
    }


def _sorted_findings(findings: Iterable[Finding]) -> tuple[Finding, ...]:
    return tuple(
        sorted(
            findings,
            key=lambda finding: (
                finding.rule_id,
                finding.domain.value,
                finding.severity.value,
                finding.root_fingerprint,
                tuple(
                    (item.fingerprint, item.source, item.masked)
                    for item in _sorted_evidence(finding.evidence)
                ),
            ),
        )
    )


def _sorted_evidence(evidence: Iterable[Evidence]) -> tuple[Evidence, ...]:
    return tuple(
        sorted(
            evidence,
            key=lambda item: (item.fingerprint, item.source, item.masked),
        )
    )


def _text(value: object) -> str:
    return escape(str(value), quote=True)
