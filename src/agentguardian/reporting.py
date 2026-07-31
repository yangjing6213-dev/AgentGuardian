from collections.abc import Iterable
from html import escape
import json

from . import __version__
from .domain import Evidence, Finding, Score


_PRODUCT = "AgentGuardian"


def render_json(
    score: Score,
    findings: Iterable[Finding],
    *,
    rule_version: str,
) -> str:
    report = {
        "product": _PRODUCT,
        "version": __version__,
        "rule_version": rule_version,
        "score": {
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
        },
        "findings": [_finding_data(finding) for finding in _sorted_findings(findings)],
    }
    return json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False)


def render_html(
    score: Score,
    findings: Iterable[Finding],
    *,
    rule_version: str,
) -> str:
    cap_reason = score.cap_reason or "None"
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
        f"<p>Score: {_text(score.total)}</p>",
        "<h2>Domain deductions</h2>",
        "<ul>",
    ]
    parts.extend(
        f"<li>{_text(domain.value)}: {_text(amount)}</li>"
        for domain, amount in score.deductions
    )
    parts.extend(
        (
            "</ul>",
            f"<p>Cap reason: {_text(cap_reason)}</p>",
            f"<p>Coverage: {_text(score.coverage)}</p>",
            f"<p>Confidence: {_text(score.confidence)}</p>",
            f"<p>Incomplete: {_text(str(score.incomplete).lower())}</p>",
            "<h2>Limits</h2>",
            "<ul>",
        )
    )
    parts.extend(f"<li>{_text(limit)}</li>" for limit in score.limits)
    parts.extend(("</ul>", "<h2>Findings</h2>"))

    for finding in _sorted_findings(findings):
        parts.extend(
            (
                "<section>",
                f"<h3>{_text(finding.rule_id)}</h3>",
                f"<p>Domain: {_text(finding.domain.value)}</p>",
                f"<p>Severity: {_text(finding.severity.value)}</p>",
                f"<p>Root HMAC fingerprint: {_text(finding.root_fingerprint)}</p>",
                "<ul>",
            )
        )
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


def _finding_data(finding: Finding) -> dict[str, object]:
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
