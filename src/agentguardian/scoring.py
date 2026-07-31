from collections.abc import Iterable

from .domain import Finding, RiskDomain, Score, Severity


_WEIGHTS = {
    RiskDomain.EXPOSURE: 20,
    RiskDomain.PRIVACY: 20,
    RiskDomain.CREDENTIALS: 20,
    RiskDomain.PERMISSIONS: 20,
    RiskDomain.RETENTION: 10,
    RiskDomain.SUPPLY_CHAIN: 10,
}
_SEVERITY_DEDUCTIONS = {
    Severity.CRITICAL: 12,
    Severity.HIGH: 7,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
}


def score(
    findings: Iterable[Finding],
    *,
    coverage: float,
    confidence: float = 1.0,
    limits: tuple[str, ...] = (),
) -> Score:
    highest_by_root: dict[tuple[RiskDomain, str], int] = {}
    rule_ids: set[str] = set()
    for finding in findings:
        rule_ids.add(finding.rule_id)
        key = (finding.domain, finding.root_fingerprint)
        deduction = _SEVERITY_DEDUCTIONS[finding.severity]
        highest_by_root[key] = max(highest_by_root.get(key, 0), deduction)

    deductions = tuple(
        (
            domain,
            min(
                _WEIGHTS[domain],
                sum(
                    amount
                    for (finding_domain, _), amount in highest_by_root.items()
                    if finding_domain is domain
                ),
            ),
        )
        for domain in RiskDomain
    )
    total = max(0, 100 - sum(amount for _, amount in deductions))

    cap_reason = None
    if "PUBLIC_ACTIVE_CREDENTIAL" in rule_ids:
        total = min(total, 39)
        cap_reason = "public_active_credential"
    elif "MCP_DANGEROUS_COMBINATION" in rule_ids:
        total = min(total, 59)
        cap_reason = "mcp_dangerous_combination"

    return Score(
        total=total,
        deductions=deductions,
        cap_reason=cap_reason,
        coverage=coverage,
        confidence=confidence,
        limits=limits,
        incomplete=bool(limits) or coverage < 1.0,
    )
