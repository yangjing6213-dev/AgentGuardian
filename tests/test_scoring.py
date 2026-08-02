import math
from datetime import datetime, timezone
from itertools import permutations

import pytest

from agentguardian.dispositions import (
    DispositionRecord,
    DispositionStatus,
    disposition_index,
    reviewed_findings,
)
from agentguardian.domain import Finding, RiskDomain, Severity
from agentguardian.scoring import score


NOW = datetime(2026, 8, 2, 9, 0, tzinfo=timezone.utc)


def _finding(
    rule_id: str,
    domain: RiskDomain,
    severity: Severity,
    fingerprint: str,
) -> Finding:
    return Finding(rule_id, domain, severity, fingerprint * 64, ())


def test_empty_findings_return_full_score_in_domain_order() -> None:
    result = score((), coverage=1.0)

    assert result.total == 100
    assert result.deductions == tuple((domain, 0) for domain in RiskDomain)
    assert result.cap_reason is None
    assert result.coverage == 1.0
    assert result.confidence == 1.0
    assert result.limits == ()
    assert result.incomplete is False


def test_same_domain_and_root_uses_only_highest_severity() -> None:
    findings = (
        _finding("LOW", RiskDomain.PRIVACY, Severity.LOW, "a"),
        _finding("CRITICAL", RiskDomain.PRIVACY, Severity.CRITICAL, "a"),
        _finding("HIGH", RiskDomain.PRIVACY, Severity.HIGH, "a"),
        _finding("OTHER_ROOT", RiskDomain.PRIVACY, Severity.LOW, "b"),
    )

    result = score(findings, coverage=1.0)

    assert dict(result.deductions)[RiskDomain.PRIVACY] == 13
    assert result.total == 87


def test_domain_deduction_is_capped_at_its_weight() -> None:
    findings = (
        _finding("ONE", RiskDomain.CREDENTIALS, Severity.CRITICAL, "a"),
        _finding("TWO", RiskDomain.CREDENTIALS, Severity.CRITICAL, "b"),
        _finding("THREE", RiskDomain.RETENTION, Severity.CRITICAL, "c"),
    )

    result = score(findings, coverage=1.0)

    deductions = dict(result.deductions)
    assert deductions[RiskDomain.CREDENTIALS] == 20
    assert deductions[RiskDomain.RETENTION] == 10
    assert result.total == 70


@pytest.mark.parametrize(
    ("rule_ids", "expected_total", "expected_reason"),
    (
        (("PUBLIC_ACTIVE_CREDENTIAL",), 39, "public_active_credential"),
        (("MCP_DANGEROUS_COMBINATION",), 59, "mcp_dangerous_combination"),
        (
            ("MCP_DANGEROUS_COMBINATION", "PUBLIC_ACTIVE_CREDENTIAL"),
            39,
            "public_active_credential",
        ),
    ),
)
def test_risk_rules_cap_total(
    rule_ids: tuple[str, ...],
    expected_total: int,
    expected_reason: str,
) -> None:
    findings = tuple(
        _finding(rule_id, RiskDomain.PERMISSIONS, Severity.LOW, chr(97 + index))
        for index, rule_id in enumerate(rule_ids)
    )

    result = score(findings, coverage=1.0)

    assert result.total == expected_total
    assert result.cap_reason == expected_reason


def test_input_order_does_not_change_score() -> None:
    findings = (
        _finding("MEDIUM", RiskDomain.EXPOSURE, Severity.MEDIUM, "a"),
        _finding("HIGH", RiskDomain.PRIVACY, Severity.HIGH, "b"),
        _finding("LOW", RiskDomain.SUPPLY_CHAIN, Severity.LOW, "c"),
    )

    results = {score(order, coverage=1.0) for order in permutations(findings)}

    assert len(results) == 1


def test_score_accepts_one_shot_finding_generator() -> None:
    findings = (
        finding
        for finding in (
            _finding("HIGH", RiskDomain.EXPOSURE, Severity.HIGH, "a"),
            _finding("LOW", RiskDomain.PRIVACY, Severity.LOW, "b"),
        )
    )

    result = score(findings, coverage=1.0)

    assert result.total == 92
    assert tuple(findings) == ()


def test_coverage_confidence_and_limits_are_display_only() -> None:
    finding = _finding("LOW", RiskDomain.EXPOSURE, Severity.LOW, "a")

    complete = score((finding,), coverage=1.0)
    partial = score(
        (finding,),
        coverage=0.4,
        confidence=0.25,
        limits=("未扫描浏览器",),
    )

    assert complete.total == partial.total == 99
    assert partial.coverage == 0.4
    assert partial.confidence == 0.25
    assert partial.limits == ("未扫描浏览器",)
    assert partial.incomplete is True
    assert score((), coverage=1.0, limits=("manual_limit",)).incomplete is True


@pytest.mark.parametrize(
    ("name", "value"),
    (
        ("coverage", -0.01),
        ("coverage", 1.01),
        ("coverage", math.nan),
        ("confidence", -0.01),
        ("confidence", 1.01),
        ("confidence", math.nan),
    ),
)
def test_score_rejects_out_of_range_boundaries(name: str, value: float) -> None:
    arguments = {"coverage": 1.0, "confidence": 1.0, name: value}

    with pytest.raises(ValueError, match=name):
        score((), **arguments)


def test_score_rejects_mutable_limits() -> None:
    with pytest.raises(TypeError, match="limits"):
        score((), coverage=1.0, limits=["mutable"])  # type: ignore[arg-type]


def test_accepted_risk_does_not_improve_reviewed_score() -> None:
    finding = Finding(
        "HIGH",
        RiskDomain.CREDENTIALS,
        Severity.HIGH,
        "a" * 64,
        (),
        "d" * 64,
    )
    record = DispositionRecord(
        "d" * 64,
        "HIGH",
        DispositionStatus.ACCEPTED_RISK,
        "Synthetic accepted risk",
        "Local reviewer",
        "2026-08-02T08:00:00Z",
        "2026-08-03T08:00:00Z",
    )

    technical = score((finding,), coverage=1.0)
    reviewed = score(
        reviewed_findings((finding,), disposition_index((record,)), now=NOW),
        coverage=1.0,
    )

    assert reviewed == technical
    assert reviewed.total == 93


def test_expired_false_positive_reenters_deductions_and_caps() -> None:
    finding = Finding(
        "PUBLIC_ACTIVE_CREDENTIAL",
        RiskDomain.CREDENTIALS,
        Severity.HIGH,
        "a" * 64,
        (),
        "e" * 64,
    )
    record = DispositionRecord(
        "e" * 64,
        "PUBLIC_ACTIVE_CREDENTIAL",
        DispositionStatus.FALSE_POSITIVE,
        "Synthetic expired fixture",
        "Local reviewer",
        "2026-08-01T08:00:00Z",
        "2026-08-02T09:00:00Z",
    )

    technical = score((finding,), coverage=1.0)
    reviewed = score(
        reviewed_findings((finding,), disposition_index((record,)), now=NOW),
        coverage=1.0,
    )

    assert reviewed == technical
    assert reviewed.total == 39
    assert reviewed.cap_reason == "public_active_credential"


def test_active_false_positive_removes_reviewed_deduction_and_cap_only() -> None:
    finding = Finding(
        "PUBLIC_ACTIVE_CREDENTIAL",
        RiskDomain.CREDENTIALS,
        Severity.HIGH,
        "a" * 64,
        (),
        "f" * 64,
    )
    record = DispositionRecord(
        "f" * 64,
        "PUBLIC_ACTIVE_CREDENTIAL",
        DispositionStatus.FALSE_POSITIVE,
        "Synthetic false positive",
        "Local reviewer",
        "2026-08-02T08:00:00Z",
        "2026-08-03T08:00:00Z",
    )

    technical = score((finding,), coverage=1.0)
    reviewed = score(
        reviewed_findings((finding,), disposition_index((record,)), now=NOW),
        coverage=1.0,
    )

    assert technical.total == 39
    assert technical.cap_reason == "public_active_credential"
    assert dict(technical.deductions)[RiskDomain.CREDENTIALS] == 7
    assert reviewed.total == 100
    assert reviewed.cap_reason is None
    assert dict(reviewed.deductions)[RiskDomain.CREDENTIALS] == 0
