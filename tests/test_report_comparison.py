import json
import subprocess
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

import agentguardian.report_comparison as comparison_module
from agentguardian.dispositions import (
    DispositionRecord,
    DispositionStatus,
    disposition_index,
    reviewed_findings,
)
from agentguardian.domain import (
    MAX_REPORT_JSON_BYTES,
    Evidence,
    Finding,
    RiskDomain,
    Severity,
)
from agentguardian.report_comparison import (
    ReportSummary,
    compare_report_summaries,
    load_report_summary,
    parse_report_summary,
)
from agentguardian.reporting import render_json
from agentguardian.scoring import score
from agentguardian.workflow import CoverageState

EVALUATED_AT = datetime(2026, 8, 3, 12, tzinfo=timezone.utc)
ATTACKER_MARKER = r"C:\Synthetic\private\comparison-marker.txt"
MAX_BASELINE_BYTES = MAX_REPORT_JSON_BYTES


class _LimitStr(str):
    pass


def _report_inputs() -> tuple[tuple[Finding, ...], tuple[DispositionRecord, ...]]:
    findings = (
        Finding(
            "Z_RULE",
            RiskDomain.CREDENTIALS,
            Severity.HIGH,
            "b" * 64,
            (Evidence("config.env", "d" * 64, "sk-p************stuv"),),
            "f" * 64,
        ),
        Finding(
            "A_RULE",
            RiskDomain.EXPOSURE,
            Severity.LOW,
            "a" * 64,
            (Evidence("share.txt", "c" * 64, "masked share marker"),),
        ),
    )
    records = (
        DispositionRecord(
            "f" * 64,
            "Z_RULE",
            DispositionStatus.FALSE_POSITIVE,
            "Synthetic false positive",
            "Local reviewer",
            "2026-08-03T08:00:00Z",
            "2026-08-04T08:00:00Z",
        ),
    )
    return findings, records


def _render_report(
    findings: tuple[Finding, ...],
    records: tuple[DispositionRecord, ...],
    *,
    coverage: float,
    confidence: float,
    limits: tuple[str, ...],
) -> str:
    options = {
        "coverage": coverage,
        "confidence": confidence,
        "limits": limits,
    }
    technical = score(findings, **options)
    reviewed = score(
        reviewed_findings(
            findings,
            disposition_index(records),
            now=EVALUATED_AT,
        ),
        **options,
    )
    return render_json(
        technical,
        findings,
        rule_version="rules-1",
        reviewed_score=reviewed,
        dispositions=records,
        evaluated_at=EVALUATED_AT,
    )


def _report_json() -> str:
    findings, records = _report_inputs()
    return _render_report(
        findings,
        records,
        coverage=0.75,
        confidence=0.8,
        limits=("file_scan_limited", "byte_limit_reached"),
    )


def _assert_comparison_invalid(json_text: object) -> None:
    with pytest.raises(ValueError) as caught:
        parse_report_summary(json_text)  # type: ignore[arg-type]

    assert caught.value.args == ("REPORT_COMPARISON_INVALID",)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert ATTACKER_MARKER not in str(caught.value)
    assert ATTACKER_MARKER not in repr(caught.value)
    assert ATTACKER_MARKER not in repr(
        (caught.value, caught.value.__cause__, caught.value.__context__)
    )


def _assert_summary_comparison_invalid(baseline: object, current: object) -> None:
    with pytest.raises(ValueError) as caught:
        compare_report_summaries(baseline, current)  # type: ignore[arg-type]

    assert caught.value.args == ("REPORT_COMPARISON_INVALID",)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def _assert_file_invalid(path: object) -> None:
    with pytest.raises(ValueError, match="^REPORT_COMPARISON_INVALID$") as caught:
        load_report_summary(path)  # type: ignore[arg-type]

    rendered = repr(caught.value)
    assert str(caught.value) == "REPORT_COMPARISON_INVALID"
    assert ATTACKER_MARKER not in rendered
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert ATTACKER_MARKER not in repr(
        (caught.value, caught.value.__cause__, caught.value.__context__)
    )


def _current_report_json() -> str:
    findings, records = _report_inputs()
    findings += (
        Finding(
            "A_RULE",
            RiskDomain.PRIVACY,
            Severity.MEDIUM,
            "9" * 64,
            (
                Evidence(
                    "settings.json",
                    "8" * 64,
                    "masked configuration marker",
                ),
            ),
            "e" * 64,
        ),
    )
    records += (
        DispositionRecord(
            "e" * 64,
            "A_RULE",
            DispositionStatus.ACCEPTED_RISK,
            "Synthetic accepted risk",
            "Second reviewer",
            "2026-08-03T09:00:00Z",
            "2026-08-05T09:00:00Z",
        ),
    )
    return _render_report(
        findings,
        records,
        coverage=0.5,
        confidence=0.8,
        limits=("file_scan_limited", "directory_excluded"),
    )


def _disposition_semantics_report_json() -> str:
    findings = (
        Finding(
            "PUBLIC_ACTIVE_CREDENTIAL",
            RiskDomain.CREDENTIALS,
            Severity.CRITICAL,
            "1" * 64,
            (Evidence("public.env", "a" * 64, "sk-p************live"),),
            "a" * 64,
        ),
        Finding(
            "MCP_DANGEROUS_COMBINATION",
            RiskDomain.PERMISSIONS,
            Severity.LOW,
            "2" * 64,
            (Evidence("mcp.json", "b" * 64, "masked MCP permissions"),),
            "b" * 64,
        ),
        Finding(
            "HIGHER_PERMISSION",
            RiskDomain.PERMISSIONS,
            Severity.HIGH,
            "2" * 64,
            (Evidence("policy.json", "c" * 64, "masked policy setting"),),
        ),
        Finding(
            "EXPIRED_RULE",
            RiskDomain.PRIVACY,
            Severity.MEDIUM,
            "3" * 64,
            (Evidence("privacy.json", "d" * 64, "masked privacy value"),),
            "c" * 64,
        ),
    )
    records = (
        DispositionRecord(
            "a" * 64,
            "PUBLIC_ACTIVE_CREDENTIAL",
            DispositionStatus.FALSE_POSITIVE,
            "Synthetic false positive",
            "Local reviewer",
            "2026-08-03T08:00:00Z",
            "2026-08-04T08:00:00Z",
        ),
        DispositionRecord(
            "b" * 64,
            "MCP_DANGEROUS_COMBINATION",
            DispositionStatus.ACCEPTED_RISK,
            "Synthetic accepted risk",
            "Local reviewer",
            "2026-08-03T08:00:00Z",
            "2026-08-04T08:00:00Z",
        ),
        DispositionRecord(
            "c" * 64,
            "EXPIRED_RULE",
            DispositionStatus.FALSE_POSITIVE,
            "Synthetic expired review",
            "Local reviewer",
            "2026-08-01T08:00:00Z",
            "2026-08-02T08:00:00Z",
        ),
    )
    options = {"coverage": 1.0, "confidence": 1.0, "limits": ()}
    technical = score(findings, **options)
    reviewed = score(
        reviewed_findings(
            findings,
            disposition_index(records),
            now=EVALUATED_AT,
        ),
        **options,
    )
    return render_json(
        technical,
        findings,
        rule_version="rules-1",
        reviewed_score=reviewed,
        dispositions=records,
        evaluated_at=EVALUATED_AT,
    )


def test_schema_1_renderer_report_reduces_to_immutable_summary() -> None:
    summary = parse_report_summary(_report_json())

    assert summary.technical_score == 92
    assert summary.reviewed_score == 99
    assert summary.coverage == 0.75
    assert summary.coverage_state is CoverageState.LIMITED
    assert summary.finding_count == 2
    assert summary.rule_counts == (("A_RULE", 1), ("Z_RULE", 1))
    assert summary.severity_counts == (("high", 1), ("low", 1))
    assert summary.disposition_counts == (("false_positive", 1), ("open", 1))
    assert summary.limits == ("byte_limit_reached", "file_scan_limited")
    assert not hasattr(summary, "__dict__")

    with pytest.raises(FrozenInstanceError):
        summary.finding_count = 3  # type: ignore[misc]


def test_schema_1_summary_discards_item_level_values() -> None:
    summary = parse_report_summary(_report_json())
    rendered = repr(summary)

    for private_value in (
        "config.env",
        "masked share marker",
        "a" * 64,
        "f" * 64,
        "Synthetic false positive",
        "Local reviewer",
        "2026-08-03T08:00:00Z",
    ):
        assert private_value not in rendered


def test_schema_1_recomputes_caps_roots_and_disposition_semantics() -> None:
    summary = parse_report_summary(_disposition_semantics_report_json())

    assert summary.technical_score == 39
    assert summary.reviewed_score == 59
    assert summary.disposition_counts == (
        ("accepted_risk", 1),
        ("expired", 1),
        ("false_positive", 1),
        ("open", 1),
    )


@pytest.mark.parametrize(
    ("score_name", "field", "value"),
    (
        ("score", "total", 0),
        ("reviewed_score", "total", 0),
        ("score", "deductions", []),
        ("reviewed_score", "deductions", []),
        ("score", "cap_reason", "mcp_dangerous_combination"),
        ("reviewed_score", "cap_reason", "public_active_credential"),
    ),
)
def test_score_recomputation_rejects_independent_contradictions(
    score_name: str,
    field: str,
    value: object,
) -> None:
    payload = json.loads(_disposition_semantics_report_json())
    payload[score_name][field] = value

    _assert_comparison_invalid(json.dumps(payload))


def test_schema_1_evaluated_at_verifies_declared_disposition_state() -> None:
    payload = json.loads(_report_json())
    payload["evaluated_at"] = "2026-08-03T12:00:00Z"

    assert parse_report_summary(json.dumps(payload)).reviewed_score == 99


def test_old_schema_1_non_open_disposition_fails_closed() -> None:
    payload = json.loads(_report_json())
    del payload["evaluated_at"]
    disposition = payload["findings"][1]["disposition"]
    disposition["created_at"] = "2020-01-01T00:00:00Z"
    disposition["expires_at"] = "2020-01-02T00:00:00Z"

    _assert_comparison_invalid(json.dumps(payload))


def test_legacy_schema_0_non_open_disposition_fails_closed() -> None:
    payload = json.loads(_report_json())
    del payload["report_schema"]
    del payload["evaluated_at"]
    del payload["score"]["coverage_state"]
    del payload["reviewed_score"]["coverage_state"]

    _assert_comparison_invalid(json.dumps(payload))


@pytest.mark.parametrize(
    ("evaluated_at", "status", "created_at", "expires_at"),
    (
        (
            "2026-08-03T12:00:00Z",
            "false_positive",
            "2026-08-04T08:00:00Z",
            "2026-08-05T08:00:00Z",
        ),
        (
            "2026-08-03T12:00:00Z",
            "false_positive",
            "2026-08-01T08:00:00Z",
            "2026-08-02T08:00:00Z",
        ),
        (
            "2026-08-03T12:00:00.1Z",
            "false_positive",
            "2026-08-03T08:00:00Z",
            "2026-08-04T08:00:00Z",
        ),
        (
            "2026-08-03T12:00:00Z",
            "expired",
            "2026-08-03T08:00:00Z",
            "2026-08-04T08:00:00Z",
        ),
    ),
    ids=(
        "future-created",
        "expired-as-active",
        "noncanonical-time",
        "active-as-expired",
    ),
)
def test_schema_1_rejects_unverifiable_disposition_time_claims(
    evaluated_at: str,
    status: str,
    created_at: str,
    expires_at: str,
) -> None:
    payload = json.loads(_report_json())
    payload["evaluated_at"] = evaluated_at
    disposition = payload["findings"][1]["disposition"]
    disposition["status"] = status
    if status == "expired":
        disposition["last_status"] = "false_positive"
    disposition["created_at"] = created_at
    disposition["expires_at"] = expires_at

    _assert_comparison_invalid(json.dumps(payload))


def test_legacy_report_derives_coverage_state_and_matches_schema_1() -> None:
    schema_1 = json.loads(_report_json())
    for finding in schema_1["findings"]:
        finding["disposition"] = {"status": "open"}
    schema_1["reviewed_score"] = schema_1["score"]
    schema_1_text = json.dumps(schema_1)
    old_schema_1 = json.loads(schema_1_text)
    del old_schema_1["evaluated_at"]
    legacy = json.loads(schema_1_text)
    del legacy["report_schema"]
    del legacy["evaluated_at"]
    del legacy["score"]["coverage_state"]
    del legacy["reviewed_score"]["coverage_state"]

    current = parse_report_summary(schema_1_text)
    assert parse_report_summary(json.dumps(old_schema_1)) == current
    assert parse_report_summary(json.dumps(legacy)) == current


@pytest.mark.parametrize("hybrid", ("legacy_with_states", "schema_without_states"))
def test_legacy_partial_hybrids_fail_closed(hybrid: str) -> None:
    payload = json.loads(_report_json())
    if hybrid == "legacy_with_states":
        del payload["report_schema"]
    else:
        del payload["score"]["coverage_state"]
        del payload["reviewed_score"]["coverage_state"]

    _assert_comparison_invalid(json.dumps(payload))


def test_legacy_unknown_schema_fails_closed() -> None:
    payload = json.loads(_report_json())
    payload["report_schema"] = 2

    _assert_comparison_invalid(json.dumps(payload))


def test_aggregate_delta_comparison_is_signed_sorted_and_immutable() -> None:
    baseline = parse_report_summary(_report_json())
    current = parse_report_summary(_current_report_json())

    comparison = compare_report_summaries(baseline, current)

    assert comparison.baseline == baseline
    assert comparison.current == current
    assert comparison.technical_score_delta == -3
    assert comparison.reviewed_score_delta == -3
    assert comparison.coverage_delta == -0.25
    assert comparison.finding_count_delta == 1
    assert comparison.rule_count_deltas == (("A_RULE", 1), ("Z_RULE", 0))
    assert comparison.severity_count_deltas == (
        ("high", 0),
        ("low", 0),
        ("medium", 1),
    )
    assert comparison.disposition_count_deltas == (
        ("accepted_risk", 1),
        ("false_positive", 0),
        ("open", 0),
    )
    assert comparison.added_limits == ("directory_excluded",)
    assert comparison.resolved_limits == ("byte_limit_reached",)
    assert not hasattr(comparison, "__dict__")

    with pytest.raises(FrozenInstanceError):
        comparison.finding_count_delta = 2  # type: ignore[misc]


def test_aggregate_delta_comparison_retains_no_item_level_data_or_claims() -> None:
    comparison = compare_report_summaries(
        parse_report_summary(_report_json()),
        parse_report_summary(_current_report_json()),
    )
    forbidden_names = {
        "evidence",
        "source",
        "masked",
        "fingerprint",
        "disposition_ref",
        "reason",
        "reviewer",
        "timestamp",
        "path",
        "new",
        "fixed",
        "matched",
        "unchanged",
    }

    assert forbidden_names.isdisjoint(field.name for field in fields(comparison))
    rendered = repr(comparison)
    for private_value in (
        "settings.json",
        "masked configuration marker",
        "9" * 64,
        "Synthetic accepted risk",
        "Second reviewer",
        "2026-08-03T09:00:00Z",
    ):
        assert private_value not in rendered


@pytest.mark.parametrize(
    ("level", "operation"),
    (
        ("top", "missing"),
        ("top", "extra"),
        ("score", "missing"),
        ("score", "extra"),
        ("deduction", "missing"),
        ("deduction", "extra"),
        ("finding", "missing"),
        ("finding", "extra"),
        ("evidence", "missing"),
        ("evidence", "extra"),
        ("disposition", "missing"),
        ("disposition", "extra"),
    ),
)
def test_hostile_missing_and_extra_keys_fail_closed(
    level: str,
    operation: str,
) -> None:
    payload = json.loads(_report_json())
    targets = {
        "top": (payload, "version"),
        "score": (payload["score"], "confidence"),
        "deduction": (payload["score"]["deductions"][0], "amount"),
        "finding": (payload["findings"][0], "domain"),
        "evidence": (payload["findings"][0]["evidence"][0], "masked"),
        "disposition": (payload["findings"][0]["disposition"], "status"),
    }
    target, key = targets[level]
    if operation == "missing":
        del target[key]
    else:
        target["unexpected"] = ATTACKER_MARKER

    _assert_comparison_invalid(json.dumps(payload))


def test_hostile_duplicate_json_keys_fail_closed() -> None:
    valid = _report_json()
    duplicate = (
        '{"product":'
        + json.dumps(ATTACKER_MARKER)
        + ","
        + valid[1:]
    )

    _assert_comparison_invalid(duplicate)


def test_hostile_nested_duplicate_json_keys_fail_closed() -> None:
    valid = _report_json()
    duplicate = valid.replace(
        '"source": "share.txt"',
        '"source": "share.txt", "source": '
        + json.dumps(ATTACKER_MARKER),
        1,
    )

    _assert_comparison_invalid(duplicate)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("report_schema", True),
        ("total", True),
        ("amount", True),
        ("coverage", True),
        ("confidence", True),
        ("incomplete", 1),
    ),
)
def test_hostile_boolean_numeric_values_fail_closed(
    field: str,
    value: object,
) -> None:
    payload = json.loads(_report_json())
    if field == "report_schema":
        payload[field] = value
    elif field == "amount":
        payload["score"]["deductions"][0][field] = value
    else:
        payload["score"][field] = value

    _assert_comparison_invalid(json.dumps(payload))


@pytest.mark.parametrize("value", (float("nan"), float("inf"), float("-inf")))
def test_hostile_nonfinite_values_fail_closed(value: float) -> None:
    payload = json.loads(_report_json())
    payload["score"]["coverage"] = value

    _assert_comparison_invalid(json.dumps(payload))


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("domain", "unknown_domain"),
        ("severity", "urgent"),
        ("status", "suppressed"),
        ("last_status", "expired"),
    ),
)
def test_hostile_invalid_finding_domains_and_statuses_fail_closed(
    field: str,
    value: str,
) -> None:
    payload = json.loads(_report_json())
    finding = payload["findings"][0]
    if field in ("domain", "severity"):
        finding[field] = value
    elif field == "status":
        finding["disposition"][field] = value
    else:
        finding["disposition"] = {
            "status": "expired",
            "last_status": value,
            "reason": "Synthetic expired review",
            "reviewer": "Local reviewer",
            "created_at": "2026-08-01T08:00:00Z",
            "expires_at": "2026-08-02T08:00:00Z",
        }

    _assert_comparison_invalid(json.dumps(payload))


@pytest.mark.parametrize("rule_id", ("lowercase", "A" * 65))
def test_hostile_invalid_rule_ids_fail_closed(rule_id: str) -> None:
    payload = json.loads(_report_json())
    payload["findings"][0]["rule_id"] = rule_id

    _assert_comparison_invalid(json.dumps(payload))


@pytest.mark.parametrize(
    "target",
    ("version", "rule_version", "source", "masked", "reason", "reviewer"),
)
def test_hostile_unsafe_strings_fail_closed(target: str) -> None:
    payload = json.loads(_report_json())
    if target in ("version", "rule_version"):
        payload[target] = ATTACKER_MARKER
    elif target in ("source", "masked"):
        payload["findings"][0]["evidence"][0][target] = ATTACKER_MARKER
    else:
        disposition = payload["findings"][1]["disposition"]
        disposition[target] = ATTACKER_MARKER

    _assert_comparison_invalid(json.dumps(payload))


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("created_at", "not-a-timestamp"),
        ("expires_at", "2026-08-03T07:00:00Z"),
    ),
)
def test_hostile_invalid_disposition_timestamps_fail_closed(
    field: str,
    value: str,
) -> None:
    payload = json.loads(_report_json())
    payload["findings"][1]["disposition"][field] = value

    _assert_comparison_invalid(json.dumps(payload))


@pytest.mark.parametrize("target", ("root", "evidence"))
def test_hostile_malformed_fingerprints_fail_closed(target: str) -> None:
    payload = json.loads(_report_json())
    if target == "root":
        payload["findings"][0]["root_hmac_fingerprint"] = ATTACKER_MARKER
    else:
        payload["findings"][0]["evidence"][0][
            "hmac_fingerprint"
        ] = ATTACKER_MARKER

    _assert_comparison_invalid(json.dumps(payload))


@pytest.mark.parametrize("limits", (("file_scan_limited",) * 2, ("unknown",)))
def test_hostile_duplicate_and_unknown_limits_fail_closed(
    limits: tuple[str, ...],
) -> None:
    payload = json.loads(_report_json())
    payload["score"]["limits"] = list(limits)

    _assert_comparison_invalid(json.dumps(payload))


@pytest.mark.parametrize("field", ("coverage", "confidence", "limits"))
def test_hostile_contradictory_reviewed_coverage_fails_closed(field: str) -> None:
    payload = json.loads(_report_json())
    replacements = {
        "coverage": 0.5,
        "confidence": 0.5,
        "limits": ["file_scan_limited"],
    }
    payload["reviewed_score"][field] = replacements[field]

    _assert_comparison_invalid(json.dumps(payload))


def test_hostile_2001_findings_fail_before_item_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = json.loads(_report_json())
    payload["findings"] = [payload["findings"][0]] * 2_001

    def fail_if_called(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError(ATTACKER_MARKER)

    monkeypatch.setattr(comparison_module, "Finding", fail_if_called)

    _assert_comparison_invalid(json.dumps(payload))


def test_hostile_4001_evidence_fail_before_item_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = json.loads(_report_json())
    evidence = payload["findings"][0]["evidence"][0]
    payload["findings"] = [payload["findings"][0]]
    payload["findings"][0]["evidence"] = [evidence] * 4_001

    def fail_if_called(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError(ATTACKER_MARKER)

    monkeypatch.setattr(comparison_module, "Evidence", fail_if_called)

    _assert_comparison_invalid(json.dumps(payload))


def test_exact_finding_and_evidence_limits_are_accepted() -> None:
    finding = Finding(
        "A_RULE",
        RiskDomain.EXPOSURE,
        Severity.LOW,
        "a" * 64,
        (
            Evidence("first.txt", "b" * 64, "masked first value"),
            Evidence("second.txt", "c" * 64, "masked second value"),
        ),
    )
    findings = (finding,) * 2_000
    report = render_json(
        score(
            findings,
            coverage=0.75,
            confidence=0.8,
            limits=("file_scan_limited",),
        ),
        findings,
        rule_version="rules-1",
        evaluated_at=EVALUATED_AT,
    )

    summary = parse_report_summary(report)

    assert summary.finding_count == 2_000
    assert summary.rule_counts == (("A_RULE", 2_000),)
    assert summary.severity_counts == (("low", 2_000),)
    assert summary.disposition_counts == (("open", 2_000),)


def test_parser_accepts_exact_utf8_budget_and_rejects_one_byte_over() -> None:
    report = _report_json()
    padding = " " * (MAX_BASELINE_BYTES - len(report.encode("utf-8")))

    exact = padding + report
    assert len(exact.encode("utf-8")) == MAX_BASELINE_BYTES
    assert parse_report_summary(exact) == parse_report_summary(report)

    _assert_comparison_invalid(" " + exact)


def test_public_parser_rejects_non_text_without_file_access() -> None:
    _assert_comparison_invalid(b"{}")


def test_public_parser_normalizes_real_unpaired_surrogate() -> None:
    hostile = chr(0xD800)

    _assert_comparison_invalid(hostile)


def test_public_comparison_normalizes_forged_missing_summary_slots() -> None:
    forged = object.__new__(ReportSummary)

    _assert_summary_comparison_invalid(
        forged,
        parse_report_summary(_report_json()),
    )


@pytest.mark.parametrize(
    "limits",
    (
        [],
        ([ATTACKER_MARKER],),
        ("file_scan_limited", 1),
        (_LimitStr("file_scan_limited"),),
    ),
    ids=("list", "unhashable-item", "mixed-item", "str-subclass"),
)
def test_public_comparison_normalizes_forged_limit_types(
    limits: object,
) -> None:
    valid = parse_report_summary(_report_json())
    forged = replace(valid, limits=limits)  # type: ignore[arg-type]

    _assert_summary_comparison_invalid(forged, valid)


@pytest.mark.parametrize(
    ("coverage", "coverage_state", "limits"),
    (
        (0.0, CoverageState.LIMITED, ("no_supported_files",)),
        (
            0.0,
            CoverageState.LIMITED,
            ("file_scan_limited", "no_supported_files"),
        ),
        (1.0, CoverageState.COMPLETE, ("file_scan_limited",)),
        (0.5, CoverageState.NO_SUPPORTED_FILES, ("no_supported_files",)),
        (0.0, CoverageState.NO_SUPPORTED_FILES, ("file_scan_limited",)),
    ),
)
def test_public_comparison_rejects_contradictory_summary_coverage(
    coverage: float,
    coverage_state: CoverageState,
    limits: tuple[str, ...],
) -> None:
    valid = parse_report_summary(_report_json())
    forged = replace(
        valid,
        coverage=coverage,
        coverage_state=coverage_state,
        limits=limits,
    )

    _assert_summary_comparison_invalid(forged, valid)


def test_summary_validation_propagates_internal_classifier_defects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    valid = parse_report_summary(_report_json())

    def fail_classifier(_score: object) -> object:
        raise RuntimeError(ATTACKER_MARKER)

    monkeypatch.setattr(comparison_module, "classify_coverage", fail_classifier)

    with pytest.raises(RuntimeError, match="comparison-marker") as caught:
        compare_report_summaries(valid, valid)

    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


@pytest.mark.parametrize(
    "masked",
    ("masked\x00value", "masked\nvalue", "masked\u202evalue"),
)
def test_renderer_round_trip_accepts_domain_valid_masked_text(
    masked: str,
) -> None:
    findings = (
        Finding(
            "A_RULE",
            RiskDomain.EXPOSURE,
            Severity.LOW,
            "a" * 64,
            (Evidence("notes.txt", "b" * 64, masked),),
        ),
    )
    report = render_json(
        score(findings, coverage=1.0),
        findings,
        rule_version="rules-1",
        evaluated_at=EVALUATED_AT,
    )

    summary = parse_report_summary(report)

    assert summary.technical_score == 99
    assert summary.reviewed_score == 99
    assert summary.coverage == 1.0
    assert summary.coverage_state is CoverageState.COMPLETE
    assert summary.finding_count == 1
    assert summary.rule_counts == (("A_RULE", 1),)
    assert summary.severity_counts == (("low", 1),)
    assert summary.disposition_counts == (("open", 1),)
    assert summary.limits == ()


@pytest.mark.parametrize(
    "exception_type",
    (AttributeError, RuntimeError, TypeError, UnicodeError),
)
def test_parser_propagates_unexpected_internal_dependency_defects(
    monkeypatch: pytest.MonkeyPatch,
    exception_type: type[Exception],
) -> None:
    def fail_dependency(*_args: object, **_kwargs: object) -> object:
        raise exception_type(ATTACKER_MARKER)

    monkeypatch.setattr(
        comparison_module,
        "validate_safe_annotation",
        fail_dependency,
    )

    with pytest.raises(exception_type, match="comparison-marker") as caught:
        parse_report_summary(_report_json())

    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_parser_propagates_internal_json_unicode_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_json(*_args: object, **_kwargs: object) -> object:
        raise UnicodeError(ATTACKER_MARKER)

    monkeypatch.setattr(comparison_module.json, "loads", fail_json)

    with pytest.raises(UnicodeError, match="comparison-marker") as caught:
        parse_report_summary(_report_json())

    assert str(caught.value) == ATTACKER_MARKER
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_report_file_loader_propagates_internal_json_unicode_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_path = tmp_path / "internal-json-unicode.json"
    report_path.write_text(_report_json(), encoding="utf-8")

    def fail_json(*_args: object, **_kwargs: object) -> object:
        raise UnicodeError(ATTACKER_MARKER)

    monkeypatch.setattr(comparison_module.json, "loads", fail_json)

    with pytest.raises(UnicodeError, match="comparison-marker") as caught:
        load_report_summary(report_path)

    assert str(caught.value) == ATTACKER_MARKER
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_local_report_file_loads_through_the_canonical_parser(tmp_path: Path) -> None:
    report_path = tmp_path / "baseline.json"
    report_path.write_text(_report_json(), encoding="utf-8")

    summary = load_report_summary(report_path)

    assert summary == parse_report_summary(_report_json())
    assert not hasattr(summary, "__dict__")


def test_report_file_requires_json_suffix(tmp_path: Path) -> None:
    report_path = tmp_path / "baseline.txt"
    report_path.write_text(_report_json(), encoding="utf-8")

    _assert_file_invalid(report_path)


def test_missing_report_file_fails_closed(tmp_path: Path) -> None:
    _assert_file_invalid(tmp_path / "missing.json")


def test_report_file_directory_fails_closed(tmp_path: Path) -> None:
    report_path = tmp_path / "directory.json"
    report_path.mkdir()

    _assert_file_invalid(report_path)


@pytest.mark.parametrize(
    "path",
    (
        r"\\synthetic-server\share\baseline.json",
        r"\\.\NUL.json",
        r"\\?\C:\Synthetic\baseline.json",
    ),
    ids=("unc", "device", "extended-device"),
)
def test_report_file_rejects_unc_and_device_paths(path: str) -> None:
    _assert_file_invalid(path)


def test_report_file_requires_strict_utf8(tmp_path: Path) -> None:
    report_path = tmp_path / "invalid-utf8.json"
    report_path.write_bytes(b"\xff\xfe")

    _assert_file_invalid(report_path)


def test_oversized_report_file_fails_before_parsing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_path = tmp_path / "oversized.json"
    report_path.write_bytes(b" " * (MAX_BASELINE_BYTES + 1))

    def fail_parser(_text: str) -> ReportSummary:
        raise AssertionError("oversized input reached parser")

    def fail_open(*_args: object) -> object:
        raise AssertionError("oversized input was opened")

    monkeypatch.setattr(comparison_module, "parse_report_summary", fail_parser)
    monkeypatch.setattr(comparison_module, "open", fail_open, raising=False)

    _assert_file_invalid(report_path)


def test_report_file_accepts_exact_byte_limit(tmp_path: Path) -> None:
    report_path = tmp_path / "exact-limit.JSON"
    content = _report_json().encode("utf-8")
    report_path.write_bytes(content + b" " * (MAX_BASELINE_BYTES - len(content)))

    assert load_report_summary(report_path) == parse_report_summary(_report_json())


def test_report_file_symlink_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text(_report_json(), encoding="utf-8")
    linked = tmp_path / "linked.json"
    try:
        linked.symlink_to(target)
    except OSError as error:
        if getattr(error, "winerror", None) in (5, 1314):
            pytest.skip("file symlink creation permission unavailable")
        raise

    _assert_file_invalid(linked)


def test_report_file_symlink_ancestor_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "baseline.json").write_text(_report_json(), encoding="utf-8")
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(target, target_is_directory=True)
    except OSError as error:
        if getattr(error, "winerror", None) in (5, 1314):
            pytest.skip("directory symlink creation permission unavailable")
        raise

    _assert_file_invalid(linked / "baseline.json")


def test_report_file_windows_junction_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "junction-target"
    target.mkdir()
    (target / "baseline.json").write_text(_report_json(), encoding="utf-8")
    junction = tmp_path / "junction"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
        capture_output=True,
        check=False,
        text=True,
    )
    if created.returncode != 0:
        details = f"{created.stdout}\n{created.stderr}".casefold()
        permission_markers = (
            "privilege",
            "permission",
            "access is denied",
            "权限",
            "拒绝访问",
        )
        if any(marker in details for marker in permission_markers):
            pytest.skip("directory junction creation permission unavailable")
        pytest.fail("directory junction creation failed without a permission error")

    _assert_file_invalid(junction / "baseline.json")


def test_report_file_read_is_bounded_and_rechecks_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_path = tmp_path / "baseline.json"
    report_path.write_text(_report_json(), encoding="utf-8")
    real_open = open
    real_fstat = comparison_module.os.fstat
    read_sizes: list[int] = []
    fstat_calls: list[int] = []
    path_checks: list[Path] = []
    real_path_check = comparison_module._checked_file_state

    class TrackingStream:
        def __init__(self) -> None:
            self._stream = real_open(report_path, "rb")

        def __enter__(self) -> "TrackingStream":
            return self

        def __exit__(self, *args: object) -> None:
            self._stream.close()

        def fileno(self) -> int:
            return self._stream.fileno()

        def read(self, size: int) -> bytes:
            read_sizes.append(size)
            return self._stream.read(size)

    def checked_path(path: Path) -> object:
        path_checks.append(path)
        return real_path_check(path)

    def checked_fstat(descriptor: int) -> object:
        fstat_calls.append(descriptor)
        return real_fstat(descriptor)

    monkeypatch.setattr(comparison_module, "open", lambda *_args: TrackingStream(), raising=False)
    monkeypatch.setattr(comparison_module, "_checked_file_state", checked_path)
    monkeypatch.setattr(comparison_module.os, "fstat", checked_fstat)

    summary = load_report_summary(report_path)

    assert summary == parse_report_summary(_report_json())
    assert read_sizes == [MAX_BASELINE_BYTES + 1]
    assert len(fstat_calls) == 2
    assert path_checks == [report_path, report_path]


def test_report_file_growth_during_bounded_read_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_path = tmp_path / "growing.json"
    report_path.write_text(_report_json(), encoding="utf-8")
    real_open = open
    read_sizes: list[int] = []

    class GrowingStream:
        def __init__(self) -> None:
            self._stream = real_open(report_path, "rb")

        def __enter__(self) -> "GrowingStream":
            return self

        def __exit__(self, *args: object) -> None:
            self._stream.close()

        def fileno(self) -> int:
            return self._stream.fileno()

        def read(self, size: int) -> bytes:
            read_sizes.append(size)
            return b"x" * size

    monkeypatch.setattr(comparison_module, "open", lambda *_args: GrowingStream(), raising=False)

    _assert_file_invalid(report_path)
    assert read_sizes == [MAX_BASELINE_BYTES + 1]


def test_report_file_replacement_race_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_path = tmp_path / "replaced.json"
    report_path.write_text(_report_json(), encoding="utf-8")
    initial = comparison_module.os.lstat(report_path)

    class ReplacedState:
        st_dev = initial.st_dev
        st_ino = initial.st_ino + 1
        st_size = initial.st_size
        st_mtime_ns = initial.st_mtime_ns

    states = iter((initial, ReplacedState()))
    calls: list[Path] = []

    def changing_state(path: Path) -> object:
        calls.append(path)
        return next(states)

    monkeypatch.setattr(comparison_module, "_checked_file_state", changing_state)

    _assert_file_invalid(report_path)
    assert calls == [report_path, report_path]


def test_report_file_reparse_change_around_read_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_path = tmp_path / "reparse-change.json"
    report_path.write_text(_report_json(), encoding="utf-8")
    real_fstat = comparison_module.os.fstat
    calls = 0

    class ReparseState:
        def __init__(self, original: object) -> None:
            self.st_mode = original.st_mode
            self.st_dev = original.st_dev
            self.st_ino = original.st_ino
            self.st_size = original.st_size
            self.st_mtime_ns = original.st_mtime_ns
            self.st_file_attributes = comparison_module._REPARSE_POINT

    def changing_fstat(descriptor: int) -> object:
        nonlocal calls
        calls += 1
        state = real_fstat(descriptor)
        return state if calls == 1 else ReparseState(state)

    monkeypatch.setattr(comparison_module.os, "fstat", changing_fstat)

    _assert_file_invalid(report_path)
    assert calls == 2


def test_report_file_discards_path_and_item_level_private_text(
    tmp_path: Path,
) -> None:
    secret = "private-secret-marker"
    payload = json.loads(_report_json())
    payload["findings"][0]["evidence"][0]["masked"] = secret
    report_path = tmp_path / "private-baseline.json"
    report_path.write_text(json.dumps(payload), encoding="utf-8")

    summary = load_report_summary(report_path)
    comparison = compare_report_summaries(summary, summary)
    rendered = repr((summary, comparison))

    assert secret not in rendered
    assert str(report_path) not in rendered
    assert ATTACKER_MARKER not in rendered


def test_malformed_report_file_error_discards_path_and_content(
    tmp_path: Path,
) -> None:
    secret = "private-secret-marker"
    report_path = tmp_path / "malformed-private.json"
    report_path.write_text(
        json.dumps({"secret": secret, "path": str(report_path)}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="^REPORT_COMPARISON_INVALID$") as caught:
        load_report_summary(report_path)

    rendered = repr(caught.value)
    assert secret not in rendered
    assert str(report_path) not in rendered
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_report_file_loader_normalizes_loader_value_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_path = tmp_path / "internal-error.json"
    report_path.write_text(_report_json(), encoding="utf-8")

    def fail_fstat(_descriptor: int) -> object:
        raise ValueError(ATTACKER_MARKER)

    monkeypatch.setattr(comparison_module.os, "fstat", fail_fstat)

    with pytest.raises(ValueError, match="^REPORT_COMPARISON_INVALID$") as caught:
        load_report_summary(report_path)

    assert ATTACKER_MARKER not in repr(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_report_file_loader_normalizes_parser_value_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_path = tmp_path / "parser-value-error.json"
    report_path.write_text(_report_json(), encoding="utf-8")

    def fail_parser(_text: str) -> ReportSummary:
        raise ValueError(ATTACKER_MARKER)

    monkeypatch.setattr(comparison_module, "parse_report_summary", fail_parser)

    _assert_file_invalid(report_path)


@pytest.mark.parametrize(
    "stage",
    ("path", "lstat", "open", "read", "fstat"),
)
def test_report_file_loader_normalizes_file_stage_os_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
) -> None:
    report_path = tmp_path / "file-stage-error.json"
    report_path.write_text(_report_json(), encoding="utf-8")
    real_open = open

    class FailingReadStream:
        def __init__(self) -> None:
            self._stream = real_open(report_path, "rb")

        def __enter__(self) -> "FailingReadStream":
            return self

        def __exit__(self, *args: object) -> None:
            self._stream.close()

        def fileno(self) -> int:
            return self._stream.fileno()

        def read(self, _size: int) -> bytes:
            raise OSError(ATTACKER_MARKER)

    def fail(*_args: object) -> object:
        raise OSError(ATTACKER_MARKER)

    if stage == "path":
        monkeypatch.setattr(comparison_module, "_validated_baseline_path", fail)
    elif stage == "lstat":
        monkeypatch.setattr(comparison_module.os, "lstat", fail)
    elif stage == "open":
        monkeypatch.setattr(comparison_module, "open", fail, raising=False)
    elif stage == "read":
        monkeypatch.setattr(
            comparison_module,
            "open",
            lambda *_args: FailingReadStream(),
            raising=False,
        )
    else:
        monkeypatch.setattr(comparison_module.os, "fstat", fail)

    _assert_file_invalid(report_path)


@pytest.mark.parametrize("exception_type", (OSError, UnicodeError))
def test_report_file_loader_propagates_parser_boundary_faults(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    exception_type: type[Exception],
) -> None:
    report_path = tmp_path / "parser-boundary-fault.json"
    report_path.write_text(_report_json(), encoding="utf-8")

    def fail_parser(_text: str) -> ReportSummary:
        raise exception_type(ATTACKER_MARKER)

    monkeypatch.setattr(comparison_module, "parse_report_summary", fail_parser)

    with pytest.raises(exception_type, match="comparison-marker") as caught:
        load_report_summary(report_path)

    assert str(caught.value) == ATTACKER_MARKER
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_report_file_loader_documents_residual_same_user_race() -> None:
    documentation = " ".join((load_report_summary.__doc__ or "").split())

    assert "same-user path-replacement race" in documentation
    assert "portable python on windows" in documentation.casefold()
