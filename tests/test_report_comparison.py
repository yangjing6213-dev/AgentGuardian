from dataclasses import FrozenInstanceError, fields
from datetime import datetime, timezone
import json

import pytest

import agentguardian.report_comparison as comparison_module
from agentguardian.dispositions import (
    DispositionRecord,
    DispositionStatus,
    disposition_index,
    reviewed_findings,
)
from agentguardian.domain import Evidence, Finding, RiskDomain, Severity
from agentguardian.report_comparison import (
    ReportSummary,
    compare_report_summaries,
    parse_report_summary,
)
from agentguardian.reporting import render_json
from agentguardian.scoring import score
from agentguardian.workflow import CoverageState


EVALUATED_AT = datetime(2026, 8, 3, 12, tzinfo=timezone.utc)
ATTACKER_MARKER = r"C:\Synthetic\private\comparison-marker.txt"


def _report_json() -> str:
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
    options = {
        "coverage": 0.75,
        "confidence": 0.8,
        "limits": ("file_scan_limited", "byte_limit_reached"),
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
    assert ATTACKER_MARKER not in repr(
        (caught.value, caught.value.__cause__, caught.value.__context__)
    )


def _current_report_json() -> str:
    payload = json.loads(_report_json())
    payload["score"]["total"] = 88
    payload["reviewed_score"]["total"] = 95
    for score_data in (payload["score"], payload["reviewed_score"]):
        score_data["coverage"] = 0.5
        score_data["limits"] = [
            "file_scan_limited",
            "directory_excluded",
        ]
    payload["findings"].append(
        {
            "rule_id": "A_RULE",
            "domain": "privacy",
            "severity": "medium",
            "root_hmac_fingerprint": "9" * 64,
            "evidence": [
                {
                    "source": "settings.json",
                    "hmac_fingerprint": "8" * 64,
                    "masked": "masked configuration marker",
                }
            ],
            "disposition": {
                "status": "accepted_risk",
                "reason": "Synthetic accepted risk",
                "reviewer": "Second reviewer",
                "created_at": "2026-08-03T09:00:00Z",
                "expires_at": "2026-08-05T09:00:00Z",
            },
        }
    )
    return json.dumps(payload)


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


def test_legacy_report_derives_coverage_state_and_matches_schema_1() -> None:
    schema_1_text = _report_json()
    legacy = json.loads(schema_1_text)
    del legacy["report_schema"]
    del legacy["score"]["coverage_state"]
    del legacy["reviewed_score"]["coverage_state"]

    assert parse_report_summary(json.dumps(legacy)) == parse_report_summary(
        schema_1_text
    )


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
    assert comparison.technical_score_delta == -4
    assert comparison.reviewed_score_delta == -4
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
    payload = json.loads(_report_json())
    finding = payload["findings"][0]
    finding["evidence"] = [finding["evidence"][0]] * 2
    payload["findings"] = [finding] * 2_000

    summary = parse_report_summary(json.dumps(payload))

    assert summary.finding_count == 2_000
    assert summary.rule_counts == (("A_RULE", 2_000),)
    assert summary.severity_counts == (("low", 2_000),)
    assert summary.disposition_counts == (("open", 2_000),)


def test_public_parser_rejects_non_text_without_file_access() -> None:
    _assert_comparison_invalid(b"{}")


def test_public_comparison_normalizes_forged_missing_summary_slots() -> None:
    forged = object.__new__(ReportSummary)

    _assert_summary_comparison_invalid(
        forged,
        parse_report_summary(_report_json()),
    )


@pytest.mark.parametrize(
    "exception_type",
    (AttributeError, RuntimeError, TypeError),
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
