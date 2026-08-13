import ast
import json
import math
from datetime import datetime, timedelta, timezone, tzinfo
from html import escape
from pathlib import Path

import pytest

import agentguardian.reporting as reporting_module
from agentguardian.detectors import detect_text
from agentguardian.dispositions import (
    DispositionRecord,
    DispositionStatus,
    disposition_index,
    reviewed_findings,
)
from agentguardian.domain import (
    MAX_REPORT_EVIDENCE,
    MAX_REPORT_FINDINGS,
    MAX_REPORT_JSON_BYTES,
    Evidence,
    Finding,
    RiskDomain,
    Score,
    Severity,
)
from agentguardian.reporting import render_html, render_json
from agentguardian.report_comparison import parse_report_summary
from agentguardian.scoring import score as calculate_score
from agentguardian.workflow import classify_coverage

EVALUATED_AT = datetime(2026, 8, 2, 12, tzinfo=timezone.utc)
REPORT_MARKER = r"C:\Synthetic\private\report-marker.txt"
SECRET_MARKER = "sk-proj-abcdefghijklmnopqrstuv"
REPORT_LIMIT = MAX_REPORT_FINDINGS
REPORT_EVIDENCE_LIMIT = MAX_REPORT_EVIDENCE
REPORT_JSON_BYTES = MAX_REPORT_JSON_BYTES


class _LeakyStr(str):
    def __str__(self) -> str:
        return REPORT_MARKER

    def __lt__(self, other: object) -> bool:
        raise RuntimeError(REPORT_MARKER)


class _StatefulFinding(Finding):
    def __getattribute__(self, name: str) -> object:
        if name == "rule_id":
            state = object.__getattribute__(self, "__dict__")
            state["rule_reads"] = state.get("rule_reads", 0) + 1
            if state["rule_reads"] > 1:
                return object.__getattribute__(self, "disposition_ref")
        return super().__getattribute__(name)


class _EvidenceSubclass(Evidence):
    pass


class _ScoreSubclass(Score):
    pass


class _DispositionSubclass(DispositionRecord):
    pass


class _NoHintIterator:
    def __init__(self, value: object) -> None:
        self.value = value
        self.consumed = 0

    def __iter__(self) -> "_NoHintIterator":
        return self

    def __next__(self) -> object:
        if self.consumed == REPORT_LIMIT + 2:
            raise StopIteration
        self.consumed += 1
        return self.value

    def __len__(self) -> int:
        raise RuntimeError(REPORT_MARKER)

    def __length_hint__(self) -> int:
        raise RuntimeError(REPORT_MARKER)


class _NoHintDispositionIterator:
    def __init__(self) -> None:
        self.consumed = 0

    def __iter__(self) -> "_NoHintDispositionIterator":
        return self

    def __next__(self) -> DispositionRecord:
        if self.consumed == REPORT_LIMIT + 2:
            raise StopIteration
        self.consumed += 1
        return DispositionRecord(
            f"{self.consumed:064x}",
            "SAME_RULE",
            DispositionStatus.FALSE_POSITIVE,
            "Synthetic duplicate review",
            "Local reviewer",
            "2026-08-02T08:00:00Z",
            "2026-08-03T08:00:00Z",
        )

    def __len__(self) -> int:
        raise RuntimeError(REPORT_MARKER)

    def __length_hint__(self) -> int:
        raise RuntimeError(REPORT_MARKER)


class _ExplodingIterator:
    def __init__(self, value: object) -> None:
        self.value = value
        self.consumed = 0

    def __iter__(self) -> "_ExplodingIterator":
        return self

    def __next__(self) -> object:
        self.consumed += 1
        if self.consumed > 1:
            raise RuntimeError(REPORT_MARKER)
        return self.value


class _InvalidThenExploding:
    def __init__(self, invalid: object) -> None:
        self.invalid = invalid
        self.consumed = 0

    def __iter__(self) -> "_InvalidThenExploding":
        return self

    def __next__(self) -> object:
        self.consumed += 1
        if self.consumed == 1:
            return self.invalid
        raise RuntimeError(REPORT_MARKER)


class _ExplodingMapping(dict[str, DispositionRecord]):
    def __iter__(self) -> object:
        raise RuntimeError(REPORT_MARKER)


class _HostileTimezone(tzinfo):
    def utcoffset(self, value: datetime | None) -> timedelta:
        raise RuntimeError(REPORT_MARKER)


class _CountingUtc(tzinfo):
    def __init__(self) -> None:
        self.calls = 0

    def utcoffset(self, value: datetime | None) -> timedelta:
        self.calls += 1
        return timedelta(0)


class _DatetimeSubclass(datetime):
    pass


def _score() -> Score:
    return calculate_score(
        (),
        coverage=0.75,
        confidence=0.8,
        limits=("file_scan_limited",),
    )


def _findings() -> tuple[Finding, ...]:
    return (
        Finding(
            "Z_RULE",
            RiskDomain.CREDENTIALS,
            Severity.HIGH,
            "b" * 64,
            (
                Evidence("凭据.env", "d" * 64, "sk-p************stuv"),
                Evidence("配置.txt", "c" * 64, "身份证号：********1234"),
            ),
        ),
        Finding(
            "A_RULE",
            RiskDomain.EXPOSURE,
            Severity.LOW,
            "a" * 64,
            (Evidence("分享记录.txt", "e" * 64, "已脱敏分享标识"),),
        ),
    )


def _findings_score() -> Score:
    return calculate_score(
        _findings(),
        coverage=0.75,
        confidence=0.8,
        limits=("file_scan_limited",),
    )


def _assert_report_invalid(
    renderer: object,
    score: object,
    findings: object,
    rule_version: object = "rules-1",
    **kwargs: object,
) -> None:
    kwargs.setdefault("evaluated_at", EVALUATED_AT)
    with pytest.raises(ValueError) as caught:
        renderer(score, findings, rule_version=rule_version, **kwargs)  # type: ignore[operator]

    assert caught.value.args == ("REPORT_INVALID",)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert REPORT_MARKER not in str(caught.value)
    assert REPORT_MARKER not in repr(caught.value)
    assert SECRET_MARKER not in str(caught.value)
    assert SECRET_MARKER not in repr(caught.value)


def _unchecked_score(**overrides: object) -> Score:
    values = {
        "total": 100,
        "deductions": tuple((domain, 0) for domain in RiskDomain),
        "cap_reason": None,
        "coverage": 1.0,
        "confidence": 1.0,
        "limits": (),
        "incomplete": False,
    }
    values.update(overrides)
    result = object.__new__(Score)
    for name, value in values.items():
        object.__setattr__(result, name, value)
    return result


def _score_subclass() -> Score:
    base = _score()
    return _ScoreSubclass(
        base.total,
        base.deductions,
        base.cap_reason,
        base.coverage,
        base.confidence,
        base.limits,
        base.incomplete,
    )


def _unchecked_finding(**overrides: object) -> Finding:
    values = {
        "rule_id": "RULE",
        "domain": RiskDomain.PRIVACY,
        "severity": Severity.MEDIUM,
        "root_fingerprint": "a" * 64,
        "evidence": (),
        "disposition_ref": None,
    }
    values.update(overrides)
    result = object.__new__(Finding)
    for name, value in values.items():
        object.__setattr__(result, name, value)
    return result


def _unchecked_evidence(**overrides: object) -> Evidence:
    values = {
        "source": "safe.txt",
        "fingerprint": "a" * 64,
        "masked": "safe masked evidence",
    }
    values.update(overrides)
    result = object.__new__(Evidence)
    for name, value in values.items():
        object.__setattr__(result, name, value)
    return result


def _disposition_record() -> DispositionRecord:
    return DispositionRecord(
        "5" * 64,
        "SAME_RULE",
        DispositionStatus.FALSE_POSITIVE,
        "Synthetic duplicate review",
        "Local reviewer",
        "2026-08-02T08:00:00Z",
        "2026-08-03T08:00:00Z",
    )


def _reviewed_report_inputs() -> tuple[
    tuple[Finding, ...], tuple[DispositionRecord, ...], Score, Score
]:
    findings = (
        Finding(
            "PUBLIC_ACTIVE_CREDENTIAL",
            RiskDomain.CREDENTIALS,
            Severity.HIGH,
            "a" * 64,
            (),
            "1" * 64,
        ),
        Finding(
            "ACCEPTED_RULE",
            RiskDomain.PRIVACY,
            Severity.MEDIUM,
            "b" * 64,
            (),
            "2" * 64,
        ),
        Finding(
            "EXPIRED_RULE",
            RiskDomain.EXPOSURE,
            Severity.LOW,
            "c" * 64,
            (),
            "3" * 64,
        ),
        Finding(
            "OPEN_RULE",
            RiskDomain.RETENTION,
            Severity.LOW,
            "d" * 64,
            (),
        ),
        Finding(
            "MISMATCH_RULE",
            RiskDomain.PERMISSIONS,
            Severity.LOW,
            "e" * 64,
            (),
            "4" * 64,
        ),
    )
    records = (
        DispositionRecord(
            "1" * 64,
            "PUBLIC_ACTIVE_CREDENTIAL",
            DispositionStatus.FALSE_POSITIVE,
            "Synthetic <false positive>",
            "Reviewer & one",
            "2026-08-02T08:00:00Z",
            "2026-08-03T08:00:00Z",
        ),
        DispositionRecord(
            "2" * 64,
            "ACCEPTED_RULE",
            DispositionStatus.ACCEPTED_RISK,
            "Accepted <risk>",
            "Reviewer & two",
            "2026-08-02T08:00:00Z",
            "2026-08-03T08:00:00Z",
        ),
        DispositionRecord(
            "3" * 64,
            "EXPIRED_RULE",
            DispositionStatus.FALSE_POSITIVE,
            "Expired <false positive>",
            "Reviewer & three",
            "2026-08-01T08:00:00Z",
            "2026-08-02T11:00:00Z",
        ),
        DispositionRecord(
            "4" * 64,
            "OTHER_RULE",
            DispositionStatus.ACCEPTED_RISK,
            "Should stay hidden",
            "Hidden reviewer",
            "2026-08-02T08:00:00Z",
            "2026-08-03T08:00:00Z",
        ),
    )
    scoring_options = {
        "coverage": 0.75,
        "confidence": 0.8,
        "limits": ("file_scan_limited",),
    }
    technical = calculate_score(findings, **scoring_options)
    reviewed = calculate_score(
        reviewed_findings(
            findings,
            disposition_index(records),
            now=EVALUATED_AT,
        ),
        **scoring_options,
    )
    return findings, records, technical, reviewed


def _expected_score_data(score: Score) -> dict[str, object]:
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
        "coverage_state": classify_coverage(score).value,
    }


@pytest.mark.parametrize("renderer", (render_json, render_html))
def test_renderers_reject_stateful_finding_subclasses_before_field_access(
    renderer: object,
) -> None:
    finding = _StatefulFinding(
        "SAFE_RULE",
        RiskDomain.PRIVACY,
        Severity.MEDIUM,
        "a" * 64,
        (),
        "f" * 64,
    )

    _assert_report_invalid(renderer, _score(), (finding,))

    assert finding.__dict__.get("rule_reads", 0) == 0


@pytest.mark.parametrize("renderer", (render_json, render_html))
@pytest.mark.parametrize(
    "location",
    ("finding", "evidence", "score", "rule_version"),
)
def test_renderers_reject_string_subclasses_without_leaking_paths(
    renderer: object,
    location: str,
) -> None:
    score: Score = _score()
    findings: tuple[Finding, ...] = ()
    rule_version: object = "rules-1"
    if location == "finding":
        findings = (_unchecked_finding(rule_id=_LeakyStr(REPORT_MARKER)),)
    elif location == "evidence":
        findings = (
            _unchecked_finding(
                evidence=(
                    Evidence(
                        _LeakyStr("safe.txt"),
                        "a" * 64,
                        "safe masked evidence",
                    ),
                )
            ),
        )
    elif location == "score":
        score = _unchecked_score(cap_reason=_LeakyStr(REPORT_MARKER))
    else:
        rule_version = _LeakyStr(REPORT_MARKER)

    _assert_report_invalid(
        renderer,
        score,
        findings,
        rule_version=rule_version,
    )


@pytest.mark.parametrize("renderer", (render_json, render_html))
@pytest.mark.parametrize("target", ("rule_version", "cap_reason", "rule_id"))
@pytest.mark.parametrize(
    "hostile",
    (
        REPORT_MARKER,
        "https://example.invalid/private",
        SECRET_MARKER,
        "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima",
        "unsafe\nvalue",
    ),
    ids=("path", "url", "api-key", "seed-phrase", "control"),
)
def test_renderers_reject_unsafe_report_metadata_without_leaking_values(
    renderer: object,
    target: str,
    hostile: str,
) -> None:
    score = _score()
    findings = _findings()
    rule_version = "rules-1"
    if target == "rule_version":
        rule_version = hostile
    elif target == "cap_reason":
        score = _unchecked_score(cap_reason=hostile)
        findings = ()
    else:
        findings = (_unchecked_finding(rule_id=hostile),)

    _assert_report_invalid(
        renderer,
        score,
        findings,
        rule_version=rule_version,
    )


@pytest.mark.parametrize("renderer", (render_json, render_html))
@pytest.mark.parametrize("rule_id", ("lowercase", "A" * 65, "BAD-RULE"))
def test_renderers_require_parser_compatible_rule_ids(
    renderer: object,
    rule_id: str,
) -> None:
    _assert_report_invalid(
        renderer,
        _score(),
        (_unchecked_finding(rule_id=rule_id),),
    )


@pytest.mark.parametrize("renderer", (render_json, render_html))
@pytest.mark.parametrize(
    "finding",
    (
        _unchecked_finding(domain="privacy"),
        _unchecked_finding(severity="medium"),
        _unchecked_finding(evidence=[]),
        _unchecked_finding(
            evidence=(
                _EvidenceSubclass(
                    "safe.txt",
                    "a" * 64,
                    "safe masked evidence",
                ),
            )
        ),
        _unchecked_finding(evidence=(_unchecked_evidence(source=1),)),
        _unchecked_finding(
            disposition_ref=_LeakyStr("f" * 64),
        ),
    ),
    ids=(
        "string-domain",
        "string-severity",
        "list-evidence",
        "evidence-subclass",
        "integer-evidence-source",
        "string-subclass-reference",
    ),
)
def test_renderers_reject_noncanonical_finding_and_evidence_fields(
    renderer: object,
    finding: Finding,
) -> None:
    _assert_report_invalid(renderer, _score(), (finding,))


@pytest.mark.parametrize("renderer", (render_json, render_html))
@pytest.mark.parametrize(
    "masked",
    ("masked\x00value", "masked\nvalue", "masked\u202evalue"),
    ids=("null", "newline", "bidi-control"),
)
def test_renderers_reject_non_printable_masked_evidence(
    renderer: object,
    masked: str,
) -> None:
    finding = _unchecked_finding(
        evidence=(_unchecked_evidence(masked=masked),),
    )

    _assert_report_invalid(
        renderer,
        calculate_score((finding,), coverage=1.0),
        (finding,),
    )


def test_render_html_rejects_unpaired_surrogate_masked_evidence() -> None:
    finding = _unchecked_finding(
        evidence=(_unchecked_evidence(masked=chr(0xD800)),),
    )

    _assert_report_invalid(
        render_html,
        calculate_score((finding,), coverage=1.0),
        (finding,),
    )


@pytest.mark.parametrize("renderer", (render_json, render_html))
@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("reason", REPORT_MARKER),
        ("reviewer", SECRET_MARKER),
        ("disposition_ref", "not-a-reference"),
        ("rule_id", "bad rule"),
        ("status", "false_positive"),
        ("created_at", "not-a-time"),
        ("expires_at", "2026-08-02T07:00:00Z"),
    ),
    ids=(
        "path-reason",
        "secret-reviewer",
        "malformed-reference",
        "malformed-rule",
        "malformed-status",
        "malformed-created-at",
        "invalid-expiry-order",
    ),
)
def test_renderers_revalidate_forged_exact_disposition_records(
    renderer: object,
    field: str,
    value: object,
) -> None:
    record = _disposition_record()
    object.__setattr__(record, field, value)
    finding = Finding(
        "SAME_RULE",
        RiskDomain.PRIVACY,
        Severity.MEDIUM,
        "a" * 64,
        (),
        "5" * 64,
    )

    _assert_report_invalid(
        renderer,
        _score(),
        (finding,),
        dispositions=(record,),
        evaluated_at=EVALUATED_AT,
    )


@pytest.mark.parametrize("renderer", (render_json, render_html))
def test_renderers_require_exact_disposition_record_type(
    renderer: object,
) -> None:
    record = _DispositionSubclass(
        "5" * 64,
        "SAME_RULE",
        DispositionStatus.FALSE_POSITIVE,
        "Synthetic duplicate review",
        "Local reviewer",
        "2026-08-02T08:00:00Z",
        "2026-08-03T08:00:00Z",
    )

    _assert_report_invalid(
        renderer,
        _score(),
        (),
        dispositions=(record,),
        evaluated_at=EVALUATED_AT,
    )


@pytest.mark.parametrize("renderer", (render_json, render_html))
def test_renderers_stop_after_first_invalid_finding(
    renderer: object,
) -> None:
    findings = _InvalidThenExploding(_unchecked_finding(domain="privacy"))

    _assert_report_invalid(
        renderer,
        _score(),
        findings,
        evaluated_at=EVALUATED_AT,
    )

    assert findings.consumed == 1


@pytest.mark.parametrize("renderer", (render_json, render_html))
@pytest.mark.parametrize("target", ("findings", "dispositions"))
def test_renderers_bound_one_pass_inputs_without_length_hints(
    renderer: object,
    target: str,
) -> None:
    finding = Finding(
        "SAME_RULE",
        RiskDomain.PRIVACY,
        Severity.MEDIUM,
        "a" * 64,
        (),
    )
    probe = (
        _NoHintIterator(finding)
        if target == "findings"
        else _NoHintDispositionIterator()
    )
    findings: object = probe if target == "findings" else ()
    dispositions: object = probe if target == "dispositions" else ()

    _assert_report_invalid(
        renderer,
        _score(),
        findings,
        dispositions=dispositions,
        evaluated_at=EVALUATED_AT,
    )

    assert probe.consumed == REPORT_LIMIT + 1


@pytest.mark.parametrize("renderer", (render_json, render_html))
def test_renderers_reject_more_than_total_evidence_budget(renderer: object) -> None:
    evidence = Evidence("safe.txt", "a" * 64, "safe masked evidence")
    finding = Finding(
        "EVIDENCE_LIMIT",
        RiskDomain.EXPOSURE,
        Severity.LOW,
        "b" * 64,
        (evidence,) * (REPORT_EVIDENCE_LIMIT + 1),
    )

    _assert_report_invalid(renderer, _score(), (finding,))


def test_renderers_reject_evidence_over_budget_before_reading_item_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = Evidence("safe.txt", "a" * 64, "safe masked evidence")
    finding = Finding(
        "EVIDENCE_LIMIT",
        RiskDomain.EXPOSURE,
        Severity.LOW,
        "b" * 64,
        (evidence,) * (REPORT_EVIDENCE_LIMIT + 1),
    )
    audit_score = calculate_score((finding,), coverage=1.0)
    reads: list[str] = []
    real_getattribute = Evidence.__getattribute__

    def observe_field_access(item: Evidence, name: str) -> object:
        if name in ("source", "fingerprint", "masked"):
            reads.append(name)
        return real_getattribute(item, name)

    monkeypatch.setattr(Evidence, "__getattribute__", observe_field_access)

    _assert_report_invalid(render_json, audit_score, (finding,))

    assert reads == []


def test_render_json_rejects_real_output_over_utf8_byte_budget() -> None:
    evidence = Evidence("界" * 80, "a" * 64, "遮" * 80)
    finding = Finding(
        "EVIDENCE_LIMIT",
        RiskDomain.EXPOSURE,
        Severity.LOW,
        "b" * 64,
        (evidence,) * REPORT_EVIDENCE_LIMIT,
    )

    _assert_report_invalid(
        render_json,
        calculate_score((finding,), coverage=1.0),
        (finding,),
    )


def test_render_json_accepts_real_valid_json_below_utf8_byte_budget() -> None:
    findings = (
        Finding(
            "A_RULE",
            RiskDomain.EXPOSURE,
            Severity.LOW,
            "a" * 64,
            (Evidence("safe.txt", "b" * 64, "safe masked evidence"),),
        ),
    )

    rendered = render_json(
        calculate_score(findings, coverage=1.0),
        findings,
        rule_version="rules-1",
        evaluated_at=EVALUATED_AT,
    )

    assert len(rendered.encode("utf-8")) < REPORT_JSON_BYTES
    assert parse_report_summary(rendered).finding_count == 1


def test_render_json_rejects_technical_score_inconsistent_with_findings() -> None:
    findings = (
        Finding(
            "A_RULE",
            RiskDomain.EXPOSURE,
            Severity.LOW,
            "a" * 64,
            (),
        ),
    )

    _assert_report_invalid(
        render_json,
        calculate_score((), coverage=1.0),
        findings,
    )


def test_render_json_recomputes_omitted_reviewed_score_and_round_trips() -> None:
    finding = Finding(
        "A_RULE",
        RiskDomain.EXPOSURE,
        Severity.LOW,
        "a" * 64,
        (),
        "f" * 64,
    )
    record = DispositionRecord(
        "f" * 64,
        "A_RULE",
        DispositionStatus.FALSE_POSITIVE,
        "Synthetic false positive",
        "Local reviewer",
        "2026-08-02T08:00:00Z",
        "2026-08-03T08:00:00Z",
    )

    rendered = render_json(
        calculate_score((finding,), coverage=1.0),
        (finding,),
        rule_version="rules-1",
        dispositions=(record,),
        evaluated_at=EVALUATED_AT,
    )
    summary = parse_report_summary(rendered)

    assert summary.technical_score == 99
    assert summary.reviewed_score == 100


def test_render_json_rejects_excessive_declared_deductions() -> None:
    excessive = Score(
        total=100,
        deductions=((RiskDomain.EXPOSURE, 0),) * 2_001,
        cap_reason=None,
        coverage=1.0,
        confidence=1.0,
        limits=(),
        incomplete=False,
    )

    _assert_report_invalid(render_json, excessive, ())


@pytest.mark.parametrize("renderer", (render_json, render_html))
def test_renderers_bound_deduction_shape_before_classifying(
    renderer: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    excessive = _unchecked_score(
        deductions=((RiskDomain.EXPOSURE, 0),) * 2_001,
    )
    classifier_calls = 0

    def fail_if_called(_score: object) -> object:
        nonlocal classifier_calls
        classifier_calls += 1
        raise RuntimeError(REPORT_MARKER)

    monkeypatch.setattr(reporting_module, "classify_coverage", fail_if_called)

    _assert_report_invalid(renderer, excessive, ())

    assert classifier_calls == 0


@pytest.mark.parametrize("renderer", (render_json, render_html))
def test_renderers_require_explicit_evaluated_at(renderer: object) -> None:
    with pytest.raises(TypeError):
        renderer(  # type: ignore[operator]
            calculate_score((), coverage=1.0),
            (),
            rule_version="rules-1",
        )


@pytest.mark.parametrize("renderer", (render_json, render_html))
@pytest.mark.parametrize("target", ("findings", "dispositions", "mapping"))
def test_renderers_normalize_iterator_and_mapping_failures(
    renderer: object,
    target: str,
) -> None:
    finding = Finding(
        "SAME_RULE",
        RiskDomain.PRIVACY,
        Severity.MEDIUM,
        "a" * 64,
        (),
    )
    record = _disposition_record()
    findings: object = ()
    dispositions: object = ()
    if target == "findings":
        findings = _ExplodingIterator(finding)
    elif target == "dispositions":
        dispositions = _ExplodingIterator(record)
    else:
        dispositions = _ExplodingMapping({record.disposition_ref: record})

    _assert_report_invalid(
        renderer,
        _score(),
        findings,
        dispositions=dispositions,
        evaluated_at=EVALUATED_AT,
    )


@pytest.mark.parametrize("renderer", (render_json, render_html))
@pytest.mark.parametrize(
    "evaluated_at",
    (
        datetime(2026, 8, 2, 12),
        datetime(2026, 8, 2, 12, tzinfo=timezone(timedelta(hours=1))),
        _DatetimeSubclass(2026, 8, 2, 12, tzinfo=timezone.utc),
    ),
    ids=("naive", "non-utc", "datetime-subclass"),
)
def test_renderers_validate_evaluated_at_with_empty_findings(
    renderer: object,
    evaluated_at: datetime,
) -> None:
    _assert_report_invalid(
        renderer,
        _score(),
        (),
        evaluated_at=evaluated_at,
    )


@pytest.mark.parametrize("renderer", (render_json, render_html))
def test_renderers_normalize_hostile_timezone_failures(
    renderer: object,
) -> None:
    hostile = datetime(2026, 8, 2, 12, tzinfo=_HostileTimezone())

    _assert_report_invalid(
        renderer,
        _score(),
        (),
        evaluated_at=hostile,
    )


@pytest.mark.parametrize("renderer", (render_json, render_html))
def test_renderers_validate_evaluated_at_once(
    renderer: object,
) -> None:
    counting_utc = _CountingUtc()
    evaluated_at = datetime(2026, 8, 2, 12, tzinfo=counting_utc)

    renderer(  # type: ignore[operator]
        _findings_score(),
        _findings(),
        rule_version="rules-1",
        evaluated_at=evaluated_at,
    )

    assert counting_utc.calls == 1


@pytest.mark.parametrize("renderer", (render_json, render_html))
def test_renderers_reject_subsecond_evaluated_at(renderer: object) -> None:
    _assert_report_invalid(
        renderer,
        _score(),
        (),
        evaluated_at=EVALUATED_AT.replace(microsecond=1),
    )


def test_render_json_contains_safe_complete_deterministic_report() -> None:
    first = render_json(
        _findings_score(),
        _findings(),
        rule_version="规则-1",
        evaluated_at=EVALUATED_AT,
    )
    second = render_json(
        _findings_score(),
        tuple(reversed(_findings())),
        rule_version="规则-1",
        evaluated_at=EVALUATED_AT,
    )
    report = json.loads(first)

    assert first == second
    assert first == json.dumps(report, ensure_ascii=False, indent=2)
    assert report["product"] == "AgentGuardian"
    assert report["version"] == "0.1.0"
    assert report["evaluated_at"] == "2026-08-02T12:00:00Z"
    assert report["rule_version"] == "规则-1"
    assert report["score"] == {
        "total": 92,
        "deductions": [
            {
                "domain": domain.value,
                "amount": (
                    7
                    if domain is RiskDomain.CREDENTIALS
                    else 1 if domain is RiskDomain.EXPOSURE else 0
                ),
            }
            for domain in RiskDomain
        ],
        "cap_reason": None,
        "coverage": 0.75,
        "confidence": 0.8,
        "incomplete": True,
        "limits": ["file_scan_limited"],
        "coverage_state": "limited",
    }
    assert report["reviewed_score"] == report["score"]
    assert all(
        finding["disposition"] == {"status": "open"}
        for finding in report["findings"]
    )
    assert [finding["rule_id"] for finding in report["findings"]] == [
        "A_RULE",
        "Z_RULE",
    ]
    assert report["findings"][1]["root_hmac_fingerprint"] == "b" * 64
    evidence = report["findings"][1]["evidence"]
    assert [item["source"] for item in evidence] == ["配置.txt", "凭据.env"]
    assert evidence[0]["hmac_fingerprint"] == "c" * 64
    assert evidence[0]["masked"] == "身份证号：********1234"
    assert "身份证号" in first


@pytest.mark.parametrize(
    ("score", "coverage_state"),
    (
        (_unchecked_score(), "complete"),
        (
            _unchecked_score(
                coverage=0.75,
                confidence=0.8,
                limits=("file_scan_limited",),
                incomplete=True,
            ),
            "limited",
        ),
        (
            _unchecked_score(
                coverage=0.0,
                confidence=0.0,
                limits=("no_supported_files",),
                incomplete=True,
            ),
            "no_supported_files",
        ),
    ),
)
def test_render_json_schema_exposes_exact_coverage_state(
    score: Score,
    coverage_state: str,
) -> None:
    report = json.loads(
        render_json(
            score,
            (),
            rule_version="rules-1",
            evaluated_at=EVALUATED_AT,
        )
    )

    assert report["report_schema"] == 1
    assert report["score"]["coverage_state"] == coverage_state
    assert report["reviewed_score"]["coverage_state"] == coverage_state


@pytest.mark.parametrize("renderer", (render_json, render_html))
@pytest.mark.parametrize(
    "reviewed_score",
    (
        _unchecked_score(
            coverage=0.5,
            confidence=0.8,
            limits=("file_scan_limited",),
            incomplete=True,
        ),
        _unchecked_score(
            coverage=0.75,
            confidence=0.5,
            limits=("file_scan_limited",),
            incomplete=True,
        ),
        _unchecked_score(
            coverage=0.75,
            confidence=0.8,
            limits=("byte_limit_reached",),
            incomplete=True,
        ),
        _unchecked_score(confidence=0.8),
    ),
    ids=("coverage", "confidence", "limits", "incomplete-state"),
)
def test_renderers_reject_score_coverage_consistency_mismatches(
    renderer: object,
    reviewed_score: Score,
) -> None:
    _assert_report_invalid(
        renderer,
        _score(),
        (),
        reviewed_score=reviewed_score,
    )


@pytest.mark.parametrize("renderer", (render_json, render_html))
def test_renderers_require_exact_score_limit_order(renderer: object) -> None:
    technical = _unchecked_score(
        coverage=0.75,
        confidence=0.8,
        limits=("byte_limit_reached", "file_scan_limited"),
        incomplete=True,
    )
    reviewed = _unchecked_score(
        coverage=0.75,
        confidence=0.8,
        limits=("file_scan_limited", "byte_limit_reached"),
        incomplete=True,
    )

    _assert_report_invalid(
        renderer,
        technical,
        (),
        reviewed_score=reviewed,
    )


def test_render_json_exports_exact_reviewed_dispositions_from_one_shot_inputs() -> None:
    findings, records, technical, reviewed = _reviewed_report_inputs()
    finding_generator = (finding for finding in reversed(findings))
    disposition_generator = (record for record in reversed(records))

    first = render_json(
        technical,
        finding_generator,
        rule_version="rules-1",
        reviewed_score=reviewed,
        dispositions=disposition_generator,
        evaluated_at=EVALUATED_AT,
    )
    second = render_json(
        technical,
        (finding for finding in findings),
        rule_version="rules-1",
        reviewed_score=reviewed,
        dispositions=(record for record in records),
        evaluated_at=EVALUATED_AT,
    )
    report = json.loads(first)
    by_rule = {finding["rule_id"]: finding for finding in report["findings"]}

    assert first == second
    assert tuple(finding_generator) == ()
    assert tuple(disposition_generator) == ()
    assert report["score"] == _expected_score_data(technical)
    assert report["reviewed_score"] == _expected_score_data(reviewed)
    assert report["score"]["total"] == 39
    assert report["reviewed_score"]["total"] == 94
    assert by_rule["PUBLIC_ACTIVE_CREDENTIAL"]["disposition"] == {
        "status": "false_positive",
        "reason": "Synthetic <false positive>",
        "reviewer": "Reviewer & one",
        "created_at": "2026-08-02T08:00:00Z",
        "expires_at": "2026-08-03T08:00:00Z",
    }
    assert by_rule["ACCEPTED_RULE"]["disposition"] == {
        "status": "accepted_risk",
        "reason": "Accepted <risk>",
        "reviewer": "Reviewer & two",
        "created_at": "2026-08-02T08:00:00Z",
        "expires_at": "2026-08-03T08:00:00Z",
    }
    assert by_rule["EXPIRED_RULE"]["disposition"] == {
        "status": "expired",
        "last_status": "false_positive",
        "reason": "Expired <false positive>",
        "reviewer": "Reviewer & three",
        "created_at": "2026-08-01T08:00:00Z",
        "expires_at": "2026-08-02T11:00:00Z",
    }
    assert by_rule["OPEN_RULE"]["disposition"] == {"status": "open"}
    assert by_rule["MISMATCH_RULE"]["disposition"] == {"status": "open"}
    assert "Should stay hidden" not in first
    assert "Hidden reviewer" not in first
    assert "disposition_ref" not in first
    for finding in findings:
        if finding.disposition_ref is not None:
            assert finding.disposition_ref not in first


def test_real_detection_scoring_reporting_chain_keeps_raw_data_private() -> None:
    raw_secret = "sk-" + "proj-" + "abcdefghijklmnopqrstuv"
    full_source = r"C:\Users\Synthetic\sample.env"
    scan_key = b"synthetic-scan-key-with-at-least-32-bytes"
    disposition_key = b"private-disposition-key-12345678"
    findings = detect_text(
        f"OPENAI_API_KEY={raw_secret}",
        full_source,
        scan_key=scan_key,
        disposition_key=disposition_key,
    )
    assert findings[0].disposition_ref is not None
    record = DispositionRecord(
        findings[0].disposition_ref,
        findings[0].rule_id,
        DispositionStatus.FALSE_POSITIVE,
        "Synthetic <reviewed>",
        "Analyst & owner",
        "2026-08-02T08:00:00Z",
        "2026-08-03T08:00:00Z",
    )
    audit_score = calculate_score(findings, coverage=1.0)
    reviewed_score = calculate_score((), coverage=1.0)
    json_report = render_json(
        audit_score,
        findings,
        rule_version="rules-1",
        reviewed_score=reviewed_score,
        dispositions=(record for record in (record,)),
        evaluated_at=EVALUATED_AT,
    )
    html_report = render_html(
        audit_score,
        (finding for finding in findings),
        rule_version="rules-1",
        reviewed_score=reviewed_score,
        dispositions=(record for record in (record,)),
        evaluated_at=EVALUATED_AT,
    )
    finding = findings[0]
    evidence = finding.evidence[0]

    assert finding.evidence[0].source == "sample.env"
    assert json.loads(json_report)["findings"][0]["evidence"][0]["source"] == "sample.env"

    for output in (json_report, html_report):
        assert raw_secret not in output
        assert full_source not in output
        assert scan_key.decode() not in output
        assert disposition_key.decode() not in output
        assert findings[0].disposition_ref not in output
        assert "disposition_ref" not in output
        assert "sample.env" in output
        assert evidence.masked in output
        assert findings[0].root_fingerprint in output
        assert evidence.fingerprint in output

    disposition = json.loads(json_report)["findings"][0]["disposition"]
    assert disposition["reason"] == "Synthetic <reviewed>"
    assert disposition["reviewer"] == "Analyst & owner"
    assert "Synthetic <reviewed>" not in html_report
    assert "Analyst & owner" not in html_report
    assert escape("Synthetic <reviewed>", quote=True) in html_report
    assert escape("Analyst & owner", quote=True) in html_report


@pytest.mark.parametrize("renderer", (render_json, render_html))
@pytest.mark.parametrize("position", ("technical", "reviewed"))
@pytest.mark.parametrize(
    "malformed",
    (
        _score_subclass(),
        _unchecked_score(total=True),
        _unchecked_score(deductions=[]),
        _unchecked_score(deductions=((RiskDomain.PRIVACY,),)),
        _unchecked_score(deductions=(("privacy", 1),)),
        _unchecked_score(deductions=((RiskDomain.PRIVACY, True),)),
        _unchecked_score(deductions=((RiskDomain.PRIVACY, -1),)),
        _unchecked_score(deductions=((RiskDomain.PRIVACY, math.nan),)),
        _unchecked_score(cap_reason=1),
        _unchecked_score(coverage=math.nan),
        _unchecked_score(coverage=True),
        _unchecked_score(confidence=math.inf),
        _unchecked_score(limits=[]),
        _unchecked_score(limits=(_LeakyStr(REPORT_MARKER),)),
        _unchecked_score(limits=("unknown_limit",), incomplete=True),
        _unchecked_score(limits=("file_scan_limited",)),
        _unchecked_score(coverage=0.5),
        _unchecked_score(incomplete=True),
        _unchecked_score(
            coverage=0.5,
            limits=("no_supported_files",),
            incomplete=True,
        ),
        _unchecked_score(
            coverage=0.0,
            limits=("no_supported_files", "file_scan_limited"),
            incomplete=True,
        ),
        _unchecked_score(incomplete=1),
    ),
    ids=(
        "score-subclass",
        "bool-total",
        "list-deductions",
        "short-deduction",
        "string-domain",
        "bool-deduction",
        "negative-deduction",
        "nan-deduction",
        "integer-cap",
        "nan-coverage",
        "bool-coverage",
        "infinite-confidence",
        "list-limits",
        "string-subclass-limit",
        "unknown-limit",
        "complete-with-limit",
        "complete-with-partial-coverage",
        "incomplete-without-limit-or-gap",
        "no-supported-files-with-coverage",
        "no-supported-files-with-extra-limit",
        "integer-incomplete",
    ),
)
def test_renderers_reject_malformed_technical_and_reviewed_scores(
    renderer: object,
    position: str,
    malformed: Score,
) -> None:
    technical = malformed if position == "technical" else _score()
    reviewed = malformed if position == "reviewed" else None

    _assert_report_invalid(
        renderer,
        technical,
        (),
        reviewed_score=reviewed,
    )


def test_render_html_escapes_every_dynamic_text_field() -> None:
    source_html = "<img onerror='x'>"
    masked_html = "<b onclick='x'>已脱敏"
    finding = Finding(
        "SAFE_RULE",
        RiskDomain.PRIVACY,
        Severity.MEDIUM,
        "f" * 64,
        (Evidence(source_html, "e" * 64, masked_html),),
    )
    audit_score = Score(
        97,
        tuple((domain, 3 if domain is RiskDomain.PRIVACY else 0) for domain in RiskDomain),
        None,
        1.0,
        0.5,
        ("file_scan_limited",),
        True,
    )

    rendered = render_html(
        audit_score,
        (finding,),
        rule_version="rules-1",
        evaluated_at=EVALUATED_AT,
    )

    assert source_html not in rendered
    assert masked_html not in rendered
    assert escape(source_html, quote=True) in rendered
    assert escape(masked_html, quote=True) in rendered
    assert "HMAC fingerprint" in rendered


def test_render_html_contains_requested_score_and_finding_fields() -> None:
    rendered = render_html(
        _findings_score(),
        _findings(),
        rule_version="规则-1",
        evaluated_at=EVALUATED_AT,
    )

    for value in (
        "AgentGuardian",
        "0.1.0",
        "规则-1",
        "92",
        "0.75",
        "0.8",
        "覆盖受限",
        "文件扫描受限",
        "本次结果不能证明系统、账户、提供商或端点安全。",
        "Z_RULE",
        "凭据.env",
        "身份证号：********1234",
        "b" * 64,
        "c" * 64,
    ):
        assert escape(value, quote=True) in rendered

    assert "<h2>Technical score</h2>" in rendered
    assert "<h2>Reviewed score</h2>" in rendered
    assert rendered.count("<p>Disposition status: open</p>") == 2
    assert "Disposition reason:" not in rendered


@pytest.mark.parametrize(
    ("score", "state", "state_label", "reason_label", "incomplete"),
    (
        (_unchecked_score(), "complete", "已完成", None, False),
        (
            _unchecked_score(
                coverage=0.75,
                confidence=0.8,
                limits=("file_scan_limited",),
                incomplete=True,
            ),
            "limited",
            "覆盖受限",
            "文件扫描受限",
            True,
        ),
        (
            _unchecked_score(
                coverage=0.0,
                confidence=0.0,
                limits=("no_supported_files",),
                incomplete=True,
            ),
            "no_supported_files",
            "无支持文件",
            "未发现支持的文件",
            True,
        ),
    ),
)
def test_render_html_uses_fixed_coverage_state_and_reason_labels(
    score: Score,
    state: str,
    state_label: str,
    reason_label: str | None,
    incomplete: bool,
) -> None:
    first = render_html(
        score, (), rule_version="rules-1", evaluated_at=EVALUATED_AT
    )
    second = render_html(
        score, (), rule_version="rules-1", evaluated_at=EVALUATED_AT
    )
    disclaimer = "本次结果不能证明系统、账户、提供商或端点安全。"
    completion = "已完成配置范围扫描。"

    assert first == second
    assert first.count(f"<p>Coverage state: {state}</p>") == 2
    assert first.count(f"<p>Coverage state label: {state_label}</p>") == 2
    if reason_label is not None:
        assert first.count(f"<li>{reason_label}</li>") == 2
    if incomplete:
        assert first.count(f"<p>{disclaimer}</p>") == 2
        assert completion not in first
    else:
        assert first.count(f"<p>{completion}</p>") == 2
        assert disclaimer not in first
        for unsafe_claim in ("系统安全", "账户安全", "提供商安全", "端点安全"):
            assert unsafe_claim not in first


def test_render_html_presents_complete_reviewed_scores_and_dispositions() -> None:
    findings, records, technical, reviewed = _reviewed_report_inputs()

    forward = render_html(
        technical,
        (finding for finding in findings),
        rule_version="rules-1",
        reviewed_score=reviewed,
        dispositions=(record for record in records),
        evaluated_at=EVALUATED_AT,
    )
    reverse = render_html(
        technical,
        (finding for finding in reversed(findings)),
        rule_version="rules-1",
        reviewed_score=reviewed,
        dispositions=(record for record in reversed(records)),
        evaluated_at=EVALUATED_AT,
    )

    assert forward == reverse
    technical_section = forward[
        forward.index("<h2>Technical score</h2>") : forward.index(
            "<h2>Reviewed score</h2>"
        )
    ]
    reviewed_section = forward[
        forward.index("<h2>Reviewed score</h2>") : forward.index(
            "<h2>Findings</h2>"
        )
    ]
    for section, audit_score in (
        (technical_section, technical),
        (reviewed_section, reviewed),
    ):
        assert f"<p>Total: {audit_score.total}</p>" in section
        assert "<h3>Domain deductions</h3>" in section
        assert f"<p>Coverage: {audit_score.coverage}</p>" in section
        assert f"<p>Confidence: {audit_score.confidence}</p>" in section
        assert "<p>Incomplete: true</p>" in section
        assert "覆盖受限" in section
        assert "文件扫描受限" in section
        assert "本次结果不能证明系统、账户、提供商或端点安全。" in section
        for domain, amount in audit_score.deductions:
            assert f"<li>{domain.value}: {amount}</li>" in section
    assert "<p>Cap reason: public_active_credential</p>" in technical_section
    assert "<p>Cap reason: None</p>" in reviewed_section
    assert "<p>Disposition status: false_positive</p>" in forward
    assert "<p>Disposition status: accepted_risk</p>" in forward
    assert "<p>Disposition status: expired</p>" in forward
    assert "<p>Last disposition status: false_positive</p>" in forward
    for value in (
        "Synthetic <false positive>",
        "Reviewer & one",
        "Accepted <risk>",
        "Reviewer & two",
        "Expired <false positive>",
        "Reviewer & three",
        "2026-08-02T08:00:00Z",
        "2026-08-03T08:00:00Z",
        "2026-08-01T08:00:00Z",
        "2026-08-02T11:00:00Z",
    ):
        assert escape(value, quote=True) in forward
    assert "Synthetic <false positive>" not in forward
    assert "Accepted <risk>" not in forward
    assert "Expired <false positive>" not in forward
    assert "Should stay hidden" not in forward
    assert "Hidden reviewer" not in forward
    assert "disposition_ref" not in forward
    mismatch_section = forward[
        forward.index("<h3>MISMATCH_RULE</h3>") : forward.index(
            "<h3>OPEN_RULE</h3>"
        )
    ]
    assert "<p>Disposition status: open</p>" in mismatch_section
    assert "Disposition reason:" not in mismatch_section
    assert "Disposition reviewer:" not in mismatch_section
    assert "Disposition created at:" not in mismatch_section
    assert "Disposition expires at:" not in mismatch_section


def test_renderers_sort_identical_finding_keys_by_evidence() -> None:
    first = Finding(
        "SAME_RULE",
        RiskDomain.PRIVACY,
        Severity.MEDIUM,
        "f" * 64,
        (Evidence("b.txt", "b" * 64, "脱敏证据B"),),
    )
    second = Finding(
        "SAME_RULE",
        RiskDomain.PRIVACY,
        Severity.MEDIUM,
        "f" * 64,
        (Evidence("a.txt", "a" * 64, "脱敏证据A"),),
    )
    audit_score = calculate_score(
        (first, second),
        coverage=0.75,
        confidence=0.8,
        limits=("file_scan_limited",),
    )

    forward_json = render_json(
        audit_score,
        (first, second),
        rule_version="规则-1",
        evaluated_at=EVALUATED_AT,
    )
    reverse_json = render_json(
        audit_score,
        (second, first),
        rule_version="规则-1",
        evaluated_at=EVALUATED_AT,
    )
    forward_html = render_html(
        audit_score,
        (first, second),
        rule_version="规则-1",
        evaluated_at=EVALUATED_AT,
    )
    reverse_html = render_html(
        audit_score,
        (second, first),
        rule_version="规则-1",
        evaluated_at=EVALUATED_AT,
    )

    assert forward_json == reverse_json
    assert forward_html == reverse_html
    assert [
        item["evidence"][0]["hmac_fingerprint"]
        for item in json.loads(forward_json)["findings"]
    ] == ["a" * 64, "b" * 64]
    assert forward_html.index("a" * 64) < forward_html.index("b" * 64)


@pytest.mark.parametrize("renderer", (render_json, render_html))
def test_renderers_stabilize_identical_findings_by_safe_disposition(
    renderer: object,
) -> None:
    evidence = (Evidence("same.txt", "a" * 64, "same masked evidence"),)
    false_positive = Finding(
        "SAME_RULE",
        RiskDomain.PRIVACY,
        Severity.MEDIUM,
        "a" * 64,
        evidence,
        "f" * 64,
    )
    open_finding = Finding(
        "SAME_RULE",
        RiskDomain.PRIVACY,
        Severity.MEDIUM,
        "a" * 64,
        evidence,
        "0" * 64,
    )
    record = DispositionRecord(
        "f" * 64,
        "SAME_RULE",
        DispositionStatus.FALSE_POSITIVE,
        "Synthetic duplicate review",
        "Local reviewer",
        "2026-08-02T08:00:00Z",
        "2026-08-03T08:00:00Z",
    )
    audit_score = calculate_score(
        (false_positive, open_finding),
        coverage=1.0,
    )

    forward = renderer(  # type: ignore[operator]
        audit_score,
        (finding for finding in (false_positive, open_finding)),
        rule_version="rules-1",
        dispositions=(item for item in (record,)),
        evaluated_at=EVALUATED_AT,
    )
    reverse = renderer(  # type: ignore[operator]
        audit_score,
        (finding for finding in (open_finding, false_positive)),
        rule_version="rules-1",
        dispositions=(item for item in (record,)),
        evaluated_at=EVALUATED_AT,
    )

    assert forward == reverse
    if renderer is render_json:
        states = [
            finding["disposition"]["status"]
            for finding in json.loads(forward)["findings"]
        ]
        assert states == ["false_positive", "open"]
    else:
        assert forward.index("Disposition status: false_positive") < forward.index(
            "Disposition status: open"
        )
    assert "f" * 64 not in forward
    assert "0" * 64 not in forward


@pytest.mark.parametrize("renderer", (render_json, render_html))
def test_renderers_accept_one_shot_finding_generators(renderer: object) -> None:
    expected_findings = (
        Finding(
            "GENERATOR_A",
            RiskDomain.EXPOSURE,
            Severity.LOW,
            "a" * 64,
            (),
        ),
        Finding(
            "GENERATOR_B",
            RiskDomain.PRIVACY,
            Severity.MEDIUM,
            "b" * 64,
            (),
        ),
    )
    findings = (finding for finding in expected_findings)

    output = renderer(  # type: ignore[operator]
        calculate_score(expected_findings, coverage=1.0),
        findings,
        rule_version="rules-1",
        evaluated_at=EVALUATED_AT,
    )

    assert "GENERATOR_A" in output
    assert "GENERATOR_B" in output
    assert tuple(findings) == ()


def test_scoring_and_reporting_use_only_approved_imports_and_calls() -> None:
    allowed_imports = {
        "scoring.py": {
            ("from", 0, "collections.abc", (("Iterable", None),)),
            (
                "from",
                1,
                "domain",
                (
                    ("Finding", None),
                    ("RiskDomain", None),
                    ("Score", None),
                    ("Severity", None),
                ),
            ),
        },
        "reporting.py": {
            ("from", 0, "collections.abc", (("Iterable", None),)),
            (
                "from",
                0,
                "datetime",
                (
                    ("datetime", None),
                    ("timedelta", None),
                    ("timezone", None),
                ),
            ),
            ("from", 0, "html", (("escape", None),)),
            ("import", 0, None, (("json", None),)),
            ("from", 1, None, (("__version__", None),)),
            (
                "from",
                1,
                "dispositions",
                (
                    ("DispositionRecord", None),
                    ("disposition_index", None),
                    ("evaluate_disposition", None),
                ),
            ),
            (
                "from",
                1,
                "domain",
                (
                    ("MAX_REPORT_EVIDENCE", None),
                    ("MAX_REPORT_FINDINGS", None),
                    ("MAX_REPORT_JSON_BYTES", None),
                    ("Evidence", None),
                    ("Finding", None),
                    ("RiskDomain", None),
                    ("Score", None),
                    ("Severity", None),
                    ("validate_rule_id", None),
                    ("validate_safe_annotation", None),
                ),
            ),
            (
                "from",
                1,
                "scoring",
                (("score", "calculate_score"),),
            ),
            (
                "from",
                1,
                "workflow",
                (
                    ("COVERAGE_LIMIT_LABELS", None),
                    ("COVERAGE_STATE_LABELS", None),
                    ("CoverageState", None),
                    ("classify_coverage", None),
                ),
            ),
        },
    }
    allowed_name_calls = {
        "scoring.py": {
            "Score",
            "bool",
            "max",
            "min",
            "set",
            "sum",
            "tuple",
        },
        "reporting.py": {
            "DispositionRecord",
            "Evidence",
            "Finding",
            "CoverageState",
            "ValueError",
            "_bounded_items",
            "_disposition_data",
            "_disposition_sort_key",
            "_finding_data",
            "_prepare_report",
            "_text",
            "_validated_finding",
            "_validated_dispositions",
            "_validated_score_data",
            "_validated_report_time",
            "calculate_score",
            "classify_coverage",
            "disposition_index",
            "escape",
            "evaluate_disposition",
            "len",
            "sorted",
            "str",
            "timedelta",
            "tuple",
            "type",
            "validate_rule_id",
            "validate_safe_annotation",
        },
    }
    allowed_attribute_calls = {
        "scoring.py": {"add", "get", "items"},
        "reporting.py": {
            "append",
            "dumps",
            "encode",
            "extend",
            "join",
            "lower",
            "replace",
            "strftime",
            "utcoffset",
        },
    }
    blocked_dynamic_calls = {"__import__", "eval", "exec", "getattr", "open"}

    package_path = Path(__file__).parents[1] / "src" / "agentguardian"
    for module_name in ("scoring.py", "reporting.py"):
        tree = ast.parse((package_path / module_name).read_text(encoding="utf-8"))
        imports = {
            (
                "import" if isinstance(node, ast.Import) else "from",
                0 if isinstance(node, ast.Import) else node.level,
                None if isinstance(node, ast.Import) else node.module,
                tuple((alias.name, alias.asname) for alias in node.names),
            )
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
        }
        calls = [node.func for node in ast.walk(tree) if isinstance(node, ast.Call)]
        name_calls = {node.id for node in calls if isinstance(node, ast.Name)}
        attribute_calls = {
            node.attr for node in calls if isinstance(node, ast.Attribute)
        }
        dynamic_calls = {
            type(node).__name__
            for node in calls
            if not isinstance(node, (ast.Name, ast.Attribute))
        }

        assert imports == allowed_imports[module_name]
        assert name_calls == allowed_name_calls[module_name]
        assert attribute_calls == allowed_attribute_calls[module_name]
        assert name_calls.isdisjoint(blocked_dynamic_calls)
        assert attribute_calls.isdisjoint(blocked_dynamic_calls)
        assert dynamic_calls == set()
