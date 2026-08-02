from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone

import pytest

from agentguardian.dispositions import (
    DispositionEvaluation,
    DispositionRecord,
    DispositionStatus,
    disposition_index,
    evaluate_disposition,
    make_disposition_ref,
    parse_utc,
    reviewed_findings,
    upsert_disposition,
    withdraw_disposition,
)
from agentguardian.domain import Finding, RiskDomain, Severity


FIXED_NOW = datetime(2026, 8, 2, 9, 0, tzinfo=timezone.utc)
KEY = b"d" * 32


def _record(
    disposition_ref: str = "a" * 64,
    *,
    rule_id: str = "OPENAI_API_KEY",
    status: DispositionStatus = DispositionStatus.FALSE_POSITIVE,
    created_at: str = "2026-08-02T08:00:00Z",
    expires_at: str = "2026-08-31T08:00:00Z",
    reason: str = "Synthetic test fixture",
    reviewer: str = "Local reviewer",
) -> DispositionRecord:
    return DispositionRecord(
        disposition_ref=disposition_ref,
        rule_id=rule_id,
        status=status,
        reason=reason,
        reviewer=reviewer,
        created_at=created_at,
        expires_at=expires_at,
    )


def _finding(
    disposition_ref: str | None = "a" * 64,
    *,
    rule_id: str = "OPENAI_API_KEY",
) -> Finding:
    return Finding(
        rule_id,
        RiskDomain.CREDENTIALS,
        Severity.HIGH,
        "b" * 64,
        (),
        disposition_ref,
    )


def test_disposition_reference_is_deterministic_normalized_and_hidden() -> None:
    reference = make_disposition_ref(
        KEY,
        rule_id="OPENAI_API_KEY",
        source=r"C:\Synthetic\config.env",
        raw_match="caf\u00e9 synthetic value",
    )
    equivalent = make_disposition_ref(
        KEY,
        rule_id="OPENAI_API_KEY",
        source=r"c:\synthetic\.\config.env",
        raw_match="cafe\u0301 synthetic value",
    )

    assert reference == equivalent
    assert len(reference) == 64
    assert set(reference) <= set("0123456789abcdef")
    assert reference not in repr(_finding(reference))
    assert reference not in repr(_record(reference))


def test_disposition_reference_separates_every_input_component() -> None:
    arguments = {
        "rule_id": "OPENAI_API_KEY",
        "source": r"C:\Synthetic\config.env",
        "raw_match": "synthetic value",
    }
    references = {
        make_disposition_ref(KEY, **arguments),
        make_disposition_ref(b"e" * 32, **arguments),
        make_disposition_ref(KEY, **(arguments | {"rule_id": "GENERIC_API_KEY"})),
        make_disposition_ref(
            KEY, **(arguments | {"source": r"C:\Synthetic\moved.env"})
        ),
        make_disposition_ref(KEY, **(arguments | {"raw_match": "changed value"})),
    }

    assert len(references) == 5


@pytest.mark.parametrize(
    ("key", "rule_id", "source", "raw_match"),
    (
        (b"short", "OPENAI_API_KEY", r"C:\Synthetic\a.env", "value"),
        (bytearray(b"d" * 32), "OPENAI_API_KEY", r"C:\Synthetic\a.env", "value"),
        (KEY, "invalid-rule", r"C:\Synthetic\a.env", "value"),
        (KEY, "OPENAI_API_KEY", "", "value"),
        (KEY, "OPENAI_API_KEY", r"C:\Synthetic\a.env", ""),
        (KEY, "OPENAI_API_KEY", r"C:\Synthetic\a.env", 1),
    ),
)
def test_disposition_reference_rejects_invalid_inputs_without_echoing_them(
    key: object,
    rule_id: object,
    source: object,
    raw_match: object,
) -> None:
    with pytest.raises(ValueError) as raised:
        make_disposition_ref(  # type: ignore[arg-type]
            key,
            rule_id=rule_id,
            source=source,
            raw_match=raw_match,
        )

    assert str(raised.value) == "DISPOSITION_INVALID"


def test_disposition_record_is_exact_frozen_and_trims_annotations() -> None:
    record = _record(reason="  Synthetic fixture  ", reviewer="  Reviewer  ")

    assert record.status is DispositionStatus.FALSE_POSITIVE
    assert record.reason == "Synthetic fixture"
    assert record.reviewer == "Reviewer"
    assert not hasattr(record, "__dict__")
    with pytest.raises(FrozenInstanceError):
        record.reason = "Changed"  # type: ignore[misc]


@pytest.mark.parametrize(
    "changes",
    (
        {"disposition_ref": "A" * 64},
        {"disposition_ref": "a" * 63},
        {"rule_id": "invalid-rule"},
        {"rule_id": "A" * 81},
        {"status": "false_positive"},
        {"reason": " "},
        {"reason": "r" * 241},
        {"reviewer": "r" * 81},
        {"created_at": "2026-08-02T08:00:00.000Z"},
        {"created_at": "2026-08-02T08:00:00+00:00"},
        {"expires_at": "2026-08-02T08:00:00Z"},
        {"expires_at": "2027-08-04T08:00:00Z"},
    ),
)
def test_disposition_record_rejects_malformed_contract(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="^DISPOSITION_INVALID$"):
        replace(_record(), **changes)


def test_disposition_record_allows_exact_366_day_lifetime() -> None:
    record = _record(
        created_at="2026-08-02T08:00:00Z",
        expires_at="2027-08-03T08:00:00Z",
    )

    assert parse_utc(record.expires_at) - parse_utc(record.created_at) == timedelta(
        days=366
    )


@pytest.mark.parametrize(
    "unsafe",
    (
        r"C:\private\secret.txt",
        "https://example.invalid/private",
        "ghp_" + "a" * 32,
        "abandon ability able about above absent absorb abstract absurd abuse access accident",
        "review\nmarker",
    ),
)
def test_disposition_record_rejects_unsafe_annotations_without_echoing_them(
    unsafe: str,
) -> None:
    with pytest.raises(ValueError) as raised:
        replace(_record(), reason=unsafe)

    assert str(raised.value) == "DISPOSITION_INVALID"
    assert unsafe not in str(raised.value)


@pytest.mark.parametrize(
    "value",
    (
        "2026-08-02 09:00:00Z",
        "2026-08-02T09:00:00z",
        "2026-02-30T09:00:00Z",
        123,
    ),
)
def test_parse_utc_accepts_only_canonical_utc_seconds(value: object) -> None:
    with pytest.raises(ValueError, match="^DISPOSITION_INVALID$"):
        parse_utc(value)


def test_disposition_index_rejects_non_records_and_duplicates() -> None:
    record = _record()

    assert disposition_index((record,)) == {record.disposition_ref: record}
    with pytest.raises(ValueError, match="^DISPOSITION_INVALID$"):
        disposition_index((record, record))
    with pytest.raises(ValueError, match="^DISPOSITION_INVALID$"):
        disposition_index((object(),))  # type: ignore[arg-type]


def test_evaluate_disposition_covers_open_active_expired_and_future_states() -> None:
    finding = _finding()
    false_positive = _record()
    accepted = replace(false_positive, status=DispositionStatus.ACCEPTED_RISK)
    expired = replace(false_positive, expires_at="2026-08-02T09:00:00Z")
    future = replace(
        false_positive,
        created_at="2026-08-02T10:00:00Z",
        expires_at="2026-08-03T10:00:00Z",
    )

    assert evaluate_disposition(finding, {}, now=FIXED_NOW) == DispositionEvaluation(
        "open", None
    )
    assert evaluate_disposition(
        finding, disposition_index((false_positive,)), now=FIXED_NOW
    ) == DispositionEvaluation("false_positive", false_positive)
    assert evaluate_disposition(
        finding, disposition_index((accepted,)), now=FIXED_NOW
    ) == DispositionEvaluation("accepted_risk", accepted)
    assert evaluate_disposition(
        finding, disposition_index((expired,)), now=FIXED_NOW
    ) == DispositionEvaluation("expired", expired)
    assert evaluate_disposition(
        finding, disposition_index((future,)), now=FIXED_NOW
    ) == DispositionEvaluation("open", None)


def test_evaluate_disposition_fails_closed_on_missing_or_mismatched_references() -> None:
    finding = _finding()
    wrong_rule = _record(rule_id="GENERIC_API_KEY")
    wrong_reference = _record("b" * 64)

    for candidate, records in (
        (_finding(None), {}),
        (finding, {}),
        (finding, {finding.disposition_ref: wrong_rule}),
        (finding, {finding.disposition_ref: wrong_reference}),
    ):
        assert evaluate_disposition(candidate, records, now=FIXED_NOW) == (
            DispositionEvaluation("open", None)
        )


@pytest.mark.parametrize(
    "now",
    (
        datetime(2026, 8, 2, 9, 0),
        datetime(2026, 8, 2, 9, 0, tzinfo=timezone(timedelta(hours=1))),
        "2026-08-02T09:00:00Z",
    ),
)
def test_evaluate_disposition_requires_aware_utc_now(now: object) -> None:
    with pytest.raises(ValueError, match="^DISPOSITION_INVALID$"):
        evaluate_disposition(  # type: ignore[arg-type]
            _finding(), disposition_index((_record(),)), now=now
        )


def test_reviewed_findings_excludes_only_active_false_positives() -> None:
    active_false_positive = _finding("a" * 64)
    accepted_risk = _finding("b" * 64)
    expired_false_positive = _finding("c" * 64)
    open_finding = _finding(None)
    records = disposition_index(
        (
            _record("a" * 64),
            _record("b" * 64, status=DispositionStatus.ACCEPTED_RISK),
            _record("c" * 64, expires_at="2026-08-02T09:00:00Z"),
        )
    )

    assert reviewed_findings(
        (
            active_false_positive,
            accepted_risk,
            expired_false_positive,
            open_finding,
        ),
        records,
        now=FIXED_NOW,
    ) == (accepted_risk, expired_false_positive, open_finding)


def test_upsert_replaces_same_reference_and_sorts_deterministically() -> None:
    first = _record("a" * 64)
    second = _record("b" * 64)
    replacement = replace(first, status=DispositionStatus.ACCEPTED_RISK)

    assert upsert_disposition((second, first), replacement) == (replacement, second)
    with pytest.raises(ValueError, match="^DISPOSITION_INVALID$"):
        upsert_disposition((first, first), replacement)
    with pytest.raises(ValueError, match="^DISPOSITION_INVALID$"):
        upsert_disposition((first,), object())  # type: ignore[arg-type]


def test_withdraw_validates_reference_and_returns_sorted_records() -> None:
    first = _record("a" * 64)
    second = _record("b" * 64)

    assert withdraw_disposition((second, first), second.disposition_ref) == (first,)
    assert withdraw_disposition((second, first), "c" * 64) == (first, second)
    with pytest.raises(ValueError, match="^DISPOSITION_INVALID$"):
        withdraw_disposition((first,), "A" * 64)
