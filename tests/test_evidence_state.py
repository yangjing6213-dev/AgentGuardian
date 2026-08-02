from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone
import json

import pytest

from agentguardian.domain import Evidence, Finding, RiskDomain, Score, Severity
from agentguardian.dispositions import DispositionRecord, DispositionStatus
from agentguardian.evidence_state import (
    MAX_STATE_BYTES,
    MAX_STATE_FINDINGS,
    SCHEMA_VERSION,
    EvidenceStateError,
    build_snapshot,
    decode_snapshot,
    encode_snapshot,
)


CAPTURED_AT = datetime(2026, 8, 2, 1, 2, 3, tzinfo=timezone.utc)
DISPOSITION_KEY = b"k" * 32
LEGACY_SCHEMA_V1_JSON = (
    b'{"schema_version":1,"captured_at":"2026-08-02T01:02:03Z",'
    b'"product_version":"0.1.0","rule_version":"1.1.0",'
    b'"scan":{"coverage":0.75,"confidence":0.8,"incomplete":true,'
    b'"limits":["file_scan_limited"]},"findings":[{"rule_id":'
    b'"OPENAI_API_KEY","root_hmac_fingerprint":"'
    + b"a" * 64
    + b'","evidence":[{"hmac_fingerprint":"'
    + b"b" * 64
    + b'","masked":"OpenAI API key detected"}]}]}'
)


class _BytesSubclass(bytes):
    pass


def _score() -> Score:
    return Score(
        total=88,
        deductions=((RiskDomain.CREDENTIALS, 12),),
        cap_reason=None,
        coverage=0.75,
        confidence=0.8,
        limits=("file_scan_limited",),
        incomplete=True,
    )


def _finding(
    rule_id: str = "OPENAI_API_KEY",
    root: str = "a",
    evidence: str = "b",
    source: str = "synthetic.env",
    masked: str = "sk-...last4",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        domain=RiskDomain.CREDENTIALS,
        severity=Severity.HIGH,
        root_fingerprint=root * 64,
        evidence=(Evidence(source, evidence * 64, masked),),
    )


def _record(
    disposition_ref: str = "c" * 64,
    *,
    rule_id: str = "OPENAI_API_KEY",
    status: DispositionStatus = DispositionStatus.FALSE_POSITIVE,
    reason: str = "Synthetic review reason",
    reviewer: str = "Local reviewer",
    created_at: str = "2026-08-02T01:00:00Z",
    expires_at: str = "2026-08-31T01:00:00Z",
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


def test_snapshot_contains_only_minimized_safe_fields() -> None:
    source = "private-config.env"
    record = _record()
    snapshot = build_snapshot(
        (_finding(source=source),),
        _score(),
        rule_version="1.1.0",
        captured_at=CAPTURED_AT,
        disposition_key=DISPOSITION_KEY,
        dispositions=(record,),
    )
    encoded = encode_snapshot(snapshot)
    payload = json.loads(encoded)

    assert payload == {
        "schema_version": 2,
        "captured_at": "2026-08-02T01:02:03Z",
        "product_version": "0.1.0",
        "rule_version": "1.1.0",
        "scan": {
            "coverage": 0.75,
            "confidence": 0.8,
            "incomplete": True,
            "limits": ["file_scan_limited"],
        },
        "findings": [
            {
                "rule_id": "OPENAI_API_KEY",
                "root_hmac_fingerprint": "a" * 64,
                "evidence": [
                    {
                        "hmac_fingerprint": "b" * 64,
                        "masked": "OpenAI API key detected",
                    }
                ],
            }
        ],
        "disposition_hmac_key": DISPOSITION_KEY.hex(),
        "dispositions": [
            {
                "disposition_ref": "c" * 64,
                "rule_id": "OPENAI_API_KEY",
                "status": "false_positive",
                "reason": "Synthetic review reason",
                "reviewer": "Local reviewer",
                "created_at": "2026-08-02T01:00:00Z",
                "expires_at": "2026-08-31T01:00:00Z",
            }
        ],
    }
    assert list(payload) == [
        "schema_version",
        "captured_at",
        "product_version",
        "rule_version",
        "scan",
        "findings",
        "disposition_hmac_key",
        "dispositions",
    ]
    assert list(payload["dispositions"][0]) == [
        "disposition_ref",
        "rule_id",
        "status",
        "reason",
        "reviewer",
        "created_at",
        "expires_at",
    ]
    assert encoded == json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    assert source.encode() not in encoded
    for forbidden in (
        b"source",
        b"path",
        b"root_path",
        b"scan_key",
        b"raw",
        b"endpoint",
        b"domain",
        b"severity",
    ):
        assert forbidden not in encoded


def test_snapshot_encoding_is_deterministic_and_round_trips() -> None:
    findings = (
        _finding("OPENAI_API_KEY", "d", "f", masked="masked-z"),
        _finding("GENERIC_API_KEY", "c", "e", masked="masked-a"),
    )
    first = build_snapshot(
        findings,
        _score(),
        rule_version="1.1.0",
        captured_at=CAPTURED_AT,
        disposition_key=DISPOSITION_KEY,
        dispositions=(
            _record("f" * 64),
            _record(
                "e" * 64,
                status=DispositionStatus.ACCEPTED_RISK,
            ),
        ),
    )
    second = build_snapshot(
        reversed(findings),
        _score(),
        rule_version="1.1.0",
        captured_at=CAPTURED_AT,
        disposition_key=DISPOSITION_KEY,
        dispositions=iter(reversed(first.dispositions)),
    )

    assert first == second
    assert encode_snapshot(first) == encode_snapshot(second)
    assert decode_snapshot(encode_snapshot(first)) == first
    assert [finding.rule_id for finding in first.findings] == [
        "GENERIC_API_KEY",
        "OPENAI_API_KEY",
    ]
    assert [record.disposition_ref for record in first.dispositions] == [
        "e" * 64,
        "f" * 64,
    ]
    assert [record.status for record in first.dispositions] == [
        DispositionStatus.ACCEPTED_RISK,
        DispositionStatus.FALSE_POSITIVE,
    ]
    assert [
        record["status"]
        for record in json.loads(encode_snapshot(first))["dispositions"]
    ] == ["accepted_risk", "false_positive"]


def test_snapshot_replaces_free_text_with_rule_owned_summary() -> None:
    marker = "api.openai.com/v1-private-token"
    snapshot = build_snapshot(
        (_finding(masked=marker),),
        _score(),
        rule_version="1.1.0",
        captured_at=CAPTURED_AT,
        disposition_key=DISPOSITION_KEY,
        dispositions=(),
    )
    encoded = encode_snapshot(snapshot)

    assert marker.encode() not in encoded
    assert snapshot.findings[0].evidence[0].masked == "OpenAI API key detected"


def test_snapshot_rejects_unknown_rule_without_persistence_summary() -> None:
    with pytest.raises(EvidenceStateError, match="^PROTECTED_STATE_INVALID$"):
        build_snapshot(
            (_finding(rule_id="UNMAPPED_RULE"),),
            _score(),
            rule_version="1.1.0",
            captured_at=CAPTURED_AT,
            disposition_key=DISPOSITION_KEY,
            dispositions=(),
        )


@pytest.mark.parametrize(
    "mutate",
    (
        lambda payload: payload.update({"unknown": True}),
        lambda payload: payload.update({"schema_version": 3}),
        lambda payload: payload.update({"captured_at": "not-a-time"}),
        lambda payload: payload["scan"].update({"coverage": float("nan")}),
        lambda payload: payload["findings"][0].update(
            {"root_hmac_fingerprint": "not-a-hmac"}
        ),
        lambda payload: payload["findings"][0]["evidence"][0].update(
            {"masked": "https://synthetic-provider.invalid/v1"}
        ),
        lambda payload: payload["findings"][0]["evidence"][0].update(
            {"source": "must-not-be-accepted.env"}
        ),
    ),
)
def test_decode_rejects_invalid_or_extended_payload_without_echoing_input(
    mutate: object,
) -> None:
    snapshot = build_snapshot(
        (_finding(),),
        _score(),
        rule_version="1.1.0",
        captured_at=CAPTURED_AT,
        disposition_key=DISPOSITION_KEY,
        dispositions=(_record(),),
    )
    payload = json.loads(encode_snapshot(snapshot))
    mutate(payload)  # type: ignore[operator]
    marker = "must-not-be-accepted"
    encoded = json.dumps(payload, allow_nan=True).encode()

    with pytest.raises(EvidenceStateError) as raised:
        decode_snapshot(encoded)

    assert str(raised.value) == "PROTECTED_STATE_INVALID"
    assert marker not in str(raised.value)


def test_snapshot_requires_utc_aware_capture_time() -> None:
    with pytest.raises(EvidenceStateError, match="^PROTECTED_STATE_INVALID$"):
        build_snapshot(
            (_finding(),),
            _score(),
            rule_version="1.1.0",
            captured_at=datetime(2026, 8, 2, 1, 2, 3),
            disposition_key=DISPOSITION_KEY,
            dispositions=(),
        )


def test_decode_rejects_duplicate_json_keys() -> None:
    snapshot = build_snapshot(
        (_finding(),),
        _score(),
        rule_version="1.1.0",
        captured_at=CAPTURED_AT,
        disposition_key=DISPOSITION_KEY,
        dispositions=(),
    )
    encoded = encode_snapshot(snapshot).replace(
        b'"schema_version":2,',
        b'"schema_version":2,"schema_version":2,',
        1,
    )

    with pytest.raises(EvidenceStateError, match="^PROTECTED_STATE_INVALID$"):
        decode_snapshot(encoded)


def test_literal_schema_v1_fixture_decodes_but_cannot_be_reencoded() -> None:
    snapshot = decode_snapshot(LEGACY_SCHEMA_V1_JSON)

    assert snapshot.schema_version == 1
    assert snapshot.disposition_key is None
    assert snapshot.dispositions == ()
    assert snapshot.findings[0].evidence[0].masked == "OpenAI API key detected"
    with pytest.raises(EvidenceStateError, match="^PROTECTED_STATE_INVALID$"):
        encode_snapshot(snapshot)


def test_snapshot_is_frozen_slotted_and_hides_disposition_secrets() -> None:
    snapshot = build_snapshot(
        (_finding(),),
        _score(),
        rule_version="1.1.0",
        captured_at=CAPTURED_AT,
        disposition_key=DISPOSITION_KEY,
        dispositions=(_record(),),
    )
    rendered = repr(snapshot)

    assert SCHEMA_VERSION == 2
    assert not hasattr(snapshot, "__dict__")
    assert DISPOSITION_KEY.hex() not in rendered
    assert repr(DISPOSITION_KEY) not in rendered
    assert "c" * 64 not in rendered
    with pytest.raises(FrozenInstanceError):
        snapshot.schema_version = 1  # type: ignore[misc]


@pytest.mark.parametrize(
    "change",
    (
        {"schema_version": True},
        {"schema_version": 3},
        {"disposition_key": None},
        {"disposition_key": b"short"},
        {"disposition_key": bytearray(DISPOSITION_KEY)},
        {"dispositions": [_record()]},
        {"dispositions": (_record("d" * 64), _record("c" * 64))},
        {"dispositions": (_record(), _record())},
    ),
)
def test_schema_v2_rejects_invalid_in_memory_combinations(
    change: dict[str, object],
) -> None:
    snapshot = build_snapshot(
        (),
        _score(),
        rule_version="1.1.0",
        captured_at=CAPTURED_AT,
        disposition_key=DISPOSITION_KEY,
        dispositions=(_record(),),
    )

    with pytest.raises(EvidenceStateError) as raised:
        replace(snapshot, **change)

    assert str(raised.value) == "PROTECTED_STATE_INVALID"
    assert raised.value.__cause__ is None


@pytest.mark.parametrize(
    "change",
    (
        {"disposition_key": DISPOSITION_KEY},
        {"dispositions": (_record(),)},
    ),
)
def test_schema_v1_rejects_disposition_state(change: dict[str, object]) -> None:
    legacy = decode_snapshot(LEGACY_SCHEMA_V1_JSON)

    with pytest.raises(EvidenceStateError, match="^PROTECTED_STATE_INVALID$"):
        replace(legacy, **change)


def test_build_snapshot_consumes_dispositions_once_and_sorts_them() -> None:
    class OneShot:
        def __init__(self) -> None:
            self.iterations = 0

        def __iter__(self):
            self.iterations += 1
            if self.iterations != 1:
                raise RuntimeError("private one-shot marker")
            yield _record("f" * 64)
            yield _record("e" * 64)

    dispositions = OneShot()

    snapshot = build_snapshot(
        (),
        _score(),
        rule_version="1.1.0",
        captured_at=CAPTURED_AT,
        disposition_key=DISPOSITION_KEY,
        dispositions=dispositions,
    )

    assert dispositions.iterations == 1
    assert tuple(record.disposition_ref for record in snapshot.dispositions) == (
        "e" * 64,
        "f" * 64,
    )


@pytest.mark.parametrize(
    "key",
    (
        b"",
        b"k" * 31,
        b"k" * 33,
        bytearray(DISPOSITION_KEY),
        _BytesSubclass(DISPOSITION_KEY),
    ),
    ids=("empty", "short", "long", "bytearray", "bytes-subclass"),
)
def test_build_snapshot_rejects_invalid_disposition_key(key: object) -> None:
    with pytest.raises(EvidenceStateError, match="^PROTECTED_STATE_INVALID$"):
        build_snapshot(
            (),
            _score(),
            rule_version="1.1.0",
            captured_at=CAPTURED_AT,
            disposition_key=key,  # type: ignore[arg-type]
            dispositions=(),
        )


def test_build_snapshot_rejects_duplicate_dispositions_without_leaking_ref() -> None:
    marker = "d" * 64

    with pytest.raises(EvidenceStateError) as raised:
        build_snapshot(
            (),
            _score(),
            rule_version="1.1.0",
            captured_at=CAPTURED_AT,
            disposition_key=DISPOSITION_KEY,
            dispositions=(_record(marker), _record(marker)),
        )

    assert str(raised.value) == "PROTECTED_STATE_INVALID"
    assert marker not in str(raised.value)
    assert raised.value.__cause__ is None


def test_build_snapshot_rejects_dispositions_above_state_limit() -> None:
    records = (
        _record(f"{index:064x}") for index in range(MAX_STATE_FINDINGS + 1)
    )

    with pytest.raises(EvidenceStateError, match="^PROTECTED_STATE_INVALID$"):
        build_snapshot(
            (),
            _score(),
            rule_version="1.1.0",
            captured_at=CAPTURED_AT,
            disposition_key=DISPOSITION_KEY,
            dispositions=records,
        )


def test_build_snapshot_replaces_caller_evidence_state_error_and_chain() -> None:
    marker = "private-evidence-state-marker"

    class AdversarialFindings:
        def __iter__(self):
            try:
                raise RuntimeError(r"C:\private\finding.txt")
            except RuntimeError as error:
                raise EvidenceStateError(marker) from error

    with pytest.raises(EvidenceStateError) as raised:
        build_snapshot(
            AdversarialFindings(),
            _score(),
            rule_version="1.1.0",
            captured_at=CAPTURED_AT,
            disposition_key=DISPOSITION_KEY,
            dispositions=(),
        )

    assert str(raised.value) == "PROTECTED_STATE_INVALID"
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert marker not in str(raised.value)


def test_build_snapshot_bounds_findings_before_transforming() -> None:
    class CountingFindings:
        def __init__(self) -> None:
            self.consumed = 0

        def __iter__(self):
            while True:
                self.consumed += 1
                if self.consumed > MAX_STATE_FINDINGS + 1:
                    raise AssertionError("private findings over-consumed")
                yield _finding()

    findings = CountingFindings()

    with pytest.raises(EvidenceStateError) as raised:
        build_snapshot(
            findings,
            _score(),
            rule_version="1.1.0",
            captured_at=CAPTURED_AT,
            disposition_key=DISPOSITION_KEY,
            dispositions=(),
        )

    assert findings.consumed == MAX_STATE_FINDINGS + 1
    assert str(raised.value) == "PROTECTED_STATE_INVALID"
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


def test_build_snapshot_bounds_dispositions_before_indexing() -> None:
    class CountingDispositions:
        def __init__(self) -> None:
            self.consumed = 0

        def __iter__(self):
            while True:
                self.consumed += 1
                if self.consumed > MAX_STATE_FINDINGS + 1:
                    raise AssertionError("private dispositions over-consumed")
                yield _record(f"{self.consumed:064x}")

    dispositions = CountingDispositions()

    with pytest.raises(EvidenceStateError) as raised:
        build_snapshot(
            (),
            _score(),
            rule_version="1.1.0",
            captured_at=CAPTURED_AT,
            disposition_key=DISPOSITION_KEY,
            dispositions=dispositions,
        )

    assert dispositions.consumed == MAX_STATE_FINDINGS + 1
    assert str(raised.value) == "PROTECTED_STATE_INVALID"
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


@pytest.mark.parametrize(
    "mutate",
    (
        lambda payload: payload.pop("disposition_hmac_key"),
        lambda payload: payload.update({"schema_version": True}),
        lambda payload: payload.update({"schema_version": "2"}),
        lambda payload: payload.update({"disposition_hmac_key": "K" * 64}),
        lambda payload: payload.update({"disposition_hmac_key": "k" * 63}),
        lambda payload: payload.update({"dispositions": {}}),
        lambda payload: payload["dispositions"][0].update({"unknown": True}),
        lambda payload: payload["dispositions"][0].pop("reviewer"),
        lambda payload: payload["dispositions"][0].update(
            {"status": "open"}
        ),
        lambda payload: payload["dispositions"][0].update(
            {"created_at": "2026-08-02T01:00:00+00:00"}
        ),
        lambda payload: payload["dispositions"][0].update(
            {"reason": r"C:\private\raw-secret.txt"}
        ),
        lambda payload: payload.update(
            {"dispositions": list(reversed(payload["dispositions"]))}
        ),
        lambda payload: payload["dispositions"].append(
            payload["dispositions"][0]
        ),
    ),
)
def test_decode_v2_rejects_invalid_schema_without_leaking_input(
    mutate: object,
) -> None:
    snapshot = build_snapshot(
        (),
        _score(),
        rule_version="1.1.0",
        captured_at=CAPTURED_AT,
        disposition_key=DISPOSITION_KEY,
        dispositions=(_record("c" * 64), _record("d" * 64)),
    )
    payload = json.loads(encode_snapshot(snapshot))
    mutate(payload)  # type: ignore[operator]

    with pytest.raises(EvidenceStateError) as raised:
        decode_snapshot(json.dumps(payload).encode("utf-8"))

    assert str(raised.value) == "PROTECTED_STATE_INVALID"
    assert "raw-secret" not in str(raised.value)
    assert "c" * 64 not in str(raised.value)
    assert raised.value.__cause__ is None


@pytest.mark.parametrize(
    "mutate",
    (
        lambda payload: payload.update({"dispositions": []}),
        lambda payload: payload["scan"].update({"unknown": True}),
        lambda payload: payload["findings"][0]["evidence"][0].update(
            {"source": "private.env"}
        ),
    ),
)
def test_decode_v1_accepts_only_historical_schema(mutate: object) -> None:
    payload = json.loads(LEGACY_SCHEMA_V1_JSON)
    mutate(payload)  # type: ignore[operator]

    with pytest.raises(EvidenceStateError, match="^PROTECTED_STATE_INVALID$"):
        decode_snapshot(json.dumps(payload).encode("utf-8"))


def test_decode_rejects_oversized_payload_and_disposition_count() -> None:
    with pytest.raises(EvidenceStateError, match="^PROTECTED_STATE_INVALID$"):
        decode_snapshot(b"x" * (MAX_STATE_BYTES + 1))

    snapshot = build_snapshot(
        (),
        _score(),
        rule_version="1.1.0",
        captured_at=CAPTURED_AT,
        disposition_key=DISPOSITION_KEY,
        dispositions=(),
    )
    payload = json.loads(encode_snapshot(snapshot))
    record = json.loads(
        json.dumps(
            {
                "disposition_ref": "0" * 64,
                "rule_id": "OPENAI_API_KEY",
                "status": "false_positive",
                "reason": "Synthetic review reason",
                "reviewer": "Local reviewer",
                "created_at": "2026-08-02T01:00:00Z",
                "expires_at": "2026-08-31T01:00:00Z",
            }
        )
    )
    payload["dispositions"] = [record] * (MAX_STATE_FINDINGS + 1)

    with pytest.raises(EvidenceStateError, match="^PROTECTED_STATE_INVALID$"):
        decode_snapshot(json.dumps(payload).encode("utf-8"))
