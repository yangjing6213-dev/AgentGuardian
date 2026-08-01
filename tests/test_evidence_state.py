from __future__ import annotations

from datetime import datetime, timezone
import json

import pytest

from agentguardian.domain import Evidence, Finding, RiskDomain, Score, Severity
from agentguardian.evidence_state import (
    EvidenceStateError,
    build_snapshot,
    decode_snapshot,
    encode_snapshot,
)


CAPTURED_AT = datetime(2026, 8, 2, 1, 2, 3, tzinfo=timezone.utc)


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


def test_snapshot_contains_only_minimized_safe_fields() -> None:
    source = "private-config.env"
    snapshot = build_snapshot(
        (_finding(source=source),),
        _score(),
        rule_version="1.1.0",
        captured_at=CAPTURED_AT,
    )
    encoded = encode_snapshot(snapshot)
    payload = json.loads(encoded)

    assert payload == {
        "schema_version": 1,
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
                        "masked": "sk-...last4",
                    }
                ],
            }
        ],
    }
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
        _finding("Z_RULE", "d", "f", masked="masked-z"),
        _finding("A_RULE", "c", "e", masked="masked-a"),
    )
    first = build_snapshot(
        findings,
        _score(),
        rule_version="1.1.0",
        captured_at=CAPTURED_AT,
    )
    second = build_snapshot(
        reversed(findings),
        _score(),
        rule_version="1.1.0",
        captured_at=CAPTURED_AT,
    )

    assert first == second
    assert encode_snapshot(first) == encode_snapshot(second)
    assert decode_snapshot(encode_snapshot(first)) == first
    assert [finding.rule_id for finding in first.findings] == ["A_RULE", "Z_RULE"]


@pytest.mark.parametrize(
    "mutate",
    (
        lambda payload: payload.update({"unknown": True}),
        lambda payload: payload.update({"schema_version": 2}),
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
        )
