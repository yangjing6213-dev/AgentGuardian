from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

import pytest

from agentguardian.enterprise_policy import (
    PolicyDecisionStatus,
    canonical_policy_sha256,
    evaluate_capability,
    parse_enterprise_policy,
)


NOW = datetime(2026, 8, 15, 12, 0, tzinfo=timezone.utc)


def _document(**overrides: object) -> bytes:
    value: dict[str, object] = {
        "schema": 1,
        "version": 3,
        "policy_id": "policy-alpha",
        "tenant_id": "tenant-alpha",
        "device_id": "device-alpha",
        "issued_at": "2026-08-01T00:00:00Z",
        "expires_at": "2026-09-01T00:00:00Z",
        "roles": {"operator": ["local_scan", "share_verify", "mcp_dynamic"]},
        "high_sensitivity_requires_confirmation": True,
    }
    value.update(overrides)
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def test_policy_digest_is_canonical_and_evaluation_requires_matching_pin() -> None:
    document = _document()
    digest = canonical_policy_sha256(document)

    decision = evaluate_capability(
        document,
        expected_sha256=digest,
        role="operator",
        capability="local_scan",
        device_id="device-alpha",
        now=NOW,
    )

    assert decision.status is PolicyDecisionStatus.ALLOWED
    assert decision.allowed is True
    assert decision.integrity_pin_verified is True
    assert decision.policy_sha256 == digest
    assert digest == hashlib.sha256(parse_enterprise_policy(document).canonical_bytes).hexdigest()

    denied = evaluate_capability(
        document,
        expected_sha256="0" * 64,
        role="operator",
        capability="local_scan",
        device_id="device-alpha",
        now=NOW,
    )
    assert denied.status is PolicyDecisionStatus.DENIED
    assert denied.reason == "policy_pin_mismatch"


def test_policy_defaults_to_denied_for_missing_role_or_unknown_capability() -> None:
    document = _document()

    missing_role = evaluate_capability(
        document,
        expected_sha256=canonical_policy_sha256(document),
        role="auditor",
        capability="local_scan",
        device_id="device-alpha",
        now=NOW,
    )
    assert missing_role.status is PolicyDecisionStatus.DENIED
    assert missing_role.reason == "role_not_granted"

    with pytest.raises(ValueError, match="POLICY_CAPABILITY_INVALID"):
        evaluate_capability(
            document,
            expected_sha256=canonical_policy_sha256(document),
            role="operator",
            capability="arbitrary_code",
            device_id="device-alpha",
            now=NOW,
        )


def test_policy_expiry_and_high_sensitivity_confirmation_are_fail_closed() -> None:
    document = _document()
    digest = canonical_policy_sha256(document)

    expired = evaluate_capability(
        document,
        expected_sha256=digest,
        role="operator",
        capability="local_scan",
        device_id="device-alpha",
        now=datetime(2026, 10, 1, tzinfo=timezone.utc),
    )
    assert expired.status is PolicyDecisionStatus.EXPIRED
    assert expired.allowed is False

    unconfirmed = evaluate_capability(
        document,
        expected_sha256=digest,
        role="operator",
        capability="share_verify",
        device_id="device-alpha",
        high_sensitivity=True,
        confirmation=False,
        now=NOW,
    )
    assert unconfirmed.status is PolicyDecisionStatus.DENIED
    assert unconfirmed.reason == "high_sensitivity_confirmation_required"

    confirmed = evaluate_capability(
        document,
        expected_sha256=digest,
        role="operator",
        capability="share_verify",
        device_id="device-alpha",
        high_sensitivity=True,
        confirmation=True,
        now=NOW,
    )
    assert confirmed.allowed is True


def test_dynamic_mcp_requires_an_independently_attested_sandbox() -> None:
    document = _document()
    digest = canonical_policy_sha256(document)

    denied = evaluate_capability(
        document,
        expected_sha256=digest,
        role="operator",
        capability="mcp_dynamic",
        device_id="device-alpha",
        sandbox_enforced=False,
        now=NOW,
    )
    assert denied.status is PolicyDecisionStatus.DENIED
    assert denied.reason == "mcp_isolation_required"

    allowed = evaluate_capability(
        document,
        expected_sha256=digest,
        role="operator",
        capability="mcp_dynamic",
        device_id="device-alpha",
        sandbox_enforced=True,
        now=NOW,
    )
    assert allowed.allowed is True


def test_policy_parser_rejects_duplicate_keys_unknown_fields_and_malformed_values() -> None:
    duplicate = b'{"schema":1,"schema":1}'
    with pytest.raises(ValueError, match="POLICY_DOCUMENT_INVALID"):
        parse_enterprise_policy(duplicate)

    with pytest.raises(ValueError, match="POLICY_DOCUMENT_INVALID"):
        parse_enterprise_policy(_document(unexpected="value"))

    with pytest.raises(ValueError, match="POLICY_CAPABILITY_INVALID"):
        parse_enterprise_policy(_document(roles={"operator": ["shell"]}))


def test_policy_rejects_wrong_device_and_version_rollback() -> None:
    document = _document()
    digest = canonical_policy_sha256(document)

    wrong_device = evaluate_capability(
        document,
        expected_sha256=digest,
        role="operator",
        capability="local_scan",
        device_id="other-device",
        now=NOW,
    )
    assert wrong_device.reason == "device_not_bound"

    rollback = evaluate_capability(
        document,
        expected_sha256=digest,
        role="operator",
        capability="local_scan",
        device_id="device-alpha",
        last_seen_version=3,
        now=NOW,
    )
    assert rollback.reason == "policy_version_rollback"
