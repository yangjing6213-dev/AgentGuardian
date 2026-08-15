from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agentguardian.enterprise_control_plane import EnterpriseControlPlane, TenantSummary
from agentguardian.enterprise_policy import PolicyDecisionStatus


NOW = datetime(2026, 8, 15, 12, 0, tzinfo=timezone.utc)


def _document(*, tenant_id: str = "tenant-alpha", device_id: str = "device-alpha", version: int = 1) -> bytes:
    return json.dumps(
        {
            "schema": 1,
            "version": version,
            "policy_id": "policy-alpha",
            "tenant_id": tenant_id,
            "device_id": device_id,
            "issued_at": "2026-08-01T00:00:00Z",
            "expires_at": "2026-09-01T00:00:00Z",
            "roles": {"operator": ["local_scan", "share_verify"]},
            "high_sensitivity_requires_confirmation": True,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _provisioned(tmp_path: Path) -> EnterpriseControlPlane:
    control_plane = EnterpriseControlPlane(tmp_path / "control-plane.sqlite3")
    control_plane.register_tenant("tenant-alpha", "Alpha", now=NOW)
    control_plane.register_device("tenant-alpha", "device-alpha", now=NOW)
    control_plane.grant_role("tenant-alpha", "subject-alpha", "operator")
    control_plane.provision_policy(_document(), now=NOW)
    return control_plane


def test_control_plane_binds_policy_to_registered_device_and_subject_role(tmp_path: Path) -> None:
    control_plane = _provisioned(tmp_path)

    decision = control_plane.evaluate_capability(
        tenant_id="tenant-alpha",
        device_id="device-alpha",
        subject_id="subject-alpha",
        policy_id="policy-alpha",
        capability="local_scan",
        now=NOW,
    )

    assert decision.status is PolicyDecisionStatus.ALLOWED
    assert decision.allowed is True

    wrong_tenant = control_plane.evaluate_capability(
        tenant_id="other-tenant",
        device_id="device-alpha",
        subject_id="subject-alpha",
        policy_id="policy-alpha",
        capability="local_scan",
        now=NOW,
    )
    assert wrong_tenant.status is PolicyDecisionStatus.DENIED
    assert wrong_tenant.reason == "tenant_not_registered"


def test_control_plane_rejects_policy_rollback_and_revokes_access(tmp_path: Path) -> None:
    control_plane = _provisioned(tmp_path)
    with pytest.raises(ValueError, match="POLICY_VERSION_ROLLBACK"):
        control_plane.provision_policy(_document(version=1), now=NOW)

    control_plane.provision_policy(_document(version=2), now=NOW)
    with pytest.raises(ValueError, match="CONTROL_PLANE_TIME_INVALID"):
        control_plane.revoke_policy("tenant-alpha", "policy-alpha", 2, now=None)  # type: ignore[arg-type]
    still_active = control_plane.evaluate_capability(
        tenant_id="tenant-alpha",
        device_id="device-alpha",
        subject_id="subject-alpha",
        policy_id="policy-alpha",
        capability="local_scan",
        now=NOW,
    )
    assert still_active.allowed is True

    control_plane.revoke_policy("tenant-alpha", "policy-alpha", 2, now=NOW)
    revoked_policy = control_plane.evaluate_capability(
        tenant_id="tenant-alpha",
        device_id="device-alpha",
        subject_id="subject-alpha",
        policy_id="policy-alpha",
        capability="local_scan",
        now=NOW,
    )
    assert revoked_policy.status is PolicyDecisionStatus.DENIED
    assert revoked_policy.reason == "policy_revoked"

    control_plane.provision_policy(_document(version=3), now=NOW)
    control_plane.revoke_device("tenant-alpha", "device-alpha", now=NOW)
    revoked_device = control_plane.evaluate_capability(
        tenant_id="tenant-alpha",
        device_id="device-alpha",
        subject_id="subject-alpha",
        policy_id="policy-alpha",
        capability="local_scan",
        now=NOW,
    )
    assert revoked_device.status is PolicyDecisionStatus.DENIED
    assert revoked_device.reason == "device_revoked"


def test_control_plane_exports_only_bounded_metadata_and_purges_expired_events(
    tmp_path: Path,
) -> None:
    control_plane = _provisioned(tmp_path)
    control_plane.record_event(
        tenant_id="tenant-alpha",
        device_id="device-alpha",
        event_type="scan_completed",
        metadata={"finding_count": 2, "coverage": "complete"},
        occurred_at=NOW,
        retention=timedelta(days=1),
    )
    with pytest.raises(ValueError, match="AUDIT_METADATA_KEY_INVALID"):
        control_plane.record_event(
            tenant_id="tenant-alpha",
            device_id="device-alpha",
            event_type="scan_completed",
            metadata={"raw_content": "must-not-be-stored"},
            occurred_at=NOW,
            retention=timedelta(days=1),
        )

    exported = json.loads(control_plane.export_events("tenant-alpha", now=NOW))
    assert exported["tenant_id"] == "tenant-alpha"
    assert exported["events"] == [
        {
            "device_id": "device-alpha",
            "event_type": "scan_completed",
            "metadata": {"coverage": "complete", "finding_count": 2},
            "occurred_at": "2026-08-15T12:00:00Z",
        }
    ]
    assert "must-not-be-stored" not in json.dumps(exported)

    assert control_plane.purge_expired_events(NOW + timedelta(days=2)) == 1
    assert json.loads(control_plane.export_events("tenant-alpha", now=NOW))["events"] == []


def test_control_plane_exposes_operational_summaries_without_event_content(tmp_path: Path) -> None:
    control_plane = _provisioned(tmp_path)
    control_plane.record_event(
        tenant_id="tenant-alpha",
        device_id="device-alpha",
        event_type="scan_completed",
        metadata={"finding_count": 2},
        occurred_at=NOW,
        retention=timedelta(days=1),
    )

    tenants = control_plane.list_tenant_summaries()
    assert tenants == (
        TenantSummary(
            tenant_id="tenant-alpha",
            display_name="Alpha",
            device_count=1,
            active_device_count=1,
            active_policy_count=1,
            audit_event_count=1,
        ),
    )
    assert control_plane.list_device_summaries("tenant-alpha")[0].device_id == "device-alpha"
    assert control_plane.list_policy_summaries("tenant-alpha")[0].policy_sha256


def test_admin_tokens_are_hashed_tenant_bound_and_revocable(tmp_path: Path) -> None:
    control_plane = _provisioned(tmp_path)
    token_id, token = control_plane.issue_admin_token(
        "tenant-alpha",
        "admin",
        now=NOW,
        expires_at=NOW + timedelta(days=1),
    )

    assert control_plane.authenticate_admin_token(token, now=NOW) == (
        "tenant-alpha",
        "admin",
    )
    stored = control_plane._connection.execute(
        "SELECT token_hash FROM admin_tokens WHERE token_id = ?", (token_id,)
    ).fetchone()
    assert stored is not None
    assert bytes(stored["token_hash"]) != token.encode()
    assert control_plane.authenticate_admin_token(token, now=NOW + timedelta(days=2)) is None

    control_plane.revoke_admin_token("tenant-alpha", token_id, now=NOW)
    assert control_plane.authenticate_admin_token(token, now=NOW) is None
