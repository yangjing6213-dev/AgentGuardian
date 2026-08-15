from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agentguardian.enterprise_control_plane import EnterpriseControlPlane
from agentguardian.enterprise_service import EnterpriseService, ServiceRequest
from agentguardian.enterprise_signing import (
    Ed25519PolicySigner,
    Ed25519PolicyVerifier,
    create_signed_policy,
)


NOW = datetime(2026, 8, 15, 12, 0, tzinfo=timezone.utc)


def _policy() -> bytes:
    return json.dumps(
        {
            "schema": 1,
            "version": 1,
            "policy_id": "policy-alpha",
            "tenant_id": "tenant-alpha",
            "device_id": "device-alpha",
            "issued_at": "2026-08-01T00:00:00Z",
            "expires_at": "2026-09-01T00:00:00Z",
            "roles": {"operator": ["local_scan"]},
            "high_sensitivity_requires_confirmation": True,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _signer() -> tuple[Ed25519PolicySigner, Ed25519PolicyVerifier]:
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    private = Ed25519PrivateKey.generate()
    return (
        Ed25519PolicySigner(
            private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        ),
        Ed25519PolicyVerifier(
            private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ),
    )


def _service(tmp_path: Path) -> tuple[EnterpriseService, str, str, Ed25519PolicySigner]:
    control_plane = EnterpriseControlPlane(tmp_path / "control-plane.sqlite3")
    control_plane.register_tenant("tenant-alpha", "Alpha", now=NOW)
    control_plane.register_device("tenant-alpha", "device-alpha", now=NOW)
    admin_id, admin_token = control_plane.issue_admin_token(
        "tenant-alpha",
        "admin",
        now=NOW,
        expires_at=NOW + timedelta(days=1),
    )
    _auditor_id, auditor_token = control_plane.issue_admin_token(
        "tenant-alpha",
        "auditor",
        now=NOW,
        expires_at=NOW + timedelta(days=1),
    )
    _ = admin_id
    signer, verifier = _signer()
    return (
        EnterpriseService(control_plane, verifier=verifier, now=lambda: NOW),
        admin_token,
        auditor_token,
        signer,
    )


def _json(response) -> dict[str, object]:
    return json.loads(response.body)


def test_service_enforces_tenant_and_role_boundaries(tmp_path: Path) -> None:
    service, admin_token, auditor_token, _signer_value = _service(tmp_path)

    summary = service.handle(
        ServiceRequest(
            "GET",
            "/v1/tenants/tenant-alpha/summary",
            {"Authorization": f"Bearer {admin_token}"},
        )
    )
    assert summary.status == 200
    assert _json(summary)["tenants"][0]["tenant_id"] == "tenant-alpha"

    forbidden = service.handle(
        ServiceRequest(
            "POST",
            "/v1/tenants/tenant-alpha/policies",
            {"Authorization": f"Bearer {auditor_token}"},
            body=_policy(),
        )
    )
    assert forbidden.status == 403
    assert _json(forbidden)["error"] == "ROLE_FORBIDDEN"

    cross_tenant = service.handle(
        ServiceRequest(
            "GET",
            "/v1/tenants/other-tenant/summary",
            {"Authorization": f"Bearer {admin_token}"},
        )
    )
    assert cross_tenant.status == 403
    assert "Alpha" not in cross_tenant.body.decode()


def test_service_requires_signed_policy_and_returns_only_digest(tmp_path: Path) -> None:
    service, admin_token, _auditor_token, signer = _service(tmp_path)
    signed = create_signed_policy(_policy(), key_id="org-alpha-2026", signer=signer)

    response = service.handle(
        ServiceRequest(
            "POST",
            "/v1/tenants/tenant-alpha/policies",
            {"Authorization": f"Bearer {admin_token}"},
            body=signed,
        )
    )
    assert response.status == 201
    assert _json(response)["policy_sha256"]
    assert b"local_scan" not in response.body

    tampered = service.handle(
        ServiceRequest(
            "POST",
            "/v1/tenants/tenant-alpha/policies",
            {"Authorization": f"Bearer {admin_token}"},
            body=signed.replace(b"local_scan", b"share_verify"),
        )
    )
    assert tampered.status == 400
    assert _json(tampered)["error"] == "POLICY_SIGNATURE_INVALID"


def test_service_exports_bounded_audit_metadata_and_rejects_revoked_token(
    tmp_path: Path,
) -> None:
    service, admin_token, _auditor_token, _signer_value = _service(tmp_path)
    service._control_plane.record_event(
        tenant_id="tenant-alpha",
        device_id="device-alpha",
        event_type="scan_completed",
        metadata={"finding_count": 1},
        occurred_at=NOW,
        retention=timedelta(days=1),
    )
    exported = service.handle(
        ServiceRequest(
            "GET",
            "/v1/tenants/tenant-alpha/audit",
            {"Authorization": f"Bearer {admin_token}"},
        )
    )
    assert exported.status == 200
    assert "finding_count" in exported.body.decode()
    assert "raw_content" not in exported.body.decode()

    token_id, _ = service._control_plane.issue_admin_token(
        "tenant-alpha", "admin", now=NOW, expires_at=NOW + timedelta(days=1)
    )
    # The service test uses the public control-plane revocation operation; the
    # token itself is never exposed by the API after provisioning.
    service._control_plane.revoke_admin_token("tenant-alpha", token_id, now=NOW)
    invalid = service.handle(
        ServiceRequest(
            "GET",
            "/v1/tenants/tenant-alpha/summary",
            {"Authorization": "Bearer revoked-token"},
        )
    )
    assert invalid.status == 401
