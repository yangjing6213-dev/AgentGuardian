from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from agentguardian.enterprise_control_plane import EnterpriseControlPlane
from agentguardian.enterprise_signing import (
    Ed25519PolicySigner,
    Ed25519PolicyVerifier,
    create_signed_policy,
    verify_signed_policy,
)


NOW = datetime(2026, 8, 15, 12, 0, tzinfo=timezone.utc)


def _document() -> bytes:
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
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat

    private = Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_bytes = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return Ed25519PolicySigner(private_bytes), Ed25519PolicyVerifier(public_bytes)


def test_signed_policy_round_trip_and_tamper_rejection() -> None:
    signer, verifier = _signer()
    envelope = create_signed_policy(_document(), key_id="org-alpha-2026", signer=signer)

    assert verify_signed_policy(envelope, verifier) == _document()
    tampered = envelope.replace(b"local_scan", b"share_verify")
    with pytest.raises(ValueError, match="POLICY_SIGNATURE_INVALID"):
        verify_signed_policy(tampered, verifier)


def test_signed_policy_rejects_wrong_key_and_duplicate_fields() -> None:
    signer, _verifier = _signer()
    _other_signer, other_verifier = _signer()
    envelope = create_signed_policy(_document(), key_id="org-alpha-2026", signer=signer)

    with pytest.raises(ValueError, match="POLICY_SIGNATURE_INVALID"):
        verify_signed_policy(envelope, other_verifier)
    duplicate = envelope.replace(b'"schema":1', b'"schema":1,"schema":1', 1)
    with pytest.raises(ValueError, match="POLICY_SIGNED_DOCUMENT_INVALID"):
        verify_signed_policy(duplicate, other_verifier)


def test_control_plane_provisions_only_verified_signed_policy(tmp_path: Path) -> None:
    signer, verifier = _signer()
    control_plane = EnterpriseControlPlane(tmp_path / "control-plane.sqlite3")
    control_plane.register_tenant("tenant-alpha", "Alpha", now=NOW)
    control_plane.register_device("tenant-alpha", "device-alpha", now=NOW)

    envelope = create_signed_policy(_document(), key_id="org-alpha-2026", signer=signer)
    digest = control_plane.provision_signed_policy(envelope, verifier=verifier, now=NOW)
    assert digest
    assert control_plane.list_policy_summaries("tenant-alpha")[0].policy_sha256 == digest
