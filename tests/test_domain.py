from dataclasses import FrozenInstanceError

import pytest

from agentguardian.domain import (
    Asset,
    Evidence,
    Finding,
    RemediationMode,
    RemediationPlan,
    RiskDomain,
    Score,
    Severity,
    VerificationResult,
    VerificationStatus,
)


def test_evidence_rejects_unmasked_secret() -> None:
    with pytest.raises(ValueError, match="masked"):
        Evidence(
            source="a.txt",
            fingerprint="a" * 64,
            masked="sk-" + "live-" + "secret",
        )


def test_evidence_rejects_unmasked_api_key() -> None:
    with pytest.raises(ValueError, match="masked"):
        Evidence(
            source="a.txt",
            fingerprint="a" * 64,
            masked="sk-" + "proj-" + "abcdefghijklmnopqrstuvwxyz",
        )


@pytest.mark.parametrize(
    "raw_value",
    (
        "ghp_" + "a" * 32,
        "xoxb-" + "1234567890" + "-" + "a" * 16,
        "AIza" + "a" * 35,
        "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
        "Bearer ya29.a0AfH6SMB1234567890abcdefghijklmnop",
        "sk_" + "live_" + "a" * 26,
        "https://example.invalid/share/secret",
        "postgresql://user:password@example.invalid/db",
        "abandon ability able about above absent absorb abstract absurd abuse access accident",
    ),
)
def test_evidence_rejects_common_raw_credentials(raw_value: str) -> None:
    with pytest.raises(ValueError, match="masked"):
        Evidence(source="a.txt", fingerprint="a" * 64, masked=raw_value)


def test_evidence_rejects_full_source_path() -> None:
    with pytest.raises(ValueError, match="source"):
        Evidence(
            source=r"C:\Users\Alice\secret.txt",
            fingerprint="a" * 64,
            masked="sk-p**********************wxyz",
        )


def test_evidence_rejects_path_in_masked_value() -> None:
    with pytest.raises(ValueError, match="masked"):
        Evidence(
            source="secret.txt",
            fingerprint="a" * 64,
            masked=r"C:\Users\Alice\secret.txt",
        )


@pytest.mark.parametrize(
    "raw_path",
    (
        r"path=C:\Users\Alice\secret.txt",
        r'"\\server\share\secret.txt"',
        "D:/Users/Alice/secret.txt",
        "path=/opt/project/secret.txt",
        "/secret.txt",
    ),
)
def test_evidence_rejects_embedded_paths_in_masked_value(raw_path: str) -> None:
    with pytest.raises(ValueError, match="masked"):
        Evidence(source="secret.txt", fingerprint="a" * 64, masked=raw_path)


def test_evidence_rejects_non_hmac_fingerprint() -> None:
    with pytest.raises(ValueError, match="fingerprint"):
        Evidence(source="a.txt", fingerprint=r"C:\Users\Alice", masked="s********t")


def test_finding_keeps_domain_and_severity() -> None:
    finding = Finding("R-1", RiskDomain.CREDENTIALS, Severity.HIGH, "b" * 64, ())

    assert finding.domain is RiskDomain.CREDENTIALS
    assert finding.severity is Severity.HIGH


def test_shared_alpha_contracts_are_immutable_and_manual_only() -> None:
    asset = Asset("c" * 64, "mcp_config", "mcp.json")
    result = Score(100, (), None, 1.0, 1.0, (), False)
    plan = RemediationPlan(
        "R-1",
        asset.asset_id,
        RemediationMode.MANUAL,
        ("Review the configuration.",),
        ("Run a new read-only audit.",),
    )
    verification = VerificationResult(VerificationStatus.NOT_PERFORMED, ())

    assert plan.mode == "manual"
    assert verification.status == "not_performed"
    with pytest.raises(FrozenInstanceError):
        result.total = 99  # type: ignore[misc]


def test_shared_contracts_reject_mutable_sequences() -> None:
    with pytest.raises(TypeError, match="evidence"):
        Finding(
            "R-1",
            RiskDomain.CREDENTIALS,
            Severity.HIGH,
            "b" * 64,
            [],  # type: ignore[arg-type]
        )
    with pytest.raises(TypeError, match="limits"):
        Score(100, (), None, 1.0, 1.0, [], False)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="steps"):
        RemediationPlan(
            "R-1",
            "c" * 64,
            RemediationMode.MANUAL,
            [],  # type: ignore[arg-type]
            (),
        )
    with pytest.raises(TypeError, match="notes"):
        VerificationResult(
            VerificationStatus.NOT_PERFORMED,
            [],  # type: ignore[arg-type]
        )


def test_asset_and_remediation_reject_non_opaque_references() -> None:
    with pytest.raises(ValueError, match="asset_id"):
        Asset("asset-1", "mcp_config", "mcp.json")
    with pytest.raises(ValueError, match="asset_ref"):
        RemediationPlan(
            "R-1",
            r"C:\Users\Alice\mcp.json",
            RemediationMode.MANUAL,
            ("Review the configuration.",),
            (),
        )
