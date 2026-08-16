from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

import scripts.verify_windows_release_candidate as release_evidence
from agentguardian.file_integrity import FileSizeLimitExceeded
from scripts.verify_windows_release_candidate import (
    ReleaseEvidenceError,
    validate_release_candidate,
)


COMMIT = "a" * 40
ADAPTER_NAME = "AgentGuardianMcpAdapter.exe"
ADAPTER_RELATIVE_PATH = f"adapters/{ADAPTER_NAME}"
PUBLISHER_SUBJECT = "CN=AgentGuardian Adapter Publisher,O=AgentGuardian"
CERTIFICATE_SHA256 = "b" * 64
NATIVE_LIMITS = [
    "network_isolation_enforced",
    "process_tree_isolation_enforced",
]
PACKAGE_FULL_NAME = "yangjing6213dev.AgentGuardian_0.1.0.0_x64__publisher"
ROOT = Path(__file__).resolve().parents[1]


def _write_candidate(
    tmp_path: Path, *, trusted: bool = True, fresh: bool = True
) -> tuple[Path, Path, Path, Path]:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "BUILD-METADATA.json").write_text(
        json.dumps({"artifact_status": "trusted_release", "source_commit": COMMIT}),
        encoding="utf-8",
    )
    sbom_path = bundle / "AgentGuardian.cdx.json"
    sbom_path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "components": [
                    {"name": "PySide6", "version": "6.11.1", "licenses": [{"license": {"id": "LGPL-3.0-only"}}]}
                ],
            }
        ),
        encoding="utf-8",
    )
    (bundle / "THIRD_PARTY_NOTICES.md").write_text(
        "PySide6 6.11.1\nLGPL-3.0-only\n",
        encoding="utf-8",
    )
    adapter = bundle / "adapters" / ADAPTER_NAME
    adapter.parent.mkdir()
    adapter.write_bytes(b"synthetic packaged adapter")
    adapter_sha256 = hashlib.sha256(adapter.read_bytes()).hexdigest()
    (bundle / "MCP-ADAPTER.json").write_text(
        json.dumps(
            {
                "schema": 1,
                "path": ADAPTER_RELATIVE_PATH,
                "name": ADAPTER_NAME,
                "sha256": adapter_sha256,
                "publisher_subject": PUBLISHER_SUBJECT,
                "certificate_sha256": CERTIFICATE_SHA256,
            }
        ),
        encoding="utf-8",
    )
    license_review = tmp_path / "license-review.json"
    license_review.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "status": "approved",
                "source_commit": COMMIT,
                "sbom_sha256": hashlib.sha256(sbom_path.read_bytes()).hexdigest(),
                "reviewed_at": "2026-08-15T00:00:00Z",
                "reviewer": "synthetic-independent-reviewer",
                "components": [
                    {
                        "name": "PySide6",
                        "version": "6.11.1",
                        "license_expression": "LGPL-3.0-only",
                        "redistribution": "approved",
                        "evidence_url": "https://doc.qt.io/qt-6/qtlicenses.html",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    evidence = tmp_path / "smoke.json"
    evidence.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_commit": COMMIT,
                "package_full_name": PACKAGE_FULL_NAME,
                "signature_mode": "trusted_signed" if trusted else "unsigned_ci_smoke",
                "signature": {"status": "Valid" if trusted else "NotSigned"},
                "fresh_user_state": fresh,
                "result": {
                    "process_startup": True,
                    "bounded_liveness": True,
                    "termination": True,
                    "uninstalled": True,
                    "package_residue": False,
                    "app_data_residue": False,
                },
            }
        ),
        encoding="utf-8",
    )
    mcp_evidence = tmp_path / "mcp-acceptance.json"
    mcp_evidence.write_text(
        json.dumps(
            {
                "schema": 1,
                "source_commit": COMMIT,
                "adapter": {
                    "name": ADAPTER_NAME,
                    "package_full_name": PACKAGE_FULL_NAME,
                    "sha256": adapter_sha256,
                    "publisher_subject": PUBLISHER_SUBJECT,
                    "certificate_sha256": CERTIFICATE_SHA256,
                },
                "sandbox": {
                    "status": "completed",
                    "reason": "completed",
                    "response_bytes": 17,
                    "raw_response_retained": False,
                    "limits": NATIVE_LIMITS,
                },
                "passed": True,
            }
        ),
        encoding="utf-8",
    )
    return bundle, evidence, license_review, mcp_evidence


def test_release_gate_accepts_only_trusted_fresh_evidence(tmp_path: Path) -> None:
    bundle, evidence, license_review, mcp_evidence = _write_candidate(tmp_path)

    result = validate_release_candidate(
        bundle,
        evidence,
        expected_source_commit=COMMIT,
        require_trusted_signature=True,
        require_fresh_user_state=True,
        license_review_path=license_review,
        mcp_adapter_evidence_path=mcp_evidence,
    )

    assert result == {
        "passed": True,
        "source_commit": COMMIT,
        "signature_mode": "trusted_signed",
        "fresh_user_state": True,
        "license_review": "complete",
    }


def test_release_verifier_cli_help_runs_without_pythonpath(tmp_path: Path) -> None:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment["PYTHONNOUSERSITE"] = "1"

    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            str(ROOT / "scripts" / "verify_windows_release_candidate.py"),
            "--help",
        ],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert "--mcp-adapter-evidence" in completed.stdout
    assert completed.stderr == ""


@pytest.mark.parametrize(
    "trusted,fresh,expected",
    [(False, True, "RELEASE_TRUSTED_SIGNATURE_REQUIRED"), (True, False, "RELEASE_FRESH_USER_STATE_REQUIRED")],
)
def test_release_gate_rejects_unsigned_or_nonfresh_evidence(
    tmp_path: Path,
    trusted: bool,
    fresh: bool,
    expected: str,
) -> None:
    bundle, evidence, license_review, mcp_evidence = _write_candidate(
        tmp_path, trusted=trusted, fresh=fresh
    )

    with pytest.raises(ReleaseEvidenceError, match=expected):
        validate_release_candidate(
            bundle,
            evidence,
            expected_source_commit=COMMIT,
            require_trusted_signature=True,
            require_fresh_user_state=True,
            license_review_path=license_review,
            mcp_adapter_evidence_path=mcp_evidence,
        )


def test_release_gate_rejects_unknown_license_and_source_mismatch(tmp_path: Path) -> None:
    bundle, evidence, license_review, mcp_evidence = _write_candidate(tmp_path)
    (bundle / "AgentGuardian.cdx.json").write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "components": [
                    {"name": "Unknown", "version": "1", "licenses": [{"license": {"name": "NOASSERTION"}}]}
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ReleaseEvidenceError, match="RELEASE_LICENSE_REVIEW_REQUIRED"):
        validate_release_candidate(
            bundle,
            evidence,
            expected_source_commit=COMMIT,
            require_trusted_signature=True,
            require_fresh_user_state=True,
            license_review_path=license_review,
            mcp_adapter_evidence_path=mcp_evidence,
        )

    (bundle / "AgentGuardian.cdx.json").write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "components": [
                    {"name": "PySide6", "version": "6.11.1", "licenses": [{"license": {"id": "LGPL-3.0-only"}}]}
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ReleaseEvidenceError, match="RELEASE_SOURCE_COMMIT_MISMATCH"):
        validate_release_candidate(
            bundle,
            evidence,
            expected_source_commit="b" * 40,
            require_trusted_signature=True,
            require_fresh_user_state=True,
            license_review_path=license_review,
            mcp_adapter_evidence_path=mcp_evidence,
        )


def test_release_gate_rejects_license_review_source_or_sbom_drift(tmp_path: Path) -> None:
    bundle, evidence, license_review, mcp_evidence = _write_candidate(tmp_path)
    review = json.loads(license_review.read_text(encoding="utf-8"))
    review["sbom_sha256"] = "0" * 64
    license_review.write_text(json.dumps(review), encoding="utf-8")

    with pytest.raises(ReleaseEvidenceError, match="RELEASE_LICENSE_REVIEW_REQUIRED"):
        validate_release_candidate(
            bundle,
            evidence,
            expected_source_commit=COMMIT,
            require_trusted_signature=True,
            require_fresh_user_state=True,
            license_review_path=license_review,
            mcp_adapter_evidence_path=mcp_evidence,
        )


def test_release_gate_rejects_reparse_components_in_evidence_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle, evidence, license_review, mcp_evidence = _write_candidate(tmp_path)
    monkeypatch.setattr(release_evidence, "_has_reparse_component", lambda _path: True)

    with pytest.raises(ReleaseEvidenceError, match="RELEASE_BUNDLE_INVALID"):
        validate_release_candidate(
            bundle,
            evidence,
            expected_source_commit=COMMIT,
            require_trusted_signature=True,
            require_fresh_user_state=True,
            license_review_path=license_review,
            mcp_adapter_evidence_path=mcp_evidence,
        )


def _validate_trusted_candidate(
    bundle: Path,
    evidence: Path,
    license_review: Path,
    mcp_evidence: Path,
) -> dict[str, object]:
    return validate_release_candidate(
        bundle,
        evidence,
        expected_source_commit=COMMIT,
        require_trusted_signature=True,
        require_fresh_user_state=True,
        license_review_path=license_review,
        mcp_adapter_evidence_path=mcp_evidence,
    )


def test_release_gate_rejects_absent_mcp_acceptance_evidence(tmp_path: Path) -> None:
    bundle, evidence, license_review, mcp_evidence = _write_candidate(tmp_path)
    mcp_evidence.unlink()

    with pytest.raises(ReleaseEvidenceError, match="RELEASE_MCP_ADAPTER_EVIDENCE_INVALID"):
        _validate_trusted_candidate(bundle, evidence, license_review, mcp_evidence)


def test_release_gate_rejects_mcp_source_mismatch(tmp_path: Path) -> None:
    bundle, evidence, license_review, mcp_evidence = _write_candidate(tmp_path)
    acceptance = json.loads(mcp_evidence.read_text(encoding="utf-8"))
    acceptance["source_commit"] = "c" * 40
    mcp_evidence.write_text(json.dumps(acceptance), encoding="utf-8")

    with pytest.raises(ReleaseEvidenceError, match="RELEASE_MCP_SOURCE_COMMIT_MISMATCH"):
        _validate_trusted_candidate(bundle, evidence, license_review, mcp_evidence)


def test_release_gate_rejects_boolean_mcp_manifest_schema(tmp_path: Path) -> None:
    bundle, evidence, license_review, mcp_evidence = _write_candidate(tmp_path)
    manifest_path = bundle / "MCP-ADAPTER.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["schema"] = True
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ReleaseEvidenceError, match="RELEASE_MCP_ADAPTER_MANIFEST_INVALID"):
        _validate_trusted_candidate(bundle, evidence, license_review, mcp_evidence)


def test_release_gate_rejects_boolean_mcp_acceptance_schema(tmp_path: Path) -> None:
    bundle, evidence, license_review, mcp_evidence = _write_candidate(tmp_path)
    acceptance = json.loads(mcp_evidence.read_text(encoding="utf-8"))
    acceptance["schema"] = True
    mcp_evidence.write_text(json.dumps(acceptance), encoding="utf-8")

    with pytest.raises(ReleaseEvidenceError, match="RELEASE_MCP_ADAPTER_EVIDENCE_INVALID"):
        _validate_trusted_candidate(bundle, evidence, license_review, mcp_evidence)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("name", "OtherAdapter.exe"),
        ("package_full_name", "OtherPackage_0.1.0.0_x64__publisher"),
        ("sha256", "0" * 64),
        ("publisher_subject", "CN=Other Publisher"),
        ("certificate_sha256", "0" * 64),
    ),
)
def test_release_gate_rejects_mcp_adapter_metadata_mismatch(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    bundle, evidence, license_review, mcp_evidence = _write_candidate(tmp_path)
    acceptance = json.loads(mcp_evidence.read_text(encoding="utf-8"))
    acceptance["adapter"][field] = value
    mcp_evidence.write_text(json.dumps(acceptance), encoding="utf-8")

    with pytest.raises(ReleaseEvidenceError, match="RELEASE_MCP_ADAPTER_METADATA_MISMATCH"):
        _validate_trusted_candidate(bundle, evidence, license_review, mcp_evidence)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("status", "failed"),
        ("reason", "adapter_failed"),
        ("response_bytes", 0),
        ("response_bytes", 65_537),
        ("raw_response_retained", True),
        ("limits", ["network_isolation_enforced"]),
        ("limits", ["process_tree_isolation_enforced"]),
        ("limits", NATIVE_LIMITS + ["unexpected_limit"]),
    ),
)
def test_release_gate_rejects_unbounded_mcp_sandbox_evidence(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    bundle, evidence, license_review, mcp_evidence = _write_candidate(tmp_path)
    acceptance = json.loads(mcp_evidence.read_text(encoding="utf-8"))
    acceptance["sandbox"][field] = value
    mcp_evidence.write_text(json.dumps(acceptance), encoding="utf-8")

    with pytest.raises(ReleaseEvidenceError, match="RELEASE_MCP_SANDBOX_FAILED"):
        _validate_trusted_candidate(bundle, evidence, license_review, mcp_evidence)


def test_release_gate_rejects_mcp_manifest_shape_or_fixed_path_drift(tmp_path: Path) -> None:
    bundle, evidence, license_review, mcp_evidence = _write_candidate(tmp_path)
    manifest_path = bundle / "MCP-ADAPTER.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["unexpected"] = True
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ReleaseEvidenceError, match="RELEASE_MCP_ADAPTER_MANIFEST_INVALID"):
        _validate_trusted_candidate(bundle, evidence, license_review, mcp_evidence)


def test_release_gate_rejects_actual_bundled_adapter_tampering(tmp_path: Path) -> None:
    bundle, evidence, license_review, mcp_evidence = _write_candidate(tmp_path)
    (bundle / "adapters" / ADAPTER_NAME).write_bytes(b"tampered adapter bytes")

    with pytest.raises(ReleaseEvidenceError, match="RELEASE_MCP_ADAPTER_HASH_MISMATCH"):
        _validate_trusted_candidate(bundle, evidence, license_review, mcp_evidence)


def test_release_gate_rejects_an_oversize_bundled_adapter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle, evidence, license_review, mcp_evidence = _write_candidate(tmp_path)
    monkeypatch.setattr(
        release_evidence,
        "bounded_file_sha256",
        lambda _path: (_ for _ in ()).throw(FileSizeLimitExceeded()),
    )

    with pytest.raises(ReleaseEvidenceError, match="RELEASE_MCP_ADAPTER_SIZE_LIMIT"):
        _validate_trusted_candidate(bundle, evidence, license_review, mcp_evidence)


@pytest.mark.parametrize("state", ("missing", "non_regular", "reparse"))
def test_release_gate_rejects_unsafe_or_missing_bundled_adapter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    state: str,
) -> None:
    bundle, evidence, license_review, mcp_evidence = _write_candidate(tmp_path)
    adapter = bundle / "adapters" / ADAPTER_NAME
    if state == "missing":
        adapter.unlink()
    elif state == "non_regular":
        adapter.unlink()
        adapter.mkdir()
    else:
        original = release_evidence._has_reparse_component
        monkeypatch.setattr(
            release_evidence,
            "_has_reparse_component",
            lambda path: path == adapter or original(path),
        )

    with pytest.raises(ReleaseEvidenceError, match="RELEASE_MCP_ADAPTER_FILE_INVALID"):
        _validate_trusted_candidate(bundle, evidence, license_review, mcp_evidence)
