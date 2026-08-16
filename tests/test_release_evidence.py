from __future__ import annotations

import hashlib
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

import scripts.verify_windows_release_candidate as release_evidence
from scripts.verify_windows_release_candidate import (
    ReleaseEvidenceError,
    validate_release_candidate,
)


COMMIT = "a" * 40
PACKAGE_FULL_NAME = "yangjing6213dev.AgentGuardian_0.1.0.0_x64__publisher"
ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "release_profiles" / "personal_store_release.json"


def test_personal_release_gate_has_no_dynamic_mcp_evidence_input() -> None:
    signature = inspect.signature(validate_release_candidate)

    assert tuple(signature.parameters) == (
        "bundle_root",
        "smoke_evidence_path",
        "expected_source_commit",
        "require_trusted_signature",
        "require_fresh_user_state",
        "license_review_path",
    )


def _write_candidate(
    tmp_path: Path, *, trusted: bool = True, fresh: bool = True
) -> tuple[Path, Path, Path]:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "BUILD-METADATA.json").write_text(
        json.dumps({"artifact_status": "trusted_release", "source_commit": COMMIT}),
        encoding="utf-8",
    )
    profile_bytes = PROFILE_PATH.read_bytes() if PROFILE_PATH.is_file() else b"missing"
    profile_evidence = {
        "profile": "personal_store_release",
        "profile_sha256": hashlib.sha256(profile_bytes).hexdigest(),
        "schema": 1,
        "status": "pass",
    }
    (bundle / "PERSONAL-RELEASE-PROFILE.json").write_bytes(
        (
            json.dumps(
                profile_evidence,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii")
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
    return bundle, evidence, license_review


def test_release_gate_accepts_only_trusted_fresh_evidence(tmp_path: Path) -> None:
    bundle, evidence, license_review = _write_candidate(tmp_path)

    result = validate_release_candidate(
        bundle,
        evidence,
        expected_source_commit=COMMIT,
        require_trusted_signature=True,
        require_fresh_user_state=True,
        license_review_path=license_review,
    )

    assert result == {
        "passed": True,
        "source_commit": COMMIT,
        "signature_mode": "trusted_signed",
        "fresh_user_state": True,
        "license_review": "complete",
    }


def test_release_gate_reruns_repository_and_payload_profile_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle, evidence, license_review = _write_candidate(tmp_path)
    calls: list[str] = []
    monkeypatch.setattr(
        release_evidence,
        "verify_profile",
        lambda *args: calls.append("source"),
        raising=False,
    )
    monkeypatch.setattr(
        release_evidence,
        "load_profile",
        lambda *args: {"name": "personal_store_release"},
        raising=False,
    )
    monkeypatch.setattr(
        release_evidence,
        "verify_payload",
        lambda *args: calls.append("payload"),
        raising=False,
    )

    validate_release_candidate(
        bundle,
        evidence,
        expected_source_commit=COMMIT,
        require_trusted_signature=True,
        require_fresh_user_state=True,
        license_review_path=license_review,
    )

    assert calls == ["source", "payload"]


@pytest.mark.parametrize("mode", ("missing", "mismatch"))
def test_release_gate_rejects_missing_or_mismatched_profile_evidence(
    tmp_path: Path, mode: str
) -> None:
    bundle, evidence, license_review = _write_candidate(tmp_path)
    profile_evidence = bundle / "PERSONAL-RELEASE-PROFILE.json"
    if mode == "missing":
        profile_evidence.unlink()
    else:
        value = json.loads(profile_evidence.read_text(encoding="utf-8"))
        value["profile_sha256"] = "0" * 64
        profile_evidence.write_text(
            json.dumps(
                value,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="ascii",
        )

    with pytest.raises(
        ReleaseEvidenceError,
        match="^RELEASE_PERSONAL_PROFILE_(EVIDENCE_INVALID|MISMATCH)$",
    ):
        validate_release_candidate(
            bundle,
            evidence,
            expected_source_commit=COMMIT,
            require_trusted_signature=True,
            require_fresh_user_state=True,
            license_review_path=license_review,
        )


def test_release_gate_rejects_retired_payload_residue(tmp_path: Path) -> None:
    bundle, evidence, license_review = _write_candidate(tmp_path)
    (bundle / "McpAdapter-x64.exe").write_bytes(b"synthetic")

    with pytest.raises(ReleaseEvidenceError, match="^RELEASE_PERSONAL_PAYLOAD_INVALID$"):
        validate_release_candidate(
            bundle,
            evidence,
            expected_source_commit=COMMIT,
            require_trusted_signature=True,
            require_fresh_user_state=True,
            license_review_path=license_review,
        )


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
    assert "--" + "mcp-adapter-evidence" not in completed.stdout
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
    bundle, evidence, license_review = _write_candidate(
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
        )


def test_release_gate_rejects_unknown_license_and_source_mismatch(tmp_path: Path) -> None:
    bundle, evidence, license_review = _write_candidate(tmp_path)
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
        )


def test_release_gate_rejects_license_review_source_or_sbom_drift(tmp_path: Path) -> None:
    bundle, evidence, license_review = _write_candidate(tmp_path)
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
        )


def test_release_gate_rejects_reparse_components_in_evidence_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle, evidence, license_review = _write_candidate(tmp_path)
    monkeypatch.setattr(release_evidence, "_has_reparse_component", lambda _path: True)

    with pytest.raises(ReleaseEvidenceError, match="RELEASE_BUNDLE_INVALID"):
        validate_release_candidate(
            bundle,
            evidence,
            expected_source_commit=COMMIT,
            require_trusted_signature=True,
            require_fresh_user_state=True,
            license_review_path=license_review,
        )
