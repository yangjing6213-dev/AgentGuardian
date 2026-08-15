from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.verify_windows_release_candidate import (
    ReleaseEvidenceError,
    validate_release_candidate,
)


COMMIT = "a" * 40


def _write_candidate(tmp_path: Path, *, trusted: bool = True, fresh: bool = True) -> tuple[Path, Path]:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "BUILD-METADATA.json").write_text(
        json.dumps({"artifact_status": "trusted_release", "source_commit": COMMIT}),
        encoding="utf-8",
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
    (bundle / "THIRD_PARTY_NOTICES.md").write_text(
        "PySide6 6.11.1\nLGPL-3.0-only\n",
        encoding="utf-8",
    )
    evidence = tmp_path / "smoke.json"
    evidence.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_commit": COMMIT,
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
    return bundle, evidence


def test_release_gate_accepts_only_trusted_fresh_evidence(tmp_path: Path) -> None:
    bundle, evidence = _write_candidate(tmp_path)

    result = validate_release_candidate(
        bundle,
        evidence,
        expected_source_commit=COMMIT,
        require_trusted_signature=True,
        require_fresh_user_state=True,
    )

    assert result == {
        "passed": True,
        "source_commit": COMMIT,
        "signature_mode": "trusted_signed",
        "fresh_user_state": True,
        "license_review": "complete",
    }


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
    bundle, evidence = _write_candidate(tmp_path, trusted=trusted, fresh=fresh)

    with pytest.raises(ReleaseEvidenceError, match=expected):
        validate_release_candidate(
            bundle,
            evidence,
            expected_source_commit=COMMIT,
            require_trusted_signature=True,
            require_fresh_user_state=True,
        )


def test_release_gate_rejects_unknown_license_and_source_mismatch(tmp_path: Path) -> None:
    bundle, evidence = _write_candidate(tmp_path)
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
        )
