from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

from scripts.verify_windows_installer_lifecycle_evidence import (
    canonical_json_bytes,
    verify_lifecycle_evidence,
)


BASE_VERSION = "0.1.9"
CANDIDATE_VERSION = "0.2.0-beta.1"
SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "verify_windows_installer_lifecycle_evidence.py"
)


def _pass_evidence() -> dict[str, object]:
    return {
        "base_install": "pass",
        "base_version": BASE_VERSION,
        "candidate_version": CANDIDATE_VERSION,
        "deleted_state": "pass",
        "downgrade_rejected": "pass",
        "launch_smoke": "pass",
        "no_system_integration": "pass",
        "retained_state": "pass",
        "schema": 1,
        "start_menu": "pass",
        "status": "pass",
        "uninstall_residue": "pass",
        "upgrade": "pass",
        "user_report_preserved": "pass",
    }


def _write(path: Path, value: object) -> None:
    path.write_bytes(canonical_json_bytes(value))


def test_lifecycle_evidence_accepts_exact_pass_and_fail_schemas(tmp_path: Path) -> None:
    evidence = (tmp_path / "lifecycle.json").absolute()
    _write(evidence, _pass_evidence())
    assert verify_lifecycle_evidence(
        evidence, 0, base_version=BASE_VERSION, candidate_version=CANDIDATE_VERSION
    ) == {"error": "", "status": "pass"}

    evidence.unlink()
    _write(evidence, {"error": "BASE_INSTALL_FAILED", "schema": 1, "status": "fail"})
    assert verify_lifecycle_evidence(
        evidence, 1, base_version=BASE_VERSION, candidate_version=CANDIDATE_VERSION
    ) == {"error": "BASE_INSTALL_FAILED", "status": "fail"}


def test_lifecycle_evidence_maps_missing_and_invalid_inputs_to_fixed_codes(
    tmp_path: Path,
) -> None:
    evidence = (tmp_path / "lifecycle.json").absolute()
    assert verify_lifecycle_evidence(
        evidence, 1, base_version=BASE_VERSION, candidate_version=CANDIDATE_VERSION
    ) == {"error": "LIFECYCLE_EVIDENCE_MISSING", "status": "fail"}

    for contents in (
        b"{invalid}\n",
        b'\xef\xbb\xbf{"error":"X","schema":1,"status":"fail"}\n',
        b'{"error":"X","error":"Y","schema":1,"status":"fail"}\n',
        b"x" * 4097,
    ):
        evidence.write_bytes(contents)
        assert verify_lifecycle_evidence(
            evidence,
            1,
            base_version=BASE_VERSION,
            candidate_version=CANDIDATE_VERSION,
        ) == {"error": "LIFECYCLE_EVIDENCE_INVALID", "status": "fail"}


def test_lifecycle_evidence_rejects_overlong_codes_and_exit_schema_mismatch(
    tmp_path: Path,
) -> None:
    evidence = (tmp_path / "lifecycle.json").absolute()
    _write(evidence, {"error": "A" * 65, "schema": 1, "status": "fail"})
    assert verify_lifecycle_evidence(
        evidence, 1, base_version=BASE_VERSION, candidate_version=CANDIDATE_VERSION
    ) == {"error": "LIFECYCLE_EVIDENCE_INVALID", "status": "fail"}

    _write(evidence, _pass_evidence())
    assert verify_lifecycle_evidence(
        evidence, 1, base_version=BASE_VERSION, candidate_version=CANDIDATE_VERSION
    ) == {"error": "LIFECYCLE_EVIDENCE_INVALID", "status": "fail"}

    _write(evidence, {"error": "BASE_INSTALL_FAILED", "schema": 1, "status": "fail"})
    assert verify_lifecycle_evidence(
        evidence, 0, base_version=BASE_VERSION, candidate_version=CANDIDATE_VERSION
    ) == {"error": "LIFECYCLE_EVIDENCE_INVALID", "status": "fail"}


def test_lifecycle_evidence_requires_canonical_exact_pass_values(tmp_path: Path) -> None:
    evidence = (tmp_path / "lifecycle.json").absolute()
    changed = _pass_evidence()
    changed["upgrade"] = "pending"
    _write(evidence, changed)
    assert verify_lifecycle_evidence(
        evidence, 0, base_version=BASE_VERSION, candidate_version=CANDIDATE_VERSION
    ) == {"error": "LIFECYCLE_EVIDENCE_INVALID", "status": "fail"}


def test_lifecycle_evidence_cli_emits_only_canonical_decision(tmp_path: Path) -> None:
    evidence = (tmp_path / "lifecycle.json").absolute()
    _write(evidence, {"error": "BASE_INSTALL_FAILED", "schema": 1, "status": "fail"})
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT_PATH),
            "--evidence-path",
            str(evidence),
            "--lifecycle-exit-code",
            "1",
            "--base-version",
            BASE_VERSION,
            "--candidate-version",
            CANDIDATE_VERSION,
        ],
        check=False,
        capture_output=True,
    )
    assert result.returncode == 0
    assert result.stdout == canonical_json_bytes(
        {"error": "BASE_INSTALL_FAILED", "status": "fail"}
    )
    assert result.stderr == b""

    evidence.write_text(json.dumps(_pass_evidence(), indent=2), encoding="utf-8")
    assert verify_lifecycle_evidence(
        evidence, 0, base_version=BASE_VERSION, candidate_version=CANDIDATE_VERSION
    ) == {"error": "LIFECYCLE_EVIDENCE_INVALID", "status": "fail"}
