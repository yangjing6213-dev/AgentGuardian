from __future__ import annotations

import hashlib
import importlib
import json
import os
from pathlib import Path
import zipfile

import pytest


ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40
PACKAGE_IDENTITY = "yangjing6213dev.AgentGuardian"


def _wack():
    try:
        return importlib.import_module("scripts.verify_wack_report")
    except ModuleNotFoundError:
        pytest.fail("WACK report verifier is missing")


def _write_report(root: Path, body: str) -> Path:
    report = root / "wack-report.xml"
    report.write_text(body, encoding="utf-8")
    return report


def test_store_candidate_workflow_is_manual_exact_sha_and_non_publishing() -> None:
    path = ROOT / ".github" / "workflows" / "windows-store-candidate.yml"
    assert path.is_file(), "Store candidate workflow is missing"
    workflow = path.read_text(encoding="utf-8")
    folded = workflow.casefold()

    assert "workflow_dispatch:" in workflow
    assert "push:" not in workflow
    assert "pull_request:" not in workflow
    assert "permissions:\n  contents: read" in workflow
    for name in (
        "expected_source_commit",
        "store_identity_name",
        "store_publisher",
        "store_version",
        "wack_tool_path",
    ):
        assert name in workflow
        assert f"{name}:\n        required: true" in workflow
    assert "^[0-9a-f]{40}$" in workflow
    assert "ref: ${{ inputs.expected_source_commit }}" in workflow
    assert "git rev-parse HEAD" in workflow
    assert "git status --porcelain=v1 --untracked-files=all" in workflow

    for forbidden in (
        "gh release",
        "/releases",
        "partnercenter",
        "partner center",
        "actions/deploy",
        "pfx",
        "password",
        "timestamp",
        "mcp_adapter",
    ):
        assert forbidden not in folded


def test_store_candidate_workflow_runs_bounded_reproducible_evidence_gates() -> None:
    workflow = (
        ROOT / ".github" / "workflows" / "windows-store-candidate.yml"
    ).read_text(encoding="utf-8")

    for required in (
        "requirements-dev.lock",
        "requirements-build.lock",
        "--require-hashes",
        "python -m pytest -q -p no:cacheprovider",
        "run_personal_privacy_acceptance.py",
        "check_brand_assets.py",
        "python -m compileall -q src scripts tests",
        "platform.machine()",
        "x64 build runner is required",
        "personal_store_release",
        "verify_personal_release_profile.py",
        "build_windows_portable.py",
        "build_windows_msix.py",
        "--msixupload-package",
        "verify_wack_report.py",
        "Windows App Certification Kit",
        "appcert.exe reset",
        "-appxpackagepath",
        "-reportoutputpath",
        "actions/upload-artifact@",
        "retention-days: 14",
        "if: always()",
    ):
        assert required in workflow
    assert workflow.count("build_windows_portable.py") == 2
    assert workflow.count("if: always()") == 2
    assert "SequenceEqual[byte]" in workflow
    assert "$zipsA.Count -ne 1" in workflow
    assert "$zipsB.Count -ne 1" in workflow
    assert "Select-Object -Single" not in workflow
    assert "Get-FileHash" in workflow
    assert "active user session" in workflow
    assert "CI capability is not verified" in workflow
    assert "name: agentguardian-store-candidate-${{ inputs.expected_source_commit }}" in workflow
    assert "--artifact-status store_submission_candidate" in workflow
    assert "--wack-evidence" in workflow
    assert "Store candidate must not pass the formal release gate" in workflow
    assert "exit $LASTEXITCODE" in workflow

    upload_paths = workflow.split("path: |", 1)[1]
    assert "wack-report.xml" not in upload_paths
    assert ".msix\n" not in upload_paths
    assert upload_paths.count(".analysis/store-evidence/") == 10


def test_msixupload_is_a_deterministic_zip_containing_only_the_msix(
    tmp_path: Path,
) -> None:
    from scripts.build_windows_msix import deterministic_msixupload

    package = tmp_path / "AgentGuardian.msix"
    package.write_bytes(b"synthetic msix")
    first = tmp_path / "first.msixupload"
    second = tmp_path / "second.msixupload"

    deterministic_msixupload(package, first)
    os.utime(package, (2_000_000_000, 2_000_000_000))
    deterministic_msixupload(package, second)

    assert first.read_bytes() == second.read_bytes()
    assert hashlib.sha256(first.read_bytes()).hexdigest() == hashlib.sha256(
        second.read_bytes()
    ).hexdigest()
    with zipfile.ZipFile(first) as archive:
        assert archive.namelist() == ["AgentGuardian.msix"]
        assert archive.read("AgentGuardian.msix") == b"synthetic msix"


def test_wack_tool_path_is_confined_to_official_windows_kits_location(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wack = _wack()
    program_files = tmp_path / "Program Files (x86)"
    tool = (
        program_files
        / "Windows Kits"
        / "10"
        / "App Certification Kit"
        / "appcert.exe"
    )
    tool.parent.mkdir(parents=True)
    tool.write_bytes(b"synthetic")
    monkeypatch.setenv("ProgramFiles(x86)", str(program_files))

    assert wack.validate_wack_tool_path(tool) == tool.resolve()
    for rejected in (
        program_files / "Windows Kits" / "10" / "bin" / "appcert.exe",
        program_files / "Windows Kits" / "10" / "App Certification Kit" / "cmd.exe",
        tmp_path / "appcert.exe",
    ):
        rejected.parent.mkdir(parents=True, exist_ok=True)
        rejected.write_bytes(b"synthetic")
        with pytest.raises(wack.WackEvidenceError, match="^WACK_TOOL_PATH_INVALID$"):
            wack.validate_wack_tool_path(rejected)


def test_wack_commands_match_microsoft_contract(tmp_path: Path) -> None:
    wack = _wack()
    tool = tmp_path / "appcert.exe"
    package = tmp_path / "AgentGuardian.msix"
    report = tmp_path / "evidence" / "wack-report.xml"

    reset, test = wack.wack_commands(tool, package, report)

    assert reset == (str(tool), "reset")
    assert test == (
        str(tool),
        "test",
        "-appxpackagepath",
        str(package),
        "-reportoutputpath",
        str(report),
    )


def test_wack_report_emits_canonical_bound_summary(tmp_path: Path) -> None:
    wack = _wack()
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    report = _write_report(
        evidence_root,
        f'''<?xml version="1.0" encoding="utf-8"?>
<REPORT OVERALL_RESULT="PASS" PARTIAL_RUN="FALSE" TOOL_VERSION="10.0.26100.0">
  <PACKAGE IDENTITY_NAME="{PACKAGE_IDENTITY}" />
  <REQUIREMENT RESULT="PASS" />
  <TEST RESULT="PASS" />
  <TEST RESULT="PASS" />
</REPORT>
''',
    )

    result = wack.verify_wack_report(
        report,
        evidence_root,
        source_commit=COMMIT,
        expected_package_identity=PACKAGE_IDENTITY,
        generated_at="2026-08-17T00:00:00Z",
    )

    assert result == {
        "generated_at": "2026-08-17T00:00:00Z",
        "overall_result": "PASS",
        "package_identity": PACKAGE_IDENTITY,
        "report_sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
        "schema": 1,
        "source_commit": COMMIT,
        "test_counts": {
            "failed": 0,
            "passed": 3,
            "requirements": 1,
            "tests": 2,
            "total": 3,
        },
        "tool_version": "10.0.26100.0",
    }
    assert wack.canonical_json_bytes(result) == (
        json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")
    with pytest.raises(wack.WackEvidenceError, match="^WACK_PACKAGE_IDENTITY_MISMATCH$"):
        wack.verify_wack_report(
            report,
            evidence_root,
            source_commit=COMMIT,
            expected_package_identity="different.identity",
            generated_at="2026-08-17T00:00:00Z",
        )


@pytest.mark.parametrize(
    "mutation,code",
    (
        (lambda text: text.replace('OVERALL_RESULT="PASS"', 'OVERALL_RESULT="FAIL"'), "WACK_RESULT_FAILED"),
        (lambda text: text.replace('PARTIAL_RUN="FALSE"', 'PARTIAL_RUN="TRUE"'), "WACK_PARTIAL_RUN"),
        (lambda text: text.replace('<TEST RESULT="PASS" />', '<TEST RESULT="FAIL" />', 1), "WACK_RESULT_FAILED"),
        (lambda text: text.replace(f'IDENTITY_NAME="{PACKAGE_IDENTITY}"', 'UNKNOWN="value"'), "WACK_PACKAGE_IDENTITY_UNSUPPORTED"),
        (lambda text: text.replace("<REPORT", "<!DOCTYPE REPORT [<!ENTITY xxe SYSTEM 'file:///secret'>]><REPORT"), "WACK_XML_DTD_FORBIDDEN"),
    ),
)
def test_wack_report_fails_closed_on_unsafe_or_incomplete_evidence(
    tmp_path: Path, mutation, code: str
) -> None:
    wack = _wack()
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    base = f'''<REPORT OVERALL_RESULT="PASS" PARTIAL_RUN="FALSE" TOOL_VERSION="10">
  <PACKAGE IDENTITY_NAME="{PACKAGE_IDENTITY}" />
  <REQUIREMENT RESULT="PASS" />
  <TEST RESULT="PASS" />
</REPORT>
'''
    report = _write_report(evidence_root, mutation(base))

    with pytest.raises(wack.WackEvidenceError, match=f"^{code}$"):
        wack.verify_wack_report(
            report,
            evidence_root,
            source_commit=COMMIT,
            expected_package_identity=PACKAGE_IDENTITY,
            generated_at="2026-08-17T00:00:00Z",
        )


def test_wack_report_requires_absolute_in_root_regular_non_reparse_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wack = _wack()
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    report = _write_report(
        evidence_root,
        f'<REPORT OVERALL_RESULT="PASS" PARTIAL_RUN="FALSE" TOOL_VERSION="10"><PACKAGE IDENTITY_NAME="{PACKAGE_IDENTITY}" /></REPORT>',
    )

    with pytest.raises(wack.WackEvidenceError, match="^WACK_REPORT_PATH_INVALID$"):
        wack.verify_wack_report(
            report.relative_to(tmp_path),
            evidence_root,
            source_commit=COMMIT,
            expected_package_identity=PACKAGE_IDENTITY,
            generated_at="2026-08-17T00:00:00Z",
        )
    outside = tmp_path / "outside.xml"
    outside.write_bytes(report.read_bytes())
    with pytest.raises(wack.WackEvidenceError, match="^WACK_REPORT_PATH_INVALID$"):
        wack.verify_wack_report(
            outside,
            evidence_root,
            source_commit=COMMIT,
            expected_package_identity=PACKAGE_IDENTITY,
            generated_at="2026-08-17T00:00:00Z",
        )
    monkeypatch.setattr(wack, "_has_reparse_component", lambda _path: True)
    with pytest.raises(wack.WackEvidenceError, match="^WACK_REPORT_PATH_INVALID$"):
        wack.verify_wack_report(
            report,
            evidence_root,
            source_commit=COMMIT,
            expected_package_identity=PACKAGE_IDENTITY,
            generated_at="2026-08-17T00:00:00Z",
        )


def test_license_review_is_an_unapproved_complete_component_template() -> None:
    review = json.loads(
        (ROOT / "docs" / "security" / "windows-license-review.json").read_text(
            encoding="utf-8"
        )
    )

    assert review["status"] == "pending"
    assert review["source_commit"] is None
    assert review["sbom_sha256"] is None
    assert review["reviewed_at"] is None
    assert review["reviewer"] is None
    assert {component["name"] for component in review["components"]} == {
        "CPython",
        "Microsoft Universal C Runtime",
        "Microsoft Visual C++ Runtime",
        "OpenSSL",
        "PyInstaller",
        "PyInstaller Bootloader",
        "PySide6",
        "PySide6_Addons",
        "PySide6_Essentials",
        "shiboken6",
    }
    for component in review["components"]:
        assert set(component) == {
            "evidence_url",
            "license_expression",
            "name",
            "redistribution",
            "version",
        }
        assert component["version"] is None
        assert component["redistribution"] == "pending"
        assert component["evidence_url"] is None


def test_personal_source_gate_requires_store_candidate_infrastructure() -> None:
    profile = json.loads(
        (ROOT / "release_profiles" / "personal_store_release.json").read_text(
            encoding="ascii"
        )
    )

    assert ".github/workflows/windows-store-candidate.yml" in profile[
        "required_source_paths"
    ]
    assert "scripts/verify_wack_report.py" in profile["required_source_paths"]
