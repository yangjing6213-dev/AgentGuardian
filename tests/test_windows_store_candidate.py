from __future__ import annotations

import hashlib
import importlib
import json
import os
from pathlib import Path
import zipfile

import pytest

from scripts.build_windows_msix import deterministic_msixupload, msix_manifest_bytes


ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40
PACKAGE_IDENTITY = "yangjing6213dev.AgentGuardian"
PUBLISHER = "CN=00000000-0000-0000-0000-000000000000"
VERSION = "1.0.0.0"
WACK_FIXTURE = (
    ROOT
    / "tests"
    / "fixtures"
    / "wack"
    / "windows-app-certification-kit-10.0.26100.7705.xml"
)


def _wack():
    return importlib.import_module("scripts.verify_wack_report")


def _candidate():
    try:
        return importlib.import_module("scripts.verify_windows_store_candidate")
    except ModuleNotFoundError:
        pytest.fail("Store candidate evidence verifier is missing")


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


def _write_msix(path: Path, *, version: str = VERSION) -> Path:
    manifest = msix_manifest_bytes(
        identity_name=PACKAGE_IDENTITY,
        publisher=PUBLISHER,
        version=version,
    )
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AppxManifest.xml", manifest)
        archive.writestr("AgentGuardian.exe", b"synthetic executable")
    return path


def _write_report(root: Path, body: bytes | str | None = None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    report = root / "wack-report.xml"
    if body is None:
        body = WACK_FIXTURE.read_bytes()
    if isinstance(body, str):
        body = body.encode("utf-8")
    report.write_bytes(body)
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
        assert f"{name}:\n        required: true" in workflow
    assert "^[0-9a-f]{40}$" in workflow
    assert "ref: ${{ inputs.expected_source_commit }}" in workflow
    assert "git rev-parse HEAD" in workflow
    assert "git status --porcelain=v1 --untracked-files=all" in workflow

    for forbidden in (
        "gh release create",
        "actions/create-release",
        "softprops/action-gh-release",
        "partnercenter",
        "partner center",
        "actions/deploy",
        "pfx",
        "password",
        "timestamp",
        "mcp_adapter",
    ):
        assert forbidden not in folded


def test_store_candidate_workflow_runs_reproducible_bounded_candidate_gate() -> None:
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
        "personal_store_release",
        "verify_personal_release_profile.py",
        "build_windows_portable.py",
        "build_windows_msix.py",
        "--msixupload-package",
        "verify_wack_report.py",
        "verify_windows_store_candidate.py",
        "[Environment]::UserInteractive",
        "GetCurrentProcess().SessionId",
        "appcert.exe reset",
        "-appxpackagepath",
        "-reportoutputpath",
        "candidate-SHA256SUMS",
        "payload-manifest.json",
        "release-manifest.json",
        "if-no-files-found: error",
        "retention-days: 14",
    ):
        assert required in workflow
    assert workflow.count("build_windows_portable.py") == 2
    assert "SequenceEqual[byte]" in workflow
    assert "Store candidate must not pass" not in workflow
    assert "--smoke-evidence" not in workflow
    assert "--wack-evidence" not in workflow
    assert "name: agentguardian-store-evidence-${{ inputs.expected_source_commit }}" in workflow
    assert "wack_user_interactive" in workflow
    assert "wack_session_id" in workflow
    assert "username" not in workflow.casefold()

    upload_paths = workflow.split("path: |", 1)[1]
    assert "wack-report.xml" not in upload_paths
    assert ".msix\n" not in upload_paths
    assert upload_paths.count(".analysis/store-evidence/") == 12


def test_msixupload_is_a_deterministic_zip_containing_only_the_msix(
    tmp_path: Path,
) -> None:
    package = tmp_path / "AgentGuardian.msix"
    package.write_bytes(b"synthetic msix")
    first = tmp_path / "first.msixupload"
    second = tmp_path / "second.msixupload"

    deterministic_msixupload(package, first)
    os.utime(package, (2_000_000_000, 2_000_000_000))
    deterministic_msixupload(package, second)

    assert first.read_bytes() == second.read_bytes()
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


def test_reviewed_wack_fixture_emits_canonical_summary_bound_to_msix(
    tmp_path: Path,
) -> None:
    wack = _wack()
    package = _write_msix(tmp_path / "AgentGuardian.msix")
    report = _write_report(tmp_path / "raw-wack")

    result = wack.verify_wack_report(
        report,
        report.parent,
        package_path=package,
        source_commit=COMMIT,
        generated_at="2026-08-17T00:00:00Z",
    )

    assert result == {
        "generated_at": "2026-08-17T00:00:00Z",
        "overall_result": "PASS",
        "package_identity": {
            "name": PACKAGE_IDENTITY,
            "processor_architecture": "x64",
            "publisher": PUBLISHER,
            "version": VERSION,
        },
        "package_sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
        "report_fields": {
            "app_name": "AgentGuardian",
            "app_version": VERSION,
            "id": "unknown-semantics",
            "id_semantics": "unverified",
            "publisher_display_name": "AgentGuardian",
        },
        "report_sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
        "schema": 2,
        "source_commit": COMMIT,
        "source_commit_origin": "candidate_input",
        "test_counts": {
            "failed": 0,
            "passed": 1,
            "requirements": 1,
            "tests": 1,
            "total": 1,
        },
        "tool_version": "10.0.26100.7705",
    }
    assert wack.canonical_json_bytes(result) == _canonical(result)


@pytest.mark.parametrize(
    "mutation,code",
    (
        (lambda text: text.replace('OVERALL_RESULT="PASS"', 'OVERALL_RESULT="FAIL"'), "WACK_RESULT_FAILED"),
        (lambda text: text.replace('PARTIAL_RUN="FALSE"', 'PARTIAL_RUN="TRUE"'), "WACK_PARTIAL_RUN"),
        (lambda text: text.replace("<![CDATA[PASS]]>", "<![CDATA[FAIL]]>"), "WACK_RESULT_FAILED"),
        (lambda text: text.replace('NUMBER="1"', 'NUMBER="1" RESULT="FAIL"'), "WACK_RESULT_FAILED"),
        (lambda text: text.replace(' VERSION="10.0.26100.7705"', ""), "WACK_REPORT_SCHEMA_UNSUPPORTED"),
        (lambda text: text.replace(' PUBLISHER_DISPLAY_NAME="AgentGuardian"', ""), "WACK_REPORT_SCHEMA_UNSUPPORTED"),
        (lambda text: text.replace('APP_VERSION="1.0.0.0"', 'APP_VERSION="2.0.0.0"'), "WACK_PACKAGE_VERSION_MISMATCH"),
        (lambda text: text.replace("<REPORT", "<!DOCTYPE REPORT [<!ENTITY xxe SYSTEM 'file:///secret'>]><REPORT"), "WACK_XML_DTD_FORBIDDEN"),
    ),
)
def test_wack_report_fails_closed_on_unsafe_or_incomplete_evidence(
    tmp_path: Path, mutation, code: str
) -> None:
    wack = _wack()
    package = _write_msix(tmp_path / "AgentGuardian.msix")
    report_text = WACK_FIXTURE.read_text(encoding="utf-8")
    report = _write_report(tmp_path / "raw-wack", mutation(report_text))

    with pytest.raises(wack.WackEvidenceError, match=f"^{code}$"):
        wack.verify_wack_report(
            report,
            report.parent,
            package_path=package,
            source_commit=COMMIT,
            generated_at="2026-08-17T00:00:00Z",
        )


def test_wack_report_requires_absolute_in_root_regular_non_reparse_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wack = _wack()
    package = _write_msix(tmp_path / "AgentGuardian.msix")
    report = _write_report(tmp_path / "raw-wack")

    with pytest.raises(wack.WackEvidenceError, match="^WACK_REPORT_PATH_INVALID$"):
        wack.verify_wack_report(
            report.relative_to(tmp_path),
            report.parent,
            package_path=package,
            source_commit=COMMIT,
            generated_at="2026-08-17T00:00:00Z",
        )
    monkeypatch.setattr(wack, "_has_reparse_component", lambda _path: True)
    with pytest.raises(wack.WackEvidenceError, match="^WACK_REPORT_PATH_INVALID$"):
        wack.verify_wack_report(
            report,
            report.parent,
            package_path=package,
            source_commit=COMMIT,
            generated_at="2026-08-17T00:00:00Z",
        )


def test_wack_report_rejects_more_than_16_mib(tmp_path: Path) -> None:
    wack = _wack()
    package = _write_msix(tmp_path / "AgentGuardian.msix")
    report = _write_report(
        tmp_path / "raw-wack", b" " * (wack.MAX_REPORT_BYTES + 1)
    )

    with pytest.raises(wack.WackEvidenceError, match="^WACK_REPORT_PATH_INVALID$"):
        wack.verify_wack_report(
            report,
            report.parent,
            package_path=package,
            source_commit=COMMIT,
            generated_at="2026-08-17T00:00:00Z",
        )


def _write_candidate_inputs(
    tmp_path: Path,
    *,
    license_status: str = "approved",
    license_source: str = COMMIT,
    license_sbom: str | None = None,
) -> Path:
    candidate = _candidate()
    root = tmp_path / "evidence"
    root.mkdir()
    package = _write_msix(tmp_path / "AgentGuardian-store.msix")
    upload = root / f"AgentGuardian-{COMMIT}.msixupload"
    deterministic_msixupload(package, upload)

    sbom = {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "name": "PySide6",
                "version": "6.11.1",
                "licenses": [{"license": {"id": "LGPL-3.0-only"}}],
            }
        ],
        "metadata": {
            "properties": [{"name": "agentguardian:build:id", "value": COMMIT}]
        },
        "specVersion": "1.6",
    }
    (root / "AgentGuardian.cdx.json").write_bytes(_canonical(sbom))
    (root / "THIRD_PARTY_NOTICES.md").write_text(
        "PySide6 6.11.1\nLGPL-3.0-only\n", encoding="utf-8", newline="\n"
    )
    (root / "payload-manifest.json").write_bytes(
        _canonical({"algorithm": "sha256", "files": [], "schema": 1})
    )
    (root / "provenance.json").write_bytes(
        _canonical(
            {
                "artifact_status": "store_submission_candidate",
                "built_at": "2026-08-17T00:00:00Z",
                "source_commit": COMMIT,
            }
        )
    )
    (root / "profile-result.json").write_bytes(
        _canonical({"profile": "personal_store_release", "status": "pass"})
    )
    (root / "privacy-result.json").write_bytes(
        _canonical(
            {
                "passed": True,
                "profile": "personal_privacy_acceptance",
                "schema": 1,
            }
        )
    )
    raw_report = _write_report(tmp_path / "raw-wack")
    wack_summary = _wack().verify_wack_report(
        raw_report,
        raw_report.parent,
        package_path=package,
        source_commit=COMMIT,
        generated_at="2026-08-17T00:00:00Z",
    )
    (root / "wack-summary.json").write_bytes(_canonical(wack_summary))
    (root / "workflow-run.json").write_bytes(
        _canonical(
            {
                "run_attempt": "1",
                "run_id": "123",
                "schema": 1,
                "source_commit": COMMIT,
                "store_submission": "not_performed",
                "wack_session_id": 1,
                "wack_user_interactive": True,
            }
        )
    )
    sbom_digest = hashlib.sha256((root / "AgentGuardian.cdx.json").read_bytes()).hexdigest()
    review = {
        "components": [
            {
                "evidence_url": "https://doc.qt.io/qt-6/qtlicenses.html",
                "license_expression": "LGPL-3.0-only",
                "name": "PySide6",
                "redistribution": "approved" if license_status == "approved" else "pending",
                "version": "6.11.1" if license_status == "approved" else None,
            }
        ],
        "reviewed_at": "2026-08-17T00:00:00Z" if license_status == "approved" else None,
        "reviewer": "reviewer@example.test" if license_status == "approved" else None,
        "sbom_sha256": license_sbom or sbom_digest,
        "schema_version": 1,
        "source_commit": license_source,
        "status": license_status,
    }
    (root / "windows-license-review.json").write_bytes(_canonical(review))
    candidate.create_candidate_evidence(root, expected_source_commit=COMMIT)
    return root


def test_store_candidate_manifest_and_checksums_bind_complete_chain(
    tmp_path: Path,
) -> None:
    candidate = _candidate()
    root = _write_candidate_inputs(tmp_path)

    result = candidate.validate_store_candidate(root, expected_source_commit=COMMIT)
    manifest = json.loads((root / "release-manifest.json").read_text(encoding="ascii"))

    assert result == {
        "license_review": "complete",
        "passed": True,
        "source_commit": COMMIT,
        "wack": "pass",
    }
    assert manifest["source_commit"] == COMMIT
    assert manifest["package_identity"] == {
        "name": PACKAGE_IDENTITY,
        "processor_architecture": "x64",
        "publisher": PUBLISHER,
        "version": VERSION,
    }
    assert manifest["msix"]["name"] == "AgentGuardian-store.msix"
    assert manifest["msixupload"]["name"] == f"AgentGuardian-{COMMIT}.msixupload"
    assert set(manifest["evidence"]) == {
        "license_review",
        "notices",
        "payload_manifest",
        "privacy_result",
        "profile_result",
        "provenance",
        "sbom",
        "wack_summary",
        "workflow_run",
    }
    checksum_lines = (root / "candidate-SHA256SUMS").read_text(encoding="ascii").splitlines()
    assert len(checksum_lines) == 11
    assert all("candidate-SHA256SUMS" not in line for line in checksum_lines)
    assert any("release-manifest.json" in line for line in checksum_lines)


@pytest.mark.parametrize(
    "license_status,license_source,license_sbom,code",
    (
        ("pending", COMMIT, None, "STORE_CANDIDATE_LICENSE_REVIEW_REQUIRED"),
        ("approved", "b" * 40, None, "STORE_CANDIDATE_LICENSE_SOURCE_MISMATCH"),
        ("approved", COMMIT, "0" * 64, "STORE_CANDIDATE_LICENSE_SBOM_MISMATCH"),
    ),
)
def test_store_candidate_license_gate_fails_closed(
    tmp_path: Path,
    license_status: str,
    license_source: str,
    license_sbom: str | None,
    code: str,
) -> None:
    candidate = _candidate()
    root = _write_candidate_inputs(
        tmp_path,
        license_status=license_status,
        license_source=license_source,
        license_sbom=license_sbom,
    )

    with pytest.raises(candidate.StoreCandidateError, match=f"^{code}$"):
        candidate.validate_store_candidate(root, expected_source_commit=COMMIT)


def test_store_candidate_recomputes_manifest_checksums_and_upload_msix(
    tmp_path: Path,
) -> None:
    candidate = _candidate()
    root = _write_candidate_inputs(tmp_path)
    privacy = root / "privacy-result.json"
    privacy.write_bytes(privacy.read_bytes() + b" ")

    with pytest.raises(candidate.StoreCandidateError, match="^STORE_CANDIDATE_MANIFEST_MISMATCH$"):
        candidate.validate_store_candidate(root, expected_source_commit=COMMIT)


def test_store_candidate_rejects_msixupload_with_more_than_one_msix(
    tmp_path: Path,
) -> None:
    candidate = _candidate()
    root = _write_candidate_inputs(tmp_path)
    upload = root / f"AgentGuardian-{COMMIT}.msixupload"
    with zipfile.ZipFile(upload, "a") as archive:
        archive.writestr("other.msix", b"other")

    with pytest.raises(candidate.StoreCandidateError, match="^STORE_CANDIDATE_UPLOAD_INVALID$"):
        candidate.validate_store_candidate(root, expected_source_commit=COMMIT)


def test_store_candidate_upload_allowlist_is_exact_and_safe(tmp_path: Path) -> None:
    candidate = _candidate()
    root = _write_candidate_inputs(tmp_path)

    assert {path.name for path in candidate.validate_upload_allowlist(root, COMMIT)} == {
        f"AgentGuardian-{COMMIT}.msixupload",
        "AgentGuardian.cdx.json",
        "THIRD_PARTY_NOTICES.md",
        "candidate-SHA256SUMS",
        "payload-manifest.json",
        "privacy-result.json",
        "profile-result.json",
        "provenance.json",
        "release-manifest.json",
        "wack-summary.json",
        "windows-license-review.json",
        "workflow-run.json",
    }
    (root / "unexpected.txt").write_text("unexpected", encoding="ascii")
    with pytest.raises(candidate.StoreCandidateError, match="^STORE_EVIDENCE_ALLOWLIST_INVALID$"):
        candidate.validate_upload_allowlist(root, COMMIT)


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
    assert len(review["components"]) == 10
    assert all(component["redistribution"] == "pending" for component in review["components"])


def test_personal_source_gate_requires_store_candidate_infrastructure() -> None:
    profile = json.loads(
        (ROOT / "release_profiles" / "personal_store_release.json").read_text(
            encoding="ascii"
        )
    )

    assert ".github/workflows/windows-store-candidate.yml" in profile["required_source_paths"]
    assert "scripts/verify_wack_report.py" in profile["required_source_paths"]
    assert "scripts/verify_windows_store_candidate.py" in profile["required_source_paths"]
    assert "tests/fixtures/wack/windows-app-certification-kit-10.0.26100.7705.xml" in profile[
        "required_source_paths"
    ]
