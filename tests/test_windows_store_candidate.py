from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import importlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
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


def _write_msix(
    path: Path,
    *,
    version: str = VERSION,
    processor_architecture: str = "x64",
    manifest_override: bytes | None = None,
    portable_files: dict[str, bytes] | None = None,
    extra_entries: dict[str, bytes] | None = None,
) -> Path:
    manifest = msix_manifest_bytes(
        identity_name=PACKAGE_IDENTITY,
        publisher=PUBLISHER,
        version=version,
    )
    manifest = manifest.replace(
        b'ProcessorArchitecture="x64"',
        f'ProcessorArchitecture="{processor_architecture}"'.encode("ascii"),
    )
    if manifest_override is not None:
        manifest = manifest_override
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AppxManifest.xml", manifest)
        for name, body in (
            portable_files or {"AgentGuardian.exe": b"synthetic executable"}
        ).items():
            archive.writestr(name, body)
        for name in (
            "Assets/Square44x44Logo.png",
            "Assets/Square150x150Logo.png",
            "Assets/StoreLogo.png",
        ):
            archive.writestr(name, b"synthetic png")
        archive.writestr("AppxBlockMap.xml", b"synthetic block map")
        archive.writestr("[Content_Types].xml", b"synthetic content types")
        for name, body in (extra_entries or {}).items():
            archive.writestr(name, body)
    return path


def _portable_bundle_files(
    sbom_bytes: bytes, notices: bytes, provenance: bytes
) -> dict[str, bytes]:
    files = {
        "AgentGuardian.exe": b"synthetic executable",
        "LICENSE": b"synthetic license\n",
        "THIRD_PARTY_NOTICES.md": notices,
        "AgentGuardian.cdx.json": sbom_bytes,
        "BUILD-METADATA.json": provenance,
        "_internal/runtime.dll": b"synthetic runtime",
    }
    payload = {
        "algorithm": "sha256",
        "files": [
            {
                "path": name,
                "sha256": hashlib.sha256(body).hexdigest(),
                "size": len(body),
            }
            for name, body in sorted(files.items())
        ],
        "schema": 1,
    }
    files["PAYLOAD-MANIFEST.json"] = _canonical(payload)
    files["SHA256SUMS"] = "".join(
        f"{hashlib.sha256(body).hexdigest()} *{name}\n"
        for name, body in sorted(files.items())
    ).encode("ascii")
    return files


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
    assert "approved_license_review_base64:\n        required: false" in workflow
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
        "APPROVED_LICENSE_REVIEW_BASE64",
        "--materialize-license-review",
        "--check-active-session",
        "--run-tool",
        "candidate-SHA256SUMS",
        "portable-SHA256SUMS",
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
    assert "wack_session_state" in workflow
    assert "license_review_origin" in workflow
    assert "wack_user_interactive" not in workflow
    assert "wack_session_id" not in workflow
    assert "[Environment]::UserInteractive" not in workflow
    assert "& $tool reset" not in workflow
    assert "& $tool test" not in workflow
    assert "username" not in workflow.casefold()
    metadata_step = workflow.split("- name: Record bounded workflow metadata", 1)[1].split(
        "- name:", 1
    )[0]
    assert "approved_license_review_base64" not in metadata_step.casefold()

    upload_paths = workflow.split("path: |", 1)[1]
    assert "wack-report.xml" not in upload_paths
    assert ".msix\n" not in upload_paths
    assert upload_paths.count(".analysis/store-evidence/") == 13


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
        info = archive.infolist()[0]
        assert info.compress_type == zipfile.ZIP_STORED
        assert info.compress_size == info.file_size
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


def test_wts_session_gate_accepts_only_wtsactive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wack = _wack()
    monkeypatch.setattr(wack, "_query_wts_connect_state", lambda: 0, raising=False)
    assert wack.current_wack_session_state() == "active"

    monkeypatch.setattr(wack, "_query_wts_connect_state", lambda: 1, raising=False)
    with pytest.raises(wack.WackEvidenceError, match="^WACK_SESSION_NOT_ACTIVE$"):
        wack.current_wack_session_state()


def test_wack_wrapper_binds_new_report_and_unchanged_package_to_one_process(
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
    tool.write_bytes(b"synthetic tool")
    monkeypatch.setenv("ProgramFiles(x86)", str(program_files))
    package = _write_msix(tmp_path / "AgentGuardian.msix")
    evidence_root = tmp_path / "raw-wack"
    evidence_root.mkdir()
    report = evidence_root / "wack-report.xml"
    started = datetime.now(timezone.utc) - timedelta(seconds=5)
    completed = started + timedelta(seconds=1)
    times = iter((started, completed))
    monkeypatch.setattr(wack, "_utc_now", lambda: next(times), raising=False)
    monkeypatch.setattr(
        wack, "current_wack_session_state", lambda: "active", raising=False
    )
    calls: list[tuple[str, ...]] = []

    def fake_run(command, **kwargs):
        calls.append(tuple(command))
        assert kwargs == {"check": False, "timeout": wack.WACK_COMMAND_TIMEOUT_SECONDS}
        if command[1] == "test":
            report.write_bytes(WACK_FIXTURE.read_bytes())
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(wack.subprocess, "run", fake_run)

    result = wack.run_wack_tool(
        tool,
        package,
        report,
        evidence_root,
        source_commit=COMMIT,
    )

    assert calls == list(wack.wack_commands(tool, package, report))
    package_sha = hashlib.sha256(package.read_bytes()).hexdigest()
    assert result["package_sha256"] == package_sha
    assert result["invocation"] == {
        "binding_mode": "same_process_invocation",
        "package_sha_after": package_sha,
        "package_sha_before": package_sha,
        "report_created_after_start": True,
        "started_at": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    assert result["generated_at"] == completed.strftime("%Y-%m-%dT%H:%M:%SZ")


def test_wack_wrapper_rejects_preexisting_report_or_package_mutation(
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
    tool.write_bytes(b"synthetic tool")
    monkeypatch.setenv("ProgramFiles(x86)", str(program_files))
    package = _write_msix(tmp_path / "AgentGuardian.msix")
    evidence_root = tmp_path / "raw-wack"
    evidence_root.mkdir()
    report = _write_report(evidence_root)
    monkeypatch.setattr(
        wack, "current_wack_session_state", lambda: "active", raising=False
    )
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(
        wack.subprocess,
        "run",
        lambda command, **_kwargs: calls.append(tuple(command)),
    )
    with pytest.raises(wack.WackEvidenceError, match="^WACK_REPORT_PATH_INVALID$"):
        wack.run_wack_tool(
            tool, package, report, evidence_root, source_commit=COMMIT
        )
    assert calls == []

    report.unlink()
    times = iter(
        (
            datetime.now(timezone.utc) - timedelta(seconds=5),
            datetime.now(timezone.utc),
        )
    )
    monkeypatch.setattr(wack, "_utc_now", lambda: next(times), raising=False)

    def mutate_package(command, **_kwargs):
        if command[1] == "test":
            report.write_bytes(WACK_FIXTURE.read_bytes())
            package.write_bytes(package.read_bytes() + b"changed")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(wack.subprocess, "run", mutate_package)
    with pytest.raises(wack.WackEvidenceError, match="^WACK_PACKAGE_CHANGED$"):
        wack.run_wack_tool(
            tool, package, report, evidence_root, source_commit=COMMIT
        )


def test_wack_wrapper_rejects_preexisting_report_directory_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wack = _wack()
    evidence_root = tmp_path / "raw-wack"
    evidence_root.mkdir()
    report = evidence_root / "wack-report.xml"
    monkeypatch.setattr(
        wack.os.path,
        "lexists",
        lambda value: Path(value) == report,
    )

    with pytest.raises(wack.WackEvidenceError, match="^WACK_REPORT_PATH_INVALID$"):
        wack._new_report_path(report, evidence_root)


def test_wack_wrapper_rejects_report_mtime_before_invocation(
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
    tool.write_bytes(b"synthetic tool")
    monkeypatch.setenv("ProgramFiles(x86)", str(program_files))
    package = _write_msix(tmp_path / "AgentGuardian.msix")
    evidence_root = tmp_path / "raw-wack"
    evidence_root.mkdir()
    report = evidence_root / "wack-report.xml"
    started = datetime.now(timezone.utc) - timedelta(seconds=5)
    monkeypatch.setattr(wack, "_utc_now", lambda: started, raising=False)
    monkeypatch.setattr(
        wack, "current_wack_session_state", lambda: "active", raising=False
    )

    def old_report(command, **_kwargs):
        if command[1] == "test":
            report.write_bytes(WACK_FIXTURE.read_bytes())
            old = started.timestamp() - 10
            os.utime(report, (old, old))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(wack.subprocess, "run", old_report)
    with pytest.raises(wack.WackEvidenceError, match="^WACK_REPORT_NOT_NEW$"):
        wack.run_wack_tool(
            tool, package, report, evidence_root, source_commit=COMMIT
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


def test_wack_report_rejects_utf16_internal_entity(tmp_path: Path) -> None:
    wack = _wack()
    package = _write_msix(tmp_path / "AgentGuardian.msix")
    report_text = WACK_FIXTURE.read_text(encoding="utf-8")
    report_text = report_text.replace('encoding="utf-8"', 'encoding="utf-16"')
    report_text = report_text.replace(
        "<REPORT",
        '<!DOCTYPE REPORT [<!ENTITY pass "PASS">]><REPORT',
        1,
    ).replace('OVERALL_RESULT="PASS"', 'OVERALL_RESULT="&pass;"', 1)
    report = _write_report(tmp_path / "raw-wack", report_text.encode("utf-16"))

    with pytest.raises(wack.WackEvidenceError, match="^WACK_XML_DTD_FORBIDDEN$"):
        wack.verify_wack_report(
            report,
            report.parent,
            package_path=package,
            source_commit=COMMIT,
            generated_at="2026-08-17T00:00:00Z",
        )


def test_msix_manifest_rejects_utf16_internal_entity(tmp_path: Path) -> None:
    wack = _wack()
    manifest = msix_manifest_bytes(
        identity_name=PACKAGE_IDENTITY,
        publisher=PUBLISHER,
        version=VERSION,
    ).decode("utf-8")
    manifest = manifest.replace('encoding="utf-8"', 'encoding="utf-16"')
    manifest = manifest.replace(
        "<Package",
        f'<!DOCTYPE Package [<!ENTITY identity "{PACKAGE_IDENTITY}">]><Package',
        1,
    ).replace(f'Name="{PACKAGE_IDENTITY}"', 'Name="&identity;"', 1)
    package = _write_msix(
        tmp_path / "AgentGuardian.msix",
        manifest_override=manifest.encode("utf-16"),
    )

    with pytest.raises(
        wack.WackEvidenceError, match="^WACK_PACKAGE_MANIFEST_INVALID$"
    ):
        wack.read_msix_identity(package)


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
    create_evidence: bool = True,
    extra_msix_entries: dict[str, bytes] | None = None,
    payload_override: dict[str, object] | None = None,
    checksums_override: bytes | None = None,
    wack_binding_mode: str = "same_process_invocation",
) -> Path:
    candidate = _candidate()
    root = tmp_path / "evidence"
    root.mkdir()

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
    sbom_bytes = _canonical(sbom)
    notices = b"PySide6 6.11.1\nLGPL-3.0-only\n"
    provenance = _canonical(
        {
            "artifact_status": "store_submission_candidate",
            "built_at": "2026-08-17T00:00:00Z",
            "source_commit": COMMIT,
        }
    )
    portable_files = _portable_bundle_files(sbom_bytes, notices, provenance)
    if payload_override is not None:
        portable_files["PAYLOAD-MANIFEST.json"] = _canonical(payload_override)
        portable_files["SHA256SUMS"] = "".join(
            f"{hashlib.sha256(body).hexdigest()} *{name}\n"
            for name, body in sorted(portable_files.items())
            if name != "SHA256SUMS"
        ).encode("ascii")
    if checksums_override is not None:
        portable_files["SHA256SUMS"] = checksums_override
    package = _write_msix(
        tmp_path / "AgentGuardian-store.msix",
        portable_files=portable_files,
        extra_entries=extra_msix_entries,
    )
    upload = root / f"AgentGuardian-{COMMIT}.msixupload"
    deterministic_msixupload(package, upload)

    (root / "AgentGuardian.cdx.json").write_bytes(sbom_bytes)
    (root / "THIRD_PARTY_NOTICES.md").write_bytes(notices)
    (root / "payload-manifest.json").write_bytes(
        portable_files["PAYLOAD-MANIFEST.json"]
    )
    (root / "portable-SHA256SUMS").write_bytes(portable_files["SHA256SUMS"])
    (root / "provenance.json").write_bytes(provenance)
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
    package_sha = hashlib.sha256(package.read_bytes()).hexdigest()
    wack_summary["invocation"] = {
        "binding_mode": wack_binding_mode,
        "package_sha_after": package_sha,
        "package_sha_before": package_sha,
        "report_created_after_start": True,
        "started_at": "2026-08-16T23:59:59Z",
    }
    (root / "wack-summary.json").write_bytes(_canonical(wack_summary))
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
    encoded_review = (
        ""
        if license_status == "pending"
        else base64.b64encode(_canonical(review)).decode("ascii")
    )
    origin = candidate.materialize_license_review(
        root,
        ROOT / "docs" / "security" / "windows-license-review.json",
        encoded_review,
        expected_source_commit=COMMIT,
    )
    (root / "workflow-run.json").write_bytes(
        _canonical(
            {
                "license_review_origin": origin,
                "run_attempt": "1",
                "run_id": "123",
                "schema": 1,
                "source_commit": COMMIT,
                "store_submission": "not_performed",
                "wack_session_state": "active",
            }
        )
    )
    if create_evidence:
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
    asset_sha = hashlib.sha256(b"synthetic png").hexdigest()
    assert manifest["assets"] == [
        {"name": name, "sha256": asset_sha, "size": len(b"synthetic png")}
        for name in (
            "Assets/Square44x44Logo.png",
            "Assets/Square150x150Logo.png",
            "Assets/StoreLogo.png",
        )
    ]
    assert set(manifest["evidence"]) == {
        "license_review",
        "notices",
        "payload_manifest",
        "portable_checksums",
        "privacy_result",
        "profile_result",
        "provenance",
        "sbom",
        "wack_summary",
        "workflow_run",
    }
    workflow = json.loads((root / "workflow-run.json").read_text(encoding="ascii"))
    assert workflow["license_review_origin"] == "workflow_dispatch_input"
    checksum_lines = (root / "candidate-SHA256SUMS").read_text(encoding="ascii").splitlines()
    assert len(checksum_lines) == 12
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
    with pytest.raises(candidate.StoreCandidateError, match=f"^{code}$"):
        root = _write_candidate_inputs(
            tmp_path,
            license_status=license_status,
            license_source=license_source,
            license_sbom=license_sbom,
        )
        candidate.validate_store_candidate(root, expected_source_commit=COMMIT)


def test_external_license_input_is_strict_canonical_bounded_and_not_self_referential(
    tmp_path: Path,
) -> None:
    candidate = _candidate()
    root = tmp_path / "evidence"
    root.mkdir()
    sbom = _canonical({"bomFormat": "CycloneDX", "components": []})
    (root / "AgentGuardian.cdx.json").write_bytes(sbom)
    review = {
        "components": [],
        "reviewed_at": "2026-08-17T00:00:00Z",
        "reviewer": "reviewer@example.test",
        "sbom_sha256": hashlib.sha256(sbom).hexdigest(),
        "schema_version": 1,
        "source_commit": COMMIT,
        "status": "approved",
    }
    noncanonical = json.dumps(review, indent=2).encode("ascii")

    for encoded in (
        "not-base64!",
        base64.b64encode(noncanonical).decode("ascii"),
        "A" * (candidate.MAX_APPROVED_LICENSE_REVIEW_BASE64_BYTES + 1),
    ):
        with pytest.raises(
            candidate.StoreCandidateError,
            match="^STORE_CANDIDATE_LICENSE_INPUT_INVALID$",
        ):
            candidate.materialize_license_review(
                root,
                ROOT / "docs" / "security" / "windows-license-review.json",
                encoded,
                expected_source_commit=COMMIT,
            )
        assert not (root / "windows-license-review.json").exists()


def test_empty_license_input_materializes_only_repository_pending_template(
    tmp_path: Path,
) -> None:
    candidate = _candidate()
    root = tmp_path / "evidence"
    root.mkdir()

    origin = candidate.materialize_license_review(
        root,
        ROOT / "docs" / "security" / "windows-license-review.json",
        "",
        expected_source_commit=COMMIT,
    )

    assert origin == "repository_pending_template"
    assert (root / "windows-license-review.json").read_bytes() == (
        ROOT / "docs" / "security" / "windows-license-review.json"
    ).read_bytes()


def test_license_materialization_cli_uses_empty_dispatch_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    candidate = _candidate()
    root = tmp_path / "evidence"
    root.mkdir()
    monkeypatch.delenv("APPROVED_LICENSE_REVIEW_BASE64", raising=False)
    monkeypatch.setattr(
        candidate.sys,
        "argv",
        [
            "verify_windows_store_candidate.py",
            "--evidence-root",
            str(root),
            "--expected-source-commit",
            COMMIT,
            "--materialize-license-review",
            "--repository-license-template",
            str(ROOT / "docs" / "security" / "windows-license-review.json"),
        ],
    )

    assert candidate.main() == 0
    assert json.loads(capsys.readouterr().out) == {
        "license_review_origin": "repository_pending_template",
        "status": "materialized",
    }


def test_store_candidate_recomputes_manifest_checksums_and_upload_msix(
    tmp_path: Path,
) -> None:
    candidate = _candidate()
    root = _write_candidate_inputs(tmp_path)
    privacy = root / "privacy-result.json"
    privacy.write_bytes(privacy.read_bytes() + b" ")

    with pytest.raises(candidate.StoreCandidateError, match="^STORE_CANDIDATE_MANIFEST_MISMATCH$"):
        candidate.validate_store_candidate(root, expected_source_commit=COMMIT)


def test_store_candidate_accepts_only_same_process_wack_binding(tmp_path: Path) -> None:
    candidate = _candidate()
    with pytest.raises(
        candidate.StoreCandidateError, match="^STORE_CANDIDATE_WACK_INVALID$"
    ):
        _write_candidate_inputs(tmp_path, wack_binding_mode="report_only")


def test_store_candidate_rejects_non_x64_msix(tmp_path: Path) -> None:
    candidate = _candidate()
    root = tmp_path / "evidence"
    root.mkdir()
    package = _write_msix(
        tmp_path / "AgentGuardian-store.msix",
        processor_architecture="arm64",
    )
    upload = root / f"AgentGuardian-{COMMIT}.msixupload"
    deterministic_msixupload(package, upload)

    with pytest.raises(
        candidate.StoreCandidateError, match="^STORE_CANDIDATE_UPLOAD_INVALID$"
    ):
        candidate._msixupload_package(upload, root)


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


def test_store_candidate_rejects_compressed_outer_msixupload(tmp_path: Path) -> None:
    candidate = _candidate()
    root = _write_candidate_inputs(tmp_path, create_evidence=False)
    upload = root / f"AgentGuardian-{COMMIT}.msixupload"
    with zipfile.ZipFile(upload) as archive:
        package_name = archive.namelist()[0]
        package_bytes = archive.read(package_name)
    upload.unlink()
    with zipfile.ZipFile(upload, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(package_name, package_bytes)

    with pytest.raises(
        candidate.StoreCandidateError, match="^STORE_CANDIDATE_UPLOAD_INVALID$"
    ):
        candidate.create_candidate_evidence(root, expected_source_commit=COMMIT)


@pytest.mark.parametrize(
    "extra_name",
    ("Assets/evil.exe", "Assets/evil/", "AppxSignature.p7x"),
)
def test_store_candidate_rejects_extra_wrapper_during_full_validation(
    tmp_path: Path, extra_name: str
) -> None:
    candidate = _candidate()
    root = _write_candidate_inputs(tmp_path)
    upload = root / f"AgentGuardian-{COMMIT}.msixupload"
    package = tmp_path / "mutated-store.msix"
    with zipfile.ZipFile(upload) as archive:
        package.write_bytes(archive.read(archive.namelist()[0]))
    with zipfile.ZipFile(package, "a") as archive:
        archive.writestr(extra_name, b"unexpected wrapper asset")
    upload.unlink()
    deterministic_msixupload(package, upload)

    with pytest.raises(
        candidate.StoreCandidateError,
        match="^STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID$",
    ):
        candidate.validate_store_candidate(root, expected_source_commit=COMMIT)


@pytest.mark.parametrize(
    "name",
    (
        "AgentGuardian.cdx.json",
        "THIRD_PARTY_NOTICES.md",
        "payload-manifest.json",
        "portable-SHA256SUMS",
        "provenance.json",
    ),
)
def test_store_candidate_requires_external_sidecars_to_match_msix_bytes(
    tmp_path: Path, name: str
) -> None:
    candidate = _candidate()
    root = _write_candidate_inputs(tmp_path, create_evidence=False)
    (root / name).write_bytes(b"changed\n")

    with pytest.raises(
        candidate.StoreCandidateError,
        match="^STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID$",
    ):
        candidate.create_candidate_evidence(root, expected_source_commit=COMMIT)


@pytest.mark.parametrize(
    "payload_override",
    (
        {"algorithm": "sha256", "files": [], "schema": 1},
        {
            "algorithm": "sha256",
            "files": [
                {"path": "../escape", "sha256": "0" * 64, "size": 1}
            ],
            "schema": 1,
        },
        {
            "algorithm": "sha256",
            "files": [
                {
                    "path": "AgentGuardian.exe",
                    "sha256": "0" * 64,
                    "size": 4 * 1024 * 1024 * 1024 + 1,
                }
            ],
            "schema": 1,
        },
        {
            "algorithm": "sha256",
            "files": [
                {"path": "AgentGuardian.exe", "sha256": "0" * 64, "size": 1},
                {"path": "AgentGuardian.exe", "sha256": "0" * 64, "size": 1},
            ],
            "schema": 1,
        },
    ),
)
def test_store_candidate_rejects_empty_duplicate_or_traversing_payload_manifest(
    tmp_path: Path, payload_override: dict[str, object]
) -> None:
    candidate = _candidate()
    root = _write_candidate_inputs(
        tmp_path,
        create_evidence=False,
        payload_override=payload_override,
    )

    with pytest.raises(
        candidate.StoreCandidateError,
        match="^STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID$",
    ):
        candidate.create_candidate_evidence(root, expected_source_commit=COMMIT)


def test_store_candidate_rejects_traversing_portable_checksums(tmp_path: Path) -> None:
    candidate = _candidate()
    root = _write_candidate_inputs(
        tmp_path,
        create_evidence=False,
        checksums_override=("0" * 64 + " *../escape\n").encode("ascii"),
    )

    with pytest.raises(
        candidate.StoreCandidateError,
        match="^STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID$",
    ):
        candidate.create_candidate_evidence(root, expected_source_commit=COMMIT)


def test_store_candidate_rejects_uncovered_portable_msix_entry(tmp_path: Path) -> None:
    candidate = _candidate()
    root = _write_candidate_inputs(
        tmp_path,
        create_evidence=False,
        extra_msix_entries={"uncovered.dll": b"not in portable evidence"},
    )

    with pytest.raises(
        candidate.StoreCandidateError,
        match="^STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID$",
    ):
        candidate.create_candidate_evidence(root, expected_source_commit=COMMIT)


def test_store_candidate_rejects_evidence_root_over_total_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = _candidate()
    root = _write_candidate_inputs(tmp_path)
    total = sum(path.stat().st_size for path in root.iterdir())
    monkeypatch.setattr(candidate, "MAX_EVIDENCE_ROOT_BYTES", total - 1, raising=False)

    with pytest.raises(
        candidate.StoreCandidateError, match="^STORE_EVIDENCE_ALLOWLIST_INVALID$"
    ):
        candidate.validate_upload_allowlist(root, COMMIT)


def test_payload_manifest_schema_rejects_bool() -> None:
    candidate = _candidate()
    body = b"x"
    digest = hashlib.sha256(body).hexdigest()
    raw = _canonical(
        {
            "algorithm": "sha256",
            "files": [{"path": "file.bin", "sha256": digest, "size": 1}],
            "schema": True,
        }
    )

    with pytest.raises(
        candidate.StoreCandidateError,
        match="^STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID$",
    ):
        candidate._validate_payload_manifest(raw, {"file.bin": (1, digest)})


@pytest.mark.parametrize(
    "name,schema_value,code",
    (
        ("privacy-result.json", True, "STORE_CANDIDATE_PRIVACY_INVALID"),
        ("workflow-run.json", True, "STORE_CANDIDATE_WORKFLOW_METADATA_INVALID"),
        ("wack-summary.json", 2.0, "STORE_CANDIDATE_WACK_INVALID"),
    ),
)
def test_store_candidate_schema_fields_require_exact_integer_type(
    tmp_path: Path, name: str, schema_value: object, code: str
) -> None:
    candidate = _candidate()
    root = _write_candidate_inputs(tmp_path, create_evidence=False)
    path = root / name
    value = json.loads(path.read_text(encoding="ascii"))
    value["schema"] = schema_value
    path.write_bytes(_canonical(value))

    with pytest.raises(candidate.StoreCandidateError, match=f"^{code}$"):
        candidate.create_candidate_evidence(root, expected_source_commit=COMMIT)


def test_external_license_schema_version_rejects_bool(tmp_path: Path) -> None:
    candidate = _candidate()
    root = _write_candidate_inputs(tmp_path, create_evidence=False)
    path = root / "windows-license-review.json"
    review = json.loads(path.read_text(encoding="ascii"))
    path.unlink()
    review["schema_version"] = True
    encoded = base64.b64encode(_canonical(review)).decode("ascii")

    with pytest.raises(
        candidate.StoreCandidateError,
        match="^STORE_CANDIDATE_LICENSE_INPUT_INVALID$",
    ):
        candidate.materialize_license_review(
            root,
            ROOT / "docs" / "security" / "windows-license-review.json",
            encoded,
            expected_source_commit=COMMIT,
        )


def test_store_candidate_upload_allowlist_is_exact_and_safe(tmp_path: Path) -> None:
    candidate = _candidate()
    root = _write_candidate_inputs(tmp_path)

    assert {path.name for path in candidate.validate_upload_allowlist(root, COMMIT)} == {
        f"AgentGuardian-{COMMIT}.msixupload",
        "AgentGuardian.cdx.json",
        "THIRD_PARTY_NOTICES.md",
        "candidate-SHA256SUMS",
        "payload-manifest.json",
        "portable-SHA256SUMS",
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
    assert len(review["components"]) == 11
    assert all(component["redistribution"] == "pending" for component in review["components"])
    inno_setup = next(
        component for component in review["components"] if component["name"] == "Inno Setup"
    )
    assert inno_setup == {
        "name": "Inno Setup",
        "version": "7.0.2",
        "license_expression": None,
        "redistribution": "pending",
        "evidence_url": None,
    }


def test_personal_source_gate_requires_store_candidate_infrastructure() -> None:
    profile = json.loads(
        (ROOT / "release_profiles" / "personal_store_release.json").read_text(
            encoding="ascii"
        )
    )

    assert ".github/workflows/windows-store-candidate.yml" in profile["required_source_paths"]
    assert "requirements-build.lock" in profile["required_source_paths"]
    assert "requirements-dev.lock" in profile["required_source_paths"]
    assert "scripts/build_windows_msix.py" in profile["required_source_paths"]
    assert "scripts/verify_wack_report.py" in profile["required_source_paths"]
    assert "scripts/verify_windows_store_candidate.py" in profile["required_source_paths"]
    assert "tests/fixtures/wack/windows-app-certification-kit-10.0.26100.7705.xml" in profile[
        "required_source_paths"
    ]


def test_defusedxml_is_hash_locked_for_dev_and_build_phases() -> None:
    requirement = (
        "defusedxml==0.7.1 "
        "--hash=sha256:a352e7e428770286cc899e2542b6cdaedb2b4953ff269a210103ec58f6198a61"
    )

    for name in ("requirements-dev.lock", "requirements-build.lock"):
        assert requirement in (ROOT / name).read_text(encoding="utf-8").splitlines()
