from __future__ import annotations

import importlib
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
ISS_PATH = ROOT / "packaging" / "windows" / "AgentGuardianIntegrationsPreview.iss"
SPEC_PATH = ROOT / "packaging" / "windows" / "AgentGuardianIntegrationsPreview.spec"
LIFECYCLE_PATH = ROOT / "scripts" / "verify_windows_integrations_preview.ps1"


def _builder():
    try:
        return importlib.import_module(
            "scripts.build_windows_integrations_preview_installer"
        )
    except ModuleNotFoundError:
        pytest.fail("integrations preview installer builder is missing")


def test_preview_builder_exports_exact_identity() -> None:
    builder = _builder()
    assert builder.DISPLAY_VERSION == "0.3.0-preview.1"
    assert builder.FILE_VERSION == "0.3.0.1"
    assert builder.APP_ID == "{A64DBF23-FE14-4E04-89AE-0924666A03DE}"
    assert builder.INSTALLER_NAME == "AgentGuardian-Setup-0.3.0-preview.1-x64.exe"
    assert builder.INSTALL_DIRECTORY == (
        r"{localappdata}\Programs\AgentGuardian Integrations Preview"
    )
    assert builder.GUI_LAUNCHER == "AgentGuardian.exe"
    assert builder.MCP_LAUNCHER == "AgentGuardianMcp.exe"


def test_preview_inno_script_is_current_user_and_tasks_are_opt_in() -> None:
    script = ISS_PATH.read_text(encoding="ascii")
    folded = script.casefold()
    for required in (
        "AppId={{A64DBF23-FE14-4E04-89AE-0924666A03DE}",
        "DefaultDirName={localappdata}\\Programs\\AgentGuardian Integrations Preview",
        "PrivilegesRequired=lowest",
        "SetupArchitecture=x64",
        "ArchitecturesAllowed=x64compatible",
        "ArchitecturesInstallIn64BitMode=x64compatible",
        "MinVersion=10.0.22000",
        'Name: "codexskill"; Description: "Install AgentGuardian Codex Skill"; Flags: unchecked',
        'Name: "codexmcp"; Description: "Enable AgentGuardian local MCP"; Flags: unchecked',
    ):
        assert required in script
    for forbidden in (
        "http://",
        "https://",
        "download",
        "service",
        "schtasks",
        "startup",
        "elevation",
        "hklm",
        "[run]",
        "[uninstallrun]",
    ):
        assert forbidden not in folded
    assert "preparetoinstall" in folded
    assert "{userprofile}\\.agents\\skills\\agentguardian" in folded
    assert "{userprofile}\\.codex\\config.toml" in folded
    assert "{localappdata}\\agentguardian" in folded
    assert "--remove-codex-integration" in script


def test_preview_spec_has_one_shared_analysis_and_two_launchers() -> None:
    spec = SPEC_PATH.read_text(encoding="ascii")
    assert spec.count("Analysis(") == 1
    assert spec.count("PYZ(") == 1
    assert spec.count("COLLECT(") == 1
    assert "name='AgentGuardian'" in spec
    assert "name='AgentGuardianMcp'" in spec
    assert "console=False" in spec
    assert "console=True" in spec
    builder = (ROOT / "scripts" / "build_windows_portable.py").read_text(
        encoding="utf-8"
    )
    assert "_materialize_integrations_preview_skill" in builder
    assert 'project_root / "skills" / "agentguardian"' in builder
    assert "__main__.py" in spec


def test_preview_lifecycle_script_is_bounded_and_native() -> None:
    script = LIFECYCLE_PATH.read_text(encoding="ascii")
    folded = script.casefold()
    for required in (
        "param(",
        "candidate_sha",
        "installer_path",
        "evidence_path",
        "--stdio-mcp",
        "redirectstandardinput",
        "redirectstandardoutput",
        "codex-config-backup-v1.bin",
        "codex-integration-v1.json",
        "testmode",
        "frozen_02_baseline_missing",
        "get-nettcpconnection",
        "agentguardian.lnk",
        "mcp_prepare_schema_invalid",
        "mcp_authorized_run_invalid",
        "mcp_authorization_rejection_invalid",
        "default_tools_approval_mode = \"prompt\"",
        "test_mode_required",
        "evidence_path_ownership_conflict",
        "agentguardian-mcp-fixture",
        "agentguardian_inno_test_mode",
        "agentguardian_test_mode",
        '"/dir=$installroot"',
        "sha256]::create",
    ):
        assert required.casefold() in folded
    for forbidden in (
        "invoke-webrequest",
        "start-bitstransfer",
        "httpclient",
        "set-executionpolicy",
        "-verb runas",
        "api.openai.com",
        "get-filehash",
    ):
        assert forbidden not in folded


def test_preview_payload_integrity_rejects_tampering(tmp_path: Path) -> None:
    builder = _builder()
    portable = importlib.import_module("scripts.build_windows_portable")
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "AgentGuardian.exe").write_bytes(b"synthetic gui")
    (bundle / "_internal").mkdir()
    (bundle / "_internal" / "runtime.bin").write_bytes(b"synthetic runtime")
    manifest = portable.artifact_manifest(bundle)
    (bundle / "PAYLOAD-MANIFEST.json").write_bytes(
        portable.canonical_json_bytes(manifest)
    )
    checksummed = (*manifest["files"], {
        "path": "PAYLOAD-MANIFEST.json",
        "sha256": builder._sha256_file(bundle / "PAYLOAD-MANIFEST.json", builder.MAX_FILE_BYTES),
        "size": (bundle / "PAYLOAD-MANIFEST.json").stat().st_size,
    })
    (bundle / "SHA256SUMS").write_bytes(
        "".join(
            f"{entry['sha256']} *{entry['path']}\n"
            for entry in sorted(checksummed, key=lambda item: item["path"])
        ).encode("ascii")
    )

    builder.verify_payload_integrity(bundle)
    (bundle / "AgentGuardian.exe").write_bytes(b"tampered")
    with pytest.raises(ValueError, match="payload manifest"):
        builder.verify_payload_integrity(bundle)


def test_preview_bundle_profile_evidence_binds_source_sha(tmp_path: Path) -> None:
    verifier = importlib.import_module("scripts.verify_integrations_preview_profile")
    snapshot = verifier.load_profile_snapshot(ROOT, ROOT / "release_profiles" / "integrations_preview.json")
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    evidence = {
        "profile": "integrations_preview",
        "profile_sha256": snapshot.sha256,
        "schema": 1,
        "source_sha": "a" * 40,
        "status": "pass",
    }
    (bundle / "INTEGRATIONS-PREVIEW-PROFILE.json").write_bytes(
        verifier.canonical_json_bytes(evidence)
    )
    verifier.verify_profile_evidence(bundle, snapshot, "a" * 40)
    evidence["source_sha"] = "b" * 40
    (bundle / "INTEGRATIONS-PREVIEW-PROFILE.json").write_bytes(
        verifier.canonical_json_bytes(evidence)
    )
    with pytest.raises(verifier.ProfileViolation, match="PROFILE_PAYLOAD_IDENTITY_INVALID"):
        verifier.verify_profile_evidence(bundle, snapshot, "a" * 40)
