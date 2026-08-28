from __future__ import annotations

import hashlib
import importlib
import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
ISS_PATH = ROOT / "packaging" / "windows" / "AgentGuardianIntegrationsPreview.iss"
SPEC_PATH = ROOT / "packaging" / "windows" / "AgentGuardianIntegrationsPreview.spec"
LIFECYCLE_PATH = ROOT / "scripts" / "verify_windows_integrations_preview.ps1"
DISCLOSURE_MARKERS = (
    "AgentGuardian 0.3.0 Public Preview (unsigned).",
    "Use only personal non-regulated configuration data.",
    "Windows may show Unknown Publisher or SmartScreen warnings.",
    "Reports and redacted results may be visible to the configured host.",
)


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


def test_preview_installer_attestation_path_is_outside_installer_output_root(
    tmp_path: Path,
) -> None:
    builder = _builder()
    output = tmp_path / "installer-output"
    installer = output / builder.INSTALLER_NAME

    attestation = builder.installer_attestation_path(installer)

    assert attestation == tmp_path / f"{builder.INSTALLER_NAME}.build.json"
    assert attestation.parent == tmp_path
    assert attestation.parent != output


def test_preview_installer_attestation_is_canonical_and_exclusive(
    tmp_path: Path,
) -> None:
    builder = _builder()
    verifier = importlib.import_module("scripts.verify_integrations_preview_profile")
    snapshot = verifier.load_profile_snapshot(
        ROOT, ROOT / "release_profiles" / "integrations_preview.json"
    )
    output = tmp_path / "installer-output"
    output.mkdir()
    installer = output / builder.INSTALLER_NAME
    installer_bytes = b"synthetic-installer" * 32
    installer.write_bytes(installer_bytes)
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    bundle_values = {
        "BUILD-METADATA.json": b"metadata",
        "INTEGRATIONS-PREVIEW-PROFILE.json": b"profile-evidence",
        "PAYLOAD-MANIFEST.json": b"manifest",
        "SHA256SUMS": b"checksums",
    }
    for name, value in bundle_values.items():
        (bundle / name).write_bytes(value)

    attestation = builder.write_installer_attestation(
        installer,
        bundle,
        project_root=ROOT,
        profile_snapshot=snapshot,
        source_commit="a" * 40,
        built_at="2026-08-28T00:00:00Z",
    )

    raw = attestation.read_bytes()
    value = json.loads(raw.decode("ascii"))
    assert raw == builder.canonical_json_bytes(value)
    assert set(value) == {
        "artifact_name",
        "artifact_sha256",
        "artifact_size",
        "artifact_status",
        "built_at",
        "bundle",
        "compiler_sha256",
        "compiler_version",
        "installer_script_sha256",
        "profile",
        "profile_sha256",
        "schema",
        "source_commit",
        "version",
    }
    assert value["artifact_name"] == builder.INSTALLER_NAME
    assert value["artifact_sha256"] == hashlib.sha256(installer_bytes).hexdigest()
    assert value["artifact_size"] == len(installer_bytes)
    assert value["artifact_status"] == "unsigned_public_preview"
    assert value["built_at"] == "2026-08-28T00:00:00Z"
    assert value["compiler_sha256"] == snapshot.profile["inno_setup_iscc_sha256"]
    assert value["compiler_version"] == snapshot.profile["inno_setup_version"]
    assert value["profile"] == "integrations_preview"
    assert value["profile_sha256"] == snapshot.sha256
    assert value["schema"] == 1
    assert value["source_commit"] == "a" * 40
    assert value["version"] == builder.DISPLAY_VERSION
    assert value["bundle"] == {
        "build_metadata_sha256": hashlib.sha256(b"metadata").hexdigest(),
        "checksums_sha256": hashlib.sha256(b"checksums").hexdigest(),
        "payload_manifest_sha256": hashlib.sha256(b"manifest").hexdigest(),
        "profile_evidence_sha256": hashlib.sha256(b"profile-evidence").hexdigest(),
    }
    before = raw
    with pytest.raises(ValueError, match="installer attestation already exists"):
        builder.write_installer_attestation(
            installer,
            bundle,
            project_root=ROOT,
            profile_snapshot=snapshot,
            source_commit="a" * 40,
            built_at="2026-08-28T00:00:00Z",
        )
    assert attestation.read_bytes() == before


def test_preview_builder_keeps_single_exe_output_and_writes_attestation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    builder = _builder()
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    output = tmp_path / "installer-output"
    compiler = tmp_path / "ISCC.exe"
    compiler.write_bytes(b"synthetic-compiler")
    attestation = tmp_path / f"{builder.INSTALLER_NAME}.build.json"
    observed: dict[str, object] = {}

    def fake_git(_root: Path, *arguments: str) -> str:
        return "a" * 40 if arguments == ("rev-parse", "HEAD") else ""

    def fake_run(_command: tuple[str, ...], **_kwargs: object) -> SimpleNamespace:
        (output / builder.INSTALLER_NAME).write_bytes(b"synthetic-installer")
        return SimpleNamespace(returncode=0)

    def fake_attestation(*args: object, **kwargs: object) -> Path:
        observed["args"] = args
        observed.update(kwargs)
        attestation.write_bytes(b"{}")
        return attestation

    monkeypatch.setattr(builder.sys, "platform", "win32")
    monkeypatch.setattr(builder, "_git", fake_git)
    monkeypatch.setattr(builder, "compiler_sha256", lambda _path: builder.COMPILER_SHA256)
    monkeypatch.setattr(builder, "_require_current_source_identity", lambda *_args: None)
    monkeypatch.setattr(builder, "verify_profile", lambda *_args: None)
    monkeypatch.setattr(builder, "verify_installer_script", lambda *_args: None)
    monkeypatch.setattr(builder, "validate_preview_layout", lambda *_args: None)
    monkeypatch.setattr(builder, "verify_payload", lambda *_args: None)
    monkeypatch.setattr(builder, "verify_payload_integrity", lambda *_args: None)
    monkeypatch.setattr(builder, "verify_profile_evidence", lambda *_args: None)
    monkeypatch.setattr(builder, "require_profile_snapshot_unchanged", lambda *_args: None)
    monkeypatch.setattr(builder.subprocess, "run", fake_run)
    monkeypatch.setattr(builder, "write_installer_attestation", fake_attestation)

    installer = builder.build_installer(
        ROOT,
        bundle,
        output,
        iscc=compiler,
        source_commit="a" * 40,
        built_at="2026-08-28T00:00:00Z",
        attestation_path=attestation,
    )

    assert installer == output / builder.INSTALLER_NAME
    assert tuple(path.name for path in output.iterdir()) == (builder.INSTALLER_NAME,)
    assert observed["attestation_path"] == attestation
    assert observed["source_commit"] == "a" * 40
    assert observed["built_at"] == "2026-08-28T00:00:00Z"


def test_preview_inno_script_is_current_user_and_tasks_are_opt_in() -> None:
    script = ISS_PATH.read_text(encoding="ascii")
    folded = script.casefold()
    for marker in DISCLOSURE_MARKERS:
        assert marker in script
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


def test_preview_installer_script_verification_requires_all_disclosures() -> None:
    builder = _builder()
    script = ISS_PATH.read_bytes()
    builder.verify_installer_script(script)
    for marker in DISCLOSURE_MARKERS:
        missing = script.replace(marker.encode("ascii"), b"", 1)
        with pytest.raises(ValueError, match="installer script is not approved"):
            builder.verify_installer_script(missing)


def test_preview_installer_script_verification_rejects_tampering() -> None:
    builder = _builder()
    script = bytearray(ISS_PATH.read_bytes())
    script[script.index(b"SelectedTargets")] = ord("X")
    with pytest.raises(ValueError, match="installer script is not approved"):
        builder.verify_installer_script(bytes(script))


def test_preview_inno_script_does_not_start_pascal_lines_with_preprocessor_marker() -> None:
    script = ISS_PATH.read_text(encoding="ascii")
    invalid_lines = [
        line for line in script.splitlines() if re.match(r"^\s+#\d", line)
    ]
    assert invalid_lines == []


def test_preview_selected_targets_ends_disclosure_before_next_assignment() -> None:
    lines = ISS_PATH.read_text(encoding="ascii").splitlines()
    disclosure_index = next(
        index
        for index, line in enumerate(lines)
        if "Reports and redacted results may be visible to the configured host." in line
    )
    assert lines[disclosure_index].strip() == (
        "'Reports and redacted results may be visible to the configured host.' + #13#10;"
    )
    assert lines[disclosure_index + 1].strip() == (
        "Result := Result + #13#10 + 'Selected categories:'"
        " + #13#10;"
    )


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
        "structuredContent",
        "inputSchema",
        "python_path",
        "default_tools_approval_mode = \"prompt\"",
        "test_mode_required",
        "evidence_path_ownership_conflict",
        "agentguardian-mcp-fixture",
        "agentguardian_inno_test_mode",
        "agentguardian_test_mode",
        '/dir="',
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


def test_preview_lifecycle_compares_installed_payload_to_portable_manifest() -> None:
    script = LIFECYCLE_PATH.read_text(encoding="ascii").casefold()
    for required in (
        "portable_bundle_root",
        "payload-manifest.json",
        "assert-installed-payload-matches-bundle",
        "payload_tree_match",
        "installed_payload_file_count",
        "portable_payload_file_count",
    ):
        assert required in script


def test_preview_lifecycle_retries_bounded_inno_self_delete_cleanup() -> None:
    script = LIFECYCLE_PATH.read_text(encoding="ascii").casefold()
    for required in (
        "function remove-fixtureroot",
        "function wait-pathabsent",
        "fixture_cleanup_timeout",
        "uninstall_cleanup_timeout",
        "getfullpath([io.path]::gettemppath())",
        "start-sleep -milliseconds 250",
        "remove-fixtureroot $fixtureroot",
        "wait-pathabsent $installroot",
    ):
        assert required in script


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
