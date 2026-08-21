from __future__ import annotations

import hashlib
import importlib
import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.build_windows_portable import artifact_manifest, canonical_json_bytes
from scripts.verify_personal_release_profile import (
    load_profile_snapshot,
)


ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "release_profiles" / "personal_exe_private_beta.json"
SCRIPT_PATH = ROOT / "packaging" / "windows" / "AgentGuardian.iss"
COMMIT = "a" * 40
BUILT_AT = "2026-08-21T00:00:00Z"


def _builder():
    try:
        return importlib.import_module("scripts.build_windows_installer")
    except ModuleNotFoundError:
        pytest.fail("Windows installer builder is missing")


def _portable_bundle(tmp_path: Path) -> Path:
    bundle = tmp_path / "portable" / "AgentGuardian"
    internal = bundle / "_internal"
    internal.mkdir(parents=True)
    (bundle / "AgentGuardian.exe").write_bytes(b"MZ-synthetic-executable")
    (internal / "runtime.bin").write_bytes(b"synthetic-runtime")

    snapshot = load_profile_snapshot(ROOT, PROFILE_PATH)
    (bundle / "PERSONAL-RELEASE-PROFILE.json").write_bytes(
        canonical_json_bytes(
            {
                "profile": "personal_exe_private_beta",
                "profile_sha256": snapshot.sha256,
                "schema": 2,
                "status": "pass",
            }
        )
    )
    (bundle / "BUILD-METADATA.json").write_bytes(
        canonical_json_bytes(
            {
                "artifact_status": "unsigned_development_only",
                "build_dependencies": {},
                "build_mode": "pyinstaller_onedir",
                "built_at": BUILT_AT,
                "source_commit": COMMIT,
            }
        )
    )
    (bundle / "PAYLOAD-MANIFEST.json").write_bytes(
        canonical_json_bytes(artifact_manifest(bundle))
    )
    checksummed = artifact_manifest(bundle)
    (bundle / "SHA256SUMS").write_bytes(
        "".join(
            f"{entry['sha256']} *{entry['path']}\n"
            for entry in checksummed["files"]
        ).encode("ascii")
    )
    return bundle


def test_private_beta_profile_tracks_installer_build_inputs() -> None:
    profile = json.loads(PROFILE_PATH.read_text(encoding="ascii"))

    for relative in (
        "packaging/windows/AgentGuardian.iss",
        "scripts/build_windows_installer.py",
    ):
        assert relative in profile["package_input_paths"]
        assert relative in profile["required_source_paths"]


def test_inno_script_is_current_user_offline_and_static() -> None:
    if not SCRIPT_PATH.is_file():
        pytest.fail("Inno Setup script is missing")
    script = SCRIPT_PATH.read_text(encoding="utf-8")
    folded = script.casefold()

    for required in (
        "AppId={{7A76221A-CFA0-4860-B250-7083B736F3FB}",
        "AppVersion={#DisplayVersion}",
        "VersionInfoVersion={#FileVersion}",
        r"DefaultDirName={localappdata}\Programs\AgentGuardian",
        "DisableDirPage=yes",
        "UsePreviousAppDir=no",
        "PrivilegesRequired=lowest",
        "SetupArchitecture=x64",
        "ArchitecturesAllowed=x64compatible",
        "ArchitecturesInstallIn64BitMode=x64compatible",
        "MinVersion=10.0.22000",
        "Uninstallable=yes",
        "OutputBaseFilename=AgentGuardian-Setup-{#DisplayVersion}-x64",
        'Name: "{autoprograms}\\AgentGuardian"',
        'Name: "{autodesktop}\\AgentGuardian"',
        "Flags: unchecked",
    ):
        assert required in script

    for forbidden in (
        "privilegesrequiredoverridesallowed",
        "http://",
        "https://",
        "download",
        "signtool",
        "signing",
        "[run]",
        "[uninstallrun]",
        "hklm",
        "{commonappdata}",
        "{commonpf}",
        "{commonprograms}",
        "{commondesktop}",
        "schtasks",
        "service",
        "driver",
        "startup",
        "filesandordirs",
        "[uninstalldelete]",
    ):
        assert forbidden not in folded


def test_inno_script_rejects_downgrades_and_has_bounded_state_cleanup() -> None:
    script = SCRIPT_PATH.read_text(encoding="utf-8")
    folded = script.casefold()

    assert "[Registry]" in script
    assert (
        'Root: HKCU; Subkey: "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\'
        '{{7A76221A-CFA0-4860-B250-7083B736F3FB}_is1"; '
        'ValueType: string; ValueName: "AgentGuardianFileVersion"; '
        'ValueData: "{#FileVersion}"; Flags: uninsdeletevalue' in script
    )
    assert '_is1' in script
    assert (
        "UninstallKey = 'Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"
        "{7A76221A-CFA0-4860-B250-7083B736F3FB}_is1';" in script
    )
    assert "function InitializeSetup(): Boolean;" not in script
    assert "function PrepareToInstall(var NeedsRestart: Boolean): String;" in script
    assert "ComparePackedVersion" in script
    assert "StrToVersion" in script
    assert "procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);" in script
    assert "usUninstall" in script
    assert "UninstallSilent" in script
    assert "/PURGEAGENTGUARDIANSTATE" in script
    assert "--purge-protected-state" in script
    assert "SuppressibleMsgBox" in script
    assert "Abort;" in script
    assert "{app}\\AgentGuardian.exe" in script
    assert "{localappdata}\\agentguardian\\evidence-state-v1.bin" not in folded
    assert "del /" not in folded
    assert "rmdir" not in folded

    setup_body = script.split(
        "function PrepareToInstall(var NeedsRestart: Boolean): String;", 1
    )[1].split(
        "function HasPurgeStateParameter(): Boolean;", 1
    )[0]
    assert "WizardDirValue <> ExpandConstant('{localappdata}\\Programs\\AgentGuardian')" in setup_body
    assert "Result :=" in setup_body
    assert not re.search(r"(?<!Suppressible)MsgBox\(", setup_body)


def test_installer_builder_locks_the_complete_inno_script() -> None:
    builder = _builder()
    script = SCRIPT_PATH.read_bytes()
    lf_script = script.replace(b"\r\n", b"\n")

    assert b"\r" not in lf_script
    builder.verify_installer_script(lf_script)
    builder.verify_installer_script(lf_script.replace(b"\n", b"\r\n"))
    with pytest.raises(ValueError, match="installer script is not approved"):
        builder.verify_installer_script(lf_script + b"\n[Code]\n")
    with pytest.raises(ValueError, match="installer script is not approved"):
        builder.verify_installer_script(lf_script.replace(b"\n", b"\r", 1))


def test_compiler_digest_is_exact_and_fails_closed(tmp_path: Path) -> None:
    builder = _builder()
    compiler = tmp_path / "ISCC.exe"
    compiler.write_bytes(b"MZ-synthetic-iscc")

    assert builder.compiler_sha256(compiler) == hashlib.sha256(
        b"MZ-synthetic-iscc"
    ).hexdigest()
    with pytest.raises(ValueError, match="compiler digest is unavailable"):
        builder.compiler_sha256(tmp_path / "missing.exe")


def test_iscc_command_uses_only_fixed_defines(tmp_path: Path) -> None:
    builder = _builder()
    iscc = (tmp_path / "ISCC.exe").absolute()
    bundle = (tmp_path / "bundle").absolute()
    output = (tmp_path / "output").absolute()

    command = builder.build_iscc_command(
        iscc=iscc,
        script=SCRIPT_PATH.absolute(),
        bundle_root=bundle,
        output_root=output,
        source_commit=COMMIT,
        built_at=BUILT_AT,
    )

    assert command == (
        str(iscc),
        "/Qp",
        f"/DBundleRoot={bundle}",
        f"/DOutputRoot={output}",
        "/DDisplayVersion=0.2.0-beta.1",
        "/DFileVersion=0.2.0.1",
        f"/DSourceCommit={COMMIT}",
        f"/DBuiltAt={BUILT_AT}",
        str(SCRIPT_PATH.absolute()),
    )
    assert all("http" not in item.casefold() for item in command)
    assert not any("password" in item.casefold() for item in command)


@pytest.mark.parametrize(
    "unsafe",
    (
        'C:\\unsafe"path',
        "C:\\unsafe\npath",
        "C:\\unsafe\rpath",
    ),
)
def test_iscc_command_rejects_unsafe_define_values(
    tmp_path: Path, unsafe: str
) -> None:
    builder = _builder()

    with pytest.raises(ValueError, match="unsafe compiler define"):
        builder.build_iscc_command(
            iscc=(tmp_path / "ISCC.exe").absolute(),
            script=SCRIPT_PATH.absolute(),
            bundle_root=Path(unsafe),
            output_root=(tmp_path / "output").absolute(),
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )


def test_portable_bundle_manifest_is_exact_and_profile_bound(tmp_path: Path) -> None:
    builder = _builder()
    bundle = _portable_bundle(tmp_path)
    snapshot = load_profile_snapshot(ROOT, PROFILE_PATH)

    builder.verify_portable_bundle(
        bundle,
        snapshot,
        source_commit=COMMIT,
        built_at=BUILT_AT,
    )


def test_portable_bundle_rejects_unexpected_file(tmp_path: Path) -> None:
    builder = _builder()
    bundle = _portable_bundle(tmp_path)
    (bundle / "unexpected.dll").write_bytes(b"unexpected")
    snapshot = load_profile_snapshot(ROOT, PROFILE_PATH)

    with pytest.raises(ValueError, match="portable payload file set is invalid"):
        builder.verify_portable_bundle(
            bundle,
            snapshot,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )


def test_portable_bundle_rejects_changed_profile_evidence(tmp_path: Path) -> None:
    builder = _builder()
    bundle = _portable_bundle(tmp_path)
    evidence = bundle / "PERSONAL-RELEASE-PROFILE.json"
    evidence.write_bytes(evidence.read_bytes().replace(b'"status":"pass"', b'"status":"fail"'))
    snapshot = load_profile_snapshot(ROOT, PROFILE_PATH)

    with pytest.raises(ValueError, match="portable profile evidence is invalid"):
        builder.verify_portable_bundle(
            bundle,
            snapshot,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )


def test_portable_bundle_rejects_changed_source_metadata(tmp_path: Path) -> None:
    builder = _builder()
    bundle = _portable_bundle(tmp_path)
    metadata = bundle / "BUILD-METADATA.json"
    metadata.write_bytes(metadata.read_bytes().replace(COMMIT.encode(), b"b" * 40))
    snapshot = load_profile_snapshot(ROOT, PROFILE_PATH)

    with pytest.raises(ValueError, match="portable build metadata is invalid"):
        builder.verify_portable_bundle(
            bundle,
            snapshot,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )


def test_build_installer_invokes_iscc_without_shell_and_rechecks_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    builder = _builder()
    bundle = _portable_bundle(tmp_path)
    output = (tmp_path / "installer-output").absolute()
    iscc = (tmp_path / "ISCC.exe").absolute()
    iscc.write_bytes(b"MZ-synthetic-iscc")
    git_calls: list[tuple[str, ...]] = []
    compiler_calls: list[tuple[tuple[str, ...], dict[str, object]]] = []

    def fake_git(_root: Path, *arguments: str) -> str:
        git_calls.append(arguments)
        return COMMIT if arguments == ("rev-parse", "HEAD") else ""

    def fake_run(command: tuple[str, ...], **kwargs: object) -> SimpleNamespace:
        compiler_calls.append((command, kwargs))
        (output / "AgentGuardian-Setup-0.2.0-beta.1-x64.exe").write_bytes(
            b"MZ-synthetic-installer"
        )
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(builder.sys, "platform", "win32")
    monkeypatch.setattr(builder, "_git", fake_git)
    monkeypatch.setattr(
        builder,
        "compiler_sha256",
        lambda _path: builder._COMPILER_SHA256,
    )
    monkeypatch.setattr(builder, "validate_frozen_layout", lambda *args: None)
    monkeypatch.setattr(builder.subprocess, "run", fake_run)

    installer = builder.build_installer(
        ROOT,
        bundle,
        output,
        iscc=iscc,
        source_commit=COMMIT,
        built_at=BUILT_AT,
    )

    assert installer == output / "AgentGuardian-Setup-0.2.0-beta.1-x64.exe"
    assert installer.read_bytes() == b"MZ-synthetic-installer"
    assert len(compiler_calls) == 1
    command, kwargs = compiler_calls[0]
    assert command[0] == str(iscc)
    assert kwargs == {"check": True, "cwd": ROOT.resolve(), "shell": False}
    assert git_calls == [
        ("rev-parse", "HEAD"),
        ("status", "--porcelain=v1", "--untracked-files=all"),
        ("rev-parse", "HEAD"),
        ("status", "--porcelain=v1", "--untracked-files=all"),
    ]


def test_build_installer_rejects_wrong_compiler_digest_before_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    builder = _builder()
    bundle = _portable_bundle(tmp_path)
    output = (tmp_path / "installer-output").absolute()
    iscc = (tmp_path / "ISCC.exe").absolute()
    iscc.write_bytes(b"MZ-synthetic-iscc")

    monkeypatch.setattr(builder.sys, "platform", "win32")
    monkeypatch.setattr(builder, "_git", lambda *_args: COMMIT)
    monkeypatch.setattr(builder, "compiler_sha256", lambda _path: "0" * 64)

    with pytest.raises(ValueError, match="Inno Setup compiler digest is invalid"):
        builder.build_installer(
            ROOT,
            bundle,
            output,
            iscc=iscc,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )

    assert not output.exists()


def test_build_installer_rejects_existing_output_root(tmp_path: Path) -> None:
    builder = _builder()
    output = (tmp_path / "installer-output").absolute()
    output.mkdir()

    with pytest.raises(ValueError, match="installer output root already exists"):
        builder.build_installer(
            ROOT,
            (tmp_path / "bundle").absolute(),
            output,
            iscc=(tmp_path / "ISCC.exe").absolute(),
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )


def test_build_installer_rejects_reparse_compiler_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    builder = _builder()
    iscc = (tmp_path / "ISCC.exe").absolute()
    iscc.write_bytes(b"MZ-synthetic-iscc")
    real_check = builder._has_reparse_component
    monkeypatch.setattr(
        builder,
        "_has_reparse_component",
        lambda path: path == iscc or real_check(path),
    )

    with pytest.raises(ValueError, match="compiler path is invalid"):
        builder.build_installer(
            ROOT,
            (tmp_path / "bundle").absolute(),
            (tmp_path / "output").absolute(),
            iscc=iscc,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )


def test_exe_workflow_pins_inno_and_runs_native_lifecycle() -> None:
    path = ROOT / ".github" / "workflows" / "windows-exe-private-beta.yml"
    if not path.is_file():
        pytest.fail("Windows EXE private-beta workflow is missing")
    workflow = path.read_text(encoding="utf-8")

    for required in (
        "workflow_dispatch:",
        "push:",
        "- agent/founder-alpha",
        "candidate_sha:",
        "runs-on: windows-2025",
        "timeout-minutes: 45",
        "^[0-9a-f]{40}$",
        "WORKFLOW_SOURCE_COMMIT: ${{ github.workflow_sha }}",
        "persist-credentials: false",
        "EVIDENCE_ROOT=$env:RUNNER_TEMP\\agentguardian-private-beta-evidence",
        "is-7_0_2",
        "innosetup-7.0.2-x64.exe",
        "5ad54ca3def786f8f4212552e54cc6d8d61329e2d24a1cfee0571d42c2684ff1",
        "0ff6140d641f84b64204a2c4d52207c6fc437c9f4db8779c83083d84f7e3d70d",
        "Get-FileHash -Algorithm SHA256 -LiteralPath $env:ISCC",
        "gh release verify-asset",
        "2.93.0",
        "Get-AuthenticodeSignature",
        "CN=Pyrsys B.V., O=Pyrsys B.V., S=Noord-Holland, C=NL",
        "requirements-dev.lock",
        "requirements-build.lock",
        "scripts/build_windows_portable.py",
        "scripts/build_windows_installer.py",
        "scripts/verify_windows_installer.ps1",
        "scripts/verify_windows_installer_candidate.py",
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
        "retention-days: 14",
        "agentguardian-personal-exe-candidate-${{ env.EXPECTED_SOURCE_COMMIT }}",
    ):
        assert required in workflow

    assert "gh release create" not in workflow.casefold()
    assert "signtool" not in workflow.casefold()
    assert "partner center" not in workflow.casefold()
    assert "\n  pull_request:" not in workflow
    assert "public repository artifact" in workflow.casefold()
    assert workflow.index("Require local fixed drives") < workflow.index(
        "actions/setup-python@"
    )
    assert workflow.index("scripts/build_windows_installer.py") < workflow.index(
        "& $env:ISCC /Qp"
    )
    installer_step = workflow.split(
        "Build lower baseline and exact candidate installers", 1
    )[1].split("Assemble and verify exact candidate evidence", 1)[0]
    candidate_build = installer_step.split(
        "New-Item -ItemType Directory -Path $env:BASE_OUTPUT", 1
    )[0]
    assert "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }" in candidate_build
    assert "$baseVersionInfo.FileMajorPart" in installer_step
    assert "$baseVersionInfo.FileMinorPart" in installer_step
    assert "$baseVersionInfo.FileBuildPart" in installer_step
    assert "$baseVersionInfo.FilePrivatePart" in installer_step
    assert ".VersionInfo.FileVersion -cne" not in installer_step

    lifecycle_step = workflow.split(
        "Run native install upgrade downgrade and uninstall lifecycle", 1
    )[1].split("Validate exact eight-file upload allowlist", 1)[0]
    assert "$lifecycleExitCode = $LASTEXITCODE" in lifecycle_step
    assert "scripts/verify_windows_installer_lifecycle_evidence.py" in lifecycle_step
    assert "--lifecycle-exit-code $lifecycleExitCode" in lifecycle_step
    assert "native installer lifecycle failed: $($decision.error)" in lifecycle_step
    assert "Get-Content -LiteralPath $env:LIFECYCLE_EVIDENCE" not in lifecycle_step

    job_environment = workflow.split("    env:", 1)[1].split("    steps:", 1)[0]
    download_step = workflow.split("Download and verify pinned Inno Setup", 1)[1].split(
        "Install verified Inno compiler privately", 1
    )[0]
    assert "GH_TOKEN" not in job_environment
    assert "${{ runner.temp }}" not in job_environment
    assert "GH_TOKEN: ${{ github.token }}" in download_step


def test_exe_workflow_uploads_only_the_candidate_eight_file_allowlist() -> None:
    workflow = (
        ROOT / ".github" / "workflows" / "windows-exe-private-beta.yml"
    ).read_text(encoding="utf-8")
    assert workflow.count("permissions:") == 1
    assert "contents: write" not in workflow
    assert workflow.count(
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
    ) == 1
    assert workflow.count("actions/upload-artifact@") == 1
    assert workflow.count("path: |") == 1
    upload = workflow.split("path: |", 1)[1]
    uploaded = []
    for line in upload.splitlines()[1:]:
        if not line.startswith("            "):
            break
        value = line.strip()
        if value:
            uploaded.append(value)

    assert uploaded == [
        "${{ runner.temp }}/agentguardian-private-beta-evidence/AgentGuardian-Setup-0.2.0-beta.1-x64.exe",
        "${{ runner.temp }}/agentguardian-private-beta-evidence/AgentGuardian.cdx.json",
        "${{ runner.temp }}/agentguardian-private-beta-evidence/BUILD-METADATA.json",
        "${{ runner.temp }}/agentguardian-private-beta-evidence/PAYLOAD-MANIFEST.json",
        "${{ runner.temp }}/agentguardian-private-beta-evidence/PRIVATE-BETA-MANIFEST.json",
        "${{ runner.temp }}/agentguardian-private-beta-evidence/PRIVATE-BETA-README.txt",
        "${{ runner.temp }}/agentguardian-private-beta-evidence/SHA256SUMS",
        "${{ runner.temp }}/agentguardian-private-beta-evidence/THIRD_PARTY_NOTICES.md",
    ]
