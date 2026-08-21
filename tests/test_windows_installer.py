from __future__ import annotations

import builtins
import importlib
import json
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
        "[registry]",
        "hklm",
        "{commonappdata}",
        "{commonpf}",
        "{commonprograms}",
        "{commondesktop}",
        "schtasks",
        "service",
        "driver",
        "startup",
    ):
        assert forbidden not in folded


def test_installer_builder_locks_the_complete_inno_script() -> None:
    builder = _builder()
    script = SCRIPT_PATH.read_bytes()

    builder.verify_installer_script(script)
    with pytest.raises(ValueError, match="installer script is not approved"):
        builder.verify_installer_script(script + b"\n[Code]\n")


def test_compiler_version_fails_closed_when_pefile_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _builder()
    real_import = builtins.__import__

    def missing_pefile(name, *args, **kwargs):
        if name == "pefile":
            raise ModuleNotFoundError("synthetic missing pefile")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", missing_pefile)
    with pytest.raises(ValueError, match="compiler version is unavailable"):
        builder.compiler_file_version(Path("C:/synthetic/ISCC.exe"))


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
    monkeypatch.setattr(builder, "compiler_file_version", lambda _path: "7.0.2")
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


def test_build_installer_rejects_wrong_compiler_version_before_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    builder = _builder()
    bundle = _portable_bundle(tmp_path)
    output = (tmp_path / "installer-output").absolute()
    iscc = (tmp_path / "ISCC.exe").absolute()
    iscc.write_bytes(b"MZ-synthetic-iscc")

    monkeypatch.setattr(builder.sys, "platform", "win32")
    monkeypatch.setattr(builder, "_git", lambda *_args: COMMIT)
    monkeypatch.setattr(builder, "compiler_file_version", lambda _path: "7.0.1")

    with pytest.raises(ValueError, match="Inno Setup compiler version is invalid"):
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
