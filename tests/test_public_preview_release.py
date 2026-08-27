from __future__ import annotations

import ctypes
import hashlib
import importlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from contextlib import contextmanager
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40
BUILT_AT = "2026-08-27T00:00:00Z"
ASSET_NAMES = (
    "AgentGuardian-0.3.0-preview.1-windows-x64.zip",
    "AgentGuardian-Setup-0.3.0-preview.1-x64.exe",
    "AgentGuardian-Setup-Windows-x64.exe",
    "AgentGuardian-Skill-0.2.0.zip",
    "DOWNLOAD-METADATA.json",
    "LICENSE",
    "SHA256SUMS",
    "THIRD_PARTY_NOTICES.md",
)
DOWNLOAD_VERIFIER = ROOT / "scripts" / "verify_public_preview_download.ps1"
PRIMARY_DOWNLOAD_URL = (
    "https://github.com/yangjing6213-dev/AgentGuardian/releases/latest/download/"
    "AgentGuardian-Setup-Windows-x64.exe"
)


def test_documented_download_route_matches_profile_and_is_not_temporary() -> None:
    profile = json.loads(
        (ROOT / "release_profiles" / "integrations_preview.json").read_text(
            encoding="ascii"
        )
    )
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    document = (ROOT / "docs" / "security" / "integrations-preview.md").read_text(
        encoding="utf-8"
    )
    release_url = str(profile["release_download_url"])

    assert release_url in readme
    assert release_url in document
    assert tuple(profile["release_assets"]) == ASSET_NAMES
    for asset in profile["release_assets"]:
        assert asset in readme
        assert asset in document
    for text in (readme, document):
        assert "releases/download/" not in text
        assert "actions/artifacts/" not in text
        assert "hqwzhu" not in text.casefold()
        for forbidden in profile["forbidden_document_promises"]:
            assert str(forbidden).casefold() not in text.casefold()
    assert "--portable-bundle-root" in document
    assert "structural validation" in document
    assert "not public-release evidence" in document


def test_public_download_verifier_has_fixed_bounded_request_contract() -> None:
    script = DOWNLOAD_VERIFIER.read_text(encoding="ascii")

    assert "Set-StrictMode -Version Latest" in script
    assert f"$downloadUrl = '{PRIMARY_DOWNLOAD_URL}'" in script
    assert script.count(PRIMARY_DOWNLOAD_URL) == 1
    assert "raw-argument parsing" in script
    assert "$rawArguments = @($args)" in script
    assert "$rawArguments.Count -ne 2" in script
    assert "[string]$rawArguments[0] -cne '-ExpectedSha256'" in script
    assert "$ExpectedSha256 = [string]$rawArguments[1]" in script
    assert "[Parameter(" not in script
    assert "CmdletBinding" not in script
    assert "param(" not in script
    assert "-ExpectedSha256" in script
    assert "$ExpectedSha256.Length -ne 64" in script
    assert "-cnotmatch '\\A[0-9a-f]{64}\\z'" in script
    assert script.count("curl.exe") == 1
    for flag in (
        "--fail",
        "--location",
        "--max-time 30",
        "--proto '=https'",
        "--tlsv1.2",
        "--output",
    ):
        assert flag in script
    assert "1>$null 2>$null" in script
    for forbidden in (
        "--retry",
        "api.github.com",
        "/api/",
        "Authorization",
        "Bearer ",
        "token",
        "hqwzhu",
        "mirror",
        "alternate",
    ):
        assert forbidden.casefold() not in script.casefold()


def test_public_download_verifier_has_safe_digest_json_and_cleanup_contract() -> None:
    script = DOWNLOAD_VERIFIER.read_text(encoding="ascii")

    assert "Get-FileHash -Algorithm SHA256" in script
    assert "-ine $normalizedExpected" in script
    assert "ConvertTo-Json -Compress" in script
    assert 'actual_sha256' in script
    assert 'expected_sha256' in script
    assert 'status' in script
    assert 'error' in script
    assert 'exit $exitCode' in script
    assert 'finally' in script
    assert 'Remove-Item -LiteralPath $tempPath' in script
    assert '[Guid]::NewGuid()' in script
    assert 'Start-Process' not in script
    assert 'Invoke-Expression' not in script
    assert '& $tempPath' not in script
    assert 'DOWNLOAD_REQUEST_FAILED' in script
    assert 'DOWNLOAD_FILE_MISSING' in script
    assert 'DOWNLOAD_FILE_EMPTY' in script
    assert 'DOWNLOAD_DIGEST_MISMATCH' in script
    assert 'EXPECTED_SHA256_INVALID' in script


def test_public_download_verifier_validates_digest_before_network_and_profile_lists_it() -> None:
    script = DOWNLOAD_VERIFIER.read_text(encoding="ascii")
    validation = script.index("EXPECTED_SHA256_INVALID")
    request = script.index("curl.exe")
    assert validation < request
    assert "[ValidatePattern" not in script

    profile = json.loads(
        (ROOT / "release_profiles" / "integrations_preview.json").read_text(
            encoding="ascii"
        )
    )
    relative = "scripts/verify_public_preview_download.ps1"
    assert relative in profile["package_input_paths"]
    assert relative in profile["required_source_paths"]


def test_invalid_expected_digest_emits_fixed_json_without_network() -> None:
    powershell = shutil.which("pwsh") or shutil.which("powershell.exe")
    if powershell is None:
        pytest.skip("PowerShell is unavailable")

    completed = subprocess.run(
        [
            powershell,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(DOWNLOAD_VERIFIER),
            "-ExpectedSha256",
            "not-a-sha256",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode != 0
    assert completed.stderr == ""
    payload = json.loads(completed.stdout)
    assert payload == {
        "actual_sha256": None,
        "error": "EXPECTED_SHA256_INVALID",
        "expected_sha256": None,
        "status": "fail",
    }
    assert completed.stdout.strip() == json.dumps(payload, separators=(",", ":"))
    assert str(ROOT) not in completed.stdout


def _run_download_verifier_with_curl_sentinel(
    tmp_path: Path, invocation: str
) -> tuple[subprocess.CompletedProcess[str], Path]:
    powershell = shutil.which("pwsh") or shutil.which("powershell.exe")
    if powershell is None:
        pytest.skip("PowerShell is unavailable")

    marker = tmp_path / "curl-called.txt"
    target = str(DOWNLOAD_VERIFIER).replace("'", "''")
    marker_literal = str(marker).replace("'", "''")
    harness = tmp_path / "invoke-download-verifier.ps1"
    harness.write_text(
        "\n".join(
            (
                "$ErrorActionPreference = 'Stop'",
                f"$marker = '{marker_literal}'",
                "function curl.exe {",
                "    Set-Content -LiteralPath $marker -Value 'called' -Encoding ascii",
                "    $global:LASTEXITCODE = 0",
                "}",
                # Keep the probe offline even if command resolution ignores the function.
                "$env:PATH = $marker.DirectoryName",
                f"& '{target}' {invocation}".rstrip(),
                "exit 1",
            )
        )
        + "\n",
        encoding="utf-8-sig",
    )
    return (
        subprocess.run(
            [
                powershell,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(harness),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        ),
        marker,
    )


def _run_download_verifier_with_mocked_commands(
    tmp_path: Path,
    invocation: str,
    *,
    fail_hash: bool = False,
    fail_remove: bool = False,
) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
    powershell = shutil.which("pwsh") or shutil.which("powershell.exe")
    if powershell is None:
        pytest.skip("PowerShell is unavailable")

    temp_directory = tmp_path / "powershell-temp"
    temp_directory.mkdir()
    marker = tmp_path / "curl-called.txt"
    target = str(DOWNLOAD_VERIFIER).replace("'", "''")
    temp_literal = str(temp_directory).replace("'", "''")
    marker_literal = str(marker).replace("'", "''")
    harness = tmp_path / "invoke-download-verifier-mocks.ps1"
    lines = [
        "$ErrorActionPreference = 'Stop'",
        f"$tempDirectory = '{temp_literal}'",
        "$env:TEMP = $tempDirectory",
        "$env:TMP = $tempDirectory",
        f"$marker = '{marker_literal}'",
        "$payload = [Text.Encoding]::ASCII.GetBytes('known-download')",
        "function curl.exe {",
        "    $outputIndex = -1",
        "    for ($i = 0; $i -lt $args.Count; $i++) {",
        "        if ([string]$args[$i] -ceq '--output') {",
        "            $outputIndex = $i",
        "            break",
        "        }",
        "    }",
        "    if ($outputIndex -lt 0 -or $outputIndex + 1 -ge $args.Count) {",
        "        $global:LASTEXITCODE = 2",
        "        return",
        "    }",
        "    [IO.File]::WriteAllBytes([string]$args[$outputIndex + 1], $payload)",
        "    [IO.File]::WriteAllText($marker, 'called')",
        "    $global:LASTEXITCODE = 0",
        "}",
        # Keep the probe offline even if command resolution ignores the function.
        "$env:PATH = $tempDirectory",
    ]
    if fail_hash:
        lines.extend(
            (
                "function Get-FileHash {",
                "    throw 'unexpected hash failure'",
                "}",
            )
        )
    if fail_remove:
        lines.extend(
            (
                "function Remove-Item {",
                "    param([string]$LiteralPath, [switch]$Force, [string]$ErrorAction)",
                "    [IO.File]::WriteAllText($marker, 'remove-called')",
                "    throw 'cleanup sentinel'",
                "}",
            )
        )
    lines.extend(
        (
            f"& '{target}' {invocation}".rstrip(),
            "$scriptExitCode = [int]$LASTEXITCODE",
            "exit $scriptExitCode",
        )
    )
    harness.write_text("\n".join(lines) + "\n", encoding="utf-8-sig")
    return (
        subprocess.run(
            [
                powershell,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(harness),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        ),
        temp_directory,
        marker,
    )


def test_digest_mismatch_keeps_safe_actual_and_expected_hashes(
    tmp_path: Path,
) -> None:
    expected = "a" * 64
    actual = hashlib.sha256(b"known-download").hexdigest()
    completed, temp_directory, marker = _run_download_verifier_with_mocked_commands(
        tmp_path,
        f"-ExpectedSha256 '{expected}'",
    )

    try:
        assert completed.returncode == 1
        assert completed.stderr == ""
        payload = json.loads(completed.stdout)
        assert payload == {
            "actual_sha256": actual,
            "error": "DOWNLOAD_DIGEST_MISMATCH",
            "expected_sha256": expected,
            "status": "fail",
        }
        assert completed.stdout.strip() == json.dumps(payload, separators=(",", ":"))
        assert marker.read_text(encoding="utf-8") == "called"
        assert not list(temp_directory.glob("AgentGuardian-public-preview-*.exe"))
        assert str(ROOT) not in completed.stdout + completed.stderr
    finally:
        for path in temp_directory.glob("AgentGuardian-public-preview-*.exe"):
            path.unlink(missing_ok=True)


def test_unexpected_post_validation_error_uses_generic_failure_code(
    tmp_path: Path,
) -> None:
    expected = hashlib.sha256(b"known-download").hexdigest()
    completed, temp_directory, _marker = _run_download_verifier_with_mocked_commands(
        tmp_path,
        f"-ExpectedSha256 '{expected}'",
        fail_hash=True,
    )

    try:
        assert completed.returncode == 1
        assert completed.stderr == ""
        payload = json.loads(completed.stdout)
        assert payload == {
            "actual_sha256": None,
            "error": "DOWNLOAD_VERIFICATION_FAILED",
            "expected_sha256": expected,
            "status": "fail",
        }
        assert completed.stdout.strip() == json.dumps(payload, separators=(",", ":"))
        assert "EXPECTED_SHA256_INVALID" not in completed.stdout
        assert str(ROOT) not in completed.stdout + completed.stderr
        assert not list(temp_directory.glob("AgentGuardian-public-preview-*.exe"))
    finally:
        for path in temp_directory.glob("AgentGuardian-public-preview-*.exe"):
            path.unlink(missing_ok=True)


def test_cleanup_failure_overrides_success_and_leaves_observable_residue(
    tmp_path: Path,
) -> None:
    expected = hashlib.sha256(b"known-download").hexdigest()
    completed, temp_directory, marker = _run_download_verifier_with_mocked_commands(
        tmp_path,
        f"-ExpectedSha256 '{expected}'",
        fail_remove=True,
    )

    try:
        assert completed.returncode == 1
        assert completed.stderr == ""
        payload = json.loads(completed.stdout)
        assert payload == {
            "actual_sha256": expected,
            "error": "DOWNLOAD_CLEANUP_FAILED",
            "expected_sha256": expected,
            "status": "fail",
        }
        assert completed.stdout.strip() == json.dumps(payload, separators=(",", ":"))
        assert marker.read_text(encoding="utf-8") == "remove-called"
        assert list(temp_directory.glob("AgentGuardian-public-preview-*.exe"))
        assert str(ROOT) not in completed.stdout + completed.stderr
    finally:
        for path in temp_directory.glob("AgentGuardian-public-preview-*.exe"):
            path.unlink(missing_ok=True)


def test_missing_expected_digest_emits_fixed_json_without_curl(
    tmp_path: Path,
) -> None:
    completed, marker = _run_download_verifier_with_curl_sentinel(tmp_path, "")

    assert completed.returncode != 0
    assert completed.stderr == ""
    payload = json.loads(completed.stdout)
    assert payload == {
        "actual_sha256": None,
        "error": "EXPECTED_SHA256_INVALID",
        "expected_sha256": None,
        "status": "fail",
    }
    assert completed.stdout.strip() == json.dumps(payload, separators=(",", ":"))
    assert not marker.exists()
    assert str(ROOT) not in completed.stdout + completed.stderr


def test_bare_expected_digest_switch_emits_fixed_json_without_curl(
    tmp_path: Path,
) -> None:
    completed, marker = _run_download_verifier_with_curl_sentinel(
        tmp_path,
        "-ExpectedSha256",
    )

    assert completed.returncode != 0
    assert completed.stderr == ""
    payload = json.loads(completed.stdout)
    assert payload == {
        "actual_sha256": None,
        "error": "EXPECTED_SHA256_INVALID",
        "expected_sha256": None,
        "status": "fail",
    }
    assert completed.stdout.strip() == json.dumps(payload, separators=(",", ":"))
    assert not marker.exists()
    assert str(ROOT) not in completed.stdout + completed.stderr


def test_empty_expected_digest_emits_fixed_json_without_curl(
    tmp_path: Path,
) -> None:
    completed, marker = _run_download_verifier_with_curl_sentinel(
        tmp_path,
        "-ExpectedSha256 ''",
    )

    assert completed.returncode != 0
    assert completed.stderr == ""
    payload = json.loads(completed.stdout)
    assert payload == {
        "actual_sha256": None,
        "error": "EXPECTED_SHA256_INVALID",
        "expected_sha256": None,
        "status": "fail",
    }
    assert completed.stdout.strip() == json.dumps(payload, separators=(",", ":"))
    assert not marker.exists()
    assert str(ROOT) not in completed.stdout + completed.stderr


def test_extra_download_verifier_argument_emits_fixed_json_without_curl(
    tmp_path: Path,
) -> None:
    completed, marker = _run_download_verifier_with_curl_sentinel(
        tmp_path,
        "-ExpectedSha256 ('a' * 64) unexpected",
    )

    assert completed.returncode != 0
    assert completed.stderr == ""
    payload = json.loads(completed.stdout)
    assert payload == {
        "actual_sha256": None,
        "error": "EXPECTED_SHA256_INVALID",
        "expected_sha256": None,
        "status": "fail",
    }
    assert completed.stdout.strip() == json.dumps(payload, separators=(",", ":"))
    assert not marker.exists()
    assert str(ROOT) not in completed.stdout + completed.stderr


def test_expected_digest_with_trailing_newline_is_rejected_without_curl(
    tmp_path: Path,
) -> None:
    completed, marker = _run_download_verifier_with_curl_sentinel(
        tmp_path,
        "-ExpectedSha256 (('a' * 64) + [char]10)",
    )

    assert completed.returncode != 0
    assert completed.stderr == ""
    payload = json.loads(completed.stdout)
    assert payload == {
        "actual_sha256": None,
        "error": "EXPECTED_SHA256_INVALID",
        "expected_sha256": None,
        "status": "fail",
    }
    assert completed.stdout.strip() == json.dumps(payload, separators=(",", ":"))
    assert not marker.exists()
    assert str(ROOT) not in completed.stdout + completed.stderr


def _module():
    return importlib.import_module("scripts.stage_public_preview_release")


def test_direct_script_invocation_loads_project_modules() -> None:
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "stage_public_preview_release.py"), "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "ModuleNotFoundError" not in completed.stderr
    assert "usage:" in completed.stdout


@pytest.mark.parametrize(
    "arguments",
    (("--unknown",), ("--project-root", str(ROOT))),
)
def test_cli_argument_errors_use_fixed_json(
    arguments: tuple[str, ...],
) -> None:
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "stage_public_preview_release.py"), *arguments],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode != 0
    assert completed.stdout == ""
    assert completed.stderr == '{"error":"RELEASE_CLI_ARGUMENT_INVALID","status":"fail"}\n'
    assert "usage:" not in completed.stderr


@pytest.mark.parametrize(
    "special_path",
    (
        r"\\server\share\release",
        r"\\?\C:\release",
        r"\\.\PIPE\release",
        r"\Device\HarddiskVolume1\release",
        r"/Device/HarddiskVolume1/release",
    ),
)
def test_verify_rejects_windows_special_output_before_filesystem_access(
    special_path: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name != "nt":
        pytest.skip("Windows path boundary")
    module = _module()
    monkeypatch.setattr(module, "_resolved_project_root", lambda _root: ROOT)
    monkeypatch.setattr(module, "_require_source_state", lambda *_args: None)
    monkeypatch.setattr(module, "_verified_profile", lambda _root: object())
    monkeypatch.setattr(module, "_release_contract", lambda _profile: {})

    def filesystem_access_is_unexpected(*_args: object, **_kwargs: object) -> None:
        pytest.fail("special Windows path reached filesystem resolution")

    monkeypatch.setattr(module, "_has_reparse_component", filesystem_access_is_unexpected)
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_MANIFEST_INVALID$"):
        module.verify_staged_release(special_path, ROOT, source_commit=COMMIT)


def test_cli_rejects_special_output_path_with_fixed_json() -> None:
    if os.name != "nt":
        pytest.skip("Windows path boundary")
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "stage_public_preview_release.py"),
            "--project-root",
            str(ROOT),
            "--output-root",
            r"\\?\C:\release",
            "--source-commit",
            COMMIT,
            "--verify",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode != 0
    assert completed.stdout == ""
    assert completed.stderr == '{"error":"RELEASE_MANIFEST_INVALID","status":"fail"}\n'


def test_cli_maps_expected_platform_error_to_fixed_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _module()

    def fail_verification(*_args: object, **_kwargs: object) -> None:
        raise OSError("sensitive path details")

    monkeypatch.setattr(module, "verify_staged_release", fail_verification)
    result = module.main(
        [
            "--project-root",
            str(ROOT),
            "--output-root",
            str(tmp_path / "release"),
            "--source-commit",
            COMMIT,
            "--verify",
        ]
    )
    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert captured.err == '{"error":"RELEASE_OPERATION_FAILED","status":"fail"}\n'
    assert "sensitive path details" not in captured.err
    assert str(tmp_path) not in captured.err


def _synthetic_pe(subsystem: int) -> bytes:
    offset = 0x80
    optional_size = 240
    header = bytearray(offset + 24 + optional_size)
    header[:2] = b"MZ"
    header[0x3C:0x40] = offset.to_bytes(4, "little")
    header[offset : offset + 4] = b"PE\0\0"
    header[offset + 4 : offset + 6] = (0x8664).to_bytes(2, "little")
    header[offset + 6 : offset + 8] = (1).to_bytes(2, "little")
    header[offset + 20 : offset + 22] = optional_size.to_bytes(2, "little")
    optional = offset + 24
    header[optional : optional + 2] = (0x20B).to_bytes(2, "little")
    header[optional + 68 : optional + 70] = subsystem.to_bytes(2, "little")
    return bytes(header) + b"\0" * 8192


def test_pe_header_rejects_non_x64_machine() -> None:
    module = _module()
    prefix = bytearray(_synthetic_pe(2))
    offset = int.from_bytes(prefix[0x3C:0x40], "little")
    prefix[offset + 4 : offset + 6] = (0x14C).to_bytes(2, "little")

    assert not module._pe_header_valid(bytes(prefix[:4096]), expected_subsystem=2)


@pytest.mark.parametrize(
    "name",
    (
        "CON",
        "con.txt",
        "AUX.log",
        "trailing-dot.",
        "trailing-space ",
        "control\x01",
        "angle<name",
        "pipe|name",
        "wildcard*name",
    ),
)
def test_safe_zip_name_rejects_windows_unsafe_components(name: str) -> None:
    assert not _module()._safe_zip_name(name)


def test_zip_records_scans_decompressed_private_data(tmp_path: Path) -> None:
    module = _module()
    archive_path = tmp_path / "compressed.zip"
    marker = b"OPENAI_API_KEY=sk-proj-compressed-marker-123456"
    with zipfile.ZipFile(
        archive_path, "w", compression=zipfile.ZIP_DEFLATED
    ) as archive:
        archive.writestr("payload.txt", marker + b"\n" + b"x" * 4096)
    assert marker not in archive_path.read_bytes()
    snapshot = module._snapshot_file(
        archive_path,
        max_bytes=module.MAX_INPUT_BYTES,
        code="RELEASE_INPUT_TYPE_INVALID",
    )

    with pytest.raises(
        module.ReleaseViolation,
        match="^RELEASE_PRIVATE_DATA_DETECTED: remove credentials or private data from release inputs$",
    ):
        module._zip_records(snapshot)


def test_zip_records_ignores_short_binary_key_like_fragment(tmp_path: Path) -> None:
    module = _module()
    archive_path = tmp_path / "binary-fragment.zip"
    with zipfile.ZipFile(
        archive_path, "w", compression=zipfile.ZIP_DEFLATED
    ) as archive:
        archive.writestr("payload.bin", b"\0" * 32 + b"sk-proj-abcdef\0" + b"\0" * 32)
    snapshot = module._snapshot_file(
        archive_path,
        max_bytes=module.MAX_INPUT_BYTES,
        code="RELEASE_INPUT_TYPE_INVALID",
    )

    assert "payload.bin" in module._zip_records(snapshot)


def test_zip_records_detects_contextual_binary_api_key(tmp_path: Path) -> None:
    module = _module()
    archive_path = tmp_path / "binary-secret.zip"
    with zipfile.ZipFile(
        archive_path, "w", compression=zipfile.ZIP_DEFLATED
    ) as archive:
        archive.writestr(
            "payload.bin",
            b"OPENAI_API_KEY=sk-proj-" + b"a" * 40,
        )
    snapshot = module._snapshot_file(
        archive_path,
        max_bytes=module.MAX_INPUT_BYTES,
        code="RELEASE_INPUT_TYPE_INVALID",
    )

    with pytest.raises(
        module.ReleaseViolation,
        match="^RELEASE_PRIVATE_DATA_DETECTED: remove credentials or private data from release inputs$",
    ):
        module._zip_records(snapshot)


def _inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    module = _module()
    portable_builder = importlib.import_module("scripts.build_windows_portable")
    skill_builder = importlib.import_module("scripts.build_agentguardian_skill")
    verifier = importlib.import_module("scripts.verify_integrations_preview_profile")
    profile = verifier.load_profile_snapshot(
        ROOT, ROOT / "release_profiles" / "integrations_preview.json"
    )

    inputs = tmp_path / "inputs"
    artifacts = inputs / "artifacts"
    artifacts.mkdir(parents=True)
    installer = artifacts / module.VERSIONED_INSTALLER_NAME
    portable = artifacts / module.PORTABLE_NAME
    skill = artifacts / module.SKILL_NAME

    bundle = inputs / "portable-bundle"
    package = bundle / "_internal" / "agentguardian"
    package.mkdir(parents=True)
    for source in sorted(
        (ROOT / "src" / "agentguardian").glob("*.py"),
        key=lambda path: path.name,
    ):
        shutil.copyfile(source, package / source.name)
    shutil.copyfile(
        ROOT / "src" / "agentguardian" / "source_policy.json",
        package / "source_policy.json",
    )
    (package / "rules").mkdir()
    shutil.copyfile(ROOT / "rules" / "default.json", package / "rules" / "default.json")
    shutil.copyfile(ROOT / "LICENSE", bundle / "LICENSE")
    shutil.copyfile(ROOT / "THIRD_PARTY_NOTICES.md", bundle / "THIRD_PARTY_NOTICES.md")
    skill_payload = ROOT / "skills" / "agentguardian"
    skill_target = bundle / "agentguardian_skill"
    skill_target.mkdir()
    for name in ("LICENSE", "README.md", "SKILL.md"):
        shutil.copyfile(skill_payload / name, skill_target / name)
    (bundle / "AgentGuardian.exe").write_bytes(_synthetic_pe(2))
    (bundle / "AgentGuardianMcp.exe").write_bytes(_synthetic_pe(3))
    (bundle / "AgentGuardian.cdx.json").write_bytes(
        portable_builder.canonical_json_bytes(
            {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1}
        )
    )
    lock_digest = hashlib.sha256(
        (ROOT / "requirements-build.lock").read_bytes()
    ).hexdigest()
    (bundle / "BUILD-METADATA.json").write_bytes(
        portable_builder.canonical_json_bytes(
            {
                "artifact_status": "unsigned_development_only",
                "build_dependencies": {
                    "lock_sha256": lock_digest,
                    "versions": {"synthetic-builder": "1"},
                },
                "build_mode": "pyinstaller_onedir",
                "built_at": BUILT_AT,
                "source_commit": COMMIT,
            }
        )
    )
    (bundle / "INTEGRATIONS-PREVIEW-PROFILE.json").write_bytes(
        portable_builder.canonical_json_bytes(
            {
                "profile": "integrations_preview",
                "profile_sha256": profile.sha256,
                "schema": 1,
                "source_sha": COMMIT,
                "status": "pass",
            }
        )
    )
    manifest = portable_builder.artifact_manifest(bundle)
    (bundle / "PAYLOAD-MANIFEST.json").write_bytes(
        portable_builder.canonical_json_bytes(manifest)
    )
    checksum_manifest = portable_builder.artifact_manifest(bundle)
    (bundle / "SHA256SUMS").write_bytes(
        "".join(
            f"{entry['sha256']} *{entry['path']}\n"
            for entry in checksum_manifest["files"]
        ).encode("ascii")
    )
    portable_builder.deterministic_zip(bundle, portable)

    installer_data = bytearray(_synthetic_pe(2))
    installer_data.extend(b"Inno Setup")
    installer_data.extend("AgentGuardian integrations preview".encode("utf-16le"))
    installer_data.extend("0.3.0-preview.1".encode("utf-16le"))
    installer_data.extend(COMMIT[:24].encode("utf-16le"))
    installer_data.extend(b"\0" * (1024 * 1024 - len(installer_data)))
    installer.write_bytes(installer_data)

    attestation = installer.parent.parent / f"{installer.name}.build.json"
    bundle_digests = {
        "build_metadata_sha256": hashlib.sha256(
            (bundle / "BUILD-METADATA.json").read_bytes()
        ).hexdigest(),
        "checksums_sha256": hashlib.sha256(
            (bundle / "SHA256SUMS").read_bytes()
        ).hexdigest(),
        "payload_manifest_sha256": hashlib.sha256(
            (bundle / "PAYLOAD-MANIFEST.json").read_bytes()
        ).hexdigest(),
        "profile_evidence_sha256": hashlib.sha256(
            (bundle / "INTEGRATIONS-PREVIEW-PROFILE.json").read_bytes()
        ).hexdigest(),
    }
    script_bytes = (ROOT / "packaging/windows/AgentGuardianIntegrationsPreview.iss").read_bytes()
    attestation.write_bytes(
        portable_builder.canonical_json_bytes(
            {
                "artifact_name": module.VERSIONED_INSTALLER_NAME,
                "artifact_sha256": hashlib.sha256(installer_data).hexdigest(),
                "artifact_size": len(installer_data),
                "artifact_status": "unsigned_public_preview",
                "built_at": BUILT_AT,
                "bundle": bundle_digests,
                "compiler_sha256": profile.profile["inno_setup_iscc_sha256"],
                "compiler_version": profile.profile["inno_setup_version"],
                "installer_script_sha256": hashlib.sha256(
                    script_bytes.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
                ).hexdigest(),
                "profile": "integrations_preview",
                "profile_sha256": profile.sha256,
                "schema": 1,
                "source_commit": COMMIT,
                "version": "0.3.0-preview.1",
            }
        )
    )
    skill.write_bytes(
        skill_builder._zip_bytes(
            skill_builder._validated_source(ROOT / "skills" / "agentguardian")
        )
    )
    return installer, portable, skill


def _stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[object, Path, tuple[Path, Path, Path]]:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    output = tmp_path / "release"
    result = module.stage_public_preview_release(
        ROOT,
        output,
        installer_path=installer,
        portable_path=portable,
        skill_path=skill,
        source_commit=COMMIT,
        built_at=BUILT_AT,
    )
    return result, output, (installer, portable, skill)


def test_stage_public_preview_release_writes_exact_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    result, output, _ = _stage(tmp_path, monkeypatch)

    assert result["status"] == "pass"
    assert tuple(sorted(path.name for path in output.iterdir())) == tuple(
        sorted(ASSET_NAMES)
    )
    assert (output / module.PRIMARY_INSTALLER_NAME).read_bytes() == (
        output / module.VERSIONED_INSTALLER_NAME
    ).read_bytes()

    metadata = json.loads((output / "DOWNLOAD-METADATA.json").read_text("ascii"))
    assert set(metadata) == {
        "architecture",
        "artifact_status",
        "channel",
        "files",
        "installer",
        "release",
        "schema",
        "source_commit",
        "supported_platform",
        "version",
    }
    assert metadata["architecture"] == "x64"
    assert metadata["artifact_status"] == "unsigned_public_preview"
    assert metadata["channel"] == "integrations_preview"
    assert metadata["schema"] == 1
    assert metadata["source_commit"] == COMMIT
    assert metadata["supported_platform"] == "Windows 11 x64"
    assert metadata["version"] == "0.3.0-preview.1"
    assert set(metadata["installer"]) == {
        "primary_filename",
        "versioned_filename",
        "built_at",
    }
    assert metadata["installer"] == {
        "primary_filename": module.PRIMARY_INSTALLER_NAME,
        "versioned_filename": module.VERSIONED_INSTALLER_NAME,
        "built_at": BUILT_AT,
    }
    assert metadata["release"] == {
        "tag": "v0.3.0-preview.1",
        "title": "AgentGuardian 0.3.0 Public Preview (Unsigned)",
        "draft": False,
        "prerelease": False,
        "fixed_download_url": (
            "https://github.com/yangjing6213-dev/AgentGuardian/releases/latest/"
            "download/AgentGuardian-Setup-Windows-x64.exe"
        ),
    }
    assert len(metadata["files"]) == 6
    assert all(set(record) == {"name", "sha256", "size"} for record in metadata["files"])
    assert {record["name"] for record in metadata["files"]} == {
        name
        for name in ASSET_NAMES
        if name not in {"DOWNLOAD-METADATA.json", "SHA256SUMS"}
    }

    checksum_lines = (output / "SHA256SUMS").read_text("ascii").splitlines()
    checksum_names = [line.split("  ", 1)[1] for line in checksum_lines]
    assert checksum_names == sorted(checksum_names)
    assert set(checksum_names) == set(ASSET_NAMES) - {"SHA256SUMS"}
    for line in checksum_lines:
        digest, name = line.split("  ", 1)
        assert digest == hashlib.sha256((output / name).read_bytes()).hexdigest()

    assert module.verify_staged_release(output, ROOT, source_commit=COMMIT) == {
        "status": "pass",
        "source_commit": COMMIT,
    }


def test_stage_rejects_arbitrary_regular_artifact_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    installer.write_bytes(b"arbitrary-installer")
    portable.write_bytes(b"arbitrary-portable")
    skill.write_bytes(b"arbitrary-skill")

    with pytest.raises(
        module.ReleaseViolation, match="^RELEASE_INPUT_TYPE_INVALID$"
    ):
        module.stage_public_preview_release(
            ROOT,
            tmp_path / "release",
            installer_path=installer,
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )


def test_stage_rejects_self_consistent_portable_extra_against_bundle_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    bundle = portable.parent.parent / "portable-bundle"
    builder = importlib.import_module("scripts.build_windows_portable")
    modified_bundle = tmp_path / "modified-bundle"
    shutil.copytree(bundle, modified_bundle)
    (modified_bundle / "extra.txt").write_bytes(b"unexpected payload")
    (modified_bundle / "PAYLOAD-MANIFEST.json").unlink()
    (modified_bundle / "SHA256SUMS").unlink()
    manifest = builder.artifact_manifest(modified_bundle)
    (modified_bundle / "PAYLOAD-MANIFEST.json").write_bytes(
        builder.canonical_json_bytes(manifest)
    )
    checksum_manifest = builder.artifact_manifest(modified_bundle)
    (modified_bundle / "SHA256SUMS").write_bytes(
        "".join(
            f"{entry['sha256']} *{entry['path']}\n"
            for entry in checksum_manifest["files"]
        ).encode("ascii")
    )
    builder.deterministic_zip(modified_bundle, portable)

    with pytest.raises(
        module.ReleaseViolation,
        match="^RELEASE_INPUT_PROVENANCE_INVALID$",
    ):
        module.stage_public_preview_release(
            ROOT,
            tmp_path / "release",
            installer_path=installer,
            portable_path=portable,
            portable_bundle_root=bundle,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )


def test_stage_accepts_portable_bundle_root_with_matching_archive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    bundle = portable.parent.parent / "portable-bundle"

    result = module.stage_public_preview_release(
        ROOT,
        tmp_path / "release",
        installer_path=installer,
        portable_path=portable,
        portable_bundle_root=bundle,
        skill_path=skill,
        source_commit=COMMIT,
        built_at=BUILT_AT,
    )

    assert result["status"] == "pass"


def test_stage_rejects_reused_artifact_file_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, _skill = _inputs(tmp_path)

    with pytest.raises(
        module.ReleaseViolation, match="^RELEASE_INPUT_TYPE_INVALID$"
    ):
        module.stage_public_preview_release(
            ROOT,
            tmp_path / "release",
            installer_path=installer,
            portable_path=portable,
            skill_path=installer,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )


def test_verify_rejects_changed_stable_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    _, output, _ = _stage(tmp_path, monkeypatch)
    (output / module.PRIMARY_INSTALLER_NAME).write_bytes(b"changed")
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_ASSET_DIGEST_MISMATCH$"):
        module.verify_staged_release(output, ROOT, source_commit=COMMIT)


def test_verify_rejects_missing_asset(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = _module()
    _, output, _ = _stage(tmp_path, monkeypatch)
    (output / module.SKILL_NAME).unlink()
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_MANIFEST_INVALID$"):
        module.verify_staged_release(output, ROOT, source_commit=COMMIT)


def test_verify_rejects_extra_asset(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = _module()
    _, output, _ = _stage(tmp_path, monkeypatch)
    (output / "unexpected.txt").write_text("extra", encoding="ascii")
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_MANIFEST_INVALID$"):
        module.verify_staged_release(output, ROOT, source_commit=COMMIT)


def test_verify_rejects_tampered_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    _, output, _ = _stage(tmp_path, monkeypatch)
    metadata_path = output / "DOWNLOAD-METADATA.json"
    metadata = json.loads(metadata_path.read_text("ascii"))
    metadata["version"] = "0.3.0-preview.2"
    metadata_path.write_bytes(module.canonical_json_bytes(metadata))
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_MANIFEST_INVALID$"):
        module.verify_staged_release(output, ROOT, source_commit=COMMIT)


def test_verify_rejects_reordered_metadata_records_with_valid_checksum(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    _, output, _ = _stage(tmp_path, monkeypatch)
    metadata_path = output / "DOWNLOAD-METADATA.json"
    metadata = json.loads(metadata_path.read_text("ascii"))
    metadata["files"] = list(reversed(metadata["files"]))
    metadata_bytes = module.canonical_json_bytes(metadata)
    metadata_path.write_bytes(metadata_bytes)
    checksum_path = output / "SHA256SUMS"
    checksum_lines = checksum_path.read_text("ascii").splitlines()
    metadata_digest = hashlib.sha256(metadata_bytes).hexdigest()
    checksum_path.write_bytes(
        (
            "\n".join(
                (
                    f"{metadata_digest}  DOWNLOAD-METADATA.json"
                    if line.endswith("  DOWNLOAD-METADATA.json")
                    else line
                )
                for line in checksum_lines
            )
            + "\n"
        ).encode("ascii")
    )
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_MANIFEST_INVALID$"):
        module.verify_staged_release(output, ROOT, source_commit=COMMIT)


def test_verify_rejects_checksum_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    _, output, _ = _stage(tmp_path, monkeypatch)
    checksum_path = output / "SHA256SUMS"
    lines = checksum_path.read_text("ascii").splitlines()
    checksum_path.write_text(
        "0" * 64 + lines[0][64:] + "\n" + "\n".join(lines[1:]) + "\n",
        encoding="ascii",
    )
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_CHECKSUM_INVALID$"):
        module.verify_staged_release(output, ROOT, source_commit=COMMIT)


def test_stage_rejects_relative_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_INPUT_PATH_INVALID$"):
        module.stage_public_preview_release(
            ROOT,
            tmp_path / "release",
            installer_path=Path("relative-installer.exe"),
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )


def test_stage_rejects_directory_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    _, portable, skill = _inputs(tmp_path)
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_INPUT_PATH_INVALID$"):
        module.stage_public_preview_release(
            ROOT,
            tmp_path / "release",
            installer_path=tmp_path / "inputs",
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )


def test_stage_rejects_symlink_input_when_supported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    _, portable, skill = _inputs(tmp_path)
    target = tmp_path / "target.exe"
    target.write_bytes(b"target")
    linked = tmp_path / "linked.exe"
    try:
        linked.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_INPUT_PATH_INVALID$"):
        module.stage_public_preview_release(
            ROOT,
            tmp_path / "release",
            installer_path=linked,
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )


def test_stage_rejects_output_nested_in_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_OUTPUT_PATH_INVALID$"):
        module.stage_public_preview_release(
            ROOT,
            ROOT / ".tmp" / "public-preview-test-output",
            installer_path=installer,
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )


def test_stage_rejects_non_empty_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    output = tmp_path / "release"
    output.mkdir()
    (output / "existing.txt").write_text("existing", encoding="ascii")
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_OUTPUT_PATH_INVALID$"):
        module.stage_public_preview_release(
            ROOT,
            output,
            installer_path=installer,
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )


def test_stage_rejects_private_marker_without_leaking_marker_or_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    marker = b"OPENAI_API_KEY=sk-proj-private-preview-marker-123456"
    installer.write_bytes(marker)
    with pytest.raises(module.ReleaseViolation) as caught:
        module.stage_public_preview_release(
            ROOT,
            tmp_path / "release",
            installer_path=installer,
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )
    assert str(caught.value) == (
        "RELEASE_PRIVATE_DATA_DETECTED: remove credentials or private data "
        "from release inputs"
    )
    assert marker.decode("ascii") not in str(caught.value)
    assert str(tmp_path) not in str(caught.value)


def _assert_no_release_or_staging_directories(tmp_path: Path, output: Path) -> None:
    assert not output.exists()
    assert not any(
        path.is_dir() and path.name != "inputs"
        for path in tmp_path.iterdir()
    )


@pytest.mark.parametrize("failure_point", ("copy", "checksums"))
def test_stage_cleans_failed_temporary_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    output = tmp_path / "release"
    if failure_point == "copy":
        monkeypatch.setattr(
            module,
            "_copy_and_digest",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                module.ReleaseViolation("RELEASE_INPUT_PATH_INVALID")
            ),
        )
    else:
        monkeypatch.setattr(
            module,
            "_write_checksums",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                module.ReleaseViolation("RELEASE_CHECKSUM_INVALID")
            ),
        )

    with pytest.raises(module.ReleaseViolation):
        module.stage_public_preview_release(
            ROOT,
            output,
            installer_path=installer,
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )
    _assert_no_release_or_staging_directories(tmp_path, output)


def test_stage_runs_final_verifier_before_publish_and_cleans_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    output = tmp_path / "release"
    calls: list[Path] = []

    def reject_verification(staged: Path, _root: Path, *, source_commit: str):
        calls.append(staged)
        raise module.ReleaseViolation("RELEASE_MANIFEST_INVALID")

    monkeypatch.setattr(module, "verify_staged_release", reject_verification)
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_MANIFEST_INVALID$"):
        module.stage_public_preview_release(
            ROOT,
            output,
            installer_path=installer,
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )
    assert len(calls) == 1
    assert calls[0] != output
    _assert_no_release_or_staging_directories(tmp_path, output)


def test_stage_rejects_target_competition_without_overwrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    output = tmp_path / "release"
    original_verify = module.verify_staged_release

    def compete(staged: Path, root: Path, *, source_commit: str):
        output.mkdir()
        (output / "competitor").write_text("keep", encoding="ascii")
        return original_verify(staged, root, source_commit=source_commit)

    monkeypatch.setattr(module, "verify_staged_release", compete)
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_OUTPUT_PATH_INVALID$"):
        module.stage_public_preview_release(
            ROOT,
            output,
            installer_path=installer,
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )
    assert (output / "competitor").read_text(encoding="ascii") == "keep"
    assert not any(
        path.is_dir() and path.name.startswith(f".{output.name}.staging-")
        for path in tmp_path.iterdir()
    )


def test_stage_rejects_parent_replacement_before_staging_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    parent = tmp_path / "publish-parent"
    parent.mkdir()
    displaced = tmp_path / "displaced-parent"
    output = parent / "release"
    original_mkdtemp = module.tempfile.mkdtemp

    def replace_parent(*args: object, **kwargs: object) -> str:
        parent.rename(displaced)
        parent.mkdir()
        return original_mkdtemp(*args, **kwargs)

    monkeypatch.setattr(module.tempfile, "mkdtemp", replace_parent)
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_OUTPUT_PATH_INVALID$"):
        module.stage_public_preview_release(
            ROOT,
            output,
            installer_path=installer,
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )
    assert not output.exists()
    assert displaced.exists()
    assert all(
        child.name.startswith(f".{output.name}.staging-")
        for child in parent.iterdir()
    )


def test_stage_rejects_replaced_staging_directory_before_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    output = tmp_path / "release"
    original_publish = module._publish_staged_output
    replaced_path: list[Path] = []

    def replace_staging(staged: Path, target: Path, *args: object, **kwargs: object) -> None:
        staged.rename(tmp_path / "verified-staging")
        staged.mkdir()
        (staged / "unverified").write_text("unverified", encoding="ascii")
        replaced_path.append(staged)
        original_publish(staged, target, *args, **kwargs)

    monkeypatch.setattr(module, "_publish_staged_output", replace_staging)
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_OUTPUT_PATH_INVALID$"):
        module.stage_public_preview_release(
            ROOT,
            output,
            installer_path=installer,
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )
    assert not output.exists()
    assert len(replaced_path) == 1
    assert (replaced_path[0] / "unverified").read_text(encoding="ascii") == "unverified"


def test_stage_rejects_asset_tampering_after_verifier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    output = tmp_path / "release"
    original_publish = module._publish_staged_output

    def tamper_asset(staged: Path, target: Path, *args: object, **kwargs: object) -> None:
        replacement = tmp_path / "tampered-portable.zip"
        replacement.write_bytes(b"tampered-after-verifier")
        os.replace(replacement, staged / module.PORTABLE_NAME)
        original_publish(staged, target, *args, **kwargs)

    monkeypatch.setattr(module, "_publish_staged_output", tamper_asset)
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_ASSET_DIGEST_MISMATCH$"):
        module.stage_public_preview_release(
            ROOT,
            output,
            installer_path=installer,
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )
    assert not output.exists()


def test_snapshot_staging_rejects_replacement_before_first_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name != "nt":
        pytest.fail("Windows staging binding test requires Windows")
    module = _module()
    parent = tmp_path / "parent"
    parent.mkdir()
    staging = parent / ".release.staging-test"
    staging.mkdir()
    external = tmp_path / "external"
    external.mkdir()
    (external / "keep.txt").write_text("keep", encoding="ascii")
    parent_binding = module._bind_directory(parent, 0x00000080 | 0x00000001)
    moved = tmp_path / "moved"
    original_open = module._ntdll_open_relative_directory

    def replace_before_staging_open(
        parent_handle: int, name: str
    ) -> tuple[int, tuple[int, ...]]:
        staging.rename(moved)
        external.rename(staging)
        return original_open(parent_handle, name)

    monkeypatch.setattr(
        module, "_ntdll_open_relative_directory", replace_before_staging_open
    )
    try:
        with pytest.raises(
            module.ReleaseViolation, match="^RELEASE_OUTPUT_PATH_INVALID$"
        ):
            module._snapshot_staging_directory(
                staging, ".release.staging-", parent_binding
            )
        assert (staging / "keep.txt").read_text(encoding="ascii") == "keep"
    finally:
        module._close_directory_binding(parent_binding)
        shutil.rmtree(staging, ignore_errors=True)
        shutil.rmtree(moved, ignore_errors=True)
        shutil.rmtree(parent, ignore_errors=True)


def test_open_relative_directory_requests_delete_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name != "nt":
        pytest.fail("Windows directory access test requires Windows")
    module = _module()
    parent = tmp_path / "parent"
    parent.mkdir()
    staging = parent / ".release.staging-test"
    staging.mkdir()
    parent_binding = module._bind_directory(parent, 0x00000080 | 0x00000001)
    original_win_dll = ctypes.WinDLL
    real_create = original_win_dll("ntdll", use_last_error=True).NtCreateFile
    desired_access: list[int] = []

    class CapturedNtCreateFile:
        argtypes = None
        restype = None

        def __call__(self, *args: object) -> int:
            desired_access.append(int(args[1]))
            return real_create(*args)

    class CapturedNtdll:
        NtCreateFile = CapturedNtCreateFile()

    def win_dll(name: str, *args: object, **kwargs: object) -> object:
        if name == "ntdll":
            return CapturedNtdll()
        return original_win_dll(name, *args, **kwargs)

    monkeypatch.setattr(ctypes, "WinDLL", win_dll)
    directory_handle: int | None = None
    try:
        directory_handle, _identity = module._ntdll_open_relative_directory(
            parent_binding.handle, staging.name
        )
        assert desired_access == [0x00110081]
    finally:
        if directory_handle is not None:
            module._close_bound_handle(directory_handle)
        module._close_directory_binding(parent_binding)


def test_bind_staging_contents_uses_non_writable_child_handles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name != "nt":
        pytest.fail("Windows child binding test requires Windows")
    module = _module()
    _, output, _ = _stage(tmp_path, monkeypatch)
    parent = tmp_path / "parent"
    parent.mkdir()
    staging = parent / ".release.staging-test"
    shutil.copytree(output, staging)
    parent_binding = module._bind_directory(parent, 0x00000080 | 0x00000001)
    token = module._snapshot_staging_directory(
        staging, ".release.staging-", parent_binding
    )
    original_identity = module._bound_handle_identity
    calls: list[tuple[str, dict[str, object]]] = []

    def capture(_token: object, name: str, **kwargs: object) -> int:
        calls.append((name, kwargs))
        return 99

    monkeypatch.setattr(module, "_ntdll_create_staging_file", capture)
    monkeypatch.setattr(
        module, "_close_bound_handle", lambda _handle, **_kwargs: None
    )

    def matching_identity(
        _handle: int, **_kwargs: object
    ) -> tuple[int, ...]:
        if not calls:
            return original_identity(_handle)
        info = (staging / calls[-1][0]).stat()
        if _kwargs.get("resource_type") == "fd":
            return info.st_dev, info.st_ino
        return (
            info.st_dev & 0xFFFFFFFF,
            (info.st_ino >> 32) & 0xFFFFFFFF,
            info.st_ino & 0xFFFFFFFF,
        )

    monkeypatch.setattr(module, "_bound_handle_identity", matching_identity)
    try:
        bound = module._bind_staging_contents(token, staging)
        assert tuple(name for name, _kwargs in calls) == module.RELEASE_ASSET_NAMES
        assert all(kwargs["return_native_handle"] is True for _, kwargs in calls)
        assert all(kwargs["share_access"] == 0x00000005 for _, kwargs in calls)
        assert all(kwargs["create_disposition"] == 0x00000001 for _, kwargs in calls)
        assert all(
            kwargs["desired_access"] & 0x00000002 == 0
            for _, kwargs in calls
        )
        assert all(child.handle == 99 for child in bound.children)
    finally:
        module._close_staging_token(token)
        shutil.rmtree(staging, ignore_errors=True)
        shutil.rmtree(parent, ignore_errors=True)


def test_bind_staging_contents_rejects_child_replacement_after_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    _, output, _ = _stage(tmp_path, monkeypatch)
    parent = tmp_path / "parent"
    parent.mkdir()
    staging = parent / ".release.staging-test"
    shutil.copytree(output, staging)
    parent_binding = module._bind_directory(parent, 0x00000080 | 0x00000001)
    token = module._snapshot_staging_directory(
        staging, ".release.staging-", parent_binding
    )
    original_snapshot = module._snapshot_file
    replaced = False

    def replace_after_open(
        path: Path, *, max_bytes: int, code: str
    ) -> object:
        nonlocal replaced
        if not replaced and path.name == module.PORTABLE_NAME:
            replacement = tmp_path / "replacement.zip"
            replacement.write_bytes(b"replacement after child open")
            path.unlink()
            os.replace(replacement, path)
            replaced = True
        return original_snapshot(path, max_bytes=max_bytes, code=code)

    monkeypatch.setattr(module, "_snapshot_file", replace_after_open)
    try:
        with pytest.raises(
            module.ReleaseViolation,
            match="^RELEASE_ASSET_DIGEST_MISMATCH$",
        ):
            module._bind_staging_contents(token, staging)
    finally:
        module._close_staging_token(token)
        shutil.rmtree(staging, ignore_errors=True)
        shutil.rmtree(parent, ignore_errors=True)


@pytest.mark.parametrize("persistent_close_failure", (False, True))
def test_bind_staging_contents_retries_and_retains_child_ownership_on_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    persistent_close_failure: bool,
) -> None:
    module = _module()
    _, output, _ = _stage(tmp_path, monkeypatch)
    parent = tmp_path / "parent"
    parent.mkdir()
    staging = parent / ".release.staging-test"
    shutil.copytree(output, staging)
    parent_binding = module._bind_directory(parent, 0x00000080 | 0x00000001)
    token = module._snapshot_staging_directory(
        staging, ".release.staging-", parent_binding
    )
    original_snapshot = module._snapshot_file
    original_identity = module._bound_handle_identity
    opened: list[int] = []
    closed: list[int] = []
    snapshots = 0

    def open_all_children(
        bound_token: object, name: str, code: str
    ) -> int:
        handle = 1001 + len(opened)
        opened.append(handle)
        return handle

    def snapshot_then_fail(
        path: Path, *, max_bytes: int, code: str
    ) -> object:
        nonlocal snapshots
        snapshots += 1
        if snapshots == 2:
            raise module.ReleaseViolation("RELEASE_ASSET_DIGEST_MISMATCH")
        return original_snapshot(path, max_bytes=max_bytes, code=code)

    attempts: dict[int, int] = {}

    def close_and_report(handle: int, **_kwargs: object) -> None:
        closed.append(handle)
        attempts[handle] = attempts.get(handle, 0) + 1
        if handle in opened and (
            persistent_close_failure or attempts[handle] == 1
        ):
            raise OSError("child close failed")

    monkeypatch.setattr(module, "_open_bound_staged_child", open_all_children)
    monkeypatch.setattr(module, "_snapshot_file", snapshot_then_fail)
    def identity(handle: int, **kwargs: object) -> tuple[int, ...]:
        if kwargs.get("resource_type") == "fd":
            info = os.fstat(handle)
            return info.st_dev, info.st_ino
        return (0, 0, 0) if handle in opened else original_identity(handle)

    monkeypatch.setattr(module, "_bound_handle_identity", identity)
    monkeypatch.setattr(
        module, "_path_identity_matches_handle", lambda *_args, **_kwargs: True
    )
    monkeypatch.setattr(module, "_close_bound_handle", close_and_report)
    try:
        with pytest.raises(
            module.ReleaseViolation,
            match="^RELEASE_ASSET_DIGEST_MISMATCH$",
        ) as caught:
            module._bind_staging_contents(token, staging)
        assert opened
        assert len(opened) == 2
        observed_child_closes = tuple(closed)
        child_closes = tuple(handle for handle in observed_child_closes if handle in opened)
        assert child_closes.count(opened[0]) == 2, (
            f"opened={opened}, closed={observed_child_closes}"
        )
        assert child_closes.count(opened[1]) == 1, (
            f"opened={opened}, closed={observed_child_closes}"
        )
        cleanup_token = getattr(caught.value, "cleanup_token", None)
        assert cleanup_token is not None
        expected_owned = tuple(opened) if persistent_close_failure else (opened[1],)
        assert tuple(
            child.handle for child in cleanup_token.children if child.handle
        ) == expected_owned
    finally:
        module._close_staging_token(token)
        shutil.rmtree(staging, ignore_errors=True)
        shutil.rmtree(parent, ignore_errors=True)


def test_stage_rejects_active_document_drift_before_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    project = tmp_path / "project"
    shutil.copytree(
        ROOT,
        project,
        ignore=shutil.ignore_patterns(
            ".analysis",
            ".git",
            ".local-audit",
            ".mypy_cache",
            ".pytest_cache",
            ".ruff_cache",
            ".superpowers",
            ".tmp",
            "__pycache__",
            "build",
            "dist",
            "venv",
            ".venv",
        ),
    )
    installer, portable, skill = _inputs(tmp_path)
    output = tmp_path / "release"
    documents = (
        project / "docs/security/integrations-preview-status.json",
        project / "docs/security/integrations-preview.md",
    )
    originals = tuple(path.read_bytes() for path in documents)
    original_stats = tuple(
        (
            path.stat().st_dev,
            path.stat().st_ino,
            path.stat().st_size,
            path.stat().st_mtime_ns,
        )
        for path in documents
    )
    original_publish = module._publish_staged_output

    def drift_then_publish(staged: Path, target: Path, *args: object, **kwargs: object) -> None:
        documents[1].write_bytes(originals[1] + b"\ntransient drift")
        try:
            original_publish(staged, target, *args, **kwargs)
        finally:
            for path, data, stat_info in zip(documents, originals, original_stats):
                path.write_bytes(data)
                os.utime(
                    path,
                    ns=(stat_info[3], stat_info[3]),
                )

    monkeypatch.setattr(module, "_publish_staged_output", drift_then_publish)
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_SOURCE_STATE_INVALID$"):
        module.stage_public_preview_release(
            project,
            output,
            installer_path=installer,
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )
    assert not output.exists()
    assert tuple(path.read_bytes() for path in documents) == originals
    assert tuple(
        (
            path.stat().st_dev,
            path.stat().st_ino,
            path.stat().st_size,
            path.stat().st_mtime_ns,
        )
        for path in documents
    ) == original_stats


def test_stage_rechecks_assets_after_child_handles_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name != "nt":
        pytest.fail("Windows staging close-window test requires Windows")
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    output = tmp_path / "release"
    original_close = getattr(module, "_close_staging_child_handles", None)

    def close_then_replace(token: object) -> object:
        assert original_close is not None
        closed, close_code = original_close(token)
        assert close_code is None
        replacement = tmp_path / "replacement.zip"
        replacement.write_bytes(b"changed after handle close")
        os.replace(
            replacement,
            Path(closed.parent) / closed.name / module.PORTABLE_NAME,
        )
        return closed, None

    monkeypatch.setattr(
        module, "_close_staging_child_handles", close_then_replace, raising=False
    )
    monkeypatch.setattr(module, "_win32_rename_staged", lambda *_args: None)
    with pytest.raises(
        module.ReleaseViolation, match="^RELEASE_ASSET_DIGEST_MISMATCH$"
    ):
        module.stage_public_preview_release(
            ROOT,
            output,
            installer_path=installer,
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )
    assert not output.exists()


def test_publish_rejects_asset_replaced_by_symlink_without_touching_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    output = tmp_path / "release"
    external = tmp_path / "external.bin"
    external.write_bytes(b"must-remain-unchanged")
    original_publish = module._publish_staged_output

    def replace_asset(staged: Path, target: Path, *args: object, **kwargs: object) -> None:
        asset = staged / module.PORTABLE_NAME
        asset.unlink()
        try:
            asset.symlink_to(external)
        except OSError:
            pytest.skip("symlink creation is unavailable")
        original_publish(staged, target, *args, **kwargs)

    monkeypatch.setattr(module, "_publish_staged_output", replace_asset)
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_OUTPUT_PATH_INVALID$"):
        module.stage_public_preview_release(
            ROOT,
            output,
            installer_path=installer,
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )
    assert not output.exists()
    assert external.read_bytes() == b"must-remain-unchanged"


def test_cleanup_does_not_remove_replaced_staging_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    output = tmp_path / "release"
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    (unrelated / "keep.txt").write_text("keep", encoding="ascii")
    replaced_path: list[Path] = []

    def replace_then_fail(staged: Path, *args: object, **kwargs: object) -> None:
        shutil.rmtree(staged)
        unrelated.rename(staged)
        replaced_path.append(staged)
        raise module.ReleaseViolation("RELEASE_CHECKSUM_INVALID")

    monkeypatch.setattr(module, "_write_checksums", replace_then_fail)
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_CHECKSUM_INVALID$"):
        module.stage_public_preview_release(
            ROOT,
            output,
            installer_path=installer,
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )
    assert not output.exists()
    assert len(replaced_path) == 1
    replaced_staging = replaced_path[0]
    assert replaced_staging.exists()
    assert (replaced_staging / "keep.txt").read_text(encoding="ascii") == "keep"


def test_cleanup_without_directory_token_fails_closed(
    tmp_path: Path,
) -> None:
    module = _module()
    staging = tmp_path / ".release.staging-unbound"
    staging.mkdir()
    (staging / "keep.txt").write_text("keep", encoding="ascii")
    assert module._cleanup_temporary_output(staging, None) == "RELEASE_CLEANUP_FAILED"
    assert (staging / "keep.txt").read_text(encoding="ascii") == "keep"


def test_cleanup_rejects_staging_replacement_after_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name != "nt":
        pytest.fail("Windows handle-relative cleanup test requires Windows")
    module = _module()
    parent = tmp_path / "parent"
    parent.mkdir()
    staging = parent / ".release.staging-test"
    staging.mkdir()
    external = tmp_path / "external"
    external.mkdir()
    (external / "keep.txt").write_text("keep", encoding="ascii")
    parent_binding = module._bind_directory(parent, 0x00000080 | 0x00000001)
    token = module._snapshot_staging_directory(
        staging, ".release.staging-", parent_binding
    )
    moved = tmp_path / "moved"
    original_validate = module._validated_staging_path
    replaced = False

    def replace_after_validation(*args: object, **kwargs: object) -> Path:
        nonlocal replaced
        result = original_validate(*args, **kwargs)
        if not replaced:
            staging.rename(moved)
            external.rename(staging)
            replaced = True
        return result

    monkeypatch.setattr(module, "_validated_staging_path", replace_after_validation)
    try:
        assert (
            module._cleanup_temporary_output(staging, token)
            == "RELEASE_CLEANUP_FAILED"
        )
        assert (staging / "keep.txt").read_text(encoding="ascii") == "keep"
    finally:
        module._close_staging_token(token)
        shutil.rmtree(staging, ignore_errors=True)
        shutil.rmtree(moved, ignore_errors=True)
        shutil.rmtree(parent, ignore_errors=True)


@pytest.mark.parametrize("name", (r"outside\file", ".", ".."))
def test_native_staging_file_rejects_untrusted_relative_names(
    tmp_path: Path, name: str
) -> None:
    if os.name != "nt":
        pytest.fail("Windows handle-relative creation test requires Windows")
    module = _module()
    parent = tmp_path / "parent"
    parent.mkdir()
    staging = parent / ".release.staging-test"
    staging.mkdir()
    external = tmp_path / "external"
    external.mkdir()
    (external / "keep.txt").write_text("keep", encoding="ascii")
    parent_binding = module._bind_directory(parent, 0x00000080 | 0x00000001)
    token = module._snapshot_staging_directory(
        staging, ".release.staging-", parent_binding
    )
    try:
        with pytest.raises(
            module.ReleaseViolation, match="^RELEASE_OUTPUT_PATH_INVALID$"
        ):
            module._ntdll_create_staging_file(token, name)
        assert (external / "keep.txt").read_text(encoding="ascii") == "keep"
        assert tuple(child.name for child in external.iterdir()) == ("keep.txt",)
    finally:
        module._close_staging_token(token)
        shutil.rmtree(staging, ignore_errors=True)
        shutil.rmtree(parent, ignore_errors=True)


def test_cleanup_uses_fixed_asset_allowlist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name != "nt":
        pytest.fail("Windows handle-relative cleanup test requires Windows")
    module = _module()
    parent = tmp_path / "parent"
    parent.mkdir()
    staging = parent / ".release.staging-test"
    staging.mkdir()
    parent_binding = module._bind_directory(parent, 0x00000080 | 0x00000001)
    token = module._snapshot_staging_directory(
        staging, ".release.staging-", parent_binding
    )
    token = module.replace(
        token,
        children=(
            module._StagedChildToken(
                "outside",
                module._FileSnapshot(staging / "outside", (1, 2, 3, 4), 0),
                "0" * 64,
            ),
        ),
    )
    opened: list[str] = []
    monkeypatch.setattr(
        module,
        "_ntdll_create_staging_file",
        lambda _token, name, **_kwargs: opened.append(name) or None,
    )
    monkeypatch.setattr(module, "_win32_set_disposition", lambda _handle: None)
    try:
        assert module._cleanup_bound_staging(token, staging)
        assert tuple(opened) == module.RELEASE_ASSET_NAMES
        assert not (parent / "outside").exists()
    finally:
        module._close_staging_token(token)
        shutil.rmtree(staging, ignore_errors=True)
        shutil.rmtree(parent, ignore_errors=True)


def test_create_output_file_binds_native_creation_before_path_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name != "nt":
        pytest.fail("Windows handle-relative creation test requires Windows")
    module = _module()
    parent = tmp_path / "parent"
    parent.mkdir()
    staging = parent / ".release.staging-test"
    staging.mkdir()
    external = tmp_path / "external"
    external.mkdir()
    (external / "keep.txt").write_text("keep", encoding="ascii")
    parent_binding = module._bind_directory(parent, 0x00000080 | 0x00000001)
    token = module._snapshot_staging_directory(
        staging, ".release.staging-", parent_binding
    )
    moved = tmp_path / "moved"
    original_create = module._ntdll_create_staging_file
    original_win_dll = ctypes.WinDLL
    native_calls: list[tuple[int, str, int, int, int]] = []
    from ctypes import wintypes

    class UnicodeString(ctypes.Structure):
        _fields_ = [
            ("length", wintypes.USHORT),
            ("maximum_length", wintypes.USHORT),
            ("buffer", wintypes.LPWSTR),
        ]

    class ObjectAttributes(ctypes.Structure):
        _fields_ = [
            ("length", wintypes.ULONG),
            ("root_directory", wintypes.HANDLE),
            ("object_name", ctypes.POINTER(UnicodeString)),
            ("attributes", wintypes.ULONG),
            ("security_descriptor", wintypes.LPVOID),
            ("security_quality_of_service", wintypes.LPVOID),
        ]

    class CapturedNtCreateFile:
        argtypes = None
        restype = None

        def __call__(self, *args: object) -> int:
            attributes = ctypes.cast(
                args[2], ctypes.POINTER(ObjectAttributes)
            ).contents
            unicode_name = attributes.object_name.contents
            name = ctypes.wstring_at(
                unicode_name.buffer, unicode_name.length // 2
            )
            native_calls.append(
                (
                    int(attributes.root_directory),
                    name,
                    int(attributes.attributes),
                    int(args[7]),
                    int(args[8]),
                )
            )
            return real_create(*args)

    real_ntdll = original_win_dll("ntdll", use_last_error=True)
    real_create = real_ntdll.NtCreateFile

    class CapturedNtdll:
        NtCreateFile = CapturedNtCreateFile()

    def win_dll(name: str, *args: object, **kwargs: object) -> object:
        if name == "ntdll":
            return CapturedNtdll()
        return original_win_dll(name, *args, **kwargs)

    def create_then_replace(*args: object, **kwargs: object) -> int | None:
        return original_create(*args, **kwargs)

    monkeypatch.setattr(ctypes, "WinDLL", win_dll)
    monkeypatch.setattr(module, "_ntdll_create_staging_file", create_then_replace)
    try:
        asset = staging / module.PORTABLE_NAME
        with module._create_output_file(asset, token) as stream:
            stream.write(b"written through bound handle")
        staging.rename(moved)
        external.rename(staging)
        assert (moved / module.PORTABLE_NAME).read_bytes() == (
            b"written through bound handle"
        )
        assert (staging / "keep.txt").read_text(encoding="ascii") == "keep"
        assert native_calls == [
            (
                token.directory_handle,
                module.PORTABLE_NAME,
                0x00000040 | 0x00001000,
                0x00000002,
                0x00000040 | 0x00000020,
            )
        ]
    finally:
        module._close_staging_token(token)
        shutil.rmtree(staging, ignore_errors=True)
        shutil.rmtree(moved, ignore_errors=True)
        shutil.rmtree(parent, ignore_errors=True)


def test_close_bound_handle_maps_windows_false(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module.os, "name", "nt")

    class FakeCloseHandle:
        argtypes = None
        restype = None

        def __call__(self, _handle: int) -> int:
            return 0

    class FakeKernel32:
        CloseHandle = FakeCloseHandle()

    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: FakeKernel32())
    binding = module._DirectoryBinding(tmp_path, (1, 2), 55)
    assert module._close_directory_binding(binding) == "RELEASE_RESOURCE_CLOSE_FAILED"


def test_open_bound_directory_closes_after_identity_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module.os, "name", "nt")
    closed: list[int] = []

    class FakeCreateFileW:
        argtypes = None
        restype = None

        def __call__(self, *_args: object) -> int:
            return 77

    class FakeGetFileInformationByHandle:
        argtypes = None
        restype = None

        def __call__(self, *_args: object) -> int:
            return 0

    class FakeKernel32:
        CreateFileW = FakeCreateFileW()
        GetFileInformationByHandle = FakeGetFileInformationByHandle()

        class CloseHandle:
            argtypes = None
            restype = None

    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: FakeKernel32())
    monkeypatch.setattr(
        module,
        "_close_bound_handle",
        lambda handle, **_kwargs: closed.append(handle),
    )
    with pytest.raises(OSError):
        module._win32_open_directory(tmp_path, 0)
    assert closed == [77]


def test_win32_open_directory_transfers_close_lease_after_identity_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module.os, "name", "nt")

    class FakeCreateFileW:
        argtypes = None
        restype = None

        def __call__(self, *_args: object) -> int:
            return 77

    class FakeGetFileInformationByHandle:
        argtypes = None
        restype = None

        def __call__(self, *_args: object) -> int:
            return 0

    class FakeKernel32:
        CreateFileW = FakeCreateFileW()
        GetFileInformationByHandle = FakeGetFileInformationByHandle()

        class CloseHandle:
            argtypes = None
            restype = None

    close_calls: list[int] = []

    def close_fails(handle: int, **_kwargs: object) -> None:
        close_calls.append(handle)
        raise OSError("close failed")

    class FakeCloseHandle:
        argtypes = None
        restype = None

    FakeKernel32.CloseHandle = FakeCloseHandle()
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: FakeKernel32())
    monkeypatch.setattr(module, "_close_bound_handle", close_fails)
    with pytest.raises(module.ReleaseViolation) as caught:
        module._win32_open_directory(tmp_path, 0)

    assert caught.value.code == "RELEASE_OUTPUT_PATH_INVALID"
    assert caught.value.cleanup_lease is not None
    assert caught.value.cleanup_lease.owns(77)
    assert close_calls == [77]


def test_win32_open_directory_query_exception_keeps_lease_when_close_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module.os, "name", "nt")

    class FakeCreateFileW:
        argtypes = None
        restype = None

        def __call__(self, *_args: object) -> int:
            return 77

    class FakeGetFileInformationByHandle:
        argtypes = None
        restype = None

        def __call__(self, *_args: object) -> int:
            raise ctypes.ArgumentError("identity query failed")

    class FakeKernel32:
        CreateFileW = FakeCreateFileW()
        GetFileInformationByHandle = FakeGetFileInformationByHandle()

        class CloseHandle:
            argtypes = None
            restype = None

    close_calls: list[int] = []

    def close_fails(handle: int, **_kwargs: object) -> None:
        close_calls.append(handle)
        raise OSError("close failed")

    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: FakeKernel32())
    monkeypatch.setattr(module, "_close_bound_handle", close_fails)
    with pytest.raises(module.ReleaseViolation) as caught:
        module._win32_open_directory(tmp_path, 0)
    assert caught.value.code == "RELEASE_OUTPUT_PATH_INVALID"
    assert caught.value.cleanup_lease is not None
    assert caught.value.cleanup_lease.owns(77)
    assert close_calls == [77]


def test_win32_open_directory_query_exception_closes_once_when_close_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module.os, "name", "nt")

    class FakeCreateFileW:
        argtypes = None
        restype = None

        def __call__(self, *_args: object) -> int:
            return 77

    class FakeGetFileInformationByHandle:
        argtypes = None
        restype = None

        def __call__(self, *_args: object) -> int:
            raise OSError("identity query failed")

    class FakeKernel32:
        CreateFileW = FakeCreateFileW()
        GetFileInformationByHandle = FakeGetFileInformationByHandle()

        class CloseHandle:
            argtypes = None
            restype = None

    close_calls: list[int] = []
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: FakeKernel32())
    monkeypatch.setattr(
        module,
        "_close_bound_handle",
        lambda handle, **_kwargs: close_calls.append(handle),
    )
    with pytest.raises(module.ReleaseViolation) as caught:
        module._win32_open_directory(tmp_path, 0)
    assert caught.value.code == "RELEASE_OUTPUT_PATH_INVALID"
    assert caught.value.cleanup_lease is None
    assert close_calls == [77]


def test_win32_open_directory_normalizes_arbitrary_query_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module.os, "name", "nt")

    class FakeCreateFileW:
        argtypes = None
        restype = None

        def __call__(self, *_args: object) -> int:
            return 77

    class FakeGetFileInformationByHandle:
        argtypes = None
        restype = None

        def __call__(self, *_args: object) -> int:
            raise RuntimeError("unexpected identity failure")

    class FakeKernel32:
        CreateFileW = FakeCreateFileW()
        GetFileInformationByHandle = FakeGetFileInformationByHandle()

        class CloseHandle:
            argtypes = None
            restype = None

    close_calls: list[int] = []
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: FakeKernel32())
    monkeypatch.setattr(
        module,
        "_close_bound_handle",
        lambda handle, **_kwargs: close_calls.append(handle),
    )

    with pytest.raises(module.ReleaseViolation) as caught:
        module._win32_open_directory(tmp_path, 0)

    assert caught.value.code == "RELEASE_OUTPUT_PATH_INVALID"
    assert caught.value.cleanup_lease is None
    assert close_calls == [77]


def test_cleanup_path_adopts_open_directory_lease_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    staged = tmp_path / ".release.staging-test"
    staged.mkdir()
    token = module._StagingDirectoryToken(
        parent=tmp_path,
        name=staged.name,
        prefix=".release.staging-",
        parent_identity=(1,),
        identity=(2,),
        is_reparse_point=False,
        parent_handle=None,
        directory_handle=None,
    )
    foreign_lease = module._HandleOwnershipLedger()
    foreign_lease.register(5678, resource_type="directory", identity=(3, 4))

    def open_fails(*_args: object) -> tuple[int, tuple[int, ...]]:
        raise module.ReleaseViolation(
            "RELEASE_OUTPUT_PATH_INVALID", cleanup_lease=foreign_lease
        )

    monkeypatch.setattr(module, "_open_bound_directory", open_fails)
    assert module._cleanup_path_still_bound(token, staged) is False
    assert token.ledger.owns(5678)
    assert token.ledger.record(5678) == foreign_lease.record(5678)


def test_open_bound_posix_directory_query_exception_keeps_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module.os, "name", "posix")
    monkeypatch.setattr(module.os, "open", lambda *_args, **_kwargs: 88)
    monkeypatch.setattr(
        module,
        "_bound_handle_identity",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("query failed")),
    )
    close_calls: list[int] = []

    def close_fails(handle: int, **_kwargs: object) -> None:
        close_calls.append(handle)
        raise OSError("close failed")

    monkeypatch.setattr(module, "_close_bound_handle", close_fails)
    with pytest.raises(module.ReleaseViolation) as caught:
        module._open_bound_directory(tmp_path, 0)
    assert caught.value.code == "RELEASE_OUTPUT_PATH_INVALID"
    assert caught.value.cleanup_lease is not None
    assert caught.value.cleanup_lease.owns(88)
    assert close_calls == [88]


def test_open_bound_posix_directory_normalizes_arbitrary_query_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module.os, "name", "posix")
    monkeypatch.setattr(module.os, "open", lambda *_args, **_kwargs: 88)
    monkeypatch.setattr(
        module,
        "_bound_handle_identity",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("query failed")),
    )
    close_calls: list[int] = []
    monkeypatch.setattr(
        module,
        "_close_bound_handle",
        lambda handle, **_kwargs: close_calls.append(handle),
    )

    with pytest.raises(module.ReleaseViolation) as caught:
        module._open_bound_directory(tmp_path, 0)

    assert caught.value.code == "RELEASE_OUTPUT_PATH_INVALID"
    assert caught.value.cleanup_lease is None
    assert close_calls == [88]


def test_error_with_cleanup_merges_existing_and_new_leases() -> None:
    module = _module()
    existing = module._HandleOwnershipLedger()
    existing.register(11, resource_type="directory", identity=(1,))
    new = module._HandleOwnershipLedger()
    new.register(22, resource_type="fd", identity=(2,))
    primary = module.ReleaseViolation("RELEASE_SOURCE_STATE_INVALID", cleanup_lease=existing)

    updated = module._error_with_cleanup(
        primary, new, "RELEASE_OUTPUT_PATH_INVALID"
    )

    assert updated.code == "RELEASE_SOURCE_STATE_INVALID"
    assert updated.cleanup_lease is not None
    assert updated.cleanup_lease.owns(11)
    assert updated.cleanup_lease.owns(22)


def test_final_cleanup_merges_primary_token_and_parent_leases() -> None:
    module = _module()
    primary_lease = module._HandleOwnershipLedger()
    primary_lease.register(11, resource_type="fd", identity=(1,))
    token_lease = module._HandleOwnershipLedger()
    token_lease.register(22, resource_type="directory", identity=(2,))
    parent_lease = module._HandleOwnershipLedger()
    parent_lease.register(33, resource_type="directory", identity=(3,))
    primary = module.ReleaseViolation(
        "RELEASE_SOURCE_STATE_INVALID", cleanup_lease=primary_lease
    )

    merged = module._attach_cleanup_lease(
        primary, token_lease, "RELEASE_RESOURCE_CLOSE_FAILED"
    )
    merged = module._attach_cleanup_lease(
        merged, parent_lease, "RELEASE_RESOURCE_CLOSE_FAILED"
    )

    assert isinstance(merged, module.ReleaseViolation)
    assert merged.code == "RELEASE_SOURCE_STATE_INVALID"
    assert merged.cleanup_lease is primary_lease
    assert merged.cleanup_lease.handles() == (11, 22, 33)


def test_create_output_file_fdopen_failure_uses_os_close_without_kernel32(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module.os, "name", "nt")
    monkeypatch.setattr(module.os, "open", lambda *_args, **_kwargs: 77)
    monkeypatch.setattr(
        module.os,
        "fdopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(TypeError("fdopen failed")),
    )
    monkeypatch.setattr(module, "_bound_handle_identity", lambda *_args, **_kwargs: (1, 2))
    close_calls: list[int] = []

    def close_fails(handle: int) -> None:
        close_calls.append(handle)
        raise OSError("close failed")

    monkeypatch.setattr(module.os, "close", close_fails)

    def unexpected_kernel32(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("fd cleanup must not call CloseHandle")

    monkeypatch.setattr(ctypes, "WinDLL", unexpected_kernel32)
    with pytest.raises(module.ReleaseViolation) as caught:
        with module._create_output_file(tmp_path / "output.bin"):
            pass
    assert caught.value.code == "RELEASE_OUTPUT_PATH_INVALID"
    assert caught.value.cleanup_lease is not None
    assert caught.value.cleanup_lease.owns(77)
    assert close_calls == [77, 77]


def test_bound_handle_identity_is_pure_query_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name != "nt":
        pytest.skip("Windows handle identity test requires Windows")
    module = _module()

    class FakeGetFileInformationByHandle:
        argtypes = None
        restype = None

        def __call__(self, *_args: object) -> int:
            return 0

    class FakeKernel32:
        GetFileInformationByHandle = FakeGetFileInformationByHandle()

    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: FakeKernel32())
    with pytest.raises(OSError):
        module._bound_handle_identity(77)


def test_open_bound_posix_child_keeps_lease_when_identity_and_close_fail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name != "posix":
        pytest.skip("POSIX bound child test requires POSIX")
    module = _module()
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / module.PORTABLE_NAME).mkdir()
    directory_handle = os.open(
        staging, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    )
    token = module._StagingDirectoryToken(
        parent=tmp_path,
        name=staging.name,
        prefix="staging-",
        parent_identity=(1,),
        identity=(2,),
        is_reparse_point=False,
        parent_handle=None,
        directory_handle=directory_handle,
    )
    original_close = module._close_bound_handle

    def close_fails(_handle: int, **_kwargs: object) -> None:
        raise OSError("close failed")

    monkeypatch.setattr(module, "_close_bound_handle", close_fails)
    try:
        with pytest.raises(module.ReleaseViolation) as caught:
            module._open_bound_staged_child(
                token, module.PORTABLE_NAME, "RELEASE_ASSET_DIGEST_MISMATCH"
            )
        assert caught.value.code == "RELEASE_RESOURCE_CLOSE_FAILED"
        assert caught.value.cleanup_lease is token.ledger
        assert token.ledger.owns(directory_handle)
        assert token.ledger.handles()
    finally:
        monkeypatch.setattr(module, "_close_bound_handle", original_close)
        module._close_staging_token(token)
        shutil.rmtree(staging, ignore_errors=True)


def test_cleanup_child_failure_keeps_lease_for_bounded_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name != "nt":
        pytest.skip("Windows cleanup test requires Windows")
    module = _module()
    staging = tmp_path / "staging"
    staging.mkdir()
    token = module._StagingDirectoryToken(
        parent=tmp_path,
        name=staging.name,
        prefix="staging-",
        parent_identity=(1,),
        identity=(2,),
        is_reparse_point=False,
        parent_handle=None,
        directory_handle=22,
    )
    child_handle = 77
    token.ledger.register(child_handle)
    calls: list[int] = []
    attempts: dict[int, int] = {}

    def close_once(handle: int, **_kwargs: object) -> None:
        calls.append(handle)
        attempts[handle] = attempts.get(handle, 0) + 1
        if handle == child_handle and attempts[handle] == 1:
            raise OSError("close failed")

    monkeypatch.setattr(module, "_validated_staging_path", lambda *_args: staging)
    monkeypatch.setattr(module, "_cleanup_path_still_bound", lambda *_args: True)
    monkeypatch.setattr(
        module,
        "_ntdll_create_staging_file",
        lambda _token, name, **_kwargs: child_handle
        if name == module.PORTABLE_NAME
        else None,
    )
    monkeypatch.setattr(
        module,
        "_win32_set_disposition",
        lambda _handle: (_ for _ in ()).throw(
            module.ReleaseViolation("RELEASE_CLEANUP_FAILED")
        ),
    )
    monkeypatch.setattr(module, "_close_bound_handle", close_once)

    assert module._cleanup_temporary_output(staging, token) == "RELEASE_CLEANUP_FAILED"
    assert calls == [child_handle]
    assert token.ledger.owns(child_handle)
    assert module._close_staging_token(token) is None
    assert calls == [child_handle, 22, child_handle]


def test_handle_ledger_does_not_retry_reused_resource(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    ledger = module._HandleOwnershipLedger()
    ledger.register(77, resource_type="fd", identity=(1, 2))
    calls: list[int] = []

    def close_once_then_reused(handle: int, **_kwargs: object) -> None:
        calls.append(handle)
        raise OSError("close outcome unknown")

    monkeypatch.setattr(module, "_close_bound_handle", close_once_then_reused)
    monkeypatch.setattr(
        module,
        "_bound_handle_identity",
        lambda _handle, **_kwargs: (3, 4),
    )

    assert module._close_ledger_handle(ledger, 77) is False
    assert calls == [77]
    assert ledger.owns(77)


def test_handle_ledger_tracks_and_closes_each_resource_namespace_exactly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    ledger = module._HandleOwnershipLedger()
    handle = 1234
    resource_types = ("handle", "fd", "directory", "file")
    initial_identities = {
        resource_type: (index,)
        for index, resource_type in enumerate(resource_types, start=1)
    }
    updated_identities = {
        resource_type: (index + 10,)
        for index, resource_type in enumerate(resource_types, start=1)
    }

    for resource_type in resource_types:
        ledger.register(
            handle,
            resource_type=resource_type,
            identity=initial_identities[resource_type],
        )

    close_calls: list[tuple[int, str]] = []

    def close_bound_handle(value: int, *, resource_type: str) -> None:
        close_calls.append((value, resource_type))

    monkeypatch.setattr(module, "_close_bound_handle", close_bound_handle)

    for resource_type in resource_types:
        assert ledger.record(handle, resource_type=resource_type).identity == (
            initial_identities[resource_type]
        )
        ledger.set_identity(
            handle,
            updated_identities[resource_type],
            resource_type=resource_type,
        )
        assert ledger.record(handle, resource_type=resource_type).identity == (
            updated_identities[resource_type]
        )
        assert module._close_ledger_handle(
            ledger, handle, resource_type=resource_type
        ) is True
        assert not ledger.owns(handle, resource_type=resource_type)

    assert close_calls == [(handle, resource_type) for resource_type in resource_types]


def test_handle_ledger_keeps_colliding_resource_namespaces_fail_closed() -> None:
    module = _module()
    ledger = module._HandleOwnershipLedger()
    ledger.register(1234, resource_type="handle", identity=(1,))
    ledger.register(1234, resource_type="fd", identity=(2,))

    assert ledger.record(1234, resource_type="handle").identity == (1,)
    assert ledger.record(1234, resource_type="fd").identity == (2,)
    with pytest.raises(module.ReleaseViolation) as record_error:
        ledger.record(1234)
    assert record_error.value.code == "RELEASE_RESOURCE_TYPE_AMBIGUOUS"
    assert record_error.value.cleanup_lease is ledger
    with pytest.raises(module.ReleaseViolation) as owns_error:
        ledger.owns(1234)
    assert owns_error.value.code == "RELEASE_RESOURCE_TYPE_AMBIGUOUS"
    assert owns_error.value.cleanup_lease is ledger
    with pytest.raises(module.ReleaseViolation) as release_error:
        ledger.release(1234)
    assert release_error.value.code == "RELEASE_RESOURCE_TYPE_AMBIGUOUS"
    assert release_error.value.cleanup_lease is ledger
    with pytest.raises(module.ReleaseViolation) as identity_error:
        ledger.set_identity(1234, (9,))
    assert identity_error.value.code == "RELEASE_RESOURCE_TYPE_AMBIGUOUS"
    assert identity_error.value.cleanup_lease is ledger
    with pytest.raises(module.ReleaseViolation) as close_error:
        module._close_ledger_handle(ledger, 1234)
    assert close_error.value.code == "RELEASE_RESOURCE_TYPE_AMBIGUOUS"
    assert close_error.value.cleanup_lease is ledger
    assert ledger.owns(1234, resource_type="handle")
    assert ledger.owns(1234, resource_type="fd")


def test_fd_transfer_keeps_preexisting_handle_on_numeric_collision() -> None:
    """Model open_osfhandle returning a value used by an existing HANDLE."""
    module = _module()
    ledger = module._HandleOwnershipLedger()
    ledger.register(1234, resource_type="handle", identity=(1,))
    ledger.register(5678, resource_type="handle", identity=(2,))

    ledger.release(5678, resource_type="handle")
    ledger.register(1234, resource_type="fd", identity=(3,))

    assert ledger.record(1234, resource_type="handle").identity == (1,)
    assert ledger.record(1234, resource_type="fd").identity == (3,)
    assert ledger.record(5678, resource_type="handle") is None


def test_handle_ledger_does_not_retry_without_stable_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    ledger = module._HandleOwnershipLedger()
    ledger.register(77, resource_type="fd")
    calls: list[int] = []

    def close_fails(handle: int, **_kwargs: object) -> None:
        calls.append(handle)
        raise OSError("close outcome unknown")

    monkeypatch.setattr(module, "_close_bound_handle", close_fails)
    assert module._close_ledger_handle(ledger, 77) is False
    assert calls == [77]
    assert ledger.owns(77)


@pytest.mark.parametrize("failure_stage", ("close", "identity", "retry"))
def test_handle_ledger_normalizes_arbitrary_close_failure(
    monkeypatch: pytest.MonkeyPatch, failure_stage: str
) -> None:
    module = _module()
    ledger = module._HandleOwnershipLedger()
    ledger.register(77, resource_type="fd", identity=(1, 2))

    close_calls: list[int] = []

    def close(handle: int, **_kwargs: object) -> None:
        close_calls.append(handle)
        if failure_stage == "close" or (
            failure_stage == "retry" and len(close_calls) == 2
        ):
            raise RuntimeError("close details must not escape")
        if failure_stage in {"identity", "retry"} and len(close_calls) == 1:
            raise OSError("close outcome is unknown")

    monkeypatch.setattr(module, "_close_bound_handle", close)
    monkeypatch.setattr(
        module,
        "_bound_handle_identity",
        lambda *_args, **_kwargs: (
            (_ for _ in ()).throw(RuntimeError("identity details must not escape"))
            if failure_stage == "identity"
            else (1, 2)
        ),
    )

    assert module._close_ledger_handle(ledger, 77) is False
    assert ledger.owns(77)
    expected_calls = [77] if failure_stage == "identity" else [77, 77]
    assert close_calls == expected_calls


def test_open_verified_file_keeps_primary_code_when_close_raises_runtime_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    source = tmp_path / "source.bin"
    source.write_bytes(b"source")
    snapshot = module._snapshot_file(
        source, max_bytes=module.MAX_INPUT_BYTES, code="RELEASE_INPUT_PATH_INVALID"
    )
    monkeypatch.setattr(module, "_close_bound_handle", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("close details must not escape")))
    monkeypatch.setattr(module.os, "open", lambda *_args, **_kwargs: 77)
    monkeypatch.setattr(module, "_bound_handle_identity", lambda *_args, **_kwargs: snapshot.identity)

    class FailingStream:
        def close(self) -> None:
            raise RuntimeError("stream close details must not escape")

    monkeypatch.setattr(module.os, "fdopen", lambda *_args, **_kwargs: FailingStream())
    with pytest.raises(module.ReleaseViolation) as caught:
        with module._open_verified_file(
            snapshot,
            max_bytes=module.MAX_INPUT_BYTES,
            code="RELEASE_INPUT_PATH_INVALID",
        ):
            raise module.ReleaseViolation("RELEASE_SOURCE_STATE_INVALID")
    assert caught.value.code == "RELEASE_SOURCE_STATE_INVALID"
    assert caught.value.cleanup_lease is not None


def test_create_output_file_keeps_primary_code_when_close_raises_runtime_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    output = tmp_path / "output.bin"
    monkeypatch.setattr(module, "_close_bound_handle", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("close details must not escape")))
    monkeypatch.setattr(module.os, "open", lambda *_args, **_kwargs: 77)
    monkeypatch.setattr(module, "_bound_handle_identity", lambda *_args, **_kwargs: (1, 2))

    class FailingStream:
        def close(self) -> None:
            raise RuntimeError("stream close details must not escape")

    monkeypatch.setattr(module.os, "fdopen", lambda *_args, **_kwargs: FailingStream())
    with pytest.raises(module.ReleaseViolation) as caught:
        with module._create_output_file(output):
            raise module.ReleaseViolation("RELEASE_SOURCE_STATE_INVALID")
    assert caught.value.code == "RELEASE_SOURCE_STATE_INVALID"
    assert caught.value.cleanup_lease is not None


@pytest.mark.parametrize("failure_stage", ("identity", "fdopen"))
@pytest.mark.parametrize("exception_type", (KeyboardInterrupt, SystemExit))
def test_create_output_file_cleans_up_base_exception_during_setup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
    exception_type: type[BaseException],
) -> None:
    module = _module()
    descriptor = 177
    monkeypatch.setattr(module.os, "open", lambda *_args, **_kwargs: descriptor)
    monkeypatch.setattr(
        module,
        "_bound_handle_identity",
        (
            lambda *_args, **_kwargs: (_ for _ in ()).throw(exception_type())
            if failure_stage == "identity"
            else (1, 2)
        ),
    )
    if failure_stage == "fdopen":
        monkeypatch.setattr(
            module.os,
            "fdopen",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(exception_type()),
        )
    close_calls: list[int] = []
    monkeypatch.setattr(
        module,
        "_close_bound_handle",
        lambda handle, **_kwargs: close_calls.append(handle),
    )

    with pytest.raises(exception_type):
        with module._create_output_file(tmp_path / "output.bin"):
            pass
    assert close_calls == [descriptor]


def test_create_output_file_keeps_base_exception_lease_when_setup_cleanup_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    descriptor = 177
    monkeypatch.setattr(module.os, "open", lambda *_args, **_kwargs: descriptor)
    monkeypatch.setattr(
        module,
        "_bound_handle_identity",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    close_calls: list[int] = []

    def close_fails(handle: int, **_kwargs: object) -> None:
        close_calls.append(handle)
        raise OSError("close failed")

    monkeypatch.setattr(module, "_close_bound_handle", close_fails)
    with pytest.raises(KeyboardInterrupt) as caught:
        with module._create_output_file(tmp_path / "output.bin"):
            pass
    assert caught.value.cleanup_lease.owns(descriptor)
    assert close_calls == [descriptor]


@pytest.mark.parametrize("exception_type", (KeyboardInterrupt, SystemExit))
def test_open_verified_file_preserves_base_exception_and_attaches_cleanup_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    exception_type: type[BaseException],
) -> None:
    module = _module()
    source = tmp_path / "source.bin"
    source.write_bytes(b"source")
    snapshot = module._snapshot_file(
        source, max_bytes=module.MAX_INPUT_BYTES, code="RELEASE_INPUT_PATH_INVALID"
    )
    descriptor = 177
    monkeypatch.setattr(module.os, "open", lambda *_args, **_kwargs: descriptor)
    monkeypatch.setattr(
        module,
        "_bound_handle_identity",
        lambda *_args, **_kwargs: snapshot.identity,
    )

    class FailingStream:
        def close(self) -> None:
            raise RuntimeError("stream close failed")

    monkeypatch.setattr(module.os, "fdopen", lambda *_args, **_kwargs: FailingStream())
    close_calls: list[int] = []

    def close_fails(handle: int, **_kwargs: object) -> None:
        close_calls.append(handle)
        raise OSError("close failed")

    monkeypatch.setattr(module, "_close_bound_handle", close_fails)
    with pytest.raises(exception_type) as caught:
        with module._open_verified_file(
            snapshot,
            max_bytes=module.MAX_INPUT_BYTES,
            code="RELEASE_INPUT_PATH_INVALID",
        ):
            raise exception_type()
    assert caught.value.cleanup_lease.owns(descriptor)
    assert close_calls == [descriptor, descriptor]


def test_snapshot_staging_directory_cleans_up_base_exception_after_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    staged = tmp_path / ".release.staging-test"
    staged.mkdir()
    binding = module._DirectoryBinding(tmp_path, (1,), 11)
    original_lstat = Path.lstat
    opened = False

    def lstat(path: Path) -> object:
        if path == staged and opened:
            raise KeyboardInterrupt()
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(module.os, "name", "posix")
    monkeypatch.setattr(module.os, "O_DIRECTORY", 0x10000, raising=False)
    monkeypatch.setattr(module.os, "O_NOFOLLOW", 0x20000, raising=False)
    def open_directory(*_args: object, **_kwargs: object) -> int:
        nonlocal opened
        opened = True
        return 177

    monkeypatch.setattr(module.os, "open", open_directory)
    monkeypatch.setattr(
        module,
        "_bound_handle_identity",
        lambda handle, **_kwargs: (1,) if handle == 11 else (2,),
    )
    close_calls: list[int] = []
    monkeypatch.setattr(
        module,
        "_close_bound_handle",
        lambda handle, **_kwargs: close_calls.append(handle),
    )

    with pytest.raises(KeyboardInterrupt):
        module._snapshot_staging_directory(staged, ".release.staging-", binding)
    assert close_calls == [177]


def test_validated_staging_path_keeps_base_exception_lease_when_close_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    staged = tmp_path / ".release.staging-test"
    staged.mkdir()
    token = module._StagingDirectoryToken(
        parent=tmp_path,
        name=staged.name,
        prefix=".release.staging-",
        parent_identity=(1,),
        identity=(2,),
        is_reparse_point=False,
        parent_handle=11,
        directory_handle=22,
    )
    calls = 0

    def open_directory(*_args: object) -> tuple[int, tuple[int, ...]]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return 177, (1,)
        raise KeyboardInterrupt()

    monkeypatch.setattr(module, "_open_bound_directory", open_directory)
    close_calls: list[int] = []

    def close_fails(handle: int, **_kwargs: object) -> None:
        close_calls.append(handle)
        raise OSError("close failed")

    monkeypatch.setattr(module, "_close_bound_handle", close_fails)
    monkeypatch.setattr(
        module,
        "_bound_handle_identity",
        lambda handle, **_kwargs: (1,)
        if handle == 11
        else (3,)
        if handle == 177
        else (2,),
    )
    with pytest.raises(KeyboardInterrupt) as caught:
        module._validated_staging_path(token, staged, "RELEASE_OUTPUT_PATH_INVALID")
    assert caught.value.cleanup_lease.owns(177)
    assert close_calls == [177]


@pytest.mark.skipif(os.name != "nt", reason="native Windows open test requires Windows")
@pytest.mark.parametrize("close_fails", (False, True))
def test_ntdll_open_relative_directory_normalizes_base_exception(
    monkeypatch: pytest.MonkeyPatch, close_fails: bool
) -> None:
    module = _module()

    class NativeOpen:
        argtypes = None
        restype = None

        def __call__(self, handle_pointer: object, *_args: object) -> int:
            ctypes.cast(handle_pointer, ctypes.POINTER(ctypes.c_void_p)).contents.value = 177
            raise RuntimeError("native open failed")

    class FakeNtdll:
        NtCreateFile = NativeOpen()

    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: FakeNtdll())
    close_calls: list[int] = []

    def close(handle: int, **_kwargs: object) -> None:
        close_calls.append(handle)
        if close_fails:
            raise OSError("close failed")

    monkeypatch.setattr(module, "_close_bound_handle", close)
    with pytest.raises(module.ReleaseViolation) as caught:
        module._ntdll_open_relative_directory(11, "staging")
    assert caught.value.code == "RELEASE_OUTPUT_PATH_INVALID"
    assert close_calls == [177]
    if close_fails:
        assert caught.value.cleanup_lease.owns(177)
    else:
        assert caught.value.cleanup_lease is None


def test_validated_staging_path_normalizes_arbitrary_error_and_keeps_cleanup_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    staged = tmp_path / ".release.staging-test"
    staged.mkdir()
    token = module._StagingDirectoryToken(
        parent=tmp_path,
        name=staged.name,
        prefix=".release.staging-",
        parent_identity=(1,),
        identity=(2,),
        is_reparse_point=False,
        parent_handle=11,
        directory_handle=22,
    )
    calls = 0

    def open_directory(*_args: object) -> tuple[int, tuple[int, ...]]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return 77, (1,)
        raise RuntimeError("directory details must not escape")

    monkeypatch.setattr(module, "_open_bound_directory", open_directory)
    monkeypatch.setattr(module, "_close_bound_handle", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("close details must not escape")))
    monkeypatch.setattr(
        module,
        "_bound_handle_identity",
        lambda handle, **_kwargs: (1,) if handle in (11, 77) else (2,),
    )
    with pytest.raises(module.ReleaseViolation) as caught:
        module._validated_staging_path(
            token, staged, "RELEASE_OUTPUT_PATH_INVALID"
        )
    assert caught.value.code == "RELEASE_OUTPUT_PATH_INVALID"
    assert caught.value.cleanup_lease is not None
    assert caught.value.cleanup_lease.owns(77)


def test_validate_staging_contents_normalizes_path_iteration_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    staged = tmp_path / ".release.staging-test"
    staged.mkdir()
    child = module._StagedChildToken(
        "asset.bin", module._FileSnapshot(staged, (1, 2, 3, 4), 0), "digest"
    )
    token = module._StagingDirectoryToken(
        parent=tmp_path,
        name=staged.name,
        prefix=".release.staging-",
        parent_identity=(1,),
        identity=(2,),
        is_reparse_point=False,
        parent_handle=11,
        directory_handle=22,
        children=(child,),
    )
    monkeypatch.setattr(module, "_validated_staging_path", lambda *_args: staged)
    monkeypatch.setattr(
        Path,
        "iterdir",
        lambda _path: (_ for _ in ()).throw(
            RuntimeError("iteration details must not escape")
        ),
    )
    with pytest.raises(module.ReleaseViolation) as caught:
        module._validate_staging_contents(token, staged)
    assert caught.value.code == "RELEASE_OUTPUT_PATH_INVALID"
    assert token.ledger.owns(11)
    assert token.ledger.owns(22)


def test_validate_staging_contents_normalizes_child_identity_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    staged = tmp_path / ".release.staging-test"
    staged.mkdir()
    child_path = staged / "asset.bin"
    child_path.write_bytes(b"asset")
    child = module._StagedChildToken(
        "asset.bin",
        module._snapshot_file(
            child_path, max_bytes=module.MAX_INPUT_BYTES, code="RELEASE_ASSET_DIGEST_MISMATCH"
        ),
        "digest",
        77,
    )
    token = module._StagingDirectoryToken(
        parent=tmp_path,
        name=staged.name,
        prefix=".release.staging-",
        parent_identity=(1,),
        identity=(2,),
        is_reparse_point=False,
        parent_handle=11,
        directory_handle=22,
        children=(child,),
    )
    monkeypatch.setattr(module, "_validated_staging_path", lambda *_args: staged)
    monkeypatch.setattr(module, "_bound_handle_identity", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("identity details must not escape")))
    monkeypatch.setattr(module, "_staging_file_limit", lambda _name: (module.MAX_INPUT_BYTES, "RELEASE_ASSET_DIGEST_MISMATCH"))
    with pytest.raises(module.ReleaseViolation) as caught:
        module._validate_staging_contents(token, staged)
    assert caught.value.code == "RELEASE_ASSET_DIGEST_MISMATCH"
    assert token.ledger.owns(77)


def test_validate_staging_contents_normalizes_snapshot_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    staged = tmp_path / ".release.staging-test"
    staged.mkdir()
    (staged / "asset.bin").write_bytes(b"asset")
    child = module._StagedChildToken(
        "asset.bin", module._FileSnapshot(staged, (1, 2, 3, 4), 0), "digest", 77
    )
    token = module._StagingDirectoryToken(
        parent=tmp_path,
        name=staged.name,
        prefix=".release.staging-",
        parent_identity=(1,),
        identity=(2,),
        is_reparse_point=False,
        parent_handle=11,
        directory_handle=22,
        children=(child,),
    )
    monkeypatch.setattr(module, "_validated_staging_path", lambda *_args: staged)
    monkeypatch.setattr(module, "_snapshot_file", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("snapshot details must not escape")))
    monkeypatch.setattr(module, "_staging_file_limit", lambda _name: (module.MAX_INPUT_BYTES, "RELEASE_ASSET_DIGEST_MISMATCH"))
    with pytest.raises(module.ReleaseViolation) as caught:
        module._validate_staging_contents(token, staged)
    assert caught.value.code == "RELEASE_ASSET_DIGEST_MISMATCH"
    assert token.ledger.owns(77)


def test_bind_directory_normalizes_arbitrary_path_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(
        module,
        "_has_reparse_component",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("path details must not escape")
        ),
    )
    with pytest.raises(module.ReleaseViolation) as caught:
        module._bind_directory(tmp_path, 0)
    assert caught.value.code == "RELEASE_OUTPUT_PATH_INVALID"


def test_bind_directory_preserves_nested_cleanup_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    lease = module._HandleOwnershipLedger()
    lease.register(77, resource_type="directory", identity=(1,))
    nested = module.ReleaseViolation(
        "RELEASE_OUTPUT_PATH_INVALID", cleanup_lease=lease
    )
    monkeypatch.setattr(module, "_open_bound_directory", lambda *_args: (_ for _ in ()).throw(nested))
    with pytest.raises(module.ReleaseViolation) as caught:
        module._bind_directory(tmp_path, 0)
    assert caught.value.code == "RELEASE_OUTPUT_PATH_INVALID"
    assert caught.value.cleanup_lease is lease
    assert lease.owns(77)


def test_close_bound_handles_attempts_all_handles_after_one_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    token = module._StagingDirectoryToken(
        parent=tmp_path,
        name=".release.staging-bound",
        prefix=".release.staging-",
        parent_identity=(1, 2),
        identity=(3, 4),
        is_reparse_point=False,
        parent_handle=11,
        directory_handle=22,
    )
    monkeypatch.setattr(
        module,
        "_bound_handle_identity",
        lambda handle, **_kwargs: (1, 2) if handle == 11 else (3, 4),
    )
    calls: list[int] = []

    def close(handle: int, **_kwargs: object) -> None:
        calls.append(handle)
        if handle == 22:
            raise OSError("close failed")

    monkeypatch.setattr(module, "_close_bound_handle", close)
    assert module._close_staging_token(token) == "RELEASE_RESOURCE_CLOSE_FAILED"
    assert calls == [22, 22, 11]


def test_close_staging_children_retains_failed_handle_for_cleanup_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    snapshot = module._FileSnapshot(tmp_path / "asset", (1, 2, 3, 4), 1)
    token = module._StagingDirectoryToken(
        parent=tmp_path,
        name=".release.staging-test",
        prefix=".release.staging-",
        parent_identity=(1,),
        identity=(2,),
        is_reparse_point=False,
        parent_handle=None,
        directory_handle=None,
        children=(module._StagedChildToken("asset", snapshot, "a" * 64, 77),),
    )
    calls: list[int] = []

    def close_once(handle: int, **_kwargs: object) -> None:
        calls.append(handle)
        if len(calls) == 1:
            raise OSError("close failed")

    monkeypatch.setattr(module, "_close_bound_handle", close_once)
    detached, code = module._close_staging_child_handles(token)

    assert code == "RELEASE_RESOURCE_CLOSE_FAILED"
    assert detached.children[0].handle == 77
    assert module._close_staging_token(detached) is None
    assert calls == [77, 77]


def test_staging_token_retries_with_stable_identity_without_losing_ownership(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    token = module._StagingDirectoryToken(
        parent=tmp_path,
        name=".release.staging-test",
        prefix=".release.staging-",
        parent_identity=(1,),
        identity=(2,),
        is_reparse_point=False,
        parent_handle=None,
        directory_handle=77,
    )
    monkeypatch.setattr(
        module, "_bound_handle_identity", lambda *_args, **_kwargs: (2,)
    )
    calls: list[int] = []

    def close(handle: int, **_kwargs: object) -> None:
        calls.append(handle)
        if len(calls) < 3:
            raise OSError("close failed")

    monkeypatch.setattr(module, "_close_bound_handle", close)
    assert module._close_staging_token(token) == "RELEASE_RESOURCE_CLOSE_FAILED"
    assert 77 in token.ledger.handles()
    assert module._close_staging_token(token) is None
    assert calls == [77, 77, 77]


def test_staging_token_does_not_repeat_confirmed_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    token = module._StagingDirectoryToken(
        parent=tmp_path,
        name=".release.staging-test",
        prefix=".release.staging-",
        parent_identity=(1,),
        identity=(2,),
        is_reparse_point=False,
        parent_handle=None,
        directory_handle=77,
    )
    calls: list[int] = []
    monkeypatch.setattr(
        module,
        "_close_bound_handle",
        lambda handle, **_kwargs: calls.append(handle),
    )
    assert module._close_staging_token(token) is None
    assert module._close_staging_token(token) is None
    assert calls == [77]


def test_validated_staging_path_closes_both_current_handles_after_close_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    parent = tmp_path / "parent"
    parent.mkdir()
    staged = parent / ".release.staging-test"
    staged.mkdir()
    token = module._StagingDirectoryToken(
        parent=parent,
        name=staged.name,
        prefix=".release.staging-",
        parent_identity=(1,),
        identity=(2,),
        is_reparse_point=False,
        parent_handle=11,
        directory_handle=22,
    )
    monkeypatch.setattr(
        module,
        "_bound_handle_identity",
        lambda handle, **_kwargs: (
            (1,) if handle in (11, 33) else (2,)
        ),
    )
    opened = iter(((33, (1,)), (44, (2,))))
    monkeypatch.setattr(module, "_open_bound_directory", lambda *_args: next(opened))
    calls: list[int] = []

    def close(handle: int, **_kwargs: object) -> None:
        calls.append(handle)
        if handle == 33:
            raise OSError("close failed")

    monkeypatch.setattr(module, "_close_bound_handle", close)
    with pytest.raises(
        module.ReleaseViolation, match="^RELEASE_OUTPUT_PATH_INVALID$"
    ):
        module._validated_staging_path(token, staged, "RELEASE_OUTPUT_PATH_INVALID")
    assert calls == [33, 33, 44]


def test_validated_staging_path_accepts_retry_when_both_handles_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    parent = tmp_path / "parent"
    parent.mkdir()
    staged = parent / ".release.staging-test"
    staged.mkdir()
    token = module._StagingDirectoryToken(
        parent=parent,
        name=staged.name,
        prefix=".release.staging-",
        parent_identity=(1,),
        identity=(2,),
        is_reparse_point=False,
        parent_handle=11,
        directory_handle=22,
    )
    monkeypatch.setattr(
        module,
        "_bound_handle_identity",
        lambda handle, **_kwargs: (
            (1,) if handle in (11, 33) else (2,)
        ),
    )
    opened = iter(((33, (1,)), (44, (2,))))
    monkeypatch.setattr(module, "_open_bound_directory", lambda *_args: next(opened))
    calls: list[int] = []
    attempts: dict[int, int] = {}

    def close(handle: int, **_kwargs: object) -> None:
        calls.append(handle)
        attempts[handle] = attempts.get(handle, 0) + 1
        if handle == 33 and attempts[handle] == 1:
            raise OSError("close failed")

    monkeypatch.setattr(module, "_close_bound_handle", close)
    assert module._validated_staging_path(
        token, staged, "RELEASE_OUTPUT_PATH_INVALID"
    ) == staged
    assert calls == [33, 33, 44]


def test_ntdll_open_relative_directory_closes_failed_nonempty_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()

    class FakeNtCreateFile:
        argtypes = None
        restype = None

        def __call__(self, output_handle: object, *_args: object) -> int:
            ctypes.cast(
                output_handle, ctypes.POINTER(ctypes.wintypes.HANDLE)
            ).contents.value = 1234
            return ctypes.c_int32(0xC000000D).value

    class FakeNtdll:
        NtCreateFile = FakeNtCreateFile()

    closed: list[int] = []
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: FakeNtdll())
    monkeypatch.setattr(
        module,
        "_close_bound_handle",
        lambda handle, **_kwargs: closed.append(handle),
    )
    with pytest.raises(
        module.ReleaseViolation, match="^RELEASE_OUTPUT_PATH_INVALID$"
    ):
        module._ntdll_open_relative_directory(77, ".release.staging-test")
    assert closed == [1234]


def test_ntdll_identity_failure_closes_native_handle_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()

    class FakeNtCreateFile:
        argtypes = None
        restype = None

        def __call__(self, output_handle: object, *_args: object) -> int:
            ctypes.cast(
                output_handle, ctypes.POINTER(ctypes.wintypes.HANDLE)
            ).contents.value = 1234
            return 0

    class FakeNtdll:
        NtCreateFile = FakeNtCreateFile()

    class FakeGetFileInformationByHandle:
        argtypes = None
        restype = None

        def __call__(self, *_args: object) -> int:
            return 0

    class FakeKernel32:
        GetFileInformationByHandle = FakeGetFileInformationByHandle()

    closed: list[int] = []

    def close(handle: int, *, resource_type: str = "handle") -> None:
        assert resource_type == "handle"
        closed.append(handle)

    def win_dll(name: str, **_kwargs: object) -> object:
        return FakeNtdll() if name == "ntdll" else FakeKernel32()

    monkeypatch.setattr(module.os, "name", "nt")
    monkeypatch.setattr(ctypes, "WinDLL", win_dll)
    monkeypatch.setattr(module, "_close_bound_handle", close)
    with pytest.raises(module.ReleaseViolation):
        module._ntdll_open_relative_directory(77, ".release.staging-test")
    assert closed == [1234]


def test_ntdll_arbitrary_identity_failure_normalizes_and_closes_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()

    class FakeNtCreateFile:
        argtypes = None
        restype = None

        def __call__(self, output_handle: object, *_args: object) -> int:
            ctypes.cast(
                output_handle, ctypes.POINTER(ctypes.wintypes.HANDLE)
            ).contents.value = 1234
            return 0

    class FakeNtdll:
        NtCreateFile = FakeNtCreateFile()

    class FakeGetFileInformationByHandle:
        argtypes = None
        restype = None

        def __call__(self, *_args: object) -> int:
            raise RuntimeError("unexpected identity failure")

    class FakeKernel32:
        GetFileInformationByHandle = FakeGetFileInformationByHandle()

    closed: list[int] = []

    def close(handle: int, *, resource_type: str = "handle") -> None:
        assert resource_type == "handle"
        closed.append(handle)

    def win_dll(name: str, **_kwargs: object) -> object:
        return FakeNtdll() if name == "ntdll" else FakeKernel32()

    monkeypatch.setattr(module.os, "name", "nt")
    monkeypatch.setattr(ctypes, "WinDLL", win_dll)
    monkeypatch.setattr(module, "_close_bound_handle", close)

    with pytest.raises(module.ReleaseViolation) as caught:
        module._ntdll_open_relative_directory(77, ".release.staging-test")

    assert caught.value.code == "RELEASE_OUTPUT_PATH_INVALID"
    assert caught.value.cleanup_lease is None
    assert closed == [1234]


def test_ntdll_arbitrary_identity_failure_keeps_lease_when_close_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()

    class FakeNtCreateFile:
        argtypes = None
        restype = None

        def __call__(self, output_handle: object, *_args: object) -> int:
            ctypes.cast(
                output_handle, ctypes.POINTER(ctypes.wintypes.HANDLE)
            ).contents.value = 1234
            return 0

    class FakeNtdll:
        NtCreateFile = FakeNtCreateFile()

    class FakeGetFileInformationByHandle:
        argtypes = None
        restype = None

        def __call__(self, *_args: object) -> int:
            raise RuntimeError("unexpected identity failure")

    class FakeKernel32:
        GetFileInformationByHandle = FakeGetFileInformationByHandle()

    closed: list[int] = []

    def close(handle: int, *, resource_type: str = "handle") -> None:
        assert resource_type == "handle"
        closed.append(handle)
        raise OSError("close failed")

    def win_dll(name: str, **_kwargs: object) -> object:
        return FakeNtdll() if name == "ntdll" else FakeKernel32()

    monkeypatch.setattr(module.os, "name", "nt")
    monkeypatch.setattr(ctypes, "WinDLL", win_dll)
    monkeypatch.setattr(module, "_close_bound_handle", close)

    with pytest.raises(module.ReleaseViolation) as caught:
        module._ntdll_open_relative_directory(77, ".release.staging-test")

    assert caught.value.code == "RELEASE_OUTPUT_PATH_INVALID"
    assert caught.value.cleanup_lease is not None
    assert caught.value.cleanup_lease.owns(1234)
    assert closed == [1234]


def test_open_verified_file_keeps_persistent_fd_close_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    source = tmp_path / "source.bin"
    source.write_bytes(b"source")
    snapshot = module._snapshot_file(
        source, max_bytes=module.MAX_INPUT_BYTES, code="RELEASE_INPUT_PATH_INVALID"
    )
    monkeypatch.setattr(module.os, "open", lambda *_args, **_kwargs: 77)
    monkeypatch.setattr(module.os, "fdopen", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("fdopen failed")))
    monkeypatch.setattr(module, "_bound_handle_identity", lambda *_args, **_kwargs: snapshot.identity)

    def close_fails(handle: int, *, resource_type: str = "handle") -> None:
        assert resource_type == "fd"
        assert handle == 77
        raise OSError("close failed")

    monkeypatch.setattr(module, "_close_bound_handle", close_fails)
    with pytest.raises(module.ReleaseViolation) as caught:
        with module._open_verified_file(
            snapshot,
            max_bytes=module.MAX_INPUT_BYTES,
            code="RELEASE_INPUT_PATH_INVALID",
        ):
            pass
    assert caught.value.code == "RELEASE_INPUT_PATH_INVALID"
    assert caught.value.cleanup_lease is not None
    assert caught.value.cleanup_lease.owns(77)


def test_fd_ledger_uses_os_close_even_when_platform_is_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    ledger = module._HandleOwnershipLedger()
    ledger.register(77, resource_type="fd", identity=(1, 2))
    closed: list[int] = []
    monkeypatch.setattr(module.os, "name", "nt")
    monkeypatch.setattr(module.os, "close", closed.append)

    def unexpected_kernel32(*_args: object, **_kwargs: object) -> object:
        pytest.fail("CRT fd cleanup must not call CloseHandle")

    monkeypatch.setattr(ctypes, "WinDLL", unexpected_kernel32)
    assert module._close_ledger_handle(ledger, 77)
    assert closed == [77]
    assert not ledger.owns(77)


@pytest.mark.parametrize(
    ("mode", "allow_missing", "returns_none"),
    (
        ("exception", False, False),
        ("missing", True, False),
        ("failure", False, False),
    ),
)
def test_ntdll_create_staging_file_bounded_cleanup_of_failed_handle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    allow_missing: bool,
    returns_none: bool,
) -> None:
    if os.name != "nt":
        pytest.skip("Windows native create failure cleanup")
    module = _module()
    sensitive = str(tmp_path / "private-output")

    class FakeNtCreateFile:
        argtypes = None
        restype = None

        def __call__(self, output_handle: object, *_args: object) -> int:
            ctypes.cast(
                output_handle, ctypes.POINTER(ctypes.wintypes.HANDLE)
            ).contents.value = 1234
            if mode == "exception":
                raise OSError(sensitive)
            if mode == "missing":
                return -1073741772
            return ctypes.c_int32(0xC000000D).value

    class FakeNtdll:
        NtCreateFile = FakeNtCreateFile()

    closed: list[int] = []

    def fail_close(handle: int, **_kwargs: object) -> None:
        closed.append(handle)
        raise OSError(sensitive)

    token = module._StagingDirectoryToken(
        parent=tmp_path,
        name=".release.staging-test",
        prefix=".release.staging-",
        parent_identity=(1,),
        identity=(2,),
        is_reparse_point=False,
        parent_handle=11,
        directory_handle=22,
    )
    token.ledger.release(11)
    token.ledger.release(22)
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: FakeNtdll())
    monkeypatch.setattr(module, "_close_bound_handle", fail_close)

    if returns_none:
        assert module._ntdll_create_staging_file(
            token, module.PORTABLE_NAME, allow_missing=allow_missing
        ) is None
    else:
        with pytest.raises(
            module.ReleaseViolation,
            match=(
                "^RELEASE_RESOURCE_CLOSE_FAILED$"
                if mode == "missing"
                else "^RELEASE_OUTPUT_PATH_INVALID$"
            ),
        ) as caught:
            module._ntdll_create_staging_file(
                token, module.PORTABLE_NAME, allow_missing=allow_missing
            )
        assert sensitive not in str(caught.value)
    assert closed == [1234]


def test_ntdll_create_missing_retains_lease_after_persistent_close_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name != "nt":
        pytest.skip("Windows native create failure cleanup")
    module = _module()

    class FakeNtCreateFile:
        argtypes = None
        restype = None

        def __call__(self, output_handle: object, *_args: object) -> int:
            ctypes.cast(
                output_handle, ctypes.POINTER(ctypes.wintypes.HANDLE)
            ).contents.value = 1234
            return -1073741772

    class FakeNtdll:
        NtCreateFile = FakeNtCreateFile()

    calls: list[int] = []
    close_attempts = 0

    def close(handle: int, **_kwargs: object) -> None:
        nonlocal close_attempts
        calls.append(handle)
        close_attempts += 1
        if close_attempts < 2:
            raise OSError("close failed")

    token = module._StagingDirectoryToken(
        parent=tmp_path,
        name=".release.staging-test",
        prefix=".release.staging-",
        parent_identity=(1,),
        identity=(2,),
        is_reparse_point=False,
        parent_handle=11,
        directory_handle=22,
    )
    token.ledger.release(11)
    token.ledger.release(22)
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: FakeNtdll())
    monkeypatch.setattr(module, "_close_bound_handle", close)
    with pytest.raises(
        module.ReleaseViolation, match="^RELEASE_RESOURCE_CLOSE_FAILED$"
    ) as caught:
        module._ntdll_create_staging_file(
            token, module.PORTABLE_NAME, allow_missing=True
        )
    assert getattr(caught.value, "cleanup_lease", None) is token.ledger
    assert calls == [1234]
    assert module._close_staging_token(token) is None
    assert calls == [1234, 1234]


@pytest.mark.parametrize("exception_type", (KeyboardInterrupt, SystemExit))
def test_open_verified_file_stream_base_exception_uses_fd_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    exception_type: type[BaseException],
) -> None:
    module = _module()
    source = tmp_path / "source.bin"
    source.write_bytes(b"source")
    snapshot = module._snapshot_file(
        source, max_bytes=module.MAX_INPUT_BYTES, code="RELEASE_INPUT_PATH_INVALID"
    )
    descriptor = 177
    monkeypatch.setattr(module.os, "open", lambda *_args, **_kwargs: descriptor)
    monkeypatch.setattr(
        module,
        "_bound_handle_identity",
        lambda *_args, **_kwargs: snapshot.identity,
    )

    class InterruptingStream:
        def close(self) -> None:
            raise exception_type()

    monkeypatch.setattr(module.os, "fdopen", lambda *_args, **_kwargs: InterruptingStream())
    close_calls: list[tuple[int, str]] = []
    monkeypatch.setattr(
        module,
        "_close_bound_handle",
        lambda handle, **kwargs: close_calls.append((handle, kwargs["resource_type"])),
    )

    with pytest.raises(exception_type):
        with module._open_verified_file(
            snapshot,
            max_bytes=module.MAX_INPUT_BYTES,
            code="RELEASE_INPUT_PATH_INVALID",
        ):
            pass
    assert close_calls == [(descriptor, "fd")]


@pytest.mark.parametrize("exception_type", (KeyboardInterrupt, SystemExit))
def test_create_output_file_stream_base_exception_uses_fd_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    exception_type: type[BaseException],
) -> None:
    module = _module()
    descriptor = 177
    monkeypatch.setattr(module.os, "open", lambda *_args, **_kwargs: descriptor)
    monkeypatch.setattr(
        module,
        "_bound_handle_identity",
        lambda *_args, **_kwargs: (1, 2),
    )

    class InterruptingStream:
        def close(self) -> None:
            raise exception_type()

    monkeypatch.setattr(module.os, "fdopen", lambda *_args, **_kwargs: InterruptingStream())
    close_calls: list[tuple[int, str]] = []
    monkeypatch.setattr(
        module,
        "_close_bound_handle",
        lambda handle, **kwargs: close_calls.append((handle, kwargs["resource_type"])),
    )

    with pytest.raises(exception_type):
        with module._create_output_file(tmp_path / "output.bin"):
            pass
    assert close_calls == [(descriptor, "fd")]


@pytest.mark.parametrize("exception_type", (KeyboardInterrupt, SystemExit))
def test_open_bound_posix_directory_base_exception_uses_directory_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    exception_type: type[BaseException],
) -> None:
    module = _module()
    monkeypatch.setattr(module.os, "name", "posix")
    handle = 88
    monkeypatch.setattr(module.os, "open", lambda *_args, **_kwargs: handle)
    monkeypatch.setattr(
        module,
        "_bound_handle_identity",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(exception_type()),
    )
    close_calls: list[tuple[int, str]] = []
    monkeypatch.setattr(
        module,
        "_close_bound_handle",
        lambda value, **kwargs: close_calls.append((value, kwargs["resource_type"])),
    )

    with pytest.raises(exception_type):
        module._open_bound_directory(tmp_path, 0)
    assert close_calls == [(handle, "directory")]


@pytest.mark.skipif(os.name != "nt", reason="native Windows open test requires Windows")
@pytest.mark.parametrize("exception_type", (KeyboardInterrupt, SystemExit))
def test_ntdll_open_relative_directory_identity_base_exception_cleans_handle(
    monkeypatch: pytest.MonkeyPatch,
    exception_type: type[BaseException],
) -> None:
    module = _module()

    class NativeOpen:
        argtypes = None
        restype = None

        def __call__(self, output_handle: object, *_args: object) -> int:
            ctypes.cast(
                output_handle, ctypes.POINTER(ctypes.wintypes.HANDLE)
            ).contents.value = 177
            return 0

    class FakeNtdll:
        NtCreateFile = NativeOpen()

    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: FakeNtdll())
    monkeypatch.setattr(
        module,
        "_bound_handle_identity",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(exception_type()),
    )
    close_calls: list[tuple[int, str]] = []
    monkeypatch.setattr(
        module,
        "_close_bound_handle",
        lambda handle, **kwargs: close_calls.append((handle, kwargs["resource_type"])),
    )

    with pytest.raises(exception_type):
        module._ntdll_open_relative_directory(11, "staging")
    assert close_calls == [(177, "handle")]


@pytest.mark.skipif(os.name != "nt", reason="native Windows create test requires Windows")
@pytest.mark.parametrize("exception_type", (RuntimeError, KeyboardInterrupt, SystemExit))
def test_ntdll_create_staging_file_registers_handle_after_native_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    exception_type: type[BaseException],
) -> None:
    module = _module()

    class NativeCreate:
        argtypes = None
        restype = None

        def __call__(self, output_handle: object, *_args: object) -> int:
            ctypes.cast(
                output_handle, ctypes.POINTER(ctypes.wintypes.HANDLE)
            ).contents.value = 1234
            raise exception_type("native create failed")

    class FakeNtdll:
        NtCreateFile = NativeCreate()

    token = module._StagingDirectoryToken(
        parent=tmp_path,
        name=".release.staging-test",
        prefix=".release.staging-",
        parent_identity=(1,),
        identity=(2,),
        is_reparse_point=False,
        parent_handle=11,
        directory_handle=22,
    )
    token.ledger.release(11)
    token.ledger.release(22)
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: FakeNtdll())
    close_calls: list[tuple[int, str]] = []
    monkeypatch.setattr(
        module,
        "_close_bound_handle",
        lambda handle, **kwargs: close_calls.append((handle, kwargs["resource_type"])),
    )

    if issubclass(exception_type, Exception):
        with pytest.raises(module.ReleaseViolation) as caught:
            module._ntdll_create_staging_file(token, module.PORTABLE_NAME)
        assert caught.value.code == "RELEASE_OUTPUT_PATH_INVALID"
    else:
        with pytest.raises(exception_type):
            module._ntdll_create_staging_file(token, module.PORTABLE_NAME)
    assert close_calls == [(1234, "handle")]
    assert not token.ledger.owns(1234)


@pytest.mark.skipif(os.name != "nt", reason="native Windows create test requires Windows")
@pytest.mark.parametrize("exception_type", (RuntimeError, KeyboardInterrupt, SystemExit))
def test_ntdll_create_staging_file_open_osfhandle_exception_keeps_handle_ownership(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    exception_type: type[BaseException],
) -> None:
    module = _module()

    class NativeCreate:
        argtypes = None
        restype = None

        def __call__(self, output_handle: object, *_args: object) -> int:
            ctypes.cast(
                output_handle, ctypes.POINTER(ctypes.wintypes.HANDLE)
            ).contents.value = 1234
            return 0

    class FakeNtdll:
        NtCreateFile = NativeCreate()

    token = module._StagingDirectoryToken(
        parent=tmp_path,
        name=".release.staging-test",
        prefix=".release.staging-",
        parent_identity=(1,),
        identity=(2,),
        is_reparse_point=False,
        parent_handle=11,
        directory_handle=22,
    )
    token.ledger.release(11)
    token.ledger.release(22)
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: FakeNtdll())
    import msvcrt

    monkeypatch.setattr(
        msvcrt,
        "open_osfhandle",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(exception_type("fd transfer failed")),
    )
    close_calls: list[tuple[int, str]] = []
    monkeypatch.setattr(
        module,
        "_close_bound_handle",
        lambda handle, **kwargs: close_calls.append((handle, kwargs["resource_type"])),
    )

    if issubclass(exception_type, Exception):
        with pytest.raises(module.ReleaseViolation) as caught:
            module._ntdll_create_staging_file(token, module.PORTABLE_NAME)
        assert caught.value.code == "RELEASE_OUTPUT_PATH_INVALID"
    else:
        with pytest.raises(exception_type):
            module._ntdll_create_staging_file(token, module.PORTABLE_NAME)
    assert close_calls == [(1234, "handle")]
    assert not token.ledger.owns(1234)


def test_close_ledger_handle_does_not_swallow_base_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    ledger = module._HandleOwnershipLedger()
    ledger.register(77, resource_type="fd", identity=(1, 2))

    def interrupting_close(*_args: object, **_kwargs: object) -> None:
        raise KeyboardInterrupt()

    monkeypatch.setattr(module, "_close_bound_handle", interrupting_close)
    with pytest.raises(KeyboardInterrupt):
        module._close_ledger_handle(ledger, 77)
    assert ledger.owns(77)


def test_stage_reports_close_failure_after_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    output = tmp_path / "release"

    def fail_close(_token: object) -> None:
        raise OSError("close failed")

    monkeypatch.setattr(module, "_close_staging_token", fail_close)
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_RESOURCE_CLOSE_FAILED$"):
        module.stage_public_preview_release(
            ROOT,
            output,
            installer_path=installer,
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )
    assert output.exists()


def test_stage_preserves_primary_code_and_staging_cleanup_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    output = tmp_path / "release"
    observed: dict[str, object] = {}
    original_close = module._close_staging_token

    def fail_source_verification(*_args: object, **_kwargs: object) -> None:
        raise module.ReleaseViolation("RELEASE_SOURCE_STATE_INVALID")

    def retain_staging_lease(
        token: module._StagingDirectoryToken | None,
    ) -> str:
        assert token is not None
        observed["token"] = token
        return "RELEASE_RESOURCE_CLOSE_FAILED"

    def discard_staging(path: Path | None, _token: object) -> None:
        if path is not None:
            shutil.rmtree(path, ignore_errors=True)

    monkeypatch.setattr(module, "_verify_source_inputs", fail_source_verification)
    monkeypatch.setattr(module, "_close_staging_token", retain_staging_lease)
    monkeypatch.setattr(module, "_cleanup_temporary_output", discard_staging)
    try:
        with pytest.raises(module.ReleaseViolation) as caught:
            module.stage_public_preview_release(
                ROOT,
                output,
                installer_path=installer,
                portable_path=portable,
                skill_path=skill,
                source_commit=COMMIT,
                built_at=BUILT_AT,
            )
        token = observed["token"]
        assert isinstance(token, module._StagingDirectoryToken)
        assert caught.value.code == "RELEASE_SOURCE_STATE_INVALID"
        assert caught.value.cleanup_lease is token.ledger
        assert token.ledger.handles()
    finally:
        token = observed.get("token")
        if isinstance(token, module._StagingDirectoryToken):
            original_close(token)


def test_stage_preserves_parent_binding_lease_before_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    output = tmp_path / "release"
    observed: dict[str, object] = {}
    original_close = module._close_directory_binding

    def fail_mkdtemp(*_args: object, **_kwargs: object) -> Path:
        raise OSError("temporary directory failed")

    def retain_parent_lease(
        binding: module._DirectoryBinding | None,
    ) -> str:
        assert binding is not None
        observed["binding"] = binding
        return "RELEASE_RESOURCE_CLOSE_FAILED"

    monkeypatch.setattr(module.tempfile, "mkdtemp", fail_mkdtemp)
    monkeypatch.setattr(module, "_close_directory_binding", retain_parent_lease)
    try:
        with pytest.raises(module.ReleaseViolation) as caught:
            module.stage_public_preview_release(
                ROOT,
                output,
                installer_path=installer,
                portable_path=portable,
                skill_path=skill,
                source_commit=COMMIT,
                built_at=BUILT_AT,
            )
        binding = observed["binding"]
        assert isinstance(binding, module._DirectoryBinding)
        assert caught.value.code == "RELEASE_OUTPUT_PATH_INVALID"
        assert caught.value.cleanup_lease is binding.ledger
        assert binding.ledger.owns(binding.handle)
    finally:
        binding = observed.get("binding")
        if isinstance(binding, module._DirectoryBinding):
            original_close(binding)


def test_create_output_file_fdopen_type_error_keeps_fd_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    output = tmp_path / "output.bin"
    monkeypatch.setattr(module.os, "open", lambda *_args, **_kwargs: 77)
    monkeypatch.setattr(
        module.os,
        "fdopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(TypeError("fdopen failed")),
    )
    monkeypatch.setattr(module, "_bound_handle_identity", lambda *_args, **_kwargs: (1, 2))
    close_calls: list[int] = []

    def close_fails(handle: int, *, resource_type: str = "handle") -> None:
        assert resource_type == "fd"
        close_calls.append(handle)
        raise OSError("close failed")

    monkeypatch.setattr(module, "_close_bound_handle", close_fails)
    with pytest.raises(module.ReleaseViolation) as caught:
        with module._create_output_file(output):
            pass
    assert caught.value.code == "RELEASE_OUTPUT_PATH_INVALID"
    assert caught.value.cleanup_lease is not None
    assert caught.value.cleanup_lease.owns(77)
    assert close_calls == [77, 77]


def test_open_verified_file_normalizes_unexpected_identity_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    source = tmp_path / "source.bin"
    source.write_bytes(b"source")
    snapshot = module._snapshot_file(
        source, max_bytes=module.MAX_INPUT_BYTES, code="RELEASE_INPUT_PATH_INVALID"
    )
    original_close = module._close_bound_handle
    close_calls: list[tuple[int, str]] = []

    def close_once(handle: int, *, resource_type: str = "handle") -> None:
        close_calls.append((handle, resource_type))
        original_close(handle, resource_type=resource_type)

    monkeypatch.setattr(module, "_close_bound_handle", close_once)
    monkeypatch.setattr(
        module,
        "_bound_handle_identity",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("identity details must not escape")
        ),
    )
    with pytest.raises(
        module.ReleaseViolation, match="^RELEASE_INPUT_PATH_INVALID$"
    ):
        with module._open_verified_file(
            snapshot, max_bytes=module.MAX_INPUT_BYTES, code="RELEASE_INPUT_PATH_INVALID"
        ):
            pass
    assert len(close_calls) == 1
    assert close_calls[0][1] == "fd"


def test_create_output_file_normalizes_unexpected_identity_error_and_closes_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    output = tmp_path / "output.bin"
    monkeypatch.setattr(module.os, "open", lambda *_args, **_kwargs: 77)
    monkeypatch.setattr(
        module,
        "_bound_handle_identity",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("identity details must not escape")
        ),
    )
    close_calls: list[tuple[int, str]] = []

    def close_once(handle: int, *, resource_type: str = "handle") -> None:
        close_calls.append((handle, resource_type))

    monkeypatch.setattr(module, "_close_bound_handle", close_once)
    with pytest.raises(
        module.ReleaseViolation, match="^RELEASE_OUTPUT_PATH_INVALID$"
    ):
        with module._create_output_file(output):
            pass
    assert close_calls == [(77, "fd")]


def test_create_output_file_normalizes_unexpected_write_error(
    tmp_path: Path,
) -> None:
    module = _module()
    output = tmp_path / "output.bin"
    with pytest.raises(
        module.ReleaseViolation, match="^RELEASE_OUTPUT_PATH_INVALID$"
    ):
        with module._create_output_file(output) as stream:
            stream.write(b"output")
            raise RuntimeError("write details must not escape")


def test_open_verified_file_reports_stream_close_error_after_fallback_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    source = tmp_path / "source.bin"
    source.write_bytes(b"source")
    snapshot = module._snapshot_file(
        source, max_bytes=module.MAX_INPUT_BYTES, code="RELEASE_INPUT_PATH_INVALID"
    )
    close_calls: list[tuple[int, str]] = []

    class FailingStream:
        def close(self) -> None:
            raise OSError("stream close failed")

    monkeypatch.setattr(module.os, "open", lambda *_args, **_kwargs: 77)
    monkeypatch.setattr(module.os, "fdopen", lambda *_args, **_kwargs: FailingStream())
    monkeypatch.setattr(module, "_bound_handle_identity", lambda *_args, **_kwargs: (1, 2))
    monkeypatch.setattr(module, "_path_identity_matches_handle", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        module,
        "_close_bound_handle",
        lambda handle, **kwargs: close_calls.append((handle, kwargs["resource_type"])),
    )
    with pytest.raises(
        module.ReleaseViolation, match="^RELEASE_RESOURCE_CLOSE_FAILED$"
    ):
        with module._open_verified_file(
            snapshot, max_bytes=module.MAX_INPUT_BYTES, code="RELEASE_INPUT_PATH_INVALID"
        ):
            pass
    assert close_calls == [(77, "fd")]


def test_create_output_file_reports_stream_close_error_after_fallback_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    output = tmp_path / "output.bin"
    close_calls: list[tuple[int, str]] = []

    class FailingStream:
        def close(self) -> None:
            raise RuntimeError("stream close failed")

    monkeypatch.setattr(module.os, "open", lambda *_args, **_kwargs: 77)
    monkeypatch.setattr(module.os, "fdopen", lambda *_args, **_kwargs: FailingStream())
    monkeypatch.setattr(module, "_bound_handle_identity", lambda *_args, **_kwargs: (1, 2))
    monkeypatch.setattr(
        module,
        "_close_bound_handle",
        lambda handle, **kwargs: close_calls.append((handle, kwargs["resource_type"])),
    )
    with pytest.raises(
        module.ReleaseViolation, match="^RELEASE_RESOURCE_CLOSE_FAILED$"
    ):
        with module._create_output_file(output):
            pass
    assert close_calls == [(77, "fd")]


def test_close_staging_children_continues_after_base_exception_and_keeps_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    snapshot = module._FileSnapshot(tmp_path / "asset", (1, 2, 3, 4), 1)
    token = module._StagingDirectoryToken(
        parent=tmp_path,
        name=".release.staging-test",
        prefix=".release.staging-",
        parent_identity=(1,),
        identity=(2,),
        is_reparse_point=False,
        parent_handle=None,
        directory_handle=None,
        children=(
            module._StagedChildToken("first", snapshot, "a" * 64, 77),
            module._StagedChildToken("second", snapshot, "b" * 64, 88),
        ),
    )
    calls: list[int] = []

    def close(_ledger: object, handle: int, **_kwargs: object) -> bool:
        calls.append(handle)
        if handle == 77:
            raise KeyboardInterrupt()
        return True

    monkeypatch.setattr(module, "_close_ledger_handle", close)
    with pytest.raises(KeyboardInterrupt) as caught:
        module._close_staging_child_handles(token)
    assert calls == [77, 88]
    assert caught.value.cleanup_lease is token.ledger
    assert token.ledger.owns(77)


def test_close_staging_token_continues_after_base_exception_and_keeps_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    token = module._StagingDirectoryToken(
        parent=tmp_path,
        name=".release.staging-test",
        prefix=".release.staging-",
        parent_identity=(1,),
        identity=(2,),
        is_reparse_point=False,
        parent_handle=77,
        directory_handle=88,
    )
    calls: list[int] = []

    def close(_ledger: object, handle: int, **_kwargs: object) -> bool:
        calls.append(handle)
        if handle == 88:
            raise SystemExit()
        return True

    monkeypatch.setattr(module, "_close_ledger_handle", close)
    with pytest.raises(SystemExit) as caught:
        module._close_staging_token(token)
    assert calls == [88, 77]
    assert caught.value.cleanup_lease is token.ledger


def test_stage_preserves_primary_code_when_cleanup_base_exception_has_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    observed: dict[str, object] = {}

    def fail_source_verification(*_args: object, **_kwargs: object) -> None:
        raise module.ReleaseViolation("RELEASE_SOURCE_STATE_INVALID")

    def fail_cleanup(token: module._StagingDirectoryToken | None) -> str:
        assert token is not None
        observed["token"] = token
        lease = module._HandleOwnershipLedger()
        lease.register(909, resource_type="handle", identity=(9,))
        error = KeyboardInterrupt()
        error.cleanup_lease = lease  # type: ignore[attr-defined]
        raise error

    monkeypatch.setattr(module, "_verify_source_inputs", fail_source_verification)
    monkeypatch.setattr(module, "_close_staging_token", fail_cleanup)
    with pytest.raises(module.ReleaseViolation) as caught:
        module.stage_public_preview_release(
            ROOT,
            tmp_path / "release",
            installer_path=installer,
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )
    assert caught.value.code == "RELEASE_SOURCE_STATE_INVALID"
    assert caught.value.cleanup_lease is not None
    assert caught.value.cleanup_lease.owns(909)


def test_stage_preserves_cleanup_base_exception_without_primary_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    lease = module._HandleOwnershipLedger()
    lease.register(910, resource_type="handle", identity=(10,))

    def fail_cleanup(_token: object) -> str:
        error = SystemExit("cleanup failed")
        error.cleanup_lease = lease  # type: ignore[attr-defined]
        raise error

    monkeypatch.setattr(module, "_close_staging_token", fail_cleanup)
    with pytest.raises(SystemExit) as caught:
        module.stage_public_preview_release(
            ROOT,
            tmp_path / "release",
            installer_path=installer,
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )
    assert caught.value.cleanup_lease is lease
    assert lease.owns(910)


def test_snapshot_staging_directory_normalizes_error_after_directory_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    parent = tmp_path / "parent"
    parent.mkdir()
    staging = parent / ".release.staging-test"
    staging.mkdir()
    parent_binding = module._bind_directory(parent, 0)
    original_file_identity = module._file_identity
    identity_calls = 0
    original_close = module._close_bound_handle
    close_calls: list[int] = []

    def fail_after_directory_open(value: object) -> tuple[int, ...]:
        nonlocal identity_calls
        identity_calls += 1
        if identity_calls == 2:
            raise RuntimeError("directory identity details must not escape")
        return original_file_identity(value)

    def close_once(handle: int, *, resource_type: str = "handle") -> None:
        close_calls.append(handle)
        original_close(handle, resource_type=resource_type)

    monkeypatch.setattr(module, "_file_identity", fail_after_directory_open)
    monkeypatch.setattr(module, "_close_bound_handle", close_once)
    try:
        with pytest.raises(
            module.ReleaseViolation, match="^RELEASE_OUTPUT_PATH_INVALID$"
        ):
            module._snapshot_staging_directory(
                staging, ".release.staging-", parent_binding
            )
        assert len(close_calls) == 1
    finally:
        module._close_directory_binding(parent_binding)


@pytest.mark.parametrize("cleanup_fails", (False, True))
def test_bind_staging_contents_normalizes_unexpected_child_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cleanup_fails: bool,
) -> None:
    module = _module()
    _, output, _ = _stage(tmp_path, monkeypatch)
    parent = tmp_path / "parent"
    parent.mkdir()
    staging = parent / ".release.staging-test"
    shutil.copytree(output, staging)
    parent_binding = module._bind_directory(parent, 0)
    token = module._snapshot_staging_directory(
        staging, ".release.staging-", parent_binding
    )
    original_close = module._close_bound_handle
    opened: list[int] = []
    closed: list[int] = []

    def open_child(_token: object, _name: str, _code: str) -> int:
        opened.append(1001)
        return 1001

    def close_child(handle: int, **_kwargs: object) -> None:
        closed.append(handle)
        if cleanup_fails and handle == 1001:
            raise OSError("child cleanup details must not escape")

    monkeypatch.setattr(module, "_open_bound_staged_child", open_child)
    monkeypatch.setattr(
        module,
        "_snapshot_file",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("child error details must not escape")
        ),
    )
    monkeypatch.setattr(module, "_close_bound_handle", close_child)
    first_name = sorted(module.RELEASE_ASSET_NAMES)[0]
    expected_code = module._staging_file_limit(first_name)[1]
    try:
        with pytest.raises(module.ReleaseViolation) as caught:
            module._bind_staging_contents(token, staging)
        if cleanup_fails:
            assert caught.value.code == expected_code
            assert caught.value.cleanup_lease is not None
            assert caught.value.cleanup_lease.owns(1001)
        else:
            assert caught.value.code == expected_code
            assert caught.value.cleanup_lease is None
        assert opened == [1001]
        assert tuple(handle for handle in closed if handle in opened) == (1001,)
    finally:
        if token.ledger.owns(1001):
            token.ledger.release(1001)
        monkeypatch.setattr(module, "_close_bound_handle", original_close)
        module._close_staging_token(token)
        shutil.rmtree(staging, ignore_errors=True)
        shutil.rmtree(parent, ignore_errors=True)


def test_stage_rejects_source_state_changed_before_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    state = [COMMIT, ""]
    monkeypatch.setattr(module, "_git_state", lambda _root: tuple(state))
    installer, portable, skill = _inputs(tmp_path)
    output = tmp_path / "release"
    original_publish = module._publish_staged_output

    def change_state(staged: Path, target: Path, *args: object, **kwargs: object) -> None:
        state[:] = ["b" * 40, ""]
        original_publish(staged, target, *args, **kwargs)

    monkeypatch.setattr(module, "_publish_staged_output", change_state)
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_SOURCE_STATE_INVALID$"):
        module.stage_public_preview_release(
            ROOT,
            output,
            installer_path=installer,
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )
    assert not output.exists()


@pytest.mark.parametrize(
    ("name", "max_bytes", "code"),
    (
        ("integrations_preview.json", 256 * 1024, "RELEASE_MANIFEST_INVALID"),
        ("LICENSE", 2 * 1024 * 1024 * 1024, "RELEASE_INPUT_PATH_INVALID"),
        ("THIRD_PARTY_NOTICES.md", 2 * 1024 * 1024 * 1024, "RELEASE_INPUT_PATH_INVALID"),
    ),
)
def test_source_input_snapshot_rejects_content_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    max_bytes: int,
    code: str,
) -> None:
    module = _module()
    source = tmp_path / name
    source.write_bytes(b"before")
    snapshot = module._snapshot_file(source, max_bytes=max_bytes, code=code)
    token = module._capture_source_file(snapshot, max_bytes=max_bytes, code=code)
    source.write_bytes(b"after")
    monkeypatch.setattr(module, "_require_source_state", lambda *_args: None)
    monkeypatch.setattr(module, "_verified_profile", lambda _root: object())
    monkeypatch.setattr(module, "_release_contract", lambda _profile: {"same": True})
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_SOURCE_STATE_INVALID$"):
        module._verify_source_inputs(
            tmp_path,
            COMMIT,
            {"same": True},
            (token,),
        )


@pytest.mark.parametrize(
    "path_value",
    (r"\\server\share\installer.exe", r"\\?\C:\installer.exe", r"\\.\PIPE\installer"),
)
def test_rejects_windows_special_input_paths_before_filesystem_access(
    path_value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name != "nt":
        pytest.skip("Windows path boundary")
    module = _module()

    def filesystem_access_is_unexpected(*_args: object, **_kwargs: object) -> None:
        pytest.fail("special Windows path reached filesystem resolution")

    monkeypatch.setattr(module, "_snapshot_file", filesystem_access_is_unexpected)
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_INPUT_PATH_INVALID$"):
        module._resolve_input(path_value)


def test_posix_rename_without_renameat2_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name != "posix":
        pytest.skip("POSIX platform branch")
    module = _module()
    monkeypatch.setattr(module, "_load_renameat2", lambda: None, raising=False)
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_OUTPUT_PATH_INVALID$"):
        module._rename_staged_posix(tmp_path / "staging", tmp_path / "release", None)


def test_windows_rename_uses_bound_parent_and_target_basename(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name != "nt":
        pytest.skip("Windows platform branch")
    module = _module()
    calls: list[tuple[object, ...]] = []

    class FakeNtSetInformationFile:
        argtypes = None
        restype = None

        def __call__(self, *args):
            calls.append(args)
            return 0

    class FakeNtdll:
        NtSetInformationFile = FakeNtSetInformationFile()

    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: FakeNtdll())
    token = module._StagingDirectoryToken(
        parent=tmp_path,
        name=".release.staging-test",
        prefix=".release.staging-",
        parent_identity=(1,),
        identity=(2,),
        is_reparse_point=False,
        parent_handle=101,
        directory_handle=202,
    )
    module._ntdll_rename_staged(token, tmp_path / "release")

    assert len(calls) == 1
    source_handle, io_status, buffer, size, information_class = calls[0]
    assert source_handle == 202
    assert information_class == 65
    class IoStatusBlock(ctypes.Structure):
        _fields_ = [
            ("status", ctypes.c_int32),
            ("status_padding", ctypes.c_uint32),
            ("information", ctypes.c_size_t),
        ]

    assert ctypes.sizeof(IoStatusBlock) == 16
    assert ctypes.cast(io_status, ctypes.POINTER(IoStatusBlock)).contents.status == 0
    class RenameInfo(ctypes.Structure):
        _fields_ = [
            ("flags", ctypes.c_uint32),
            ("root_directory", ctypes.c_void_p),
            ("file_name_length", ctypes.c_uint32),
            ("file_name", ctypes.c_wchar * 1),
        ]

    info = ctypes.cast(buffer, ctypes.POINTER(RenameInfo)).contents
    assert info.flags == 0
    assert info.root_directory == 101
    assert info.file_name_length == len("release".encode("utf-16-le"))
    assert size == RenameInfo.file_name.offset + info.file_name_length + 2
    assert ctypes.string_at(
        ctypes.addressof(buffer) + RenameInfo.file_name.offset,
        info.file_name_length,
    ).decode("utf-16-le") == "release"


def test_windows_native_rename_rejects_existing_target_without_replacing_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name != "nt":
        pytest.skip("Windows native no-replace integration")
    module = _module()
    _result, staged_output, _inputs_used = _stage(tmp_path, monkeypatch)
    parent = tmp_path / "native-parent"
    parent.mkdir()
    staging = parent / ".release.staging-test"
    shutil.copytree(staged_output, staging)
    target = parent / "release"
    target.write_bytes(b"existing-target")
    binding = module._bind_directory(parent, 0x00000080 | 0x00000001)
    token = module._snapshot_staging_directory(
        staging, ".release.staging-", binding
    )
    try:
        with pytest.raises(
            module.ReleaseViolation, match="^RELEASE_OUTPUT_PATH_INVALID$"
        ):
            module._ntdll_rename_staged(token, target)
        assert target.read_bytes() == b"existing-target"
        assert staging.is_dir()
    finally:
        module._close_staging_token(token)
        shutil.rmtree(staging, ignore_errors=True)
        shutil.rmtree(parent, ignore_errors=True)


@pytest.mark.parametrize("mode", ("missing", "unsupported"))
def test_windows_native_rename_unavailable_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    module = _module()

    class UnsupportedNtSetInformationFile:
        argtypes = None
        restype = None

        def __call__(self, *_args: object) -> int:
            return ctypes.c_int32(0xC0000003).value

    class UnsupportedNtdll:
        NtSetInformationFile = UnsupportedNtSetInformationFile()

    fake_ntdll = object() if mode == "missing" else UnsupportedNtdll()
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: fake_ntdll)
    token = module._StagingDirectoryToken(
        parent=tmp_path,
        name=".release.staging-test",
        prefix=".release.staging-",
        parent_identity=(1,),
        identity=(2,),
        is_reparse_point=False,
        parent_handle=101,
        directory_handle=202,
    )
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_OUTPUT_PATH_INVALID$"):
        module._ntdll_rename_staged(token, tmp_path / "release")


def test_stage_rejects_input_replaced_before_verified_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    output = tmp_path / "release"
    calls: list[Path] = []

    original_open_verified_file = module._open_verified_file

    @contextmanager
    def reject_replaced(snapshot, *args, **kwargs):
        if snapshot.path == portable:
            calls.append(snapshot.path)
            raise module.ReleaseViolation("RELEASE_INPUT_PATH_INVALID")
        with original_open_verified_file(snapshot, *args, **kwargs) as stream:
            yield stream

    monkeypatch.setattr(module, "_open_verified_file", reject_replaced, raising=False)
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_INPUT_PATH_INVALID$"):
        module.stage_public_preview_release(
            ROOT,
            output,
            installer_path=installer,
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )
    assert calls == [portable]
    _assert_no_release_or_staging_directories(tmp_path, output)


def test_verified_file_snapshot_rejects_replaced_input(
    tmp_path: Path,
) -> None:
    module = _module()
    installer, _, _ = _inputs(tmp_path)
    snapshot = module._resolve_input(installer)
    installer.write_bytes(b"replaced-input")
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_INPUT_PATH_INVALID$"):
        module._digest_file(
            snapshot,
            max_bytes=module.MAX_INPUT_BYTES,
            code="RELEASE_INPUT_PATH_INVALID",
        )


def test_verify_rejects_oversized_staged_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    _, output, _ = _stage(tmp_path, monkeypatch)
    monkeypatch.setattr(module, "MAX_INPUT_BYTES", 32)
    (output / module.PORTABLE_NAME).write_bytes(b"x" * 33)
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_ASSET_TOO_LARGE$"):
        module.verify_staged_release(output, ROOT, source_commit=COMMIT)


def test_verify_rejects_oversized_metadata_before_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    _, output, _ = _stage(tmp_path, monkeypatch)
    metadata_limit = 256 * 1024
    monkeypatch.setattr(module, "MAX_METADATA_BYTES", metadata_limit)
    (output / "DOWNLOAD-METADATA.json").write_bytes(b"{" + b"x" * metadata_limit)
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_MANIFEST_TOO_LARGE$"):
        module.verify_staged_release(output, ROOT, source_commit=COMMIT)


def test_verify_rejects_oversized_checksums_before_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    _, output, _ = _stage(tmp_path, monkeypatch)
    checksum_limit = 64 * 1024
    monkeypatch.setattr(module, "MAX_CHECKSUM_BYTES", checksum_limit)
    (output / "SHA256SUMS").write_bytes(b"x" * (checksum_limit + 1))
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_CHECKSUM_TOO_LARGE$"):
        module.verify_staged_release(output, ROOT, source_commit=COMMIT)


@pytest.mark.parametrize("separator", (b"\r\n", b"\v\n", b"\x1c\n", b"\n\n"))
def test_verify_rejects_non_lf_checksum_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, separator: bytes
) -> None:
    module = _module()
    _, output, _ = _stage(tmp_path, monkeypatch)
    checksum_path = output / "SHA256SUMS"
    raw = checksum_path.read_bytes()
    checksum_path.write_bytes(raw.replace(b"\n", separator, 1))
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_CHECKSUM_INVALID$"):
        module.verify_staged_release(output, ROOT, source_commit=COMMIT)


def test_stage_rejects_reparse_ancestor_when_supported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    linked_parent = tmp_path / "linked-parent"
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    try:
        linked_parent.symlink_to(real_parent, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_OUTPUT_PATH_INVALID$"):
        module.stage_public_preview_release(
            ROOT,
            linked_parent / "release",
            installer_path=installer,
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )
