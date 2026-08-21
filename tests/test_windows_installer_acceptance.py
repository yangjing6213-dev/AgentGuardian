from __future__ import annotations

import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "verify_windows_installer.ps1"


def _script() -> str:
    if not SCRIPT_PATH.is_file():
        raise AssertionError("Windows installer acceptance script is missing")
    return SCRIPT_PATH.read_text(encoding="utf-8")


def test_acceptance_script_covers_fixed_lifecycle_and_both_state_choices() -> None:
    script = _script()

    for required in (
        "BaseInstaller",
        "CandidateInstaller",
        "EvidenceOutput",
        "BaseVersion",
        "CandidateVersion",
        "{7A76221A-CFA0-4860-B250-7083B736F3FB}",
        "_is1",
        "AgentGuardian-Setup-0.2.0-beta.1-x64.exe",
        "AgentGuardian.exe",
        "AgentGuardian-private-beta-acceptance-report-v1",
        "retained_state",
        "deleted_state",
        "user_report_preserved",
        "downgrade_rejected",
        "Start-Process",
        "Get-ChildItem",
        "/PURGEAGENTGUARDIANSTATE",
    ):
        assert required in script

    assert script.count("Assert-ExactBytes $StatePath $StateMarker") == 4
    assert script.count("Assert-ExactText $ReportPath $ReportMarker") == 2
    assert script.index("Assert-InstalledFileVersion $CandidateFileVersion") < script.index(
        "$downgrade = Start-Process"
    )
    downgrade_body = script.split(
        "Assert-InstalledFileVersion $CandidateFileVersion", 1
    )[1].split(
        "Invoke-Setup $Uninstaller", 1
    )[0]
    assert "Assert-DisplayVersion $CandidateVersion" in downgrade_body
    assert "Assert-PathPresent $ProgramDirectory" in downgrade_body
    assert "Assert-ExactBytes $StatePath $StateMarker" in downgrade_body
    assert "$downgrade.ExitCode -ne 7" in downgrade_body


def test_acceptance_script_uses_exact_process_and_startup_residue_checks() -> None:
    script = _script()

    assert "Stop-Process -Id $process.Id -Force" in script
    assert "Wait-Process -Id $process.Id -Timeout 10" in script
    assert "Get-Process -Id $process.Id" in script
    assert "Stop-Process -Name" not in script
    assert "Assert-NoAgentGuardianProcess" in script
    assert (
        "Join-Path $env:APPDATA "
        "'Microsoft\\Windows\\Start Menu\\Programs\\Startup\\AgentGuardian.lnk'" in script
    )
    assert "STARTUP_SHORTCUT_RESIDUE" in script


def test_acceptance_script_bounds_setup_and_requires_a_responsive_window() -> None:
    script = _script()

    assert "function Wait-ProcessExit" in script
    assert ".WaitForExit(" in script
    assert "$SetupTimeoutMilliseconds" in script
    assert '"${Code}_TIMEOUT"' in script
    assert "DOWNGRADE_TIMEOUT" in script
    assert "MainWindowHandle" in script
    assert ".Responding" in script
    assert "LAUNCH_WINDOW_TIMEOUT" in script
    assert "Start-Process -FilePath $Installer -ArgumentList $Arguments -Wait" not in script


def test_acceptance_script_checks_system_integration_throughout_lifecycle() -> None:
    script = _script()

    assert script.count("Assert-NoSystemIntegration") == 5
    assert script.count("Assert-NoAgentGuardianProcess") == 3

    base_body = script.split("Invoke-Setup $base", 1)[1].split(
        "Invoke-LaunchSmoke", 1
    )[0]
    assert "Assert-NoSystemIntegration" in base_body
    assert "Assert-InstalledFileVersion $BaseFileVersion" in base_body

    upgrade_body = script.split("Invoke-Setup $candidate", 1)[1].split(
        "$downgrade = Start-Process", 1
    )[0]
    assert "Assert-NoSystemIntegration" in upgrade_body

    retained_body = script.split("RETAINED_UNINSTALL_FAILED", 1)[1].split(
        "Invoke-Setup $candidate", 1
    )[0]
    assert "Assert-NoAgentGuardianProcess" in retained_body

    reinstall_body = script.rsplit("Invoke-Setup $candidate", 1)[1].split(
        "Invoke-Setup $Uninstaller", 1
    )[0]
    assert "Assert-NoSystemIntegration" in reinstall_body


def test_acceptance_script_has_no_caller_controlled_cleanup_or_network() -> None:
    script = _script()
    folded = script.casefold()

    for forbidden in (
        "invoke-webrequest",
        "start-bitstransfer",
        "http://",
        "https://",
        "remove-item -recurse",
        "remove-item -literalpath $evidenceoutput",
        "remove-item -literalpath $baseinstaller",
        "remove-item -literalpath $candidateinstaller",
        "hklm:",
    ):
        assert forbidden not in folded

    assert "$env:LOCALAPPDATA" in script
    assert "$env:APPDATA" in script
    assert "Join-Path $env:LOCALAPPDATA 'Programs\\AgentGuardian'" in script
    assert "Join-Path $env:LOCALAPPDATA 'AgentGuardian\\evidence-state-v1.bin'" in script


def test_acceptance_script_rejects_unsafe_path_forms_and_reparse_ancestors() -> None:
    script = _script()

    assert "function Assert-NoReparseAncestor" in script
    assert "-notmatch '^[A-Za-z]:[\\\\/]'" in script
    assert "Assert-NoReparseAncestor $Value $Code" in script
    assert "Assert-NoReparseAncestor (Split-Path -Parent $fullPath)" in script
    assert "UNC" in script
    assert "DEVICE" in script


def test_acceptance_script_locks_fixed_paths_and_evidence_output_before_actions() -> None:
    script = _script()

    assert "function Assert-FixedPathsSafe" in script
    assert "function Assert-FixedWriteParentsSafe" in script
    assert "function Assert-EvidenceOutputDoesNotOverlap" in script
    assert "function Test-CanonicalPathOverlap" in script
    assert "ToUpperInvariant" in script
    assert "EVIDENCE_OUTPUT_OVERLAP" in script
    assert script.count("Assert-FixedWriteParentsSafe") == 2

    pre_install = script.split("try {", 1)[1].split("Invoke-Setup $base", 1)[0]
    assert "Assert-FixedPathsSafe" in pre_install
    assert "Assert-EvidenceOutputDoesNotOverlap $evidenceCandidate" in pre_install
    assert "Get-InstallerFileVersion $base" in pre_install
    assert "Get-InstallerFileVersion $candidate" in pre_install
    assert "[Version]'0.2.0.1'" in pre_install


def test_acceptance_installer_file_version_uses_numeric_parts() -> None:
    script = _script()
    fail_source = script.split("function Fail", 1)[1].split(
        "function Assert-LocalPathSyntax", 1
    )[0]
    helper = script.split("function Get-InstallerFileVersion", 1)[1].split(
        "function Assert-InstalledFileVersion", 1
    )[0]
    assert ".FileVersion" not in helper

    command = (
        "function Fail"
        + fail_source
        + "function Get-Item { [pscustomobject]@{VersionInfo=[pscustomobject]@{"
        + "FileVersion='0.1.9.0             '; FileMajorPart=0; FileMinorPart=1; "
        + "FileBuildPart=9; FilePrivatePart=0}} }\n"
        + "function Get-InstallerFileVersion"
        + helper
        + "\ntry { [Console]::Write((Get-InstallerFileVersion 'C:\\synthetic.exe' 'VERSION_INVALID').ToString()) } "
        + "catch { [Console]::Write($_.Exception.Message) }"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "0.1.9.0"


def test_acceptance_script_assigns_writable_evidence_only_after_overlap_check() -> None:
    script = _script()
    pre_install = script.split("try {", 1)[1].split("Invoke-Setup $base", 1)[0]

    assert "$evidenceCandidate = Get-NewAbsoluteOutputFile $EvidenceOutput" in pre_install
    assert "Assert-EvidenceOutputDoesNotOverlap $evidenceCandidate" in pre_install
    assert "$evidencePath = $evidenceCandidate" in pre_install
    assert pre_install.index("Assert-EvidenceOutputDoesNotOverlap $evidenceCandidate") < pre_install.index(
        "$evidencePath = $evidenceCandidate"
    )
    assert "Write-Evidence $evidencePath" not in pre_install


def test_acceptance_script_writes_evidence_once_without_following_new_reparse_paths() -> None:
    script = _script()
    writer = script.split("function Write-Evidence", 1)[1].rsplit("\ntry {", 1)[0]

    assert "Assert-NoReparseAncestor (Split-Path -Parent $Path)" in writer
    assert "[System.IO.FileMode]::CreateNew" in writer
    assert "[System.IO.FileShare]::None" in writer
    assert "$stream.Write($bytes, 0, $bytes.Length)" in writer
    assert "$stream.Flush($true)" in writer
    assert "WriteAllText" not in writer


def test_local_path_syntax_rejects_dot_segment_normalization() -> None:
    script = _script()
    fail_source = script.split("function Fail", 1)[1].split(
        "function Assert-LocalPathSyntax", 1
    )[0]
    syntax_source = script.split("function Assert-LocalPathSyntax", 1)[1].split(
        "function Assert-NoReparseAncestor", 1
    )[0]
    command = (
        "function Fail"
        + fail_source
        + "function Assert-LocalPathSyntax"
        + syntax_source
        + "\ntry { Assert-LocalPathSyntax 'C:\\Temp\\..\\Evidence.json' 'PATH_INVALID'; [Console]::Write('accepted') } "
        + "catch { [Console]::Write($_.Exception.Message) }"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "PATH_INVALID"


def test_reparse_ancestor_check_stops_after_windows_drive_root() -> None:
    script = _script()
    fail_source = script.split("function Fail", 1)[1].split(
        "function Assert-LocalPathSyntax", 1
    )[0]
    helper = script.split("function Assert-NoReparseAncestor", 1)[1].split(
        "function Get-ExistingAbsoluteFile", 1
    )[0]
    command = (
        "function Fail"
        + fail_source
        + "function Assert-NoReparseAncestor"
        + helper
        + "\ntry { Assert-NoReparseAncestor 'C:\\' 'REPARSE_INVALID'; "
        + "[Console]::Write('accepted') } catch { [Console]::Write($_.Exception.Message) }"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "accepted"


def test_acceptance_script_polls_for_post_uninstall_absence() -> None:
    script = _script()

    assert "function Assert-PathAbsentWithPolling" in script
    assert script.count("Assert-PathAbsentWithPolling") == 9
    retained_body = script.split("RETAINED_UNINSTALL_FAILED", 1)[1].split(
        "Invoke-Setup $candidate", 1
    )[0]
    deleted_body = script.split("DELETED_UNINSTALL_FAILED", 1)[1].split(
        "Assert-NoAgentGuardianProcess", 1
    )[0]
    for body in (retained_body, deleted_body):
        assert "Assert-PathAbsentWithPolling $ProgramDirectory" in body
        assert "Assert-PathAbsentWithPolling $UninstallKey" in body
        assert "Assert-PathAbsentWithPolling $StartMenuShortcut" in body
        assert "Assert-PathAbsentWithPolling $StartupShortcut" in body


def test_acceptance_path_overlap_helper_is_case_insensitive_and_bounded() -> None:
    script = _script()

    def function_source(name: str, next_name: str) -> str:
        return script.split(f"function {name}", 1)[1].split(
            f"function {next_name}", 1
        )[0]

    command = (
        "function Fail"
        + function_source("Fail", "Assert-LocalPathSyntax")
        + "function Assert-LocalPathSyntax"
        + function_source("Assert-LocalPathSyntax", "Assert-NoReparseAncestor")
        + "function Get-CanonicalPathKey"
        + function_source("Get-CanonicalPathKey", "Test-CanonicalPathOverlap")
        + "function Test-CanonicalPathOverlap"
        + function_source("Test-CanonicalPathOverlap", "Assert-EvidenceOutputDoesNotOverlap")
        + "\n$equal = Test-CanonicalPathOverlap 'C:\\Users\\Test\\AppData\\Local\\Programs\\AgentGuardian' 'c:\\users\\test\\appdata\\local\\programs\\agentguardian'; "
        + "$nested = Test-CanonicalPathOverlap 'C:\\Users\\Test\\AppData\\Local\\Programs\\AgentGuardian\\evidence.json' 'C:\\Users\\Test\\AppData\\Local\\Programs\\AgentGuardian'; "
        + "$separate = Test-CanonicalPathOverlap 'C:\\Users\\Test\\evidence.json' 'C:\\Users\\Test\\AppData\\Local\\Programs\\AgentGuardian'; "
        + '[Console]::Write("$equal,$nested,$separate")'
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "True,True,False"


def test_acceptance_evidence_is_lexicographic_utf8_without_bom_and_lf() -> None:
    script = _script()

    assert "function ConvertTo-CanonicalEvidenceJson" in script
    assert "($Evidence.Keys | Sort-Object)" in script
    assert "ConvertTo-Json -InputObject ([string]$key) -Compress" in script
    assert "[System.Text.UTF8Encoding]::new($false)" in script
    assert "+ \"`n\"" in script
    assert "schema = 1; status = 'fail'; error = $ErrorCode" in script


def test_acceptance_evidence_serializer_orders_keys_lexicographically() -> None:
    script = _script()
    serializer = script.split("function ConvertTo-CanonicalEvidenceJson", 1)[1].split(
        "function Write-Evidence", 1
    )[0]
    command = (
        "function ConvertTo-CanonicalEvidenceJson"
        + serializer
        + "\n$evidence = @{z = 'last'; schema = 1; a = 'first'}; "
        + "[Console]::Write((ConvertTo-CanonicalEvidenceJson $evidence))"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == '{"a":"first","schema":1,"z":"last"}'


def test_acceptance_script_parses_in_windows_powershell() -> None:
    path = str(SCRIPT_PATH).replace("'", "''")
    command = (
        "[void][scriptblock]::Create("
        "[System.IO.File]::ReadAllText('"
        + path
        + "', [System.Text.Encoding]::UTF8)"
        ")"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert result.returncode == 0, result.stderr
