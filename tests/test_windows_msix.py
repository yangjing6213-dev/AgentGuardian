import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from scripts.build_windows_msix import (
    build_msix_stage,
    makeappx_pack_command,
    msix_manifest_bytes,
    signtool_verify_command,
    signtool_sign_by_thumbprint_command,
)


PROJECT_ROOT = Path(__file__).parents[1]
UNSIGNED_WORKFLOW_SHA256 = "38681bd29edf6d8adf0c5df79427fc5e46ca889b7f98102ef5b5733a78a9711c"


def _git_text_sha256(path: Path) -> str:
    content = path.read_bytes().replace(b"\r\n", b"\n")
    return hashlib.sha256(content).hexdigest()


def test_git_text_sha256_ignores_checkout_line_endings(tmp_path: Path) -> None:
    lf_path = tmp_path / "lf.yml"
    crlf_path = tmp_path / "crlf.yml"
    lf_path.write_bytes(b"name: CI\nsteps:\n  - run: test\n")
    crlf_path.write_bytes(b"name: CI\r\nsteps:\r\n  - run: test\r\n")

    assert _git_text_sha256(lf_path) == _git_text_sha256(crlf_path)


def test_manifest_declares_full_trust_executable_and_required_logos() -> None:
    manifest = msix_manifest_bytes(
        identity_name="yangjing6213dev.AgentGuardian",
        publisher="CN=AgentGuardian Test",
        version="0.1.0.0",
    ).decode("utf-8")

    assert 'Name="yangjing6213dev.AgentGuardian"' in manifest
    assert 'Publisher="CN=AgentGuardian Test"' in manifest
    assert 'ProcessorArchitecture="x64"' in manifest
    assert 'Executable="AgentGuardian.exe"' in manifest
    assert 'EntryPoint="Windows.FullTrustApplication"' in manifest
    assert '<Logo>Assets/StoreLogo.png</Logo>' in manifest
    assert '<Dependencies>' in manifest
    assert 'Name="Windows.Desktop"' in manifest
    assert 'xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"' in manifest
    assert '<rescap:Capability Name="runFullTrust" />' in manifest
    for logo in ("Square44x44Logo.png", "Square150x150Logo.png"):
        assert f'Logo="Assets/{logo}"' in manifest


@pytest.mark.parametrize(
    ("identity_name", "publisher", "version"),
    (
        ("bad name", "CN=AgentGuardian Test", "0.1.0.0"),
        ("yangjing6213dev.AgentGuardian", "", "0.1.0.0"),
        ("yangjing6213dev.AgentGuardian", "CN=AgentGuardian Test", "0.1"),
    ),
)
def test_manifest_rejects_invalid_identity_values(
    identity_name: str, publisher: str, version: str
) -> None:
    with pytest.raises(ValueError):
        msix_manifest_bytes(
            identity_name=identity_name,
            publisher=publisher,
            version=version,
        )


def test_stage_copies_verified_bundle_and_manifest_assets(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "AgentGuardian.exe").write_bytes(b"synthetic executable")
    internal = bundle / "_internal" / "agentguardian"
    internal.mkdir(parents=True)
    (internal / "source_policy.json").write_text("{}", encoding="utf-8")
    stage = tmp_path / "stage"

    result = build_msix_stage(
        bundle,
        stage,
        project_root=PROJECT_ROOT,
        identity_name="yangjing6213dev.AgentGuardian",
        publisher="CN=AgentGuardian Test",
        version="0.1.0.0",
    )

    assert result == stage
    assert (stage / "AgentGuardian.exe").read_bytes() == b"synthetic executable"
    assert (stage / "AppxManifest.xml").is_file()
    for logo in ("Square44x44Logo.png", "Square150x150Logo.png", "StoreLogo.png"):
        assert (stage / "Assets" / logo).read_bytes() == (
            PROJECT_ROOT / "assets" / "brand" / "agentguardian-mark-512.png"
        ).read_bytes()


def test_stage_rejects_existing_output_and_symlinked_bundle(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "AgentGuardian.exe").write_bytes(b"synthetic executable")
    stage = tmp_path / "stage"
    stage.mkdir()

    with pytest.raises(ValueError, match="output stage already exists"):
        build_msix_stage(
            bundle,
            stage,
            project_root=PROJECT_ROOT,
            identity_name="yangjing6213dev.AgentGuardian",
            publisher="CN=AgentGuardian Test",
            version="0.1.0.0",
        )

    stage.rmdir()
    try:
        (bundle / "link").symlink_to(bundle / "AgentGuardian.exe")
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(ValueError, match="reparse or symlink"):
        build_msix_stage(
            bundle,
            stage,
            project_root=PROJECT_ROOT,
            identity_name="yangjing6213dev.AgentGuardian",
            publisher="CN=AgentGuardian Test",
            version="0.1.0.0",
        )


def test_native_tool_commands_are_non_elevated_and_do_not_embed_passwords(
    tmp_path: Path,
) -> None:
    stage = tmp_path / "stage"
    package = tmp_path / "AgentGuardian.msix"
    certificate_thumbprint = "A" * 40

    pack = makeappx_pack_command("makeappx.exe", stage, package)
    sign = signtool_sign_by_thumbprint_command(
        "signtool.exe", package, certificate_thumbprint
    )
    verify = signtool_verify_command("signtool.exe", package)

    assert pack == (
        "makeappx.exe",
        "pack",
        "/d",
        str(stage),
        "/p",
        str(package),
    )
    assert sign == (
        "signtool.exe",
        "sign",
        "/fd",
        "SHA256",
        "/sha1",
        certificate_thumbprint,
        "/tr",
        "http://timestamp.digicert.com",
        "/td",
        "SHA256",
        str(package),
    )
    assert verify == ("signtool.exe", "verify", "/pa", "/all", str(package))
    assert "password" not in " ".join(sign).casefold()


def test_msix_verifier_installs_launches_and_uninstalls_without_elevation() -> None:
    verifier = (
        PROJECT_ROOT / "scripts" / "verify_windows_msix.ps1"
    ).read_text(encoding="utf-8")

    for required in (
        "Add-AppxPackage",
        "Get-AppxPackage",
        "Start-Process",
        "Remove-AppxPackage",
        "UpgradePackagePath",
        "preexisting package",
        "version_before",
        "version_after",
        "upgrade_attempted",
        "upgraded",
        "process_startup",
        "bounded_liveness",
        "uninstalled",
        "package_residue",
        "AllowUnsigned",
        "unsigned_ci_smoke",
    ):
        assert required in verifier
    assert "-Verb RunAs" not in verifier
    assert "Remove-Item" not in verifier


def test_retired_adapter_workflow_modules_and_scripts_are_absent() -> None:
    retired_paths = (
        ".github/workflows/windows-mvp-signed.yml",
        "src/agentguardian/" + "mcp_" + "sandbox.py",
        "src/agentguardian/windows_" + "appcontainer.py",
        "src/agentguardian/windows_" + "code_signing.py",
        "src/agentguardian/windows_" + "job_object.py",
        "scripts/download_" + "trusted_" + "mcp_" + "adapter.py",
        "scripts/run_windows_" + "mcp_" + "adapter_acceptance.py",
    )

    assert all(not (PROJECT_ROOT / relative).exists() for relative in retired_paths)


def test_build_release_msix_and_workflows_have_no_retired_adapter_contract() -> None:
    active_paths = (
        PROJECT_ROOT / "scripts" / "build_windows_portable.py",
        PROJECT_ROOT / "scripts" / "verify_windows_release_candidate.py",
        PROJECT_ROOT / "scripts" / "verify_windows_msix.ps1",
        *(PROJECT_ROOT / ".github" / "workflows").glob("*.yml"),
    )
    retired_contract = (
        "download_" + "trusted_" + "mcp_" + "adapter.py",
        "run_windows_" + "mcp_" + "adapter_acceptance.py",
        "AgentGuardianMcp" + "Adapter.exe",
        "MCP-" + "ADAPTER.json",
        "--mcp-" + "adapter-",
        "mcp_" + "adapter_",
        "Mcp" + "Adapter",
        "AGENTGUARDIAN_MCP_" + "ADAPTER",
        "P" + "FX",
    )

    for path in active_paths:
        content = path.read_text(encoding="utf-8").casefold()
        assert all(value.casefold() not in content for value in retired_contract), path


def test_task2_quality_review_cleanup_requeries_after_stale_removal_error() -> None:
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("pwsh is unavailable")
    verifier_path = str(PROJECT_ROOT / "scripts" / "verify_windows_msix.ps1").replace(
        "'", "''"
    )
    harness = rf"""
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    '{verifier_path}',
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count -ne 0) {{ throw "verifier parse failed" }}
$cleanupFunction = $ast.Find({{
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Remove-AgentGuardianPackagesBounded'
}}, $true)
if ($null -eq $cleanupFunction) {{ throw "cleanup function missing" }}
Invoke-Expression $cleanupFunction.Extent.Text

$script:mode = 'transient'
$script:queryCount = 0
$script:removed = @()
$script:staleAttempts = 0
$script:clock = 0
function Get-Date {{
    $script:clock++
    $base = [datetime]'2026-08-16T00:00:00Z'
    if ($script:mode -eq 'permanent') {{
        return $base.AddSeconds(2 * $script:clock)
    }}
    return $base.AddMilliseconds(100 * $script:clock)
}}
function Get-AgentGuardianPackages {{
    $script:queryCount++
    if ($script:queryCount -eq 1) {{
        throw 'transient package query failed'
    }}
    if ($script:queryCount -eq 2) {{
        return @(
            [pscustomobject]@{{ PackageFullName = 'stale-old' }},
            [pscustomobject]@{{ PackageFullName = 'current-upgraded' }}
        )
    }}
    if ($script:queryCount -eq 3) {{
        return @([pscustomobject]@{{ PackageFullName = 'stale-old' }})
    }}
    if ($script:mode -eq 'permanent') {{
        throw 'permanent package query failed'
    }}
    return @()
}}
function Remove-AppxPackage {{
    param([string]$Package, [string]$ErrorAction)
    $script:removed += $Package
    if ($Package -eq 'stale-old') {{
        $script:staleAttempts++
        if ($script:staleAttempts -eq 1) {{ throw 'stale removal failed' }}
    }}
}}
function Start-Sleep {{ param([int]$Milliseconds) }}

$transientCleanup = Remove-AgentGuardianPackagesBounded -TimeoutSeconds 1 -RetryMilliseconds 0
$transientQueryCount = $script:queryCount
$transientRemoved = @($script:removed)

$script:mode = 'permanent'
$script:queryCount = 0
$script:clock = 0
$exhaustedCleanup = Remove-AgentGuardianPackagesBounded -TimeoutSeconds 1 -RetryMilliseconds 0
[ordered]@{{
    transient = [ordered]@{{
        query_count = $transientQueryCount
        removed = $transientRemoved
        uninstalled = [bool]$transientCleanup.Uninstalled
        package_residue = [bool]$transientCleanup.PackageResidue
    }}
    exhausted = [ordered]@{{
        query_count = $script:queryCount
        uninstalled = [bool]$exhaustedCleanup.Uninstalled
        package_residue = [bool]$exhaustedCleanup.PackageResidue
    }}
}} | ConvertTo-Json -Compress
"""

    result = subprocess.run(
        [pwsh, "-NoProfile", "-NonInteractive", "-Command", harness],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    evidence = json.loads(result.stdout.strip().splitlines()[-1])
    assert evidence["transient"] == {
        "query_count": 4,
        "removed": ["stale-old", "current-upgraded", "stale-old"],
        "uninstalled": True,
        "package_residue": False,
    }
    assert evidence["exhausted"] == {
        "query_count": 1,
        "uninstalled": False,
        "package_residue": True,
    }


def test_task2_calibrated_cleanup_finally_is_fail_closed_and_checks_app_data() -> None:
    verifier = (
        PROJECT_ROOT / "scripts" / "verify_windows_msix.ps1"
    ).read_text(encoding="utf-8")

    smoke_catch = verifier.index("\ncatch {\n    $smokeError")
    smoke_finally = verifier.index("\nfinally {", smoke_catch)
    final_checks = verifier.index("\nif (-not $termination)", smoke_finally)
    cleanup_finally = verifier[smoke_finally:final_checks]
    cleanup_call = cleanup_finally.index("Remove-AgentGuardianPackagesBounded")
    cleanup_catch = cleanup_finally.index("catch {", cleanup_call)
    app_data_check = cleanup_finally.index(
        "$appDataResidue = Test-Path -LiteralPath $appDataRoot"
    )

    assert cleanup_call < cleanup_catch < app_data_check
    assert "$uninstalled = $false" in cleanup_finally[cleanup_catch:app_data_check]
    assert "$packageResidue = $true" in cleanup_finally[cleanup_catch:app_data_check]
    assert "$remainingPackages = @(Get-AgentGuardianPackages)" not in cleanup_finally
    assert 'throw "MSIX package remains installed after uninstall"' in verifier[final_checks:]

    helper_start = verifier.index("function Remove-AgentGuardianPackagesBounded")
    helper_end = verifier.index("\n$resolvedPackage =", helper_start)
    helper = verifier[helper_start:helper_end]
    for fake_timeout_primitive in ("Start-Job", "Wait-Job", "Stop-Job"):
        assert fake_timeout_primitive not in helper


def test_msix_workflow_builds_and_verifies_a_same_identity_upgrade() -> None:
    workflow = (
        PROJECT_ROOT / ".github" / "workflows" / "windows-mvp.yml"
    ).read_text(encoding="utf-8")

    for required in (
        "ci-msix-upgrade-stage",
        "AgentGuardian-ci-upgrade.msix",
        'version "0.1.0.1"',
        "-UpgradePackagePath",
        "same-identity upgrade and uninstall",
    ):
        assert required in workflow


def test_windows_mvp_workflow_binds_tools_and_install_smoke() -> None:
    workflow = (
        PROJECT_ROOT / ".github" / "workflows" / "windows-mvp.yml"
    ).read_text(encoding="utf-8")

    for required in (
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
        "requirements-dev.lock",
        "requirements-build.lock",
        "MakeAppx.exe",
        "verify_windows_msix.ps1",
        "run_personal_privacy_acceptance.py",
        "personal-privacy-acceptance.json",
        "Install launch and uninstall unsigned MSIX CI smoke",
    ):
        assert required in workflow
    assert "-Verb RunAs" not in workflow
    assert "production" not in workflow.casefold()
    assert "New-SelfSignedCertificate" not in workflow
    assert "Export-PfxCertificate" not in workflow
    assert "-AllowUnsigned" in workflow
    assert "OID.2.25.311729368913984317654407730594956997722=1" in workflow
    assert "git show -s --format=%ct HEAD" in workflow


def test_msix_signature_gate_is_fail_closed_and_checks_trusted_publisher() -> None:
    verifier = (
        PROJECT_ROOT / "scripts" / "verify_windows_msix.ps1"
    ).read_text(encoding="utf-8")
    for required in (
        "Get-AuthenticodeSignature",
        "RequireTrustedSignature",
        "ExpectedPublisher",
        "SignerCertificate",
        "TimeStamperCertificate",
    ):
        assert required in verifier

def test_msix_verifier_has_a_strict_fresh_user_state_mode() -> None:
    verifier = (
        PROJECT_ROOT / "scripts" / "verify_windows_msix.ps1"
    ).read_text(encoding="utf-8")
    for required in (
        "RequireFreshUserState",
        "fresh_user_state",
        "app_data_residue",
        "LOCALAPPDATA",
        "empty user state",
    ):
        assert required in verifier
    assert "RequireFreshUserState cannot be combined with AllowUnsigned" in verifier
    assert "RequireFreshUserState requires RequireTrustedSignature" in verifier


def test_task2_source_commit_contract_is_conditional_for_unsigned_compatibility() -> None:
    verifier = (
        PROJECT_ROOT / "scripts" / "verify_windows_msix.ps1"
    ).read_text(encoding="utf-8")
    unsigned_workflow_path = PROJECT_ROOT / ".github" / "workflows" / "windows-mvp.yml"
    unsigned_workflow = unsigned_workflow_path.read_text(encoding="utf-8")
    parameter_prefix = verifier.split("[string]$ExpectedSourceCommit,", 1)[0]
    source_parameter_attributes = parameter_prefix.rsplit(",", 1)[1]

    assert "[Parameter(Mandatory = $true)]" not in source_parameter_attributes
    for required in (
        "$sourceCommitRequired = $RequireTrustedSignature",
        '$sourceCommitProvided = $PSBoundParameters.ContainsKey("ExpectedSourceCommit")',
        "$sourceCommitValid = $sourceCommitProvided -and",
        "($sourceCommitRequired -or $sourceCommitProvided) -and -not $sourceCommitValid",
        '$evidence["source_commit"] = $ExpectedSourceCommit',
    ):
        assert required in verifier
    assert verifier.index("$evidence = [ordered]@{") < verifier.index(
        '$evidence["source_commit"] = $ExpectedSourceCommit'
    )
    assert "source_commit = $ExpectedSourceCommit" not in verifier
    assert "-ExpectedSourceCommit" not in unsigned_workflow
    assert (
        _git_text_sha256(unsigned_workflow_path) == UNSIGNED_WORKFLOW_SHA256
    )


def test_unsigned_workflow_git_text_is_unchanged() -> None:
    workflow = PROJECT_ROOT / ".github" / "workflows" / "windows-mvp.yml"

    assert _git_text_sha256(workflow) == UNSIGNED_WORKFLOW_SHA256
