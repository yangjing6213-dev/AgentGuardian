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
UNSIGNED_WORKFLOW_SHA256 = "4c48dec977fa7bc6eafbc6f1e06b295943dac097764a5bbbcc4e93cf6d0fc31d"


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
    helper_end = verifier.index("\nfunction Get-InstalledMcpAdapterPath", helper_start)
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
        "run_sensitive_data_acceptance.py",
        "sensitive-data-acceptance.json",
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


def test_signed_msix_gate_is_fail_closed_and_checks_trusted_publisher() -> None:
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

    workflow_path = PROJECT_ROOT / ".github" / "workflows" / "windows-mvp-signed.yml"
    workflow = workflow_path.read_text(encoding="utf-8")
    for required in (
        "AGENTGUARDIAN_SIGNING_PFX_B64",
        "AGENTGUARDIAN_SIGNING_PFX_PASSWORD",
        "AGENTGUARDIAN_SIGNING_PUBLISHER",
        "Import-PfxCertificate",
        "signtool sign",
        "RequireTrustedSignature",
        "ExpectedPublisher",
        "signed-upgrade-msix-stage",
        "AgentGuardian-signed-upgrade.msix",
        "-UpgradePackagePath",
        'version "0.1.0.1"',
        "--artifact-status trusted_release",
        "-RequireFreshUserState",
        "scripts/verify_windows_release_candidate.py",
        "--require-trusted-signature",
        "--require-fresh-user-state",
        "--license-review",
    ):
        assert required in workflow
    assert "New-SelfSignedCertificate" not in workflow
    assert "-AllowUnsigned" not in workflow


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


def test_task2_mcp_msix_verifier_requires_source_commit_and_strict_acceptance_mode() -> None:
    verifier = (
        PROJECT_ROOT / "scripts" / "verify_windows_msix.ps1"
    ).read_text(encoding="utf-8")

    for required in (
        "$ExpectedSourceCommit",
        '$evidence["source_commit"] = $ExpectedSourceCommit',
        "^[0-9a-f]{40}$",
        "$RequireMcpAdapterAcceptance",
        "$McpAdapterRelativePath",
        '"adapters/AgentGuardianMcpAdapter.exe"',
        "$ExpectedMcpAdapterSha256",
        "$ExpectedMcpAdapterPublisher",
        "$ExpectedMcpAdapterCertificateSha256",
        "$McpAdapterEvidencePath",
        "RequireMcpAdapterAcceptance requires RequireTrustedSignature",
        "RequireMcpAdapterAcceptance cannot be combined with AllowUnsigned",
        "McpAdapterEvidencePath must be absolute",
        "McpAdapterEvidencePath must be new",
        "^[0-9a-f]{64}$",
    ):
        assert required in verifier


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
        "$sourceCommitRequired = $RequireTrustedSignature -or $RequireMcpAdapterAcceptance",
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


def test_task2_mcp_acceptance_requires_upgrade_package_during_validation() -> None:
    verifier = (
        PROJECT_ROOT / "scripts" / "verify_windows_msix.ps1"
    ).read_text(encoding="utf-8")
    validation_start = verifier.index("if ($RequireMcpAdapterAcceptance) {")
    validation_end = verifier.index("$appDataRoot = $null")
    validation = verifier[validation_start:validation_end]

    assert "[string]::IsNullOrWhiteSpace($UpgradePackagePath)" in validation
    assert "RequireMcpAdapterAcceptance requires UpgradePackagePath" in validation


def test_task2_mcp_acceptance_requires_completed_upgrade_before_resolution() -> None:
    verifier = (
        PROJECT_ROOT / "scripts" / "verify_windows_msix.ps1"
    ).read_text(encoding="utf-8")
    runtime_start = verifier.index(
        "    if ($RequireMcpAdapterAcceptance) {",
        verifier.index("try {")
    )
    runtime_end = verifier.index("$appUserModelId", runtime_start)
    runtime_acceptance = verifier[runtime_start:runtime_end]

    guard = "if (-not $upgradeAttempted -or -not $upgraded)"
    assert guard in runtime_acceptance
    assert "MCP adapter acceptance requires a completed package upgrade" in runtime_acceptance
    assert runtime_acceptance.index(guard) < runtime_acceptance.index(
        "Get-InstalledMcpAdapterPath"
    )


def test_task2_mcp_msix_verifier_runs_fixed_installed_adapter_before_cleanup() -> None:
    verifier = (
        PROJECT_ROOT / "scripts" / "verify_windows_msix.ps1"
    ).read_text(encoding="utf-8")

    for required in (
        "$Package.InstallLocation",
        "Get-InstalledMcpAdapterPath -Package $installedPackages[0]",
        "$installRootItem = Get-Item -LiteralPath $installLocation -Force",
        "installed package InstallLocation is a reparse point",
        "expected exactly one installed package for MCP adapter acceptance",
        "Join-Path $installLocation $McpAdapterRelativePath",
        "[IO.Path]::GetFullPath",
        "[StringComparison]::OrdinalIgnoreCase",
        "[IO.FileInfo]",
        "[IO.FileAttributes]::ReparsePoint",
        "run_windows_mcp_adapter_acceptance.py",
        "--adapter-path",
        "--evidence-path",
        "--expected-source-commit",
        "--expected-adapter-sha256",
        "--expected-publisher-subject",
        "--expected-certificate-sha256",
        "MCP adapter acceptance failed",
        "| Out-Null",
    ):
        assert required in verifier

    acceptance = verifier.index("run_windows_mcp_adapter_acceptance.py")
    smoke_catch = verifier.index("\ncatch {", acceptance)
    smoke_finally = verifier.index("finally {", smoke_catch)
    assert verifier.index("$installedPackages = $upgradedPackages") < acceptance
    assert acceptance < verifier.index("$appUserModelId")
    assert acceptance < smoke_catch < smoke_finally
    assert "request_bytes" not in verifier
    assert "response_bytes" not in verifier


def test_task2_mcp_signed_workflow_downloads_and_binds_pinned_adapter() -> None:
    workflow = (
        PROJECT_ROOT / ".github" / "workflows" / "windows-mvp-signed.yml"
    ).read_text(encoding="utf-8")

    for required in (
        "AGENTGUARDIAN_MCP_ADAPTER_URL: ${{ vars.AGENTGUARDIAN_MCP_ADAPTER_URL }}",
        "AGENTGUARDIAN_MCP_ADAPTER_SHA256: ${{ vars.AGENTGUARDIAN_MCP_ADAPTER_SHA256 }}",
        "AGENTGUARDIAN_MCP_ADAPTER_PUBLISHER: ${{ vars.AGENTGUARDIAN_MCP_ADAPTER_PUBLISHER }}",
        "AGENTGUARDIAN_MCP_ADAPTER_CERTIFICATE_SHA256: ${{ vars.AGENTGUARDIAN_MCP_ADAPTER_CERTIFICATE_SHA256 }}",
        'Join-Path $env:RUNNER_TEMP "AgentGuardianMcpAdapter.exe"',
        "[UriKind]::Absolute",
        'Scheme -ne "https"',
        "Invoke-WebRequest",
        "Get-FileHash -Algorithm SHA256",
        "--mcp-adapter-path",
        "--mcp-adapter-sha256",
        "--mcp-adapter-publisher",
        "--mcp-adapter-certificate-sha256",
        "-ExpectedSourceCommit $sha",
        "-RequireMcpAdapterAcceptance",
        "-McpAdapterRelativePath \"adapters/AgentGuardianMcpAdapter.exe\"",
        "-ExpectedMcpAdapterSha256",
        "-ExpectedMcpAdapterPublisher",
        "-ExpectedMcpAdapterCertificateSha256",
        "-McpAdapterEvidencePath",
        "--mcp-adapter-evidence",
    ):
        assert required in workflow

    assert workflow.index("Invoke-WebRequest") < workflow.index("Get-FileHash -Algorithm SHA256")
    assert workflow.index("Get-FileHash -Algorithm SHA256") < workflow.index(
        "python scripts/build_windows_portable.py"
    )
    assert "Get-Content -LiteralPath $mcpAdapterEvidence" not in workflow
    assert "-AllowUnsigned" not in workflow


def test_task2_signed_workflow_does_not_dump_full_signature_evidence() -> None:
    workflow = (
        PROJECT_ROOT / ".github" / "workflows" / "windows-mvp-signed.yml"
    ).read_text(encoding="utf-8")
    verifier = (
        PROJECT_ROOT / "scripts" / "verify_windows_msix.ps1"
    ).read_text(encoding="utf-8")

    assert 'Get-Content -LiteralPath "$pwd\\.analysis\\signed-msix-smoke.json"' not in workflow
    assert "$evidence.result | ConvertTo-Json -Compress" in verifier


def test_task2_quality_review_signing_secrets_are_scoped_and_keys_removed() -> None:
    workflow = (
        PROJECT_ROOT / ".github" / "workflows" / "windows-mvp-signed.yml"
    ).read_text(encoding="utf-8")

    def step(name: str) -> str:
        start = workflow.index(f"      - name: {name}")
        end = workflow.find("\n      - name:", start + 1)
        return workflow[start:] if end == -1 else workflow[start:end]

    job_env = workflow[workflow.index("    env:"):workflow.index("    steps:")]
    material_check = step("Fail closed when trusted signing material is absent")
    build = step("Build and stage signed package")
    signing = step("Sign with organization certificate and trusted timestamp")
    install = step("Install launch and uninstall trusted signed MSIX on fresh runner")
    pfx_secret = "SIGNING_PFX_B64: ${{ secrets.AGENTGUARDIAN_SIGNING_PFX_B64 }}"
    password_secret = (
        "SIGNING_PFX_PASSWORD: ${{ secrets.AGENTGUARDIAN_SIGNING_PFX_PASSWORD }}"
    )
    publisher_secret = (
        "SIGNING_PUBLISHER: ${{ secrets.AGENTGUARDIAN_SIGNING_PUBLISHER }}"
    )

    assert pfx_secret not in job_env
    assert password_secret not in job_env
    assert publisher_secret not in job_env
    for scoped_secret in (pfx_secret, password_secret):
        assert scoped_secret in material_check
        assert scoped_secret in signing
        assert workflow.count(scoped_secret) == 2
    assert publisher_secret in material_check
    assert publisher_secret in build
    assert publisher_secret in install
    assert publisher_secret not in signing
    assert workflow.count(publisher_secret) == 3
    for required in (
        "$importedCertificates = @()",
        "$signingCertificate = $null",
        "foreach ($importedCertificate in $importedCertificates)",
        '"Cert:\\CurrentUser\\My\\$thumbprint"',
        "-DeleteKey",
        "Remove-Item -LiteralPath $pfxPath",
    ):
        assert required in signing


def test_task2_calibrated_signing_cleanup_is_verified_and_job_bounded() -> None:
    workflow = (
        PROJECT_ROOT / ".github" / "workflows" / "windows-mvp-signed.yml"
    ).read_text(encoding="utf-8")

    signing_start = workflow.index(
        "      - name: Sign with organization certificate and trusted timestamp"
    )
    signing_end = workflow.index("\n      - name:", signing_start + 1)
    signing = workflow[signing_start:signing_end]
    job_header = workflow[
        workflow.index("  signed-msix-fresh-runner:") : workflow.index("    env:")
    ]

    assert "timeout-minutes: 30" in job_header
    for required in (
        "$preexistingThumbprints = @(",
        "Get-ChildItem -LiteralPath Cert:\\CurrentUser\\My -ErrorAction Stop",
        "$preImportSnapshotComplete = $true",
        "$postImportThumbprints = @(",
        "$newThumbprints = @(",
        "$targetThumbprints = @(",
        "Where-Object { $_ -notin $preexistingThumbprints }",
        "$cleanupFailures = [System.Collections.Generic.List[string]]::new()",
        "$cleanupFailures.Add(",
        "Remove-Item -LiteralPath $certificatePath -DeleteKey -Force -ErrorAction Stop",
        "Remove-Item -LiteralPath $pfxPath -Force -ErrorAction Stop",
        "Test-Path -LiteralPath $certificatePath -ErrorAction Stop",
        "Test-Path -LiteralPath $pfxPath -ErrorAction Stop",
        'throw "SIGNING_MATERIAL_CLEANUP_FAILED"',
    ):
        assert required in signing

    assert "SilentlyContinue" not in signing
    assert signing.index("$preexistingThumbprints = @(") < signing.index(
        "Import-PfxCertificate"
    )
    assert signing.index("$postImportThumbprints = @(") > signing.index("finally {")
    assert signing.index("Where-Object { $_ -notin $preexistingThumbprints }") > (
        signing.index("$postImportThumbprints = @(")
    )
    certificate_remove = signing.index(
        "Remove-Item -LiteralPath $certificatePath -DeleteKey -Force -ErrorAction Stop"
    )
    pfx_remove = signing.index(
        "Remove-Item -LiteralPath $pfxPath -Force -ErrorAction Stop"
    )
    assert certificate_remove < signing.index(
        "Test-Path -LiteralPath $certificatePath -ErrorAction Stop"
    )
    assert pfx_remove < signing.index(
        "Test-Path -LiteralPath $pfxPath -ErrorAction Stop", pfx_remove
    )


def test_task2_mcp_unsigned_workflow_git_text_is_unchanged() -> None:
    workflow = PROJECT_ROOT / ".github" / "workflows" / "windows-mvp.yml"

    assert _git_text_sha256(workflow) == UNSIGNED_WORKFLOW_SHA256
