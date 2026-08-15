import hashlib
from pathlib import Path

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
        hashlib.sha256(unsigned_workflow_path.read_bytes()).hexdigest()
        == UNSIGNED_WORKFLOW_SHA256
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
    assert verifier.index("$installedPackages = $upgradedPackages") < acceptance
    assert acceptance < verifier.index("$appUserModelId")
    assert acceptance < verifier.index("catch {") < verifier.index("finally {")
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


def test_task2_mcp_unsigned_workflow_is_byte_for_byte_unchanged() -> None:
    workflow = PROJECT_ROOT / ".github" / "workflows" / "windows-mvp.yml"

    assert hashlib.sha256(workflow.read_bytes()).hexdigest() == UNSIGNED_WORKFLOW_SHA256
