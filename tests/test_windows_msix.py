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
        "process_startup",
        "bounded_liveness",
        "uninstalled",
        "package_residue",
    ):
        assert required in verifier
    assert "-Verb RunAs" not in verifier
    assert "Remove-Item" not in verifier


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
        "SignTool.exe",
        "CertificateRequest",
        "X509EnhancedKeyUsageExtension",
        "Invoke-BoundedProcess",
        "WaitForExit",
        "Cert:\\CurrentUser\\Root",
        "verify_windows_msix.ps1",
        "Install launch and uninstall MSIX as standard user",
    ):
        assert required in workflow
    assert "-Verb RunAs" not in workflow
    assert "production" not in workflow.casefold()
    assert "New-SelfSignedCertificate" not in workflow
    assert "Export-PfxCertificate" not in workflow
    assert "timeout-minutes: 5" in workflow
    assert '"/p", $pfxPassword' in workflow
