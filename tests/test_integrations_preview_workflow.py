from __future__ import annotations

import json
from pathlib import Path
import re

from scripts.verify_integrations_preview_profile import canonical_json_bytes


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "windows-integrations-preview.yml"
STATUS = ROOT / "docs" / "security" / "integrations-preview-status.json"
ACTIVE_DOC = ROOT / "docs" / "security" / "integrations-preview.md"
PROFILE = ROOT / "release_profiles" / "integrations_preview.json"


def _release_profile() -> dict[str, object]:
    return json.loads(PROFILE.read_text(encoding="ascii"))


def test_integrations_preview_workflow_is_exact_sha_and_non_publishing() -> None:
    workflow = WORKFLOW.read_text(encoding="ascii")
    profile = _release_profile()
    assert "runs-on: windows-2025" in workflow
    assert "permissions:\n  contents: read" in workflow
    assert "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" in workflow
    assert "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97" in workflow
    assert "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02" in workflow
    assert "EXPECTED_SOURCE_COMMIT" in workflow
    assert "candidate_sha" in workflow
    assert "ref: ${{ env.EXPECTED_SOURCE_COMMIT }}" in workflow
    for required in (
        "pip install --require-hashes -r requirements-dev.lock",
        "pip install --require-hashes -r requirements-build.lock",
        "python -m pytest -q",
        "run_personal_privacy_acceptance.py",
        "check_brand_assets.py",
        "verify_integrations_preview_profile.py",
        "build_agentguardian_skill.py",
        "--release-profile integrations_preview",
        "build_windows_integrations_preview_installer.py",
        "-Mode $mode",
        "skill,mcp",
        "compileall",
        "git diff --check",
        "secret scan",
        "artifact_sha256",
        "source_sha",
    ):
        assert required in workflow
    assert profile["installer_filename"] in workflow
    assert f"-Filter '{profile['portable_filename']}'" in workflow
    assert (
        str(profile["portable_filename"]).removesuffix(".zip") + "-*.zip"
    ) not in workflow
    assert "pull_request_target" not in workflow
    assert "permissions: write" not in workflow.casefold()
    assert "secrets." not in workflow
    for forbidden in (
        "softprops/action-gh-release",
        "gh release create",
        "marketplace upload",
        "azure/login",
        "deploy-prod",
    ):
        assert forbidden not in workflow.casefold()
    for match in re.finditer(r"uses:\s*([^\s]+)", workflow):
        assert re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", match.group(1))


def test_download_staging_materializes_primary_alias_and_exact_asset_contract() -> None:
    workflow = WORKFLOW.read_text(encoding="ascii")
    profile = _release_profile()
    primary_name = str(profile["primary_download_filename"])

    assert f"$primaryInstallerName = '{primary_name}'" in workflow
    assert "$primaryInstallerPath = Join-Path $downloadRoot $primaryInstallerName" in workflow
    assert "if (Test-Path -LiteralPath $primaryInstallerPath)" in workflow
    assert (
        "Copy-Item -LiteralPath $versionedInstallerPath "
        "-Destination $primaryInstallerPath"
        in workflow
    )
    assert (
        "$versionedInstallerHash = (Get-FileHash -Algorithm SHA256 "
        "-LiteralPath $versionedInstallerPath).Hash.ToLowerInvariant()"
        in workflow
    )
    assert (
        "$primaryInstallerHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $primaryInstallerPath).Hash.ToLowerInvariant()"
        in workflow
    )
    assert "if ($versionedInstallerHash -cne $primaryInstallerHash)" in workflow
    assert "$payloadFiles.Count -ne 6" in workflow
    assert "$metadataDocument = Get-Content -Raw -LiteralPath $metadataPath | ConvertFrom-Json" in workflow
    assert "$metadataFiles.Count -ne $payloadFiles.Count" in workflow
    assert "$actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $actualFile.FullName).Hash.ToLowerInvariant()" in workflow
    assert "if ($actualHash -cne ([string]$metadataFile.sha256).ToLowerInvariant())" in workflow
    assert "if ([int64]$metadataFile.size -ne $actualFile.Length)" in workflow
    assert "$checksumTargets.Count -ne 7" in workflow
    assert "Get-ChildItem -LiteralPath $downloadRoot -Directory" in workflow
    assert "$finalFiles.Count -ne 8" in workflow
    for asset in profile["release_assets"]:
        assert str(asset) in workflow


def test_download_staging_binds_installers_to_lifecycle_sha() -> None:
    workflow = WORKFLOW.read_text(encoding="ascii")
    staging = workflow.split(
        "      - name: Prepare verified downloadable preview files", 1
    )[1].split("      - name: Archive verified downloadable preview", 1)[0]

    assert "$expectedInstallerSha256 = [string]$env:INSTALLER_SHA256" in staging
    assert (
        "$expectedInstallerSha256 -cnotmatch '^[0-9a-fA-F]{64}$'" in staging
    )
    assert (
        "$versionedInstallerHash = (Get-FileHash -Algorithm SHA256 "
        "-LiteralPath $versionedInstallerPath).Hash.ToLowerInvariant()"
        in staging
    )
    assert (
        "if ($versionedInstallerHash -cne $expectedInstallerSha256)" in staging
    )
    assert (
        "$primaryInstallerHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $primaryInstallerPath).Hash.ToLowerInvariant()"
        in staging
    )
    assert "if ($primaryInstallerHash -cne $expectedInstallerSha256)" in staging
    assert "if ($versionedInstallerHash -cne $primaryInstallerHash)" in staging


def test_download_staging_verifies_versioned_copy_before_alias_copy() -> None:
    workflow = WORKFLOW.read_text(encoding="ascii")
    staging = workflow.split(
        "      - name: Prepare verified downloadable preview files", 1
    )[1].split("      - name: Archive verified downloadable preview", 1)[0]

    versioned_copy = (
        "Copy-Item -LiteralPath $installer.FullName "
        "-Destination $versionedInstallerPath"
    )
    versioned_hash = (
        "$versionedInstallerHash = (Get-FileHash -Algorithm SHA256 "
        "-LiteralPath $versionedInstallerPath).Hash.ToLowerInvariant()"
    )
    lifecycle_check = "if ($versionedInstallerHash -cne $expectedInstallerSha256)"
    alias_copy = (
        "Copy-Item -LiteralPath $versionedInstallerPath "
        "-Destination $primaryInstallerPath"
    )

    assert "$versionedInstallerPath = Join-Path $downloadRoot" in staging
    assert versioned_copy in staging
    assert versioned_hash in staging
    assert lifecycle_check in staging
    assert alias_copy in staging
    assert (
        staging.index(versioned_copy)
        < staging.index(versioned_hash)
        < staging.index(lifecycle_check)
        < staging.index(alias_copy)
    )
    assert (
        "Copy-Item -LiteralPath $installer.FullName "
        "-Destination $primaryInstallerPath"
    ) not in staging


def test_download_staging_enumerates_and_rejects_unsafe_entries() -> None:
    workflow = WORKFLOW.read_text(encoding="ascii")
    staging = workflow.split(
        "      - name: Prepare verified downloadable preview files", 1
    )[1].split("      - name: Archive verified downloadable preview", 1)[0]

    for command in re.findall(r"Get-ChildItem[^\r\n]*", workflow):
        assert re.search(r"\s-Force(?:\s|[)\r\n]|$)", command)
    assert "$finalEntries = @(Get-ChildItem -LiteralPath $downloadRoot -Force)" in staging
    assert "if ($entry.PSIsContainer)" in staging
    assert "[IO.FileAttributes]::Hidden" in staging
    assert "[IO.FileAttributes]::ReparsePoint" in staging
    assert "$finalEntries.Count -ne 8" in staging
    assert "$finalFiles.Count -ne 8" in staging


def test_secret_scan_preserves_exit_code_and_fails_closed_without_output() -> None:
    workflow = WORKFLOW.read_text(encoding="ascii")
    scan = workflow.split("$secretMatches = @(git grep", 1)[1].split(
        "git diff --check", 1
    )[0]

    assert "$secretScanExitCode = $LASTEXITCODE" in scan
    assert "if ($secretScanExitCode -eq 0)" in scan
    assert "if (($secretScanExitCode -ne 0) -and ($secretScanExitCode -ne 1))" in scan
    assert "candidate secret scan found a match" in scan
    assert "candidate secret scan failed with exit code $secretScanExitCode" in scan
    assert "Write-Host $secretMatches" not in scan
    assert "Write-Output $secretMatches" not in scan


def test_integrations_preview_status_is_canonical_and_all_pending() -> None:
    raw = STATUS.read_bytes()
    value = json.loads(raw.decode("ascii"))
    assert raw == canonical_json_bytes(value)
    assert value == {
        "gates": {
            "clean_machine_lifecycle": "pending",
            "codex_cli_stdio": "pending",
            "codex_desktop_stdio": "pending",
            "github_ci": "pending",
            "independent_security_review": "pending",
            "license_and_marketplace_review": "pending",
            "local_verification": "pending",
            "windows_integrations_workflow": "pending",
        },
        "schema": 1,
        "status": "INTEGRATIONS-PREVIEW-NOT-READY",
    }


def test_active_03_boundary_and_frozen_02_history_are_explicit() -> None:
    document = ACTIVE_DOC.read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    profile = json.loads(PROFILE.read_text(encoding="ascii"))
    for marker in (
        "desktop GUI",
        "standalone\nCodex Skill",
        "local STDIO MCP",
        "`files`, `browser`, `clipboard`, and\n`public_share`",
        "`prepare_audit`",
        "`run_prepared_audit`",
        "Codex model context",
        "Apache-2.0",
        "INTEGRATIONS-PREVIEW-NOT-READY",
        "NO-GO",
        "high-sensitivity",
    ):
        assert marker in document
    assert "0.3 Integrations Preview is the active development track" in readme
    assert "0.2.0-beta.1" in readme
    assert "frozen exact SHA" in readme
    assert profile["active_document_paths"] == [
        "docs/security/integrations-preview-status.json",
        "docs/security/integrations-preview.md",
    ]


def test_active_docs_publish_the_profile_backed_download_contract() -> None:
    document = ACTIVE_DOC.read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    profile = _release_profile()
    release_url = str(profile["release_download_url"])
    assets = tuple(profile["release_assets"])

    for text in (readme, document):
        assert release_url in text
        assert "unsigned Public Preview" in text
        assert "personal non-regulated" in text
        assert "high-sensitivity real data" in text
        assert "production-safety" in text
        assert "enterprise control-plane" in text
        for asset in assets:
            assert asset in text
        assert "releases/download/" not in text
        assert "actions/artifacts/" not in text
        assert "hqwzhu" not in text.casefold()
        for forbidden in profile["forbidden_document_promises"]:
            assert str(forbidden).casefold() not in text.casefold()

    assert str(profile["primary_download_filename"]) in readme
    assert "AgentGuardianMcp.exe" in readme
    assert "Skill payload" in readme
    assert "does not silently download or enable a Provider API" in readme
    assert "SHA256SUMS" in readme
    assert "INTEGRATIONS-PREVIEW-NOT-READY" in readme
    assert "NO-GO" in readme


def test_active_doc_contains_authorized_manual_release_handoff() -> None:
    document = ACTIVE_DOC.read_text(encoding="utf-8")
    profile = _release_profile()

    for marker in (
        "exact source SHA",
        "exact eight",
        "DOWNLOAD-METADATA.json",
        "SHA256SUMS",
        "v0.3.0-preview.1",
        "AgentGuardian 0.3.0 Public Preview (Unsigned)",
        "non-draft",
        "non-prerelease",
        "fixed unauthenticated link",
        "post-publish report",
        "HTTP 503",
        "alternate owner",
        "alternate account",
        "force push",
        "token disclosure",
    ):
        assert marker in document
    assert str(profile["release_title"]) in document
    assert str(profile["release_tag"]) in document
