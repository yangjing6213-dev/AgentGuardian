from __future__ import annotations

import json
import re
from pathlib import Path

from scripts.verify_integrations_preview_profile import canonical_json_bytes

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "windows-integrations-preview.yml"
STATUS = ROOT / "docs" / "security" / "integrations-preview-status.json"
ACTIVE_DOC = ROOT / "docs" / "security" / "integrations-preview.md"
PERSONAL_RUNBOOK = ROOT / "docs" / "security" / "personal-v1-release-runbook.md"
PROFILE = ROOT / "release_profiles" / "integrations_preview.json"


def _release_profile() -> dict[str, object]:
    return json.loads(PROFILE.read_text(encoding="ascii"))


def _named_run_block(workflow: str, step_name: str) -> str:
    marker = f"      - name: {step_name}\n"
    start = workflow.index(marker) + len(marker)
    remainder = workflow[start:]
    next_step = re.search(r"^      - (?:name|uses):", remainder, re.MULTILINE)
    end = start + next_step.start() if next_step else len(workflow)
    return workflow[start:end]


def _assert_each_line_is_checked_immediately(
    block: str, command_fragment: str, check_fragment: str
) -> None:
    lines = block.splitlines()
    matches = [
        index
        for index, line in enumerate(lines)
        if command_fragment in line and "Assert-NativeSuccess" not in line
    ]
    assert matches, f"missing native command: {command_fragment}"
    for index in matches:
        next_index = index + 1
        while next_index < len(lines) and not lines[next_index].strip():
            next_index += 1
        assert next_index < len(lines), f"missing check after: {command_fragment}"
        assert check_fragment in lines[next_index], (
            f"native command is not checked immediately: {command_fragment}"
        )


def test_integrations_preview_workflow_is_exact_sha_and_non_publishing() -> None:
    workflow = WORKFLOW.read_text(encoding="ascii")
    profile = _release_profile()
    assert "runs-on: windows-2025" in workflow
    assert (
        "push:\n"
        "    branches:\n"
        "      - codex/0.3-public-preview-release\n"
        "      - codex/0.3-integrations-preview"
    ) in workflow
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
    assert "hqwzhu" not in workflow.casefold()
    assert "actions/artifacts/" not in workflow
    assert "releases/download/" not in workflow
    assert "personal access token" not in workflow.casefold()
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


def test_critical_native_commands_use_fail_closed_checks_per_run_block() -> None:
    workflow = WORKFLOW.read_text(encoding="ascii")
    expected_blocks = (
        "Verify exact clean checkout and derive bounded paths",
        "Install hash-locked runtime and build dependencies",
        "Run full local gates and secret scan",
        "Build deterministic standalone Skills",
        "Build deterministic preview portable payloads",
        "Download and verify pinned Inno Setup compiler",
        "Build exact preview installer",
        "Run every bounded integration lifecycle mode",
        "Verify final checkout remains clean",
    )
    for step_name in expected_blocks:
        block = _named_run_block(workflow, step_name)
        assert "function Assert-NativeSuccess" in block
        assert 'throw "$Command failed with exit code $ExitCode"' in block

    checkout = _named_run_block(
        workflow, "Verify exact clean checkout and derive bounded paths"
    )
    _assert_each_line_is_checked_immediately(
        checkout,
        "$head = (git rev-parse HEAD).Trim()",
        "Assert-NativeSuccess $LASTEXITCODE",
    )
    _assert_each_line_is_checked_immediately(
        checkout,
        "$status = git status --porcelain=v1 --untracked-files=all",
        "Assert-NativeSuccess $LASTEXITCODE",
    )
    _assert_each_line_is_checked_immediately(
        checkout,
        "$commitEpoch = [int64](git show -s --format=%ct HEAD)",
        "Assert-NativeSuccess $LASTEXITCODE",
    )

    dependencies = _named_run_block(
        workflow, "Install hash-locked runtime and build dependencies"
    )
    for command in (
        "python -m pip install --require-hashes -r requirements-dev.lock",
        "python -m pip install --require-hashes -r requirements-build.lock",
    ):
        _assert_each_line_is_checked_immediately(
            dependencies, command, "Assert-NativeSuccess $LASTEXITCODE"
        )

    full_gates = _named_run_block(workflow, "Run full local gates and secret scan")
    for command in (
        "python -m pytest -q -p no:cacheprovider --basetemp",
        "python scripts/run_personal_privacy_acceptance.py",
        "python scripts/check_brand_assets.py",
        "python scripts/verify_integrations_preview_profile.py",
        "python -m compileall -q src scripts tests",
        "git diff --check",
    ):
        _assert_each_line_is_checked_immediately(
            full_gates, command, "Assert-NativeSuccess $LASTEXITCODE"
        )

    skills = _named_run_block(workflow, "Build deterministic standalone Skills")
    for command in (
        "python scripts/build_agentguardian_skill.py --output-root $env:SKILL_ONE",
        "python scripts/build_agentguardian_skill.py --output-root $env:SKILL_TWO",
    ):
        _assert_each_line_is_checked_immediately(
            skills, command, "Assert-NativeSuccess $LASTEXITCODE"
        )

    portable = _named_run_block(
        workflow, "Build deterministic preview portable payloads"
    )
    assert sum(
        line.strip().startswith("python scripts/build_windows_portable.py")
        for line in portable.splitlines()
    ) == 2
    assert portable.count("Assert-NativeSuccess $LASTEXITCODE") >= 2
    _assert_each_line_is_checked_immediately(
        portable,
        "--release-profile integrations_preview",
        "Assert-NativeSuccess $LASTEXITCODE",
    )

    gh_download = _named_run_block(
        workflow, "Download and verify pinned Inno Setup compiler"
    )
    _assert_each_line_is_checked_immediately(
        gh_download,
        "gh release download $env:INNO_RELEASE_TAG",
        "Assert-NativeSuccess $LASTEXITCODE",
    )

    installer = _named_run_block(workflow, "Build exact preview installer")
    _assert_each_line_is_checked_immediately(
        installer,
        "--built-at $env:COMMIT_UTC",
        "Assert-NativeSuccess $LASTEXITCODE",
    )

    lifecycle = _named_run_block(
        workflow, "Run every bounded integration lifecycle mode"
    )
    _assert_each_line_is_checked_immediately(
        lifecycle, "-TestMode", "Assert-NativeSuccess $LASTEXITCODE"
    )

    final_status = _named_run_block(workflow, "Verify final checkout remains clean")
    _assert_each_line_is_checked_immediately(
        final_status,
        "$status = git status --porcelain=v1 --untracked-files=all",
        "Assert-NativeSuccess $LASTEXITCODE",
    )


def test_full_gate_secret_scan_keeps_git_grep_exit_semantics_without_output() -> None:
    workflow = WORKFLOW.read_text(encoding="ascii")
    full_gates = _named_run_block(workflow, "Run full local gates and secret scan")
    assert "function Assert-GitGrepNoMatches" in full_gates
    assert "$secretScanExitCode = $LASTEXITCODE" in full_gates
    assert "Assert-GitGrepNoMatches $secretScanExitCode" in full_gates
    assert "if ($ExitCode -eq 0)" in full_gates
    assert "if ($ExitCode -ne 1)" in full_gates
    assert "candidate secret scan found a match" in full_gates
    assert "candidate secret scan failed with exit code $ExitCode" in full_gates
    assert "Write-Host $secretMatches" not in full_gates
    assert "Write-Output $secretMatches" not in full_gates

    grep_line = next(
        line for line in full_gates.splitlines() if "$secretMatches = @(git grep" in line
    )
    lines = full_gates.splitlines()
    grep_index = lines.index(grep_line)
    assert "$secretScanExitCode = $LASTEXITCODE" in lines[grep_index + 1]
    assert "Assert-GitGrepNoMatches" in lines[grep_index + 2]
    assert "sk-(proj|live|test)-[A-Za-z0-9]{32,}" in full_gates
    assert "sk-[A-Za-z0-9]{32,}" in full_gates
    assert "github[_]pat_[A-Za-z0-9_]{20,}" in full_gates


def test_workflow_adds_pinned_gitleaks_history_and_asset_scans() -> None:
    workflow = WORKFLOW.read_text(encoding="ascii")
    assert "fetch-depth: 0" in workflow
    assert "GITLEAKS_RELEASE_TAG: v8.30.1" in workflow
    assert "GITLEAKS_ASSET_NAME: gitleaks_8.30.1_windows_x64.zip" in workflow
    assert (
        "GITLEAKS_ASSET_SHA256: "
        "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e"
    ) in workflow
    assert "$env:GITLEAKS_EXE git" in workflow
    assert "$env:GITLEAKS_EXE dir $env:RELEASE_ROOT" in workflow
    assert "--redact" in workflow
    assert "--log-opts='--all -m'" in workflow
    assert "GITLEAKS_EXE" in workflow
    assert "gitleaks scan failed" in workflow


def _public_preview_staging_block(workflow: str) -> str:
    marker = "      - name: Stage verified public preview release bundle\n"
    assert marker in workflow
    return _named_run_block(workflow, "Stage verified public preview release bundle")


def test_download_staging_delegates_to_unified_profile_backed_tool() -> None:
    workflow = WORKFLOW.read_text(encoding="ascii")
    staging = _public_preview_staging_block(workflow)

    assert "$workspaceParent = Split-Path -Parent $pwd.Path" in workflow
    assert "id: derive_paths" in workflow
    assert (
        '$releaseRoot = Join-Path $workspaceParent '
        '("agentguardian-public-preview-release-" + $env:EXPECTED_SOURCE_COMMIT)'
    ) in workflow
    assert '"RELEASE_ROOT=$releaseRoot" >> $env:GITHUB_ENV' in workflow
    assert '"release_root=$releaseRoot" >> $env:GITHUB_OUTPUT' in workflow
    assert "RELEASE_ROOT=$env:RUNNER_TEMP\\agentguardian-public-preview-release" not in workflow
    assert "INSTALLER_ATTESTATION_PATH=$env:RUNNER_TEMP\\AgentGuardian-Setup-0.3.0-preview.1-x64.exe.build.json" in workflow
    assert "if (Test-Path -LiteralPath $env:RELEASE_ROOT)" in staging
    assert "python scripts/stage_public_preview_release.py `" in staging
    for argument in (
        "--project-root $pwd `",
        "--output-root $env:RELEASE_ROOT `",
        "--installer-path $env:INSTALLER_PATH `",
        "--portable-path $portablePath `",
        "--portable-bundle-root $env:PORTABLE_BUNDLE `",
        "--skill-path $skillPath `",
        "--installer-attestation-path $env:INSTALLER_ATTESTATION_PATH `",
        "--source-commit $env:EXPECTED_SOURCE_COMMIT `",
        "--built-at $env:COMMIT_UTC",
    ):
        assert argument in staging
    assert (
        "Assert-NativeSuccess $LASTEXITCODE "
        "'python scripts/stage_public_preview_release.py'"
    ) in staging
    assert "$portablePath = Join-Path $env:PORTABLE_ONE 'AgentGuardian-0.3.0-preview.1-windows-x64.zip'" in staging
    assert "$skillPath = Join-Path $env:SKILL_ONE 'AgentGuardian-Skill-0.2.0.zip'" in staging
    assert "Copy-Item" not in staging
    assert "ConvertTo-Json" not in staging
    assert "WriteAllText" not in staging
    assert "$downloadRoot" not in staging


def test_lifecycle_binds_installed_payload_to_portable_bundle() -> None:
    workflow = WORKFLOW.read_text(encoding="ascii")
    lifecycle = _named_run_block(
        workflow, "Run every bounded integration lifecycle mode"
    )
    assert "-Portable_Bundle_Root $env:PORTABLE_BUNDLE `" in lifecycle


def test_download_staging_checks_exact_profile_assets_and_unsigned_metadata() -> None:
    workflow = WORKFLOW.read_text(encoding="ascii")
    staging = _public_preview_staging_block(workflow)
    profile = _release_profile()

    for asset in profile["release_assets"]:
        assert str(asset) in staging
    assert "$profileDocument = Get-Content -Raw -LiteralPath" in staging
    assert "$profileAssetNames = @($profileDocument.release_assets | Sort-Object)" in staging
    assert "$stagedFiles = @(Get-ChildItem -LiteralPath $env:RELEASE_ROOT -File -Force | Sort-Object Name)" in staging
    assert "$stagedFiles.Count -ne $profileAssetNames.Count" in staging
    assert "if (($stagedFiles.Name -join \"`n\") -cne ($profileAssetNames -join \"`n\"))" in staging
    assert "--verify" in staging
    assert "$verification.source_commit -cne $env:EXPECTED_SOURCE_COMMIT" in staging
    assert "$metadata.artifact_status -cne 'unsigned_public_preview'" in staging
    assert "DOWNLOAD-METADATA.json" in staging
    assert "SHA256SUMS" in staging


def test_download_staging_archive_uses_only_the_public_preview_bundle_root() -> None:
    workflow = WORKFLOW.read_text(encoding="ascii")
    archive = _named_run_block(workflow, "Archive verified public preview bundle")

    assert "agentguardian-public-preview-bundle-${{ env.EXPECTED_SOURCE_COMMIT }}" in workflow
    assert "retention-days: 14" in archive
    assert "if-no-files-found: error" in archive
    assert "path: ${{ steps.derive_paths.outputs.release_root }}" in archive
    assert "../agentguardian-public-preview-release-" not in archive
    assert "agentguardian-downloadable-preview" not in workflow


def test_public_preview_staging_has_no_repository_write_or_release_operation() -> None:
    workflow = WORKFLOW.read_text(encoding="ascii")

    assert "contents: read" in workflow
    assert "contents: write" not in workflow.casefold()
    assert "gh release create" not in workflow.casefold()
    assert "create-release" not in workflow.casefold()
    assert "softprops/action-gh-release" not in workflow.casefold()
    assert "github_pat_" not in workflow.casefold()
    assert "personal access token" not in workflow.casefold()
    assert "secrets." not in workflow


def test_secret_scan_preserves_exit_code_and_fails_closed_without_output() -> None:
    workflow = WORKFLOW.read_text(encoding="ascii")
    scan = _named_run_block(workflow, "Run full local gates and secret scan")

    assert "function Assert-GitGrepNoMatches" in scan
    assert "$secretScanExitCode = $LASTEXITCODE" in scan
    assert "Assert-GitGrepNoMatches $secretScanExitCode" in scan
    assert "if ($ExitCode -eq 0)" in scan
    assert "if ($ExitCode -ne 1)" in scan
    assert "candidate secret scan found a match" in scan
    assert "candidate secret scan failed with exit code $ExitCode" in scan
    assert "Write-Host $secretMatches" not in scan
    assert "Write-Output $secretMatches" not in scan


def test_personal_v1_runbook_is_explicitly_historical_for_current_preview() -> None:
    document = PERSONAL_RUNBOOK.read_text(encoding="utf-8").casefold()

    assert "historical governance snapshot" in document
    assert "current 0.3 integrations preview" in document


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
