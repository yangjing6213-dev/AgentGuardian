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


def test_integrations_preview_workflow_is_exact_sha_and_non_publishing() -> None:
    workflow = WORKFLOW.read_text(encoding="ascii")
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
