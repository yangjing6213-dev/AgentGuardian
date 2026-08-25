from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "release_profiles" / "integrations_preview.json"


def _verifier():
    try:
        return importlib.import_module("scripts.verify_integrations_preview_profile")
    except ModuleNotFoundError:
        pytest.fail("integrations preview profile verifier is missing")


def test_integrations_preview_profile_has_exact_identity() -> None:
    profile = json.loads(PROFILE_PATH.read_text(encoding="ascii"))
    assert profile["schema"] == 1
    assert profile["name"] == "integrations_preview"
    assert profile["channel"] == "integrations_preview"
    assert profile["python_package_version"] == "0.3.0a1"
    assert profile["product_version"] == "0.3.0-preview.1"
    assert profile["windows_file_version"] == "0.3.0.1"
    assert profile["installer_app_id"] == "{A64DBF23-FE14-4E04-89AE-0924666A03DE}"
    assert profile["installer_filename"] == (
        "AgentGuardian-Setup-0.3.0-preview.1-x64.exe"
    )
    assert profile["install_directory"] == (
        r"{localappdata}\Programs\AgentGuardian Integrations Preview"
    )
    assert profile["skill_version"] == "0.1.0"
    assert profile["mcp_sdk"] == "2.0.0"
    assert profile["transport"] == "stdio"
    assert profile["mcp_tools"] == ["prepare_audit", "run_prepared_audit"]
    assert profile["skill_path"] == r"%USERPROFILE%\.agents\skills\agentguardian"
    assert profile["config_path"] == r"%USERPROFILE%\.codex\config.toml"
    assert profile["backup_path"] == (
        r"%LOCALAPPDATA%\AgentGuardian\codex-config-backup-v1.bin"
    )
    assert profile["manifest_path"] == (
        r"%LOCALAPPDATA%\AgentGuardian\codex-integration-v1.json"
    )
    assert profile["launcher_inventory"] == [
        {"console": False, "name": "AgentGuardian.exe"},
        {"console": True, "name": "AgentGuardianMcp.exe"},
    ]
    assert all(not task["default_selected"] for task in profile["installer_tasks"])


def test_integrations_preview_profile_is_canonical_and_verifies() -> None:
    verifier = _verifier()
    raw = PROFILE_PATH.read_bytes()
    snapshot = verifier.load_profile_snapshot(ROOT, PROFILE_PATH)
    assert raw == verifier.canonical_json_bytes(json.loads(raw.decode("ascii")))
    assert verifier.verify_profile(ROOT, snapshot) == {
        "profile": "integrations_preview",
        "status": "pass",
    }


def test_integrations_preview_profile_rejects_noncanonical_and_unknown_keys() -> None:
    verifier = _verifier()
    profile = json.loads(PROFILE_PATH.read_text(encoding="ascii"))
    with pytest.raises(verifier.ProfileViolation, match="PROFILE_JSON_INVALID"):
        verifier.profile_snapshot_from_bytes(
            json.dumps(profile, ensure_ascii=True).encode("ascii")
        )
    profile["unexpected"] = True
    raw = verifier.canonical_json_bytes(profile)
    with pytest.raises(verifier.ProfileViolation, match="PROFILE_SCHEMA_INVALID"):
        verifier.profile_snapshot_from_bytes(raw)


def test_integrations_preview_profile_rejects_identity_and_tool_drift() -> None:
    verifier = _verifier()
    profile = json.loads(PROFILE_PATH.read_text(encoding="ascii"))
    profile["installer_app_id"] = "{7A76221A-CFA0-4860-B250-7083B736F3FB}"
    with pytest.raises(verifier.ProfileViolation, match="PROFILE_IDENTITY_INVALID"):
        verifier.profile_snapshot_from_bytes(verifier.canonical_json_bytes(profile))

    profile = json.loads(PROFILE_PATH.read_text(encoding="ascii"))
    profile["mcp_tools"].append("third_tool")
    with pytest.raises(verifier.ProfileViolation, match="PROFILE_TOOL_SET_INVALID"):
        verifier.profile_snapshot_from_bytes(verifier.canonical_json_bytes(profile))


def test_integrations_preview_profile_rejects_default_selected_task_and_codex_skills() -> None:
    verifier = _verifier()
    profile = json.loads(PROFILE_PATH.read_text(encoding="ascii"))
    profile["installer_tasks"][0]["default_selected"] = True
    with pytest.raises(verifier.ProfileViolation, match="PROFILE_TASK_DEFAULT_INVALID"):
        verifier.profile_snapshot_from_bytes(verifier.canonical_json_bytes(profile))

    profile = json.loads(PROFILE_PATH.read_text(encoding="ascii"))
    profile["skill_path"] = r"%USERPROFILE%\.codex\skills\agentguardian"
    with pytest.raises(verifier.ProfileViolation, match="PROFILE_IDENTITY_INVALID"):
        verifier.profile_snapshot_from_bytes(verifier.canonical_json_bytes(profile))


def test_integrations_preview_profile_rejects_provider_source_in_fixture(
    tmp_path: Path,
) -> None:
    verifier = _verifier()
    project = tmp_path / "project"
    (project / "src" / "agentguardian").mkdir(parents=True)
    (project / "src" / "agentguardian" / "provider.py").write_text(
        "import openai\n", encoding="ascii"
    )
    profile = json.loads(PROFILE_PATH.read_text(encoding="ascii"))
    profile["required_source_paths"] = ["src/agentguardian/provider.py"]
    profile["package_input_paths"] = ["src/agentguardian/provider.py"]
    profile["active_document_paths"] = []
    profile["required_document_markers"] = []
    profile["declared_network_modules"] = []
    snapshot = verifier.profile_snapshot_from_bytes(
        verifier.canonical_json_bytes(profile)
    )
    with pytest.raises(verifier.ProfileViolation, match="PROFILE_RUNTIME_IMPORT_FORBIDDEN"):
        verifier.verify_profile(project, snapshot)
