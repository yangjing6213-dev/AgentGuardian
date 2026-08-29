from __future__ import annotations

import importlib
import json
import shutil
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "release_profiles" / "integrations_preview.json"
RELEASE_CONTRACT = {
    "release_artifact_status": "unsigned_public_preview",
    "release_tag": "v0.3.0-preview.1",
    "release_title": "AgentGuardian 0.3.0 Public Preview (Unsigned)",
    "release_draft": False,
    "release_prerelease": False,
    "primary_download_filename": "AgentGuardian-Setup-Windows-x64.exe",
    "portable_filename": "AgentGuardian-0.3.0-preview.1-windows-x64.zip",
    "release_download_url": (
        "https://github.com/yangjing6213-dev/AgentGuardian/releases/latest/"
        "download/AgentGuardian-Setup-Windows-x64.exe"
    ),
    "release_assets": [
        "AgentGuardian-0.3.0-preview.1-windows-x64.zip",
        "AgentGuardian-Setup-0.3.0-preview.1-x64.exe",
        "AgentGuardian-Setup-Windows-x64.exe",
        "AgentGuardian-Skill-0.2.0.zip",
        "DOWNLOAD-METADATA.json",
        "LICENSE",
        "SHA256SUMS",
        "THIRD_PARTY_NOTICES.md",
    ],
}


def _verifier():
    try:
        return importlib.import_module("scripts.verify_integrations_preview_profile")
    except ModuleNotFoundError:
        pytest.fail("integrations preview profile verifier is missing")


def _marker_profile(required: list[str], forbidden: list[str]) -> dict[str, object]:
    return {
        "active_document_paths": ["first.md", "second.md"],
        "required_document_markers": required,
        "forbidden_document_promises": forbidden,
    }


def test_active_document_required_marker_checks_every_document(
    tmp_path: Path,
) -> None:
    verifier = _verifier()
    (tmp_path / "first.md").write_text("required marker", encoding="utf-8")
    (tmp_path / "second.md").write_text("ordinary text", encoding="utf-8")

    verifier._verify_documents(
        tmp_path,
        _marker_profile(["required marker"], []),
    )


def test_active_document_forbidden_marker_checks_every_document(
    tmp_path: Path,
) -> None:
    verifier = _verifier()
    (tmp_path / "first.md").write_text("forbidden promise", encoding="utf-8")
    (tmp_path / "second.md").write_text("ordinary text", encoding="utf-8")

    with pytest.raises(
        verifier.ProfileViolation,
        match="^PROFILE_DOCUMENT_FORBIDDEN$",
    ):
        verifier._verify_documents(
            tmp_path,
            _marker_profile([], ["forbidden promise"]),
        )


def test_active_document_markers_still_accept_clean_combined_documents(
    tmp_path: Path,
) -> None:
    verifier = _verifier()
    (tmp_path / "first.md").write_text("ordinary text", encoding="utf-8")
    (tmp_path / "second.md").write_text("required marker", encoding="utf-8")

    verifier._verify_documents(
        tmp_path,
        _marker_profile(["required marker"], ["forbidden promise"]),
    )


def test_integrations_preview_profile_has_exact_identity() -> None:
    profile = json.loads(PROFILE_PATH.read_text(encoding="ascii"))
    assert profile["schema"] == 2
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
    assert profile["skill_version"] == "0.2.0"
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
    for field, expected in RELEASE_CONTRACT.items():
        assert profile[field] == expected


def test_integrations_preview_profile_binds_license_packet_inputs() -> None:
    profile = json.loads(PROFILE_PATH.read_text(encoding="ascii"))
    packet_root = ROOT / "packaging" / "third_party_licenses"
    packet_paths = {
        "packaging/third_party_licenses/"
        + path.relative_to(packet_root).as_posix()
        for path in packet_root.rglob("*")
        if path.is_file()
    }

    for field in ("required_source_paths", "package_input_paths"):
        assert packet_paths <= set(profile[field])


@pytest.mark.parametrize(
    ("field", "mutated"),
    [
        ("schema", 1),
        ("release_artifact_status", "unsigned_development_only"),
        ("release_tag", "v0.3.0-preview.2"),
        ("release_title", "AgentGuardian 0.3.0 Private Beta"),
        ("release_draft", True),
        ("release_prerelease", True),
        ("primary_download_filename", "AgentGuardian-Setup-Windows-arm64.exe"),
        ("portable_filename", "AgentGuardian-0.3.0-preview.1-windows-arm64.zip"),
        (
            "release_download_url",
            "https://example.invalid/private-token.exe",
        ),
        (
            "release_assets",
            [
                "AgentGuardian-0.3.0-preview.1-windows-x64.zip",
                "AgentGuardian-Setup-0.3.0-preview.1-x64.exe",
                "AgentGuardian-Setup-Windows-x64.exe",
                "AgentGuardian-Skill-0.2.0.zip",
                "DOWNLOAD-METADATA.json",
                "LICENSE",
                "SHA256SUMS",
            ],
        ),
    ],
)
def test_integrations_preview_profile_rejects_release_contract_drift(
    field: str, mutated: object
) -> None:
    verifier = _verifier()
    profile = json.loads(PROFILE_PATH.read_text(encoding="ascii"))
    profile[field] = mutated

    with pytest.raises(
        verifier.ProfileViolation,
        match="^PROFILE_RELEASE_CONTRACT_INVALID$",
    ) as caught:
        verifier.profile_snapshot_from_bytes(
            verifier.canonical_json_bytes(profile)
        )

    assert str(caught.value) == "PROFILE_RELEASE_CONTRACT_INVALID"
    assert "private-token" not in str(caught.value)


@pytest.mark.parametrize(
    ("field", "invalid_type"),
    [
        ("release_draft", "false"),
        ("release_prerelease", 0),
        ("primary_download_filename", 7),
        ("portable_filename", ["AgentGuardian.zip"]),
        ("release_download_url", ["https://example.invalid/file.exe"]),
        ("release_tag", False),
        ("release_title", {"title": "preview"}),
        ("release_assets", ["LICENSE", 7]),
    ],
)
def test_integrations_preview_profile_rejects_release_contract_types(
    field: str, invalid_type: object
) -> None:
    verifier = _verifier()
    profile = json.loads(PROFILE_PATH.read_text(encoding="ascii"))
    profile[field] = invalid_type

    with pytest.raises(
        verifier.ProfileViolation,
        match="^PROFILE_RELEASE_CONTRACT_INVALID$",
    ):
        verifier.profile_snapshot_from_bytes(
            verifier.canonical_json_bytes(profile)
        )


@pytest.mark.parametrize(
    ("field", "unsafe_name"),
    [
        ("primary_download_filename", "../AgentGuardian-Setup-Windows-x64.exe"),
        ("portable_filename", "nested/AgentGuardian-preview.zip"),
    ],
)
def test_integrations_preview_profile_rejects_release_paths(
    field: str, unsafe_name: str
) -> None:
    verifier = _verifier()
    profile = json.loads(PROFILE_PATH.read_text(encoding="ascii"))
    profile[field] = unsafe_name

    with pytest.raises(
        verifier.ProfileViolation,
        match="^PROFILE_RELEASE_CONTRACT_INVALID$",
    ):
        verifier.profile_snapshot_from_bytes(
            verifier.canonical_json_bytes(profile)
        )


def test_integrations_preview_profile_is_canonical_and_verifies() -> None:
    verifier = _verifier()
    raw = PROFILE_PATH.read_bytes()
    snapshot = verifier.load_profile_snapshot(ROOT, PROFILE_PATH)
    assert raw == verifier.canonical_json_bytes(json.loads(raw.decode("ascii")))
    assert verifier.verify_profile(ROOT, snapshot) == {
        "profile": "integrations_preview",
        "status": "pass",
    }


def test_integrations_preview_profile_accepts_windows_source_newlines(
    tmp_path: Path,
) -> None:
    verifier = _verifier()
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
    source = project / "src" / "agentguardian" / "self_audit.py"
    normalized = source.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    source.write_bytes(normalized.replace(b"\n", b"\r\n"))
    snapshot = verifier.load_profile_snapshot(
        project, project / "release_profiles" / "integrations_preview.json"
    )

    assert verifier.verify_profile(project, snapshot) == {
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


def test_portable_builder_selects_integrations_preview_loader(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import scripts.build_windows_portable as build_module

    snapshot = _verifier().load_profile_snapshot(ROOT, PROFILE_PATH)
    calls: list[Path] = []

    monkeypatch.setattr(build_module.sys, "platform", "win32")
    monkeypatch.setattr(build_module.sys, "version_info", (3, 12))
    monkeypatch.setattr(
        build_module,
        "_git",
        lambda _root, *arguments: "a" * 40
        if arguments == ("rev-parse", "HEAD")
        else "",
    )

    def load_preview(project_root: Path, profile_path: Path):
        calls.append(profile_path)
        return snapshot

    monkeypatch.setattr(
        build_module,
        "load_integrations_preview_profile_snapshot",
        load_preview,
    )
    monkeypatch.setattr(
        build_module,
        "_build_integrations_preview_portable",
        lambda *args, **kwargs: kwargs["profile_snapshot"],
    )

    result = build_module.build_portable(
        tmp_path,
        tmp_path / "output",
        source_commit="a" * 40,
        built_at="2026-08-25T00:00:00Z",
        release_profile="integrations_preview",
    )

    assert result is snapshot
    assert calls == [tmp_path / "release_profiles" / "integrations_preview.json"]
