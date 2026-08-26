from __future__ import annotations

import hashlib
import importlib
import json
import os
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40
BUILT_AT = "2026-08-27T00:00:00Z"
ASSET_NAMES = (
    "AgentGuardian-0.3.0-preview.1-windows-x64.zip",
    "AgentGuardian-Setup-0.3.0-preview.1-x64.exe",
    "AgentGuardian-Setup-Windows-x64.exe",
    "AgentGuardian-Skill-0.2.0.zip",
    "DOWNLOAD-METADATA.json",
    "LICENSE",
    "SHA256SUMS",
    "THIRD_PARTY_NOTICES.md",
)


def _module():
    return importlib.import_module("scripts.stage_public_preview_release")


def _inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    installer = inputs / "built-installer.exe"
    portable = inputs / "built-portable.zip"
    skill = inputs / "built-skill.zip"
    installer.write_bytes(b"installer-bytes\x00\x01")
    portable.write_bytes(b"portable-bytes")
    skill.write_bytes(b"skill-zip-bytes")
    return installer, portable, skill


def _stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[object, Path, tuple[Path, Path, Path]]:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    output = tmp_path / "release"
    result = module.stage_public_preview_release(
        ROOT,
        output,
        installer_path=installer,
        portable_path=portable,
        skill_path=skill,
        source_commit=COMMIT,
        built_at=BUILT_AT,
    )
    return result, output, (installer, portable, skill)


def test_stage_public_preview_release_writes_exact_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    result, output, _ = _stage(tmp_path, monkeypatch)

    assert result["status"] == "pass"
    assert tuple(sorted(path.name for path in output.iterdir())) == tuple(
        sorted(ASSET_NAMES)
    )
    assert (output / module.PRIMARY_INSTALLER_NAME).read_bytes() == (
        output / module.VERSIONED_INSTALLER_NAME
    ).read_bytes()

    metadata = json.loads((output / "DOWNLOAD-METADATA.json").read_text("ascii"))
    assert set(metadata) == {
        "architecture",
        "artifact_status",
        "channel",
        "files",
        "installer",
        "release",
        "schema",
        "source_commit",
        "supported_platform",
        "version",
    }
    assert metadata["architecture"] == "x64"
    assert metadata["artifact_status"] == "unsigned_public_preview"
    assert metadata["channel"] == "integrations_preview"
    assert metadata["schema"] == 1
    assert metadata["source_commit"] == COMMIT
    assert metadata["supported_platform"] == "Windows 11 x64"
    assert metadata["version"] == "0.3.0-preview.1"
    assert set(metadata["installer"]) == {
        "primary_filename",
        "versioned_filename",
        "built_at",
    }
    assert metadata["installer"] == {
        "primary_filename": module.PRIMARY_INSTALLER_NAME,
        "versioned_filename": module.VERSIONED_INSTALLER_NAME,
        "built_at": BUILT_AT,
    }
    assert metadata["release"] == {
        "tag": "v0.3.0-preview.1",
        "title": "AgentGuardian 0.3.0 Public Preview (Unsigned)",
        "draft": False,
        "prerelease": False,
        "fixed_download_url": (
            "https://github.com/yangjing6213-dev/AgentGuardian/releases/latest/"
            "download/AgentGuardian-Setup-Windows-x64.exe"
        ),
    }
    assert len(metadata["files"]) == 6
    assert all(set(record) == {"name", "sha256", "size"} for record in metadata["files"])
    assert {record["name"] for record in metadata["files"]} == {
        name
        for name in ASSET_NAMES
        if name not in {"DOWNLOAD-METADATA.json", "SHA256SUMS"}
    }

    checksum_lines = (output / "SHA256SUMS").read_text("ascii").splitlines()
    checksum_names = [line.split("  ", 1)[1] for line in checksum_lines]
    assert checksum_names == sorted(checksum_names)
    assert set(checksum_names) == set(ASSET_NAMES) - {"SHA256SUMS"}
    for line in checksum_lines:
        digest, name = line.split("  ", 1)
        assert digest == hashlib.sha256((output / name).read_bytes()).hexdigest()

    assert module.verify_staged_release(output, ROOT, source_commit=COMMIT) == {
        "status": "pass",
        "source_commit": COMMIT,
    }


def test_verify_rejects_changed_stable_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    _, output, _ = _stage(tmp_path, monkeypatch)
    (output / module.PRIMARY_INSTALLER_NAME).write_bytes(b"changed")
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_ASSET_DIGEST_MISMATCH$"):
        module.verify_staged_release(output, ROOT, source_commit=COMMIT)


def test_verify_rejects_missing_asset(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = _module()
    _, output, _ = _stage(tmp_path, monkeypatch)
    (output / module.SKILL_NAME).unlink()
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_MANIFEST_INVALID$"):
        module.verify_staged_release(output, ROOT, source_commit=COMMIT)


def test_verify_rejects_extra_asset(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = _module()
    _, output, _ = _stage(tmp_path, monkeypatch)
    (output / "unexpected.txt").write_text("extra", encoding="ascii")
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_MANIFEST_INVALID$"):
        module.verify_staged_release(output, ROOT, source_commit=COMMIT)


def test_verify_rejects_tampered_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    _, output, _ = _stage(tmp_path, monkeypatch)
    metadata_path = output / "DOWNLOAD-METADATA.json"
    metadata = json.loads(metadata_path.read_text("ascii"))
    metadata["version"] = "0.3.0-preview.2"
    metadata_path.write_bytes(module.canonical_json_bytes(metadata))
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_MANIFEST_INVALID$"):
        module.verify_staged_release(output, ROOT, source_commit=COMMIT)


def test_verify_rejects_checksum_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    _, output, _ = _stage(tmp_path, monkeypatch)
    checksum_path = output / "SHA256SUMS"
    lines = checksum_path.read_text("ascii").splitlines()
    checksum_path.write_text("0" * 64 + lines[0][64:] + "\n" + "\n".join(lines[1:]) + "\n", encoding="ascii")
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_CHECKSUM_INVALID$"):
        module.verify_staged_release(output, ROOT, source_commit=COMMIT)


def test_stage_rejects_relative_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_INPUT_PATH_INVALID$"):
        module.stage_public_preview_release(
            ROOT,
            tmp_path / "release",
            installer_path=Path("relative-installer.exe"),
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )


def test_stage_rejects_directory_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    _, portable, skill = _inputs(tmp_path)
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_INPUT_PATH_INVALID$"):
        module.stage_public_preview_release(
            ROOT,
            tmp_path / "release",
            installer_path=tmp_path / "inputs",
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )


def test_stage_rejects_symlink_input_when_supported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    _, portable, skill = _inputs(tmp_path)
    target = tmp_path / "target.exe"
    target.write_bytes(b"target")
    linked = tmp_path / "linked.exe"
    try:
        linked.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_INPUT_PATH_INVALID$"):
        module.stage_public_preview_release(
            ROOT,
            tmp_path / "release",
            installer_path=linked,
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )


def test_stage_rejects_output_nested_in_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_OUTPUT_PATH_INVALID$"):
        module.stage_public_preview_release(
            ROOT,
            ROOT / ".tmp" / "public-preview-test-output",
            installer_path=installer,
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )


def test_stage_rejects_non_empty_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    output = tmp_path / "release"
    output.mkdir()
    (output / "existing.txt").write_text("existing", encoding="ascii")
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_OUTPUT_PATH_INVALID$"):
        module.stage_public_preview_release(
            ROOT,
            output,
            installer_path=installer,
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )


def test_stage_rejects_private_marker_without_leaking_marker_or_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    marker = b"OPENAI_API_KEY=sk-proj-private-preview-marker-123456"
    installer.write_bytes(marker)
    with pytest.raises(module.ReleaseViolation) as caught:
        module.stage_public_preview_release(
            ROOT,
            tmp_path / "release",
            installer_path=installer,
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )
    assert str(caught.value) == (
        "RELEASE_PRIVATE_DATA_DETECTED: remove credentials or private data "
        "from release inputs"
    )
    assert marker.decode("ascii") not in str(caught.value)
    assert str(tmp_path) not in str(caught.value)

