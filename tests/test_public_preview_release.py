from __future__ import annotations

import hashlib
import importlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

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


def test_direct_script_invocation_loads_project_modules() -> None:
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "stage_public_preview_release.py"), "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "ModuleNotFoundError" not in completed.stderr
    assert "usage:" in completed.stdout


@pytest.mark.parametrize(
    "arguments",
    (("--unknown",), ("--project-root", str(ROOT))),
)
def test_cli_argument_errors_use_fixed_json(
    arguments: tuple[str, ...],
) -> None:
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "stage_public_preview_release.py"), *arguments],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode != 0
    assert completed.stdout == ""
    assert completed.stderr == '{"error":"RELEASE_CLI_ARGUMENT_INVALID","status":"fail"}\n'
    assert "usage:" not in completed.stderr


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
    checksum_path.write_text(
        "0" * 64 + lines[0][64:] + "\n" + "\n".join(lines[1:]) + "\n",
        encoding="ascii",
    )
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


def _assert_no_release_or_staging_directories(tmp_path: Path, output: Path) -> None:
    assert not output.exists()
    assert not any(
        path.is_dir() and path.name != "inputs"
        for path in tmp_path.iterdir()
    )


@pytest.mark.parametrize("failure_point", ("copy", "checksums"))
def test_stage_cleans_failed_temporary_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    output = tmp_path / "release"
    if failure_point == "copy":
        monkeypatch.setattr(
            module,
            "_copy_and_digest",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                module.ReleaseViolation("RELEASE_INPUT_PATH_INVALID")
            ),
        )
    else:
        monkeypatch.setattr(
            module,
            "_write_checksums",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                module.ReleaseViolation("RELEASE_CHECKSUM_INVALID")
            ),
        )

    with pytest.raises(module.ReleaseViolation):
        module.stage_public_preview_release(
            ROOT,
            output,
            installer_path=installer,
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )
    _assert_no_release_or_staging_directories(tmp_path, output)


def test_stage_runs_final_verifier_before_publish_and_cleans_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    output = tmp_path / "release"
    calls: list[Path] = []

    def reject_verification(staged: Path, _root: Path, *, source_commit: str):
        calls.append(staged)
        raise module.ReleaseViolation("RELEASE_MANIFEST_INVALID")

    monkeypatch.setattr(module, "verify_staged_release", reject_verification)
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_MANIFEST_INVALID$"):
        module.stage_public_preview_release(
            ROOT,
            output,
            installer_path=installer,
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )
    assert len(calls) == 1
    assert calls[0] != output
    _assert_no_release_or_staging_directories(tmp_path, output)


def test_stage_rejects_target_competition_without_overwrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    output = tmp_path / "release"
    original_verify = module.verify_staged_release

    def compete(staged: Path, root: Path, *, source_commit: str):
        output.mkdir()
        (output / "competitor").write_text("keep", encoding="ascii")
        return original_verify(staged, root, source_commit=source_commit)

    monkeypatch.setattr(module, "verify_staged_release", compete)
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
    assert (output / "competitor").read_text(encoding="ascii") == "keep"
    assert not any(
        path.is_dir() and path.name.startswith(f".{output.name}.staging-")
        for path in tmp_path.iterdir()
    )


def test_stage_rejects_replaced_staging_directory_before_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    output = tmp_path / "release"
    original_publish = module._publish_staged_output
    replaced_path: list[Path] = []

    def replace_staging(staged: Path, target: Path, *args: object, **kwargs: object) -> None:
        staged.rename(tmp_path / "verified-staging")
        staged.mkdir()
        (staged / "unverified").write_text("unverified", encoding="ascii")
        replaced_path.append(staged)
        original_publish(staged, target, *args, **kwargs)

    monkeypatch.setattr(module, "_publish_staged_output", replace_staging)
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
    assert not output.exists()
    assert len(replaced_path) == 1
    assert (replaced_path[0] / "unverified").read_text(encoding="ascii") == "unverified"


def test_cleanup_does_not_remove_replaced_staging_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    output = tmp_path / "release"
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    (unrelated / "keep.txt").write_text("keep", encoding="ascii")
    replaced_path: list[Path] = []

    def replace_then_fail(staged: Path, *args: object, **kwargs: object) -> None:
        shutil.rmtree(staged)
        unrelated.rename(staged)
        replaced_path.append(staged)
        raise module.ReleaseViolation("RELEASE_CHECKSUM_INVALID")

    monkeypatch.setattr(module, "_write_checksums", replace_then_fail)
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_CHECKSUM_INVALID$"):
        module.stage_public_preview_release(
            ROOT,
            output,
            installer_path=installer,
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )
    assert not output.exists()
    assert len(replaced_path) == 1
    replaced_staging = replaced_path[0]
    assert replaced_staging.exists()
    assert (replaced_staging / "keep.txt").read_text(encoding="ascii") == "keep"


def test_stage_rejects_input_replaced_before_verified_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    output = tmp_path / "release"
    calls: list[Path] = []

    def reject_replaced(snapshot, *_args, **_kwargs):
        calls.append(snapshot.path)
        raise module.ReleaseViolation("RELEASE_INPUT_PATH_INVALID")

    monkeypatch.setattr(module, "_open_verified_file", reject_replaced, raising=False)
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_INPUT_PATH_INVALID$"):
        module.stage_public_preview_release(
            ROOT,
            output,
            installer_path=installer,
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )
    assert calls == [portable]
    _assert_no_release_or_staging_directories(tmp_path, output)


def test_verified_file_snapshot_rejects_replaced_input(
    tmp_path: Path,
) -> None:
    module = _module()
    installer, _, _ = _inputs(tmp_path)
    snapshot = module._resolve_input(installer)
    installer.write_bytes(b"replaced-input")
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_INPUT_PATH_INVALID$"):
        module._digest_file(
            snapshot,
            max_bytes=module.MAX_INPUT_BYTES,
            code="RELEASE_INPUT_PATH_INVALID",
        )


def test_verify_rejects_oversized_staged_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    _, output, _ = _stage(tmp_path, monkeypatch)
    monkeypatch.setattr(module, "MAX_INPUT_BYTES", 32)
    (output / module.PORTABLE_NAME).write_bytes(b"x" * 33)
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_ASSET_TOO_LARGE$"):
        module.verify_staged_release(output, ROOT, source_commit=COMMIT)


def test_verify_rejects_oversized_metadata_before_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    _, output, _ = _stage(tmp_path, monkeypatch)
    metadata_limit = 256 * 1024
    monkeypatch.setattr(module, "MAX_METADATA_BYTES", metadata_limit)
    (output / "DOWNLOAD-METADATA.json").write_bytes(b"{" + b"x" * metadata_limit)
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_MANIFEST_TOO_LARGE$"):
        module.verify_staged_release(output, ROOT, source_commit=COMMIT)


def test_verify_rejects_oversized_checksums_before_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    _, output, _ = _stage(tmp_path, monkeypatch)
    checksum_limit = 64 * 1024
    monkeypatch.setattr(module, "MAX_CHECKSUM_BYTES", checksum_limit)
    (output / "SHA256SUMS").write_bytes(b"x" * (checksum_limit + 1))
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_CHECKSUM_TOO_LARGE$"):
        module.verify_staged_release(output, ROOT, source_commit=COMMIT)


@pytest.mark.parametrize("separator", (b"\r\n", b"\v\n", b"\x1c\n", b"\n\n"))
def test_verify_rejects_non_lf_checksum_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, separator: bytes
) -> None:
    module = _module()
    _, output, _ = _stage(tmp_path, monkeypatch)
    checksum_path = output / "SHA256SUMS"
    raw = checksum_path.read_bytes()
    checksum_path.write_bytes(raw.replace(b"\n", separator, 1))
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_CHECKSUM_INVALID$"):
        module.verify_staged_release(output, ROOT, source_commit=COMMIT)


def test_stage_rejects_reparse_ancestor_when_supported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_git_state", lambda _root: (COMMIT, ""))
    installer, portable, skill = _inputs(tmp_path)
    linked_parent = tmp_path / "linked-parent"
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    try:
        linked_parent.symlink_to(real_parent, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(module.ReleaseViolation, match="^RELEASE_OUTPUT_PATH_INVALID$"):
        module.stage_public_preview_release(
            ROOT,
            linked_parent / "release",
            installer_path=installer,
            portable_path=portable,
            skill_path=skill,
            source_commit=COMMIT,
            built_at=BUILT_AT,
        )
