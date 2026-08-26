"""Stage and verify the bounded AgentGuardian public-preview release."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Iterable

from scripts.verify_integrations_preview_profile import (
    ProfileViolation,
    _has_reparse_component,
    _is_reparse_point,
    canonical_json_bytes,
    load_profile_snapshot,
    verify_profile,
)


RELEASE_ASSET_NAMES = (
    "AgentGuardian-0.3.0-preview.1-windows-x64.zip",
    "AgentGuardian-Setup-0.3.0-preview.1-x64.exe",
    "AgentGuardian-Setup-Windows-x64.exe",
    "AgentGuardian-Skill-0.2.0.zip",
    "DOWNLOAD-METADATA.json",
    "LICENSE",
    "SHA256SUMS",
    "THIRD_PARTY_NOTICES.md",
)
PRIMARY_INSTALLER_NAME = "AgentGuardian-Setup-Windows-x64.exe"
VERSIONED_INSTALLER_NAME = "AgentGuardian-Setup-0.3.0-preview.1-x64.exe"
PORTABLE_NAME = "AgentGuardian-0.3.0-preview.1-windows-x64.zip"
SKILL_NAME = "AgentGuardian-Skill-0.2.0.zip"
MAX_INPUT_BYTES = 2 * 1024 * 1024 * 1024

_PROFILE_RELATIVE_PATH = "release_profiles/integrations_preview.json"
_METADATA_NAME = "DOWNLOAD-METADATA.json"
_CHECKSUMS_NAME = "SHA256SUMS"
_METADATA_FILE_NAMES = (
    PORTABLE_NAME,
    VERSIONED_INSTALLER_NAME,
    PRIMARY_INSTALLER_NAME,
    SKILL_NAME,
    "LICENSE",
    "THIRD_PARTY_NOTICES.md",
)
_CHECKSUM_FILE_NAMES = tuple(
    name for name in RELEASE_ASSET_NAMES if name != _CHECKSUMS_NAME
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_PRIVATE_PATTERNS = (
    re.compile(rb"\bsk[-_](?:proj|live|test)?[-_]?[A-Za-z0-9_-]{6,}\b", re.I),
    re.compile(rb"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b", re.I),
    re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{20,}\b", re.I),
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)
_PRIVATE_REMEDIATION = (
    "RELEASE_PRIVATE_DATA_DETECTED: remove credentials or private data from release inputs"
)


class ReleaseViolation(ValueError):
    """A fixed, non-sensitive release staging failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(_PRIVATE_REMEDIATION if code == "RELEASE_PRIVATE_DATA_DETECTED" else code)


def _fail(code: str) -> None:
    raise ReleaseViolation(code)


def _git_state(project_root: Path) -> tuple[str, str]:
    """Return HEAD and porcelain status; tests replace this small boundary."""
    try:
        head = subprocess.run(
            ["git", "-C", str(project_root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        status = subprocess.run(
            [
                "git",
                "-C",
                str(project_root),
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except (OSError, subprocess.SubprocessError, UnicodeError):
        _fail("RELEASE_SOURCE_STATE_INVALID")
    return head, status


def _require_source_state(project_root: Path, source_commit: str) -> None:
    if not isinstance(source_commit, str) or not _SOURCE_COMMIT.fullmatch(source_commit):
        _fail("RELEASE_SOURCE_STATE_INVALID")
    head, status = _git_state(project_root)
    if head != source_commit or status:
        _fail("RELEASE_SOURCE_STATE_INVALID")


def _require_built_at(value: str) -> None:
    if not isinstance(value, str) or len(value) != 20 or not value.endswith("Z"):
        _fail("RELEASE_MANIFEST_INVALID")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        _fail("RELEASE_MANIFEST_INVALID")
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        _fail("RELEASE_MANIFEST_INVALID")


def _path_has_reparse(path: Path) -> bool:
    try:
        return _has_reparse_component(path)
    except (ProfileViolation, OSError):
        _fail("RELEASE_INPUT_PATH_INVALID")
    return False


def _resolved_project_root(project_root: str | Path) -> Path:
    candidate = Path(project_root).absolute()
    if _path_has_reparse(candidate):
        _fail("RELEASE_SOURCE_STATE_INVALID")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        _fail("RELEASE_SOURCE_STATE_INVALID")
    if not resolved.is_dir():
        _fail("RELEASE_SOURCE_STATE_INVALID")
    return resolved


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _resolve_input(path_value: str | Path) -> Path:
    candidate = Path(path_value)
    if not candidate.is_absolute():
        _fail("RELEASE_INPUT_PATH_INVALID")
    candidate = candidate.absolute()
    try:
        if _has_reparse_component(candidate) or _is_reparse_point(candidate):
            _fail("RELEASE_INPUT_PATH_INVALID")
        resolved = candidate.resolve(strict=True)
        info = resolved.stat()
    except (FileNotFoundError, OSError, ProfileViolation):
        _fail("RELEASE_INPUT_PATH_INVALID")
    if not stat.S_ISREG(info.st_mode) or not resolved.is_file():
        _fail("RELEASE_INPUT_PATH_INVALID")
    if info.st_size > MAX_INPUT_BYTES:
        _fail("RELEASE_INPUT_PATH_INVALID")
    return resolved


def _resolve_project_file(root: Path, relative: str) -> Path:
    path = root / relative
    try:
        if _has_reparse_component(path) or _is_reparse_point(path):
            _fail("RELEASE_INPUT_PATH_INVALID")
        resolved = path.resolve(strict=True)
        info = resolved.stat()
    except (FileNotFoundError, OSError, ProfileViolation):
        _fail("RELEASE_INPUT_PATH_INVALID")
    if not _inside(resolved, root) or not stat.S_ISREG(info.st_mode):
        _fail("RELEASE_INPUT_PATH_INVALID")
    if info.st_size > MAX_INPUT_BYTES:
        _fail("RELEASE_INPUT_PATH_INVALID")
    return resolved


def _resolve_output(output_root: str | Path, project_root: Path, inputs: Iterable[Path]) -> Path:
    candidate = Path(output_root).absolute()
    if _path_has_reparse(candidate):
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    try:
        resolved = candidate.resolve(strict=False)
    except OSError:
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    if _inside(resolved, project_root):
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    if any(_inside(resolved, path.parent) for path in inputs):
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    if candidate.exists():
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    parent = resolved.parent
    try:
        if not parent.is_dir() or _has_reparse_component(parent):
            _fail("RELEASE_OUTPUT_PATH_INVALID")
    except (OSError, ProfileViolation):
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    return resolved


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            _fail("RELEASE_MANIFEST_INVALID")
        value[key] = item
    return value


def _reject_json_constant(_: str) -> None:
    _fail("RELEASE_MANIFEST_INVALID")


def _read_bounded(path: Path, limit: int, code: str) -> bytes:
    try:
        with path.open("rb") as stream:
            value = stream.read(limit + 1)
    except (OSError, MemoryError, OverflowError):
        _fail(code)
    if len(value) > limit:
        _fail(code)
    return value


def _contains_private_marker(path: Path, workflow_markers: Iterable[str]) -> bool:
    folded_path = str(path).casefold().encode("utf-8", "ignore")
    if any(marker.casefold().encode("ascii") in folded_path for marker in workflow_markers):
        return True
    if any(pattern.search(folded_path) for pattern in _PRIVATE_PATTERNS):
        return True
    try:
        with path.open("rb") as stream:
            carry = b""
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    return False
                data = carry + chunk
                folded = data.lower()
                if any(pattern.search(data) for pattern in _PRIVATE_PATTERNS):
                    return True
                if any(
                    marker.casefold().encode("ascii") in folded
                    for marker in workflow_markers
                ):
                    return True
                carry = data[-256:]
    except (OSError, MemoryError):
        _fail("RELEASE_INPUT_PATH_INVALID")
    return False


def _reject_private_data(paths: Iterable[Path], workflow_markers: Iterable[str]) -> None:
    markers = tuple(workflow_markers)
    for path in paths:
        if _contains_private_marker(path, markers):
            _fail("RELEASE_PRIVATE_DATA_DETECTED")


def _copy_and_digest(source: Path, target: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    try:
        with source.open("rb") as source_stream, target.open("wb") as target_stream:
            while True:
                chunk = source_stream.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_INPUT_BYTES:
                    _fail("RELEASE_INPUT_PATH_INVALID")
                digest.update(chunk)
                target_stream.write(chunk)
    except ReleaseViolation:
        raise
    except (OSError, MemoryError):
        _fail("RELEASE_INPUT_PATH_INVALID")
    return digest.hexdigest(), size


def _digest_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                digest.update(chunk)
    except (OSError, MemoryError):
        _fail("RELEASE_ASSET_DIGEST_MISMATCH")
    return digest.hexdigest(), size


def _verified_profile(project_root: Path):
    try:
        snapshot = load_profile_snapshot(
            project_root, project_root / _PROFILE_RELATIVE_PATH
        )
        verify_profile(project_root, snapshot)
    except ProfileViolation:
        _fail("RELEASE_MANIFEST_INVALID")
    return snapshot


def _metadata(
    profile: Any,
    source_commit: str,
    built_at: str,
    records: list[dict[str, object]],
) -> dict[str, object]:
    values = profile.profile
    return {
        "architecture": "x64",
        "artifact_status": "unsigned_public_preview",
        "channel": "integrations_preview",
        "files": records,
        "installer": {
            "primary_filename": PRIMARY_INSTALLER_NAME,
            "versioned_filename": VERSIONED_INSTALLER_NAME,
            "built_at": built_at,
        },
        "release": {
            "tag": values["release_tag"],
            "title": values["release_title"],
            "draft": values["release_draft"],
            "prerelease": values["release_prerelease"],
            "fixed_download_url": values["release_download_url"],
        },
        "schema": 1,
        "source_commit": source_commit,
        "supported_platform": "Windows 11 x64",
        "version": "0.3.0-preview.1",
    }


def _write_checksums(output_root: Path) -> None:
    lines = []
    for name in sorted(_CHECKSUM_FILE_NAMES):
        digest, _ = _digest_file(output_root / name)
        lines.append(f"{digest}  {name}")
    try:
        (output_root / _CHECKSUMS_NAME).write_text(
            "\n".join(lines) + "\n", encoding="ascii", newline="\n"
        )
    except (OSError, UnicodeError):
        _fail("RELEASE_MANIFEST_INVALID")


def stage_public_preview_release(
    project_root: str | Path,
    output_root: str | Path,
    *,
    installer_path: str | Path,
    portable_path: str | Path,
    skill_path: str | Path,
    source_commit: str,
    built_at: str,
) -> dict[str, object]:
    root = _resolved_project_root(project_root)
    _require_source_state(root, source_commit)
    _require_built_at(built_at)
    profile = _verified_profile(root)
    installer = _resolve_input(installer_path)
    portable = _resolve_input(portable_path)
    skill = _resolve_input(skill_path)
    license_path = _resolve_project_file(root, "LICENSE")
    notices_path = _resolve_project_file(root, "THIRD_PARTY_NOTICES.md")
    inputs = (installer, portable, skill, license_path, notices_path)
    _reject_private_data(inputs, profile.profile["forbidden_workflow_tokens"])
    output = _resolve_output(output_root, root, inputs)

    try:
        output.mkdir()
    except OSError:
        _fail("RELEASE_OUTPUT_PATH_INVALID")

    sources = (
        (portable, PORTABLE_NAME),
        (installer, VERSIONED_INSTALLER_NAME),
        (skill, SKILL_NAME),
        (license_path, "LICENSE"),
        (notices_path, "THIRD_PARTY_NOTICES.md"),
    )
    for source, name in sources:
        _copy_and_digest(source, output / name)
    _copy_and_digest(output / VERSIONED_INSTALLER_NAME, output / PRIMARY_INSTALLER_NAME)

    versioned_digest, versioned_size = _digest_file(output / VERSIONED_INSTALLER_NAME)
    primary_digest, primary_size = _digest_file(output / PRIMARY_INSTALLER_NAME)
    if (primary_digest, primary_size) != (versioned_digest, versioned_size):
        _fail("RELEASE_ASSET_DIGEST_MISMATCH")
    records = []
    for name in _METADATA_FILE_NAMES:
        digest, size = _digest_file(output / name)
        records.append({"name": name, "sha256": digest, "size": size})
    try:
        (output / _METADATA_NAME).write_bytes(
            canonical_json_bytes(_metadata(profile, source_commit, built_at, records))
        )
    except (OSError, MemoryError):
        _fail("RELEASE_MANIFEST_INVALID")
    _write_checksums(output)
    return {"status": "pass", "source_commit": source_commit, "files": list(RELEASE_ASSET_NAMES)}


def _load_metadata(output_root: Path) -> dict[str, object]:
    raw = _read_bounded(
        output_root / _METADATA_NAME, MAX_INPUT_BYTES, "RELEASE_MANIFEST_INVALID"
    )
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except ReleaseViolation:
        raise
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError, MemoryError):
        _fail("RELEASE_MANIFEST_INVALID")
    if not isinstance(value, dict) or raw != canonical_json_bytes(value):
        _fail("RELEASE_MANIFEST_INVALID")
    return value


def _validate_metadata(
    metadata: dict[str, object], profile: Any, source_commit: str
) -> list[dict[str, object]]:
    if set(metadata) != {
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
    }:
        _fail("RELEASE_MANIFEST_INVALID")
    if (
        type(metadata["architecture"]) is not str
        or metadata["architecture"] != "x64"
        or type(metadata["artifact_status"]) is not str
        or metadata["artifact_status"] != "unsigned_public_preview"
    ):
        _fail("RELEASE_MANIFEST_INVALID")
    if (
        type(metadata["channel"]) is not str
        or metadata["channel"] != "integrations_preview"
        or type(metadata["schema"]) is not int
        or metadata["schema"] != 1
    ):
        _fail("RELEASE_MANIFEST_INVALID")
    if (
        type(metadata["source_commit"]) is not str
        or metadata["source_commit"] != source_commit
        or type(metadata["supported_platform"]) is not str
        or metadata["supported_platform"] != "Windows 11 x64"
    ):
        _fail("RELEASE_MANIFEST_INVALID")
    if type(metadata["version"]) is not str or metadata["version"] != "0.3.0-preview.1":
        _fail("RELEASE_MANIFEST_INVALID")
    installer = metadata["installer"]
    if not isinstance(installer, dict) or set(installer) != {
        "primary_filename",
        "versioned_filename",
        "built_at",
    }:
        _fail("RELEASE_MANIFEST_INVALID")
    if installer["primary_filename"] != PRIMARY_INSTALLER_NAME or installer["versioned_filename"] != VERSIONED_INSTALLER_NAME:
        _fail("RELEASE_MANIFEST_INVALID")
    _require_built_at(installer["built_at"])
    release = metadata["release"]
    expected_release = profile.profile
    if not isinstance(release, dict) or set(release) != {
        "tag",
        "title",
        "draft",
        "prerelease",
        "fixed_download_url",
    }:
        _fail("RELEASE_MANIFEST_INVALID")
    if (
        type(release["tag"]) is not str
        or type(release["title"]) is not str
        or type(release["draft"]) is not bool
        or type(release["prerelease"]) is not bool
        or type(release["fixed_download_url"]) is not str
        or release != {
        "tag": expected_release["release_tag"],
        "title": expected_release["release_title"],
        "draft": expected_release["release_draft"],
        "prerelease": expected_release["release_prerelease"],
        "fixed_download_url": expected_release["release_download_url"],
        }
    ):
        _fail("RELEASE_MANIFEST_INVALID")
    records = metadata["files"]
    if not isinstance(records, list) or len(records) != 6:
        _fail("RELEASE_MANIFEST_INVALID")
    expected_names = set(_METADATA_FILE_NAMES)
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != {"name", "sha256", "size"}:
            _fail("RELEASE_MANIFEST_INVALID")
        name = record["name"]
        size = record["size"]
        if (
            not isinstance(name, str)
            or name not in expected_names
            or name in seen
            or not isinstance(record["sha256"], str)
            or not _SHA256.fullmatch(record["sha256"])
            or type(size) is not int
            or size < 0
        ):
            _fail("RELEASE_MANIFEST_INVALID")
        seen.add(name)
    if seen != expected_names:
        _fail("RELEASE_MANIFEST_INVALID")
    return records


def _verify_checksums(output_root: Path) -> None:
    raw = _read_bounded(
        output_root / _CHECKSUMS_NAME, MAX_INPUT_BYTES, "RELEASE_CHECKSUM_INVALID"
    )
    try:
        text = raw.decode("ascii")
    except UnicodeError:
        _fail("RELEASE_CHECKSUM_INVALID")
    if not raw.endswith(b"\n") or b"\r" in raw:
        _fail("RELEASE_CHECKSUM_INVALID")
    lines = text.splitlines()
    pattern = re.compile(r"^([0-9a-f]{64})  ([^\s]+)$")
    found: dict[str, str] = {}
    for line in lines:
        match = pattern.fullmatch(line)
        if match is None or match.group(2) in found:
            _fail("RELEASE_CHECKSUM_INVALID")
        found[match.group(2)] = match.group(1)
    if set(found) != set(_CHECKSUM_FILE_NAMES) or list(found) != sorted(found):
        _fail("RELEASE_CHECKSUM_INVALID")
    for name, expected in found.items():
        actual, _ = _digest_file(output_root / name)
        if actual != expected:
            _fail("RELEASE_CHECKSUM_INVALID")


def verify_staged_release(
    output_root: str | Path, project_root: str | Path, *, source_commit: str
) -> dict[str, object]:
    root = _resolved_project_root(project_root)
    _require_source_state(root, source_commit)
    profile = _verified_profile(root)
    candidate = Path(output_root).absolute()
    try:
        if _has_reparse_component(candidate):
            _fail("RELEASE_MANIFEST_INVALID")
        output = candidate.resolve(strict=True)
    except (OSError, ProfileViolation):
        _fail("RELEASE_MANIFEST_INVALID")
    if not output.is_dir() or _inside(output, root):
        _fail("RELEASE_MANIFEST_INVALID")
    try:
        entries = tuple(output.iterdir())
    except OSError:
        _fail("RELEASE_MANIFEST_INVALID")
    if any(_is_reparse_point(path) or not path.is_file() for path in entries):
        _fail("RELEASE_MANIFEST_INVALID")
    if tuple(sorted(path.name for path in entries)) != tuple(sorted(RELEASE_ASSET_NAMES)):
        _fail("RELEASE_MANIFEST_INVALID")
    _reject_private_data(entries, profile.profile["forbidden_workflow_tokens"])
    metadata = _load_metadata(output)
    records = _validate_metadata(metadata, profile, source_commit)
    for record in records:
        actual_digest, actual_size = _digest_file(output / record["name"])
        if actual_digest != record["sha256"] or actual_size != record["size"]:
            _fail("RELEASE_ASSET_DIGEST_MISMATCH")
    if _digest_file(output / PRIMARY_INSTALLER_NAME) != _digest_file(
        output / VERSIONED_INSTALLER_NAME
    ):
        _fail("RELEASE_ASSET_DIGEST_MISMATCH")
    _verify_checksums(output)
    return {"status": "pass", "source_commit": source_commit}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--built-at")
    parser.add_argument("--installer-path", type=Path)
    parser.add_argument("--portable-path", type=Path)
    parser.add_argument("--skill-path", type=Path)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.verify:
            result = verify_staged_release(
                args.output_root, args.project_root, source_commit=args.source_commit
            )
        else:
            if not all((args.installer_path, args.portable_path, args.skill_path, args.built_at)):
                _fail("RELEASE_MANIFEST_INVALID")
            result = stage_public_preview_release(
                args.project_root,
                args.output_root,
                installer_path=args.installer_path,
                portable_path=args.portable_path,
                skill_path=args.skill_path,
                source_commit=args.source_commit,
                built_at=args.built_at,
            )
    except ReleaseViolation as error:
        sys.stderr.buffer.write(canonical_json_bytes({"error": error.code, "status": "fail"}))
        return 1
    sys.stdout.buffer.write(canonical_json_bytes(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
