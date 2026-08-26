"""Stage and verify the bounded AgentGuardian public-preview release."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from typing import BinaryIO, Iterable, Iterator

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.verify_integrations_preview_profile import (
    ProfileSnapshot,
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
MAX_METADATA_BYTES = 256 * 1024
MAX_CHECKSUM_BYTES = 64 * 1024

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


class _ReleaseArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise ReleaseViolation("RELEASE_CLI_ARGUMENT_INVALID")


@dataclass(frozen=True)
class _FileSnapshot:
    path: Path
    identity: tuple[int, int, int, int]
    size: int


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


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _path_has_reparse(path: Path, code: str) -> bool:
    try:
        return _has_reparse_component(path)
    except (ProfileViolation, OSError):
        _fail(code)
    return False


def _resolved_project_root(project_root: str | Path) -> Path:
    candidate = Path(project_root).absolute()
    if _path_has_reparse(candidate, "RELEASE_SOURCE_STATE_INVALID"):
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


def _snapshot_file(path: Path, *, max_bytes: int, code: str) -> _FileSnapshot:
    try:
        if _has_reparse_component(path) or _is_reparse_point(path):
            _fail(code)
        resolved = path.resolve(strict=True)
        info = resolved.stat()
    except (FileNotFoundError, OSError, ProfileViolation):
        _fail(code)
    if not stat.S_ISREG(info.st_mode) or not resolved.is_file():
        _fail(code)
    if info.st_size > max_bytes:
        _fail(code)
    return _FileSnapshot(resolved, _file_identity(info), info.st_size)


def _resolve_input(path_value: str | Path) -> _FileSnapshot:
    candidate = Path(path_value)
    if not candidate.is_absolute():
        _fail("RELEASE_INPUT_PATH_INVALID")
    candidate = candidate.absolute()
    return _snapshot_file(
        candidate, max_bytes=MAX_INPUT_BYTES, code="RELEASE_INPUT_PATH_INVALID"
    )


def _resolve_project_file(root: Path, relative: str) -> _FileSnapshot:
    snapshot = _snapshot_file(
        root / relative,
        max_bytes=MAX_INPUT_BYTES,
        code="RELEASE_INPUT_PATH_INVALID",
    )
    if not _inside(snapshot.path, root):
        _fail("RELEASE_INPUT_PATH_INVALID")
    return snapshot


def _resolve_output(
    output_root: str | Path,
    project_root: Path,
    inputs: Iterable[_FileSnapshot],
) -> Path:
    candidate = Path(output_root).absolute()
    if _path_has_reparse(candidate, "RELEASE_OUTPUT_PATH_INVALID"):
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    try:
        resolved = candidate.resolve(strict=False)
    except OSError:
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    if _inside(resolved, project_root):
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    if any(_inside(resolved, snapshot.path.parent) for snapshot in inputs):
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


@contextmanager
def _open_verified_file(
    snapshot: _FileSnapshot, *, max_bytes: int, code: str
) -> Iterator[BinaryIO]:
    """Open one expected file and verify its path and handle identity."""
    if snapshot.size > max_bytes:
        _fail(code)
    stream: BinaryIO | None = None
    file_descriptor: int | None = None
    try:
        if _has_reparse_component(snapshot.path) or _is_reparse_point(snapshot.path):
            _fail(code)
        if _file_identity(snapshot.path.stat()) != snapshot.identity:
            _fail(code)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        file_descriptor = os.open(snapshot.path, flags)
        stream = os.fdopen(file_descriptor, "rb", closefd=True)
        file_descriptor = None
        if _file_identity(os.fstat(stream.fileno())) != snapshot.identity:
            _fail(code)
        yield stream
        if _file_identity(os.fstat(stream.fileno())) != snapshot.identity:
            _fail(code)
        if _has_reparse_component(snapshot.path) or _is_reparse_point(snapshot.path):
            _fail(code)
        if _file_identity(snapshot.path.stat()) != snapshot.identity:
            _fail(code)
    except ReleaseViolation:
        raise
    except (FileNotFoundError, OSError, ValueError):
        _fail(code)
    finally:
        if stream is not None:
            stream.close()
        elif file_descriptor is not None:
            os.close(file_descriptor)


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
    snapshot = _snapshot_file(path, max_bytes=limit, code=code)
    try:
        with _open_verified_file(snapshot, max_bytes=limit, code=code) as stream:
            value = stream.read(limit + 1)
    except (MemoryError, OverflowError):
        _fail(code)
    if len(value) > limit:
        _fail(code)
    return value


def _path_has_private_marker(path: Path, workflow_markers: Iterable[str]) -> bool:
    folded_path = str(path).casefold().encode("utf-8", "ignore")
    if any(marker.casefold().encode("ascii") in folded_path for marker in workflow_markers):
        return True
    if any(pattern.search(folded_path) for pattern in _PRIVATE_PATTERNS):
        return True
    return False


def _stream_has_private_marker(
    stream: BinaryIO, workflow_markers: Iterable[str]
) -> bool:
    markers = tuple(marker.casefold().encode("ascii") for marker in workflow_markers)
    carry = b""
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            return False
        data = carry + chunk
        folded = data.lower()
        if any(pattern.search(data) for pattern in _PRIVATE_PATTERNS):
            return True
        if any(marker in folded for marker in markers):
            return True
        carry = data[-256:]


def _reject_private_data(
    snapshots: Iterable[_FileSnapshot],
    workflow_markers: Iterable[str],
    *,
    max_bytes: int,
    code: str,
) -> None:
    markers = tuple(workflow_markers)
    for snapshot in snapshots:
        if _path_has_private_marker(snapshot.path, markers):
            _fail("RELEASE_PRIVATE_DATA_DETECTED")
        try:
            with _open_verified_file(snapshot, max_bytes=max_bytes, code=code) as stream:
                if _stream_has_private_marker(stream, markers):
                    _fail("RELEASE_PRIVATE_DATA_DETECTED")
        except MemoryError:
            _fail(code)


def _copy_and_digest(
    source: _FileSnapshot | Path,
    target: Path,
    workflow_markers: Iterable[str] = (),
) -> tuple[str, int]:
    snapshot = (
        source
        if isinstance(source, _FileSnapshot)
        else _snapshot_file(
            source,
            max_bytes=MAX_INPUT_BYTES,
            code="RELEASE_ASSET_DIGEST_MISMATCH",
        )
    )
    digest = hashlib.sha256()
    size = 0
    try:
        with _open_verified_file(
            snapshot,
            max_bytes=MAX_INPUT_BYTES,
            code="RELEASE_INPUT_PATH_INVALID",
        ) as source_stream, target.open("wb") as target_stream:
            carry = b""
            while True:
                chunk = source_stream.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_INPUT_BYTES:
                    _fail("RELEASE_INPUT_PATH_INVALID")
                data = carry + chunk
                if any(pattern.search(data) for pattern in _PRIVATE_PATTERNS) or any(
                    marker.casefold().encode("ascii") in data.lower()
                    for marker in workflow_markers
                ):
                    _fail("RELEASE_PRIVATE_DATA_DETECTED")
                carry = data[-256:]
                digest.update(chunk)
                target_stream.write(chunk)
    except ReleaseViolation:
        raise
    except (OSError, MemoryError):
        _fail("RELEASE_INPUT_PATH_INVALID")
    return digest.hexdigest(), size


def _digest_file(
    path: Path | _FileSnapshot,
    *,
    max_bytes: int = MAX_INPUT_BYTES,
    code: str = "RELEASE_ASSET_DIGEST_MISMATCH",
) -> tuple[str, int]:
    snapshot = (
        path
        if isinstance(path, _FileSnapshot)
        else _snapshot_file(path, max_bytes=max_bytes, code=code)
    )
    digest = hashlib.sha256()
    size = 0
    try:
        with _open_verified_file(snapshot, max_bytes=max_bytes, code=code) as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                digest.update(chunk)
    except MemoryError:
        _fail(code)
    return digest.hexdigest(), size


def _verified_profile(project_root: Path) -> ProfileSnapshot:
    try:
        snapshot = load_profile_snapshot(
            project_root, project_root / _PROFILE_RELATIVE_PATH
        )
        verify_profile(project_root, snapshot)
    except ProfileViolation:
        _fail("RELEASE_MANIFEST_INVALID")
    return snapshot


def _release_contract(profile: ProfileSnapshot) -> dict[str, object]:
    values = profile.profile
    expected_skill_name = f"AgentGuardian-Skill-{values['skill_version']}.zip"
    expected_assets = (
        values["portable_filename"],
        values["installer_filename"],
        values["primary_download_filename"],
        expected_skill_name,
        _METADATA_NAME,
        "LICENSE",
        _CHECKSUMS_NAME,
        "THIRD_PARTY_NOTICES.md",
    )
    if (
        tuple(values["release_assets"]) != RELEASE_ASSET_NAMES
        or values["primary_download_filename"] != PRIMARY_INSTALLER_NAME
        or values["installer_filename"] != VERSIONED_INSTALLER_NAME
        or values["portable_filename"] != PORTABLE_NAME
        or expected_skill_name != SKILL_NAME
        or expected_assets != RELEASE_ASSET_NAMES
        or values["product_version"] != "0.3.0-preview.1"
    ):
        _fail("RELEASE_MANIFEST_INVALID")
    return {
        "architecture": values["architecture"],
        "artifact_status": values["release_artifact_status"],
        "channel": values["channel"],
        "primary_filename": values["primary_download_filename"],
        "versioned_filename": values["installer_filename"],
        "portable_filename": values["portable_filename"],
        "skill_filename": expected_skill_name,
        "version": values["product_version"],
        "release_tag": values["release_tag"],
        "release_title": values["release_title"],
        "release_draft": values["release_draft"],
        "release_prerelease": values["release_prerelease"],
        "release_download_url": values["release_download_url"],
    }


def _metadata(
    contract: dict[str, object],
    source_commit: str,
    built_at: str,
    records: list[dict[str, object]],
) -> dict[str, object]:
    return {
        "architecture": contract["architecture"],
        "artifact_status": contract["artifact_status"],
        "channel": contract["channel"],
        "files": records,
        "installer": {
            "primary_filename": contract["primary_filename"],
            "versioned_filename": contract["versioned_filename"],
            "built_at": built_at,
        },
        "release": {
            "tag": contract["release_tag"],
            "title": contract["release_title"],
            "draft": contract["release_draft"],
            "prerelease": contract["release_prerelease"],
            "fixed_download_url": contract["release_download_url"],
        },
        "schema": 1,
        "source_commit": source_commit,
        "supported_platform": "Windows 11 x64",
        "version": contract["version"],
    }


def _write_checksums(output_root: Path) -> None:
    lines: list[str] = []
    for name in sorted(_CHECKSUM_FILE_NAMES):
        digest, _ = _digest_file(output_root / name)
        lines.append(f"{digest}  {name}")
    try:
        (output_root / _CHECKSUMS_NAME).write_text(
            "\n".join(lines) + "\n", encoding="ascii", newline="\n"
        )
    except (OSError, UnicodeError):
        _fail("RELEASE_MANIFEST_INVALID")


def _cleanup_temporary_output(path: Path | None) -> None:
    if path is None:
        return
    try:
        if path.exists():
            shutil.rmtree(path)
    except OSError:
        pass


def _publish_staged_output(staged: Path, output: Path) -> None:
    if output.exists():
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    try:
        if os.name == "nt":
            os.rename(staged, output)
            return
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            _fail("RELEASE_OUTPUT_PATH_INVALID")
        result = renameat2(
            -100,
            os.fsencode(staged),
            -100,
            os.fsencode(output),
            1,
        )
        if result != 0:
            _fail("RELEASE_OUTPUT_PATH_INVALID")
    except FileExistsError:
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    except (OSError, TypeError):
        _fail("RELEASE_OUTPUT_PATH_INVALID")


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
    contract = _release_contract(profile)
    installer = _resolve_input(installer_path)
    portable = _resolve_input(portable_path)
    skill = _resolve_input(skill_path)
    license_path = _resolve_project_file(root, "LICENSE")
    notices_path = _resolve_project_file(root, "THIRD_PARTY_NOTICES.md")
    inputs = (installer, portable, skill, license_path, notices_path)
    workflow_markers = profile.profile["forbidden_workflow_tokens"]
    if any(_path_has_private_marker(snapshot.path, workflow_markers) for snapshot in inputs):
        _fail("RELEASE_PRIVATE_DATA_DETECTED")
    output = _resolve_output(output_root, root, inputs)

    temporary: Path | None = None
    try:
        try:
            temporary = Path(
                tempfile.mkdtemp(prefix=f".{output.name}.staging-", dir=output.parent)
            )
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
            _copy_and_digest(source, temporary / name, workflow_markers)
        _copy_and_digest(
            temporary / VERSIONED_INSTALLER_NAME,
            temporary / PRIMARY_INSTALLER_NAME,
        )

        versioned_digest, versioned_size = _digest_file(
            temporary / VERSIONED_INSTALLER_NAME
        )
        primary_digest, primary_size = _digest_file(
            temporary / PRIMARY_INSTALLER_NAME
        )
        if (primary_digest, primary_size) != (versioned_digest, versioned_size):
            _fail("RELEASE_ASSET_DIGEST_MISMATCH")
        records: list[dict[str, object]] = []
        metadata_names = (
            contract["portable_filename"],
            contract["versioned_filename"],
            contract["primary_filename"],
            contract["skill_filename"],
            "LICENSE",
            "THIRD_PARTY_NOTICES.md",
        )
        for name in metadata_names:
            digest, size = _digest_file(temporary / str(name))
            records.append({"name": name, "sha256": digest, "size": size})
        try:
            (temporary / _METADATA_NAME).write_bytes(
                canonical_json_bytes(
                    _metadata(contract, source_commit, built_at, records)
                )
            )
        except (OSError, MemoryError):
            _fail("RELEASE_MANIFEST_INVALID")
        _write_checksums(temporary)
        result = verify_staged_release(
            temporary, root, source_commit=source_commit
        )
        _publish_staged_output(temporary, output)
        temporary = None
        return result
    finally:
        _cleanup_temporary_output(temporary)


def _load_metadata(output_root: Path) -> dict[str, object]:
    raw = _read_bounded(
        output_root / _METADATA_NAME,
        MAX_METADATA_BYTES,
        "RELEASE_MANIFEST_TOO_LARGE",
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
    metadata: dict[str, object], contract: dict[str, object], source_commit: str
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
    if metadata["architecture"] != contract["architecture"] or type(
        metadata["architecture"]
    ) is not str:
        _fail("RELEASE_MANIFEST_INVALID")
    if metadata["artifact_status"] != contract["artifact_status"] or type(
        metadata["artifact_status"]
    ) is not str:
        _fail("RELEASE_MANIFEST_INVALID")
    if (
        type(metadata["channel"]) is not str
        or metadata["channel"] != contract["channel"]
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
    if type(metadata["version"]) is not str or metadata["version"] != contract["version"]:
        _fail("RELEASE_MANIFEST_INVALID")
    installer = metadata["installer"]
    if not isinstance(installer, dict) or set(installer) != {
        "primary_filename",
        "versioned_filename",
        "built_at",
    }:
        _fail("RELEASE_MANIFEST_INVALID")
    if (
        type(installer["primary_filename"]) is not str
        or type(installer["versioned_filename"]) is not str
        or installer["primary_filename"] != contract["primary_filename"]
        or installer["versioned_filename"] != contract["versioned_filename"]
    ):
        _fail("RELEASE_MANIFEST_INVALID")
    _require_built_at(installer["built_at"])
    release = metadata["release"]
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
        "tag": contract["release_tag"],
        "title": contract["release_title"],
        "draft": contract["release_draft"],
        "prerelease": contract["release_prerelease"],
        "fixed_download_url": contract["release_download_url"],
        }
    ):
        _fail("RELEASE_MANIFEST_INVALID")
    records = metadata["files"]
    if not isinstance(records, list) or len(records) != 6:
        _fail("RELEASE_MANIFEST_INVALID")
    expected_names = {
        contract["portable_filename"],
        contract["versioned_filename"],
        contract["primary_filename"],
        contract["skill_filename"],
        "LICENSE",
        "THIRD_PARTY_NOTICES.md",
    }
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
        output_root / _CHECKSUMS_NAME,
        MAX_CHECKSUM_BYTES,
        "RELEASE_CHECKSUM_TOO_LARGE",
    )
    try:
        text = raw.decode("ascii")
    except UnicodeError:
        _fail("RELEASE_CHECKSUM_INVALID")
    if not raw.endswith(b"\n") or any(
        separator in raw for separator in (b"\r", b"\v", b"\f", b"\x1c", b"\x1d", b"\x1e")
    ):
        _fail("RELEASE_CHECKSUM_INVALID")
    lines = text[:-1].split("\n")
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
        max_bytes = (
            MAX_METADATA_BYTES if name == _METADATA_NAME else MAX_INPUT_BYTES
        )
        code = (
            "RELEASE_MANIFEST_TOO_LARGE"
            if name == _METADATA_NAME
            else "RELEASE_ASSET_TOO_LARGE"
        )
        actual, _ = _digest_file(
            output_root / name, max_bytes=max_bytes, code=code
        )
        if actual != expected:
            _fail("RELEASE_CHECKSUM_INVALID")


def verify_staged_release(
    output_root: str | Path, project_root: str | Path, *, source_commit: str
) -> dict[str, object]:
    root = _resolved_project_root(project_root)
    _require_source_state(root, source_commit)
    profile = _verified_profile(root)
    contract = _release_contract(profile)
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
    snapshots: dict[str, _FileSnapshot] = {}
    for path in entries:
        if path.name == _METADATA_NAME:
            snapshot = _snapshot_file(
                path,
                max_bytes=MAX_METADATA_BYTES,
                code="RELEASE_MANIFEST_TOO_LARGE",
            )
        elif path.name == _CHECKSUMS_NAME:
            snapshot = _snapshot_file(
                path,
                max_bytes=MAX_CHECKSUM_BYTES,
                code="RELEASE_CHECKSUM_TOO_LARGE",
            )
        else:
            snapshot = _snapshot_file(
                path,
                max_bytes=MAX_INPUT_BYTES,
                code="RELEASE_ASSET_TOO_LARGE",
            )
        snapshots[path.name] = snapshot
    markers = profile.profile["forbidden_workflow_tokens"]
    for name, snapshot in snapshots.items():
        if name == _METADATA_NAME:
            limit, code = MAX_METADATA_BYTES, "RELEASE_MANIFEST_TOO_LARGE"
        elif name == _CHECKSUMS_NAME:
            limit, code = MAX_CHECKSUM_BYTES, "RELEASE_CHECKSUM_TOO_LARGE"
        else:
            limit, code = MAX_INPUT_BYTES, "RELEASE_ASSET_TOO_LARGE"
        _reject_private_data((snapshot,), markers, max_bytes=limit, code=code)
    metadata = _load_metadata(output)
    records = _validate_metadata(metadata, contract, source_commit)
    for record in records:
        actual_digest, actual_size = _digest_file(
            snapshots[record["name"]],
            max_bytes=MAX_INPUT_BYTES,
            code="RELEASE_ASSET_TOO_LARGE",
        )
        if actual_digest != record["sha256"] or actual_size != record["size"]:
            _fail("RELEASE_ASSET_DIGEST_MISMATCH")
    if _digest_file(
        snapshots[PRIMARY_INSTALLER_NAME],
        max_bytes=MAX_INPUT_BYTES,
        code="RELEASE_ASSET_TOO_LARGE",
    ) != _digest_file(
        snapshots[VERSIONED_INSTALLER_NAME],
        max_bytes=MAX_INPUT_BYTES,
        code="RELEASE_ASSET_TOO_LARGE",
    ):
        _fail("RELEASE_ASSET_DIGEST_MISMATCH")
    _verify_checksums(output)
    return {"status": "pass", "source_commit": source_commit}


def main(argv: list[str] | None = None) -> int:
    parser = _ReleaseArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--built-at")
    parser.add_argument("--installer-path", type=Path)
    parser.add_argument("--portable-path", type=Path)
    parser.add_argument("--skill-path", type=Path)
    parser.add_argument("--verify", action="store_true")
    try:
        args = parser.parse_args(argv)
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
