"""Bounded evidence assembly and verification for private-beta installers."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.build_windows_portable import canonical_json_bytes, validate_build_time
from scripts.verify_personal_release_profile import (
    ProfileSnapshot,
    ProfileViolation,
    load_profile_snapshot,
)


MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_METADATA_BYTES = 256 * 1024
MAX_SBOM_BYTES = 1024 * 1024
MAX_PAYLOAD_MANIFEST_BYTES = 8 * 1024 * 1024
_CHUNK_SIZE = 1024 * 1024
_SCHEMA = 1
_PORTABLE_KEYS = {
    "artifact_status",
    "build_dependencies",
    "build_mode",
    "built_at",
    "source_commit",
}
_METADATA_KEYS = {
    "architecture",
    "artifact_status",
    "build_dependencies",
    "built_at",
    "channel",
    "compiler_asset",
    "compiler_sha256",
    "compiler_version",
    "installer_filename",
    "installer_sha256",
    "payload_manifest_sha256",
    "portable_artifact_status",
    "portable_build_metadata_sha256",
    "portable_build_mode",
    "portable_built_at",
    "portable_source_commit",
    "product_version",
    "profile_sha256",
    "schema",
    "source_commit",
    "windows_file_version",
}
_README = (
    "AgentGuardian private beta is unsupported for unsupported or high-sensitivity data.\n"
    "Unsigned installer and Microsoft SmartScreen warnings are expected.\n"
    "Use manual installation and upgrade only; verify SHA256SUMS before running Setup.\n"
    "Uninstall offers a protected-state choice; user reports are preserved.\n"
    "Support and issue reports: https://github.com/yangjing6213-dev/AgentGuardian/issues\n"
    "Private Vulnerability Reporting is currently disabled.\n"
).encode("ascii")


class CandidateEvidenceError(ValueError):
    """Raised with a stable public candidate-evidence error code."""


def verify_candidate(
    evidence_root: str | Path,
    expected_commit: str,
    profile_snapshot: ProfileSnapshot,
    *,
    expected_portable_metadata: dict[str, Any] | None = None,
) -> dict[str, str]:
    """Verify the complete private-beta evidence binding without local disclosure."""
    profile = _profile(profile_snapshot)
    if not _lower_hex(expected_commit, 40):
        raise CandidateEvidenceError("CANDIDATE_EXPECTED_COMMIT_INVALID")
    root = _existing_directory(evidence_root, "CANDIDATE_ROOT_INVALID")
    files = _files(root)
    expected_files = {
        profile["installer_filename"],
        "SHA256SUMS",
        "BUILD-METADATA.json",
        "PAYLOAD-MANIFEST.json",
        "AgentGuardian.cdx.json",
        "THIRD_PARTY_NOTICES.md",
        "PRIVATE-BETA-README.txt",
        "PRIVATE-BETA-MANIFEST.json",
    }
    if set(files) != expected_files:
        raise CandidateEvidenceError("CANDIDATE_FILE_SET_INVALID")
    metadata_raw, metadata = _json(root / "BUILD-METADATA.json")
    _, manifest = _json(root / "PRIVATE-BETA-MANIFEST.json")
    _metadata(metadata, expected_commit, profile_snapshot, profile, expected_portable_metadata)
    _payload_manifest(root)
    _sbom(root / "AgentGuardian.cdx.json")
    if _read(root / "PRIVATE-BETA-README.txt") != _README:
        raise CandidateEvidenceError("CANDIDATE_README_INVALID")
    if _sha256(root / "PAYLOAD-MANIFEST.json") != metadata["payload_manifest_sha256"]:
        raise CandidateEvidenceError("CANDIDATE_PAYLOAD_DIGEST_MISMATCH")
    if _size(root / profile["installer_filename"]) <= 0:
        raise CandidateEvidenceError("CANDIDATE_INSTALLER_INVALID")
    if _sha256(root / profile["installer_filename"]) != metadata["installer_sha256"]:
        raise CandidateEvidenceError("CANDIDATE_INSTALLER_DIGEST_MISMATCH")
    _manifest(manifest, metadata_raw, metadata)
    _checksums(root, files)
    return {"channel": profile["channel"], "status": "pass"}


def _write_candidate_evidence(
    evidence_root: str | Path,
    installer: str | Path,
    portable_bundle: str | Path,
    *,
    source_commit: str,
    built_at: str,
    profile_snapshot: ProfileSnapshot,
    portable_raw: bytes,
    portable_metadata: dict[str, Any],
) -> Path:
    """Assemble evidence into a verified sibling partial directory, then rename."""
    profile = _profile(profile_snapshot)
    if not _lower_hex(source_commit, 40):
        raise CandidateEvidenceError("CANDIDATE_EXPECTED_COMMIT_INVALID")
    _build_time(built_at)
    destination = _new_destination(evidence_root)
    executable = _existing_file(installer, "CANDIDATE_INSTALLER_INVALID")
    portable = _existing_directory(portable_bundle, "CANDIDATE_PAYLOAD_INVALID")
    partial = destination.with_name(destination.name + ".partial")
    if (
        partial.exists()
        or _is_reparse_point(partial)
        or _has_reparse_component(partial.parent)
        or _paths_overlap(destination, portable)
        or _paths_overlap(partial, portable)
        or _paths_overlap(destination, executable)
        or _paths_overlap(partial, executable)
    ):
        raise CandidateEvidenceError("CANDIDATE_OUTPUT_INVALID")
    if (
        not _portable_metadata_value(portable_metadata)
        or portable_raw != canonical_json_bytes(portable_metadata)
        or _read(portable / "BUILD-METADATA.json", MAX_METADATA_BYTES, "CANDIDATE_PORTABLE_METADATA_MISMATCH") != portable_raw
        or portable_metadata["source_commit"] != source_commit
        or portable_metadata["built_at"] != built_at
    ):
        raise CandidateEvidenceError("CANDIDATE_PORTABLE_METADATA_MISMATCH")
    partial_created = False
    try:
        partial.mkdir()
        partial_created = True
        shutil.copyfile(executable, partial / profile["installer_filename"])
        for name in ("PAYLOAD-MANIFEST.json", "AgentGuardian.cdx.json", "THIRD_PARTY_NOTICES.md"):
            source = portable / name
            if not source.is_file() or _has_reparse_component(source):
                raise CandidateEvidenceError("CANDIDATE_PAYLOAD_INVALID")
            shutil.copyfile(source, partial / name)
        (partial / "PRIVATE-BETA-README.txt").write_bytes(_README)
        metadata = _candidate_metadata(
            partial,
            profile,
            profile_snapshot,
            source_commit,
            built_at,
            portable_raw,
            portable_metadata,
        )
        metadata_raw = canonical_json_bytes(metadata)
        (partial / "BUILD-METADATA.json").write_bytes(metadata_raw)
        manifest = {**metadata, "build_metadata_sha256": hashlib.sha256(metadata_raw).hexdigest()}
        (partial / "PRIVATE-BETA-MANIFEST.json").write_bytes(canonical_json_bytes(manifest))
        files = _files(partial)
        (partial / "SHA256SUMS").write_bytes(_checksum_bytes(files))
        verify_candidate(
            partial,
            source_commit,
            profile_snapshot,
            expected_portable_metadata=portable_metadata,
        )
        os.replace(partial, destination)
    except CandidateEvidenceError:
        if partial_created:
            _remove_partial(partial)
        raise
    except (OSError, MemoryError, OverflowError):
        if partial_created:
            _remove_partial(partial)
        raise CandidateEvidenceError("CANDIDATE_OUTPUT_INVALID") from None
    return destination


def _candidate_metadata(
    root: Path,
    profile: dict[str, Any],
    snapshot: ProfileSnapshot,
    source_commit: str,
    built_at: str,
    portable_raw: bytes,
    portable: dict[str, Any],
) -> dict[str, Any]:
    return {
        "architecture": profile["architecture"],
        "artifact_status": "unsigned_private_beta",
        "build_dependencies": portable["build_dependencies"],
        "built_at": built_at,
        "channel": profile["channel"],
        "compiler_asset": profile["inno_setup_asset"],
        "compiler_sha256": profile["inno_setup_sha256"],
        "compiler_version": profile["inno_setup_version"],
        "installer_filename": profile["installer_filename"],
        "installer_sha256": _sha256(root / profile["installer_filename"]),
        "payload_manifest_sha256": _sha256(root / "PAYLOAD-MANIFEST.json"),
        "portable_artifact_status": portable["artifact_status"],
        "portable_build_metadata_sha256": hashlib.sha256(portable_raw).hexdigest(),
        "portable_build_mode": portable["build_mode"],
        "portable_built_at": portable["built_at"],
        "portable_source_commit": portable["source_commit"],
        "product_version": profile["product_version"],
        "profile_sha256": snapshot.sha256,
        "schema": _SCHEMA,
        "source_commit": source_commit,
        "windows_file_version": profile["windows_file_version"],
    }


def _profile(snapshot: ProfileSnapshot) -> dict[str, Any]:
    if not isinstance(snapshot, ProfileSnapshot):
        raise CandidateEvidenceError("CANDIDATE_PROFILE_INVALID")
    profile = snapshot.profile
    required = {
        "architecture", "channel", "inno_setup_asset", "inno_setup_sha256",
        "inno_setup_version", "installer_filename", "name", "product_version",
        "windows_file_version",
    }
    if (
        not required.issubset(profile)
        or profile.get("name") != "personal_exe_private_beta"
        or profile.get("channel") != "personal_exe_private_beta"
        or profile.get("architecture") != "x64"
        or not _lower_hex(profile.get("inno_setup_sha256"), 64)
        or not _version(profile.get("inno_setup_version"))
        or not _version(profile.get("product_version"))
        or not _version(profile.get("windows_file_version"))
        or not _safe_filename(profile.get("installer_filename"))
        or not str(profile["installer_filename"]).endswith(".exe")
        or not _safe_filename(profile.get("inno_setup_asset"))
        or not _lower_hex(snapshot.sha256, 64)
    ):
        raise CandidateEvidenceError("CANDIDATE_PROFILE_INVALID")
    return profile


def _portable_metadata(root: Path) -> tuple[bytes, dict[str, Any]]:
    raw, value = _json(root / "BUILD-METADATA.json")
    if not _portable_metadata_value(value):
        raise CandidateEvidenceError("CANDIDATE_PORTABLE_METADATA_MISMATCH")
    return raw, value


def _portable_metadata_value(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    try:
        _build_time(value.get("built_at"))
    except CandidateEvidenceError:
        return False
    return (
        set(value) == _PORTABLE_KEYS
        and value.get("artifact_status") == "unsigned_development_only"
        and value.get("build_mode") == "pyinstaller_onedir"
        and _valid_dependency_snapshot(value.get("build_dependencies"))
        and _lower_hex(value.get("source_commit"), 40)
    )


def _payload_manifest(root: Path) -> None:
    try:
        _, value = _json(root / "PAYLOAD-MANIFEST.json", MAX_PAYLOAD_MANIFEST_BYTES)
    except CandidateEvidenceError:
        raise CandidateEvidenceError("CANDIDATE_PAYLOAD_MANIFEST_INVALID") from None
    if (
        set(value) != {"algorithm", "files", "schema"}
        or value.get("algorithm") != "sha256"
        or value.get("schema") != 1
        or not isinstance(value.get("files"), list)
        or len(value["files"]) > 20_000
    ):
        raise CandidateEvidenceError("CANDIDATE_PAYLOAD_MANIFEST_INVALID")
    entries = value["files"]
    paths: list[str] = []
    for entry in entries:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"path", "sha256", "size"}
            or not _safe_payload_path(entry.get("path"))
            or not _lower_hex(entry.get("sha256"), 64)
            or type(entry.get("size")) is not int
            or entry["size"] < 0
            or entry["size"] > MAX_ARTIFACT_BYTES
        ):
            raise CandidateEvidenceError("CANDIDATE_PAYLOAD_MANIFEST_INVALID")
        paths.append(entry["path"])
    if paths != sorted(paths) or len({path.casefold() for path in paths}) != len(paths):
        raise CandidateEvidenceError("CANDIDATE_PAYLOAD_MANIFEST_INVALID")
    declared = {entry["path"]: entry for entry in entries}
    for name in ("AgentGuardian.cdx.json", "THIRD_PARTY_NOTICES.md"):
        entry = declared.get(name)
        path = root / name
        if entry is None or _size(path) != entry["size"] or _sha256(path) != entry["sha256"]:
            raise CandidateEvidenceError("CANDIDATE_PAYLOAD_ENTRY_MISMATCH")


def _sbom(path: Path) -> None:
    try:
        _, value = _json(path, MAX_SBOM_BYTES)
    except CandidateEvidenceError:
        raise CandidateEvidenceError("CANDIDATE_SBOM_INVALID") from None
    if value.get("bomFormat") != "CycloneDX":
        raise CandidateEvidenceError("CANDIDATE_SBOM_INVALID")


def _metadata(
    value: dict[str, Any],
    expected_commit: str,
    snapshot: ProfileSnapshot,
    profile: dict[str, Any],
    expected_portable_metadata: dict[str, Any] | None,
) -> None:
    if (
        set(value) != _METADATA_KEYS
        or value.get("schema") != _SCHEMA
        or value.get("artifact_status") != "unsigned_private_beta"
    ):
        raise CandidateEvidenceError("CANDIDATE_METADATA_INVALID")
    if value.get("source_commit") != expected_commit:
        raise CandidateEvidenceError("CANDIDATE_SOURCE_COMMIT_MISMATCH")
    if (
        value.get("portable_source_commit") != expected_commit
        or value.get("portable_built_at") != value.get("built_at")
        or value.get("portable_artifact_status") != "unsigned_development_only"
        or value.get("portable_build_mode") != "pyinstaller_onedir"
        or not _valid_dependency_snapshot(value.get("build_dependencies"))
    ):
        raise CandidateEvidenceError("CANDIDATE_PORTABLE_METADATA_MISMATCH")
    expected_portable = {
        "artifact_status": value["portable_artifact_status"],
        "build_dependencies": value["build_dependencies"],
        "build_mode": value["portable_build_mode"],
        "built_at": value["portable_built_at"],
        "source_commit": value["portable_source_commit"],
    }
    if (
        expected_portable_metadata is not None
        and (
            not _portable_metadata_value(expected_portable_metadata)
            or expected_portable != expected_portable_metadata
        )
    ):
        raise CandidateEvidenceError("CANDIDATE_PORTABLE_METADATA_MISMATCH")
    if value.get("portable_build_metadata_sha256") != hashlib.sha256(canonical_json_bytes(expected_portable)).hexdigest():
        raise CandidateEvidenceError("CANDIDATE_PORTABLE_METADATA_MISMATCH")
    expected_values = {
        "architecture": profile["architecture"],
        "channel": profile["channel"],
        "compiler_asset": profile["inno_setup_asset"],
        "compiler_version": profile["inno_setup_version"],
        "product_version": profile["product_version"],
        "windows_file_version": profile["windows_file_version"],
    }
    if any(value.get(key) != expected for key, expected in expected_values.items()):
        raise CandidateEvidenceError("CANDIDATE_VERSION_MISMATCH")
    if value.get("compiler_sha256") != profile["inno_setup_sha256"]:
        raise CandidateEvidenceError("CANDIDATE_COMPILER_DIGEST_MISMATCH")
    if value.get("profile_sha256") != snapshot.sha256:
        raise CandidateEvidenceError("CANDIDATE_PROFILE_MISMATCH")
    if (
        value.get("installer_filename") != profile["installer_filename"]
        or not _safe_filename(value.get("installer_filename"))
        or not _lower_hex(value.get("installer_sha256"), 64)
        or not _lower_hex(value.get("payload_manifest_sha256"), 64)
    ):
        raise CandidateEvidenceError("CANDIDATE_METADATA_INVALID")
    _build_time(value.get("built_at"))


def _manifest(value: dict[str, Any], metadata_raw: bytes, metadata: dict[str, Any]) -> None:
    expected_keys = {*_METADATA_KEYS, "build_metadata_sha256"}
    if set(value) != expected_keys:
        raise CandidateEvidenceError("CANDIDATE_MANIFEST_INVALID")
    if value.get("build_metadata_sha256") != hashlib.sha256(metadata_raw).hexdigest():
        raise CandidateEvidenceError("CANDIDATE_METADATA_DIGEST_MISMATCH")
    if any(value.get(key) != metadata[key] for key in _METADATA_KEYS):
        raise CandidateEvidenceError("CANDIDATE_MANIFEST_BINDING_MISMATCH")


def _existing_directory(value: str | Path, code: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or not path.is_dir() or _has_reparse_component(path):
        raise CandidateEvidenceError(code)
    try:
        return path.resolve(strict=True)
    except OSError:
        raise CandidateEvidenceError(code) from None


def _existing_file(value: str | Path, code: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or not path.is_file() or _has_reparse_component(path):
        raise CandidateEvidenceError(code)
    try:
        return path.resolve(strict=True)
    except OSError:
        raise CandidateEvidenceError(code) from None


def _new_destination(value: str | Path) -> Path:
    path = Path(value)
    if (
        not path.is_absolute()
        or path.exists()
        or _is_reparse_point(path)
        or _has_reparse_component(path.parent)
    ):
        raise CandidateEvidenceError("CANDIDATE_OUTPUT_INVALID")
    try:
        parent = path.parent.resolve(strict=True)
    except OSError:
        raise CandidateEvidenceError("CANDIDATE_OUTPUT_INVALID") from None
    return parent / path.name


def _files(root: Path) -> dict[str, Path]:
    files: dict[str, Path] = {}
    try:
        with os.scandir(root) as entries:
            for item in entries:
                path = Path(item.path)
                if _has_reparse_component(path):
                    raise CandidateEvidenceError("CANDIDATE_REPARSE_POINT")
                if not item.is_file(follow_symlinks=False):
                    raise CandidateEvidenceError("CANDIDATE_FILE_SET_INVALID")
                if item.name.casefold() in {name.casefold() for name in files}:
                    raise CandidateEvidenceError("CANDIDATE_FILE_SET_INVALID")
                if _size(path) > MAX_ARTIFACT_BYTES:
                    raise CandidateEvidenceError("CANDIDATE_FILE_SIZE_INVALID")
                files[item.name] = path
    except CandidateEvidenceError:
        raise
    except OSError:
        raise CandidateEvidenceError("CANDIDATE_ROOT_INVALID") from None
    return files


def _json(path: Path, limit: int | None = None) -> tuple[bytes, dict[str, Any]]:
    try:
        if limit is None:
            limit = MAX_METADATA_BYTES
        raw = _read(path, limit, "CANDIDATE_JSON_INVALID")
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_unique_object,
            parse_constant=_invalid_json_constant,
        )
        if not isinstance(value, dict) or raw != canonical_json_bytes(value):
            raise CandidateEvidenceError("CANDIDATE_JSON_INVALID")
    except CandidateEvidenceError:
        raise
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError, MemoryError, OverflowError):
        raise CandidateEvidenceError("CANDIDATE_JSON_INVALID") from None
    return raw, value


def _checksums(root: Path, files: dict[str, Path]) -> None:
    if _read(root / "SHA256SUMS") != _checksum_bytes(files):
        raise CandidateEvidenceError("CANDIDATE_CHECKSUMS_INVALID")


def _checksum_bytes(files: dict[str, Path]) -> bytes:
    return "".join(
        f"{_sha256(path)} *{name}\n"
        for name, path in sorted(files.items())
        if name != "SHA256SUMS"
    ).encode("ascii")


def _read(
    path: Path,
    limit: int = MAX_ARTIFACT_BYTES,
    too_large_code: str = "CANDIDATE_FILE_SIZE_INVALID",
) -> bytes:
    try:
        with path.open("rb") as handle:
            value = handle.read(limit + 1)
    except (OSError, MemoryError, OverflowError):
        raise CandidateEvidenceError("CANDIDATE_FILE_READ_INVALID") from None
    if len(value) > limit:
        raise CandidateEvidenceError(too_large_code)
    return value


def _remove_partial(partial: Path) -> None:
    if _is_reparse_point(partial):
        raise CandidateEvidenceError("CANDIDATE_OUTPUT_INVALID")
    if not partial.exists():
        return
    if _has_reparse_component(partial.parent):
        raise CandidateEvidenceError("CANDIDATE_OUTPUT_INVALID")
    try:
        shutil.rmtree(partial)
    except OSError:
        raise CandidateEvidenceError("CANDIDATE_OUTPUT_INVALID") from None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    seen = 0
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(_CHUNK_SIZE):
                seen += len(chunk)
                if seen > MAX_ARTIFACT_BYTES:
                    raise CandidateEvidenceError("CANDIDATE_FILE_SIZE_INVALID")
                digest.update(chunk)
    except CandidateEvidenceError:
        raise
    except OSError:
        raise CandidateEvidenceError("CANDIDATE_FILE_READ_INVALID") from None
    return digest.hexdigest()


def _size(path: Path) -> int:
    try:
        return path.stat(follow_symlinks=False).st_size
    except OSError:
        raise CandidateEvidenceError("CANDIDATE_FILE_READ_INVALID") from None


def _build_time(value: object) -> None:
    try:
        validate_build_time(value)
    except (TypeError, ValueError):
        raise CandidateEvidenceError("CANDIDATE_METADATA_INVALID") from None


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate")
        value[key] = item
    return value


def _invalid_json_constant(value: str) -> None:
    raise ValueError(value)


def _safe_filename(value: object) -> bool:
    if type(value) is not str or not value:
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and path.name == value and "\\" not in value and ":" not in value


def _safe_payload_path(value: object) -> bool:
    if type(value) is not str or not value or "\\" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and all(part not in {"", ".", ".."} and ":" not in part for part in path.parts)
    )


def _valid_dependency_snapshot(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {"lock_sha256", "versions"}:
        return False
    versions = value.get("versions")
    return (
        _lower_hex(value.get("lock_sha256"), 64)
        and isinstance(versions, dict)
        and bool(versions)
        and all(
            _safe_dependency_string(name) and _safe_dependency_string(version)
            for name, version in versions.items()
        )
    )


def _safe_dependency_string(value: object) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= 256
        and value.isascii()
        and not any(character.isspace() or ord(character) < 32 for character in value)
        and not any(character in value for character in ("/", "\\", ":"))
    )


def _lower_hex(value: object, length: int) -> bool:
    return type(value) is str and len(value) == length and all(char in "0123456789abcdef" for char in value)


def _version(value: object) -> bool:
    return type(value) is str and bool(value) and all(char.isdigit() or char in ".-beta" for char in value)


def _has_reparse_component(path: Path) -> bool:
    current = path
    while True:
        if current.exists() or current.is_symlink():
            if _is_reparse_point(current):
                return True
        if current.parent == current:
            return False
        current = current.parent


def _paths_overlap(left: Path, right: Path) -> bool:
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def _is_reparse_point(path: Path) -> bool:
    try:
        value = path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return stat.S_ISLNK(value.st_mode) or bool(
        getattr(value, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--profile", type=Path, required=True)
    args = parser.parse_args()
    try:
        snapshot = load_profile_snapshot(ROOT, args.profile)
        result = verify_candidate(args.evidence_root, args.expected_commit, snapshot)
    except CandidateEvidenceError as error:
        parser.error(str(error))
    except (ProfileViolation, OSError, UnicodeError, json.JSONDecodeError, ValueError, RecursionError, MemoryError, OverflowError):
        parser.error("CANDIDATE_PROFILE_INVALID")
    sys.stdout.buffer.write(canonical_json_bytes(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
