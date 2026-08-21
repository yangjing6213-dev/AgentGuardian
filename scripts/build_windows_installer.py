"""Build a bounded current-user Inno Setup installer from a verified payload."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.build_windows_portable import (
    canonical_json_bytes,
    validate_build_time,
    validate_frozen_layout,
    validate_git_build_context,
    validate_relative_paths,
)
from scripts.verify_personal_release_profile import (
    ProfileSnapshot,
    load_profile_snapshot,
    require_profile_snapshot_unchanged,
    verify_payload,
    verify_profile,
)
from scripts.verify_windows_installer_candidate import (
    CandidateEvidenceError,
    _portable_metadata,
    _write_candidate_evidence,
)


MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_METADATA_BYTES = 256 * 1024
MAX_COMPILER_BYTES = 16 * 1024 * 1024
MAX_PAYLOAD_FILES = 20_000
MAX_PAYLOAD_BYTES = 2 * 1024 * 1024 * 1024
_PROFILE_NAME = "personal_exe_private_beta"
_DISPLAY_VERSION = "0.2.0-beta.1"
_FILE_VERSION = "0.2.0.1"
_COMPILER_VERSION = "7.0.2"
_COMPILER_SHA256 = (
    "0ff6140d641f84b64204a2c4d52207c6fc437c9f4db8779c83083d84f7e3d70d"
)
_INSTALLER_SCRIPT_SHA256 = (
    "a5897f4158da4d9cb4246fb62ca1138a2b1c6324cadaf0a4261bfb5158237167"
)
_SCRIPT_RELATIVE = Path("packaging/windows/AgentGuardian.iss")
_PROFILE_RELATIVE = Path("release_profiles/personal_exe_private_beta.json")
_MANIFEST_NAME = "PAYLOAD-MANIFEST.json"
_CHECKSUMS_NAME = "SHA256SUMS"


def build_iscc_command(
    *,
    iscc: Path,
    script: Path,
    bundle_root: Path,
    output_root: Path,
    source_commit: str,
    built_at: str,
    display_version: str = _DISPLAY_VERSION,
    file_version: str = _FILE_VERSION,
) -> tuple[str, ...]:
    values = (
        os.fspath(iscc),
        os.fspath(script),
        os.fspath(bundle_root),
        os.fspath(output_root),
        source_commit,
        built_at,
        display_version,
        file_version,
    )
    if any(not _safe_define(value) for value in values):
        raise ValueError("unsafe compiler define")
    if not all(path.is_absolute() for path in (iscc, script, bundle_root, output_root)):
        raise ValueError("compiler paths must be absolute")
    if not _lower_hex(source_commit, 40):
        raise ValueError("source commit must be a full lowercase SHA-1")
    validate_build_time(built_at)
    return (
        os.fspath(iscc),
        "/Qp",
        f"/DBundleRoot={bundle_root}",
        f"/DOutputRoot={output_root}",
        f"/DDisplayVersion={display_version}",
        f"/DFileVersion={file_version}",
        f"/DSourceCommit={source_commit}",
        f"/DBuiltAt={built_at}",
        os.fspath(script),
    )


def compiler_sha256(iscc: Path) -> str:
    digest = hashlib.sha256()
    size = 0
    try:
        with iscc.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_COMPILER_BYTES:
                    raise ValueError("Inno Setup compiler digest is unavailable")
                digest.update(chunk)
    except ValueError:
        raise
    except OSError:
        raise ValueError("Inno Setup compiler digest is unavailable") from None
    return digest.hexdigest()


def verify_installer_script(contents: bytes) -> None:
    canonical = contents.replace(b"\r\n", b"\n")
    if b"\r" in canonical or hashlib.sha256(canonical).hexdigest() != (
        _INSTALLER_SCRIPT_SHA256
    ):
        raise ValueError("installer script is not approved")


def verify_portable_bundle(
    bundle_root: Path,
    profile_snapshot: ProfileSnapshot,
    *,
    source_commit: str,
    built_at: str,
) -> None:
    if not isinstance(profile_snapshot, ProfileSnapshot):
        raise ValueError("portable profile snapshot is invalid")
    bundle = _existing_absolute_directory(bundle_root, "portable bundle is invalid")
    verify_payload(bundle, profile_snapshot)

    expected_profile = {
        "profile": _PROFILE_NAME,
        "profile_sha256": profile_snapshot.sha256,
        "schema": 2,
        "status": "pass",
    }
    profile_evidence = _load_canonical_json(
        bundle / "PERSONAL-RELEASE-PROFILE.json",
        MAX_METADATA_BYTES,
        "portable profile evidence is invalid",
    )
    if profile_evidence != expected_profile:
        raise ValueError("portable profile evidence is invalid")

    metadata = _load_canonical_json(
        bundle / "BUILD-METADATA.json",
        MAX_METADATA_BYTES,
        "portable build metadata is invalid",
    )
    if (
        not isinstance(metadata, dict)
        or set(metadata)
        != {
            "artifact_status",
            "build_dependencies",
            "build_mode",
            "built_at",
            "source_commit",
        }
        or metadata["artifact_status"] != "unsigned_development_only"
        or metadata["build_mode"] != "pyinstaller_onedir"
        or metadata["built_at"] != built_at
        or metadata["source_commit"] != source_commit
        or not isinstance(metadata["build_dependencies"], dict)
    ):
        raise ValueError("portable build metadata is invalid")

    manifest_path = bundle / _MANIFEST_NAME
    manifest = _load_canonical_json(
        manifest_path,
        MAX_MANIFEST_BYTES,
        "portable payload manifest is invalid",
    )
    entries = _validated_manifest_entries(manifest)
    actual_files = _walk_regular_files(bundle, "portable payload is invalid")
    actual_by_name = {
        path.relative_to(bundle).as_posix(): path for path in actual_files
    }
    declared_names = tuple(entry["path"] for entry in entries)
    expected_names = set(declared_names) | {_MANIFEST_NAME, _CHECKSUMS_NAME}
    if set(actual_by_name) != expected_names:
        raise ValueError("portable payload file set is invalid")
    if "AgentGuardian.exe" not in declared_names:
        raise ValueError("portable payload file set is invalid")

    total_size = 0
    for entry in entries:
        path = actual_by_name[entry["path"]]
        size, digest = _file_identity(path)
        total_size += size
        if total_size > MAX_PAYLOAD_BYTES:
            raise ValueError("portable payload exceeds the size limit")
        if size != entry["size"] or digest != entry["sha256"]:
            raise ValueError("portable payload manifest is invalid")

    manifest_size, manifest_digest = _file_identity(manifest_path)
    checksum_entries = sorted(
        (
            *entries,
            {
                "path": _MANIFEST_NAME,
                "sha256": manifest_digest,
                "size": manifest_size,
            },
        ),
        key=lambda entry: entry["path"],
    )
    expected_checksums = "".join(
        f"{entry['sha256']} *{entry['path']}\n" for entry in checksum_entries
    ).encode("ascii")
    if _read_bounded(
        bundle / _CHECKSUMS_NAME,
        MAX_MANIFEST_BYTES,
        "portable checksums are invalid",
    ) != expected_checksums:
        raise ValueError("portable checksums are invalid")


def build_installer(
    project_root: Path,
    bundle_root: Path,
    output_root: Path,
    *,
    iscc: Path,
    source_commit: str,
    built_at: str,
) -> Path:
    if sys.platform != "win32":
        raise RuntimeError("installer builds require Windows")
    if output_root.exists():
        raise ValueError("installer output root already exists")
    project = _existing_absolute_directory(project_root, "project root is invalid")
    compiler = _existing_absolute_file(iscc, "compiler path is invalid")
    if compiler_sha256(compiler) != _COMPILER_SHA256:
        raise ValueError("Inno Setup compiler digest is invalid")
    bundle = _existing_absolute_directory(bundle_root, "portable bundle is invalid")
    output = _new_absolute_directory_path(
        output_root, "installer output root is invalid"
    )
    if output == bundle or bundle in output.parents or output in bundle.parents:
        raise ValueError("installer output root is invalid")

    head = _git(project, "rev-parse", "HEAD")
    status = _git(project, "status", "--porcelain=v1", "--untracked-files=all")
    validate_git_build_context(head, status, source_commit)
    validate_build_time(built_at)

    profile_path = project / _PROFILE_RELATIVE
    profile_snapshot = load_profile_snapshot(project, profile_path)
    verify_profile(project, profile_snapshot)
    profile = profile_snapshot.profile
    if (
        profile["name"] != _PROFILE_NAME
        or profile["product_version"] != _DISPLAY_VERSION
        or profile["windows_file_version"] != _FILE_VERSION
        or profile["inno_setup_version"] != _COMPILER_VERSION
        or profile["inno_setup_iscc_sha256"] != _COMPILER_SHA256
    ):
        raise ValueError("private beta profile identity is invalid")

    script = _existing_absolute_file(
        project / _SCRIPT_RELATIVE, "installer script is invalid"
    )
    script_snapshot = _read_bounded(
        script, MAX_METADATA_BYTES, "installer script is invalid"
    )
    verify_installer_script(script_snapshot)
    validate_frozen_layout(bundle, project)
    verify_portable_bundle(
        bundle,
        profile_snapshot,
        source_commit=source_commit,
        built_at=built_at,
    )

    command = build_iscc_command(
        iscc=compiler,
        script=script,
        bundle_root=bundle,
        output_root=output,
        display_version=profile["product_version"],
        file_version=profile["windows_file_version"],
        source_commit=source_commit,
        built_at=built_at,
    )
    output.mkdir()
    subprocess.run(command, check=True, cwd=project, shell=False)

    final_head = _git(project, "rev-parse", "HEAD")
    final_status = _git(
        project, "status", "--porcelain=v1", "--untracked-files=all"
    )
    validate_git_build_context(final_head, final_status, source_commit)
    require_profile_snapshot_unchanged(project, profile_path, profile_snapshot)
    if _read_bounded(
        script, MAX_METADATA_BYTES, "installer script changed during build"
    ) != script_snapshot:
        raise ValueError("installer script changed during build")
    validate_frozen_layout(bundle, project)
    verify_portable_bundle(
        bundle,
        profile_snapshot,
        source_commit=source_commit,
        built_at=built_at,
    )

    installer = output / profile["installer_filename"]
    output_files = _walk_regular_files(output, "installer output is invalid")
    if output_files != (installer,) or installer.stat().st_size <= 0:
        raise ValueError("installer output is invalid")
    return installer


def assemble_installer_evidence(
    installer: Path,
    bundle_root: Path,
    evidence_root: Path,
    *,
    source_commit: str,
    built_at: str,
    profile_snapshot: ProfileSnapshot,
) -> Path:
    """Assemble delivery evidence only from a freshly verified portable bundle."""
    try:
        verify_portable_bundle(
            bundle_root,
            profile_snapshot,
            source_commit=source_commit,
            built_at=built_at,
        )
    except ValueError:
        raise CandidateEvidenceError("CANDIDATE_PAYLOAD_INVALID") from None
    portable_raw, portable_metadata = _portable_metadata(Path(bundle_root))
    return _write_candidate_evidence(
        evidence_root,
        installer,
        bundle_root,
        source_commit=source_commit,
        built_at=built_at,
        profile_snapshot=profile_snapshot,
        portable_raw=portable_raw,
        portable_metadata=portable_metadata,
    )


def _validated_manifest_entries(value: object) -> tuple[dict[str, Any], ...]:
    if (
        not isinstance(value, dict)
        or set(value) != {"algorithm", "files", "schema"}
        or value["algorithm"] != "sha256"
        or value["schema"] != 1
        or not isinstance(value["files"], list)
        or len(value["files"]) > MAX_PAYLOAD_FILES
    ):
        raise ValueError("portable payload manifest is invalid")
    entries = value["files"]
    if any(
        not isinstance(entry, dict)
        or set(entry) != {"path", "sha256", "size"}
        or type(entry["path"]) is not str
        or not _lower_hex(entry["sha256"], 64)
        or type(entry["size"]) is not int
        or entry["size"] < 0
        for entry in entries
    ):
        raise ValueError("portable payload manifest is invalid")
    paths = tuple(entry["path"] for entry in entries)
    try:
        validate_relative_paths(paths)
    except ValueError:
        raise ValueError("portable payload manifest is invalid") from None
    if paths != tuple(sorted(paths)):
        raise ValueError("portable payload manifest is invalid")
    return tuple(entries)


def _load_canonical_json(path: Path, limit: int, code: str) -> object:
    raw = _read_bounded(path, limit, code)
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError, ValueError):
        raise ValueError(code) from None
    if raw != canonical_json_bytes(value):
        raise ValueError(code)
    return value


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _walk_regular_files(root: Path, code: str) -> tuple[Path, ...]:
    if _is_reparse_point(root):
        raise ValueError(code)
    stack = [root]
    files: list[Path] = []
    entries = 0
    try:
        while stack:
            directory = stack.pop()
            children: list[Path] = []
            with os.scandir(directory) as iterator:
                for item in iterator:
                    path = Path(item.path)
                    if _is_reparse_point(path):
                        raise ValueError(code)
                    entries += 1
                    if entries > MAX_PAYLOAD_FILES + 2:
                        raise ValueError(code)
                    if item.is_dir(follow_symlinks=False):
                        children.append(path)
                    elif item.is_file(follow_symlinks=False):
                        files.append(path)
                    else:
                        raise ValueError(code)
            stack.extend(sorted(children, key=lambda path: path.name, reverse=True))
    except ValueError:
        raise
    except OSError:
        raise ValueError(code) from None
    return tuple(sorted(files, key=lambda path: path.relative_to(root).as_posix()))


def _file_identity(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_PAYLOAD_BYTES:
                    raise ValueError("portable payload exceeds the size limit")
                digest.update(chunk)
    except ValueError:
        raise
    except OSError:
        raise ValueError("portable payload is invalid") from None
    return size, digest.hexdigest()


def _read_bounded(path: Path, limit: int, code: str) -> bytes:
    try:
        with path.open("rb") as source:
            value = source.read(limit + 1)
    except OSError:
        raise ValueError(code) from None
    if len(value) > limit:
        raise ValueError(code)
    return value


def _existing_absolute_directory(path: Path, code: str) -> Path:
    return _existing_absolute_path(path, code, directory=True)


def _existing_absolute_file(path: Path, code: str) -> Path:
    return _existing_absolute_path(path, code, directory=False)


def _existing_absolute_path(path: Path, code: str, *, directory: bool) -> Path:
    if not path.is_absolute() or _has_reparse_component(path):
        raise ValueError(code)
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        raise ValueError(code) from None
    if (directory and not resolved.is_dir()) or (not directory and not resolved.is_file()):
        raise ValueError(code)
    return resolved


def _new_absolute_directory_path(path: Path, code: str) -> Path:
    if not path.is_absolute() or path.exists() or _has_reparse_component(path):
        raise ValueError(code)
    parent = path.parent
    if not parent.is_dir() or _has_reparse_component(parent):
        raise ValueError(code)
    try:
        resolved_parent = parent.resolve(strict=True)
    except OSError:
        raise ValueError(code) from None
    return resolved_parent / path.name


def _has_reparse_component(path: Path) -> bool:
    current = path
    while True:
        if current.exists() or current.is_symlink():
            if _is_reparse_point(current):
                return True
        if current.parent == current:
            return False
        current = current.parent


def _is_reparse_point(path: Path) -> bool:
    try:
        value = path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        raise ValueError("path inspection failed") from None
    return stat.S_ISLNK(value.st_mode) or bool(
        getattr(value, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _safe_define(value: str) -> bool:
    return bool(value) and len(value) <= 4096 and not any(
        character in value for character in ('"', "\r", "\n", "\x00")
    )


def _lower_hex(value: object, length: int) -> bool:
    return (
        type(value) is str
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def _git(project_root: Path, *arguments: str) -> str:
    return subprocess.run(
        ("git", *arguments),
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=ROOT)
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--iscc", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--built-at", required=True)
    arguments = parser.parse_args()
    build_installer(
        arguments.project_root,
        arguments.bundle_root,
        arguments.output_root,
        iscc=arguments.iscc,
        source_commit=arguments.source_commit,
        built_at=arguments.built_at,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
