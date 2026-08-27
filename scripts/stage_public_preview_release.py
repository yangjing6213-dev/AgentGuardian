"""Stage and verify the bounded AgentGuardian public-preview release."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass, replace
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


@dataclass(frozen=True)
class _StagedChildToken:
    name: str
    snapshot: _FileSnapshot
    digest: str
    handle: int | None = None


@dataclass(frozen=True)
class _SourceFileToken:
    snapshot: _FileSnapshot
    digest: str
    max_bytes: int
    code: str


@dataclass(frozen=True)
class _DirectoryBinding:
    path: Path
    identity: tuple[int, ...]
    handle: int


@dataclass(frozen=True)
class _StagingDirectoryToken:
    parent: Path
    name: str
    prefix: str
    parent_identity: tuple[int, ...]
    identity: tuple[int, ...]
    is_reparse_point: bool
    parent_handle: int | None
    directory_handle: int | None
    children: tuple[_StagedChildToken, ...] = ()

    @property
    def path(self) -> Path:
        return self.parent / self.name


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


def _directory_identity(info: os.stat_result) -> tuple[int, int]:
    return (info.st_dev, info.st_ino)


def _win32_open_directory(path: Path, access: int) -> tuple[int, tuple[int, ...]]:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = kernel32.CreateFileW(
        str(path),
        access,
        0x00000001 | 0x00000002 | 0x00000004,
        None,
        3,
        0x02000000 | 0x00200000,
        None,
    )
    if handle == wintypes.HANDLE(-1).value:
        raise OSError(ctypes.get_last_error(), "CreateFileW")

    class _FileTime(ctypes.Structure):
        _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]

    class _ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("attributes", wintypes.DWORD),
            ("creation_time", _FileTime),
            ("last_access_time", _FileTime),
            ("last_write_time", _FileTime),
            ("volume_serial", wintypes.DWORD),
            ("file_size_high", wintypes.DWORD),
            ("file_size_low", wintypes.DWORD),
            ("number_of_links", wintypes.DWORD),
            ("file_index_high", wintypes.DWORD),
            ("file_index_low", wintypes.DWORD),
        ]

    info = _ByHandleFileInformation()
    kernel32.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_ByHandleFileInformation),
    ]
    kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
        error_code = ctypes.get_last_error()
        try:
            _close_bound_handle(int(handle))
        except Exception:
            pass
        raise OSError(error_code, "GetFileInformationByHandle")
    return (
        int(handle),
        (
            int(info.volume_serial),
            int(info.file_index_high),
            int(info.file_index_low),
        ),
    )


def _close_bound_handle(handle: int | None) -> None:
    if handle is None:
        return
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        close_handle = ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL
        if not close_handle(handle):
            raise OSError(ctypes.get_last_error(), "CloseHandle")
    else:
        os.close(handle)


def _bound_handle_identity(handle: int) -> tuple[int, ...]:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        class _FileTime(ctypes.Structure):
            _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]

        class _ByHandleFileInformation(ctypes.Structure):
            _fields_ = [
                ("attributes", wintypes.DWORD),
                ("creation_time", _FileTime),
                ("last_access_time", _FileTime),
                ("last_write_time", _FileTime),
                ("volume_serial", wintypes.DWORD),
                ("file_size_high", wintypes.DWORD),
                ("file_size_low", wintypes.DWORD),
                ("number_of_links", wintypes.DWORD),
                ("file_index_high", wintypes.DWORD),
                ("file_index_low", wintypes.DWORD),
            ]

        info = _ByHandleFileInformation()
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetFileInformationByHandle.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_ByHandleFileInformation),
        ]
        kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
        if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
            raise OSError(ctypes.get_last_error(), "GetFileInformationByHandle")
        return (
            int(info.volume_serial),
            int(info.file_index_high),
            int(info.file_index_low),
        )
    return _directory_identity(os.fstat(handle))


def _path_has_reparse(path: Path, code: str) -> bool:
    try:
        return _has_reparse_component(path)
    except (ProfileViolation, OSError):
        _fail(code)
    return False


def _reject_windows_special_path(path_value: str | Path, code: str) -> None:
    if os.name != "nt":
        return
    try:
        raw = os.fspath(path_value)
    except TypeError:
        _fail(code)
    if isinstance(raw, bytes):
        _fail(code)
    folded = raw.casefold()
    if (
        raw.startswith(("\\\\", "//", "\\Device\\", "/Device/"))
        or folded.startswith(("\\device\\", "/device/"))
    ):
        _fail(code)


def _resolved_project_root(project_root: str | Path) -> Path:
    _reject_windows_special_path(project_root, "RELEASE_SOURCE_STATE_INVALID")
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
    _reject_windows_special_path(path_value, "RELEASE_INPUT_PATH_INVALID")
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
    _reject_windows_special_path(output_root, "RELEASE_OUTPUT_PATH_INVALID")
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
    primary_error: BaseException | None = None
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
    except ReleaseViolation as error:
        primary_error = error
        raise
    except (FileNotFoundError, OSError, ValueError) as error:
        try:
            _fail(code)
        except BaseException as mapped:
            primary_error = mapped
            raise
    except BaseException as error:
        primary_error = error
        raise
    finally:
        close_failed = False
        if stream is not None:
            try:
                stream.close()
            except Exception:
                close_failed = True
                try:
                    os.close(stream.fileno())
                except Exception:
                    pass
        elif file_descriptor is not None:
            try:
                os.close(file_descriptor)
            except Exception:
                close_failed = True
        if close_failed and primary_error is None:
            _fail("RELEASE_RESOURCE_CLOSE_FAILED")


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


@contextmanager
def _create_output_file(
    path: Path, directory_token: _StagingDirectoryToken | None = None
) -> Iterator[BinaryIO]:
    if directory_token is not None:
        _validated_staging_path(directory_token, path.parent, "RELEASE_OUTPUT_PATH_INVALID")
        name = path.name
        if not name or any(separator in name for separator in ("\\", "/")):
            _fail("RELEASE_OUTPUT_PATH_INVALID")
    descriptor: int | None = None
    stream: BinaryIO | None = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if directory_token is None:
            if _has_reparse_component(path) or _is_reparse_point(path):
                _fail("RELEASE_OUTPUT_PATH_INVALID")
            descriptor = os.open(path, flags, 0o600)
        elif os.name == "posix":
            descriptor = os.open(
                name,
                flags,
                0o600,
                dir_fd=directory_token.directory_handle,
            )
        elif os.name == "nt":
            descriptor = _ntdll_create_staging_file(directory_token, name)
        else:
            _fail("RELEASE_OUTPUT_PATH_INVALID")
        stream = os.fdopen(descriptor, "wb", closefd=True)
        descriptor = None
    except ReleaseViolation:
        raise
    except FileExistsError:
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    except (OSError, ValueError):
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    primary_error: BaseException | None = None
    try:
        if stream is None:
            _fail("RELEASE_OUTPUT_PATH_INVALID")
        yield stream
    except BaseException as error:
        primary_error = error
        raise
    finally:
        try:
            stream.close()
        except Exception:
            if primary_error is None:
                _fail("RELEASE_RESOURCE_CLOSE_FAILED")


def _copy_and_digest(
    source: _FileSnapshot | Path,
    target: Path,
    workflow_markers: Iterable[str] = (),
    *,
    directory_token: _StagingDirectoryToken | None = None,
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
        ) as source_stream, _create_output_file(
            target, directory_token
        ) as target_stream:
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


def _capture_source_file(path: _FileSnapshot, *, max_bytes: int, code: str) -> _SourceFileToken:
    digest, size = _digest_file(path, max_bytes=max_bytes, code=code)
    if size != path.size:
        _fail("RELEASE_SOURCE_STATE_INVALID")
    return _SourceFileToken(path, digest, max_bytes, code)


def _verify_source_inputs(
    root: Path,
    source_commit: str,
    initial_contract: dict[str, object],
    source_files: tuple[_SourceFileToken, ...],
) -> None:
    _require_source_state(root, source_commit)
    try:
        current_profile = _verified_profile(root)
        if _release_contract(current_profile) != initial_contract:
            _fail("RELEASE_SOURCE_STATE_INVALID")
    except ReleaseViolation:
        raise
    for source in source_files:
        current = _snapshot_file(
            source.snapshot.path, max_bytes=source.max_bytes, code=source.code
        )
        if (
            current.identity != source.snapshot.identity
            or current.size != source.snapshot.size
        ):
            _fail("RELEASE_SOURCE_STATE_INVALID")
        digest, size = _digest_file(
            current, max_bytes=source.max_bytes, code=source.code
        )
        if size != source.snapshot.size or digest != source.digest:
            _fail("RELEASE_SOURCE_STATE_INVALID")


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


def _write_checksums(
    output_root: Path, directory_token: _StagingDirectoryToken | None = None
) -> None:
    lines: list[str] = []
    for name in sorted(_CHECKSUM_FILE_NAMES):
        digest, _ = _digest_file(output_root / name)
        lines.append(f"{digest}  {name}")
    try:
        with _create_output_file(
            output_root / _CHECKSUMS_NAME, directory_token
        ) as stream:
            stream.write(("\n".join(lines) + "\n").encode("ascii"))
    except (OSError, UnicodeError):
        _fail("RELEASE_MANIFEST_INVALID")


def _open_bound_directory(path: Path, access: int) -> tuple[int, tuple[int, ...]]:
    if os.name == "nt":
        return _win32_open_directory(path, access)
    if os.name == "posix":
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        handle = os.open(path, flags)
        return handle, _bound_handle_identity(handle)
    _fail("RELEASE_OUTPUT_PATH_INVALID")


def _bind_directory(path: Path, access: int) -> _DirectoryBinding:
    candidate = path.absolute()
    try:
        if _has_reparse_component(candidate) or _is_reparse_point(candidate):
            _fail("RELEASE_OUTPUT_PATH_INVALID")
        resolved = candidate.resolve(strict=True)
        if not resolved.is_dir():
            _fail("RELEASE_OUTPUT_PATH_INVALID")
        handle, identity = _open_bound_directory(resolved, access)
    except (FileNotFoundError, OSError, ProfileViolation):
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    return _DirectoryBinding(resolved, identity, handle)


def _ntdll_open_relative_directory(
    parent_handle: int, name: str
) -> tuple[int, tuple[int, ...]]:
    if (
        not name
        or name in {".", ".."}
        or any(separator in name for separator in ("\\", "/"))
        or len(name) > 255
    ):
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    import ctypes
    from ctypes import wintypes

    class _UnicodeString(ctypes.Structure):
        _fields_ = [
            ("length", wintypes.USHORT),
            ("maximum_length", wintypes.USHORT),
            ("buffer", wintypes.LPWSTR),
        ]

    class _ObjectAttributes(ctypes.Structure):
        _fields_ = [
            ("length", wintypes.ULONG),
            ("root_directory", wintypes.HANDLE),
            ("object_name", ctypes.POINTER(_UnicodeString)),
            ("attributes", wintypes.ULONG),
            ("security_descriptor", wintypes.LPVOID),
            ("security_quality_of_service", wintypes.LPVOID),
        ]

    class _IoStatusBlock(ctypes.Structure):
        _fields_ = [
            ("status", ctypes.c_int32),
            ("status_padding", wintypes.DWORD),
            ("information", ctypes.c_size_t),
        ]

    try:
        native_open = ctypes.WinDLL("ntdll", use_last_error=True).NtCreateFile
    except (AttributeError, OSError):
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    native_open.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        ctypes.POINTER(_ObjectAttributes),
        ctypes.POINTER(_IoStatusBlock),
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    native_open.restype = ctypes.c_int32
    name_buffer = ctypes.create_unicode_buffer(name)
    encoded_length = len(name.encode("utf-16-le"))
    unicode_name = _UnicodeString(
        encoded_length,
        encoded_length + 2,
        ctypes.cast(name_buffer, wintypes.LPWSTR),
    )
    attributes = _ObjectAttributes(
        ctypes.sizeof(_ObjectAttributes),
        wintypes.HANDLE(parent_handle),
        ctypes.pointer(unicode_name),
        0x00000040 | 0x00001000,
        None,
        None,
    )
    io_status = _IoStatusBlock()
    native_handle = wintypes.HANDLE()
    try:
        status = native_open(
            ctypes.byref(native_handle),
            0x00000001 | 0x00000080 | 0x00010000 | 0x00100000,
            ctypes.byref(attributes),
            ctypes.byref(io_status),
            None,
            0,
            0x00000007,
            0x00000001,
            0x00000001 | 0x00000020 | 0x00200000,
            None,
            0,
        )
    except (OSError, TypeError, ValueError):
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    handle_value = native_handle.value
    if (
        int(status) < 0
        or io_status.status < 0
        or handle_value in (None, wintypes.HANDLE(-1).value)
    ):
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    try:
        identity = _bound_handle_identity(int(handle_value))
    except (OSError, ValueError):
        try:
            _close_bound_handle(int(handle_value))
        except Exception:
            pass
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    return int(handle_value), identity


def _snapshot_staging_directory(
    path: Path, prefix: str, parent_binding: _DirectoryBinding
) -> _StagingDirectoryToken:
    candidate = path.absolute()
    directory_handle: int | None = None
    try:
        parent = candidate.parent.resolve(strict=True)
        info = candidate.lstat()
        is_reparse = _is_reparse_point(candidate)
        if (
            not stat.S_ISDIR(info.st_mode)
            or not candidate.name.startswith(prefix)
            or _has_reparse_component(candidate)
            or is_reparse
        ):
            _fail("RELEASE_OUTPUT_PATH_INVALID")
        if parent != parent_binding.path:
            _fail("RELEASE_OUTPUT_PATH_INVALID")
        if _bound_handle_identity(parent_binding.handle) != parent_binding.identity:
            _fail("RELEASE_OUTPUT_PATH_INVALID")
        if os.name == "posix":
            if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
                _fail("RELEASE_OUTPUT_PATH_INVALID")
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            directory_handle = os.open(
                candidate.name, flags, dir_fd=parent_binding.handle
            )
            identity = _bound_handle_identity(directory_handle)
        elif os.name == "nt":
            directory_handle, identity = _ntdll_open_relative_directory(
                parent_binding.handle, candidate.name
            )
        else:
            _fail("RELEASE_OUTPUT_PATH_INVALID")
        current_info = candidate.lstat()
        if _file_identity(current_info) != _file_identity(info):
            _fail("RELEASE_OUTPUT_PATH_INVALID")
    except (FileNotFoundError, OSError, ProfileViolation, ReleaseViolation):
        if directory_handle is not None:
            try:
                _close_bound_handle(directory_handle)
            except Exception:
                pass
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    return _StagingDirectoryToken(
        parent=parent,
        name=candidate.name,
        prefix=prefix,
        parent_identity=parent_binding.identity,
        identity=identity,
        is_reparse_point=False,
        parent_handle=parent_binding.handle,
        directory_handle=directory_handle,
    )


def _validated_staging_path(
    token: _StagingDirectoryToken, staged: Path, code: str
) -> Path:
    candidate = staged.absolute()
    if token.parent_handle is None or token.directory_handle is None:
        _fail(code)
    try:
        parent = candidate.parent.resolve(strict=True)
        info = candidate.lstat()
        is_reparse = _is_reparse_point(candidate)
        if (
            parent != token.parent
            or candidate.name != token.name
            or not candidate.name.startswith(token.prefix)
            or _has_reparse_component(candidate)
            or is_reparse
            or is_reparse != token.is_reparse_point
            or not stat.S_ISDIR(info.st_mode)
        ):
            _fail(code)
        if _bound_handle_identity(token.parent_handle) != token.parent_identity:
            _fail(code)
        if _bound_handle_identity(token.directory_handle) != token.identity:
            _fail(code)
        current_parent_handle, current_parent_identity = _open_bound_directory(
            parent, 0
        )
        _close_bound_handle(current_parent_handle)
        if current_parent_identity != token.parent_identity:
            _fail(code)
        current_handle, current_identity = _open_bound_directory(candidate, 0)
        _close_bound_handle(current_handle)
        if current_identity != token.identity:
            _fail(code)
    except (FileNotFoundError, OSError, ProfileViolation):
        _fail(code)
    return candidate


def _cleanup_path_still_bound(
    token: _StagingDirectoryToken, staged: Path
) -> bool:
    candidate = staged.absolute()
    handle: int | None = None
    try:
        if (
            candidate.parent.resolve(strict=True) != token.parent
            or candidate.name != token.name
            or not candidate.name.startswith(token.prefix)
            or _has_reparse_component(candidate)
            or _is_reparse_point(candidate)
        ):
            return False
        if os.name == "nt":
            handle, identity = _open_bound_directory(candidate, 0x00000080 | 0x00000001)
        elif os.name == "posix":
            if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
                return False
            handle = os.open(
                candidate,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
            identity = _bound_handle_identity(handle)
        else:
            return False
        return identity == token.identity
    except (FileNotFoundError, OSError, ProfileViolation, ReleaseViolation):
        return False
    finally:
        if handle is not None:
            try:
                _close_bound_handle(handle)
            except Exception:
                pass


def _staging_file_limit(name: str) -> tuple[int, str]:
    if name == _METADATA_NAME:
        return MAX_METADATA_BYTES, "RELEASE_MANIFEST_TOO_LARGE"
    if name == _CHECKSUMS_NAME:
        return MAX_CHECKSUM_BYTES, "RELEASE_CHECKSUM_TOO_LARGE"
    return MAX_INPUT_BYTES, "RELEASE_ASSET_TOO_LARGE"


def _bind_staging_contents(
    token: _StagingDirectoryToken, staged: Path
) -> _StagingDirectoryToken:
    path = _validated_staging_path(token, staged, "RELEASE_OUTPUT_PATH_INVALID")
    try:
        entries = tuple(path.iterdir())
    except OSError:
        _fail("RELEASE_MANIFEST_INVALID")
    if tuple(sorted(entry.name for entry in entries)) != tuple(
        sorted(RELEASE_ASSET_NAMES)
    ):
        _fail("RELEASE_MANIFEST_INVALID")
    children: list[_StagedChildToken] = []
    for entry in entries:
        limit, code = _staging_file_limit(entry.name)
        child_handle: int | None = None
        try:
            child_handle = _open_bound_staged_child(token, entry.name, code)
            snapshot = _snapshot_file(entry, max_bytes=limit, code=code)
            digest, _ = _digest_file(snapshot, max_bytes=limit, code=code)
            children.append(
                _StagedChildToken(entry.name, snapshot, digest, child_handle)
            )
        except BaseException:
            if child_handle is not None:
                try:
                    _close_bound_handle(child_handle)
                except Exception:
                    pass
            raise
    return replace(token, children=tuple(sorted(children, key=lambda item: item.name)))


def _close_staging_child_handles(
    token: _StagingDirectoryToken,
) -> tuple[_StagingDirectoryToken, str | None]:
    failed = False
    closed: set[int] = set()
    children: list[_StagedChildToken] = []
    for child in token.children:
        handle = child.handle
        if handle is not None and handle not in closed:
            closed.add(handle)
            try:
                _close_bound_handle(handle)
            except Exception:
                failed = True
        children.append(replace(child, handle=None))
    detached = replace(token, children=tuple(children))
    return detached, "RELEASE_RESOURCE_CLOSE_FAILED" if failed else None


def _open_bound_staged_child(
    token: _StagingDirectoryToken, name: str, code: str
) -> int:
    if (
        token.directory_handle is None
        or name not in RELEASE_ASSET_NAMES
        or any(separator in name for separator in ("\\", "/"))
    ):
        _fail(code)
    if os.name == "posix":
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        if not hasattr(os, "O_NOFOLLOW"):
            _fail(code)
        flags |= os.O_NOFOLLOW
        handle: int | None = None
        try:
            handle = os.open(name, flags, dir_fd=token.directory_handle)
            if not stat.S_ISREG(os.fstat(handle).st_mode):
                _fail(code)
            return handle
        except (FileNotFoundError, OSError, ReleaseViolation):
            if handle is not None:
                try:
                    _close_bound_handle(handle)
                except Exception:
                    pass
            _fail(code)
    if os.name == "nt":
        handle = _ntdll_create_staging_file(
            token,
            name,
            create_disposition=0x00000001,
            desired_access=0x00000001 | 0x00000080 | 0x00100000,
            share_access=0x00000005,
            create_options=0x00000040
            | 0x00000020
            | 0x00200000,
            return_native_handle=True,
        )
        if handle is None:
            _fail(code)
        return handle
    _fail(code)


def _validate_staging_contents(
    token: _StagingDirectoryToken, staged: Path
) -> None:
    path = _validated_staging_path(token, staged, "RELEASE_OUTPUT_PATH_INVALID")
    if not token.children:
        _fail("RELEASE_MANIFEST_INVALID")
    try:
        entries = tuple(path.iterdir())
    except OSError:
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    expected = tuple(child.name for child in token.children)
    if tuple(sorted(entry.name for entry in entries)) != expected:
        _fail("RELEASE_MANIFEST_INVALID")
    for child in token.children:
        if child.handle is not None:
            try:
                _bound_handle_identity(child.handle)
            except (OSError, ValueError):
                _fail("RELEASE_ASSET_DIGEST_MISMATCH")
        limit, code = _staging_file_limit(child.name)
        snapshot = _snapshot_file(path / child.name, max_bytes=limit, code=code)
        if snapshot.identity != child.snapshot.identity or snapshot.size != child.snapshot.size:
            _fail("RELEASE_ASSET_DIGEST_MISMATCH")
        digest, _ = _digest_file(snapshot, max_bytes=limit, code=code)
        if digest != child.digest:
            _fail("RELEASE_ASSET_DIGEST_MISMATCH")


def _load_renameat2():
    if os.name != "posix":
        return None
    try:
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            return None
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        return renameat2
    except (AttributeError, OSError):
        return None


def _rename_staged_posix(
    staged: Path, output: Path, token: _StagingDirectoryToken | None
) -> None:
    if token is None or token.parent_handle is None or token.directory_handle is None:
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    if output.parent.resolve(strict=True) != token.parent:
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    renameat2 = _load_renameat2()
    if renameat2 is None:
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    try:
        result = renameat2(
            token.parent_handle,
            os.fsencode(token.name),
            token.parent_handle,
            os.fsencode(output.name),
            1,
        )
    except (OSError, TypeError):
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    if result != 0:
        _fail("RELEASE_OUTPUT_PATH_INVALID")


def _win32_set_disposition(handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    class _FileDispositionInfoEx(ctypes.Structure):
        _fields_ = [("flags", wintypes.DWORD)]

    info = _FileDispositionInfoEx(0x00000001 | 0x00000002)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.SetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel32.SetFileInformationByHandle.restype = wintypes.BOOL
    if not kernel32.SetFileInformationByHandle(
        handle, 21, ctypes.byref(info), ctypes.sizeof(info)
    ):
        _fail("RELEASE_CLEANUP_FAILED")


def _ntdll_create_staging_file(
    token: _StagingDirectoryToken,
    name: str,
    *,
    create_disposition: int = 0x00000002,
    desired_access: int = 0x00000002 | 0x00000100 | 0x00100000,
    share_access: int = 0x00000007,
    create_options: int = 0x00000040 | 0x00000020,
    allow_missing: bool = False,
    return_native_handle: bool = False,
) -> int | None:
    """Create one staging file relative to the bound directory handle."""
    if (
        token.directory_handle is None
        or not isinstance(name, str)
        or not name
        or name in {".", ".."}
        or any(separator in name for separator in ("\\", "/"))
        or len(name) > 255
        or name not in RELEASE_ASSET_NAMES
    ):
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class _UnicodeString(ctypes.Structure):
        _fields_ = [
            ("length", wintypes.USHORT),
            ("maximum_length", wintypes.USHORT),
            ("buffer", wintypes.LPWSTR),
        ]

    class _ObjectAttributes(ctypes.Structure):
        _fields_ = [
            ("length", wintypes.ULONG),
            ("root_directory", wintypes.HANDLE),
            ("object_name", ctypes.POINTER(_UnicodeString)),
            ("attributes", wintypes.ULONG),
            ("security_descriptor", wintypes.LPVOID),
            ("security_quality_of_service", wintypes.LPVOID),
        ]

    class _IoStatusBlock(ctypes.Structure):
        _fields_ = [
            ("status", ctypes.c_int32),
            ("status_padding", wintypes.DWORD),
            ("information", ctypes.c_size_t),
        ]

    try:
        ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
        native_create = ntdll.NtCreateFile
    except (AttributeError, OSError):
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    native_create.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        ctypes.POINTER(_ObjectAttributes),
        ctypes.POINTER(_IoStatusBlock),
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    native_create.restype = ctypes.c_int32
    name_buffer = ctypes.create_unicode_buffer(name)
    encoded_length = len(name.encode("utf-16-le"))
    unicode_name = _UnicodeString(
        encoded_length,
        encoded_length + 2,
        ctypes.cast(name_buffer, wintypes.LPWSTR),
    )
    attributes = _ObjectAttributes(
        ctypes.sizeof(_ObjectAttributes),
        wintypes.HANDLE(token.directory_handle),
        ctypes.pointer(unicode_name),
        0x00000040 | 0x00001000,
        None,
        None,
    )
    io_status = _IoStatusBlock()
    native_handle = wintypes.HANDLE()
    try:
        status = native_create(
            ctypes.byref(native_handle),
            desired_access,
            ctypes.byref(attributes),
            ctypes.byref(io_status),
            None,
            0x00000080,
            share_access,
            create_disposition,
            create_options,
            None,
            0,
        )
    except (OSError, TypeError, ValueError):
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    handle_value = native_handle.value
    status_value = int(status)
    if status_value < 0 or io_status.status < 0:
        if allow_missing and status_value in (-1073741772, -1073741766):
            return None
        if handle_value not in (None, wintypes.HANDLE(-1).value):
            try:
                _close_bound_handle(int(handle_value))
            except Exception:
                pass
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    if handle_value in (None, wintypes.HANDLE(-1).value):
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    if return_native_handle:
        return int(handle_value)
    try:
        descriptor = msvcrt.open_osfhandle(
            int(handle_value), os.O_WRONLY | getattr(os, "O_BINARY", 0)
        )
    except (OSError, ValueError):
        try:
            _close_bound_handle(int(handle_value))
        except Exception:
            pass
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    if descriptor < 0:
        try:
            _close_bound_handle(int(handle_value))
        except Exception:
            pass
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    return descriptor


def _ntdll_rename_staged(token: _StagingDirectoryToken, output: Path) -> None:
    """Use the Windows 11 x64 preview capability, not a universal Windows guarantee."""
    if token.parent_handle is None or token.directory_handle is None:
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    import ctypes
    from ctypes import wintypes

    class _IoStatusBlock(ctypes.Structure):
        _fields_ = [
            ("status", ctypes.c_int32),
            ("status_padding", wintypes.DWORD),
            ("information", ctypes.c_size_t),
        ]

    class _FileRenameInformationEx(ctypes.Structure):
        _fields_ = [
            ("flags", wintypes.DWORD),
            ("root_directory", wintypes.HANDLE),
            ("file_name_length", wintypes.DWORD),
            ("file_name", wintypes.WCHAR * 1),
        ]

    if not output.name or any(separator in output.name for separator in ("\\", "/")):
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    encoded_name = output.name.encode("utf-16-le")
    size = _FileRenameInformationEx.file_name.offset + len(encoded_name) + 2
    buffer = ctypes.create_string_buffer(size)
    info = ctypes.cast(buffer, ctypes.POINTER(_FileRenameInformationEx)).contents
    info.flags = 0
    info.root_directory = wintypes.HANDLE(token.parent_handle)
    info.file_name_length = len(encoded_name)
    ctypes.memmove(
        ctypes.addressof(buffer) + _FileRenameInformationEx.file_name.offset,
        encoded_name,
        len(encoded_name),
    )
    try:
        ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
        native_rename = ntdll.NtSetInformationFile
    except (AttributeError, OSError):
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    native_rename.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_IoStatusBlock),
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_int,
    ]
    native_rename.restype = ctypes.c_int32
    io_status = _IoStatusBlock()
    try:
        status = native_rename(
            token.directory_handle,
            ctypes.byref(io_status),
            buffer,
            size,
            65,
        )
    except (OSError, TypeError, ValueError):
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    if int(status) < 0 or io_status.status < 0:
        _fail("RELEASE_OUTPUT_PATH_INVALID")


def _win32_rename_staged(token: _StagingDirectoryToken, output: Path) -> None:
    _ntdll_rename_staged(token, output)


def _cleanup_bound_staging(
    token: _StagingDirectoryToken, staged: Path
) -> bool:
    try:
        if os.name == "posix":
            if token.directory_handle is None or token.parent_handle is None:
                return False
            names = os.listdir(token.directory_handle)
            for name in names:
                info = os.stat(
                    name, dir_fd=token.directory_handle, follow_symlinks=False
                )
                if stat.S_ISDIR(info.st_mode):
                    return False
                os.unlink(name, dir_fd=token.directory_handle)
            _validated_staging_path(token, staged, "RELEASE_CLEANUP_FAILED")
            os.rmdir(token.name, dir_fd=token.parent_handle)
            return True
        if os.name == "nt":
            _validated_staging_path(token, staged, "RELEASE_CLEANUP_FAILED")
            if not _cleanup_path_still_bound(token, staged):
                return False
            for name in RELEASE_ASSET_NAMES:
                child_handle = _ntdll_create_staging_file(
                    token,
                    name,
                    create_disposition=0x00000001,
                    desired_access=0x00010000 | 0x00000080 | 0x00100000,
                    create_options=0x00000040
                    | 0x00000020
                    | 0x00200000,
                    allow_missing=True,
                    return_native_handle=True,
                )
                if child_handle is None:
                    continue
                child_close_failed = False
                try:
                    _win32_set_disposition(child_handle)
                finally:
                    try:
                        _close_bound_handle(child_handle)
                    except Exception:
                        child_close_failed = True
                if child_close_failed:
                    return False
            _win32_set_disposition(token.directory_handle)
            return True
    except (FileNotFoundError, OSError, ProfileViolation, ReleaseViolation):
        return False
    return False


def _cleanup_temporary_output(
    path: Path | None, token: _StagingDirectoryToken | None
) -> str | None:
    if path is None:
        return None
    if token is None:
        return "RELEASE_CLEANUP_FAILED"
    return None if _cleanup_bound_staging(token, path) else "RELEASE_CLEANUP_FAILED"


def _close_directory_binding(binding: _DirectoryBinding | None) -> str | None:
    if binding is None:
        return None
    try:
        _close_bound_handle(binding.handle)
    except Exception:
        return "RELEASE_RESOURCE_CLOSE_FAILED"
    return None


def _close_staging_token(token: _StagingDirectoryToken | None) -> str | None:
    if token is None:
        return None
    failed = False
    handles = [child.handle for child in token.children]
    handles.extend((token.directory_handle, token.parent_handle))
    closed: set[int] = set()
    for handle in handles:
        if handle is None or handle in closed:
            continue
        closed.add(handle)
        try:
            _close_bound_handle(handle)
        except Exception:
            failed = True
    return "RELEASE_RESOURCE_CLOSE_FAILED" if failed else None


def _publish_staged_output(
    staged: Path,
    output: Path,
    token: _StagingDirectoryToken,
    *,
    project_root: Path | None = None,
    source_commit: str | None = None,
    source_files: tuple[_SourceFileToken, ...] = (),
    contract: dict[str, object] | None = None,
) -> None:
    if project_root is not None and source_commit is not None and contract is not None:
        _verify_source_inputs(
            project_root, source_commit, contract, source_files
        )
    _validated_staging_path(token, staged, "RELEASE_OUTPUT_PATH_INVALID")
    _validate_staging_contents(token, staged)
    if output.exists():
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    if output.parent.resolve(strict=True) != token.parent:
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    try:
        if os.name == "nt":
            _win32_rename_staged(token, output)
        elif os.name == "posix":
            _rename_staged_posix(staged, output, token)
        else:
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
    profile_path = _resolve_project_file(root, _PROFILE_RELATIVE_PATH)
    license_path = _resolve_project_file(root, "LICENSE")
    notices_path = _resolve_project_file(root, "THIRD_PARTY_NOTICES.md")
    source_files_list = [
        _capture_source_file(
            profile_path,
            max_bytes=MAX_METADATA_BYTES,
            code="RELEASE_MANIFEST_INVALID",
        ),
        _capture_source_file(
            license_path,
            max_bytes=MAX_INPUT_BYTES,
            code="RELEASE_INPUT_PATH_INVALID",
        ),
        _capture_source_file(
            notices_path,
            max_bytes=MAX_INPUT_BYTES,
            code="RELEASE_INPUT_PATH_INVALID",
        ),
    ]
    captured_paths = {source.snapshot.path for source in source_files_list}
    for relative in profile.profile["active_document_paths"]:
        document = _resolve_project_file(root, str(relative))
        if document.path in captured_paths:
            continue
        source_files_list.append(
            _capture_source_file(
                document,
                max_bytes=MAX_METADATA_BYTES,
                code="RELEASE_SOURCE_STATE_INVALID",
            )
        )
        captured_paths.add(document.path)
    source_files = tuple(source_files_list)
    inputs = (installer, portable, skill, license_path, notices_path)
    workflow_markers = profile.profile["forbidden_workflow_tokens"]
    if any(_path_has_private_marker(snapshot.path, workflow_markers) for snapshot in inputs):
        _fail("RELEASE_PRIVATE_DATA_DETECTED")
    output = _resolve_output(output_root, root, inputs)

    temporary: Path | None = None
    temporary_token: _StagingDirectoryToken | None = None
    parent_binding: _DirectoryBinding | None = None
    primary_error: BaseException | None = None
    try:
        if os.name == "nt":
            parent_access = 0x00000080 | 0x00000001 | 0x00000004 | 0x00000020
        else:
            parent_access = 0
        parent_binding = _bind_directory(output.parent, parent_access)
        staging_prefix = f".{output.name}.staging-"
        try:
            temporary = Path(
                tempfile.mkdtemp(prefix=staging_prefix, dir=output.parent)
            )
        except OSError:
            _fail("RELEASE_OUTPUT_PATH_INVALID")
        temporary_token = _snapshot_staging_directory(
            temporary, staging_prefix, parent_binding
        )
        parent_binding = None
        sources = (
            (portable, PORTABLE_NAME),
            (installer, VERSIONED_INSTALLER_NAME),
            (skill, SKILL_NAME),
            (license_path, "LICENSE"),
            (notices_path, "THIRD_PARTY_NOTICES.md"),
        )
        for source, name in sources:
            _copy_and_digest(
                source,
                temporary / name,
                workflow_markers,
                directory_token=temporary_token,
            )
        _copy_and_digest(
            temporary / VERSIONED_INSTALLER_NAME,
            temporary / PRIMARY_INSTALLER_NAME,
            directory_token=temporary_token,
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
        metadata_names = _METADATA_FILE_NAMES
        for name in metadata_names:
            digest, size = _digest_file(temporary / str(name))
            records.append({"name": name, "sha256": digest, "size": size})
        try:
            with _create_output_file(
                temporary / _METADATA_NAME, temporary_token
            ) as stream:
                stream.write(
                    canonical_json_bytes(
                        _metadata(contract, source_commit, built_at, records)
                    )
                )
        except (OSError, MemoryError):
            _fail("RELEASE_MANIFEST_INVALID")
        _write_checksums(temporary, temporary_token)
        temporary_token = _bind_staging_contents(temporary_token, temporary)
        temporary_token, child_close_code = _close_staging_child_handles(
            temporary_token
        )
        if child_close_code is not None:
            _fail(child_close_code)
        result = verify_staged_release(
            temporary, root, source_commit=source_commit
        )
        _verify_source_inputs(root, source_commit, contract, source_files)
        _publish_staged_output(
            temporary,
            output,
            temporary_token,
            project_root=root,
            source_commit=source_commit,
            source_files=source_files,
            contract=contract,
        )
        temporary = None
        return result
    except BaseException as error:
        primary_error = error
        raise
    finally:
        try:
            cleanup_code = _cleanup_temporary_output(temporary, temporary_token)
        except Exception:
            cleanup_code = "RELEASE_CLEANUP_FAILED"
        try:
            close_code = _close_staging_token(temporary_token)
        except Exception:
            close_code = "RELEASE_RESOURCE_CLOSE_FAILED"
        unbound_close_code = None
        if temporary_token is None:
            unbound_close_code = _close_directory_binding(parent_binding)
        if primary_error is None:
            if cleanup_code is not None:
                _fail(cleanup_code)
            if close_code is not None:
                _fail(close_code)
            if unbound_close_code is not None:
                _fail(unbound_close_code)


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
    if seen != expected_names or tuple(
        record["name"] for record in records
    ) != _METADATA_FILE_NAMES:
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
    _reject_windows_special_path(output_root, "RELEASE_MANIFEST_INVALID")
    _reject_windows_special_path(project_root, "RELEASE_SOURCE_STATE_INVALID")
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
    except Exception:
        sys.stderr.buffer.write(
            canonical_json_bytes(
                {"error": "RELEASE_OPERATION_FAILED", "status": "fail"}
            )
        )
        return 1
    sys.stdout.buffer.write(canonical_json_bytes(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
