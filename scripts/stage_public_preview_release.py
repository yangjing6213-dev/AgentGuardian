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
from dataclasses import dataclass, field, replace
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


@dataclass(frozen=True)
class _OwnedHandle:
    handle: int
    resource_type: str
    identity: tuple[int, ...] | None = None


class _HandleOwnershipLedger:
    def __init__(self) -> None:
        self._owned: dict[int, _OwnedHandle] = {}

    def register(
        self,
        handle: int,
        *,
        resource_type: str = "handle",
        identity: tuple[int, ...] | None = None,
    ) -> None:
        value = int(handle)
        if value not in self._owned:
            self._owned[value] = _OwnedHandle(value, resource_type, identity)

    def release(self, handle: int) -> None:
        self._owned.pop(int(handle), None)

    def set_identity(self, handle: int, identity: tuple[int, ...]) -> None:
        record = self._owned.get(int(handle))
        if record is not None:
            self._owned[int(handle)] = replace(record, identity=identity)

    def owns(self, handle: int) -> bool:
        return int(handle) in self._owned

    def handles(self) -> tuple[int, ...]:
        return tuple(self._owned)

    def record(self, handle: int) -> _OwnedHandle | None:
        return self._owned.get(int(handle))

    def records(self) -> tuple[_OwnedHandle, ...]:
        return tuple(self._owned.values())

    def adopt(self, other: _HandleOwnershipLedger) -> None:
        for record in other.records():
            self._owned.setdefault(record.handle, record)


class ReleaseViolation(ValueError):
    """A fixed, non-sensitive release staging failure."""

    def __init__(
        self,
        code: str,
        *,
        cleanup_lease: _HandleOwnershipLedger | None = None,
    ) -> None:
        self.code = code
        self.cleanup_lease = cleanup_lease
        super().__init__(_PRIVATE_REMEDIATION if code == "RELEASE_PRIVATE_DATA_DETECTED" else code)


class _ReleaseArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise ReleaseViolation("RELEASE_CLI_ARGUMENT_INVALID")


class _StagingBindingError(ReleaseViolation):
    def __init__(
        self, primary_error: BaseException, cleanup_token: _StagingDirectoryToken
    ) -> None:
        self.cleanup_token = cleanup_token
        self.cleanup_lease = cleanup_token.ledger
        code = (
            primary_error.code
            if isinstance(primary_error, ReleaseViolation)
            else "RELEASE_RESOURCE_CLOSE_FAILED"
        )
        super().__init__(code, cleanup_lease=cleanup_token.ledger)


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
    ledger: _HandleOwnershipLedger = field(default_factory=_HandleOwnershipLedger)

    def __post_init__(self) -> None:
        self.ledger.register(self.handle, resource_type="directory")


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
    ledger: _HandleOwnershipLedger = field(default_factory=_HandleOwnershipLedger)

    def __post_init__(self) -> None:
        for handle in (self.parent_handle, self.directory_handle):
            if handle is not None:
                identity = (
                    self.parent_identity
                    if handle == self.parent_handle
                    else self.identity
                )
                self.ledger.register(
                    handle, resource_type="directory", identity=identity
                )
        for child in self.children:
            if child.handle is not None:
                self.ledger.register(
                    child.handle,
                    resource_type="fd" if os.name != "nt" else "handle",
                )

    @property
    def path(self) -> Path:
        return self.parent / self.name


def _fail(
    code: str, *, cleanup_lease: _HandleOwnershipLedger | None = None
) -> None:
    raise ReleaseViolation(code, cleanup_lease=cleanup_lease)


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


def _path_identity_matches_handle(
    snapshot: _FileSnapshot,
    handle_identity: tuple[int, ...],
    *,
    resource_type: str = "handle",
) -> bool:
    if resource_type == "fd":
        return snapshot.identity[:2] == handle_identity[:2]
    if os.name == "nt":
        if len(handle_identity) != 3:
            return False
        file_index = (int(handle_identity[1]) << 32) | int(handle_identity[2])
        return (
            int(snapshot.identity[0]) & 0xFFFFFFFF,
            int(snapshot.identity[1]),
        ) == (int(handle_identity[0]), file_index)
    if os.name == "posix":
        return snapshot.identity[:2] == handle_identity[:2]
    return False


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
    lease = _HandleOwnershipLedger()
    lease.register(int(handle), resource_type="directory")

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
    try:
        query_succeeded = bool(
            kernel32.GetFileInformationByHandle(handle, ctypes.byref(info))
        )
    except Exception as error:
        if not _close_ledger_handle(lease, int(handle), verify_identity=False):
            raise ReleaseViolation(
                "RELEASE_OUTPUT_PATH_INVALID", cleanup_lease=lease
            ) from error
        raise ReleaseViolation("RELEASE_OUTPUT_PATH_INVALID") from error
    if not query_succeeded:
        error_code = ctypes.get_last_error()
        if not _close_ledger_handle(lease, int(handle), verify_identity=False):
            raise ReleaseViolation(
                "RELEASE_OUTPUT_PATH_INVALID", cleanup_lease=lease
            )
        raise OSError(error_code, "GetFileInformationByHandle")
    identity = (
        int(info.volume_serial),
        int(info.file_index_high),
        int(info.file_index_low),
    )
    lease.set_identity(int(handle), identity)
    lease.release(int(handle))
    return (
        int(handle),
        identity,
    )


def _close_bound_handle(handle: int | None, *, resource_type: str = "handle") -> None:
    if handle is None:
        return
    if resource_type == "fd" or os.name != "nt":
        os.close(handle)
    else:
        import ctypes
        from ctypes import wintypes

        close_handle = ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL
        if not close_handle(handle):
            raise OSError(ctypes.get_last_error(), "CloseHandle")


def _close_ledger_handle(
    ledger: _HandleOwnershipLedger,
    handle: int | None,
    *,
    verify_identity: bool = True,
) -> bool:
    if handle is None:
        return True
    record = ledger.record(handle)
    if record is None:
        return True
    try:
        _close_bound_handle(handle, resource_type=record.resource_type)
    except Exception:
        # A second close is safe only when the original resource has a stable
        # identity and the numeric handle still names that same resource.
        if not verify_identity or record.identity is None:
            return False
        try:
            if (
                _bound_handle_identity(
                    handle, resource_type=record.resource_type
                )
                != record.identity
            ):
                return False
        except Exception:
            return False
        try:
            _close_bound_handle(handle, resource_type=record.resource_type)
        except Exception:
            return False
    ledger.release(handle)
    return True


def _close_ledger_handles(ledger: _HandleOwnershipLedger) -> bool:
    unresolved = False
    for handle in ledger.handles():
        if not _close_ledger_handle(ledger, handle):
            unresolved = True
    return unresolved


def _error_with_cleanup(
    error: BaseException, ledger: _HandleOwnershipLedger, fallback_code: str
) -> ReleaseViolation:
    code = error.code if isinstance(error, ReleaseViolation) else fallback_code
    existing_lease = getattr(error, "cleanup_lease", None)
    if isinstance(existing_lease, _HandleOwnershipLedger):
        if existing_lease is not ledger:
            existing_lease.adopt(ledger)
        return ReleaseViolation(code, cleanup_lease=existing_lease)
    return ReleaseViolation(code, cleanup_lease=ledger)


def _attach_cleanup_lease(
    error: BaseException,
    ledger: _HandleOwnershipLedger,
    fallback_code: str,
) -> BaseException:
    """Keep unresolved ownership reachable without replacing the primary code."""
    if not ledger.handles():
        return error
    if isinstance(error, ReleaseViolation):
        if error.cleanup_lease is None:
            error.cleanup_lease = ledger
        elif error.cleanup_lease is not ledger:
            error.cleanup_lease.adopt(ledger)
        return error
    if isinstance(error, Exception):
        return ReleaseViolation(fallback_code, cleanup_lease=ledger)
    existing_lease = getattr(error, "cleanup_lease", None)
    if isinstance(existing_lease, _HandleOwnershipLedger):
        if existing_lease is not ledger:
            existing_lease.adopt(ledger)
        return error
    try:
        setattr(error, "cleanup_lease", ledger)
    except Exception:
        return ReleaseViolation(fallback_code, cleanup_lease=ledger)
    return error


def _bound_handle_identity(
    handle: int,
    *,
    resource_type: str = "handle",
) -> tuple[int, ...]:
    if resource_type == "fd" or os.name != "nt":
        return _directory_identity(os.fstat(handle))
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
    raise OSError("unsupported handle resource type")


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
    lease = _HandleOwnershipLedger()
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
        lease.register(file_descriptor, resource_type="fd")
        handle_identity = _bound_handle_identity(
            file_descriptor, resource_type="fd"
        )
        lease.set_identity(file_descriptor, handle_identity)
        if not _path_identity_matches_handle(
            snapshot, handle_identity, resource_type="fd"
        ):
            _fail(code)
        stream = os.fdopen(file_descriptor, "rb", closefd=True)
        yield stream
        if _bound_handle_identity(file_descriptor, resource_type="fd") != handle_identity:
            _fail(code)
        if _has_reparse_component(snapshot.path) or _is_reparse_point(snapshot.path):
            _fail(code)
        if _file_identity(snapshot.path.stat()) != snapshot.identity:
            _fail(code)
    except ReleaseViolation as error:
        primary_error = error
        raise
    except Exception as error:
        primary_error = ReleaseViolation(code)
        raise primary_error from error
    except BaseException as error:
        primary_error = error
        raise
    finally:
        close_failed = False
        if stream is not None:
            try:
                stream.close()
            except Exception:
                close_failed = not _close_ledger_handle(lease, file_descriptor)
            else:
                lease.release(file_descriptor)
        elif file_descriptor is not None:
            close_failed = not _close_ledger_handle(lease, file_descriptor)
        if close_failed and primary_error is None:
            raise ReleaseViolation(
                "RELEASE_RESOURCE_CLOSE_FAILED", cleanup_lease=lease
            )
        if close_failed and isinstance(primary_error, Exception):
            raise _error_with_cleanup(primary_error, lease, code) from primary_error
        if close_failed and primary_error is not None:
            updated_error = _attach_cleanup_lease(primary_error, lease, code)
            if updated_error is not primary_error:
                raise updated_error from primary_error


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
    lease = (
        directory_token.ledger
        if directory_token is not None
        else _HandleOwnershipLedger()
    )
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
        if descriptor is None:
            _fail("RELEASE_OUTPUT_PATH_INVALID")
        lease.register(descriptor, resource_type="fd")
        descriptor_identity = _bound_handle_identity(
            descriptor, resource_type="fd"
        )
        lease.set_identity(descriptor, descriptor_identity)
        stream = os.fdopen(descriptor, "wb", closefd=True)
    except ReleaseViolation as error:
        if descriptor is not None and not _close_ledger_handle(lease, descriptor):
            raise _error_with_cleanup(
                error, lease, "RELEASE_OUTPUT_PATH_INVALID"
            ) from error
        raise
    except Exception as error:
        if descriptor is not None and not _close_ledger_handle(lease, descriptor):
            raise _error_with_cleanup(
                error, lease, "RELEASE_OUTPUT_PATH_INVALID"
            ) from error
        raise ReleaseViolation("RELEASE_OUTPUT_PATH_INVALID") from error
    except BaseException as error:
        if descriptor is not None and not _close_ledger_handle(lease, descriptor):
            updated_error = _attach_cleanup_lease(
                error, lease, "RELEASE_OUTPUT_PATH_INVALID"
            )
            if updated_error is not error:
                raise updated_error from error
        raise
    primary_error: BaseException | None = None
    try:
        if stream is None:
            _fail("RELEASE_OUTPUT_PATH_INVALID")
        yield stream
    except ReleaseViolation as error:
        primary_error = error
        raise
    except Exception as error:
        primary_error = ReleaseViolation("RELEASE_OUTPUT_PATH_INVALID")
        raise primary_error from error
    except BaseException as error:
        primary_error = error
        raise
    finally:
        try:
            stream.close()
        except Exception:
            close_failed = not _close_ledger_handle(lease, descriptor)
        else:
            lease.release(descriptor)
            close_failed = False
        if close_failed and primary_error is None:
            raise ReleaseViolation(
                "RELEASE_RESOURCE_CLOSE_FAILED", cleanup_lease=lease
            )
        if close_failed and isinstance(primary_error, Exception):
            raise _error_with_cleanup(
                primary_error, lease, "RELEASE_OUTPUT_PATH_INVALID"
            ) from primary_error
        if close_failed and primary_error is not None:
            updated_error = _attach_cleanup_lease(
                primary_error, lease, "RELEASE_OUTPUT_PATH_INVALID"
            )
            if updated_error is not primary_error:
                raise updated_error from primary_error


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
        handle: int | None = None
        lease = _HandleOwnershipLedger()
        try:
            handle = os.open(path, flags)
            lease.register(handle, resource_type="directory")
            identity = _bound_handle_identity(handle, resource_type="directory")
        except Exception as error:
            if handle is not None and not _close_ledger_handle(lease, handle):
                raise ReleaseViolation(
                    "RELEASE_OUTPUT_PATH_INVALID", cleanup_lease=lease
                ) from error
            raise ReleaseViolation("RELEASE_OUTPUT_PATH_INVALID") from error
        lease.set_identity(handle, identity)
        lease.release(handle)
        return handle, identity
    _fail("RELEASE_OUTPUT_PATH_INVALID")


def _bind_directory(path: Path, access: int) -> _DirectoryBinding:
    try:
        candidate = path.absolute()
        if _has_reparse_component(candidate) or _is_reparse_point(candidate):
            _fail("RELEASE_OUTPUT_PATH_INVALID")
        resolved = candidate.resolve(strict=True)
        if not resolved.is_dir():
            _fail("RELEASE_OUTPUT_PATH_INVALID")
        handle, identity = _open_bound_directory(resolved, access)
        binding = _DirectoryBinding(resolved, identity, handle)
        binding.ledger.set_identity(handle, identity)
        return binding
    except ReleaseViolation:
        raise
    except Exception as error:
        raise ReleaseViolation("RELEASE_OUTPUT_PATH_INVALID") from error


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
    native_lease = _HandleOwnershipLedger()

    def reject_native_handle() -> None:
        handle_value = native_handle.value
        if handle_value in (None, wintypes.HANDLE(-1).value):
            _fail("RELEASE_OUTPUT_PATH_INVALID")
        if not _close_ledger_handle(native_lease, int(handle_value)):
            raise ReleaseViolation(
                "RELEASE_OUTPUT_PATH_INVALID", cleanup_lease=native_lease
            )
        _fail("RELEASE_OUTPUT_PATH_INVALID")

    status: int | None = None
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
    except BaseException as error:
        handle_value = native_handle.value
        if handle_value not in (None, wintypes.HANDLE(-1).value):
            native_lease.register(int(handle_value), resource_type="handle")
        if handle_value in (None, wintypes.HANDLE(-1).value):
            if isinstance(error, Exception):
                raise ReleaseViolation(
                    "RELEASE_OUTPUT_PATH_INVALID"
                ) from error
            raise
        if _close_ledger_handle(native_lease, int(handle_value)):
            if isinstance(error, Exception):
                raise ReleaseViolation(
                    "RELEASE_OUTPUT_PATH_INVALID"
                ) from error
            raise
        updated_error = _attach_cleanup_lease(
            error, native_lease, "RELEASE_OUTPUT_PATH_INVALID"
        )
        if updated_error is not error:
            raise updated_error from error
        raise
    handle_value = native_handle.value
    if handle_value not in (None, wintypes.HANDLE(-1).value):
        native_lease.register(int(handle_value), resource_type="handle")
    if (
        status is None
        or int(status) < 0
        or io_status.status < 0
        or handle_value in (None, wintypes.HANDLE(-1).value)
    ):
        reject_native_handle()
    try:
        identity = _bound_handle_identity(
            int(handle_value), resource_type="directory"
        )
    except Exception:
        reject_native_handle()
    native_lease.set_identity(int(handle_value), identity)
    native_lease.release(int(handle_value))
    return int(handle_value), identity


def _snapshot_staging_directory(
    path: Path, prefix: str, parent_binding: _DirectoryBinding
) -> _StagingDirectoryToken:
    candidate = path.absolute()
    directory_handle: int | None = None
    directory_lease = _HandleOwnershipLedger()
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
        if (
            _bound_handle_identity(
                parent_binding.handle, resource_type="directory"
            )
            != parent_binding.identity
        ):
            _fail("RELEASE_OUTPUT_PATH_INVALID")
        if os.name == "posix":
            if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
                _fail("RELEASE_OUTPUT_PATH_INVALID")
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            directory_handle = os.open(
                candidate.name, flags, dir_fd=parent_binding.handle
            )
            directory_lease.register(directory_handle)
            identity = _bound_handle_identity(
                directory_handle, resource_type="directory"
            )
        elif os.name == "nt":
            directory_handle, identity = _ntdll_open_relative_directory(
                parent_binding.handle, candidate.name
            )
            directory_lease.register(directory_handle)
        else:
            _fail("RELEASE_OUTPUT_PATH_INVALID")
        current_info = candidate.lstat()
        if _file_identity(current_info) != _file_identity(info):
            _fail("RELEASE_OUTPUT_PATH_INVALID")
    except Exception as error:
        if directory_handle is not None and not _close_ledger_handle(
            directory_lease, directory_handle
        ):
            raise _error_with_cleanup(
                error, directory_lease, "RELEASE_OUTPUT_PATH_INVALID"
            ) from error
        if isinstance(error, ReleaseViolation):
            raise
        raise ReleaseViolation("RELEASE_OUTPUT_PATH_INVALID") from error
    except BaseException as error:
        if directory_handle is not None and not _close_ledger_handle(
            directory_lease, directory_handle
        ):
            updated_error = _attach_cleanup_lease(
                error, directory_lease, "RELEASE_OUTPUT_PATH_INVALID"
            )
            if updated_error is not error:
                raise updated_error from error
        raise
    if directory_handle is not None:
        directory_lease.release(directory_handle)
        parent_binding.ledger.register(directory_handle)
        parent_binding.ledger.set_identity(directory_handle, identity)
    return _StagingDirectoryToken(
        parent=parent,
        name=candidate.name,
        prefix=prefix,
        parent_identity=parent_binding.identity,
        identity=identity,
        is_reparse_point=False,
        parent_handle=parent_binding.handle,
        directory_handle=directory_handle,
        ledger=parent_binding.ledger,
    )


def _validated_staging_path(
    token: _StagingDirectoryToken, staged: Path, code: str
) -> Path:
    if token.parent_handle is None or token.directory_handle is None:
        _fail(code)
    current_handles: list[int] = []
    candidate: Path | None = None
    primary_error: BaseException | None = None
    try:
        candidate = staged.absolute()
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
        if (
            _bound_handle_identity(token.parent_handle, resource_type="directory")
            != token.parent_identity
        ):
            _fail(code)
        if (
            _bound_handle_identity(token.directory_handle, resource_type="directory")
            != token.identity
        ):
            _fail(code)
        current_parent_handle, current_parent_identity = _open_bound_directory(
            parent, 0
        )
        current_handles.append(current_parent_handle)
        token.ledger.register(current_parent_handle, resource_type="directory")
        token.ledger.set_identity(current_parent_handle, current_parent_identity)
        if current_parent_identity != token.parent_identity:
            _fail(code)
        current_handle, current_identity = _open_bound_directory(candidate, 0)
        current_handles.append(current_handle)
        token.ledger.register(current_handle, resource_type="directory")
        token.ledger.set_identity(current_handle, current_identity)
        if current_identity != token.identity:
            _fail(code)
    except ReleaseViolation as error:
        primary_error = error
    except Exception as error:
        primary_error = ReleaseViolation(code)
    except BaseException as error:
        primary_error = error
        raise
    finally:
        close_failed = False
        closed: set[int] = set()
        for handle in current_handles:
            if handle in closed:
                continue
            closed.add(handle)
            if not _close_ledger_handle(token.ledger, handle):
                close_failed = True
        if close_failed and primary_error is None:
            primary_error = ReleaseViolation(code, cleanup_lease=token.ledger)
        elif close_failed and isinstance(primary_error, Exception):
            primary_error = _error_with_cleanup(primary_error, token.ledger, code)
        elif close_failed and primary_error is not None:
            primary_error = _attach_cleanup_lease(
                primary_error, token.ledger, code
            )
    if primary_error is not None:
        raise primary_error
    assert candidate is not None
    return candidate


def _cleanup_path_still_bound(
    token: _StagingDirectoryToken, staged: Path
) -> bool:
    candidate = staged.absolute()
    handle: int | None = None
    close_confirmed = True
    result = False
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
            token.ledger.register(
                handle, resource_type="directory", identity=identity
            )
        elif os.name == "posix":
            if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
                return False
            handle = os.open(
                candidate,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
            token.ledger.register(handle, resource_type="directory")
            identity = _bound_handle_identity(handle, resource_type="directory")
            token.ledger.set_identity(handle, identity)
        else:
            return False
        result = identity == token.identity
    except ReleaseViolation as error:
        cleanup_lease = error.cleanup_lease
        if cleanup_lease is not None and cleanup_lease is not token.ledger:
            token.ledger.adopt(cleanup_lease)
        return False
    except (FileNotFoundError, OSError, ProfileViolation):
        return False
    finally:
        if handle is not None:
            close_confirmed = _close_ledger_handle(token.ledger, handle)
    return result and close_confirmed


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
    except Exception:
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
            token.ledger.register(child_handle)
            snapshot = _snapshot_file(entry, max_bytes=limit, code=code)
            try:
                record = token.ledger.record(child_handle)
                handle_identity = _bound_handle_identity(
                    child_handle,
                    resource_type=record.resource_type if record else "handle",
                )
            except Exception:
                _fail("RELEASE_ASSET_DIGEST_MISMATCH")
            token.ledger.set_identity(child_handle, handle_identity)
            if not _path_identity_matches_handle(
                snapshot,
                handle_identity,
                resource_type=record.resource_type if record else "handle",
            ):
                _fail("RELEASE_ASSET_DIGEST_MISMATCH")
            digest, _ = _digest_file(snapshot, max_bytes=limit, code=code)
            children.append(
                _StagedChildToken(entry.name, snapshot, digest, child_handle)
            )
        except BaseException as error:
            if isinstance(error, ReleaseViolation):
                primary_error = error
            elif isinstance(error, Exception):
                primary_error = ReleaseViolation(code)
            else:
                primary_error = error
            cleanup_children = list(children)
            if child_handle is not None and not any(
                child.handle == child_handle for child in cleanup_children
            ):
                cleanup_children.append(
                    _StagedChildToken(
                        entry.name,
                        _FileSnapshot(entry, (0, 0, 0, 0), 0),
                        "",
                        child_handle,
                    )
                )
            cleanup_token = replace(
                token,
                children=tuple(cleanup_children),
            )
            detached, cleanup_code = _close_staging_child_handles(cleanup_token)
            if cleanup_code is not None:
                raise _StagingBindingError(primary_error, detached) from error
            if primary_error is not error:
                raise primary_error from error
            raise
    return replace(token, children=tuple(sorted(children, key=lambda item: item.name)))


def _close_staging_child_handles(
    token: _StagingDirectoryToken,
) -> tuple[_StagingDirectoryToken, str | None]:
    failed = False
    attempted: set[int] = set()
    children: list[_StagedChildToken] = []
    for child in token.children:
        handle = child.handle
        if handle is None or handle in attempted:
            children.append(replace(child, handle=None))
            continue
        attempted.add(handle)
        close_confirmed = _close_ledger_handle(token.ledger, handle)
        if not close_confirmed:
            failed = True
        if close_confirmed:
            children.append(replace(child, handle=None))
        else:
            children.append(child)
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
            token.ledger.register(handle, resource_type="file")
            if not stat.S_ISREG(os.fstat(handle).st_mode):
                _fail(code)
            return handle
        except (FileNotFoundError, OSError, ReleaseViolation) as error:
            if handle is not None and not _close_ledger_handle(
                token.ledger, handle
            ):
                raise ReleaseViolation(
                    "RELEASE_RESOURCE_CLOSE_FAILED",
                    cleanup_lease=token.ledger,
                ) from error
            if isinstance(error, ReleaseViolation):
                raise
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
    except ReleaseViolation:
        raise
    except Exception as error:
        raise ReleaseViolation("RELEASE_OUTPUT_PATH_INVALID") from error
    expected = tuple(child.name for child in token.children)
    if tuple(sorted(entry.name for entry in entries)) != expected:
        _fail("RELEASE_MANIFEST_INVALID")
    for child in token.children:
        try:
            if child.handle is not None:
                record = token.ledger.record(child.handle)
                _bound_handle_identity(
                    child.handle,
                    resource_type=record.resource_type if record else "handle",
                )
            limit, code = _staging_file_limit(child.name)
            snapshot = _snapshot_file(path / child.name, max_bytes=limit, code=code)
            if snapshot.identity != child.snapshot.identity or snapshot.size != child.snapshot.size:
                _fail("RELEASE_ASSET_DIGEST_MISMATCH")
            digest, _ = _digest_file(snapshot, max_bytes=limit, code=code)
            if digest != child.digest:
                _fail("RELEASE_ASSET_DIGEST_MISMATCH")
        except ReleaseViolation:
            raise
        except Exception as error:
            code = _staging_file_limit(child.name)[1]
            raise ReleaseViolation(code) from error


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
    desired_access: int = 0x00000002 | 0x00000080 | 0x00000100 | 0x00100000,
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

    def close_failed_native_handle() -> bool:
        handle_value = native_handle.value
        if handle_value in (None, wintypes.HANDLE(-1).value):
            return True
        handle = int(handle_value)
        token.ledger.register(handle, resource_type="handle")
        return _close_ledger_handle(token.ledger, handle)

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
        if native_handle.value not in (None, wintypes.HANDLE(-1).value):
            token.ledger.register(int(native_handle.value), resource_type="handle")
        if not close_failed_native_handle():
            _fail(
                "RELEASE_OUTPUT_PATH_INVALID", cleanup_lease=token.ledger
            )
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    handle_value = native_handle.value
    if handle_value not in (None, wintypes.HANDLE(-1).value):
        token.ledger.register(int(handle_value), resource_type="handle")
    status_value = int(status)
    if status_value < 0 or io_status.status < 0:
        close_confirmed = close_failed_native_handle()
        if allow_missing and status_value in (-1073741772, -1073741766):
            if not close_confirmed:
                _fail(
                    "RELEASE_RESOURCE_CLOSE_FAILED",
                    cleanup_lease=token.ledger,
                )
            return None
        if not close_confirmed:
            _fail(
                "RELEASE_OUTPUT_PATH_INVALID", cleanup_lease=token.ledger
            )
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
        if not _close_ledger_handle(token.ledger, int(handle_value)):
            _fail(
                "RELEASE_OUTPUT_PATH_INVALID", cleanup_lease=token.ledger
            )
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    if descriptor < 0:
        if not _close_ledger_handle(token.ledger, int(handle_value)):
            _fail(
                "RELEASE_OUTPUT_PATH_INVALID", cleanup_lease=token.ledger
            )
        _fail("RELEASE_OUTPUT_PATH_INVALID")
    token.ledger.release(int(handle_value))
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
                    if not _close_ledger_handle(token.ledger, child_handle):
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
    if not _close_ledger_handle(binding.ledger, binding.handle):
        return "RELEASE_RESOURCE_CLOSE_FAILED"
    return None


def _close_staging_token(token: _StagingDirectoryToken | None) -> str | None:
    if token is None:
        return None
    failed = False
    handles = [child.handle for child in token.children]
    handles.extend((token.directory_handle, token.parent_handle))
    handles.extend(token.ledger.handles())
    attempted: set[int] = set()
    for handle in handles:
        if handle is None or handle in attempted:
            continue
        attempted.add(handle)
        if not _close_ledger_handle(token.ledger, handle):
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
    cleanup_lease: _HandleOwnershipLedger | None = None
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
        cleanup_token = getattr(error, "cleanup_token", None)
        if isinstance(cleanup_token, _StagingDirectoryToken):
            temporary_token = cleanup_token
        error_lease = getattr(error, "cleanup_lease", None)
        if isinstance(error_lease, _HandleOwnershipLedger):
            cleanup_lease = error_lease
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
        lease_close_code = None
        if cleanup_lease is not None and (
            temporary_token is None or cleanup_lease is not temporary_token.ledger
        ):
            lease_close_code = (
                "RELEASE_RESOURCE_CLOSE_FAILED"
                if _close_ledger_handles(cleanup_lease)
                else None
            )
        unbound_close_code = None
        if temporary_token is None:
            try:
                unbound_close_code = _close_directory_binding(parent_binding)
            except (OSError, ValueError, ReleaseViolation):
                unbound_close_code = "RELEASE_RESOURCE_CLOSE_FAILED"

        failed_ledgers: list[_HandleOwnershipLedger] = []
        if close_code is not None and temporary_token is not None:
            failed_ledgers.append(temporary_token.ledger)
        if lease_close_code is not None and cleanup_lease is not None:
            failed_ledgers.append(cleanup_lease)
        if unbound_close_code is not None and parent_binding is not None:
            failed_ledgers.append(parent_binding.ledger)

        attached_lease: _HandleOwnershipLedger | None = None
        for ledger in failed_ledgers:
            if ledger.handles():
                if attached_lease is None:
                    attached_lease = ledger
                elif attached_lease is not ledger:
                    attached_lease.adopt(ledger)

        if primary_error is None:
            if cleanup_code is not None:
                _fail(cleanup_code)
            if close_code is not None:
                if attached_lease is None:
                    _fail(close_code)
                _fail(close_code, cleanup_lease=attached_lease)
            if lease_close_code is not None:
                if attached_lease is None:
                    _fail(lease_close_code)
                _fail(lease_close_code, cleanup_lease=attached_lease)
            if unbound_close_code is not None:
                if attached_lease is None:
                    _fail(unbound_close_code)
                _fail(unbound_close_code, cleanup_lease=attached_lease)
        elif attached_lease is not None:
            updated_error = _attach_cleanup_lease(
                primary_error, attached_lease, "RELEASE_RESOURCE_CLOSE_FAILED"
            )
            if updated_error is not primary_error:
                raise updated_error from primary_error


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
