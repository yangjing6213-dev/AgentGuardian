from __future__ import annotations

from collections.abc import Callable
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import stat

from .evidence_state import (
    MAX_STATE_BYTES,
    EvidenceSnapshot,
    EvidenceStateError,
    decode_snapshot,
    encode_snapshot,
)
from .windows_dpapi import DpapiError, protect_bytes, unprotect_bytes


STATE_FILENAME = "evidence-state-v1.bin"
_APP_DIRECTORY = "AgentGuardian"
_ENVELOPE_MAGIC = b"AGSE\x01"
_DIGEST_BYTES = hashlib.sha256().digest_size
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)


class StateStoreError(RuntimeError):
    pass


def default_state_path() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data or _is_unc_path(local_app_data):
        raise StateStoreError("PROTECTED_STATE_UNAVAILABLE")
    root = Path(local_app_data)
    if not root.is_absolute():
        raise StateStoreError("PROTECTED_STATE_UNAVAILABLE")
    return root / _APP_DIRECTORY / STATE_FILENAME


def purge_protected_state() -> bool:
    try:
        target = default_state_path()
        parent = target.parent
        if _has_reparse_ancestor(parent) or _is_reparse(target):
            raise StateStoreError("PROTECTED_STATE_PURGE_FAILED")
        if not parent.exists():
            return False
        if (
            not parent.is_dir()
            or target.resolve(strict=False).parent != parent.resolve(strict=True)
        ):
            raise StateStoreError("PROTECTED_STATE_PURGE_FAILED")
        if os.name == "nt":
            return _purge_windows_target(target, parent)
        return _purge_posix_target(target, parent)
    except StateStoreError:
        raise StateStoreError("PROTECTED_STATE_PURGE_FAILED") from None
    except OSError:
        raise StateStoreError("PROTECTED_STATE_PURGE_FAILED") from None


def _purge_posix_target(target: Path, parent: Path) -> bool:
    parent_fd: int | None = None
    primary_error: BaseException | None = None
    result = False
    try:
        if (
            target.name != STATE_FILENAME
            or target.parent.absolute() != parent.absolute()
            or not hasattr(os, "O_DIRECTORY")
            or not hasattr(os, "O_NOFOLLOW")
        ):
            raise StateStoreError("PROTECTED_STATE_PURGE_FAILED")
        parent_fd = os.open(
            parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        parent_info = os.fstat(parent_fd)
        visible_parent = os.stat(parent, follow_symlinks=False)
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or not stat.S_ISDIR(visible_parent.st_mode)
            or _directory_identity(parent_info) != _directory_identity(visible_parent)
        ):
            raise StateStoreError("PROTECTED_STATE_PURGE_FAILED")
        try:
            target_info = os.stat(
                STATE_FILENAME,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            result = False
        else:
            if not stat.S_ISREG(target_info.st_mode):
                raise StateStoreError("PROTECTED_STATE_PURGE_FAILED")
            os.unlink(STATE_FILENAME, dir_fd=parent_fd)
            result = True
    except StateStoreError as error:
        primary_error = error
    except OSError:
        primary_error = StateStoreError("PROTECTED_STATE_PURGE_FAILED")
    finally:
        if parent_fd is not None:
            try:
                os.close(parent_fd)
            except Exception:
                if primary_error is None:
                    primary_error = StateStoreError(
                        "PROTECTED_STATE_PURGE_FAILED"
                    )
    if primary_error is not None:
        raise primary_error
    return result


def _purge_windows_target(target: Path, parent: Path) -> bool:
    # Handles pin both objects and deny concurrent rename/delete before disposition.
    import ctypes
    from ctypes import wintypes

    class ByHandleFileInformation(ctypes.Structure):
        _fields_ = (
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        )

    class FileDispositionInformation(ctypes.Structure):
        _fields_ = (("DeleteFile", ctypes.c_ubyte),)

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(ByHandleFileInformation),
    )
    get_information.restype = wintypes.BOOL
    get_final_path = kernel32.GetFinalPathNameByHandleW
    get_final_path.argtypes = (
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    )
    get_final_path.restype = wintypes.DWORD
    set_information = kernel32.SetFileInformationByHandle
    set_information.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    )
    set_information.restype = wintypes.BOOL

    invalid_handle = ctypes.c_void_p(-1).value
    file_read_attributes = 0x0080
    delete = 0x00010000
    share_read_write = 0x00000003
    open_existing = 3
    open_reparse_point = 0x00200000
    backup_semantics = 0x02000000
    directory_attribute = 0x00000010
    reparse_attribute = 0x00000400
    file_disposition_info = 4
    not_found_errors = {2, 3}
    open_flags = open_reparse_point | backup_semantics

    def open_handle(path: Path, access: int) -> int:
        return create_file(
            os.fspath(path),
            access,
            share_read_write,
            None,
            open_existing,
            open_flags,
            None,
        )

    def close_checked(handle: int) -> None:
        if not close_handle(handle):
            raise OSError(ctypes.get_last_error(), "close failed")

    def attributes(handle: int) -> int:
        information = ByHandleFileInformation()
        if not get_information(handle, ctypes.byref(information)):
            raise OSError(ctypes.get_last_error(), "attribute query failed")
        return information.dwFileAttributes

    def final_path(handle: int) -> str:
        buffer = ctypes.create_unicode_buffer(32_768)
        length = get_final_path(handle, buffer, len(buffer), 0)
        if not length or length >= len(buffer):
            raise OSError(ctypes.get_last_error(), "path query failed")
        value = buffer.value
        if value.startswith("\\\\?\\UNC\\"):
            value = "\\\\" + value[8:]
        elif value.startswith("\\\\?\\"):
            value = value[4:]
        return os.path.normcase(os.path.normpath(value))

    parent_handle = open_handle(parent, file_read_attributes)
    if parent_handle == invalid_handle:
        error = ctypes.get_last_error()
        if error in not_found_errors:
            return False
        raise OSError(error, "parent open failed")
    primary_error: BaseException | None = None
    result = True
    try:
        parent_attributes = attributes(parent_handle)
        if (
            not parent_attributes & directory_attribute
            or parent_attributes & reparse_attribute
        ):
            raise StateStoreError("PROTECTED_STATE_PURGE_FAILED")
        actual_parent = final_path(parent_handle)
        expected_parent = os.path.normcase(
            os.path.normpath(os.path.abspath(os.fspath(parent)))
        )
        if actual_parent != expected_parent:
            raise StateStoreError("PROTECTED_STATE_PURGE_FAILED")

        target_handle = open_handle(target, delete | file_read_attributes)
        if target_handle == invalid_handle:
            error = ctypes.get_last_error()
            if error in not_found_errors:
                result = False
            else:
                raise OSError(error, "target open failed")
        else:
            try:
                target_attributes = attributes(target_handle)
                if target_attributes & (directory_attribute | reparse_attribute):
                    raise StateStoreError("PROTECTED_STATE_PURGE_FAILED")
                actual_target = final_path(target_handle)
                if (
                    os.path.dirname(actual_target) != actual_parent
                    or os.path.basename(actual_target).casefold()
                    != STATE_FILENAME.casefold()
                ):
                    raise StateStoreError("PROTECTED_STATE_PURGE_FAILED")
                disposition = FileDispositionInformation(1)
                if not set_information(
                    target_handle,
                    file_disposition_info,
                    ctypes.byref(disposition),
                    ctypes.sizeof(disposition),
                ):
                    raise OSError(ctypes.get_last_error(), "delete failed")
            except BaseException as error:
                primary_error = error
            finally:
                try:
                    close_checked(target_handle)
                except Exception:
                    if primary_error is None:
                        primary_error = StateStoreError(
                            "PROTECTED_STATE_PURGE_FAILED"
                        )
    except BaseException as error:
        if primary_error is None:
            primary_error = error
    finally:
        try:
            close_checked(parent_handle)
        except Exception:
            if primary_error is None:
                primary_error = StateStoreError("PROTECTED_STATE_PURGE_FAILED")
    if primary_error is not None:
        raise primary_error
    return result


def save_protected_state(
    snapshot: EvidenceSnapshot,
    *,
    directory: str | Path | None = None,
    protect: Callable[[bytes], bytes] = protect_bytes,
) -> None:
    try:
        plaintext = encode_snapshot(snapshot)
        ciphertext = protect(_seal_payload(plaintext))
        if (
            type(ciphertext) is not bytes
            or not ciphertext
            or len(ciphertext) > MAX_STATE_BYTES
        ):
            raise StateStoreError("PROTECTED_STATE_SAVE_FAILED")
    except DpapiError as error:
        if str(error) == "DPAPI_UNAVAILABLE":
            raise StateStoreError("PROTECTED_STATE_UNAVAILABLE") from None
        raise StateStoreError("PROTECTED_STATE_SAVE_FAILED") from None
    except EvidenceStateError:
        raise StateStoreError("PROTECTED_STATE_SAVE_FAILED") from None
    except StateStoreError:
        raise
    except Exception:  # noqa: BLE001 - callbacks must not leak details.
        raise StateStoreError("PROTECTED_STATE_SAVE_FAILED") from None

    temporary: Path | None = None
    try:
        target = _target_path(directory, create=True)
        source_parent = target.parent
        parent = source_parent.resolve(strict=True)
        if (
            _is_unc_path(parent)
            or _has_reparse_ancestor(source_parent)
            or _is_reparse(target)
            or target.resolve(strict=False).parent != parent
        ):
            raise StateStoreError("PROTECTED_STATE_SAVE_FAILED")

        temporary = parent / f".{STATE_FILENAME}.{secrets.token_hex(16)}.tmp"
        if temporary.resolve(strict=False).parent != parent:
            raise StateStoreError("PROTECTED_STATE_SAVE_FAILED")
        with open(temporary, "xb") as stream:
            stream.write(ciphertext)
            stream.flush()
            os.fsync(stream.fileno())

        if (
            _is_unc_path(parent)
            or _has_reparse_ancestor(source_parent)
            or parent.resolve(strict=True) != source_parent.resolve(strict=True)
            or _is_reparse(target)
            or target.resolve(strict=False).parent != parent
        ):
            raise StateStoreError("PROTECTED_STATE_SAVE_FAILED")
        os.replace(temporary, target)
        temporary = None
    except StateStoreError:
        raise
    except Exception:  # noqa: BLE001 - paths and OS errors must not escape.
        raise StateStoreError("PROTECTED_STATE_SAVE_FAILED") from None
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def load_protected_state(
    *,
    directory: str | Path | None = None,
    unprotect: Callable[[bytes], bytes] = unprotect_bytes,
) -> EvidenceSnapshot:
    try:
        target = _target_path(directory, create=False)
    except StateStoreError as error:
        if str(error) == "PROTECTED_STATE_UNAVAILABLE":
            raise
        raise StateStoreError("PROTECTED_STATE_INVALID") from None

    try:
        source_parent = target.parent
        parent = source_parent.resolve(strict=True)
        if (
            _is_unc_path(parent)
            or _has_reparse_ancestor(source_parent)
            or _is_reparse(target)
            or target.resolve(strict=True).parent != parent
        ):
            raise StateStoreError("PROTECTED_STATE_INVALID")
        with open(target, "rb") as stream:
            ciphertext = stream.read(MAX_STATE_BYTES + 1)
        if not ciphertext or len(ciphertext) > MAX_STATE_BYTES:
            raise StateStoreError("PROTECTED_STATE_INVALID")
        plaintext = unprotect(ciphertext)
        if type(plaintext) is not bytes:
            raise StateStoreError("PROTECTED_STATE_INVALID")
        return decode_snapshot(_open_payload(plaintext))
    except FileNotFoundError:
        raise StateStoreError("PROTECTED_STATE_UNAVAILABLE") from None
    except DpapiError as error:
        if str(error) == "DPAPI_UNAVAILABLE":
            raise StateStoreError("PROTECTED_STATE_UNAVAILABLE") from None
        raise StateStoreError("PROTECTED_STATE_INVALID") from None
    except (EvidenceStateError, StateStoreError):
        raise
    except Exception:  # noqa: BLE001 - paths and OS errors must not escape.
        raise StateStoreError("PROTECTED_STATE_INVALID") from None


def _target_path(directory: str | Path | None, *, create: bool) -> Path:
    if directory is None:
        target = default_state_path()
        parent = target.parent
    else:
        parent = Path(directory)
        target = parent / STATE_FILENAME
    if (
        not parent.is_absolute()
        or _is_unc_path(parent)
        or _has_reparse_ancestor(parent)
    ):
        raise StateStoreError("PROTECTED_STATE_SAVE_FAILED")
    if create and not parent.exists():
        ancestor = parent.parent
        if not ancestor.is_dir() or _has_reparse_ancestor(ancestor):
            raise StateStoreError("PROTECTED_STATE_SAVE_FAILED")
        parent.mkdir(mode=0o700, exist_ok=True)
    if not parent.is_dir() or _has_reparse_ancestor(parent):
        code = "PROTECTED_STATE_SAVE_FAILED" if create else "PROTECTED_STATE_UNAVAILABLE"
        raise StateStoreError(code)
    if target.name != STATE_FILENAME:
        raise StateStoreError("PROTECTED_STATE_SAVE_FAILED")
    return target


def _is_unc_path(path: str | Path) -> bool:
    value = os.fspath(path)
    return value.startswith(("\\\\", "//"))


def _seal_payload(plaintext: bytes) -> bytes:
    if len(plaintext) + len(_ENVELOPE_MAGIC) + _DIGEST_BYTES > MAX_STATE_BYTES:
        raise StateStoreError("PROTECTED_STATE_SAVE_FAILED")
    return _ENVELOPE_MAGIC + hashlib.sha256(plaintext).digest() + plaintext


def _open_payload(envelope: bytes) -> bytes:
    header_size = len(_ENVELOPE_MAGIC) + _DIGEST_BYTES
    if len(envelope) <= header_size or not envelope.startswith(_ENVELOPE_MAGIC):
        raise StateStoreError("PROTECTED_STATE_INVALID")
    expected = envelope[len(_ENVELOPE_MAGIC) : header_size]
    plaintext = envelope[header_size:]
    if not hmac.compare_digest(expected, hashlib.sha256(plaintext).digest()):
        raise StateStoreError("PROTECTED_STATE_INVALID")
    return plaintext


def _is_reparse(path: str | Path) -> bool:
    try:
        path_stat = os.lstat(path)
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(path_stat.st_mode) or bool(
        getattr(path_stat, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _has_reparse_ancestor(path: str | Path) -> bool:
    current = Path(path)
    while True:
        if _is_reparse(current):
            return True
        parent = current.parent
        if parent == current:
            return False
        current = parent
