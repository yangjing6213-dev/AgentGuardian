"""Download one pinned MCP adapter without redirects or unbounded buffering."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


MAX_ADAPTER_BYTES = 64 * 1024 * 1024
_CHUNK_BYTES = 1024 * 1024
_ADAPTER_NAME = "AgentGuardianMcpAdapter.exe"


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _validate_url(url: str) -> None:
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
    except ValueError:
        host = None
        parsed = None
    if (
        parsed is None
        or parsed.scheme != "https"
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("trusted adapter URL must be an absolute HTTPS URL without credentials, query, or fragment")


def _validate_sha256(value: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError("trusted adapter SHA-256 must be exact lowercase hex")


def _is_reparse_point(path: Path) -> bool:
    if path.is_symlink():
        return True
    attributes = getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _has_reparse_component(path: Path) -> bool:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if _is_reparse_point(current):
            return True
    return False


def _is_unc(path: Path) -> bool:
    return path.anchor.startswith("\\\\") or os.fspath(path).startswith(("\\\\", "//"))


def _validate_windows_handle_path(handle: int, target: Path) -> None:
    from ctypes import wintypes

    get_final_path = ctypes.WinDLL(
        "kernel32", use_last_error=True
    ).GetFinalPathNameByHandleW
    get_final_path.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    get_final_path.restype = wintypes.DWORD
    required = get_final_path(handle, None, 0, 0)
    if not required:
        raise OSError(ctypes.get_last_error(), "trusted adapter final path query failed")
    buffer = ctypes.create_unicode_buffer(required + 1)
    written = get_final_path(handle, buffer, len(buffer), 0)
    if not written or written >= len(buffer):
        raise OSError(ctypes.get_last_error(), "trusted adapter final path query failed")
    expected = "\\\\?\\" + os.path.abspath(target)
    if os.path.normcase(buffer.value) != os.path.normcase(expected):
        raise ValueError("trusted adapter handle resolved outside the private directory")


@contextmanager
def _exclusive_binary_writer(target: Path):
    if sys.platform != "win32":
        output = target.open("xb")
        try:
            yield output
        except BaseException:
            try:
                output.close()
                target.unlink()
            except OSError as cleanup_error:
                raise RuntimeError("trusted adapter cleanup failed") from cleanup_error
            raise
        else:
            output.close()
        return

    import msvcrt
    from ctypes import wintypes

    class FileDispositionInfo(ctypes.Structure):
        _fields_ = [("delete_file", wintypes.BOOL)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    set_file_information = kernel32.SetFileInformationByHandle
    set_file_information.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    set_file_information.restype = wintypes.BOOL
    handle = create_file(
        str(target),
        0x80000000 | 0x40000000 | 0x00010000,
        0,
        None,
        1,
        0x00000080,
        None,
    )
    if handle in (None, ctypes.c_void_p(-1).value):
        raise OSError(ctypes.get_last_error(), "trusted adapter exclusive create failed")
    try:
        descriptor = msvcrt.open_osfhandle(int(handle), os.O_BINARY | os.O_RDWR)
    except OSError as error:
        if not close_handle(handle):
            raise RuntimeError("trusted adapter handle cleanup failed") from error
        raise
    try:
        output = os.fdopen(descriptor, "w+b", buffering=0)
    except Exception:
        os.close(descriptor)
        raise

    try:
        _validate_windows_handle_path(handle, target)
        yield output
        _validate_windows_handle_path(handle, target)
    except BaseException as error:
        disposition = FileDispositionInfo(True)
        marked = set_file_information(
            handle,
            4,
            ctypes.byref(disposition),
            ctypes.sizeof(disposition),
        )
        try:
            output.close()
        except OSError as close_error:
            raise RuntimeError("trusted adapter cleanup close failed") from close_error
        if not marked:
            raise RuntimeError("trusted adapter cleanup disposition failed") from error
        raise
    else:
        output.close()


def download_trusted_adapter(
    url: str,
    temporary_root: Path,
    expected_sha256: str,
    *,
    opener=None,
    max_bytes: int = MAX_ADAPTER_BYTES,
    timeout_seconds: int = 30,
) -> Path:
    _validate_url(url)
    _validate_sha256(expected_sha256)
    root = Path(temporary_root)
    if (
        not root.is_absolute()
        or _is_unc(root)
        or not root.is_dir()
        or _has_reparse_component(root)
    ):
        raise ValueError("trusted adapter temporary root is invalid or contains a reparse point")
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError("trusted adapter size limit is invalid")
    if type(timeout_seconds) is not int or timeout_seconds <= 0:
        raise ValueError("trusted adapter timeout is invalid")

    client = opener if opener is not None else build_opener(NoRedirectHandler())
    request = Request(url, headers={"User-Agent": "AgentGuardian-trusted-artifact/0.1"})
    private_root = Path(tempfile.mkdtemp(prefix="agentguardian-mcp-", dir=root))
    target = private_root / _ADAPTER_NAME
    try:
        if _has_reparse_component(private_root):
            raise ValueError("trusted adapter private directory contains a reparse point")
        with client.open(request, timeout=timeout_seconds) as response:
            if getattr(response, "status", None) != 200 or response.geturl() != url:
                raise ValueError("trusted adapter redirect or HTTP status is not allowed")
            declared_length = response.headers.get("Content-Length")
            if declared_length is not None:
                try:
                    declared_bytes = int(declared_length)
                except ValueError:
                    raise ValueError("trusted adapter Content-Length is invalid") from None
                if declared_bytes < 0 or declared_bytes > max_bytes:
                    raise ValueError("trusted adapter exceeds size limit")

            digest = hashlib.sha256()
            written = 0
            with _exclusive_binary_writer(target) as output:
                while chunk := response.read(min(_CHUNK_BYTES, max_bytes - written + 1)):
                    written += len(chunk)
                    if written > max_bytes:
                        raise ValueError("trusted adapter exceeds size limit")
                    digest.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
                if digest.hexdigest() != expected_sha256:
                    raise ValueError("trusted adapter SHA-256 does not match")
    except Exception as error:
        try:
            private_root.rmdir()
        except OSError as cleanup_error:
            cleanup_error = RuntimeError("trusted adapter private directory cleanup failed")
            raise cleanup_error from error
        raise
    return target


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--temporary-root", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    args = parser.parse_args()
    downloaded = download_trusted_adapter(args.url, args.temporary_root, args.expected_sha256)
    print(os.fspath(downloaded))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
