from __future__ import annotations

import ctypes
from ctypes import wintypes
import sys

from .evidence_state import MAX_STATE_BYTES


_UI_FORBIDDEN = 0x1
_DESCRIPTION = "AgentGuardian protected evidence state"


class DpapiError(RuntimeError):
    pass


class _DataBlob(ctypes.Structure):
    _fields_ = (
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    )


def protect_bytes(plaintext: bytes) -> bytes:
    if sys.platform != "win32":
        raise DpapiError("DPAPI_UNAVAILABLE")
    if type(plaintext) is not bytes or not plaintext or len(plaintext) > MAX_STATE_BYTES:
        raise DpapiError("DPAPI_PROTECT_FAILED")
    try:
        crypt32, kernel32 = _libraries()
        function = crypt32.CryptProtectData
        function.argtypes = (
            ctypes.POINTER(_DataBlob),
            wintypes.LPCWSTR,
            ctypes.POINTER(_DataBlob),
            wintypes.LPVOID,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(_DataBlob),
        )
        function.restype = wintypes.BOOL
        protected = _call(
            function,
            plaintext,
            kernel32,
            description=_DESCRIPTION,
            failure="DPAPI_PROTECT_FAILED",
        )
        if len(protected) > MAX_STATE_BYTES:
            raise DpapiError("DPAPI_PROTECT_FAILED")
        return protected
    except DpapiError:
        raise
    except Exception:  # noqa: BLE001 - native details must not escape.
        raise DpapiError("DPAPI_PROTECT_FAILED") from None


def unprotect_bytes(ciphertext: bytes) -> bytes:
    if sys.platform != "win32":
        raise DpapiError("DPAPI_UNAVAILABLE")
    if (
        type(ciphertext) is not bytes
        or not ciphertext
        or len(ciphertext) > MAX_STATE_BYTES
    ):
        raise DpapiError("PROTECTED_STATE_INVALID")
    try:
        crypt32, kernel32 = _libraries()
        function = crypt32.CryptUnprotectData
        function.argtypes = (
            ctypes.POINTER(_DataBlob),
            wintypes.LPVOID,
            ctypes.POINTER(_DataBlob),
            wintypes.LPVOID,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(_DataBlob),
        )
        function.restype = wintypes.BOOL
        plaintext = _call(
            function,
            ciphertext,
            kernel32,
            description=None,
            failure="PROTECTED_STATE_INVALID",
        )
        if len(plaintext) > MAX_STATE_BYTES:
            raise DpapiError("PROTECTED_STATE_INVALID")
        return plaintext
    except DpapiError:
        raise
    except Exception:  # noqa: BLE001 - native details must not escape.
        raise DpapiError("PROTECTED_STATE_INVALID") from None


def _libraries() -> tuple[object, object]:
    crypt32 = ctypes.WinDLL("Crypt32.dll", use_last_error=True)
    kernel32 = ctypes.WinDLL("Kernel32.dll", use_last_error=True)
    local_free = kernel32.LocalFree
    local_free.argtypes = (wintypes.LPVOID,)
    local_free.restype = wintypes.LPVOID
    return crypt32, kernel32


def _call(
    function: object,
    data: bytes,
    kernel32: object,
    *,
    description: str | None,
    failure: str,
) -> bytes:
    buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    input_blob = _DataBlob(
        len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
    )
    output_blob = _DataBlob()
    succeeded = function(
        ctypes.byref(input_blob),
        description,
        None,
        None,
        None,
        _UI_FORBIDDEN,
        ctypes.byref(output_blob),
    )
    try:
        if not succeeded or not output_blob.pbData or output_blob.cbData == 0:
            raise DpapiError(failure)
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        if output_blob.pbData:
            kernel32.LocalFree(output_blob.pbData)
