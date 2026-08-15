"""Local Authenticode verification for Windows adapter executables."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import pathlib
import stat
import sys


class _Guid(ctypes.Structure):
    _fields_ = [
        ("data1", wintypes.DWORD),
        ("data2", wintypes.WORD),
        ("data3", wintypes.WORD),
        ("data4", ctypes.c_ubyte * 8),
    ]


class _WintrustFileInfo(ctypes.Structure):
    _fields_ = [
        ("cb_struct", wintypes.DWORD),
        ("file_path", wintypes.LPCWSTR),
        ("file_handle", wintypes.HANDLE),
        ("known_subject", ctypes.POINTER(_Guid)),
    ]


class _WintrustData(ctypes.Structure):
    _fields_ = [
        ("cb_struct", wintypes.DWORD),
        ("policy_callback_data", ctypes.c_void_p),
        ("sip_client_data", ctypes.c_void_p),
        ("ui_choice", wintypes.DWORD),
        ("revocation_checks", wintypes.DWORD),
        ("union_choice", wintypes.DWORD),
        ("file_info", ctypes.POINTER(_WintrustFileInfo)),
        ("state_action", wintypes.DWORD),
        ("state_data", wintypes.HANDLE),
        ("url_reference", wintypes.LPWSTR),
        ("provider_flags", wintypes.DWORD),
        ("ui_context", wintypes.DWORD),
        ("signature_settings", ctypes.c_void_p),
    ]


_WINTRUST_ACTION_GENERIC_VERIFY_V2 = _Guid(
    0x00AAC56B,
    0xCD44,
    0x11D0,
    (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
)
_WTD_UI_NONE = 2
_WTD_CHOICE_FILE = 1
_WTD_STATEACTION_VERIFY = 1
_WTD_STATEACTION_CLOSE = 2
_WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000


def verify_authenticode(executable: pathlib.Path) -> bool:
    """Return true only when Windows trusts the file's Authenticode signature.

    Verification is cache-only so this gate cannot turn adapter launch into a
    hidden certificate-network request. A missing provider or failed cleanup
    is treated as untrusted.
    """
    if sys.platform != "win32":
        return False
    path = pathlib.Path(executable)
    try:
        if (
            not path.is_absolute()
            or path.is_symlink()
            or not stat.S_ISREG(path.stat().st_mode)
        ):
            return False
        wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
        verify = wintrust.WinVerifyTrust
        verify.argtypes = [ctypes.c_void_p, ctypes.POINTER(_Guid), ctypes.c_void_p]
        verify.restype = wintypes.LONG
    except (AttributeError, OSError, ValueError):
        return False

    file_info = _WintrustFileInfo(
        cb_struct=ctypes.sizeof(_WintrustFileInfo),
        file_path=str(path),
        file_handle=None,
        known_subject=None,
    )
    data = _WintrustData(
        cb_struct=ctypes.sizeof(_WintrustData),
        policy_callback_data=None,
        sip_client_data=None,
        ui_choice=_WTD_UI_NONE,
        revocation_checks=0,
        union_choice=_WTD_CHOICE_FILE,
        file_info=ctypes.pointer(file_info),
        state_action=_WTD_STATEACTION_VERIFY,
        state_data=None,
        url_reference=None,
        provider_flags=_WTD_CACHE_ONLY_URL_RETRIEVAL,
        ui_context=0,
        signature_settings=None,
    )
    try:
        result = verify(ctypes.c_void_p(-1), ctypes.byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(data))
        data.state_action = _WTD_STATEACTION_CLOSE
        cleanup = verify(
            ctypes.c_void_p(-1),
            ctypes.byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2),
            ctypes.byref(data),
        )
    except (OSError, ctypes.ArgumentError):
        return False
    return result == 0 and cleanup == 0
