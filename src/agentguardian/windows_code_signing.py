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

_CERT_QUERY_OBJECT_FILE = 1
_CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 1 << 10
_CERT_QUERY_FORMAT_FLAG_BINARY = 2
_CMSG_SIGNER_CERT_INFO_PARAM = 7
_X509_ASN_ENCODING = 0x00000001
_PKCS_7_ASN_ENCODING = 0x00010000
_CERT_FIND_SUBJECT_CERT = 11 << 16
_CERT_NAME_RDN_TYPE = 2
_CERT_X500_NAME_STR = 3
_CERT_CLOSE_STORE_CHECK_FLAG = 0x00000002


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


def verify_authenticode_publisher(
    executable: pathlib.Path,
    allowed_publishers: tuple[str, ...],
) -> bool:
    """Return true only when a trusted signature has an exact subject match.

    The subject is read from the embedded PKCS#7 signature through Crypt32;
    no certificate or revocation network request is made here. The caller
    remains responsible for supplying an explicit, reviewed allowlist.
    """
    if type(allowed_publishers) is not tuple or not allowed_publishers:
        return False
    if any(
        type(subject) is not str
        or not subject
        or "\x00" in subject
        or subject != subject.strip()
        for subject in allowed_publishers
    ):
        return False
    if not verify_authenticode(executable):
        return False
    subject = _authenticode_subject(executable)
    return subject is not None and subject in allowed_publishers


def _authenticode_subject(executable: pathlib.Path) -> str | None:
    """Extract the signer's X.500 subject from an embedded signature."""
    if sys.platform != "win32":
        return None
    path = pathlib.Path(executable)
    try:
        if (
            not path.is_absolute()
            or path.is_symlink()
            or not stat.S_ISREG(path.stat().st_mode)
        ):
            return None
        crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        query = crypt32.CryptQueryObject
        query.argtypes = [
            wintypes.DWORD,
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
        ]
        query.restype = wintypes.BOOL
        get_param = crypt32.CryptMsgGetParam
        get_param.argtypes = [
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.DWORD),
        ]
        get_param.restype = wintypes.BOOL
        find_certificate = crypt32.CertFindCertificateInStore
        find_certificate.argtypes = [
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        find_certificate.restype = ctypes.c_void_p
        get_name = crypt32.CertGetNameStringW
        get_name.argtypes = [
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.LPWSTR,
            wintypes.DWORD,
        ]
        get_name.restype = wintypes.DWORD
        free_certificate = crypt32.CertFreeCertificateContext
        free_certificate.argtypes = [ctypes.c_void_p]
        free_certificate.restype = wintypes.BOOL
        close_message = crypt32.CryptMsgClose
        close_message.argtypes = [ctypes.c_void_p]
        close_message.restype = wintypes.BOOL
        close_store = crypt32.CertCloseStore
        close_store.argtypes = [ctypes.c_void_p, wintypes.DWORD]
        close_store.restype = wintypes.BOOL
    except (AttributeError, OSError, ValueError):
        return None

    encoding = wintypes.DWORD()
    content_type = wintypes.DWORD()
    format_type = wintypes.DWORD()
    cert_store = ctypes.c_void_p()
    message = ctypes.c_void_p()
    context = ctypes.c_void_p()
    x500_name_type = wintypes.DWORD(_CERT_X500_NAME_STR)
    try:
        if not query(
            _CERT_QUERY_OBJECT_FILE,
            str(path),
            _CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            _CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            ctypes.byref(encoding),
            ctypes.byref(content_type),
            ctypes.byref(format_type),
            ctypes.byref(cert_store),
            ctypes.byref(message),
            ctypes.byref(context),
        ):
            return None
        if not cert_store.value or not message.value:
            return None
        signer_size = wintypes.DWORD()
        if not get_param(
            message,
            _CMSG_SIGNER_CERT_INFO_PARAM,
            0,
            None,
            ctypes.byref(signer_size),
        ) or not signer_size.value:
            return None
        signer_info = ctypes.create_string_buffer(signer_size.value)
        if not get_param(
            message,
            _CMSG_SIGNER_CERT_INFO_PARAM,
            0,
            ctypes.cast(signer_info, ctypes.c_void_p),
            ctypes.byref(signer_size),
        ):
            return None
        certificate = find_certificate(
            cert_store,
            _X509_ASN_ENCODING | _PKCS_7_ASN_ENCODING,
            0,
            _CERT_FIND_SUBJECT_CERT,
            ctypes.cast(signer_info, ctypes.c_void_p),
            None,
        )
        if not certificate:
            return None
        try:
            name_size = get_name(
                certificate,
                _CERT_NAME_RDN_TYPE,
                0,
                ctypes.byref(x500_name_type),
                None,
                0,
            )
            if name_size <= 1:
                return None
            name = ctypes.create_unicode_buffer(name_size)
            if not get_name(
                certificate,
                _CERT_NAME_RDN_TYPE,
                0,
                ctypes.byref(x500_name_type),
                name,
                name_size,
            ):
                return None
            return name.value or None
        finally:
            free_certificate(certificate)
    except (OSError, ctypes.ArgumentError, ValueError):
        return None
    finally:
        if message.value:
            close_message(message)
        if cert_store.value:
            close_store(cert_store, _CERT_CLOSE_STORE_CHECK_FLAG)
