"""Local Authenticode verification for Windows adapter executables."""

from __future__ import annotations

from contextlib import contextmanager
import ctypes
from ctypes import wintypes
from collections.abc import Iterator
import hashlib
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


class _CertContext(ctypes.Structure):
    _fields_ = [
        ("encoding_type", wintypes.DWORD),
        ("cert_encoded", ctypes.POINTER(ctypes.c_ubyte)),
        ("cert_encoded_size", wintypes.DWORD),
        ("cert_info", ctypes.c_void_p),
        ("cert_store", ctypes.c_void_p),
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
_GENERIC_READ = 0x80000000
_FILE_SHARE_READ = 0x00000001
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_NORMAL = 0x00000080


def verify_authenticode(
    executable: pathlib.Path,
    *,
    file_handle: int | None = None,
) -> bool:
    """Return true only when Windows trusts the file's Authenticode signature.

    Verification is cache-only so this gate cannot turn adapter launch into a
    hidden certificate-network request. A missing provider or failed cleanup
    is treated as untrusted.
    """
    if sys.platform != "win32":
        return False
    if file_handle is not None and (type(file_handle) is not int or file_handle <= 0):
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
        file_handle=file_handle,
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


@contextmanager
def hold_executable_for_launch(executable: pathlib.Path) -> Iterator[int | None]:
    """Hold a Windows executable open without write/delete sharing.

    The handle spans hash, signature, and process creation so a same-user
    replacement cannot be swapped in between validation and launch.
    """
    if sys.platform != "win32":
        yield None
        return
    path = pathlib.Path(executable)
    try:
        if (
            not path.is_absolute()
            or path.is_symlink()
            or not stat.S_ISREG(path.stat().st_mode)
        ):
            raise OSError("invalid executable")
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
    except (AttributeError, OSError, ValueError) as exc:
        raise OSError("executable lock unavailable") from exc

    handle = create_file(
        str(path),
        _GENERIC_READ,
        _FILE_SHARE_READ,
        None,
        _OPEN_EXISTING,
        _FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if handle in (None, ctypes.c_void_p(-1).value):
        raise OSError("executable lock unavailable")
    try:
        yield int(handle)
    finally:
        if not close_handle(handle):
            raise OSError("executable lock cleanup failed")


def verify_authenticode_publisher(
    executable: pathlib.Path,
    allowed_publishers: tuple[str, ...],
    *,
    allowed_certificate_sha256: tuple[str, ...],
    signature_already_verified: bool = False,
) -> bool:
    """Require a trusted signature and exact subject plus certificate pins."""
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
    if (
        type(allowed_certificate_sha256) is not tuple
        or not allowed_certificate_sha256
        or any(
            type(digest) is not str
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            for digest in allowed_certificate_sha256
        )
    ):
        return False
    if type(signature_already_verified) is not bool:
        return False
    if not signature_already_verified and not verify_authenticode(executable):
        return False
    identity = _authenticode_identity(executable)
    return (
        identity is not None
        and identity[0] in allowed_publishers
        and identity[1] in allowed_certificate_sha256
    )


def _authenticode_subject(executable: pathlib.Path) -> str | None:
    identity = _authenticode_identity(executable)
    return identity[0] if identity is not None else None


def _authenticode_certificate_sha256(executable: pathlib.Path) -> str | None:
    identity = _authenticode_identity(executable)
    return identity[1] if identity is not None else None


def _authenticode_identity(executable: pathlib.Path) -> tuple[str, str] | None:
    """Extract the signer's X.500 subject and DER SHA-256 from Crypt32."""
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

    try:
        with _open_embedded_signature(query, path, close_message, close_store) as (
            cert_store,
            message,
        ):
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
            with _held_certificate(certificate, free_certificate):
                x500_name_type = wintypes.DWORD(_CERT_X500_NAME_STR)
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
                cert_context = ctypes.cast(
                    certificate,
                    ctypes.POINTER(_CertContext),
                ).contents
                if not cert_context.cert_encoded or not cert_context.cert_encoded_size:
                    return None
                der = ctypes.string_at(
                    cert_context.cert_encoded,
                    cert_context.cert_encoded_size,
                )
                subject = name.value
                if not subject:
                    return None
                return subject, hashlib.sha256(der).hexdigest()
    except (OSError, ctypes.ArgumentError, ValueError):
        return None


@contextmanager
def _open_embedded_signature(query, path: pathlib.Path, close_message, close_store):
    encoding = wintypes.DWORD()
    content_type = wintypes.DWORD()
    format_type = wintypes.DWORD()
    cert_store = ctypes.c_void_p()
    message = ctypes.c_void_p()
    context = ctypes.c_void_p()
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
        raise OSError("embedded signature query failed")
    if not cert_store.value or not message.value:
        raise OSError("embedded signature handles unavailable")
    try:
        yield cert_store, message
    finally:
        cleanup_failed = False
        try:
            if message.value and not close_message(message):
                cleanup_failed = True
        except (OSError, ctypes.ArgumentError):
            cleanup_failed = True
        try:
            if cert_store.value and not close_store(
                cert_store, _CERT_CLOSE_STORE_CHECK_FLAG
            ):
                cleanup_failed = True
        except (OSError, ctypes.ArgumentError):
            cleanup_failed = True
        if cleanup_failed:
            raise OSError("embedded signature cleanup failed")


@contextmanager
def _held_certificate(certificate, free_certificate):
    try:
        yield
    finally:
        try:
            if not free_certificate(certificate):
                raise OSError("certificate cleanup failed")
        except (OSError, ctypes.ArgumentError) as exc:
            raise OSError("certificate cleanup failed") from exc
