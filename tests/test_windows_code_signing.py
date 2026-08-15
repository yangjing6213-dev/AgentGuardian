from __future__ import annotations

import ctypes
from ctypes import wintypes
import sys
import os
from pathlib import Path

import pytest

import agentguardian.windows_code_signing as signing
from agentguardian.windows_code_signing import verify_authenticode, verify_authenticode_publisher


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Authenticode verification is only available on Windows",
)


def _replace_with_posix_semantics(source: Path, destination: Path) -> None:
    filename = str(destination)

    class RenameInfo(ctypes.Structure):
        _fields_ = [
            ("flags", wintypes.DWORD),
            ("root_directory", wintypes.HANDLE),
            ("filename_length", wintypes.DWORD),
            ("filename", wintypes.WCHAR * len(filename)),
        ]

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
    set_file_info = kernel32.SetFileInformationByHandle
    set_file_info.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    set_file_info.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    handle = create_file(
        str(source),
        0x00010000,
        0x00000001 | 0x00000002 | 0x00000004,
        None,
        3,
        0x00000080,
        None,
    )
    if handle in (None, ctypes.c_void_p(-1).value):
        raise OSError(ctypes.get_last_error(), "replacement open failed")
    info = RenameInfo(
        flags=0x1 | 0x2,
        root_directory=None,
        filename_length=len(filename.encode("utf-16-le")),
        filename=filename,
    )
    try:
        if not set_file_info(handle, 22, ctypes.byref(info), ctypes.sizeof(info)):
            raise OSError(ctypes.get_last_error(), "POSIX replacement failed")
    finally:
        assert close_handle(handle)


def test_authenticode_accepts_a_trusted_system_binary() -> None:
    assert verify_authenticode(Path(sys.executable)) is True


def test_executable_launch_lock_returns_a_native_handle() -> None:
    with signing.hold_executable_for_launch(Path(sys.executable)) as handle:
        assert type(handle) is int
        assert handle > 0
        assert verify_authenticode(Path(sys.executable), file_handle=handle) is True


def test_authenticode_binds_the_provided_handle_to_wintrust(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "adapter.exe"
    executable.write_bytes(b"MZ synthetic")
    observed_handles = []

    class FakeVerify:
        argtypes = None
        restype = None

        def __call__(self, _window, _action, data_pointer):
            data = signing.ctypes.cast(
                data_pointer,
                signing.ctypes.POINTER(signing._WintrustData),
            ).contents
            observed_handles.append(data.file_info.contents.file_handle)
            return 0

    class FakeWintrust:
        WinVerifyTrust = FakeVerify()

    monkeypatch.setattr(
        signing.ctypes,
        "WinDLL",
        lambda _name, use_last_error=True: FakeWintrust(),
    )

    assert verify_authenticode(executable, file_handle=1234) is True
    assert observed_handles == [1234, 1234]


def test_publisher_verification_accepts_the_exact_subject_of_a_trusted_binary() -> None:
    executable = Path(sys.executable)
    identity = signing._authenticode_identity(executable)
    assert identity is not None
    subject, certificate_sha256 = identity
    assert verify_authenticode_publisher(
        executable,
        (subject,),
        allowed_certificate_sha256=(certificate_sha256,),
    ) is True
    assert verify_authenticode_publisher(
        executable,
        (subject,),
        allowed_certificate_sha256=("0" * 64,),
    ) is False


def test_authenticode_rejects_an_unsigned_file(tmp_path: Path) -> None:
    executable = tmp_path / "unsigned.exe"
    executable.write_bytes(b"MZ synthetic unsigned executable")
    assert verify_authenticode(executable) is False


def test_executable_launch_lock_blocks_write_and_replacement(tmp_path: Path) -> None:
    executable = tmp_path / "adapter.exe"
    replacement = tmp_path / "replacement.exe"
    executable.write_bytes(b"original")
    replacement.write_bytes(b"replacement")

    with signing.hold_executable_for_launch(executable):
        with pytest.raises(OSError):
            executable.write_bytes(b"changed")
        with pytest.raises(OSError):
            os.replace(replacement, executable)
        assert executable.read_bytes() == b"original"

    os.replace(replacement, executable)
    assert executable.read_bytes() == b"replacement"


def test_executable_launch_lock_blocks_parent_directory_replacement(
    tmp_path: Path,
) -> None:
    active = tmp_path / "active"
    moved = tmp_path / "moved"
    active.mkdir()
    executable = active / "adapter.exe"
    executable.write_bytes(b"original")

    with signing.hold_executable_for_launch(executable):
        with pytest.raises(OSError):
            os.replace(active, moved)

    os.replace(active, moved)
    assert (moved / "adapter.exe").read_bytes() == b"original"


def test_executable_launch_lock_blocks_posix_path_replacement(tmp_path: Path) -> None:
    executable = tmp_path / "adapter.exe"
    replacement = tmp_path / "replacement.exe"
    executable.write_bytes(b"original")
    replacement.write_bytes(b"replacement")

    with signing.hold_executable_for_launch(executable):
        with pytest.raises(OSError) as error:
            _replace_with_posix_semantics(replacement, executable)
        assert error.value.errno == 32

    _replace_with_posix_semantics(replacement, executable)
    assert executable.read_bytes() == b"replacement"


def test_publisher_verification_requires_an_exact_allowlist_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "adapter.exe"
    executable.write_bytes(b"MZ synthetic")
    monkeypatch.setattr(signing, "verify_authenticode", lambda _path: True)
    monkeypatch.setattr(
        signing,
        "_authenticode_identity",
        lambda _path: ("CN=Allowed", "1" * 64),
    )

    assert verify_authenticode_publisher(
        executable,
        ("CN=Allowed",),
        allowed_certificate_sha256=("1" * 64,),
    ) is True
    assert verify_authenticode_publisher(
        executable,
        ("CN=Allowed",),
        allowed_certificate_sha256=("2" * 64,),
    ) is False
    assert verify_authenticode_publisher(
        executable,
        ("CN=Other",),
        allowed_certificate_sha256=("1" * 64,),
    ) is False
