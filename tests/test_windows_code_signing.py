from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import sys

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


def test_writable_path_gate_covers_posix_replacement_variance(tmp_path: Path) -> None:
    executable = tmp_path / "adapter.exe"
    replacement = tmp_path / "replacement.exe"
    executable.write_bytes(b"original")
    replacement.write_bytes(b"replacement")

    assert signing.executable_path_is_protected(executable) is False
    replaced_while_locked = False
    with signing.hold_executable_for_launch(executable):
        try:
            _replace_with_posix_semantics(replacement, executable)
        except OSError as error:
            assert error.errno == 32
        else:
            replaced_while_locked = True

    if not replaced_while_locked:
        _replace_with_posix_semantics(replacement, executable)
    assert executable.read_bytes() == b"replacement"


def test_user_writable_executable_parent_is_not_protected(tmp_path: Path) -> None:
    executable = tmp_path / "adapter.exe"
    executable.write_bytes(b"original")

    assert signing.executable_path_is_protected(executable) is False


def test_executable_parent_is_protected_when_dangerous_access_is_denied(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "adapter.exe"
    executable.write_bytes(b"original")
    requested_access = []

    class FakeCreateFile:
        argtypes = None
        restype = None

        def __call__(self, path, access, *_args):
            requested_access.append((Path(path), access))
            signing.ctypes.set_last_error(5)
            return signing.ctypes.c_void_p(-1).value

    class FakeCloseHandle:
        argtypes = None
        restype = None

        def __call__(self, _handle):
            pytest.fail("invalid ACL probe handle was closed")

    class FakeKernel32:
        CreateFileW = FakeCreateFile()
        CloseHandle = FakeCloseHandle()

    monkeypatch.setattr(
        signing.ctypes,
        "WinDLL",
        lambda _name, use_last_error=True: FakeKernel32(),
    )

    assert signing.executable_path_is_protected(executable) is True
    root = Path(executable.anchor)
    expected_access = {
        (executable, 0x00010000),
        (executable, 0x00040000),
        (executable, 0x00080000),
        (executable.parent, 0x00000002),
    }
    for directory in executable.parents:
        if directory != root:
            expected_access.add((directory, 0x00010000))
        expected_access.update(
            {
                (directory, 0x00000040),
                (directory, 0x00040000),
                (directory, 0x00080000),
            }
        )
    assert set(requested_access) == expected_access


def test_executable_parent_protection_fails_closed_on_unexpected_probe_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "adapter.exe"
    executable.write_bytes(b"original")

    class FakeCreateFile:
        argtypes = None
        restype = None

        def __call__(self, *_args):
            signing.ctypes.set_last_error(32)
            return signing.ctypes.c_void_p(-1).value

    class FakeCloseHandle:
        argtypes = None
        restype = None

        def __call__(self, _handle):
            pytest.fail("invalid ACL probe handle was closed")

    class FakeKernel32:
        CreateFileW = FakeCreateFile()
        CloseHandle = FakeCloseHandle()

    monkeypatch.setattr(
        signing.ctypes,
        "WinDLL",
        lambda _name, use_last_error=True: FakeKernel32(),
    )

    assert signing.executable_path_is_protected(executable) is False


@pytest.mark.parametrize("deletable_part", ["executable", "parent"])
def test_executable_parent_protection_rejects_a_deletable_path_component(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    deletable_part: str,
) -> None:
    executable = tmp_path / "adapter.exe"
    executable.write_bytes(b"original")
    target = executable if deletable_part == "executable" else executable.parent

    class FakeCreateFile:
        argtypes = None
        restype = None

        def __call__(self, path, access, *_args):
            if Path(path) == target and access == 0x00010000:
                return 123
            signing.ctypes.set_last_error(5)
            return signing.ctypes.c_void_p(-1).value

    class FakeCloseHandle:
        argtypes = None
        restype = None

        def __call__(self, handle):
            assert handle == 123
            return True

    class FakeKernel32:
        CreateFileW = FakeCreateFile()
        CloseHandle = FakeCloseHandle()

    monkeypatch.setattr(
        signing.ctypes,
        "WinDLL",
        lambda _name, use_last_error=True: FakeKernel32(),
    )

    assert signing.executable_path_is_protected(executable) is False


def test_executable_path_protection_fails_closed_when_handle_cleanup_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "adapter.exe"
    executable.write_bytes(b"original")

    class FakeCreateFile:
        argtypes = None
        restype = None

        def __call__(self, *_args):
            return 123

    class FakeCloseHandle:
        argtypes = None
        restype = None

        def __call__(self, handle):
            assert handle == 123
            return False

    class FakeKernel32:
        CreateFileW = FakeCreateFile()
        CloseHandle = FakeCloseHandle()

    monkeypatch.setattr(
        signing.ctypes,
        "WinDLL",
        lambda _name, use_last_error=True: FakeKernel32(),
    )

    assert signing.executable_path_is_protected(executable) is False


@pytest.mark.parametrize(
    ("package_origin", "extra_path_type", "expected"),
    (
        (6, None, True),
        (5, None, False),
        (6, 1, False),
        (6, 2, False),
        (6, 3, False),
        (6, 4, False),
        (6, 5, False),
    ),
)
def test_executable_matches_the_os_resolved_installed_package(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    package_origin: int,
    extra_path_type: int | None,
    expected: bool,
) -> None:
    program_files = tmp_path / "Program Files"
    package_full_name = "yangjing6213dev.AgentGuardian_0.1.0.0_x64__publisher"
    package_root = program_files / "WindowsApps" / package_full_name
    executable = package_root / "adapters" / "AgentGuardianMcpAdapter.exe"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"MZ synthetic")
    alternate_root = tmp_path / "alternate-package-location"
    alternate_root.mkdir()

    class FakeGetPackagePath:
        argtypes = None
        restype = None

        def __call__(self, full_name, path_type, length_pointer, buffer):
            assert full_name == package_full_name
            length = ctypes.cast(
                length_pointer,
                ctypes.POINTER(ctypes.c_uint32),
            ).contents
            if path_type == 1 and extra_path_type != 1:
                return 15707
            if path_type in (3, 4, 5) and extra_path_type != path_type:
                return 1168
            target = alternate_root if path_type == extra_path_type else package_root
            if buffer is None:
                length.value = len(str(target)) + 1
                return 122
            buffer.value = str(target)
            return 0

    class FakeGetPackageOrigin:
        argtypes = None
        restype = None

        def __call__(self, full_name, origin_pointer):
            assert full_name == package_full_name
            ctypes.cast(
                origin_pointer,
                ctypes.POINTER(ctypes.c_int),
            ).contents.value = package_origin
            return 0

    class FakeKernel32:
        GetPackagePathByFullName2 = FakeGetPackagePath()
        GetStagedPackageOrigin = FakeGetPackageOrigin()

    monkeypatch.setattr(
        signing.ctypes,
        "WinDLL",
        lambda _name, use_last_error=True: FakeKernel32(),
    )
    monkeypatch.setattr(
        signing,
        "_program_files_root",
        lambda: program_files,
        raising=False,
    )

    matcher = getattr(signing, "executable_matches_installed_package", None)
    assert matcher is not None
    assert matcher(executable, package_full_name) is expected
    other = package_root / "adapters" / "OtherAdapter.exe"
    other.write_bytes(b"MZ other")
    assert matcher(other, package_full_name) is False
    if expected:
        other_program_files = tmp_path / "Other Program Files"
        (other_program_files / "WindowsApps").mkdir(parents=True)
        monkeypatch.setattr(
            signing,
            "_program_files_root",
            lambda: other_program_files,
        )
        assert matcher(executable, package_full_name) is False


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
