"""Windows AppContainer launcher for the dynamic MCP network boundary.

The launcher creates a short-lived AppContainer profile with no declared
capabilities. A successful run is only reported after the process has been
assigned to the existing Job Object and the profile has been removed.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import ctypes
from ctypes import wintypes
import hashlib
import os
import pathlib
import stat
import sys
import uuid
import time
from collections.abc import Mapping

from .discovery import _has_reparse_component
from .windows_job_object import _create_job


class AppContainerUnavailable(RuntimeError):
    """Raised when Windows cannot establish the native network boundary."""


@dataclass(frozen=True, slots=True)
class AppContainerRun:
    returncode: int
    output: bytes
    timed_out: bool
    output_limited: bool
    network_isolated: bool
    process_tree_isolated: bool
    profile_removed: bool


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [
        ("length", wintypes.DWORD),
        ("security_descriptor", ctypes.c_void_p),
        ("inherit_handle", wintypes.BOOL),
    ]


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [
        ("sid", ctypes.c_void_p),
        ("attributes", wintypes.DWORD),
    ]


class _SecurityCapabilities(ctypes.Structure):
    _fields_ = [
        ("app_container_sid", ctypes.c_void_p),
        ("capabilities", ctypes.POINTER(_SidAndAttributes)),
        ("capability_count", wintypes.DWORD),
        ("reserved", wintypes.DWORD),
    ]


class _StartupInfo(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("reserved", wintypes.LPWSTR),
        ("desktop", wintypes.LPWSTR),
        ("title", wintypes.LPWSTR),
        ("x", wintypes.DWORD),
        ("y", wintypes.DWORD),
        ("x_size", wintypes.DWORD),
        ("y_size", wintypes.DWORD),
        ("x_count_chars", wintypes.DWORD),
        ("y_count_chars", wintypes.DWORD),
        ("fill_attribute", wintypes.DWORD),
        ("flags", wintypes.DWORD),
        ("show_window", wintypes.WORD),
        ("reserved2_count", wintypes.WORD),
        ("reserved2", ctypes.POINTER(ctypes.c_ubyte)),
        ("std_input", wintypes.HANDLE),
        ("std_output", wintypes.HANDLE),
        ("std_error", wintypes.HANDLE),
    ]


class _StartupInfoEx(ctypes.Structure):
    _fields_ = [
        ("startup_info", _StartupInfo),
        ("attribute_list", ctypes.c_void_p),
    ]


class _ProcessInformation(ctypes.Structure):
    _fields_ = [
        ("process", wintypes.HANDLE),
        ("thread", wintypes.HANDLE),
        ("process_id", wintypes.DWORD),
        ("thread_id", wintypes.DWORD),
    ]


_CREATE_SUSPENDED = 0x00000004
_CREATE_UNICODE_ENVIRONMENT = 0x00000400
_EXTENDED_STARTUPINFO_PRESENT = 0x00080000
_STARTF_USESTDHANDLES = 0x00000100
_HANDLE_FLAG_INHERIT = 0x00000001
_PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
_PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 258
_HRESULT_ALREADY_EXISTS = -2147024713


def run_in_appcontainer(
    executable: str | pathlib.Path,
    arguments: tuple[str, ...],
    request: bytes,
    *,
    workdir: pathlib.Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
    max_output_bytes: int,
) -> AppContainerRun:
    """Run one process in a no-capability AppContainer and bounded Job Object."""
    _validate_inputs(
        executable,
        arguments,
        request,
        workdir,
        environment,
        timeout_seconds,
        max_output_bytes,
    )
    if sys.platform != "win32":
        raise AppContainerUnavailable("WINDOWS_APPCONTAINER_UNAVAILABLE")

    kernel = _appcontainer_kernel32()
    userenv = _userenv()
    profile_name = _profile_name(pathlib.Path(executable))
    app_sid = ctypes.c_void_p()
    profile_created = False
    profile_removed = False
    job_handle: int | None = None
    process_info = _ProcessInformation()
    input_read: int | None = None
    input_write: int | None = None
    output_read: int | None = None
    output_write: int | None = None
    attribute_buffer: ctypes.Array[ctypes.c_char] | None = None
    attribute_list: ctypes.c_void_p | None = None
    capabilities = _SecurityCapabilities()
    result: AppContainerRun | None = None
    try:
        app_sid.value = _create_profile(userenv, profile_name)
        profile_created = True
        temp_dir = _appcontainer_folder(userenv, kernel, app_sid)
        os.makedirs(temp_dir, exist_ok=True)
        sandbox_temp = os.path.join(temp_dir, "Temp")
        os.makedirs(sandbox_temp, exist_ok=True)
        input_read, input_write = _create_pipe(kernel)
        output_read, output_write = _create_pipe(kernel)
        _set_inherit(kernel, input_write, False)
        _set_inherit(kernel, output_read, False)
        handles = (wintypes.HANDLE * 2)(input_read, output_write)
        capabilities.app_container_sid = app_sid
        attribute_list, attribute_buffer = _build_attributes(
            kernel,
            capabilities,
            handles,
        )
        startup = _StartupInfoEx()
        startup.startup_info.cb = ctypes.sizeof(_StartupInfoEx)
        startup.startup_info.flags = _STARTF_USESTDHANDLES
        startup.startup_info.std_input = input_read
        startup.startup_info.std_output = output_write
        startup.startup_info.std_error = output_write
        startup.attribute_list = attribute_list
        command_line = ctypes.create_unicode_buffer(
            _command_line(pathlib.Path(executable), arguments)
        )
        env_block = ctypes.create_unicode_buffer(
            _environment_block(environment, temp_dir, sandbox_temp)
        )
        if not kernel.CreateProcessW(
            os.fspath(executable),
            command_line,
            None,
            None,
            True,
            _CREATE_SUSPENDED
            | _CREATE_UNICODE_ENVIRONMENT
            | _EXTENDED_STARTUPINFO_PRESENT,
            env_block,
            temp_dir,
            ctypes.byref(startup.startup_info),
            ctypes.byref(process_info),
        ):
            raise AppContainerUnavailable("WINDOWS_APPCONTAINER_CREATE_FAILED")
        _close_handle(kernel, input_read)
        input_read = None
        _close_handle(kernel, output_write)
        output_write = None
        job_handle = _create_job(kernel)
        if not kernel.AssignProcessToJobObject(job_handle, process_info.process):
            raise AppContainerUnavailable("WINDOWS_APPCONTAINER_JOB_ASSIGN_FAILED")
        if kernel.ResumeThread(process_info.thread) == 0xFFFFFFFF:
            raise AppContainerUnavailable("WINDOWS_APPCONTAINER_RESUME_FAILED")
        _write_all(kernel, input_write, request)
        _close_handle(kernel, input_write)
        input_write = None
        deadline = time.monotonic() + timeout_seconds
        output = bytearray()
        timed_out = False
        output_limited = False
        while True:
            _read_available(kernel, output_read, output, max_output_bytes)
            if len(output) > max_output_bytes:
                output_limited = True
                kernel.TerminateJobObject(job_handle, 1)
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                kernel.TerminateJobObject(job_handle, 1)
                break
            wait_result = kernel.WaitForSingleObject(
                process_info.process,
                max(1, min(50, int(remaining * 1000))),
            )
            if wait_result == _WAIT_OBJECT_0:
                break
            if wait_result != _WAIT_TIMEOUT:
                kernel.TerminateJobObject(job_handle, 1)
                raise AppContainerUnavailable("WINDOWS_APPCONTAINER_WAIT_FAILED")
        kernel.WaitForSingleObject(process_info.process, 5_000)
        _drain_output(kernel, output_read, output, max_output_bytes)
        returncode = wintypes.DWORD()
        if not kernel.GetExitCodeProcess(process_info.process, ctypes.byref(returncode)):
            raise AppContainerUnavailable("WINDOWS_APPCONTAINER_EXIT_CODE_FAILED")
        result = AppContainerRun(
            returncode=returncode.value,
            output=bytes(output[: max_output_bytes + 1]),
            timed_out=timed_out,
            output_limited=output_limited or len(output) > max_output_bytes,
            network_isolated=True,
            process_tree_isolated=True,
            profile_removed=False,
        )
    except AppContainerUnavailable:
        if job_handle is not None and process_info.process:
            kernel.TerminateJobObject(job_handle, 1)
        raise
    except (OSError, ValueError, ctypes.ArgumentError) as error:
        if job_handle is not None and process_info.process:
            kernel.TerminateJobObject(job_handle, 1)
        raise AppContainerUnavailable("WINDOWS_APPCONTAINER_RUNTIME_FAILED") from error
    finally:
        if attribute_list is not None:
            kernel.DeleteProcThreadAttributeList(attribute_list)
        if process_info.thread:
            _close_handle(kernel, process_info.thread)
        if process_info.process:
            _close_handle(kernel, process_info.process)
        if job_handle is not None:
            _close_handle(kernel, job_handle)
        for handle in (input_read, input_write, output_read, output_write):
            if handle is not None:
                _close_handle(kernel, handle)
        if app_sid.value:
            kernel.LocalFree(app_sid)
        if profile_created and not profile_removed:
            if userenv.DeleteAppContainerProfile(profile_name) != 0:
                raise AppContainerUnavailable("WINDOWS_APPCONTAINER_PROFILE_CLEANUP_FAILED")
            profile_removed = True
    if result is None:
        raise AppContainerUnavailable("WINDOWS_APPCONTAINER_RUNTIME_FAILED")
    return replace(result, profile_removed=profile_removed)


def appcontainer_available() -> bool:
    """Return whether the required native AppContainer APIs are loadable."""
    if sys.platform != "win32":
        return False
    try:
        _appcontainer_kernel32()
        _userenv()
    except (AttributeError, OSError):
        return False
    return True


def _validate_inputs(
    executable: str | pathlib.Path,
    arguments: tuple[str, ...],
    request: bytes,
    workdir: pathlib.Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
    max_output_bytes: int,
) -> None:
    path = pathlib.Path(executable)
    root = pathlib.Path(workdir)
    if (
        not path.is_absolute()
        or path.is_symlink()
        or _is_unc(path)
        or _has_reparse_component(path)
    ):
        raise ValueError("MCP_EXECUTABLE_INVALID")
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            raise ValueError("MCP_EXECUTABLE_INVALID")
    except OSError:
        raise ValueError("MCP_EXECUTABLE_INVALID") from None
    if (
        not root.is_dir()
        or root.is_symlink()
        or _is_unc(root)
        or _has_reparse_component(root)
    ):
        raise ValueError("MCP_WORKDIR_INVALID")
    if type(arguments) is not tuple or any(
        type(argument) is not str or not argument or "\x00" in argument
        for argument in arguments
    ):
        raise ValueError("MCP_ARGUMENT_INVALID")
    if type(request) is not bytes:
        raise ValueError("MCP_REQUEST_INVALID")
    if type(environment) is not dict or any(
        type(key) is not str
        or type(value) is not str
        or not key
        or "\x00" in key
        or "\x00" in value
        for key, value in environment.items()
    ):
        raise ValueError("MCP_ENVIRONMENT_INVALID")
    if (
        type(timeout_seconds) not in (int, float)
        or timeout_seconds <= 0
        or type(max_output_bytes) is not int
        or max_output_bytes < 1
    ):
        raise ValueError("MCP_LIMIT_INVALID")


def _appcontainer_kernel32():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreatePipe.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        ctypes.POINTER(wintypes.HANDLE),
        ctypes.POINTER(_SecurityAttributes),
        wintypes.DWORD,
    ]
    kernel.CreatePipe.restype = wintypes.BOOL
    kernel.SetHandleInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD]
    kernel.SetHandleInformation.restype = wintypes.BOOL
    kernel.InitializeProcThreadAttributeList.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel.InitializeProcThreadAttributeList.restype = wintypes.BOOL
    kernel.UpdateProcThreadAttribute.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel.UpdateProcThreadAttribute.restype = wintypes.BOOL
    kernel.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
    kernel.DeleteProcThreadAttributeList.restype = None
    kernel.CreateProcessW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.BOOL,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        ctypes.POINTER(_ProcessInformation),
    ]
    kernel.CreateProcessW.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    kernel.WriteFile.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    ]
    kernel.WriteFile.restype = wintypes.BOOL
    kernel.PeekNamedPipe.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    ]
    kernel.PeekNamedPipe.restype = wintypes.BOOL
    kernel.ReadFile.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    ]
    kernel.ReadFile.restype = wintypes.BOOL
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel.ResumeThread.restype = wintypes.DWORD
    kernel.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel.TerminateJobObject.restype = wintypes.BOOL
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.GetExitCodeProcess.restype = wintypes.BOOL
    return kernel


def _userenv():
    userenv = ctypes.WinDLL("userenv", use_last_error=True)
    userenv.CreateAppContainerProfile.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.POINTER(_SidAndAttributes),
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    userenv.CreateAppContainerProfile.restype = wintypes.LONG
    userenv.DeriveAppContainerSidFromAppContainerName.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    userenv.DeriveAppContainerSidFromAppContainerName.restype = wintypes.LONG
    userenv.GetAppContainerFolderPath.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    userenv.GetAppContainerFolderPath.restype = wintypes.LONG
    userenv.DeleteAppContainerProfile.argtypes = [wintypes.LPCWSTR]
    userenv.DeleteAppContainerProfile.restype = wintypes.LONG
    return userenv


def _create_profile(userenv, profile_name: str) -> int:
    sid = ctypes.c_void_p()
    result = userenv.CreateAppContainerProfile(
        profile_name,
        "AgentGuardian MCP",
        "Short-lived AgentGuardian MCP adapter sandbox",
        None,
        0,
        ctypes.byref(sid),
    )
    if result == _HRESULT_ALREADY_EXISTS:
        result = userenv.DeriveAppContainerSidFromAppContainerName(
            profile_name,
            ctypes.byref(sid),
        )
    if result != 0 or not sid.value:
        raise AppContainerUnavailable("WINDOWS_APPCONTAINER_PROFILE_CREATE_FAILED")
    return int(sid.value)


def _appcontainer_folder(userenv, kernel, app_sid: ctypes.c_void_p) -> str:
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    security.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    security.ConvertSidToStringSidW.restype = wintypes.BOOL
    sid_text = wintypes.LPWSTR()
    if not security.ConvertSidToStringSidW(app_sid, ctypes.byref(sid_text)):
        raise AppContainerUnavailable("WINDOWS_APPCONTAINER_SID_FORMAT_FAILED")
    path_text = wintypes.LPWSTR()
    try:
        result = userenv.GetAppContainerFolderPath(
            sid_text,
            ctypes.byref(path_text),
        )
        if result != 0 or not path_text.value:
            raise AppContainerUnavailable("WINDOWS_APPCONTAINER_FOLDER_FAILED")
        return path_text.value
    finally:
        if path_text:
            ctypes.WinDLL("ole32").CoTaskMemFree(path_text)
        kernel.LocalFree(sid_text)


def _create_pipe(kernel) -> tuple[int, int]:
    attributes = _SecurityAttributes(
        length=ctypes.sizeof(_SecurityAttributes),
        security_descriptor=None,
        inherit_handle=True,
    )
    read_handle = wintypes.HANDLE()
    write_handle = wintypes.HANDLE()
    if not kernel.CreatePipe(
        ctypes.byref(read_handle),
        ctypes.byref(write_handle),
        ctypes.byref(attributes),
        0,
    ):
        raise AppContainerUnavailable("WINDOWS_APPCONTAINER_PIPE_FAILED")
    return int(read_handle.value), int(write_handle.value)


def _set_inherit(kernel, handle: int, inheritable: bool) -> None:
    if not kernel.SetHandleInformation(
        handle,
        _HANDLE_FLAG_INHERIT,
        _HANDLE_FLAG_INHERIT if inheritable else 0,
    ):
        raise AppContainerUnavailable("WINDOWS_APPCONTAINER_HANDLE_POLICY_FAILED")


def _build_attributes(kernel, capabilities, handles):
    size = ctypes.c_size_t()
    kernel.InitializeProcThreadAttributeList(None, 2, 0, ctypes.byref(size))
    if not size.value:
        raise AppContainerUnavailable("WINDOWS_APPCONTAINER_ATTRIBUTE_SIZE_FAILED")
    attribute_buffer = ctypes.create_string_buffer(size.value)
    attribute_list = ctypes.cast(attribute_buffer, ctypes.c_void_p)
    if not kernel.InitializeProcThreadAttributeList(
        attribute_list,
        2,
        0,
        ctypes.byref(size),
    ):
        raise AppContainerUnavailable("WINDOWS_APPCONTAINER_ATTRIBUTE_INIT_FAILED")
    if not kernel.UpdateProcThreadAttribute(
        attribute_list,
        0,
        _PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
        ctypes.byref(capabilities),
        ctypes.sizeof(capabilities),
        None,
        None,
    ):
        raise AppContainerUnavailable("WINDOWS_APPCONTAINER_CAPABILITY_ATTRIBUTE_FAILED")
    if not kernel.UpdateProcThreadAttribute(
        attribute_list,
        0,
        _PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        ctypes.cast(handles, ctypes.c_void_p),
        ctypes.sizeof(handles),
        None,
        None,
    ):
        raise AppContainerUnavailable("WINDOWS_APPCONTAINER_HANDLE_ATTRIBUTE_FAILED")
    return attribute_list, attribute_buffer


def _write_all(kernel, handle: int, data: bytes) -> None:
    if not data:
        return
    buffer = ctypes.create_string_buffer(data)
    written = wintypes.DWORD()
    if not kernel.WriteFile(handle, buffer, len(data), ctypes.byref(written), None):
        raise AppContainerUnavailable("WINDOWS_APPCONTAINER_INPUT_FAILED")
    if written.value != len(data):
        raise AppContainerUnavailable("WINDOWS_APPCONTAINER_INPUT_INCOMPLETE")


def _read_available(kernel, handle: int, output: bytearray, limit: int) -> None:
    available = wintypes.DWORD()
    if not kernel.PeekNamedPipe(handle, None, 0, None, ctypes.byref(available), None):
        return
    if available.value == 0:
        return
    size = min(available.value, limit + 1 - len(output))
    if size <= 0:
        output.extend(b"x")
        return
    buffer = ctypes.create_string_buffer(size)
    read = wintypes.DWORD()
    if kernel.ReadFile(handle, buffer, size, ctypes.byref(read), None):
        output.extend(buffer.raw[: read.value])


def _drain_output(kernel, handle: int | None, output: bytearray, limit: int) -> None:
    if handle is None:
        return
    for _ in range(32):
        before = len(output)
        _read_available(kernel, handle, output, limit)
        if len(output) == before:
            break


def _command_line(executable: pathlib.Path, arguments: tuple[str, ...]) -> str:
    import subprocess

    return subprocess.list2cmdline([os.fspath(executable), *arguments])


def _environment_block(
    environment: Mapping[str, str],
    local_app_data: str,
    temp_dir: str,
) -> str:
    inherited_names = (
        "COMSPEC",
        "PATHEXT",
        "PATH",
        "PROCESSOR_ARCHITECTURE",
        "ProgramData",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "SystemDrive",
        "SystemRoot",
        "WINDIR",
    )
    values = {
        name: os.environ[name]
        for name in inherited_names
        if os.environ.get(name)
    }
    values.update(
        {
            "LOCALAPPDATA": local_app_data,
            "TEMP": temp_dir,
            "TMP": temp_dir,
        }
    )
    values.update(dict(environment))
    return "".join(f"{key}={values[key]}\0" for key in sorted(values)) + "\0"


def _profile_name(executable: pathlib.Path) -> str:
    digest = hashlib.sha256(os.fspath(executable).encode("utf-8")).hexdigest()[:24]
    return f"AgentGuardian.MCP.{digest}.{uuid.uuid4().hex[:16]}"


def _close_handle(kernel, handle: int) -> None:
    kernel.CloseHandle(handle)


def _is_unc(path: pathlib.Path) -> bool:
    return os.fspath(path).startswith(("\\\\", "//"))
