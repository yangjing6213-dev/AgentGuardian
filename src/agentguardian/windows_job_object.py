"""Small Windows Job Object launcher used by the dynamic MCP supervisor."""

from __future__ import annotations

from dataclasses import dataclass
import ctypes
from ctypes import wintypes
import os
import pathlib
import stat
import subprocess
import sys
import time
from typing import Mapping

from .discovery import _has_reparse_component


class JobObjectUnavailable(RuntimeError):
    """Raised when the native process-tree boundary cannot be established."""


@dataclass(frozen=True, slots=True)
class JobObjectRun:
    returncode: int
    output: bytes
    timed_out: bool
    output_limited: bool
    process_tree_isolated: bool


class _JobObjectBasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("per_process_user_time", ctypes.c_longlong),
        ("per_job_user_time", ctypes.c_longlong),
        ("limit_flags", wintypes.DWORD),
        ("minimum_working_set_size", ctypes.c_size_t),
        ("maximum_working_set_size", ctypes.c_size_t),
        ("active_process_limit", wintypes.DWORD),
        ("affinity", ctypes.c_size_t),
        ("priority_class", wintypes.DWORD),
        ("scheduling_class", wintypes.DWORD),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [
        ("read_operation_count", ctypes.c_ulonglong),
        ("write_operation_count", ctypes.c_ulonglong),
        ("other_operation_count", ctypes.c_ulonglong),
        ("read_transfer_count", ctypes.c_ulonglong),
        ("write_transfer_count", ctypes.c_ulonglong),
        ("other_transfer_count", ctypes.c_ulonglong),
    ]


class _JobObjectExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("basic_limit_information", _JobObjectBasicLimitInformation),
        ("io_info", _IoCounters),
        ("process_memory_limit", ctypes.c_size_t),
        ("job_memory_limit", ctypes.c_size_t),
        ("peak_process_memory_used", ctypes.c_size_t),
        ("peak_job_memory_used", ctypes.c_size_t),
    ]


_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_CREATE_SUSPENDED = 0x00000004
_CREATE_UNICODE_ENVIRONMENT = 0x00000400
_EXTENDED_STARTUPINFO_PRESENT = 0x00080000
_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 258


def run_in_job_object(
    executable: str | pathlib.Path,
    arguments: tuple[str, ...],
    request: bytes,
    *,
    workdir: pathlib.Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
    max_output_bytes: int,
) -> JobObjectRun:
    """Run one fixed process inside a bounded Windows Job Object.

    The caller remains responsible for the network boundary.  This function
    proves and enforces process-tree containment only.
    """
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
        raise JobObjectUnavailable("WINDOWS_JOB_OBJECT_UNAVAILABLE")

    import _winapi

    kernel = _kernel32()
    workdir = pathlib.Path(workdir)
    request_path = workdir / ".agentguardian-mcp-request.bin"
    output_path = workdir / ".agentguardian-mcp-output.bin"
    job_handle = _create_job(kernel)
    process_handle: int | None = None
    thread_handle: int | None = None
    child_handles: list[int] = []
    started = False
    timed_out = False
    output_limited = False
    try:
        request_path.write_bytes(request)
        output_path.write_bytes(b"")
        with (
            request_path.open("rb", buffering=0) as request_stream,
            output_path.open("wb", buffering=0) as output_stream,
        ):
            request_handle = _duplicate_inheritable(
                _handle_from_file(request_stream),
            )
            output_handle = _duplicate_inheritable(
                _handle_from_file(output_stream),
            )
            child_handles.extend((request_handle, output_handle))
            startup = subprocess.STARTUPINFO(
                dwFlags=subprocess.STARTF_USESTDHANDLES,
                hStdInput=request_handle,
                hStdOutput=output_handle,
                hStdError=output_handle,
            )
            startup.lpAttributeList = {
                "handle_list": [request_handle, output_handle],
            }
            command_line = subprocess.list2cmdline(
                [os.fspath(executable), *arguments]
            )
            try:
                process_handle, thread_handle, _pid, _tid = _winapi.CreateProcess(
                    os.fspath(executable),
                    command_line,
                    None,
                    None,
                    True,
                    _CREATE_SUSPENDED
                    | _CREATE_UNICODE_ENVIRONMENT
                    | _EXTENDED_STARTUPINFO_PRESENT,
                    dict(environment),
                    os.fspath(workdir),
                    startup,
                )
            except OSError as error:
                raise JobObjectUnavailable("WINDOWS_JOB_OBJECT_CREATE_FAILED") from error
            finally:
                for handle in child_handles:
                    _winapi.CloseHandle(handle)
                child_handles.clear()

        if not kernel.AssignProcessToJobObject(job_handle, process_handle):
            raise JobObjectUnavailable("WINDOWS_JOB_OBJECT_ASSIGN_FAILED")
        if kernel.ResumeThread(thread_handle) == 0xFFFFFFFF:
            raise JobObjectUnavailable("WINDOWS_JOB_OBJECT_RESUME_FAILED")
        started = True
        _winapi.CloseHandle(thread_handle)
        thread_handle = None

        deadline = time.monotonic() + timeout_seconds
        while True:
            try:
                if output_path.stat().st_size > max_output_bytes:
                    output_limited = True
                    kernel.TerminateJobObject(job_handle, 1)
                    break
            except OSError:
                pass
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                kernel.TerminateJobObject(job_handle, 1)
                break
            wait_ms = max(1, min(50, int(remaining * 1000)))
            wait_result = _winapi.WaitForSingleObject(process_handle, wait_ms)
            if wait_result == _WAIT_OBJECT_0:
                break
            if wait_result != _WAIT_TIMEOUT:
                kernel.TerminateJobObject(job_handle, 1)
                raise JobObjectUnavailable("WINDOWS_JOB_OBJECT_WAIT_FAILED")
        _winapi.WaitForSingleObject(process_handle, 5_000)
        returncode = _winapi.GetExitCodeProcess(process_handle)
        output = output_path.read_bytes()[: max_output_bytes + 1]
        if len(output) > max_output_bytes:
            output_limited = True
            output = output[:max_output_bytes]
        return JobObjectRun(
            returncode=returncode,
            output=output,
            timed_out=timed_out,
            output_limited=output_limited,
            process_tree_isolated=started,
        )
    except JobObjectUnavailable:
        if process_handle is not None:
            kernel.TerminateJobObject(job_handle, 1)
        raise
    except (OSError, ValueError) as error:
        if process_handle is not None:
            kernel.TerminateJobObject(job_handle, 1)
        raise JobObjectUnavailable("WINDOWS_JOB_OBJECT_RUNTIME_FAILED") from error
    finally:
        if child_handles:
            for handle in child_handles:
                _winapi.CloseHandle(handle)
        if thread_handle is not None:
            _winapi.CloseHandle(thread_handle)
        if process_handle is not None:
            _winapi.CloseHandle(process_handle)
        kernel.CloseHandle(job_handle)
        for path in (request_path, output_path):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass


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
    if (
        type(environment) is not dict
        or any(
            type(key) is not str
            or type(value) is not str
            or not key
            or "\x00" in key
            or "\x00" in value
            for key, value in environment.items()
        )
    ):
        raise ValueError("MCP_ENVIRONMENT_INVALID")
    if (
        type(timeout_seconds) not in (int, float)
        or timeout_seconds <= 0
        or type(max_output_bytes) is not int
        or max_output_bytes < 1
    ):
        raise ValueError("MCP_LIMIT_INVALID")


def _kernel32():
    try:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    except AttributeError:
        raise JobObjectUnavailable("WINDOWS_JOB_OBJECT_UNAVAILABLE") from None
    kernel.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    kernel.SetInformationJobObject.restype = wintypes.BOOL
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel.ResumeThread.restype = wintypes.DWORD
    kernel.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel.TerminateJobObject.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    return kernel


def _create_job(kernel) -> wintypes.HANDLE:
    job = kernel.CreateJobObjectW(None, None)
    if not job:
        raise JobObjectUnavailable("WINDOWS_JOB_OBJECT_CREATE_FAILED")
    information = _JobObjectExtendedLimitInformation()
    information.basic_limit_information.limit_flags = (
        _JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    )
    information.basic_limit_information.active_process_limit = 1
    if not kernel.SetInformationJobObject(
        job,
        _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
        ctypes.byref(information),
        ctypes.sizeof(information),
    ):
        kernel.CloseHandle(job)
        raise JobObjectUnavailable("WINDOWS_JOB_OBJECT_CONFIGURE_FAILED")
    return job


def _handle_from_file(stream) -> int:
    import msvcrt

    return int(msvcrt.get_osfhandle(stream.fileno()))


def _duplicate_inheritable(handle: int) -> int:
    import _winapi

    return int(
        _winapi.DuplicateHandle(
            _winapi.GetCurrentProcess(),
            handle,
            _winapi.GetCurrentProcess(),
            0,
            True,
            _winapi.DUPLICATE_SAME_ACCESS,
        )
    )


def _is_unc(path: pathlib.Path) -> bool:
    return os.fspath(path).startswith(("\\\\", "//"))
