"""Default-deny supervisor contract for dynamic MCP adapters.

The portable package does not claim to provide a native network sandbox.  A
real attestation must come from a platform provider (for example an
AppContainer-backed Windows launcher).  Without it, no adapter process starts.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import os
import pathlib
import re
import stat
import subprocess
import tempfile

from .discovery import _has_reparse_component
from .file_integrity import FileSizeLimitExceeded, bounded_file_sha256
from .windows_appcontainer import AppContainerUnavailable, appcontainer_available, run_in_appcontainer
from .windows_code_signing import (
    executable_matches_installed_package,
    executable_path_is_protected,
    hold_executable_for_launch,
    verify_authenticode,
    verify_authenticode_publisher,
)
from .windows_job_object import JobObjectUnavailable, run_in_job_object


MAX_MCP_REQUEST_BYTES = 64 * 1024
MAX_MCP_OUTPUT_BYTES = 64 * 1024
MAX_MCP_RUNTIME_SECONDS = 30.0
_ADAPTER_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_ALLOWED_ADAPTER_CAPABILITIES = frozenset({"tools", "resources", "prompts"})
_MAX_PUBLISHER_SUBJECTS = 16
_MAX_PUBLISHER_SUBJECT_LENGTH = 512
_MAX_PUBLISHER_CERTIFICATE_HASHES = 16
_PACKAGE_NAME_PREFIX = "yangjing6213dev.AgentGuardian_"


class SandboxStatus(str, Enum):
    NOT_PERFORMED = "not_performed"
    DENIED = "denied"
    COMPLETED = "completed"
    TIMED_OUT = "timed_out"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class McpSandboxPolicy:
    adapter_id: str
    executable: pathlib.Path
    executable_sha256: str
    arguments: tuple[str, ...]
    capabilities: tuple[str, ...]
    network_access: str
    max_runtime_seconds: float
    max_output_bytes: int
    allowed_publisher_subjects: tuple[str, ...] = ()
    allowed_publisher_certificate_sha256: tuple[str, ...] = ()
    package_full_name: str = ""

    @classmethod
    def from_command(
        cls,
        *,
        adapter_id: str,
        executable: str | pathlib.Path,
        executable_sha256: str,
        arguments: tuple[str, ...] = (),
        capabilities: tuple[str, ...] = (),
        allowed_publisher_subjects: tuple[str, ...] = (),
        allowed_publisher_certificate_sha256: tuple[str, ...] = (),
        package_full_name: str = "",
        max_runtime_seconds: float = 5.0,
        max_output_bytes: int = MAX_MCP_OUTPUT_BYTES,
    ) -> "McpSandboxPolicy":
        if type(adapter_id) is not str or _ADAPTER_ID.fullmatch(adapter_id) is None:
            raise ValueError("MCP_ADAPTER_ID_INVALID")
        if (
            type(executable_sha256) is not str
            or len(executable_sha256) != 64
            or any(character not in "0123456789abcdef" for character in executable_sha256)
        ):
            raise ValueError("MCP_EXECUTABLE_HASH_INVALID")
        if type(arguments) is not tuple or len(arguments) > 32:
            raise ValueError("MCP_ARGUMENT_INVALID")
        if any(
            type(argument) is not str
            or not argument
            or len(argument) > 512
            or "\x00" in argument
            for argument in arguments
        ):
            raise ValueError("MCP_ARGUMENT_INVALID")
        if type(capabilities) is not tuple or any(
            type(capability) is not str for capability in capabilities
        ) or len(set(capabilities)) != len(capabilities):
            raise ValueError("MCP_CAPABILITY_INVALID")
        if any(capability not in _ALLOWED_ADAPTER_CAPABILITIES for capability in capabilities):
            raise ValueError("MCP_CAPABILITY_INVALID")
        if (
            type(allowed_publisher_subjects) is not tuple
            or len(allowed_publisher_subjects) > _MAX_PUBLISHER_SUBJECTS
            or any(
                type(subject) is not str
                or not subject
                or len(subject) > _MAX_PUBLISHER_SUBJECT_LENGTH
                or "\x00" in subject
                or subject != subject.strip()
                for subject in allowed_publisher_subjects
            )
            or len(set(allowed_publisher_subjects)) != len(allowed_publisher_subjects)
        ):
            raise ValueError("MCP_PUBLISHER_ALLOWLIST_INVALID")
        if (
            type(allowed_publisher_certificate_sha256) is not tuple
            or len(allowed_publisher_certificate_sha256) > _MAX_PUBLISHER_CERTIFICATE_HASHES
            or any(
                type(digest) is not str
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
                for digest in allowed_publisher_certificate_sha256
            )
            or len(set(allowed_publisher_certificate_sha256))
            != len(allowed_publisher_certificate_sha256)
        ):
            raise ValueError("MCP_PUBLISHER_CERT_ALLOWLIST_INVALID")
        if (
            type(package_full_name) is not str
            or len(package_full_name) > 256
            or "\x00" in package_full_name
            or package_full_name != package_full_name.strip()
            or (package_full_name and not package_full_name.startswith(_PACKAGE_NAME_PREFIX))
        ):
            raise ValueError("MCP_PACKAGE_IDENTITY_INVALID")
        if (
            type(max_runtime_seconds) not in (int, float)
            or not 0.1 <= max_runtime_seconds <= MAX_MCP_RUNTIME_SECONDS
            or type(max_output_bytes) is not int
            or not 1 <= max_output_bytes <= MAX_MCP_OUTPUT_BYTES
        ):
            raise ValueError("MCP_LIMIT_INVALID")
        path = pathlib.Path(executable)
        if (
            not path.is_absolute()
            or _is_unc(path)
            or path.is_symlink()
            or _has_reparse_component(path)
        ):
            raise ValueError("MCP_EXECUTABLE_INVALID")
        try:
            target_stat = os.lstat(path)
        except OSError:
            raise ValueError("MCP_EXECUTABLE_INVALID") from None
        if not stat.S_ISREG(target_stat.st_mode):
            raise ValueError("MCP_EXECUTABLE_INVALID")
        return cls(
            adapter_id=adapter_id,
            executable=path,
            executable_sha256=executable_sha256,
            arguments=arguments,
            capabilities=capabilities,
            network_access="deny",
            max_runtime_seconds=float(max_runtime_seconds),
            max_output_bytes=max_output_bytes,
            allowed_publisher_subjects=allowed_publisher_subjects,
            allowed_publisher_certificate_sha256=allowed_publisher_certificate_sha256,
            package_full_name=package_full_name,
        )


@dataclass(frozen=True, slots=True)
class _SandboxAttestation:
    provider: str
    network_isolated: bool
    process_tree_isolated: bool


@dataclass(frozen=True, slots=True)
class SandboxAssessment:
    status: SandboxStatus
    provider: str
    network_isolation: str
    process_tree_isolation: str
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class McpSandboxResult:
    status: SandboxStatus
    adapter_id: str
    reason: str
    response_bytes: int
    raw_response_retained: bool
    limits: tuple[str, ...]


def assess_mcp_sandbox(
    policy: McpSandboxPolicy,
) -> SandboxAssessment:
    if type(policy) is not McpSandboxPolicy:
        raise ValueError("MCP_POLICY_INVALID")
    attestation = probe_native_sandbox()
    if attestation is None:
        return SandboxAssessment(
            status=SandboxStatus.DENIED,
            provider="none",
            network_isolation="unavailable",
            process_tree_isolation="unavailable",
            reasons=(
                "native_network_isolation_required",
                "native_process_tree_isolation_required",
            ),
        )
    reasons: list[str] = []
    if not attestation.network_isolated:
        reasons.append("native_network_isolation_required")
    if not attestation.process_tree_isolated:
        reasons.append("native_process_tree_isolation_required")
    if reasons:
        return SandboxAssessment(
            status=SandboxStatus.DENIED,
            provider=attestation.provider,
            network_isolation="unavailable" if not attestation.network_isolated else "enforced",
            process_tree_isolation=(
                "unavailable" if not attestation.process_tree_isolated else "enforced"
            ),
            reasons=tuple(reasons),
        )
    return SandboxAssessment(
        status=SandboxStatus.COMPLETED,
        provider=attestation.provider,
        network_isolation="enforced",
        process_tree_isolation="enforced",
        reasons=(),
    )


def run_mcp_sandbox(
    policy: McpSandboxPolicy,
    request: bytes,
    *,
    confirmed: bool,
    temp_root: pathlib.Path | None = None,
) -> McpSandboxResult:
    if type(policy) is not McpSandboxPolicy:
        raise ValueError("MCP_POLICY_INVALID")
    if type(request) is not bytes:
        raise ValueError("MCP_REQUEST_INVALID")
    if len(request) > MAX_MCP_REQUEST_BYTES:
        raise ValueError("MCP_REQUEST_SIZE_LIMIT")
    if type(confirmed) is not bool:
        raise ValueError("MCP_CONFIRMATION_INVALID")
    if not confirmed:
        return _result(policy, SandboxStatus.NOT_PERFORMED, "confirmation_required")
    assessment = assess_mcp_sandbox(policy)
    if assessment.status is not SandboxStatus.COMPLETED:
        return _result(policy, SandboxStatus.DENIED, assessment.reasons[0])
    if (
        assessment.provider == "windows-appcontainer"
        and policy.allowed_publisher_subjects
        and policy.allowed_publisher_certificate_sha256
    ):
        if not policy.package_full_name:
            return _result(
                policy,
                SandboxStatus.DENIED,
                "adapter_package_identity_required",
            )
        if not executable_matches_installed_package(
            policy.executable,
            policy.package_full_name,
        ):
            return _result(
                policy,
                SandboxStatus.DENIED,
                "adapter_package_path_mismatch",
            )
        if not executable_path_is_protected(policy.executable):
            return _result(
                policy,
                SandboxStatus.DENIED,
                "adapter_path_unprotected",
            )
    try:
        with hold_executable_for_launch(policy.executable) as executable_handle:
            return _run_mcp_sandbox_with_locked_executable(
                policy,
                request,
                assessment,
                executable_handle=executable_handle,
                temp_root=temp_root,
            )
    except (OSError, ValueError):
        return _result(policy, SandboxStatus.FAILED, "sandbox_launch_failed")


def _run_mcp_sandbox_with_locked_executable(
    policy: McpSandboxPolicy,
    request: bytes,
    assessment: SandboxAssessment,
    *,
    executable_handle: int | None,
    temp_root: pathlib.Path | None,
) -> McpSandboxResult:
    try:
        current_sha256 = bounded_file_sha256(policy.executable)
    except FileSizeLimitExceeded:
        return _result(policy, SandboxStatus.DENIED, "executable_size_limit")
    except OSError:
        return _result(policy, SandboxStatus.FAILED, "executable_unavailable")
    if current_sha256 != policy.executable_sha256:
        return _result(policy, SandboxStatus.DENIED, "executable_hash_mismatch")
    if assessment.provider == "windows-appcontainer":
        if (
            not policy.allowed_publisher_subjects
            or not policy.allowed_publisher_certificate_sha256
        ):
            return _result(policy, SandboxStatus.DENIED, "adapter_publisher_allowlist_required")
        if not verify_authenticode(
            policy.executable,
            file_handle=executable_handle,
        ):
            return _result(policy, SandboxStatus.DENIED, "adapter_signature_required")
        if not verify_authenticode_publisher(
            policy.executable,
            policy.allowed_publisher_subjects,
            allowed_certificate_sha256=policy.allowed_publisher_certificate_sha256,
            signature_already_verified=True,
        ):
            return _result(policy, SandboxStatus.DENIED, "adapter_publisher_not_allowlisted")
    root = _validated_temp_root(temp_root)
    with tempfile.TemporaryDirectory(dir=root) as workdir:
        if os.name == "nt":
            if assessment.provider == "windows-appcontainer":
                return _run_windows_appcontainer(policy, request, pathlib.Path(workdir))
            return _run_windows_job_object(policy, request, pathlib.Path(workdir))
        process = subprocess.Popen(
            [os.fspath(policy.executable), *policy.arguments],
            shell=False,
            cwd=workdir,
            env={"PYTHONNOUSERSITE": "1"},
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
        try:
            output, _ = process.communicate(
                input=request,
                timeout=policy.max_runtime_seconds,
            )
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            return _result(
                policy,
                SandboxStatus.TIMED_OUT,
                "runtime_limit",
                limits=("process_tree_isolation_enforced",),
            )
        if len(output) > policy.max_output_bytes:
            return _result(
                policy,
                SandboxStatus.FAILED,
                "output_size_limit",
                response_bytes=policy.max_output_bytes,
            )
        if process.returncode != 0:
            return _result(
                policy,
                SandboxStatus.FAILED,
                "adapter_failed",
                response_bytes=len(output),
            )
        return _result(
            policy,
            SandboxStatus.COMPLETED,
            "completed",
            response_bytes=len(output),
        )


def _run_windows_job_object(
    policy: McpSandboxPolicy,
    request: bytes,
    workdir: pathlib.Path,
) -> McpSandboxResult:
    try:
        native = run_in_job_object(
            policy.executable,
            policy.arguments,
            request,
            workdir=workdir,
            environment={"PYTHONNOUSERSITE": "1"},
            timeout_seconds=policy.max_runtime_seconds,
            max_output_bytes=policy.max_output_bytes,
        )
    except JobObjectUnavailable:
        return _result(
            policy,
            SandboxStatus.DENIED,
            "native_process_tree_isolation_unavailable",
        )
    except Exception:  # noqa: BLE001 - native boundary fails closed
        return _result(policy, SandboxStatus.FAILED, "sandbox_launch_failed")
    if native.timed_out:
        return _result(
            policy,
            SandboxStatus.TIMED_OUT,
            "runtime_limit",
            limits=("process_tree_isolation_enforced",),
        )
    if native.output_limited:
        return _result(
            policy,
            SandboxStatus.FAILED,
            "output_size_limit",
            response_bytes=policy.max_output_bytes,
            limits=("process_tree_isolation_enforced",),
        )
    if native.returncode != 0:
        return _result(
            policy,
            SandboxStatus.FAILED,
            "adapter_failed",
            response_bytes=len(native.output),
            limits=("process_tree_isolation_enforced",),
        )
    return _result(
        policy,
        SandboxStatus.COMPLETED,
        "completed",
        response_bytes=len(native.output),
        limits=("process_tree_isolation_enforced",),
    )


def _run_windows_appcontainer(
    policy: McpSandboxPolicy,
    request: bytes,
    workdir: pathlib.Path,
) -> McpSandboxResult:
    try:
        native = run_in_appcontainer(
            policy.executable,
            policy.arguments,
            request,
            workdir=workdir,
            environment={"PYTHONNOUSERSITE": "1"},
            timeout_seconds=policy.max_runtime_seconds,
            max_output_bytes=policy.max_output_bytes,
        )
    except AppContainerUnavailable:
        return _result(
            policy,
            SandboxStatus.DENIED,
            "native_network_isolation_unavailable",
        )
    except Exception:  # noqa: BLE001 - native boundary fails closed
        return _result(policy, SandboxStatus.FAILED, "sandbox_launch_failed")
    if native.timed_out:
        return _result(
            policy,
            SandboxStatus.TIMED_OUT,
            "runtime_limit",
            limits=("network_isolation_enforced", "process_tree_isolation_enforced"),
        )
    if native.output_limited:
        return _result(
            policy,
            SandboxStatus.FAILED,
            "output_size_limit",
            response_bytes=policy.max_output_bytes,
            limits=("network_isolation_enforced", "process_tree_isolation_enforced"),
        )
    if native.returncode != 0:
        return _result(
            policy,
            SandboxStatus.FAILED,
            "adapter_failed",
            response_bytes=len(native.output),
            limits=("network_isolation_enforced", "process_tree_isolation_enforced"),
        )
    return _result(
        policy,
        SandboxStatus.COMPLETED,
        "completed",
        response_bytes=len(native.output),
        limits=("network_isolation_enforced", "process_tree_isolation_enforced"),
    )


def probe_native_sandbox() -> _SandboxAttestation | None:
    """Return a platform attestation only when native controls are proven.

    Windows AppContainer provides the network-deny and process-tree boundary
    used by the supervisor. Portable and MSIX full-trust launchers without
    that provider continue to return no attestation.
    """
    if os.name == "nt" and appcontainer_available():
        return _SandboxAttestation(
            provider="windows-appcontainer",
            network_isolated=True,
            process_tree_isolated=True,
        )
    return None


def _validated_temp_root(value: pathlib.Path | None) -> str | None:
    if value is None:
        return None
    root = pathlib.Path(value)
    if not root.is_dir() or root.is_symlink() or _has_reparse_component(root):
        raise ValueError("MCP_TEMP_ROOT_INVALID")
    return os.fspath(root)


def _result(
    policy: McpSandboxPolicy,
    status: SandboxStatus,
    reason: str,
    *,
    response_bytes: int = 0,
    limits: tuple[str, ...] = (),
) -> McpSandboxResult:
    return McpSandboxResult(
        status=status,
        adapter_id=policy.adapter_id,
        reason=reason,
        response_bytes=response_bytes,
        raw_response_retained=False,
        limits=limits,
    )


def _is_unc(path: pathlib.Path) -> bool:
    return os.fspath(path).startswith(("\\\\", "//"))
