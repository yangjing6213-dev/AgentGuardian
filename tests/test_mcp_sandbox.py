from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

import agentguardian.mcp_sandbox as mcp_sandbox
from agentguardian.mcp_sandbox import (
    McpSandboxPolicy,
    SandboxStatus,
    _SandboxAttestation,
    assess_mcp_sandbox,
    run_mcp_sandbox,
)
from agentguardian.windows_job_object import JobObjectRun


def _policy() -> McpSandboxPolicy:
    executable = Path(sys.executable)
    return McpSandboxPolicy.from_command(
        adapter_id="synthetic-adapter",
        executable=executable,
        executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        arguments=("-c", "import sys; sys.stdout.buffer.write(b'ok')"),
    )


def test_policy_requires_an_absolute_regular_executable_and_fixed_argv() -> None:
    assert _policy().network_access == "deny"
    with pytest.raises(ValueError, match="MCP_EXECUTABLE_INVALID"):
        McpSandboxPolicy.from_command(
            adapter_id="synthetic-adapter",
            executable="python",
            executable_sha256="0" * 64,
        )
    with pytest.raises(ValueError, match="MCP_ARGUMENT_INVALID"):
        McpSandboxPolicy.from_command(
            adapter_id="synthetic-adapter",
            executable=sys.executable,
            executable_sha256="0" * 64,
            arguments=("--bad\x00arg",),
        )
    with pytest.raises(ValueError, match="MCP_PUBLISHER_ALLOWLIST_INVALID"):
        McpSandboxPolicy.from_command(
            adapter_id="synthetic-adapter",
            executable=sys.executable,
            executable_sha256="0" * 64,
            allowed_publisher_subjects=("",),
        )


def test_policy_keeps_an_explicit_publisher_allowlist() -> None:
    policy = McpSandboxPolicy.from_command(
        adapter_id="synthetic-adapter",
        executable=sys.executable,
        executable_sha256=hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
        allowed_publisher_subjects=("CN=AgentGuardian Adapter Publisher",),
    )
    assert policy.allowed_publisher_subjects == ("CN=AgentGuardian Adapter Publisher",)


def test_assessment_is_denied_without_native_network_and_process_isolation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(mcp_sandbox, "probe_native_sandbox", lambda: None)
    assessment = assess_mcp_sandbox(_policy())
    assert assessment.status is SandboxStatus.DENIED
    assert assessment.network_isolation == "unavailable"
    assert assessment.process_tree_isolation == "unavailable"
    assert assessment.reasons == (
        "native_network_isolation_required",
        "native_process_tree_isolation_required",
    )


def test_default_run_does_not_start_a_process_or_retain_raw_output(monkeypatch: pytest.MonkeyPatch) -> None:
    started = False

    def forbidden(*_args: object, **_kwargs: object) -> None:
        nonlocal started
        started = True

    monkeypatch.setattr(mcp_sandbox, "probe_native_sandbox", lambda: None)
    monkeypatch.setattr("agentguardian.mcp_sandbox.subprocess.Popen", forbidden)
    result = run_mcp_sandbox(_policy(), b"synthetic-request", confirmed=True)
    assert result.status is SandboxStatus.DENIED
    assert result.reason == "native_network_isolation_required"
    assert result.raw_response_retained is False
    assert result.response_bytes == 0
    assert started is False


def test_attested_execution_is_bounded_and_returns_only_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = McpSandboxPolicy.from_command(
        adapter_id="synthetic-adapter",
        executable=sys.executable,
        executable_sha256=hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
        arguments=("-c", "import sys; sys.stdout.buffer.write(b'ok')"),
    )
    monkeypatch.setattr(
        mcp_sandbox,
        "probe_native_sandbox",
        lambda: _SandboxAttestation(
            provider="synthetic-test-only",
            network_isolated=True,
            process_tree_isolated=True,
        ),
    )
    result = run_mcp_sandbox(
        policy,
        b"synthetic-request",
        confirmed=True,
        temp_root=tmp_path,
    )
    assert result.status is SandboxStatus.COMPLETED
    assert result.response_bytes == 2
    assert result.raw_response_retained is False
    assert tuple(tmp_path.iterdir()) == ()


def test_adapter_crash_fails_closed_without_restart_or_raw_retention(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = McpSandboxPolicy.from_command(
        adapter_id="crashing-adapter",
        executable=sys.executable,
        executable_sha256=hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
        arguments=("-c", "raise SystemExit(17)"),
    )
    monkeypatch.setattr(
        mcp_sandbox,
        "probe_native_sandbox",
        lambda: _SandboxAttestation(
            provider="synthetic-test-only",
            network_isolated=True,
            process_tree_isolated=True,
        ),
    )

    result = run_mcp_sandbox(
        policy,
        b"synthetic-request",
        confirmed=True,
        temp_root=tmp_path,
    )

    assert result.status is SandboxStatus.FAILED
    assert result.reason == "adapter_failed"
    assert result.raw_response_retained is False
    assert tuple(tmp_path.iterdir()) == ()


def test_attested_execution_rejects_oversize_request() -> None:
    with pytest.raises(ValueError, match="MCP_REQUEST_SIZE_LIMIT"):
        run_mcp_sandbox(_policy(), b"x" * 65_537, confirmed=True)


def test_attested_execution_rechecks_the_executable_hash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _policy()
    monkeypatch.setattr(
        mcp_sandbox,
        "probe_native_sandbox",
        lambda: _SandboxAttestation(
            provider="synthetic-test-only",
            network_isolated=True,
            process_tree_isolated=True,
        ),
    )
    tampered = McpSandboxPolicy(
        adapter_id=policy.adapter_id,
        executable=policy.executable,
        executable_sha256="0" * 64,
        arguments=policy.arguments,
        capabilities=policy.capabilities,
        network_access=policy.network_access,
        max_runtime_seconds=policy.max_runtime_seconds,
        max_output_bytes=policy.max_output_bytes,
    )
    result = run_mcp_sandbox(tampered, b"synthetic-request", confirmed=True)
    assert result.status is SandboxStatus.DENIED
    assert result.reason == "executable_hash_mismatch"


def test_attested_windows_execution_uses_job_object_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if sys.platform != "win32":
        pytest.skip("Windows Job Object integration")
    policy = _policy()
    calls = []
    monkeypatch.setattr(
        mcp_sandbox,
        "probe_native_sandbox",
        lambda: _SandboxAttestation(
            provider="synthetic-test-only",
            network_isolated=True,
            process_tree_isolated=True,
        ),
    )

    def fake_run(*args: object, **kwargs: object) -> JobObjectRun:
        calls.append((args, kwargs))
        return JobObjectRun(0, b"ok", False, False, True)

    monkeypatch.setattr(mcp_sandbox, "run_in_job_object", fake_run)
    monkeypatch.setattr(
        mcp_sandbox.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("Popen bypassed native job boundary"),
    )

    result = run_mcp_sandbox(
        policy,
        b"synthetic-request",
        confirmed=True,
        temp_root=tmp_path,
    )

    assert result.status is SandboxStatus.COMPLETED
    assert result.response_bytes == 2
    assert result.limits == ("process_tree_isolation_enforced",)
    assert len(calls) == 1


def test_native_windows_execution_requires_a_trusted_adapter_signature(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if sys.platform != "win32":
        pytest.skip("Windows Authenticode integration")
    policy = _policy()
    monkeypatch.setattr(
        mcp_sandbox,
        "probe_native_sandbox",
        lambda: _SandboxAttestation(
            provider="windows-appcontainer",
            network_isolated=True,
            process_tree_isolated=True,
        ),
    )
    policy = McpSandboxPolicy.from_command(
        adapter_id=policy.adapter_id,
        executable=policy.executable,
        executable_sha256=policy.executable_sha256,
        arguments=policy.arguments,
        allowed_publisher_subjects=("CN=Trusted",),
    )
    monkeypatch.setattr(mcp_sandbox, "verify_authenticode", lambda _path: False)

    result = run_mcp_sandbox(policy, b"synthetic-request", confirmed=True)

    assert result.status is SandboxStatus.DENIED
    assert result.reason == "adapter_signature_required"
    assert result.raw_response_retained is False


def test_native_windows_execution_requires_a_publisher_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if sys.platform != "win32":
        pytest.skip("Windows Authenticode integration")
    policy = _policy()
    monkeypatch.setattr(
        mcp_sandbox,
        "probe_native_sandbox",
        lambda: _SandboxAttestation(
            provider="windows-appcontainer",
            network_isolated=True,
            process_tree_isolated=True,
        ),
    )
    result = run_mcp_sandbox(policy, b"synthetic-request", confirmed=True)

    assert result.status is SandboxStatus.DENIED
    assert result.reason == "adapter_publisher_allowlist_required"


def test_native_windows_execution_rejects_a_non_allowlisted_publisher(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if sys.platform != "win32":
        pytest.skip("Windows Authenticode integration")
    policy = McpSandboxPolicy.from_command(
        adapter_id="synthetic-adapter",
        executable=sys.executable,
        executable_sha256=hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
        allowed_publisher_subjects=("CN=Allowed",),
    )
    monkeypatch.setattr(
        mcp_sandbox,
        "probe_native_sandbox",
        lambda: _SandboxAttestation(
            provider="windows-appcontainer",
            network_isolated=True,
            process_tree_isolated=True,
        ),
    )
    monkeypatch.setattr(mcp_sandbox, "verify_authenticode", lambda _path: True)
    monkeypatch.setattr(
        mcp_sandbox,
        "verify_authenticode_publisher",
        lambda _path, _allowed: False,
    )

    result = run_mcp_sandbox(policy, b"synthetic-request", confirmed=True)

    assert result.status is SandboxStatus.DENIED
    assert result.reason == "adapter_publisher_not_allowlisted"


@pytest.mark.parametrize(
    ("runner_name", "launcher_name"),
    (
        ("_run_windows_job_object", "run_in_job_object"),
        ("_run_windows_appcontainer", "run_in_appcontainer"),
    ),
)
def test_native_launcher_unexpected_exception_fails_closed_without_leaking(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    runner_name: str,
    launcher_name: str,
) -> None:
    policy = _policy()
    marker = "synthetic native launcher failure"

    def fail_closed(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(marker)

    monkeypatch.setattr(mcp_sandbox, launcher_name, fail_closed)
    result = getattr(mcp_sandbox, runner_name)(
        policy,
        b"synthetic-request",
        tmp_path,
    )

    assert result.status is SandboxStatus.FAILED
    assert result.reason == "sandbox_launch_failed"
    assert result.raw_response_retained is False
    assert marker not in repr(result)
