from __future__ import annotations

import socket
import sys
import hashlib
from pathlib import Path

import pytest

import agentguardian.mcp_sandbox as mcp_sandbox
from agentguardian.windows_appcontainer import _profile_name, run_in_appcontainer
from agentguardian.mcp_sandbox import McpSandboxPolicy, SandboxStatus, run_mcp_sandbox


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Windows AppContainer is only available on Windows",
)


def test_appcontainer_profile_name_is_unique_per_run() -> None:
    executable = Path(r"C:\Windows\System32\curl.exe")
    assert _profile_name(executable) != _profile_name(executable)


def test_appcontainer_denies_loopback_and_cleans_transient_state(tmp_path: Path) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(0.5)
        port = listener.getsockname()[1]
        result = run_in_appcontainer(
            Path(r"C:\Windows\System32\curl.exe"),
            ("-sS", "--max-time", "1", f"http://127.0.0.1:{port}"),
            b"synthetic-request",
            workdir=tmp_path,
            environment={"PYTHONNOUSERSITE": "1"},
            timeout_seconds=5.0,
            max_output_bytes=4096,
        )

        assert result.network_isolated is True
        assert result.process_tree_isolated is True
        assert result.profile_removed is True
        assert result.returncode != 0
        with pytest.raises(TimeoutError):
            listener.accept()
    assert tuple(tmp_path.iterdir()) == ()


def test_mcp_supervisor_uses_appcontainer_network_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = Path(r"C:\Windows\System32\curl.exe")
    monkeypatch.setattr(
        mcp_sandbox,
        "verify_authenticode",
        lambda _path, **_kwargs: True,
    )
    monkeypatch.setattr(
        mcp_sandbox,
        "verify_authenticode_publisher",
        lambda _path, _allowed, **_kwargs: True,
    )
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(0.5)
        port = listener.getsockname()[1]
        policy = McpSandboxPolicy.from_command(
            adapter_id="curl-probe",
            executable=executable,
            executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
            arguments=("-sS", "--max-time", "1", f"http://127.0.0.1:{port}"),
            allowed_publisher_subjects=("CN=Windows Test Publisher",),
            allowed_publisher_certificate_sha256=("0" * 64,),
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
        assert result.limits == (
            "network_isolation_enforced",
            "process_tree_isolation_enforced",
        )
        with pytest.raises(TimeoutError):
            listener.accept()
    assert tuple(tmp_path.iterdir()) == ()
