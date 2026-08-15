from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import scripts.run_windows_mcp_adapter_acceptance as acceptance
from agentguardian.file_integrity import FileSizeLimitExceeded
from agentguardian.mcp_sandbox import McpSandboxResult, SandboxStatus
from scripts.run_windows_mcp_adapter_acceptance import run_packaged_adapter_acceptance


COMMIT = "a" * 40
PUBLISHER_SUBJECT = "CN=AgentGuardian Adapter Publisher,O=AgentGuardian"
CERTIFICATE_SHA256 = "b" * 64
ADAPTER_NAME = "AgentGuardianMcpAdapter.exe"
NATIVE_LIMITS = (
    "network_isolation_enforced",
    "process_tree_isolation_enforced",
)


def _adapter(tmp_path: Path) -> tuple[Path, str]:
    adapter = tmp_path / ADAPTER_NAME
    adapter.write_bytes(b"synthetic packaged adapter")
    return adapter, hashlib.sha256(adapter.read_bytes()).hexdigest()


def _result(
    *,
    status: SandboxStatus = SandboxStatus.COMPLETED,
    reason: str = "completed",
    response_bytes: int = 17,
    raw_response_retained: bool = False,
    limits: tuple[str, ...] = NATIVE_LIMITS,
) -> McpSandboxResult:
    return McpSandboxResult(
        status=status,
        adapter_id="packaged-adapter",
        reason=reason,
        response_bytes=response_bytes,
        raw_response_retained=raw_response_retained,
        limits=limits,
    )


def _run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    sandbox_result: McpSandboxResult | None = None,
) -> tuple[dict[str, object], Path, Path, str]:
    adapter, adapter_sha256 = _adapter(tmp_path)
    evidence_path = tmp_path / "mcp-acceptance.json"
    captured: dict[str, object] = {}

    def fake_run(policy: object, request: bytes, *, confirmed: bool) -> McpSandboxResult:
        captured.update(policy=policy, request=request, confirmed=confirmed)
        return sandbox_result or _result()

    monkeypatch.setattr(acceptance, "run_mcp_sandbox", fake_run)
    evidence = run_packaged_adapter_acceptance(
        adapter,
        evidence_path,
        expected_source_commit=COMMIT,
        expected_adapter_sha256=adapter_sha256,
        expected_publisher_subject=PUBLISHER_SUBJECT,
        expected_certificate_sha256=CERTIFICATE_SHA256,
    )
    policy = captured["policy"]
    assert policy.executable == adapter
    assert policy.executable_sha256 == adapter_sha256
    assert policy.arguments == ()
    assert policy.allowed_publisher_subjects == (PUBLISHER_SUBJECT,)
    assert policy.allowed_publisher_certificate_sha256 == (CERTIFICATE_SHA256,)
    assert captured["request"] == acceptance.SYNTHETIC_REQUEST
    assert captured["confirmed"] is True
    return evidence, adapter, evidence_path, adapter_sha256


def test_acceptance_writes_only_canonical_bounded_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence, adapter, evidence_path, adapter_sha256 = _run(tmp_path, monkeypatch)
    expected = {
        "schema": 1,
        "source_commit": COMMIT,
        "adapter": {
            "name": ADAPTER_NAME,
            "sha256": adapter_sha256,
            "publisher_subject": PUBLISHER_SUBJECT,
            "certificate_sha256": CERTIFICATE_SHA256,
        },
        "sandbox": {
            "status": "completed",
            "reason": "completed",
            "response_bytes": 17,
            "raw_response_retained": False,
            "limits": list(NATIVE_LIMITS),
        },
        "passed": True,
    }
    assert evidence == expected
    assert evidence_path.read_bytes() == (
        json.dumps(expected, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")
    serialized = evidence_path.read_bytes()
    assert str(adapter).encode() not in serialized
    assert acceptance.SYNTHETIC_REQUEST not in serialized
    assert b"synthetic-response-marker" not in serialized
    assert b"PYTHONNOUSERSITE" not in serialized
    assert b"synthetic exception text" not in serialized


def test_acceptance_rejects_an_oversize_adapter_before_sandbox_or_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter, adapter_sha256 = _adapter(tmp_path)
    evidence_path = tmp_path / "mcp-acceptance.json"
    monkeypatch.setattr(
        acceptance,
        "bounded_file_sha256",
        lambda _path: (_ for _ in ()).throw(FileSizeLimitExceeded()),
    )
    monkeypatch.setattr(
        acceptance,
        "run_mcp_sandbox",
        lambda *_args, **_kwargs: pytest.fail("oversize adapter reached sandbox"),
    )

    with pytest.raises(ValueError, match="MCP_ACCEPTANCE_ADAPTER_SIZE_LIMIT"):
        run_packaged_adapter_acceptance(
            adapter,
            evidence_path,
            expected_source_commit=COMMIT,
            expected_adapter_sha256=adapter_sha256,
            expected_publisher_subject=PUBLISHER_SUBJECT,
            expected_certificate_sha256=CERTIFICATE_SHA256,
        )

    assert not evidence_path.exists()


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    (
        ("expected_source_commit", "A" * 40, "MCP_ACCEPTANCE_SOURCE_COMMIT_INVALID"),
        ("expected_source_commit", "a" * 39, "MCP_ACCEPTANCE_SOURCE_COMMIT_INVALID"),
        ("expected_adapter_sha256", "A" * 64, "MCP_ACCEPTANCE_ADAPTER_HASH_INVALID"),
        ("expected_publisher_subject", "", "MCP_ACCEPTANCE_PUBLISHER_SUBJECT_INVALID"),
        (
            "expected_publisher_subject",
            " CN=AgentGuardian Adapter Publisher",
            "MCP_ACCEPTANCE_PUBLISHER_SUBJECT_INVALID",
        ),
        ("expected_certificate_sha256", "B" * 64, "MCP_ACCEPTANCE_CERTIFICATE_HASH_INVALID"),
        ("expected_certificate_sha256", "b" * 63, "MCP_ACCEPTANCE_CERTIFICATE_HASH_INVALID"),
    ),
)
def test_acceptance_rejects_invalid_identity_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: str,
    expected: str,
) -> None:
    adapter, adapter_sha256 = _adapter(tmp_path)
    arguments = {
        "expected_source_commit": COMMIT,
        "expected_adapter_sha256": adapter_sha256,
        "expected_publisher_subject": PUBLISHER_SUBJECT,
        "expected_certificate_sha256": CERTIFICATE_SHA256,
    }
    arguments[field] = value
    monkeypatch.setattr(
        acceptance,
        "run_mcp_sandbox",
        lambda *_args, **_kwargs: pytest.fail("sandbox must not run"),
    )

    with pytest.raises(ValueError, match=expected):
        run_packaged_adapter_acceptance(
            adapter,
            tmp_path / "evidence.json",
            **arguments,
        )


def test_acceptance_rejects_adapter_hash_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter, _adapter_sha256 = _adapter(tmp_path)
    monkeypatch.setattr(
        acceptance,
        "run_mcp_sandbox",
        lambda *_args, **_kwargs: pytest.fail("sandbox must not run"),
    )

    with pytest.raises(ValueError, match="MCP_ACCEPTANCE_ADAPTER_HASH_MISMATCH"):
        run_packaged_adapter_acceptance(
            adapter,
            tmp_path / "evidence.json",
            expected_source_commit=COMMIT,
            expected_adapter_sha256="0" * 64,
            expected_publisher_subject=PUBLISHER_SUBJECT,
            expected_certificate_sha256=CERTIFICATE_SHA256,
        )


@pytest.mark.parametrize(
    "sandbox_result",
    (
        _result(status=SandboxStatus.DENIED, reason="adapter_publisher_not_allowlisted"),
        _result(status=SandboxStatus.FAILED, reason="sandbox_launch_failed"),
        _result(response_bytes=0),
        _result(response_bytes=65_537),
        _result(raw_response_retained=True),
        _result(limits=("network_isolation_enforced",)),
        _result(limits=("process_tree_isolation_enforced",)),
        _result(limits=NATIVE_LIMITS + ("unexpected_limit",)),
    ),
)
def test_acceptance_rejects_unbounded_or_failed_sandbox_results(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    sandbox_result: McpSandboxResult,
) -> None:
    adapter, adapter_sha256 = _adapter(tmp_path)
    evidence_path = tmp_path / "evidence.json"
    monkeypatch.setattr(acceptance, "run_mcp_sandbox", lambda *_args, **_kwargs: sandbox_result)

    with pytest.raises(RuntimeError, match="MCP_ADAPTER_ACCEPTANCE_FAILED"):
        run_packaged_adapter_acceptance(
            adapter,
            evidence_path,
            expected_source_commit=COMMIT,
            expected_adapter_sha256=adapter_sha256,
            expected_publisher_subject=PUBLISHER_SUBJECT,
            expected_certificate_sha256=CERTIFICATE_SHA256,
        )
    assert not evidence_path.exists()


def test_acceptance_rejects_invalid_adapter_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter, adapter_sha256 = _adapter(tmp_path)
    wrong_name = tmp_path / "other.exe"
    wrong_name.write_bytes(adapter.read_bytes())
    monkeypatch.setattr(
        acceptance,
        "run_mcp_sandbox",
        lambda *_args, **_kwargs: pytest.fail("sandbox must not run"),
    )

    for invalid in (Path(ADAPTER_NAME), wrong_name, tmp_path / "missing" / ADAPTER_NAME):
        with pytest.raises(ValueError, match="MCP_ACCEPTANCE_ADAPTER_PATH_INVALID"):
            run_packaged_adapter_acceptance(
                invalid,
                tmp_path / "evidence.json",
                expected_source_commit=COMMIT,
                expected_adapter_sha256=adapter_sha256,
                expected_publisher_subject=PUBLISHER_SUBJECT,
                expected_certificate_sha256=CERTIFICATE_SHA256,
            )

    monkeypatch.setattr(acceptance, "_has_reparse_component", lambda path: path == adapter)
    with pytest.raises(ValueError, match="MCP_ACCEPTANCE_ADAPTER_PATH_INVALID"):
        run_packaged_adapter_acceptance(
            adapter,
            tmp_path / "evidence.json",
            expected_source_commit=COMMIT,
            expected_adapter_sha256=adapter_sha256,
            expected_publisher_subject=PUBLISHER_SUBJECT,
            expected_certificate_sha256=CERTIFICATE_SHA256,
        )


def test_acceptance_requires_a_new_absolute_non_reparse_evidence_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter, adapter_sha256 = _adapter(tmp_path)
    existing = tmp_path / "existing.json"
    existing.write_text("preserve", encoding="utf-8")
    monkeypatch.setattr(acceptance, "run_mcp_sandbox", lambda *_args, **_kwargs: _result())

    for invalid in (Path("relative.json"), existing, tmp_path / "missing" / "evidence.json"):
        with pytest.raises(ValueError, match="MCP_ACCEPTANCE_EVIDENCE_PATH_INVALID"):
            run_packaged_adapter_acceptance(
                adapter,
                invalid,
                expected_source_commit=COMMIT,
                expected_adapter_sha256=adapter_sha256,
                expected_publisher_subject=PUBLISHER_SUBJECT,
                expected_certificate_sha256=CERTIFICATE_SHA256,
            )
    assert existing.read_text(encoding="utf-8") == "preserve"

    evidence_path = tmp_path / "reparse.json"
    monkeypatch.setattr(acceptance, "_has_reparse_component", lambda path: path == evidence_path)
    with pytest.raises(ValueError, match="MCP_ACCEPTANCE_EVIDENCE_PATH_INVALID"):
        run_packaged_adapter_acceptance(
            adapter,
            evidence_path,
            expected_source_commit=COMMIT,
            expected_adapter_sha256=adapter_sha256,
            expected_publisher_subject=PUBLISHER_SUBJECT,
            expected_certificate_sha256=CERTIFICATE_SHA256,
        )
    assert not evidence_path.exists()
