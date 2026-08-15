"""Run bounded acceptance for the packaged Windows MCP adapter."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentguardian.discovery import _has_reparse_component  # noqa: E402
from agentguardian.file_integrity import (  # noqa: E402
    FileSizeLimitExceeded,
    bounded_file_sha256,
)
from agentguardian.mcp_sandbox import (  # noqa: E402
    McpSandboxPolicy,
    SandboxStatus,
    run_mcp_sandbox,
)


ADAPTER_NAME = "AgentGuardianMcpAdapter.exe"
SYNTHETIC_REQUEST = (
    b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}\n'
)
_NATIVE_LIMITS = (
    "network_isolation_enforced",
    "process_tree_isolation_enforced",
)


def run_packaged_adapter_acceptance(
    adapter_path: str | Path,
    evidence_path: str | Path,
    *,
    expected_source_commit: str,
    expected_adapter_sha256: str,
    expected_publisher_subject: str,
    expected_certificate_sha256: str,
) -> dict[str, object]:
    adapter = _adapter_path(adapter_path)
    destination = _evidence_path(evidence_path)
    _lower_hex(expected_source_commit, 40, "MCP_ACCEPTANCE_SOURCE_COMMIT_INVALID")
    _lower_hex(expected_adapter_sha256, 64, "MCP_ACCEPTANCE_ADAPTER_HASH_INVALID")
    if (
        type(expected_publisher_subject) is not str
        or not expected_publisher_subject
        or expected_publisher_subject != expected_publisher_subject.strip()
        or len(expected_publisher_subject) > 512
        or "\x00" in expected_publisher_subject
    ):
        raise ValueError("MCP_ACCEPTANCE_PUBLISHER_SUBJECT_INVALID")
    _lower_hex(
        expected_certificate_sha256,
        64,
        "MCP_ACCEPTANCE_CERTIFICATE_HASH_INVALID",
    )
    try:
        actual_sha256 = bounded_file_sha256(adapter)
    except FileSizeLimitExceeded:
        raise ValueError("MCP_ACCEPTANCE_ADAPTER_SIZE_LIMIT") from None
    except OSError:
        raise ValueError("MCP_ACCEPTANCE_ADAPTER_PATH_INVALID") from None
    if actual_sha256 != expected_adapter_sha256:
        raise ValueError("MCP_ACCEPTANCE_ADAPTER_HASH_MISMATCH")

    policy = McpSandboxPolicy.from_command(
        adapter_id="packaged-adapter",
        executable=adapter,
        executable_sha256=expected_adapter_sha256,
        arguments=(),
        allowed_publisher_subjects=(expected_publisher_subject,),
        allowed_publisher_certificate_sha256=(expected_certificate_sha256,),
    )
    try:
        result = run_mcp_sandbox(policy, SYNTHETIC_REQUEST, confirmed=True)
    except Exception:  # noqa: BLE001 - acceptance boundary must not leak adapter details
        raise RuntimeError("MCP_ADAPTER_ACCEPTANCE_FAILED") from None
    if (
        result.status is not SandboxStatus.COMPLETED
        or result.reason != "completed"
        or type(result.response_bytes) is not int
        or result.response_bytes <= 0
        or result.response_bytes > policy.max_output_bytes
        or result.raw_response_retained is not False
        or result.limits != _NATIVE_LIMITS
    ):
        raise RuntimeError("MCP_ADAPTER_ACCEPTANCE_FAILED")

    evidence = {
        "schema": 1,
        "source_commit": expected_source_commit,
        "adapter": {
            "name": adapter.name,
            "sha256": expected_adapter_sha256,
            "publisher_subject": expected_publisher_subject,
            "certificate_sha256": expected_certificate_sha256,
        },
        "sandbox": {
            "status": result.status.value,
            "reason": result.reason,
            "response_bytes": result.response_bytes,
            "raw_response_retained": result.raw_response_retained,
            "limits": list(result.limits),
        },
        "passed": True,
    }
    payload = (
        json.dumps(evidence, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")
    try:
        with destination.open("xb") as output:
            output.write(payload)
    except OSError:
        raise RuntimeError("MCP_ADAPTER_ACCEPTANCE_WRITE_FAILED") from None
    return evidence


def _adapter_path(value: str | Path) -> Path:
    path = Path(value)
    if (
        not path.is_absolute()
        or path.name != ADAPTER_NAME
        or _is_unc(path)
        or path.is_symlink()
        or _has_reparse_component(path)
    ):
        raise ValueError("MCP_ACCEPTANCE_ADAPTER_PATH_INVALID")
    try:
        target_stat = os.lstat(path)
    except OSError:
        raise ValueError("MCP_ACCEPTANCE_ADAPTER_PATH_INVALID") from None
    if not stat.S_ISREG(target_stat.st_mode):
        raise ValueError("MCP_ACCEPTANCE_ADAPTER_PATH_INVALID")
    return path


def _evidence_path(value: str | Path) -> Path:
    path = Path(value)
    if (
        not path.is_absolute()
        or _is_unc(path)
        or path.exists()
        or path.is_symlink()
        or not path.parent.is_dir()
        or _has_reparse_component(path)
    ):
        raise ValueError("MCP_ACCEPTANCE_EVIDENCE_PATH_INVALID")
    return path


def _lower_hex(value: object, length: int, code: str) -> None:
    if (
        type(value) is not str
        or len(value) != length
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(code)


def _is_unc(path: Path) -> bool:
    return path.anchor.startswith("\\\\") or os.fspath(path).startswith(("\\\\", "//"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter-path", type=Path, required=True)
    parser.add_argument("--evidence-path", type=Path, required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--expected-adapter-sha256", required=True)
    parser.add_argument("--expected-publisher-subject", required=True)
    parser.add_argument("--expected-certificate-sha256", required=True)
    args = parser.parse_args()
    try:
        evidence = run_packaged_adapter_acceptance(
            args.adapter_path,
            args.evidence_path,
            expected_source_commit=args.expected_source_commit,
            expected_adapter_sha256=args.expected_adapter_sha256,
            expected_publisher_subject=args.expected_publisher_subject,
            expected_certificate_sha256=args.expected_certificate_sha256,
        )
    except (RuntimeError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(evidence, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
