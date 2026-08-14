from __future__ import annotations

import pytest

from scripts.run_windows_mvp_security_gate import ALLOWED_SKIPS


_skips: list[tuple[str, str]] = []


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    if report.skipped:
        _skips.append((report.nodeid, str(report.longrepr)))


def _is_allowed(nodeid: str, reason: str) -> bool:
    return any(
        nodeid == allowed_node and marker in reason
        for allowed_node, marker in ALLOWED_SKIPS
    )


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    unexpected = [
        (nodeid, reason)
        for nodeid, reason in _skips
        if not _is_allowed(nodeid, reason)
    ]
    if unexpected:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


def pytest_terminal_summary(terminalreporter: object) -> None:
    unexpected = [
        (nodeid, reason)
        for nodeid, reason in _skips
        if not _is_allowed(nodeid, reason)
    ]
    if unexpected:
        terminalreporter.write_sep("=", "unexpected security-gate skips")
        for nodeid, reason in unexpected:
            terminalreporter.write_line(f"{nodeid}: {reason}")
