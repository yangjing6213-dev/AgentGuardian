from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
import subprocess
import sys

import pytest

from agentguardian.audit_service import MAX_AUDIT_FINDINGS, run_clipboard_audit


PROJECT_ROOT = Path(__file__).parents[1]
DISPOSITION_KEY = b"d" * 32


def test_audit_service_import_does_not_import_qt() -> None:
    completed = subprocess.run(
        (
            sys.executable,
            "-c",
            "import sys; import agentguardian.audit_service; "
            "assert not any(name.startswith('PySide6') for name in sys.modules)",
        ),
        cwd=PROJECT_ROOT,
        env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT / "src")},
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_clipboard_service_builds_the_same_redacted_audit_outcome() -> None:
    result, outcome = run_clipboard_audit(
        lambda: "OPENAI_API_KEY=sk-proj-abcdefghijklmnop",
        disposition_key=DISPOSITION_KEY,
    )
    assert result.scanned is True
    assert result.raw_data_retained is False
    assert outcome is not None
    assert outcome.findings == result.findings
    assert outcome.score.coverage == 1.0
    assert outcome.report_json.find("sk-proj-abcdefghijklmnop") == -1
    assert outcome.report_html.find("sk-proj-abcdefghijklmnop") == -1


@pytest.mark.parametrize("evaluated_at", (0, "", datetime(2026, 8, 24, 12, 0)))
def test_clipboard_service_rejects_invalid_evaluated_at_before_inputs(
    evaluated_at: object,
) -> None:
    consumed = []
    reads = []

    def dispositions():
        consumed.append("dispositions")
        if False:
            yield

    with pytest.raises(ValueError, match="^invalid disposition context$") as error:
        run_clipboard_audit(
            lambda: reads.append("reader") or "safe",
            disposition_key=DISPOSITION_KEY,
            dispositions=dispositions(),
            evaluated_at=evaluated_at,
        )

    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert consumed == []
    assert reads == []


def test_clipboard_service_bounds_disposition_consumption_before_reader() -> None:
    consumed = 0
    reads = []

    def dispositions():
        nonlocal consumed
        for _ in range(MAX_AUDIT_FINDINGS + 2):
            consumed += 1
            yield object()

    with pytest.raises(ValueError, match="^invalid disposition context$"):
        run_clipboard_audit(
            lambda: reads.append("reader") or "safe",
            disposition_key=DISPOSITION_KEY,
            dispositions=dispositions(),
        )

    assert consumed == MAX_AUDIT_FINDINGS + 1
    assert reads == []


def test_clipboard_service_sanitizes_disposition_iteration_failure(
    capsys: pytest.CaptureFixture[str],
) -> None:
    marker = "private-disposition-iteration-marker"
    reads = []

    def dispositions():
        if False:
            yield
        raise RuntimeError(marker)

    with pytest.raises(ValueError, match="^invalid disposition context$") as error:
        run_clipboard_audit(
            lambda: reads.append("reader") or "safe",
            disposition_key=DISPOSITION_KEY,
            dispositions=dispositions(),
        )

    captured = capsys.readouterr()
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert marker not in repr(error.value)
    assert marker not in captured.out
    assert marker not in captured.err
    assert reads == []
