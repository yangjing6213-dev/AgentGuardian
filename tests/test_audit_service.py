from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

from agentguardian.audit_service import run_clipboard_audit


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
