from __future__ import annotations

import sys
from pathlib import Path

import pytest

from agentguardian.windows_job_object import run_in_job_object


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Windows Job Object is only available on Windows",
)


def _run(
    script: str,
    tmp_path: Path,
    *,
    timeout_seconds: float = 5.0,
    max_output_bytes: int = 64 * 1024,
):
    return run_in_job_object(
        sys.executable,
        ("-c", script),
        b"synthetic-request",
        workdir=tmp_path,
        environment={"PYTHONNOUSERSITE": "1"},
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
    )


def test_job_object_runs_a_fixed_process_and_cleans_transient_files(
    tmp_path: Path,
) -> None:
    result = _run(
        "import sys; sys.stdout.buffer.write(b'ok')",
        tmp_path,
    )

    assert result.returncode == 0
    assert result.output == b"ok"
    assert result.timed_out is False
    assert result.output_limited is False
    assert result.process_tree_isolated is True
    assert tuple(tmp_path.iterdir()) == ()


def test_job_object_active_process_limit_rejects_child_processes(
    tmp_path: Path,
) -> None:
    script = (
        "import subprocess,sys\n"
        "try:\n"
        "    subprocess.Popen([sys.executable, '-c', 'pass'])\n"
        "except OSError:\n"
        "    print('child_denied')\n"
        "else:\n"
        "    print('child_started')\n"
    )

    result = _run(script, tmp_path)

    assert result.returncode == 0
    assert result.output == b"child_denied\r\n"
    assert result.process_tree_isolated is True


def test_job_object_timeout_terminates_the_process_tree(tmp_path: Path) -> None:
    result = _run(
        "import time; time.sleep(30)",
        tmp_path,
        timeout_seconds=0.2,
    )

    assert result.timed_out is True
    assert result.process_tree_isolated is True
    assert tuple(tmp_path.iterdir()) == ()


def test_job_object_terminates_on_output_limit(tmp_path: Path) -> None:
    result = _run(
        "import sys,time; sys.stdout.write('x' * 4096); sys.stdout.flush(); time.sleep(30)",
        tmp_path,
        timeout_seconds=5.0,
        max_output_bytes=1024,
    )

    assert result.output_limited is True
    assert result.timed_out is False
    assert result.process_tree_isolated is True
    assert len(result.output) <= 1024
