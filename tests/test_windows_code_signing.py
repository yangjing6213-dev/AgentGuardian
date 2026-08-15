from __future__ import annotations

import sys
from pathlib import Path

import pytest

from agentguardian.windows_code_signing import verify_authenticode


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Authenticode verification is only available on Windows",
)


def test_authenticode_accepts_a_trusted_system_binary() -> None:
    assert verify_authenticode(Path(sys.executable)) is True


def test_authenticode_rejects_an_unsigned_file(tmp_path: Path) -> None:
    executable = tmp_path / "unsigned.exe"
    executable.write_bytes(b"MZ synthetic unsigned executable")
    assert verify_authenticode(executable) is False
