from __future__ import annotations

import sys
from pathlib import Path

import pytest

import agentguardian.windows_code_signing as signing
from agentguardian.windows_code_signing import verify_authenticode, verify_authenticode_publisher


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Authenticode verification is only available on Windows",
)


def test_authenticode_accepts_a_trusted_system_binary() -> None:
    assert verify_authenticode(Path(sys.executable)) is True


def test_publisher_verification_accepts_the_exact_subject_of_a_trusted_binary() -> None:
    executable = Path(sys.executable)
    subject = signing._authenticode_subject(executable)
    assert subject is not None
    assert verify_authenticode_publisher(executable, (subject,)) is True
    assert verify_authenticode_publisher(executable, (f"{subject}x",)) is False


def test_authenticode_rejects_an_unsigned_file(tmp_path: Path) -> None:
    executable = tmp_path / "unsigned.exe"
    executable.write_bytes(b"MZ synthetic unsigned executable")
    assert verify_authenticode(executable) is False


def test_publisher_verification_requires_an_exact_allowlist_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "adapter.exe"
    executable.write_bytes(b"MZ synthetic")
    monkeypatch.setattr(signing, "verify_authenticode", lambda _path: True)
    monkeypatch.setattr(signing, "_authenticode_subject", lambda _path: "CN=Allowed")

    assert verify_authenticode_publisher(executable, ("CN=Allowed",)) is True
    assert verify_authenticode_publisher(executable, ("CN=Other",)) is False
    assert verify_authenticode_publisher(executable, ()) is False
