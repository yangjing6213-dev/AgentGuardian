from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys

import pytest

from agentguardian.domain import Evidence, Finding, RiskDomain, Score, Severity
from agentguardian.evidence_state import MAX_STATE_BYTES, build_snapshot
from agentguardian.state_store import (
    STATE_FILENAME,
    StateStoreError,
    default_state_path,
    load_protected_state,
    save_protected_state,
)
from agentguardian.windows_dpapi import DpapiError


def _snapshot(masked: str = "masked-value"):
    finding = Finding(
        "SYNTHETIC_RULE",
        RiskDomain.PRIVACY,
        Severity.LOW,
        "a" * 64,
        (Evidence("private.env", "b" * 64, masked),),
    )
    score = Score(
        total=97,
        deductions=((RiskDomain.PRIVACY, 3),),
        cap_reason=None,
        coverage=1.0,
        confidence=1.0,
        limits=(),
        incomplete=False,
    )
    return build_snapshot(
        (finding,),
        score,
        rule_version="1.1.0",
        captured_at=datetime(2026, 8, 2, tzinfo=timezone.utc),
    )


def _protect(data: bytes) -> bytes:
    return b"AGS1" + bytes(value ^ 0xA5 for value in data)


def _unprotect(data: bytes) -> bytes:
    if not data.startswith(b"AGS1"):
        raise DpapiError("PROTECTED_STATE_INVALID")
    return bytes(value ^ 0xA5 for value in data[4:])


def test_store_round_trip_writes_only_ciphertext(tmp_path: Path) -> None:
    snapshot = _snapshot("private-marker")

    save_protected_state(snapshot, directory=tmp_path, protect=_protect)

    target = tmp_path / STATE_FILENAME
    ciphertext = target.read_bytes()
    assert target.is_file()
    assert b"private-marker" not in ciphertext
    assert b"private.env" not in ciphertext
    assert load_protected_state(directory=tmp_path, unprotect=_unprotect) == snapshot
    assert [path.name for path in tmp_path.iterdir()] == [STATE_FILENAME]


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI integration")
def test_store_round_trip_uses_real_dpapi_on_windows(tmp_path: Path) -> None:
    snapshot = _snapshot("real-dpapi-marker")

    save_protected_state(snapshot, directory=tmp_path)

    assert b"real-dpapi-marker" not in (tmp_path / STATE_FILENAME).read_bytes()
    assert load_protected_state(directory=tmp_path) == snapshot


def test_failed_atomic_replace_preserves_previous_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agentguardian.state_store as state_store

    original = _snapshot("original-marker")
    save_protected_state(original, directory=tmp_path, protect=_protect)
    before = (tmp_path / STATE_FILENAME).read_bytes()

    def fail_replace(source: object, target: object) -> None:
        raise OSError("synthetic path must not escape")

    monkeypatch.setattr(state_store.os, "replace", fail_replace)

    with pytest.raises(StateStoreError) as raised:
        save_protected_state(
            _snapshot("replacement-marker"), directory=tmp_path, protect=_protect
        )

    assert str(raised.value) == "PROTECTED_STATE_SAVE_FAILED"
    assert "synthetic" not in str(raised.value)
    assert (tmp_path / STATE_FILENAME).read_bytes() == before
    assert [path.name for path in tmp_path.iterdir()] == [STATE_FILENAME]


@pytest.mark.parametrize(
    "content",
    (b"corrupt", b"x" * (MAX_STATE_BYTES + 1)),
    ids=("corrupt", "oversized"),
)
def test_load_rejects_corrupt_or_oversized_state(
    tmp_path: Path, content: bytes
) -> None:
    (tmp_path / STATE_FILENAME).write_bytes(content)

    with pytest.raises(StateStoreError, match="^PROTECTED_STATE_INVALID$"):
        load_protected_state(directory=tmp_path, unprotect=_unprotect)


def test_store_rejects_reparse_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agentguardian.state_store as state_store

    monkeypatch.setattr(
        state_store,
        "_is_reparse",
        lambda path: Path(path).name == STATE_FILENAME,
    )

    with pytest.raises(StateStoreError, match="^PROTECTED_STATE_SAVE_FAILED$"):
        save_protected_state(_snapshot(), directory=tmp_path, protect=_protect)

    assert tuple(tmp_path.iterdir()) == ()


def test_default_state_path_uses_local_app_data_only_on_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    assert default_state_path() == tmp_path / "AgentGuardian" / STATE_FILENAME

    monkeypatch.delenv("LOCALAPPDATA")
    with pytest.raises(StateStoreError, match="^PROTECTED_STATE_UNAVAILABLE$"):
        default_state_path()


def test_protection_failure_does_not_create_default_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    def fail_protect(data: bytes) -> bytes:
        raise DpapiError("DPAPI_PROTECT_FAILED")

    with pytest.raises(StateStoreError, match="^PROTECTED_STATE_SAVE_FAILED$"):
        save_protected_state(_snapshot(), protect=fail_protect)

    assert not (tmp_path / "AgentGuardian").exists()


def test_missing_state_fails_without_exposing_path(tmp_path: Path) -> None:
    with pytest.raises(StateStoreError) as raised:
        load_protected_state(directory=tmp_path, unprotect=_unprotect)

    assert str(raised.value) == "PROTECTED_STATE_UNAVAILABLE"
    assert str(tmp_path) not in str(raised.value)
