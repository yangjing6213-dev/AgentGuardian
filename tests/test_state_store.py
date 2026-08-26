from __future__ import annotations

import ctypes
from datetime import datetime, timezone
import os
from pathlib import Path
import subprocess
import sys

import pytest

from agentguardian.dispositions import DispositionRecord, DispositionStatus
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


DISPOSITION_KEY = b"s" * 32
DISPOSITION_REF = "d" * 64


def _snapshot(masked: str = "masked-value"):
    finding = Finding(
        "EMAIL_ADDRESS",
        RiskDomain.PRIVACY,
        Severity.LOW,
        "a" * 64,
        (Evidence("private.env", "b" * 64, masked),),
        DISPOSITION_REF,
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
        disposition_key=DISPOSITION_KEY,
        dispositions=(
            DispositionRecord(
                disposition_ref=DISPOSITION_REF,
                rule_id="EMAIL_ADDRESS",
                status=DispositionStatus.ACCEPTED_RISK,
                reason="Synthetic state reason",
                reviewer="Local state reviewer",
                created_at="2026-08-02T00:00:00Z",
                expires_at="2026-08-31T00:00:00Z",
            ),
        ),
    )


def _protect(data: bytes) -> bytes:
    return b"AGS1" + bytes(value ^ 0xA5 for value in data)


def _unprotect(data: bytes) -> bytes:
    if not data.startswith(b"AGS1"):
        raise DpapiError("PROTECTED_STATE_INVALID")
    return bytes(value ^ 0xA5 for value in data[4:])


def _patch_purge_windows_api(
    monkeypatch: pytest.MonkeyPatch,
    state_store: object,
    parent: Path,
    target: Path,
    failure: str | None,
) -> list[int]:
    monkeypatch.setattr(state_store.os, "name", "nt")
    closed: list[int] = []

    class FakeCreateFile:
        argtypes = None
        restype = None
        calls = 0

        def __call__(self, *_args: object) -> int:
            self.calls += 1
            if failure == "parent" or self.calls == 1:
                return 10
            return 20

    class FakeCloseHandle:
        argtypes = None
        restype = None

        def __call__(self, handle: int) -> int:
            closed.append(handle)
            return 0

    class FakeGetInformation:
        argtypes = None
        restype = None

        def __call__(self, handle: int, pointer: object) -> int:
            information = pointer._obj
            if handle == 10:
                information.dwFileAttributes = 0 if failure == "parent" else 0x10
            else:
                information.dwFileAttributes = 0x10 if failure == "target" else 0
            return 1

    class FakeGetFinalPath:
        argtypes = None
        restype = None

        def __call__(self, handle: int, buffer: object, *_args: object) -> int:
            value = os.fspath(parent if handle == 10 else target)
            buffer.value = value
            return len(value)

    class FakeSetInformation:
        argtypes = None
        restype = None

        def __call__(self, *_args: object) -> int:
            return 1

    class Kernel32:
        CreateFileW = FakeCreateFile()
        CloseHandle = FakeCloseHandle()
        GetFileInformationByHandle = FakeGetInformation()
        GetFinalPathNameByHandleW = FakeGetFinalPath()
        SetFileInformationByHandle = FakeSetInformation()

    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: Kernel32())
    return closed


def test_store_round_trip_writes_only_ciphertext(tmp_path: Path) -> None:
    snapshot = _snapshot("private-marker")

    save_protected_state(snapshot, directory=tmp_path, protect=_protect)

    target = tmp_path / STATE_FILENAME
    ciphertext = target.read_bytes()
    assert target.is_file()
    for private in (
        b"private-marker",
        b"private.env",
        DISPOSITION_KEY,
        DISPOSITION_KEY.hex().encode(),
        DISPOSITION_REF.encode(),
        b"Synthetic state reason",
        b"Local state reviewer",
    ):
        assert private not in ciphertext
    assert load_protected_state(directory=tmp_path, unprotect=_unprotect) == snapshot
    assert [path.name for path in tmp_path.iterdir()] == [STATE_FILENAME]


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI integration")
def test_store_round_trip_uses_real_dpapi_on_windows(tmp_path: Path) -> None:
    snapshot = _snapshot("real-dpapi-marker")

    save_protected_state(snapshot, directory=tmp_path)

    ciphertext = (tmp_path / STATE_FILENAME).read_bytes()
    for private in (
        b"real-dpapi-marker",
        b"private.env",
        DISPOSITION_KEY,
        DISPOSITION_KEY.hex().encode(),
        DISPOSITION_REF.encode(),
        b"Synthetic state reason",
        b"Local state reviewer",
    ):
        assert private not in ciphertext
    assert load_protected_state(directory=tmp_path) == snapshot


def test_loads_legacy_schema_without_rewriting_file(tmp_path: Path) -> None:
    import agentguardian.state_store as state_store

    legacy = (
        b'{"schema_version":1,"captured_at":"2026-08-02T00:00:00Z",'
        b'"product_version":"0.1.0","rule_version":"1.1.0",'
        b'"scan":{"coverage":1.0,"confidence":1.0,"incomplete":false,'
        b'"limits":[]},"findings":[]}'
    )
    target = tmp_path / STATE_FILENAME
    target.write_bytes(_protect(state_store._seal_payload(legacy)))
    before = target.read_bytes()

    snapshot = load_protected_state(directory=tmp_path, unprotect=_unprotect)

    assert snapshot.schema_version == 1
    assert snapshot.disposition_key is None
    assert snapshot.dispositions == ()
    assert target.read_bytes() == before


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


def test_load_rejects_valid_json_changed_after_unprotect(tmp_path: Path) -> None:
    save_protected_state(_snapshot(), directory=tmp_path, protect=_protect)
    target = tmp_path / STATE_FILENAME
    ciphertext = bytearray(target.read_bytes())
    encoded_hmac = bytes(ord("a") ^ 0xA5 for _ in range(64))
    index = ciphertext.find(encoded_hmac)
    assert index >= 0
    ciphertext[index] = ord("c") ^ 0xA5
    target.write_bytes(ciphertext)

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


def test_store_rejects_real_reparse_ancestor(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-parent"
    real_child = real_parent / "ordinary-child"
    real_child.mkdir(parents=True)
    linked_parent = tmp_path / "linked-parent"
    try:
        linked_parent.symlink_to(real_parent, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation unavailable")
    linked_child = linked_parent / "ordinary-child"
    snapshot = _snapshot()

    with pytest.raises(StateStoreError, match="^PROTECTED_STATE_SAVE_FAILED$"):
        save_protected_state(snapshot, directory=linked_child, protect=_protect)
    assert not (real_child / STATE_FILENAME).exists()

    save_protected_state(snapshot, directory=real_child, protect=_protect)
    with pytest.raises(StateStoreError, match="^PROTECTED_STATE_INVALID$"):
        load_protected_state(directory=linked_child, unprotect=_unprotect)


def test_store_checks_every_existing_ancestor_for_reparse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agentguardian.state_store as state_store

    reparse_ancestor = tmp_path / "reparse-ancestor"
    child = reparse_ancestor / "ordinary-child"
    child.mkdir(parents=True)
    monkeypatch.setattr(
        state_store,
        "_is_reparse",
        lambda path: Path(path) == reparse_ancestor,
    )

    with pytest.raises(StateStoreError, match="^PROTECTED_STATE_SAVE_FAILED$"):
        save_protected_state(_snapshot(), directory=child, protect=_protect)

    assert not (child / STATE_FILENAME).exists()


def test_default_state_path_uses_local_app_data_only_on_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    assert default_state_path() == tmp_path / "AgentGuardian" / STATE_FILENAME

    monkeypatch.delenv("LOCALAPPDATA")
    with pytest.raises(StateStoreError, match="^PROTECTED_STATE_UNAVAILABLE$"):
        default_state_path()


def test_purge_protected_state_removes_only_known_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agentguardian.state_store as state_store

    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    directory = tmp_path / "AgentGuardian"
    directory.mkdir()
    state = directory / STATE_FILENAME
    state.write_bytes(b"protected")
    unrelated = directory / "keep.txt"
    unrelated.write_text("keep", encoding="ascii")

    assert state_store.purge_protected_state() is True
    assert not state.exists()
    assert unrelated.read_text(encoding="ascii") == "keep"
    assert directory.is_dir()


def test_purge_protected_state_is_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agentguardian.state_store as state_store

    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    assert state_store.purge_protected_state() is False
    assert state_store.purge_protected_state() is False
    assert not (tmp_path / "AgentGuardian").exists()


@pytest.mark.parametrize("failure", ("target", "parent"))
def test_windows_purge_close_failure_preserves_primary_state_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    import agentguardian.state_store as state_store

    parent = tmp_path / "AgentGuardian"
    parent.mkdir()
    target = parent / STATE_FILENAME
    target.write_bytes(b"protected")
    closed = _patch_purge_windows_api(
        monkeypatch, state_store, parent, target, failure
    )

    with pytest.raises(StateStoreError, match="^PROTECTED_STATE_PURGE_FAILED$"):
        state_store._purge_windows_target(target, parent)

    assert closed == [20, 10] if failure == "target" else [10]


def test_windows_purge_close_failure_without_primary_error_is_fixed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agentguardian.state_store as state_store

    parent = tmp_path / "AgentGuardian"
    parent.mkdir()
    target = parent / STATE_FILENAME
    target.write_bytes(b"protected")
    closed = _patch_purge_windows_api(
        monkeypatch, state_store, parent, target, failure=None
    )

    with pytest.raises(StateStoreError, match="^PROTECTED_STATE_PURGE_FAILED$"):
        state_store._purge_windows_target(target, parent)

    assert closed == [20, 10]


@pytest.mark.parametrize(
    "local_app_data",
    (None, "relative-local-app-data", r"\\server\share"),
    ids=("missing", "relative", "unc"),
)
def test_purge_protected_state_maps_unsafe_default_path_to_fixed_failure(
    local_app_data: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agentguardian.state_store as state_store

    if local_app_data is None:
        monkeypatch.delenv("LOCALAPPDATA", raising=False)
    else:
        monkeypatch.setenv("LOCALAPPDATA", local_app_data)

    with pytest.raises(StateStoreError, match="^PROTECTED_STATE_PURGE_FAILED$"):
        state_store.purge_protected_state()


def _junction_or_skip(link: Path, target: Path) -> None:
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)],
        capture_output=True,
        check=False,
    )
    if result.returncode:
        output = (result.stdout + b"\n" + result.stderr).decode(
            "utf-8", errors="replace"
        ).casefold()
        if any(
            marker in output
            for marker in ("access is denied", "not supported", "privilege")
        ):
            pytest.skip(f"junction creation is unavailable: {output.strip()}")
        pytest.fail(f"junction creation failed unexpectedly: {output.strip()}")


@pytest.mark.skipif(sys.platform != "win32", reason="Windows junction test")
@pytest.mark.parametrize("junction_at_app_directory", (False, True))
def test_purge_protected_state_rejects_junction_without_touching_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    junction_at_app_directory: bool,
) -> None:
    import agentguardian.state_store as state_store

    outside = tmp_path / "outside"
    outside_app = outside / "AgentGuardian"
    outside_app.mkdir(parents=True)
    protected = outside_app / STATE_FILENAME
    protected.write_bytes(b"protected")

    if junction_at_app_directory:
        local_app_data = tmp_path / "local-app-data"
        local_app_data.mkdir()
        _junction_or_skip(local_app_data / "AgentGuardian", outside_app)
    else:
        local_app_data = tmp_path / "linked-local-app-data"
        _junction_or_skip(local_app_data, outside)
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))

    with pytest.raises(StateStoreError, match="^PROTECTED_STATE_PURGE_FAILED$"):
        state_store.purge_protected_state()

    assert protected.read_bytes() == b"protected"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows junction test")
def test_purge_protected_state_rejects_parent_swap_before_delete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agentguardian.state_store as state_store

    local_app_data = tmp_path / "local-app-data"
    app_directory = local_app_data / "AgentGuardian"
    app_directory.mkdir(parents=True)
    (app_directory / STATE_FILENAME).write_bytes(b"expected-state")
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_state = outside / STATE_FILENAME
    outside_state.write_bytes(b"outside-state")
    held_directory = local_app_data / "AgentGuardian-held"
    original_is_reparse = state_store._is_reparse
    swapped = False

    def swap_parent_before_target_check(path: str | Path) -> bool:
        nonlocal swapped
        if Path(path) == app_directory / STATE_FILENAME and not swapped:
            app_directory.rename(held_directory)
            _junction_or_skip(app_directory, outside)
            swapped = True
        return original_is_reparse(path)

    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))
    monkeypatch.setattr(
        state_store, "_is_reparse", swap_parent_before_target_check
    )

    with pytest.raises(StateStoreError, match="^PROTECTED_STATE_PURGE_FAILED$"):
        state_store.purge_protected_state()

    assert (held_directory / STATE_FILENAME).read_bytes() == b"expected-state"
    assert outside_state.read_bytes() == b"outside-state"


def test_store_rejects_relative_directory_without_writing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    with pytest.raises(StateStoreError, match="^PROTECTED_STATE_SAVE_FAILED$"):
        save_protected_state(
            _snapshot(), directory=Path("relative-state"), protect=_protect
        )

    assert not (tmp_path / "relative-state").exists()


def test_default_state_path_rejects_relative_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LOCALAPPDATA", "relative-local-app-data")

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
