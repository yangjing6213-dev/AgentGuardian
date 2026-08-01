from __future__ import annotations

import ctypes
from ctypes import wintypes
import sys
from types import SimpleNamespace

import pytest

from agentguardian.evidence_state import MAX_STATE_BYTES
from agentguardian.windows_dpapi import DpapiError, protect_bytes, unprotect_bytes


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI integration")
def test_dpapi_round_trip_keeps_plaintext_out_of_ciphertext() -> None:
    plaintext = b'{"synthetic":"protected-state-marker"}'

    ciphertext = protect_bytes(plaintext)

    assert ciphertext != plaintext
    assert plaintext not in ciphertext
    assert b"protected-state-marker" not in ciphertext
    assert unprotect_bytes(ciphertext) == plaintext


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI integration")
def test_dpapi_tamper_fails_closed_without_echoing_data() -> None:
    marker = b"synthetic-private-marker"
    ciphertext = bytearray(protect_bytes(marker))
    ciphertext[len(ciphertext) // 2] ^= 1

    with pytest.raises(DpapiError) as raised:
        unprotect_bytes(bytes(ciphertext))

    assert str(raised.value) == "PROTECTED_STATE_INVALID"
    assert marker.decode() not in str(raised.value)


def test_dpapi_is_unavailable_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    import agentguardian.windows_dpapi as windows_dpapi

    monkeypatch.setattr(windows_dpapi.sys, "platform", "linux")

    with pytest.raises(DpapiError, match="^DPAPI_UNAVAILABLE$"):
        protect_bytes(b"synthetic")
    with pytest.raises(DpapiError, match="^DPAPI_UNAVAILABLE$"):
        unprotect_bytes(b"synthetic")


@pytest.mark.parametrize(
    "data",
    (b"", b"x" * (MAX_STATE_BYTES + 1), bytearray(b"x")),
    ids=("empty", "oversized", "not-bytes"),
)
def test_dpapi_rejects_invalid_protect_input(data: object) -> None:
    with pytest.raises(DpapiError, match="^DPAPI_PROTECT_FAILED$"):
        protect_bytes(data)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "data",
    (b"", b"x" * (MAX_STATE_BYTES + 1), bytearray(b"x")),
    ids=("empty", "oversized", "not-bytes"),
)
def test_dpapi_rejects_invalid_unprotect_input(data: object) -> None:
    with pytest.raises(DpapiError, match="^PROTECTED_STATE_INVALID$"):
        unprotect_bytes(data)  # type: ignore[arg-type]


def test_unprotect_uses_exact_description_pointer_signature(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import agentguardian.windows_dpapi as windows_dpapi

    class FakeFunction:
        argtypes = ()
        restype = None

        def __call__(self, *args: object) -> bool:
            return False

    function = FakeFunction()
    crypt32 = SimpleNamespace(CryptUnprotectData=function)
    kernel32 = SimpleNamespace(LocalFree=lambda pointer: None)
    monkeypatch.setattr(windows_dpapi, "_libraries", lambda: (crypt32, kernel32))
    monkeypatch.setattr(windows_dpapi.sys, "platform", "win32")

    with pytest.raises(DpapiError, match="^PROTECTED_STATE_INVALID$"):
        unprotect_bytes(b"synthetic")

    assert function.argtypes[1] == ctypes.POINTER(wintypes.LPWSTR)


def test_native_output_is_freed_when_call_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import agentguardian.windows_dpapi as windows_dpapi

    output_buffer = (ctypes.c_ubyte * 1)(42)
    freed = []

    class RaisingFunction:
        argtypes = ()
        restype = None

        def __call__(self, *args: object) -> bool:
            output = args[-1]._obj  # type: ignore[attr-defined]
            output.cbData = 1
            output.pbData = ctypes.cast(
                output_buffer, ctypes.POINTER(ctypes.c_ubyte)
            )
            raise OSError("synthetic native detail")

    crypt32 = SimpleNamespace(CryptProtectData=RaisingFunction())
    kernel32 = SimpleNamespace(LocalFree=lambda pointer: freed.append(pointer))
    monkeypatch.setattr(windows_dpapi, "_libraries", lambda: (crypt32, kernel32))
    monkeypatch.setattr(windows_dpapi.sys, "platform", "win32")

    with pytest.raises(DpapiError) as raised:
        protect_bytes(b"synthetic")

    assert str(raised.value) == "DPAPI_PROTECT_FAILED"
    assert "synthetic native detail" not in str(raised.value)
    assert len(freed) == 1
