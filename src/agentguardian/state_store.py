from __future__ import annotations

from collections.abc import Callable
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import stat

from .evidence_state import (
    MAX_STATE_BYTES,
    EvidenceSnapshot,
    EvidenceStateError,
    decode_snapshot,
    encode_snapshot,
)
from .windows_dpapi import DpapiError, protect_bytes, unprotect_bytes


STATE_FILENAME = "evidence-state-v1.bin"
_APP_DIRECTORY = "AgentGuardian"
_ENVELOPE_MAGIC = b"AGSE\x01"
_DIGEST_BYTES = hashlib.sha256().digest_size
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)


class StateStoreError(RuntimeError):
    pass


def default_state_path() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data or _is_unc_path(local_app_data):
        raise StateStoreError("PROTECTED_STATE_UNAVAILABLE")
    root = Path(local_app_data)
    if not root.is_absolute():
        raise StateStoreError("PROTECTED_STATE_UNAVAILABLE")
    return root / _APP_DIRECTORY / STATE_FILENAME


def save_protected_state(
    snapshot: EvidenceSnapshot,
    *,
    directory: str | Path | None = None,
    protect: Callable[[bytes], bytes] = protect_bytes,
) -> None:
    try:
        plaintext = encode_snapshot(snapshot)
        ciphertext = protect(_seal_payload(plaintext))
        if (
            type(ciphertext) is not bytes
            or not ciphertext
            or len(ciphertext) > MAX_STATE_BYTES
        ):
            raise StateStoreError("PROTECTED_STATE_SAVE_FAILED")
    except DpapiError as error:
        if str(error) == "DPAPI_UNAVAILABLE":
            raise StateStoreError("PROTECTED_STATE_UNAVAILABLE") from None
        raise StateStoreError("PROTECTED_STATE_SAVE_FAILED") from None
    except EvidenceStateError:
        raise StateStoreError("PROTECTED_STATE_SAVE_FAILED") from None
    except StateStoreError:
        raise
    except Exception:  # noqa: BLE001 - callbacks must not leak details.
        raise StateStoreError("PROTECTED_STATE_SAVE_FAILED") from None

    temporary: Path | None = None
    try:
        target = _target_path(directory, create=True)
        source_parent = target.parent
        parent = source_parent.resolve(strict=True)
        if (
            _is_unc_path(parent)
            or _has_reparse_ancestor(source_parent)
            or _is_reparse(target)
            or target.resolve(strict=False).parent != parent
        ):
            raise StateStoreError("PROTECTED_STATE_SAVE_FAILED")

        temporary = parent / f".{STATE_FILENAME}.{secrets.token_hex(16)}.tmp"
        if temporary.resolve(strict=False).parent != parent:
            raise StateStoreError("PROTECTED_STATE_SAVE_FAILED")
        with open(temporary, "xb") as stream:
            stream.write(ciphertext)
            stream.flush()
            os.fsync(stream.fileno())

        if (
            _is_unc_path(parent)
            or _has_reparse_ancestor(source_parent)
            or parent.resolve(strict=True) != source_parent.resolve(strict=True)
            or _is_reparse(target)
            or target.resolve(strict=False).parent != parent
        ):
            raise StateStoreError("PROTECTED_STATE_SAVE_FAILED")
        os.replace(temporary, target)
        temporary = None
    except StateStoreError:
        raise
    except Exception:  # noqa: BLE001 - paths and OS errors must not escape.
        raise StateStoreError("PROTECTED_STATE_SAVE_FAILED") from None
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def load_protected_state(
    *,
    directory: str | Path | None = None,
    unprotect: Callable[[bytes], bytes] = unprotect_bytes,
) -> EvidenceSnapshot:
    try:
        target = _target_path(directory, create=False)
    except StateStoreError as error:
        if str(error) == "PROTECTED_STATE_UNAVAILABLE":
            raise
        raise StateStoreError("PROTECTED_STATE_INVALID") from None

    try:
        source_parent = target.parent
        parent = source_parent.resolve(strict=True)
        if (
            _is_unc_path(parent)
            or _has_reparse_ancestor(source_parent)
            or _is_reparse(target)
            or target.resolve(strict=True).parent != parent
        ):
            raise StateStoreError("PROTECTED_STATE_INVALID")
        with open(target, "rb") as stream:
            ciphertext = stream.read(MAX_STATE_BYTES + 1)
        if not ciphertext or len(ciphertext) > MAX_STATE_BYTES:
            raise StateStoreError("PROTECTED_STATE_INVALID")
        plaintext = unprotect(ciphertext)
        if type(plaintext) is not bytes:
            raise StateStoreError("PROTECTED_STATE_INVALID")
        return decode_snapshot(_open_payload(plaintext))
    except FileNotFoundError:
        raise StateStoreError("PROTECTED_STATE_UNAVAILABLE") from None
    except DpapiError as error:
        if str(error) == "DPAPI_UNAVAILABLE":
            raise StateStoreError("PROTECTED_STATE_UNAVAILABLE") from None
        raise StateStoreError("PROTECTED_STATE_INVALID") from None
    except (EvidenceStateError, StateStoreError):
        raise
    except Exception:  # noqa: BLE001 - paths and OS errors must not escape.
        raise StateStoreError("PROTECTED_STATE_INVALID") from None


def _target_path(directory: str | Path | None, *, create: bool) -> Path:
    if directory is None:
        target = default_state_path()
        parent = target.parent
    else:
        parent = Path(directory)
        target = parent / STATE_FILENAME
    if (
        not parent.is_absolute()
        or _is_unc_path(parent)
        or _has_reparse_ancestor(parent)
    ):
        raise StateStoreError("PROTECTED_STATE_SAVE_FAILED")
    if create and not parent.exists():
        ancestor = parent.parent
        if not ancestor.is_dir() or _has_reparse_ancestor(ancestor):
            raise StateStoreError("PROTECTED_STATE_SAVE_FAILED")
        parent.mkdir(mode=0o700, exist_ok=True)
    if not parent.is_dir() or _has_reparse_ancestor(parent):
        code = "PROTECTED_STATE_SAVE_FAILED" if create else "PROTECTED_STATE_UNAVAILABLE"
        raise StateStoreError(code)
    if target.name != STATE_FILENAME:
        raise StateStoreError("PROTECTED_STATE_SAVE_FAILED")
    return target


def _is_unc_path(path: str | Path) -> bool:
    value = os.fspath(path)
    return value.startswith(("\\\\", "//"))


def _seal_payload(plaintext: bytes) -> bytes:
    if len(plaintext) + len(_ENVELOPE_MAGIC) + _DIGEST_BYTES > MAX_STATE_BYTES:
        raise StateStoreError("PROTECTED_STATE_SAVE_FAILED")
    return _ENVELOPE_MAGIC + hashlib.sha256(plaintext).digest() + plaintext


def _open_payload(envelope: bytes) -> bytes:
    header_size = len(_ENVELOPE_MAGIC) + _DIGEST_BYTES
    if len(envelope) <= header_size or not envelope.startswith(_ENVELOPE_MAGIC):
        raise StateStoreError("PROTECTED_STATE_INVALID")
    expected = envelope[len(_ENVELOPE_MAGIC) : header_size]
    plaintext = envelope[header_size:]
    if not hmac.compare_digest(expected, hashlib.sha256(plaintext).digest()):
        raise StateStoreError("PROTECTED_STATE_INVALID")
    return plaintext


def _is_reparse(path: str | Path) -> bool:
    try:
        path_stat = os.lstat(path)
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(path_stat.st_mode) or bool(
        getattr(path_stat, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _has_reparse_ancestor(path: str | Path) -> bool:
    current = Path(path)
    while True:
        if _is_reparse(current):
            return True
        parent = current.parent
        if parent == current:
            return False
        current = parent
