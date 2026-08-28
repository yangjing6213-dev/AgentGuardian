from collections.abc import Callable
from dataclasses import dataclass

from .detectors import detect_text
from .domain import Finding


MAX_CLIPBOARD_CHARS = 1_000_000


@dataclass(frozen=True, slots=True)
class ClipboardAuditResult:
    findings: tuple[Finding, ...]
    scanned: bool
    limits: tuple[str, ...]
    raw_data_retained: bool


def audit_clipboard_once(
    reader: Callable[[], str],
    *,
    scan_key: bytes,
    disposition_key: bytes | None = None,
) -> ClipboardAuditResult:
    """Read a clipboard value once, scan it in memory, and return masked evidence."""
    if not callable(reader):
        raise ValueError("CLIPBOARD_READER_INVALID")
    try:
        text = reader()
    except Exception:  # noqa: BLE001 - clipboard boundaries fail closed
        return ClipboardAuditResult((), False, ("clipboard_read_error",), False)
    if type(text) is not str:
        return ClipboardAuditResult((), False, ("clipboard_read_error",), False)
    if len(text) > MAX_CLIPBOARD_CHARS:
        return ClipboardAuditResult((), False, ("clipboard_size_limit",), False)
    try:
        findings = detect_text(
            text,
            "clipboard",
            scan_key=scan_key,
            disposition_key=disposition_key,
        )
    except Exception:  # noqa: BLE001 - clipboard boundaries fail closed
        return ClipboardAuditResult((), False, ("clipboard_scan_error",), False)
    return ClipboardAuditResult(findings, True, (), False)
