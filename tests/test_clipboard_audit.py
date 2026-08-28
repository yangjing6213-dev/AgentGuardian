from agentguardian.clipboard_audit import (
    MAX_CLIPBOARD_CHARS,
    audit_clipboard_once,
)


def test_clipboard_is_read_once_and_returns_only_masked_findings():
    raw_secret = "sk-proj-synthetic-clipboard-secret-123456"
    calls = []

    def reader():
        calls.append(1)
        return raw_secret

    result = audit_clipboard_once(reader, scan_key=b"c" * 32)

    assert calls == [1]
    assert result.scanned is True
    assert result.raw_data_retained is False
    assert raw_secret not in repr(result)
    assert result.findings
    assert raw_secret not in result.findings[0].evidence[0].masked


def test_clipboard_reader_failure_fails_closed_without_exception_text():
    def reader():
        raise RuntimeError("synthetic private clipboard failure")

    result = audit_clipboard_once(reader, scan_key=b"c" * 32)

    assert result.scanned is False
    assert result.findings == ()
    assert result.limits == ("clipboard_read_error",)
    assert "synthetic private" not in repr(result)


def test_clipboard_size_limit_does_not_scan_or_retain_text():
    raw_text = "x" * (MAX_CLIPBOARD_CHARS + 1)
    result = audit_clipboard_once(lambda: raw_text, scan_key=b"c" * 32)

    assert result.scanned is False
    assert result.findings == ()
    assert result.limits == ("clipboard_size_limit",)
    assert result.raw_data_retained is False
