from __future__ import annotations

import builtins
import json
import os
import socket
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from agentguardian.audit_service import (
    AuditOutcome,
    run_clipboard_audit,
    run_file_audit,
)
from agentguardian.browser_audit import (
    BrowserAuditResult,
    BrowserKind,
    audit_browser_database,
)
from agentguardian.domain import Evidence, Finding, RiskDomain, Severity
from agentguardian.mcp_service import (
    AUTHORIZATION_TTL_SECONDS,
    CLASSIFICATION,
    MAX_PREPARE_BYTES,
    MAX_RESULT_EVIDENCE,
    MAX_RESULT_FINDINGS,
    MAX_ROOTS,
    MAX_RUN_BYTES,
    OPERATIONS,
    AuditMcpService,
    _PendingAuthorization,
    _PreparedRequest,
)
from agentguardian.scoring import score
from agentguardian.share_verification import ShareVerificationResult, verify_public_share
from agentguardian.workflow import build_scope_preview, classify_coverage


PROJECT_ROOT = Path(__file__).parents[1]
FIXED_NOW = datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc)
SUPPORTED_SUFFIXES = (
    ".env",
    ".json",
    ".log",
    ".md",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
)
AUDIT_CAPS = {
    "max_files": 10_000,
    "max_entries": 50_000,
    "max_bytes": 512 * 1024 * 1024,
    "max_findings": 2_000,
    "max_evidence": 4_000,
}


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _service(**kwargs: object) -> AuditMcpService:
    return AuditMcpService(utc_now=lambda: FIXED_NOW, **kwargs)


def _prepare_files(service: AuditMcpService, root: Path) -> dict[str, object]:
    return service.prepare_audit(
        operation="files",
        classification=CLASSIFICATION,
        roots=[str(root)],
    )


def _run(
    service: AuditMcpService,
    prepared: dict[str, object],
) -> dict[str, object]:
    return service.run_prepared_audit(
        authorization_id=prepared["authorization_id"],
        scope_digest=prepared["scope_digest"],
        consent_summary=prepared["consent_summary"],
    )


def _score_data(value) -> dict[str, object]:
    return {
        "total": value.total,
        "deductions": [
            {"domain": domain.value, "amount": amount}
            for domain, amount in value.deductions
        ],
        "cap_reason": value.cap_reason,
        "coverage": value.coverage,
        "confidence": value.confidence,
        "incomplete": value.incomplete,
        "limits": list(value.limits),
        "coverage_state": classify_coverage(value).value,
    }


def _finding(index: int, *, evidence_count: int = 1, masked: str = "masked") -> Finding:
    return Finding(
        "OPENAI_API_KEY",
        RiskDomain.CREDENTIALS,
        Severity.HIGH,
        f"{index + 1:064x}",
        tuple(
            Evidence(
                "synthetic.env",
                f"{(index * evidence_count) + offset + 1:064x}",
                masked,
            )
            for offset in range(evidence_count)
        ),
    )


def _outcome(
    findings: tuple[Finding, ...] = (),
    *,
    roots: tuple[Path, ...] = (),
    report_marker: str = "presentation-only-marker",
) -> AuditOutcome:
    technical = score(findings, coverage=1.0, confidence=1.0, limits=())
    return AuditOutcome(
        findings=findings,
        score=technical,
        reviewed_score=technical,
        evaluated_at=FIXED_NOW,
        rule_version="rules-test",
        report_json=report_marker,
        report_html=report_marker,
        scanned_roots=roots,
    )


def _create_browser_database(path: Path) -> str:
    raw_url = "https://synthetic.example/private?token=must-not-leak"
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE urls (id INTEGER, url TEXT);
            CREATE TABLE visits (id INTEGER, url INTEGER);
            """
        )
        connection.execute("INSERT INTO urls VALUES (1, ?)", (raw_url,))
        connection.execute("INSERT INTO visits VALUES (1, 1)")
        connection.commit()
    return raw_url


class _Headers(dict[str, str]):
    def get_content_type(self) -> str:
        return "text/plain"


class _Response:
    def __init__(self) -> None:
        self.headers = _Headers(
            {"Content-Type": "text/plain", "Content-Length": "9"}
        )

    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def getcode(self) -> int:
        return 200

    def read(self, _limit: int) -> bytes:
        return b"reachable"


class _Opener:
    def open(self, *_args: object, **_kwargs: object) -> _Response:
        return _Response()


def test_fixed_service_contract_and_sensitive_dataclass_repr(tmp_path: Path) -> None:
    assert CLASSIFICATION == "personal_non_regulated"
    assert OPERATIONS == frozenset({"files", "browser", "clipboard", "public_share"})
    assert AUTHORIZATION_TTL_SECONDS == 300.0
    assert MAX_PREPARE_BYTES == 16 * 1024
    assert MAX_RUN_BYTES == 64 * 1024
    assert MAX_ROOTS == 32
    assert MAX_RESULT_FINDINGS == 100
    assert MAX_RESULT_EVIDENCE == 200

    preview = build_scope_preview((tmp_path,), SUPPORTED_SUFFIXES, **AUDIT_CAPS)
    request = _PreparedRequest(
        "files",
        CLASSIFICATION,
        (tmp_path,),
        preview,
        None,
        None,
        None,
        "1 selected file root",
        False,
    )
    pending = _PendingAuthorization(
        "private-authorization",
        "d" * 64,
        "fixed consent",
        310.0,
        "2026-08-24T12:05:00Z",
        request,
    )
    rendered = repr(pending)

    assert "private-authorization" not in rendered
    assert str(tmp_path) not in repr(request)
    assert "request=" not in rendered
    with pytest.raises(AttributeError):
        pending.scope_digest = "changed"  # type: ignore[misc]


def test_prepare_does_not_read_and_replaces_the_previous_authorization(
    tmp_path: Path,
) -> None:
    reads: list[str] = []
    service = _service(
        monotonic=lambda: 10.0,
        token_factory=iter(("first", "second")).__next__,
        file_runner=lambda *_args, **_kwargs: reads.append("files"),
    )

    first = _prepare_files(service, tmp_path / "first")
    second = _prepare_files(service, tmp_path / "second")

    assert reads == []
    assert str(tmp_path) not in json.dumps(second, ensure_ascii=False)
    rejected = _run(service, first)
    assert rejected == {"status": "failed", "code": "AUTHORIZATION_INVALID"}
    assert second["authorization_id"] == "second"


def test_prepare_all_operations_performs_no_content_dns_or_network_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    accesses: list[str] = []
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("dns")),
    )
    service = _service(
        file_runner=lambda *_args, **_kwargs: accesses.append("files"),
        browser_runner=lambda *_args, **_kwargs: accesses.append("browser"),
        clipboard_reader=lambda: accesses.append("clipboard") or "text",
        share_runner=lambda *_args, **_kwargs: accesses.append("share"),
    )

    prepared = (
        service.prepare_audit(
            operation="files",
            classification=CLASSIFICATION,
            roots=[str(tmp_path / "files")],
        ),
        service.prepare_audit(
            operation="browser",
            classification=CLASSIFICATION,
            browser_kind="chrome",
            database_path=str(tmp_path / "History"),
        ),
        service.prepare_audit(
            operation="clipboard",
            classification=CLASSIFICATION,
        ),
        service.prepare_audit(
            operation="public_share",
            classification=CLASSIFICATION,
            url="https://example.com/share",
        ),
    )

    assert all(item["status"] == "prepared" for item in prepared)
    assert accesses == []


@pytest.mark.parametrize(
    "mutation",
    (
        "missing",
        "expired",
        "reused",
        "digest",
        "summary",
        "authorization",
        "authorization_type",
        "digest_type",
        "summary_type",
    ),
)
def test_rejected_run_never_accesses_content(
    tmp_path: Path,
    mutation: str,
) -> None:
    now = [10.0]
    reads: list[str] = []

    def file_runner(*_args: object, **_kwargs: object) -> AuditOutcome:
        reads.append("files")
        return _outcome()

    service = _service(
        monotonic=lambda: now[0],
        token_factory=lambda: "authorization",
        file_runner=file_runner,
    )
    prepared = _prepare_files(service, tmp_path / "scope")
    if mutation == "missing":
        service = _service(file_runner=file_runner)
    if mutation == "expired":
        now[0] = 311.0
    authorization_id = prepared["authorization_id"]
    scope_digest = prepared["scope_digest"]
    consent_summary = prepared["consent_summary"]
    if mutation == "digest":
        scope_digest = "0" * 64
    if mutation == "summary":
        consent_summary = "changed"
    if mutation == "authorization":
        authorization_id = "changed"
    if mutation == "authorization_type":
        authorization_id = object()
    if mutation == "digest_type":
        scope_digest = object()
    if mutation == "summary_type":
        consent_summary = object()

    result = service.run_prepared_audit(
        authorization_id=authorization_id,  # type: ignore[arg-type]
        scope_digest=scope_digest,  # type: ignore[arg-type]
        consent_summary=consent_summary,  # type: ignore[arg-type]
    )
    if mutation == "reused":
        assert result["status"] == "completed"
        result = service.run_prepared_audit(
            authorization_id=prepared["authorization_id"],
            scope_digest=prepared["scope_digest"],
            consent_summary=prepared["consent_summary"],
        )

    assert result["status"] == "failed"
    assert reads == ([] if mutation != "reused" else ["files"])


def test_authorization_expiry_boundary_is_inclusive(tmp_path: Path) -> None:
    now = [10.0]
    reads: list[str] = []
    service = _service(
        monotonic=lambda: now[0],
        file_runner=lambda *_args, **_kwargs: reads.append("files") or _outcome(),
    )
    prepared = _prepare_files(service, tmp_path / "scope")
    now[0] = 310.0

    result = _run(service, prepared)

    assert result["status"] == "completed"
    assert reads == ["files"]


def test_authorization_compares_non_ascii_public_scope_as_utf8() -> None:
    service = _service(
        share_runner=lambda _url: ShareVerificationResult(
            "https://example.invalid",
            False,
            None,
            "unknown",
            0,
            0,
            False,
            False,
            False,
            ("network_error",),
        )
    )
    prepared = service.prepare_audit(
        operation="public_share",
        classification=CLASSIFICATION,
        url="https://\u4f8b\u5b50.example/share",
    )

    result = _run(service, prepared)

    assert result["status"] == "completed"


def test_prepare_requires_exact_classification_and_operation(tmp_path: Path) -> None:
    service = _service()

    wrong_classification = service.prepare_audit(
        operation="files",
        classification="PERSONAL_NON_REGULATED",
        roots=[str(tmp_path / "scope")],
    )
    wrong_operation = service.prepare_audit(
        operation="unknown",
        classification=CLASSIFICATION,
    )

    assert wrong_classification == {
        "status": "failed",
        "code": "CLASSIFICATION_UNSUPPORTED",
    }
    assert wrong_operation == {"status": "failed", "code": "OPERATION_UNSUPPORTED"}


@pytest.mark.parametrize(
    "fields",
    (
        {
            "operation": "files",
            "roots": [r"C:\project"],
            "browser_kind": "chrome",
        },
        {
            "operation": "browser",
            "roots": [r"C:\project"],
            "browser_kind": "chrome",
            "database_path": r"C:\profile\History",
        },
        {"operation": "clipboard", "url": "https://example.com"},
        {
            "operation": "public_share",
            "roots": [],
            "url": "https://example.com",
        },
    ),
)
def test_prepare_rejects_extra_operation_fields(fields: dict[str, object]) -> None:
    result = _service().prepare_audit(
        classification=CLASSIFICATION,
        **fields,  # type: ignore[arg-type]
    )

    assert result == {"status": "failed", "code": "REQUEST_FIELDS_INVALID"}


def test_file_root_limit_and_shape_validation_perform_no_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        Path,
        "stat",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("read")),
    )
    roots = [str(tmp_path / f"scope-{index}") for index in range(MAX_ROOTS)]
    service = _service()

    maximum = service.prepare_audit(
        operation="files",
        classification=CLASSIFICATION,
        roots=roots,
    )
    too_many = service.prepare_audit(
        operation="files",
        classification=CLASSIFICATION,
        roots=[*roots, str(tmp_path / "overflow")],
    )
    relative = service.prepare_audit(
        operation="files",
        classification=CLASSIFICATION,
        roots=["relative"],
    )

    assert maximum["status"] == "prepared"
    assert too_many == {"status": "failed", "code": "SCOPE_ROOT_LIMIT"}
    assert relative == {"status": "failed", "code": "SCOPE_INVALID"}


def test_browser_prepare_uses_path_shape_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        os,
        "lstat",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("read")),
    )
    service = _service()

    prepared = service.prepare_audit(
        operation="browser",
        classification=CLASSIFICATION,
        browser_kind="chrome",
        database_path=str(tmp_path / "History"),
    )
    relative = service.prepare_audit(
        operation="browser",
        classification=CLASSIFICATION,
        browser_kind="chrome",
        database_path="History",
    )

    assert prepared["status"] == "prepared"
    assert relative == {"status": "failed", "code": "BROWSER_PATH_INVALID"}


def test_prepare_and_run_responses_are_bounded_and_truncated(tmp_path: Path) -> None:
    findings = tuple(
        _finding(index, evidence_count=2, masked="m" * 80)
        for index in range(150)
    )
    service = _service(file_runner=lambda *_args, **_kwargs: _outcome(findings))
    prepared = _prepare_files(service, tmp_path / "scope")

    result = _run(service, prepared)
    evidence_count = sum(len(item["evidence"]) for item in result["findings"])

    assert len(_canonical_bytes(prepared)) <= MAX_PREPARE_BYTES
    assert len(_canonical_bytes(result)) <= MAX_RUN_BYTES
    assert len(result["findings"]) <= MAX_RESULT_FINDINGS
    assert evidence_count <= MAX_RESULT_EVIDENCE
    assert result["truncated"] is True


def test_prepare_limit_failure_is_fixed_and_creates_no_authorization(
    tmp_path: Path,
) -> None:
    service = _service(token_factory=lambda: "t" * MAX_PREPARE_BYTES)

    result = _prepare_files(service, tmp_path / "scope")

    assert result == {"status": "failed", "code": "PREPARE_RESULT_LIMIT"}
    rejected = service.run_prepared_audit(
        authorization_id="unused",
        scope_digest="0" * 64,
        consent_summary="unused",
    )
    assert rejected == {"status": "failed", "code": "AUTHORIZATION_INVALID"}


def test_results_exclude_raw_values_sources_paths_and_report_fields(
    tmp_path: Path,
) -> None:
    raw = "sk-proj-super-secret-value"
    service = _service(clipboard_reader=lambda: raw)
    prepared = service.prepare_audit(
        operation="clipboard",
        classification=CLASSIFICATION,
    )

    result = _run(service, prepared)
    encoded = _canonical_bytes(result)

    assert len(encoded) <= MAX_RUN_BYTES
    assert raw.encode() not in encoded
    assert b"report_html" not in encoded
    assert b"report_json" not in encoded
    assert b'"source"' not in encoded
    assert str(tmp_path).encode() not in encoded
    assert set(result["findings"][0]) == {
        "rule_id",
        "severity",
        "risk_domain",
        "asset_ref",
        "evidence",
        "manual_guidance",
    }
    assert set(result["findings"][0]["evidence"][0]) == {
        "fingerprint",
        "masked",
    }


def test_failure_codes_are_fixed_and_native_errors_are_sanitized(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    marker = "private-native-exception-marker"

    def fail(*_args: object, **_kwargs: object) -> AuditOutcome:
        raise RuntimeError(marker)

    service = _service(file_runner=fail)
    result = _run(service, _prepare_files(service, tmp_path / "scope"))
    captured = capsys.readouterr()
    serialized = json.dumps(result, sort_keys=True)

    assert result == {"status": "failed", "code": "OPERATION_FAILED"}
    assert marker not in serialized
    assert marker not in captured.out
    assert marker not in captured.err


@pytest.mark.parametrize(
    "operation",
    ("files", "browser", "public_share"),
)
def test_non_qt_callback_cannot_claim_clipboard_unavailable(
    tmp_path: Path,
    operation: str,
) -> None:
    calls: list[str] = []

    def fail(*_args: object, **_kwargs: object):
        calls.append(operation)
        raise ValueError("CLIPBOARD_UNAVAILABLE")

    if operation == "files":
        service = _service(file_runner=fail)
        prepared = _prepare_files(service, tmp_path / "scope")
    elif operation == "browser":
        service = _service(browser_runner=fail)
        prepared = service.prepare_audit(
            operation="browser",
            classification=CLASSIFICATION,
            browser_kind="chrome",
            database_path=str(tmp_path / "History"),
        )
    else:
        service = _service(share_runner=fail)
        prepared = service.prepare_audit(
            operation="public_share",
            classification=CLASSIFICATION,
            url="https://example.com/share",
        )

    result = _run(service, prepared)

    assert result == {"status": "failed", "code": "OPERATION_FAILED"}
    assert calls == [operation]


def test_injected_clipboard_reader_preserves_authoritative_read_error() -> None:
    calls: list[str] = []

    def reader() -> str:
        calls.append("reader")
        raise ValueError("CLIPBOARD_UNAVAILABLE")

    direct_result, direct_outcome = run_clipboard_audit(
        reader,
        disposition_key=b"d" * 32,
        evaluated_at=FIXED_NOW,
    )

    assert calls == ["reader"]
    calls.clear()

    service = _service(clipboard_reader=reader)
    prepared = service.prepare_audit(
        operation="clipboard",
        classification=CLASSIFICATION,
    )
    result = _run(service, prepared)

    assert direct_outcome is None
    assert direct_result.scanned is False
    assert direct_result.limits == ("clipboard_read_error",)
    assert direct_result.raw_data_retained is False
    assert result["status"] == "completed"
    assert result["scanned"] is direct_result.scanned
    assert result["limits"] == list(direct_result.limits)
    assert result["raw_data_retained"] is direct_result.raw_data_retained
    assert result["finding_count"] == len(direct_result.findings) == 0
    assert result["evidence_count"] == 0
    assert result["findings"] == []
    assert "outcome" not in result
    assert "score" not in result
    assert "reviewed_score" not in result
    assert "rule_version" not in result
    assert calls == ["reader"]


def test_authorization_is_consumed_before_operation_callback(tmp_path: Path) -> None:
    observed: list[bool] = []
    service: AuditMcpService

    def file_runner(*_args: object, **_kwargs: object) -> AuditOutcome:
        observed.append(service._pending is None)
        raise RuntimeError("callback failure")

    service = _service(file_runner=file_runner)
    prepared = _prepare_files(service, tmp_path / "scope")

    first = _run(service, prepared)
    second = _run(service, prepared)

    assert first == {"status": "failed", "code": "OPERATION_FAILED"}
    assert second == {"status": "failed", "code": "AUTHORIZATION_INVALID"}
    assert observed == [True]


def test_browser_cleanup_failure_is_fixed_and_consumed(tmp_path: Path) -> None:
    calls: list[str] = []

    def fail_cleanup(*_args: object, **_kwargs: object) -> BrowserAuditResult:
        calls.append("browser")
        raise ValueError("BROWSER_TEMP_CLEANUP_FAILED")

    service = _service(browser_runner=fail_cleanup)
    prepared = service.prepare_audit(
        operation="browser",
        classification=CLASSIFICATION,
        browser_kind="chrome",
        database_path=str(tmp_path / "History"),
    )

    first = _run(service, prepared)
    second = _run(service, prepared)

    assert first == {"status": "failed", "code": "BROWSER_TEMP_CLEANUP_FAILED"}
    assert second == {"status": "failed", "code": "AUTHORIZATION_INVALID"}
    assert calls == ["browser"]


def test_public_share_failure_has_no_retry_or_fallback() -> None:
    calls: list[str] = []

    def fail(url: str):
        calls.append(url)
        raise RuntimeError("private public-share failure")

    service = _service(share_runner=fail)
    prepared = service.prepare_audit(
        operation="public_share",
        classification=CLASSIFICATION,
        url="https://example.com/share",
    )

    result = _run(service, prepared)

    assert result == {"status": "failed", "code": "OPERATION_FAILED"}
    assert calls == ["https://example.com/share"]


def test_import_and_clipboard_prepare_leave_qt_unimported() -> None:
    script = (
        "import sys; "
        "assert not any(name.startswith('PySide6') for name in sys.modules); "
        "from agentguardian.mcp_service import AuditMcpService; "
        "service = AuditMcpService(); "
        "result = service.prepare_audit(operation='clipboard', "
        "classification='personal_non_regulated'); "
        "assert result['status'] == 'prepared'; "
        "assert not any(name.startswith('PySide6') for name in sys.modules)"
    )
    completed = subprocess.run(
        (sys.executable, "-c", script),
        cwd=PROJECT_ROOT,
        env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT / "src")},
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr


def test_lazy_clipboard_failure_is_sanitized(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    marker = "private-qt-import-marker"
    real_import = builtins.__import__

    def fail_qt(name: str, *args: object, **kwargs: object):
        if name.startswith("PySide6"):
            raise ImportError(marker)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fail_qt)
    service = _service()
    prepared = service.prepare_audit(
        operation="clipboard",
        classification=CLASSIFICATION,
    )

    result = _run(service, prepared)
    captured = capsys.readouterr()
    serialized = json.dumps(result, sort_keys=True)

    assert result == {"status": "failed", "code": "CLIPBOARD_UNAVAILABLE"}
    assert marker not in serialized
    assert marker not in captured.out
    assert marker not in captured.err


def test_falsey_injected_clipboard_reader_is_still_used() -> None:
    calls: list[str] = []

    class FalseyReader:
        def __bool__(self) -> bool:
            return False

        def __call__(self) -> str:
            calls.append("reader")
            return "ordinary clipboard text"

    service = _service(clipboard_reader=FalseyReader())
    prepared = service.prepare_audit(
        operation="clipboard",
        classification=CLASSIFICATION,
    )

    result = _run(service, prepared)

    assert result["status"] == "completed"
    assert result["scanned"] is True
    assert calls == ["reader"]


def test_files_match_the_authoritative_operation(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    raw = "OPENAI_API_KEY=sk-proj-authoritative-file-value"
    (root / ".env").write_text(raw, encoding="utf-8")
    preview = build_scope_preview((root,), SUPPORTED_SUFFIXES, **AUDIT_CAPS)
    direct = run_file_audit(
        (root,),
        scope_preview=preview,
        disposition_key=b"d" * 32,
        evaluated_at=FIXED_NOW,
    )
    service = _service()

    result = _run(service, _prepare_files(service, root))
    serialized = json.dumps(result, ensure_ascii=False, sort_keys=True)

    assert result["status"] == "completed"
    assert {(item["rule_id"], item["severity"]) for item in result["findings"]} == {
        (item.rule_id, item.severity.value) for item in direct.findings
    }
    assert result["score"] == _score_data(direct.score)
    assert result["reviewed_score"] == _score_data(direct.reviewed_score)
    assert result["rule_version"] == direct.rule_version
    assert result["limits"] == list(direct.score.limits)
    assert result["finding_count"] == len(direct.findings)
    assert result["evidence_count"] == sum(
        len(finding.evidence) for finding in direct.findings
    )
    assert raw not in serialized
    assert str(root) not in serialized


def test_browser_matches_the_authoritative_operation(tmp_path: Path) -> None:
    database = tmp_path / "History"
    raw_url = _create_browser_database(database)
    direct = audit_browser_database(database, BrowserKind.CHROME)
    service = _service()
    prepared = service.prepare_audit(
        operation="browser",
        classification=CLASSIFICATION,
        browser_kind="chrome",
        database_path=str(database),
    )

    result = _run(service, prepared)
    serialized = json.dumps(result, sort_keys=True)

    assert result["status"] == "completed"
    assert result["browser"] == direct.browser.value
    assert result["counts"] == dict(direct.counts)
    assert result["limits"] == list(direct.limits)
    assert result["raw_data_retained"] is direct.raw_data_retained
    assert result["temporary_copy_removed"] is direct.temporary_copy_removed
    assert raw_url not in serialized
    assert str(database) not in serialized


def test_clipboard_matches_the_authoritative_operation() -> None:
    raw = "OPENAI_API_KEY=sk-proj-authoritative-clipboard-value"
    direct_result, direct_outcome = run_clipboard_audit(
        lambda: raw,
        disposition_key=b"d" * 32,
        evaluated_at=FIXED_NOW,
    )
    assert direct_outcome is not None
    service = _service(clipboard_reader=lambda: raw)
    prepared = service.prepare_audit(
        operation="clipboard",
        classification=CLASSIFICATION,
    )

    result = _run(service, prepared)
    serialized = json.dumps(result, sort_keys=True)

    assert result["status"] == "completed"
    assert {(item["rule_id"], item["severity"]) for item in result["findings"]} == {
        (item.rule_id, item.severity.value) for item in direct_result.findings
    }
    assert result["score"] == _score_data(direct_outcome.score)
    assert result["reviewed_score"] == _score_data(direct_outcome.reviewed_score)
    assert result["scanned"] is direct_result.scanned
    assert result["limits"] == list(direct_result.limits)
    assert result["raw_data_retained"] is direct_result.raw_data_retained
    assert result["finding_count"] == len(direct_result.findings)
    assert result["evidence_count"] == sum(
        len(finding.evidence) for finding in direct_result.findings
    )
    assert raw not in serialized


def test_public_share_matches_the_authoritative_operation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "agentguardian.share_verification.build_opener",
        lambda *_args, **_kwargs: _Opener(),
    )
    url = "https://example.com/share"
    direct = verify_public_share(url)
    service = _service()
    prepared = service.prepare_audit(
        operation="public_share",
        classification=CLASSIFICATION,
        url=url,
    )

    result = _run(service, prepared)

    assert result["status"] == "completed"
    assert result["address"] == direct.address
    assert result["reachable"] is direct.reachable
    assert result["status_code"] == direct.status_code
    assert result["content_type"] == direct.content_type
    assert result["bytes_read"] == direct.bytes_read
    assert result["redirects_followed"] == direct.redirects_followed
    assert result["scanned_data_sent"] is direct.scanned_data_sent
    assert result["credentials_sent"] is direct.credentials_sent
    assert result["raw_response_retained"] is direct.raw_response_retained
    assert result["limits"] == list(direct.limits)
    assert result["findings"] == []
