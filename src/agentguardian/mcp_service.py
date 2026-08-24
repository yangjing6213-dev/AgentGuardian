from __future__ import annotations

import hashlib
import hmac
import json
import math
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path, PureWindowsPath

from . import __version__
from .audit_service import AuditOutcome, run_clipboard_audit, run_file_audit
from .browser_audit import BrowserAuditResult, BrowserKind, audit_browser_database
from .domain import Finding, RiskDomain, Score, validate_safe_annotation
from .guidance import guidance_for
from .share_verification import (
    ShareVerificationResult,
    validate_public_share_url,
    verify_public_share,
)
from .workflow import ScopePreview, build_scope_preview, classify_coverage


CLASSIFICATION = "personal_non_regulated"
OPERATIONS = frozenset({"files", "browser", "clipboard", "public_share"})
AUTHORIZATION_TTL_SECONDS = 300.0
MAX_PREPARE_BYTES = 16 * 1024
MAX_RUN_BYTES = 64 * 1024
MAX_ROOTS = 32
MAX_RESULT_FINDINGS = 100
MAX_RESULT_EVIDENCE = 200

_SUPPORTED_SUFFIXES = (
    ".env",
    ".json",
    ".log",
    ".md",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
)
_MAX_AUDIT_FILES = 10_000
_MAX_AUDIT_ENTRIES = 50_000
_MAX_AUDIT_BYTES = 512 * 1024 * 1024
_MAX_AUDIT_FINDINGS = 2_000
_MAX_AUDIT_EVIDENCE = 4_000
_UNSUPPORTED_USE_NOTICE = (
    "Personal, non-regulated data only; incomplete or truncated output cannot "
    "establish safety."
)
_MODEL_CONTEXT_NOTICE = (
    "Redacted tool arguments and results may enter the Codex model context."
)
_PREPARE_CODES = frozenset(
    {
        "BROWSER_INPUT_INVALID",
        "BROWSER_PATH_INVALID",
        "CLASSIFICATION_UNSUPPORTED",
        "OPERATION_UNSUPPORTED",
        "PREPARE_RESULT_LIMIT",
        "REQUEST_FIELDS_INVALID",
        "REQUEST_INVALID",
        "SCOPE_DATA_CLASS_UNSUPPORTED",
        "SCOPE_INVALID",
        "SCOPE_ROOT_LIMIT",
        "SCOPE_TOO_BROAD",
        "SHARE_PRIVATE_HOST_REJECTED",
        "SHARE_URL_FRAGMENT_REJECTED",
        "SHARE_URL_INVALID",
        "SHARE_URL_QUERY_REJECTED",
    }
)
_RUN_CODES = frozenset(
    {
        "AUTHORIZATION_EXPIRED",
        "AUTHORIZATION_INVALID",
        "BROWSER_DB_UNREADABLE",
        "BROWSER_INPUT_INVALID",
        "BROWSER_PATH_INVALID",
        "BROWSER_SCHEMA_UNSUPPORTED",
        "BROWSER_TEMP_CLEANUP_FAILED",
        "CLIPBOARD_UNAVAILABLE",
        "OPERATION_FAILED",
        "RESULT_LIMIT_EXCEEDED",
        "SHARE_PRIVATE_HOST_REJECTED",
        "SHARE_URL_FRAGMENT_REJECTED",
        "SHARE_URL_INVALID",
        "SHARE_URL_QUERY_REJECTED",
    }
)
_WINDOWS_RESERVED_NAMES = frozenset(
    {"con", "nul", "prn", "aux", "conin$", "conout$"}
    | {f"com{number}" for number in range(1, 10)}
    | {f"lpt{number}" for number in range(1, 10)}
)
_DATA_CLASSES = {
    "files": "local_files_and_configuration",
    "browser": "browser_database_metadata",
    "clipboard": "clipboard_text",
    "public_share": "public_share_reachability",
}


class _PrepareFailure(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _ClipboardUnavailable(Exception):
    pass


@dataclass(frozen=True, slots=True)
class _PreparedRequest:
    operation: str
    classification: str
    roots: tuple[Path, ...] = field(default=(), repr=False)
    scope_preview: ScopePreview | None = field(default=None, repr=False)
    browser: BrowserKind | None = None
    database_path: Path | None = field(default=None, repr=False)
    url: str | None = field(default=None, repr=False)
    redacted_scope: str = ""
    network_io: bool = False


@dataclass(frozen=True, slots=True)
class _PendingAuthorization:
    authorization_id: str = field(repr=False)
    scope_digest: str
    consent_summary: str
    expires_monotonic: float
    expires_at: str
    request: _PreparedRequest = field(repr=False)


def _qt_clipboard_text() -> str:
    try:
        from PySide6.QtWidgets import QApplication

        application = QApplication.instance()
        if application is None:
            application = QApplication([])
        clipboard = application.clipboard()
        if clipboard is None:
            raise RuntimeError
        return clipboard.text()
    except Exception:
        raise _ClipboardUnavailable from None


class AuditMcpService:
    def __init__(
        self,
        *,
        monotonic: Callable[[], float] = time.monotonic,
        utc_now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        token_factory: Callable[[], str] = lambda: secrets.token_urlsafe(32),
        file_runner: Callable[..., AuditOutcome] = run_file_audit,
        browser_runner: Callable[..., BrowserAuditResult] = audit_browser_database,
        clipboard_reader: Callable[[], str] | None = None,
        share_runner: Callable[..., ShareVerificationResult] = verify_public_share,
    ) -> None:
        self._monotonic = monotonic
        self._utc_now = utc_now
        self._token_factory = token_factory
        self._file_runner = file_runner
        self._browser_runner = browser_runner
        self._clipboard_reader = (
            _qt_clipboard_text if clipboard_reader is None else clipboard_reader
        )
        self._share_runner = share_runner
        self._pending: _PendingAuthorization | None = None

    def prepare_audit(
        self,
        *,
        operation: str,
        classification: str,
        roots: list[str] | None = None,
        browser_kind: str | None = None,
        database_path: str | None = None,
        url: str | None = None,
    ) -> dict[str, object]:
        self._pending = None
        try:
            request = _normalize_request(
                operation=operation,
                classification=classification,
                roots=roots,
                browser_kind=browser_kind,
                database_path=database_path,
                url=url,
            )
            digest = _scope_digest(request)
            summary = _consent_summary(request)
            authorization_id = self._token_factory()
            if type(authorization_id) is not str or not authorization_id:
                raise _PrepareFailure("REQUEST_INVALID")
            now = self._monotonic()
            utc_now = self._utc_now()
            if (
                type(now) not in (int, float)
                or not math.isfinite(now)
                or type(utc_now) is not datetime
                or utc_now.tzinfo is None
                or utc_now.utcoffset() != timedelta(0)
            ):
                raise _PrepareFailure("REQUEST_INVALID")
            expires = utc_now.replace(microsecond=0) + timedelta(
                seconds=AUTHORIZATION_TTL_SECONDS
            )
            pending = _PendingAuthorization(
                authorization_id,
                digest,
                summary,
                float(now) + AUTHORIZATION_TTL_SECONDS,
                expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
                request,
            )
            response = _prepare_response(pending)
            if len(_canonical_bytes(response)) > MAX_PREPARE_BYTES:
                raise _PrepareFailure("PREPARE_RESULT_LIMIT")
            self._pending = pending
            return response
        except Exception as error:
            return _fixed_failure(_allowed_prepare_code(error))

    def run_prepared_audit(
        self,
        *,
        authorization_id: str,
        scope_digest: str,
        consent_summary: str,
    ) -> dict[str, object]:
        pending, self._pending = self._pending, None
        if pending is None:
            return _fixed_failure("AUTHORIZATION_INVALID")
        if (
            type(authorization_id) is not str
            or type(scope_digest) is not str
            or type(consent_summary) is not str
        ):
            return _fixed_failure("AUTHORIZATION_INVALID")
        try:
            matches = (
                hmac.compare_digest(
                    authorization_id.encode("utf-8"),
                    pending.authorization_id.encode("utf-8"),
                ),
                hmac.compare_digest(
                    scope_digest.encode("utf-8"),
                    pending.scope_digest.encode("utf-8"),
                ),
                hmac.compare_digest(
                    consent_summary.encode("utf-8"),
                    pending.consent_summary.encode("utf-8"),
                ),
            )
        except Exception:
            return _fixed_failure("AUTHORIZATION_INVALID")
        if not all(matches):
            return _fixed_failure("AUTHORIZATION_INVALID")
        try:
            now = self._monotonic()
            if type(now) not in (int, float) or not math.isfinite(now):
                raise ValueError
        except Exception:
            return _fixed_failure("OPERATION_FAILED")
        if now > pending.expires_monotonic:
            return _fixed_failure("AUTHORIZATION_EXPIRED")
        try:
            return _bounded_run_response(self._execute(pending.request))
        except Exception as error:
            return _fixed_failure(_allowed_run_code(error))

    def _execute(self, request: _PreparedRequest) -> dict[str, object]:
        if request.operation == "files":
            if request.scope_preview is None:
                raise ValueError
            outcome = self._file_runner(
                request.roots,
                scope_preview=request.scope_preview,
                disposition_key=_disposition_key(),
            )
            return _audit_response(request, outcome)
        if request.operation == "browser":
            if request.database_path is None or request.browser is None:
                raise ValueError
            result = self._browser_runner(request.database_path, request.browser)
            return _browser_response(request, result)
        if request.operation == "clipboard":
            clipboard_text = self._clipboard_reader()
            result, outcome = run_clipboard_audit(
                lambda: clipboard_text,
                disposition_key=_disposition_key(),
            )
            return _clipboard_response(request, result, outcome)
        if request.operation == "public_share":
            if request.url is None:
                raise ValueError
            result = self._share_runner(request.url)
            return _share_response(request, result)
        raise ValueError


def _normalize_request(
    *,
    operation: str,
    classification: str,
    roots: list[str] | None,
    browser_kind: str | None,
    database_path: str | None,
    url: str | None,
) -> _PreparedRequest:
    if type(operation) is not str or operation not in OPERATIONS:
        raise _PrepareFailure("OPERATION_UNSUPPORTED")
    if type(classification) is not str or classification != CLASSIFICATION:
        raise _PrepareFailure("CLASSIFICATION_UNSUPPORTED")

    if operation == "files":
        if browser_kind is not None or database_path is not None or url is not None:
            raise _PrepareFailure("REQUEST_FIELDS_INVALID")
        if type(roots) is not list or not roots:
            raise _PrepareFailure("SCOPE_INVALID")
        if len(roots) > MAX_ROOTS:
            raise _PrepareFailure("SCOPE_ROOT_LIMIT")
        if any(type(root) is not str for root in roots):
            raise _PrepareFailure("SCOPE_INVALID")
        try:
            normalized_roots = tuple(Path(root) for root in roots)
            preview = build_scope_preview(
                normalized_roots,
                _SUPPORTED_SUFFIXES,
                max_files=_MAX_AUDIT_FILES,
                max_entries=_MAX_AUDIT_ENTRIES,
                max_bytes=_MAX_AUDIT_BYTES,
                max_findings=_MAX_AUDIT_FINDINGS,
                max_evidence=_MAX_AUDIT_EVIDENCE,
            )
        except Exception as error:
            code = str(error)
            if code not in {"SCOPE_TOO_BROAD", "SCOPE_DATA_CLASS_UNSUPPORTED"}:
                code = "SCOPE_INVALID"
            raise _PrepareFailure(code) from None
        root_label = "root" if len(normalized_roots) == 1 else "roots"
        return _PreparedRequest(
            operation,
            classification,
            normalized_roots,
            preview,
            redacted_scope=f"{len(normalized_roots)} selected file {root_label}",
        )

    if operation == "browser":
        if roots is not None or url is not None:
            raise _PrepareFailure("REQUEST_FIELDS_INVALID")
        if type(browser_kind) is not str:
            raise _PrepareFailure("BROWSER_INPUT_INVALID")
        try:
            browser = BrowserKind(browser_kind)
        except ValueError:
            raise _PrepareFailure("BROWSER_INPUT_INVALID") from None
        path = _browser_path(database_path)
        return _PreparedRequest(
            operation,
            classification,
            browser=browser,
            database_path=path,
            redacted_scope=f"{browser.value} browser database",
        )

    if operation == "clipboard":
        if any(value is not None for value in (roots, browser_kind, database_path, url)):
            raise _PrepareFailure("REQUEST_FIELDS_INVALID")
        return _PreparedRequest(
            operation,
            classification,
            redacted_scope="clipboard text present at execution",
        )

    if any(value is not None for value in (roots, browser_kind, database_path)):
        raise _PrepareFailure("REQUEST_FIELDS_INVALID")
    if type(url) is not str:
        raise _PrepareFailure("SHARE_URL_INVALID")
    try:
        request_url, address = validate_public_share_url(url)
    except Exception as error:
        code = str(error)
        if code not in {
            "SHARE_URL_INVALID",
            "SHARE_URL_QUERY_REJECTED",
            "SHARE_URL_FRAGMENT_REJECTED",
            "SHARE_PRIVATE_HOST_REJECTED",
        }:
            code = "SHARE_URL_INVALID"
        raise _PrepareFailure(code) from None
    return _PreparedRequest(
        operation,
        classification,
        url=request_url,
        redacted_scope=address,
        network_io=True,
    )


def _browser_path(value: object) -> Path:
    if type(value) is not str:
        raise _PrepareFailure("BROWSER_PATH_INVALID")
    try:
        path = PureWindowsPath(value)
        if (
            path.drive.startswith("\\\\")
            or not path.drive
            or not path.is_absolute()
            or path == PureWindowsPath(path.anchor)
            or not path.name
            or any(_unsafe_windows_component(part) for part in path.parts[1:])
        ):
            raise ValueError
        return Path(value)
    except (OSError, ValueError):
        raise _PrepareFailure("BROWSER_PATH_INVALID") from None


def _unsafe_windows_component(value: str) -> bool:
    device_name = value.partition(".")[0].rstrip(" .").casefold()
    return (
        value in {".", ".."}
        or not value
        or value.endswith((" ", "."))
        or any(character in value for character in '/\\:*?"<>|')
        or any(not character.isprintable() for character in value)
        or device_name in _WINDOWS_RESERVED_NAMES
    )


def _scope_digest(request: _PreparedRequest) -> str:
    if request.operation == "files":
        scope: object = [str(root) for root in request.roots]
    elif request.operation == "browser":
        scope = {
            "browser": request.browser.value if request.browser else None,
            "database_path": str(request.database_path),
        }
    elif request.operation == "public_share":
        scope = request.url
    else:
        scope = None
    payload = {
        "operation": request.operation,
        "classification": request.classification,
        "scope": scope,
    }
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def _consent_summary(request: _PreparedRequest) -> str:
    network = "Public network I/O will occur." if request.network_io else "No network I/O."
    return (
        f"Authorize one {request.operation} audit for {request.redacted_scope}. "
        f"{network} {_MODEL_CONTEXT_NOTICE}"
    )


def _prepare_response(pending: _PendingAuthorization) -> dict[str, object]:
    request = pending.request
    return {
        "schema": 1,
        "agentguardian_version": __version__,
        "status": "prepared",
        "operation": request.operation,
        "classification": request.classification,
        "data_class": _DATA_CLASSES[request.operation],
        "redacted_scope": request.redacted_scope,
        "network_io": request.network_io,
        "limits": {
            "prepare_bytes": MAX_PREPARE_BYTES,
            "run_bytes": MAX_RUN_BYTES,
            "roots": MAX_ROOTS,
            "findings": MAX_RESULT_FINDINGS,
            "evidence": MAX_RESULT_EVIDENCE,
        },
        "unsupported_use_notice": _UNSUPPORTED_USE_NOTICE,
        "model_context_notice": _MODEL_CONTEXT_NOTICE,
        "authorization_id": pending.authorization_id,
        "scope_digest": pending.scope_digest,
        "consent_summary": pending.consent_summary,
        "expires_at": pending.expires_at,
    }


def _base_response(request: _PreparedRequest) -> dict[str, object]:
    return {
        "schema": 1,
        "agentguardian_version": __version__,
        "status": "completed",
        "operation": request.operation,
        "classification": request.classification,
        "findings": [],
        "truncated": False,
        "unsupported_use_notice": _UNSUPPORTED_USE_NOTICE,
    }


def _audit_response(
    request: _PreparedRequest,
    outcome: object,
) -> dict[str, object]:
    if type(outcome) is not AuditOutcome:
        raise ValueError
    finding_data, truncated = _finding_data(outcome.findings)
    response = _base_response(request)
    response.update(
        {
            "findings": finding_data,
            "finding_count": len(outcome.findings),
            "evidence_count": sum(len(finding.evidence) for finding in outcome.findings),
            "score": _score_data(outcome.score),
            "reviewed_score": _score_data(outcome.reviewed_score),
            "rule_version": validate_safe_annotation(
                "rule_version", outcome.rule_version, 80
            ),
            "limits": _safe_limits(outcome.score.limits),
            "truncated": truncated,
        }
    )
    return response


def _clipboard_response(
    request: _PreparedRequest,
    result: object,
    outcome: object,
) -> dict[str, object]:
    from .clipboard_audit import ClipboardAuditResult

    if type(result) is not ClipboardAuditResult:
        raise ValueError
    response = _base_response(request)
    response.update(
        {
            "scanned": result.scanned,
            "limits": _safe_limits(result.limits),
            "raw_data_retained": result.raw_data_retained,
            "finding_count": len(result.findings),
            "evidence_count": sum(len(finding.evidence) for finding in result.findings),
        }
    )
    if outcome is None:
        return response
    if type(outcome) is not AuditOutcome or outcome.findings != result.findings:
        raise ValueError
    finding_data, truncated = _finding_data(outcome.findings)
    response.update(
        {
            "findings": finding_data,
            "score": _score_data(outcome.score),
            "reviewed_score": _score_data(outcome.reviewed_score),
            "rule_version": validate_safe_annotation(
                "rule_version", outcome.rule_version, 80
            ),
            "truncated": truncated,
        }
    )
    return response


def _browser_response(
    request: _PreparedRequest,
    result: object,
) -> dict[str, object]:
    if type(result) is not BrowserAuditResult or result.browser is not request.browser:
        raise ValueError
    if result.temporary_copy_removed is not True:
        raise ValueError("BROWSER_TEMP_CLEANUP_FAILED")
    if result.raw_data_retained is not False or type(result.counts) is not tuple:
        raise ValueError
    counts: dict[str, int] = {}
    for item in result.counts:
        if (
            type(item) is not tuple
            or len(item) != 2
            or item[0] not in {"history_entries", "visit_entries"}
            or type(item[1]) is not int
            or item[1] < 0
            or item[0] in counts
        ):
            raise ValueError
        counts[item[0]] = item[1]
    response = _base_response(request)
    response.update(
        {
            "browser": result.browser.value,
            "counts": counts,
            "limits": _safe_limits(result.limits),
            "raw_data_retained": False,
            "temporary_copy_removed": True,
        }
    )
    return response


def _share_response(
    request: _PreparedRequest,
    result: object,
) -> dict[str, object]:
    if type(result) is not ShareVerificationResult or request.url is None:
        raise ValueError
    _request_url, address = validate_public_share_url(request.url)
    if (
        type(result.reachable) is not bool
        or (
            result.status_code is not None
            and (type(result.status_code) is not int or not 100 <= result.status_code <= 599)
        )
        or type(result.bytes_read) is not int
        or result.bytes_read < 0
        or type(result.redirects_followed) is not int
        or result.redirects_followed < 0
        or type(result.scanned_data_sent) is not bool
        or type(result.credentials_sent) is not bool
        or type(result.raw_response_retained) is not bool
    ):
        raise ValueError
    response = _base_response(request)
    response.update(
        {
            "address": address,
            "reachable": result.reachable,
            "status_code": result.status_code,
            "content_type": validate_safe_annotation(
                "content_type", result.content_type, 80
            ),
            "bytes_read": result.bytes_read,
            "redirects_followed": result.redirects_followed,
            "scanned_data_sent": result.scanned_data_sent,
            "credentials_sent": result.credentials_sent,
            "raw_response_retained": result.raw_response_retained,
            "limits": _safe_limits(result.limits),
        }
    )
    return response


def _finding_data(findings: object) -> tuple[list[dict[str, object]], bool]:
    if type(findings) is not tuple:
        raise ValueError
    output: list[dict[str, object]] = []
    evidence_count = 0
    truncated = False
    for finding in findings:
        if type(finding) is not Finding:
            raise ValueError
        if len(output) >= MAX_RESULT_FINDINGS:
            truncated = True
            break
        remaining = MAX_RESULT_EVIDENCE - evidence_count
        if remaining == 0 and finding.evidence:
            truncated = True
            break
        evidence = [
            {"fingerprint": item.fingerprint, "masked": item.masked}
            for item in finding.evidence[:remaining]
        ]
        if len(evidence) != len(finding.evidence):
            truncated = True
        output.append(
            {
                "rule_id": finding.rule_id,
                "severity": finding.severity.value,
                "risk_domain": finding.domain.value,
                "asset_ref": finding.root_fingerprint,
                "evidence": evidence,
                "manual_guidance": list(
                    guidance_for(finding.rule_id, finding.root_fingerprint).steps
                ),
            }
        )
        evidence_count += len(evidence)
        if truncated:
            break
    if len(output) != len(findings):
        truncated = True
    return output, truncated


def _score_data(value: object) -> dict[str, object]:
    if type(value) is not Score or type(value.deductions) is not tuple:
        raise ValueError
    deductions: list[dict[str, object]] = []
    expected_domains = tuple(RiskDomain)
    if len(value.deductions) != len(expected_domains):
        raise ValueError
    for expected, item in zip(expected_domains, value.deductions, strict=True):
        if (
            type(item) is not tuple
            or len(item) != 2
            or item[0] is not expected
            or type(item[1]) is not int
            or item[1] < 0
        ):
            raise ValueError
        deductions.append({"domain": expected.value, "amount": item[1]})
    cap_reason = value.cap_reason
    if cap_reason is not None:
        cap_reason = validate_safe_annotation("cap_reason", cap_reason, 80)
    return {
        "total": value.total,
        "deductions": deductions,
        "cap_reason": cap_reason,
        "coverage": value.coverage,
        "confidence": value.confidence,
        "incomplete": value.incomplete,
        "limits": _safe_limits(value.limits),
        "coverage_state": classify_coverage(value).value,
    }


def _safe_limits(values: object) -> list[str]:
    if type(values) is not tuple or len(values) > 100:
        raise ValueError
    return [validate_safe_annotation("limit", value, 80) for value in values]


def _disposition_key() -> bytes:
    try:
        key = secrets.token_bytes(32)
        if type(key) is not bytes or len(key) != 32:
            raise ValueError
        return key
    except Exception:
        raise ValueError from None


def _bounded_run_response(response: dict[str, object]) -> dict[str, object]:
    if len(_canonical_bytes(response)) <= MAX_RUN_BYTES:
        return response
    response["truncated"] = True
    findings = response.get("findings")
    if type(findings) is not list:
        return _fixed_failure("RESULT_LIMIT_EXCEEDED")
    steps = 0
    while len(_canonical_bytes(response)) > MAX_RUN_BYTES and findings:
        last = findings[-1]
        evidence = last.get("evidence") if type(last) is dict else None
        if type(evidence) is list and evidence:
            evidence.pop()
        else:
            findings.pop()
        steps += 1
        if steps > MAX_RESULT_FINDINGS + MAX_RESULT_EVIDENCE:
            break
    if len(_canonical_bytes(response)) > MAX_RUN_BYTES:
        return _fixed_failure("RESULT_LIMIT_EXCEEDED")
    return response


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _allowed_prepare_code(error: Exception) -> str:
    if type(error) is _PrepareFailure and error.code in _PREPARE_CODES:
        return error.code
    return "REQUEST_INVALID"


def _allowed_run_code(error: Exception) -> str:
    if type(error) is _ClipboardUnavailable:
        return "CLIPBOARD_UNAVAILABLE"
    if type(error) is ValueError:
        code = str(error)
        if code in _RUN_CODES and code != "CLIPBOARD_UNAVAILABLE":
            return code
    return "OPERATION_FAILED"


def _fixed_failure(code: str) -> dict[str, object]:
    if code not in _PREPARE_CODES | _RUN_CODES:
        code = "OPERATION_FAILED"
    return {"status": "failed", "code": code}
