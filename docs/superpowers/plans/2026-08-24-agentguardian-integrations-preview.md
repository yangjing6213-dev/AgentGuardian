# AgentGuardian 0.3 Integrations Preview Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build one local AgentGuardian audit core with a Windows GUI, a separately distributable Codex Skill, and an on-demand STDIO MCP entry point while preserving the personal, non-regulated preview boundary.

**Architecture:** Extract the existing file and clipboard orchestration into a Qt-free audit service, place one bounded authorization and redaction service in front of the four existing local audit operations, and expose exactly two tools through the official MCP Python SDK. Package the same canonical Skill bytes independently and through a distinct current-user Inno Setup identity. One reviewed PyInstaller onedir payload contains a windowed `AgentGuardian.exe` for GUI and maintenance plus a console `AgentGuardianMcp.exe` for STDIO; both launch the same audited source. Manage Codex configuration and Skill ownership transactionally with DPAPI-protected rollback data. The frozen 0.2 profile, installer, files, reports, and evidence remain historical and unchanged.

**Tech Stack:** Python 3.12, PySide6, MCP Python SDK 2.0.0, stdlib `tomllib`, Windows DPAPI, Inno Setup 7.0.2, PyInstaller 6.16, CycloneDX, pytest, PowerShell, GitHub Actions.

---

## Approved-Spec Implementation Compatibility Corrections

A read-only execution preflight on 2026-08-24 identified three compatibility corrections before Tasks 2-8. They make the approved product shape executable with the official Skill location, Windows STDIO semantics, and frozen 0.2 coexistence. They are implementation compatibility corrections, not new features: the four operations, exactly two MCP tools, personal non-regulated boundary, `NO-GO` status, standalone Skill product, and frozen 0.2 artifacts remain unchanged.

1. The official user Skill target is `%USERPROFILE%\.agents\skills\agentguardian`, as documented by the current official OpenAI Skill documentation at `$HOME/.agents/skills`. There is no second compatibility copy.
2. Windows ships two launchers from one audited core and one reviewed PyInstaller onedir payload. `AgentGuardian.exe` is windowed (`console=False`) and remains the GUI/maintenance launcher. `AgentGuardianMcp.exe` is console-enabled (`console=True`) and supports only the planned STDIO argument path. Installed MCP configuration points to `AgentGuardianMcp.exe` with `args = ["--stdio-mcp"]`; the GUI launcher is not the installed STDIO command. Task 6 proves the helper over real redirected stdin/stdout pipes.
3. The 0.3 current-user install directory is exactly `{localappdata}\Programs\AgentGuardian Integrations Preview`. Its new AppId and uninstaller therefore cannot overwrite or remove frozen 0.2 program files under the historical AgentGuardian directory.

Authoritative references used by this plan:

- Codex local MCP configuration and approval fields: <https://learn.chatgpt.com/docs/extend/mcp?surface=cli>
- Codex Skill structure and user-level path: <https://learn.chatgpt.com/docs/build-skills>
- Official MCP Python SDK v2 server and in-process test API: <https://py.sdk.modelcontextprotocol.io/>
- Official MCP Python SDK STDIO behavior: <https://py.sdk.modelcontextprotocol.io/run/>
- Official MCP Python SDK testing API: <https://py.sdk.modelcontextprotocol.io/get-started/testing/>

## Baseline And Non-Negotiable Gates

- Source baseline: `7c8c7fb0ad9242fe9973a6f26b3ea84c12e352f4`.
- Approved design commit: `5cef0d28701b0c96fa466b64c9e7a47043b1fb9a`.
- Development branch: `codex/0.3-integrations-preview`.
- Revalidated baseline: `1838 passed, 16 skipped` on 2026-08-24 before implementation.
- Preview versions: Python `0.3.0a1`, product `0.3.0-preview.1`, Windows file `0.3.0.1`, Skill `0.1.0`.
- Preview status remains `INTEGRATIONS-PREVIEW-NOT-READY` and formal release remains `NO-GO` until every exact-SHA gate is evidenced.
- Do not push, publish, deploy, upload to a marketplace, create a GitHub Release, or claim production safety while executing this plan.
- Stage only the paths named in each task. Never use `git add .` or `git add -A`.

## File Map

### Shared runtime

- Create `src/agentguardian/audit_service.py`: Qt-free file orchestration plus the shared clipboard outcome builder.
- Create `src/agentguardian/mcp_service.py`: request normalization, one in-memory authorization, execution, redaction, and output caps.
- Create `src/agentguardian/mcp_server.py`: exactly two official-SDK tool registrations and STDIO startup.
- Create `src/agentguardian/codex_integration.py`: bounded install, upgrade, rollback, and uninstall transactions.
- Modify `src/agentguardian/app.py`: import the shared service and retain the existing GUI behavior.
- Modify `src/agentguardian/share_verification.py`: expose syntax-only URL validation for prepare without DNS or network I/O.
- Modify `src/agentguardian/__main__.py`: provide the Qt-free source dispatch reused by the console helper and preserve exact GUI/maintenance and integration-mode dispatch.
- Modify `src/agentguardian/__init__.py`: set `0.3.0a1`.
- Modify `src/agentguardian/source_policy.json`: bind every reviewed runtime source byte.

### Skill and packaging

- Create `skills/agentguardian/SKILL.md`, `skills/agentguardian/README.md`, and `skills/agentguardian/LICENSE`: the only canonical Skill source files.
- Create `scripts/build_agentguardian_skill.py`: deterministic allowlisted ZIP and SHA-256 output.
- Create `packaging/windows/AgentGuardianIntegrationsPreview.spec`: one reviewed Analysis/PYZ/COLLECT onedir build with the exact windowed and console launchers.
- Create `packaging/windows/AgentGuardianIntegrationsPreview.iss`: distinct 0.3 installer identity, distinct install directory, and two unchecked integration tasks.
- Create `scripts/build_windows_integrations_preview_installer.py`: bounded new-identity installer builder.
- Create `scripts/verify_windows_integrations_preview.ps1`: native install, use, upgrade, uninstall, and residue evidence.
- Modify `scripts/build_windows_portable.py`: support the 0.3 profile, include Skill bytes, and inventory MCP runtime dependencies.
- Create `requirements-build.in`; modify `pyproject.toml`, `requirements-dev.lock`, and `requirements-build.lock`: exact SDK and transitive dependency locks.
- Modify `THIRD_PARTY_NOTICES.md`: MCP runtime and build dependency notices.

### Governance and evidence

- Create `release_profiles/integrations_preview.json`: independent 0.3 identity, exact dual-launcher payload, install directory, capability, ownership, and forbidden-feature contract.
- Create `scripts/verify_integrations_preview_profile.py`: bounded verifier for the new profile only.
- Create `.github/workflows/windows-integrations-preview.yml`: exact-SHA Windows build and lifecycle workflow.
- Create `docs/security/integrations-preview.md` and `docs/security/integrations-preview-status.json`: active 0.3 boundary and gate ledger.
- Modify `README.md`: make 0.3 the active development track while preserving the frozen 0.2 evidence statement.
- Modify `.gitattributes`: pin the new profile and status ledger to LF without changing frozen 0.2 entries.
- The approved design is corrected by this pre-execution documentation task; Tasks 2-8 must implement the three corrections above without reopening product scope.

### Tests

- Create `tests/test_audit_service.py`.
- Create `tests/test_mcp_service.py`.
- Create `tests/test_mcp_server.py`.
- Create `tests/test_agentguardian_skill.py`.
- Create `tests/test_codex_integration.py`.
- Create `tests/test_windows_integrations_preview_installer.py`.
- Create `tests/test_integrations_preview_profile.py`.
- Modify `tests/test_self_audit.py` in Tasks 2, 3, and 5 so the exact reviewed module counts become 22, 23, and 24.
- Modify `tests/test_evidence_state.py` only for the current 0.3 runtime product-version assertion.
- Modify `tests/test_personal_release_profile.py` only to preserve frozen 0.2 assertions while separating active 0.3 documentation and rejecting a 0.2 artifact build from 0.3 source.

## Phase 1: Shared Core And STDIO MCP

### Task 1: Extract The Qt-Free Audit Service

**Files:**
- Create: `src/agentguardian/audit_service.py`
- Create: `tests/test_audit_service.py`
- Modify: `src/agentguardian/app.py:188-205,474-538,696-883,907-916,1469-1587`
- Modify: `tests/test_app_smoke.py:101-108,4038-4065`
- Modify: `tests/test_self_audit.py:22-43,199-216`
- Modify: `src/agentguardian/source_policy.json`

- [ ] **Step 1: Write the failing headless-import and clipboard-parity tests**

Create `tests/test_audit_service.py` with these initial tests:

```python
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

from agentguardian.audit_service import run_clipboard_audit


PROJECT_ROOT = Path(__file__).parents[1]
DISPOSITION_KEY = b"d" * 32


def test_audit_service_import_does_not_import_qt() -> None:
    completed = subprocess.run(
        (
            sys.executable,
            "-c",
            "import sys; import agentguardian.audit_service; "
            "assert not any(name.startswith('PySide6') for name in sys.modules)",
        ),
        cwd=PROJECT_ROOT,
        env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT / "src")},
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_clipboard_service_builds_the_same_redacted_audit_outcome() -> None:
    result, outcome = run_clipboard_audit(
        lambda: "OPENAI_API_KEY=sk-proj-abcdefghijklmnop",
        disposition_key=DISPOSITION_KEY,
    )
    assert result.scanned is True
    assert result.raw_data_retained is False
    assert outcome is not None
    assert outcome.findings == result.findings
    assert outcome.score.coverage == 1.0
    assert outcome.report_json.find("sk-proj-abcdefghijklmnop") == -1
    assert outcome.report_html.find("sk-proj-abcdefghijklmnop") == -1
```

Add focused boundary tests proving that a non-`None` invalid `evaluated_at` is rejected with the fixed audit-context error before the reader is called, and that dispositions are consumed only through `_validated_disposition_context`'s `MAX_AUDIT_FINDINGS + 1` bounded read. Cover both an over-limit iterable and an iterable that raises an exception containing a private marker; neither the returned exception nor captured output may contain that marker.

- [ ] **Step 2: Verify RED**

Run:

```powershell
rtk proxy python -m pytest -q tests/test_audit_service.py -p no:cacheprovider
```

Expected: collection fails with `ModuleNotFoundError: No module named 'agentguardian.audit_service'`.

- [ ] **Step 3: Move the existing file audit without changing its behavior**

Move these exact existing definitions and their required non-Qt imports from `app.py` to `audit_service.py`: `_DispositionContext`, `AuditOutcome`, `_utc_now`, `_generate_key`, `_validated_disposition_context`, `_validated_evaluation_time`, `_validated_audit_preview`, `_is_unc_path`, `_read_limited_json`, `_append_finding_batch`, and `_run_audit`. Rename only `_run_audit` to `run_file_audit`; keep its body and signature otherwise unchanged.

Add this complete shared clipboard function after `run_file_audit`:

```python
def run_clipboard_audit(
    reader: Callable[[], str],
    *,
    disposition_key: bytes,
    dispositions: Iterable[DispositionRecord] = (),
    evaluated_at: datetime | None = None,
) -> tuple[ClipboardAuditResult, AuditOutcome | None]:
    evaluation_time = (
        _validated_evaluation_time(evaluated_at)
        if evaluated_at is not None
        else None
    )
    context = _validated_disposition_context(
        disposition_key,
        dispositions,
        max_records=MAX_AUDIT_FINDINGS,
    )
    result = audit_clipboard_once(
        reader,
        scan_key=_generate_key(),
        disposition_key=context.key,
    )
    if not result.scanned:
        return result, None
    if evaluation_time is None:
        evaluation_time = _validated_evaluation_time(_utc_now())
    audit_score = score(
        result.findings,
        coverage=1.0,
        confidence=1.0,
        limits=result.limits,
    )
    records = {record.disposition_ref: record for record in context.records}
    reviewed_score = score(
        reviewed_findings(result.findings, records, now=evaluation_time),
        coverage=1.0,
        confidence=1.0,
        limits=result.limits,
    )
    rule_version = load_rules().version
    outcome = AuditOutcome(
        findings=result.findings,
        score=audit_score,
        reviewed_score=reviewed_score,
        evaluated_at=evaluation_time,
        rule_version=rule_version,
        report_json=render_json(
            audit_score,
            result.findings,
            rule_version=rule_version,
            reviewed_score=reviewed_score,
            dispositions=context.records,
            evaluated_at=evaluation_time,
        ),
        report_html=render_html(
            audit_score,
            result.findings,
            rule_version=rule_version,
            reviewed_score=reviewed_score,
            dispositions=context.records,
            evaluated_at=evaluation_time,
        ),
        scanned_roots=(),
    )
    return result, outcome
```

Import the moved names into `app.py` so current internal callers and monkeypatch-based acceptance tests keep their names:

```python
from .audit_service import (
    AuditOutcome,
    _generate_key,
    _read_limited_json,
    _validated_disposition_context,
    _validated_evaluation_time,
    _validated_audit_preview,
    run_clipboard_audit,
    run_file_audit as _run_audit,
)
```

Replace the duplicated clipboard scoring/report block with:

```python
result, outcome = run_clipboard_audit(
    lambda: QApplication.clipboard().text(),
    disposition_key=self._disposition_key,
    dispositions=self._dispositions,
)
if not result.scanned or outcome is None:
    self._invalidate_report()
    self.status_label.setText("剪贴板检查未执行。")
    self.coverage_status_label.setText(
        "剪贴板内容未进入审计；未生成报告。"
    )
    return
self._scan_completed(outcome)
self.status_label.setText(
    f"剪贴板一次性审计完成：发现 {len(result.findings)} 项。"
)
self.coverage_status_label.setText(
    "剪贴板仅在本次点击中读取一次；报告不包含剪贴板原文。"
)
```

Add GUI regression assertions for both the no-scan text above and the exact successful clipboard status/privacy text. The shared `_scan_completed` call must still retain the report before the clipboard-specific labels are restored.

Before `verify_public_share` is called in `_verify_share`, add a default-No `QMessageBox.question` that states this is public network I/O, sends no local scan data or credentials, may place redacted metadata in the Codex context when invoked through MCP, and is unsupported for regulated or highly sensitive real data. Cancellation must return before DNS or network access. Add a GUI test that chooses No and asserts the share verifier was never called, plus a Yes test that asserts exactly one call. Keep the existing browser and clipboard default-No consent dialogs and the file-scope consent controls.

Update the one `_read_limited_json` monkeypatch in `tests/test_app_smoke.py` to patch `agentguardian.audit_service._read_limited_json`, because `run_file_audit` now resolves that module global.

Update `EXPECTED_REVIEWED_SOURCE_MODULES` in `tests/test_self_audit.py` to include `audit_service.py` in sorted order and change both exact module-count assertions from `20` to `21`. This is the required source-policy contract update for the newly reviewed runtime module.

- [ ] **Step 4: Bind the reviewed source set and verify GREEN**

Compute SHA-256 for every `src/agentguardian/*.py`, update `source_policy.json` with the sorted exact module set, then run:

```powershell
rtk proxy python -m pytest -q tests/test_audit_service.py tests/test_app_smoke.py tests/test_personal_privacy_acceptance.py -p no:cacheprovider
rtk proxy python -m pytest -q tests/test_self_audit.py -p no:cacheprovider
rtk proxy python -m compileall -q src tests
rtk git diff --check
```

Expected: all selected tests pass, compileall returns zero, and `git diff --check` prints nothing.

- [ ] **Step 5: Commit Task 1 locally**

```powershell
rtk git add src/agentguardian/audit_service.py src/agentguardian/app.py src/agentguardian/source_policy.json tests/test_audit_service.py tests/test_app_smoke.py tests/test_self_audit.py
rtk git commit -m "Extract shared headless audit service"
```

### Task 2: Add One-Shot Authorization And Redacted Results

**Files:**
- Create: `src/agentguardian/mcp_service.py`
- Create: `tests/test_mcp_service.py`
- Modify: `src/agentguardian/share_verification.py:52-72,160-170,267-294`
- Modify: `tests/test_share_verification.py`
- Modify: `tests/test_self_audit.py:22-44,200-218`
- Modify: `src/agentguardian/source_policy.json`

- [ ] **Step 1: Expose syntax-only public-share validation with a regression test**

Rename the public validator to the exact signature `validate_public_share_url(url: str, allow_private_hosts: bool = False) -> tuple[str, str]`, rename both existing `_validated_url` callers in `verify_public_share` and `_PolicyRedirectHandler.redirect_request`, preserve the existing validated implementation body, and remove the private name.

The default is syntax-only public-host validation for MCP prepare. The existing explicit `allow_private_hosts` test seam remains available to the two reviewed callers. Add:

```python
def test_validate_public_share_url_performs_no_dns_or_network(monkeypatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("dns")))
    request_url, address = validate_public_share_url("https://example.com/path")
    assert request_url == "https://example.com/path"
    assert address == "https://example.com"
```

Run:

```powershell
rtk proxy python -m pytest -q tests/test_share_verification.py -p no:cacheprovider
```

Expected: PASS and no network request.

- [ ] **Step 2: Write failing authorization tests**

Create `tests/test_mcp_service.py` around an injected clock and injected operation functions. Include these exact cases:

```python
import json
from pathlib import Path

import pytest

from agentguardian.mcp_service import AuditMcpService


def _prepare_files(service: AuditMcpService, root: Path) -> dict[str, object]:
    return service.prepare_audit(
        operation="files",
        classification="personal_non_regulated",
        roots=[str(root)],
    )


def test_prepare_does_not_read_and_replaces_the_previous_authorization(tmp_path: Path) -> None:
    reads: list[str] = []
    service = AuditMcpService(
        monotonic=lambda: 10.0,
        token_factory=iter(("first", "second")).__next__,
        file_runner=lambda *_args, **_kwargs: reads.append("files"),
    )
    first = _prepare_files(service, tmp_path / "first")
    second = _prepare_files(service, tmp_path / "second")
    assert reads == []
    rejected = service.run_prepared_audit(
        authorization_id=first["authorization_id"],
        scope_digest=first["scope_digest"],
        consent_summary=first["consent_summary"],
    )
    assert rejected["code"] == "AUTHORIZATION_INVALID"
    assert second["authorization_id"] == "second"


@pytest.mark.parametrize(
    "mutation",
    ("missing", "expired", "reused", "digest", "summary"),
)
def test_rejected_run_never_accesses_content(tmp_path: Path, mutation: str) -> None:
    now = [10.0]
    reads: list[str] = []
    service = AuditMcpService(
        monotonic=lambda: now[0],
        token_factory=lambda: "authorization",
        file_runner=lambda *_args, **_kwargs: reads.append("files"),
    )
    prepared = _prepare_files(service, tmp_path / "scope")
    if mutation == "missing":
        service = AuditMcpService(file_runner=lambda *_args, **_kwargs: reads.append("files"))
    if mutation == "expired":
        now[0] = 311.0
    authorization_id = prepared["authorization_id"]
    scope_digest = prepared["scope_digest"]
    consent_summary = prepared["consent_summary"]
    if mutation == "digest":
        scope_digest = "0" * 64
    if mutation == "summary":
        consent_summary = "changed"
    first = service.run_prepared_audit(
        authorization_id=authorization_id,
        scope_digest=scope_digest,
        consent_summary=consent_summary,
    )
    if mutation == "reused":
        first = service.run_prepared_audit(
            authorization_id=authorization_id,
            scope_digest=scope_digest,
            consent_summary=consent_summary,
        )
    assert first["status"] == "failed"
    assert reads == ([] if mutation != "reused" else ["files"])


def test_results_are_bounded_and_exclude_raw_values(tmp_path: Path) -> None:
    raw = "sk-proj-super-secret-value"
    service = AuditMcpService(clipboard_reader=lambda: raw)
    prepared = service.prepare_audit(
        operation="clipboard",
        classification="personal_non_regulated",
    )
    result = service.run_prepared_audit(
        authorization_id=prepared["authorization_id"],
        scope_digest=prepared["scope_digest"],
        consent_summary=prepared["consent_summary"],
    )
    encoded = json.dumps(result, sort_keys=True).encode("utf-8")
    assert len(encoded) <= 64 * 1024
    assert raw.encode() not in encoded
    assert "report_html" not in result
    assert "report_json" not in result
```

Add separate tests for all four operations, exact classification, maximum 32 file roots, prepare response `<= 16 KiB`, run response `<= 64 KiB`, at most 100 findings and 200 evidence records, failure-code sanitization, consumption before the operation callback, browser cleanup failure, and no public-share fallback. For each operation, compare the MCP structured fields with the same synthetic input passed directly to `run_file_audit`, `audit_browser_database`, `run_clipboard_audit`, or `verify_public_share`; require equal rule/severity sets, scores, limits, aggregate counts, and reachability metadata after excluding presentation-only fields.

Add two clipboard-boundary tests. Importing `mcp_service.py` and calling clipboard `prepare_audit` must leave every `PySide6` module absent from `sys.modules`. An accepted clipboard run whose lazy Qt adapter cannot import or initialize clipboard access must return fixed code `CLIPBOARD_UNAVAILABLE`; its serialized result and captured output must contain no native exception, Qt error, path, environment value, or clipboard value.

- [ ] **Step 3: Verify RED**

Run:

```powershell
rtk proxy python -m pytest -q tests/test_mcp_service.py -p no:cacheprovider
```

Expected: collection fails because `agentguardian.mcp_service` does not exist.

- [ ] **Step 4: Implement the minimal service contract**

Create `mcp_service.py` with these fixed public constants and signatures:

```python
CLASSIFICATION = "personal_non_regulated"
OPERATIONS = frozenset({"files", "browser", "clipboard", "public_share"})
AUTHORIZATION_TTL_SECONDS = 300.0
MAX_PREPARE_BYTES = 16 * 1024
MAX_RUN_BYTES = 64 * 1024
MAX_ROOTS = 32
MAX_RESULT_FINDINGS = 100
MAX_RESULT_EVIDENCE = 200


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
        self._clipboard_reader = clipboard_reader or _qt_clipboard_text
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
            expires = self._utc_now().replace(microsecond=0) + timedelta(seconds=300)
            pending = _PendingAuthorization(
                self._token_factory(),
                digest,
                summary,
                self._monotonic() + AUTHORIZATION_TTL_SECONDS,
                expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
                request,
            )
            response = _prepare_response(pending)
            if len(_canonical_bytes(response)) > MAX_PREPARE_BYTES:
                raise ValueError("PREPARE_RESULT_LIMIT")
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
            or not hmac.compare_digest(authorization_id, pending.authorization_id)
            or not hmac.compare_digest(scope_digest, pending.scope_digest)
            or not hmac.compare_digest(consent_summary, pending.consent_summary)
        ):
            return _fixed_failure("AUTHORIZATION_INVALID")
        if self._monotonic() > pending.expires_monotonic:
            return _fixed_failure("AUTHORIZATION_EXPIRED")
        try:
            return _bounded_run_response(self._execute(pending.request))
        except Exception as error:
            return _fixed_failure(_allowed_run_code(error))
```

Implement `_normalize_request` as one exact-field branch per operation. It must call `build_scope_preview` for file roots, use `PureWindowsPath` shape checks for the browser path without touching the file, call `validate_public_share_url` for URL syntax only, reject extra operation fields, and reject every classification except `personal_non_regulated`.

Define `_qt_clipboard_text` in `mcp_service.py` as the default clipboard adapter. It must import `QApplication` inside the function, lazily obtain or initialize the Qt application and clipboard only when an already accepted clipboard request reaches `_execute`, read text once, and translate import, initialization, or clipboard-access failure to one internal exception. `_allowed_run_code` maps only that exception to `CLIPBOARD_UNAVAILABLE`. Module import and every prepare path remain Qt-free.

Implement `_execute` with exactly these existing functions: `run_file_audit`, `audit_browser_database`, `run_clipboard_audit`, and `verify_public_share`. Generate the file/clipboard disposition key with `secrets.token_bytes(32)`. Do not catch and retry a public-share operation.

Implement result conversion with these allowed finding fields only:

```python
{
    "rule_id": finding.rule_id,
    "severity": finding.severity.value,
    "risk_domain": finding.domain.value,
    "asset_ref": finding.root_fingerprint,
    "evidence": [
        {"fingerprint": item.fingerprint, "masked": item.masked}
        for item in finding.evidence
    ],
    "manual_guidance": list(
        guidance_for(finding.rule_id, finding.root_fingerprint).steps
    ),
}
```

Never serialize `Evidence.source`, `AuditOutcome.report_json`, `AuditOutcome.report_html`, a native exception, an environment value, clipboard text, browser URLs, or an HTTP body. `_bounded_run_response` must mark `truncated=true` and remove trailing evidence/findings until canonical UTF-8 JSON is at most 64 KiB; the bounded loop has at most 200 evidence entries.

- [ ] **Step 5: Verify authorization, privacy, and source policy**

Add `mcp_service.py` to `EXPECTED_REVIEWED_SOURCE_MODULES` in sorted order and change both exact count assertions in `tests/test_self_audit.py` from `21` to `22`. Update `source_policy.json`, then run:

```powershell
rtk proxy python -m pytest -q tests/test_mcp_service.py tests/test_share_verification.py tests/test_audit_service.py tests/test_self_audit.py -p no:cacheprovider
rtk proxy python -m compileall -q src tests
rtk git diff --check
```

Expected: PASS, no raw test secret in captured output, and no diff whitespace errors.

- [ ] **Step 6: Commit Task 2 locally**

```powershell
rtk git add src/agentguardian/mcp_service.py src/agentguardian/share_verification.py src/agentguardian/source_policy.json tests/test_mcp_service.py tests/test_share_verification.py tests/test_self_audit.py
rtk git commit -m "Add bounded MCP audit authorization"
```

### Task 3: Add The Official SDK, Locks, STDIO Server, And Dispatch

**Files:**
- Create: `requirements-build.in`
- Create: `src/agentguardian/mcp_server.py`
- Create: `tests/test_mcp_server.py`
- Modify: `pyproject.toml`
- Modify: `requirements-dev.lock`
- Modify: `requirements-build.lock`
- Modify: `src/agentguardian/__init__.py`
- Modify: `src/agentguardian/__main__.py`
- Modify: `scripts/build_windows_portable.py`
- Modify: `THIRD_PARTY_NOTICES.md`
- Modify: `tests/test_windows_packaging.py`
- Modify: `tests/test_reporting.py`
- Modify: `tests/test_evidence_state.py`
- Modify: `tests/test_personal_release_profile.py`
- Modify: `tests/test_self_audit.py:22-45,200-218`
- Modify: `src/agentguardian/source_policy.json`

- [ ] **Step 1: Write the failing SDK and dispatch tests**

Create `tests/test_mcp_server.py`:

```python
import sys

import pytest
from mcp import Client

from agentguardian import __version__
from agentguardian.mcp_server import server


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_server_exposes_exactly_two_tools() -> None:
    async with Client(server, raise_exceptions=True) as client:
        tools = await client.list_tools()
    assert [tool.name for tool in tools.tools] == [
        "prepare_audit",
        "run_prepared_audit",
    ]


@pytest.mark.anyio
async def test_prepare_returns_structured_content_without_qt() -> None:
    assert __version__ == "0.3.0a1"
    async with Client(server, raise_exceptions=True) as client:
        result = await client.call_tool(
            "prepare_audit",
            {
                "operation": "clipboard",
                "classification": "personal_non_regulated",
            },
        )
    assert result.is_error is False
    assert result.structured_content["status"] == "prepared"
    assert not any(name.startswith("PySide6") for name in sys.modules)
```

Add a source-dispatch test that injects a fake `agentguardian.mcp_server.run_stdio`, calls `agentguardian.__main__.main(["--stdio-mcp"])`, and asserts that `agentguardian.app` and `PySide6` are absent from `sys.modules`. Add a mixed-argument test that returns fixed exit code `64` without starting either entry point. This source dispatch is reused by the Task 6 console helper; it is not evidence that the windowed launcher is the installed STDIO command.

- [ ] **Step 2: Verify dependency RED**

Run:

```powershell
rtk proxy python -m pytest -q tests/test_mcp_server.py -p no:cacheprovider
```

Expected: collection fails because `mcp` and `agentguardian.mcp_server` are not installed.

- [ ] **Step 3: Pin the runtime and regenerate both hashed locks**

Set the project identity and runtime dependency exactly:

```toml
[project]
name = "agentguardian"
version = "0.3.0a1"
requires-python = ">=3.12"
dependencies = [
    "PySide6>=6.8,<7",
    "mcp==2.0.0",
]
```

Create `requirements-build.in`:

```text
cyclonedx-python-lib==11.12.0
pyinstaller==6.16.0
pyinstaller-hooks-contrib==2025.9
```

Regenerate without upgrading existing constrained packages:

```powershell
rtk proxy uv pip compile pyproject.toml --extra dev --python-version 3.12 --python-platform x86_64-pc-windows-msvc --only-binary :all: --generate-hashes --no-annotate --custom-compile-command "uv 0.11.28 pip compile pyproject.toml --extra dev --python-version 3.12 --python-platform x86_64-pc-windows-msvc --only-binary :all: --generate-hashes --no-annotate" --output-file requirements-dev.lock
rtk proxy uv pip compile pyproject.toml requirements-build.in --python-version 3.12 --python-platform x86_64-pc-windows-msvc --only-binary :all: --generate-hashes --no-annotate --custom-compile-command "uv 0.11.28 pip compile pyproject.toml requirements-build.in --python-version 3.12 --python-platform x86_64-pc-windows-msvc --only-binary :all: --generate-hashes --no-annotate" --output-file requirements-build.lock
py -3.12 -m pip install --dry-run --require-hashes -r requirements-dev.lock
py -3.12 -m pip install --dry-run --require-hashes -r requirements-build.lock
```

Expected: both dry runs return zero; `mcp==2.0.0` and every transitive requirement have hashes; no `mcp[cli]`, VCS URL, editable requirement, or index URL exists.

Create an ignored exact-lock environment for all remaining plan commands:

```powershell
py -3.12 -m venv .analysis\venv-0.3
.analysis\venv-0.3\Scripts\python.exe -m pip install --require-hashes -r requirements-dev.lock -r requirements-build.lock
.analysis\venv-0.3\Scripts\python.exe -m pip check
```

- [ ] **Step 4: Implement the two-tool official-SDK server**

Create `mcp_server.py`:

```python
from __future__ import annotations

from mcp.server import MCPServer

from . import __version__
from .mcp_service import AuditMcpService


_INSTRUCTIONS = (
    "AgentGuardian supports personal, non-regulated data only. "
    "Call prepare_audit first, show consent_summary verbatim, then request "
    "run_prepared_audit. Never describe incomplete or truncated output as safe."
)
_service = AuditMcpService()
server = MCPServer("AgentGuardian", version=__version__, instructions=_INSTRUCTIONS)


@server.tool()
def prepare_audit(
    operation: str,
    classification: str,
    roots: list[str] | None = None,
    browser_kind: str | None = None,
    database_path: str | None = None,
    url: str | None = None,
) -> dict[str, object]:
    """Prepare one bounded local audit without reading content or using the network."""
    return _service.prepare_audit(
        operation=operation,
        classification=classification,
        roots=roots,
        browser_kind=browser_kind,
        database_path=database_path,
        url=url,
    )


@server.tool()
def run_prepared_audit(
    authorization_id: str,
    scope_digest: str,
    consent_summary: str,
) -> dict[str, object]:
    """Consume one prepared authorization and return a bounded redacted result."""
    return _service.run_prepared_audit(
        authorization_id=authorization_id,
        scope_digest=scope_digest,
        consent_summary=consent_summary,
    )


def run_stdio() -> int:
    server.run()
    return 0
```

Replace `__main__.py` with a guarded dispatcher that imports no Qt before selection:

```python
from __future__ import annotations

import sys


USAGE_ERROR = 64


def main(arguments: list[str] | None = None) -> int:
    selected = list(sys.argv[1:] if arguments is None else arguments)
    if selected == ["--stdio-mcp"]:
        from agentguardian.mcp_server import run_stdio

        return run_stdio()
    if "--stdio-mcp" in selected:
        return USAGE_ERROR
    from agentguardian.app import main as run_gui

    return run_gui()


if __name__ == "__main__":
    raise SystemExit(main())
```

The only production startup call is `server.run()` with no transport argument; the official SDK defines that as STDIO. Do not import or call its HTTP/SSE application builders. Task 6 packages this source dispatch behind console-enabled `AgentGuardianMcp.exe`; windowed `AgentGuardian.exe` remains the GUI/maintenance launcher and is not configured as STDIO.

- [ ] **Step 5: Inventory SDK dependencies in notices and SBOM**

Extend `portable_component_specs` with the exact 34-package runtime closure resolved from `PySide6` plus `mcp==2.0.0`. Use reviewed SPDX expressions and `NOASSERTION` only when wheel metadata has no reviewed expression. Add tests that every runtime package name from the build lock appears in the CycloneDX components and `THIRD_PARTY_NOTICES.md`, while PyInstaller remains build-time and its bootloader remains runtime.

Keep this explicit boundary in the notice:

```markdown
The MCP Python SDK distribution contains optional HTTP transport modules in its
dependency graph. AgentGuardian 0.3 registers and starts only STDIO; the
presence of dependency code is not evidence that AgentGuardian exposes a
listener. License and redistribution review remains a release gate.
```

Update current-version assertions in `tests/test_reporting.py` and the current runtime `product_version` assertion in `tests/test_evidence_state.py` to `0.3.0a1`. Keep every frozen profile field, historical 0.2 version, path, artifact, and document assertion in `tests/test_personal_release_profile.py` exact; remove only any assumption that the current branch package itself must still be 0.2. The historical verifier and profile must remain independently verifiable. Task 6 adds a separate build-time identity guard that makes selection of the personal 0.2 artifact profile fail closed against a 0.3 package/source tree.

Add `mcp_server.py` to `EXPECTED_REVIEWED_SOURCE_MODULES` in sorted order and change both exact count assertions in `tests/test_self_audit.py` from `22` to `23`.

- [ ] **Step 6: Install the exact lock and verify GREEN**

Update `source_policy.json`, then run:

```powershell
.analysis\venv-0.3\Scripts\python.exe -m pytest -q tests/test_mcp_server.py tests/test_mcp_service.py tests/test_windows_packaging.py tests/test_reporting.py tests/test_evidence_state.py tests/test_personal_release_profile.py tests/test_self_audit.py -p no:cacheprovider
.analysis\venv-0.3\Scripts\python.exe -m compileall -q src scripts tests
rtk git diff --check
```

Expected: PASS; the tool list is exactly two; no Qt import occurs in prepare or STDIO dispatch tests.

- [ ] **Step 7: Commit Task 3 locally**

```powershell
rtk git add pyproject.toml requirements-build.in requirements-dev.lock requirements-build.lock THIRD_PARTY_NOTICES.md src/agentguardian/__init__.py src/agentguardian/__main__.py src/agentguardian/mcp_server.py src/agentguardian/source_policy.json scripts/build_windows_portable.py tests/test_mcp_server.py tests/test_windows_packaging.py tests/test_reporting.py tests/test_evidence_state.py tests/test_personal_release_profile.py tests/test_self_audit.py
rtk git commit -m "Add official STDIO MCP entry point"
```

## Phase 2: Standalone Skill And Transactional Windows Integration

### Task 4: Build The Independent Canonical Skill Package

**Files:**
- Create: `skills/agentguardian/SKILL.md`
- Create: `skills/agentguardian/README.md`
- Create: `skills/agentguardian/LICENSE`
- Create: `scripts/build_agentguardian_skill.py`
- Create: `tests/test_agentguardian_skill.py`

The pre-execution compatibility correction already fixes the canonical target at `%USERPROFILE%\.agents\skills\agentguardian`. Task 4 consumes that target and must not add a second copy or edit the approved design.

- [ ] **Step 1: Write failing package tests**

Create tests that require:

```python
EXPECTED_ENTRIES = (
    "agentguardian/LICENSE",
    "agentguardian/README.md",
    "agentguardian/SKILL.md",
)


def test_skill_zip_is_allowlisted_and_deterministic(tmp_path: Path) -> None:
    first, first_digest = build_skill(PROJECT_ROOT / "skills" / "agentguardian", tmp_path / "one")
    second, second_digest = build_skill(PROJECT_ROOT / "skills" / "agentguardian", tmp_path / "two")
    assert first.read_bytes() == second.read_bytes()
    assert first_digest == second_digest == hashlib.sha256(first.read_bytes()).hexdigest()
    with zipfile.ZipFile(first) as archive:
        assert tuple(sorted(archive.namelist())) == EXPECTED_ENTRIES
```

Add negative tests for an extra file, dotfile, link/reparse entry, executable extension, frontmatter mismatch, embedded secret pattern, non-ASCII ZIP path, oversized file, and root `LICENSE` byte mismatch.

- [ ] **Step 2: Verify RED**

Run:

```powershell
.analysis\venv-0.3\Scripts\python.exe -m pytest -q tests/test_agentguardian_skill.py -p no:cacheprovider
```

Expected: collection fails because the build module and Skill source do not exist.

- [ ] **Step 3: Create the instruction-only Skill**

Create `SKILL.md` with this exact frontmatter and workflow:

```markdown
---
name: agentguardian
description: Use AgentGuardian to audit one bounded local AI configuration scope, browser history database aggregate, current clipboard value, or public share URL. Requires the local AgentGuardian MCP tools and must not be used for regulated or highly sensitive data.
metadata:
  version: "0.1.0"
  requires-agentguardian: ">=0.3.0a1,<0.4"
---

# AgentGuardian

1. Confirm that `prepare_audit` and `run_prepared_audit` are available from the AgentGuardian MCP server. If either is absent, state that AgentGuardian 0.3 Integrations Preview and its local MCP integration must be installed, then stop. Do not substitute shell commands or read the target data yourself.
2. Ask for exactly one operation: `files`, `browser`, `clipboard`, or `public_share`. Collect only that operation's minimum scope.
3. Require the user to classify the data as `personal_non_regulated`. If the user identifies medical, financial, identity, biometric, legally privileged, customer-dataset, national-secret, regulated, or equivalent highly sensitive real data, stop without calling a tool.
4. Call `prepare_audit`. Do not claim that prepare read content, inspected the clipboard, copied a database, resolved DNS, used the network, or produced a safety score.
5. Show `consent_summary` verbatim. Explain that redacted arguments and results may enter the Codex model context and that incomplete or truncated coverage cannot establish safety.
6. Request `run_prepared_audit` only after the user chooses to continue. Pass the returned authorization identifier, scope digest, and consent summary unchanged. The Codex host approval prompt is the required human approval boundary.
7. Never reuse, repair, guess, or hide a rejected authorization. Start again with prepare after any rejection or expiry.
8. Report fixed limitations and truncation. Never restate a result as proof that an agent, account, MCP server, browser, share, or system is safe.
9. Do not call an OpenAI or other Provider API on AgentGuardian's behalf. Provider findings receive local manual guidance only.
```

Create `README.md` containing the independent Skill version, Apache-2.0 status, AgentGuardian runtime range, `%USERPROFILE%\.agents\skills\agentguardian` manual target, two required MCP tool names, Codex model-context disclosure, personal non-regulated boundary, unsupported-data list, and no-production-safety statement. Copy the root `LICENSE` bytes exactly to `skills/agentguardian/LICENSE`.

- [ ] **Step 4: Implement deterministic packaging**

`build_agentguardian_skill.py` must export:

```python
SKILL_VERSION = "0.1.0"
ALLOWED_FILES = ("LICENSE", "README.md", "SKILL.md")
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


def build_skill(source_root: Path, output_root: Path) -> tuple[Path, str]:
    source = _validated_source(source_root)
    output = _new_local_output(output_root)
    target = output / f"AgentGuardian-Skill-{SKILL_VERSION}.zip"
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in ALLOWED_FILES:
            data = (source / name).read_bytes()
            info = zipfile.ZipInfo(f"agentguardian/{name}", ZIP_TIMESTAMP)
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    (output / f"{target.name}.sha256").write_text(
        f"{digest} *{target.name}\n", encoding="ascii", newline="\n"
    )
    return target, digest
```

The validators must use `os.lstat`, reject links/reparse points and unexpected files, enforce 256 KiB per file and 512 KiB aggregate, parse the exact frontmatter fields, require root/Skill `LICENSE` equality, and scan bytes for the existing secret-pattern families plus executable headers (`MZ`, ELF, Mach-O), downloader commands, and NUL bytes.

- [ ] **Step 5: Verify and commit Task 4**

```powershell
.analysis\venv-0.3\Scripts\python.exe -m pytest -q tests/test_agentguardian_skill.py -p no:cacheprovider
.analysis\venv-0.3\Scripts\python.exe scripts/build_agentguardian_skill.py --output-root .analysis\skill-build-one
.analysis\venv-0.3\Scripts\python.exe scripts/build_agentguardian_skill.py --output-root .analysis\skill-build-two
rtk proxy powershell -NoProfile -Command "if ((Get-FileHash -Algorithm SHA256 -LiteralPath '.analysis\skill-build-one\AgentGuardian-Skill-0.1.0.zip').Hash -cne (Get-FileHash -Algorithm SHA256 -LiteralPath '.analysis\skill-build-two\AgentGuardian-Skill-0.1.0.zip').Hash) { throw 'Skill ZIP mismatch' }"
rtk git diff --check
rtk git add skills/agentguardian/SKILL.md skills/agentguardian/README.md skills/agentguardian/LICENSE scripts/build_agentguardian_skill.py tests/test_agentguardian_skill.py
rtk git commit -m "Add standalone AgentGuardian Codex Skill"
```

Expected: all tests pass and both ZIP hashes match.

### Task 5: Implement Transactional Codex Integration Ownership

**Files:**
- Create: `src/agentguardian/codex_integration.py`
- Create: `tests/test_codex_integration.py`
- Modify: `src/agentguardian/__main__.py`
- Modify: `src/agentguardian/source_policy.json`
- Modify: `tests/test_self_audit.py:22-46,200-218`
- Test unchanged: `tests/test_app_smoke.py:6101-6189`

- [ ] **Step 1: Write failing config, rollback, upgrade, and uninstall tests**

Create fixtures under a temporary absolute local directory and inject `protect`/`unprotect` callbacks. Require these constants:

```python
CONFIG_RELATIVE = Path(".codex/config.toml")
SKILL_RELATIVE = Path(".agents/skills/agentguardian")
BACKUP_RELATIVE = Path("AgentGuardian/codex-config-backup-v1.bin")
MANIFEST_RELATIVE = Path("AgentGuardian/codex-integration-v1.json")
CONFIG_LIMIT = 512 * 1024
MANIFEST_LIMIT = 64 * 1024
```

Test all four task selections: neither, Skill only, MCP only, both. Add exact tests for pre-existing foreign `mcp_servers.agentguardian`, duplicate markers, malformed/oversized TOML, UNC/reparse paths, DPAPI failure, temporary-write failure, post-replace manifest failure with exact rollback, missing-original rollback, unmanaged Skill conflict, managed upgrade, modified Skill preservation, unknown-file preservation, marker-conflict uninstall, exact-block removal with later user edits preserved, idempotent no-integration uninstall, and encrypted-backup retention on cleanup failure.

Use an installed preview directory fixture containing sibling launchers `AgentGuardian.exe` and `AgentGuardianMcp.exe`. Pass the latter as `installed_mcp_executable`; reject a missing helper, a wrong launcher name, a non-sibling path, or a reparse/UNC path. Add a focused upgrade test that records prior config, Skill, encrypted-backup, and manifest bytes, forces `_discard_superseded_backup` to fail after the new manifest commits, and requires exact restoration of all four prior states plus fixed code `INTEGRATION_BACKUP_DISCARD_FAILED` with no native error text.

The key config assertion is:

```python
parsed = tomllib.loads(config_path.read_text(encoding="utf-8"))
server = parsed["mcp_servers"]["agentguardian"]
assert server["command"] == str(installed_mcp_executable)
assert server["args"] == ["--stdio-mcp"]
assert server["enabled"] is True
assert server["enabled_tools"] == ["prepare_audit", "run_prepared_audit"]
assert server["default_tools_approval_mode"] == "prompt"
assert server["tools"]["prepare_audit"]["approval_mode"] == "auto"
assert server["tools"]["run_prepared_audit"]["approval_mode"] == "prompt"
```

- [ ] **Step 2: Verify RED**

```powershell
.analysis\venv-0.3\Scripts\python.exe -m pytest -q tests/test_codex_integration.py -p no:cacheprovider
```

Expected: collection fails because `agentguardian.codex_integration` does not exist.

- [ ] **Step 3: Implement the fixed managed block and encrypted backup envelope**

Use these exact markers and shape:

```python
BEGIN_MARKER = "# >>> AgentGuardian managed Codex integration v1 >>>"
END_MARKER = "# <<< AgentGuardian managed Codex integration v1 <<<"


def _managed_block(mcp_executable: Path) -> bytes:
    command = json.dumps(os.fspath(mcp_executable), ensure_ascii=True)
    return (
        f"{BEGIN_MARKER}\n"
        "[mcp_servers.agentguardian]\n"
        f"command = {command}\n"
        'args = ["--stdio-mcp"]\n'
        "enabled = true\n"
        'enabled_tools = ["prepare_audit", "run_prepared_audit"]\n'
        'default_tools_approval_mode = "prompt"\n\n'
        "[mcp_servers.agentguardian.tools.prepare_audit]\n"
        'approval_mode = "auto"\n\n'
        "[mcp_servers.agentguardian.tools.run_prepared_audit]\n"
        'approval_mode = "prompt"\n'
        f"{END_MARKER}\n"
    ).encode("utf-8")


def _backup_envelope(original: bytes, existed: bool) -> bytes:
    value = {
        "content_b64": base64.b64encode(original).decode("ascii"),
        "existed": existed,
        "schema": 1,
        "sha256": hashlib.sha256(original).hexdigest(),
    }
    return b"AG-CODEX-BACKUP-V1\n" + _canonical_json_bytes(value)
```

Validate original and candidate TOML with stdlib `tomllib`. The executable parameter is the validated installed `AgentGuardianMcp.exe` sibling, never the windowed GUI launcher. When `mcp_executable` is `None`, resolve only `Path(sys.executable).with_name("AgentGuardianMcp.exe")`; development tests pass an explicit temporary sibling. Back up before replacement with `windows_dpapi.protect_bytes`, write backup and manifest through same-directory `xb` temporary files with `flush`, `os.fsync`, path/reparse revalidation, and `os.replace`. The manifest stores schema, integration version, booleans, config-before hash, managed-block hash, and Skill relative-path/hash pairs only. It stores no config or Skill content.

- [ ] **Step 4: Implement bounded install, upgrade, and uninstall entry functions**

Expose only:

```python
def install_integration(
    *,
    install_skill: bool,
    enable_mcp: bool,
    mcp_executable: Path | None = None,
    environ: Mapping[str, str] = os.environ,
    protect: Callable[[bytes], bytes] = protect_bytes,
) -> str:
    if type(install_skill) is not bool or type(enable_mcp) is not bool:
        return "INTEGRATION_INPUT_INVALID"
    if not install_skill and not enable_mcp:
        return "INTEGRATION_INPUT_INVALID"
    transaction: _InstallTransaction | None = None
    try:
        transaction = _prepare_install_transaction(
            install_skill=install_skill,
            enable_mcp=enable_mcp,
            mcp_executable=mcp_executable,
            environ=environ,
        )
        if enable_mcp:
            _install_managed_mcp(transaction, protect=protect)
        if install_skill:
            _install_managed_skill(transaction)
        _commit_ownership_manifest(transaction)
        _discard_superseded_backup(transaction)
        return "INTEGRATION_INSTALLED"
    except IntegrationError as error:
        if transaction is not None and not _rollback_install(transaction):
            return "INTEGRATION_ROLLBACK_FAILED"
        return error.code
    except Exception:
        if transaction is not None and not _rollback_install(transaction):
            return "INTEGRATION_ROLLBACK_FAILED"
        return "INTEGRATION_INSTALL_FAILED"


def uninstall_integration(
    *,
    environ: Mapping[str, str] = os.environ,
    unprotect: Callable[[bytes], bytes] = unprotect_bytes,
) -> str:
    try:
        transaction = _prepare_uninstall_transaction(environ=environ)
    except IntegrationNotPresent:
        return "INTEGRATION_NOT_PRESENT"
    except IntegrationError as error:
        return error.code
    try:
        _remove_managed_mcp(transaction, unprotect=unprotect)
        skill_clean = _remove_unchanged_skill_files(transaction)
        if not skill_clean:
            return "INTEGRATION_CLEANUP_REQUIRED"
        _remove_recovery_and_manifest(transaction)
        return "INTEGRATION_REMOVED"
    except IntegrationError as error:
        return error.code
    except Exception:
        return "INTEGRATION_CLEANUP_REQUIRED"
```

Define `_InstallTransaction` and `_UninstallTransaction` as frozen, `repr=False` holders for validated paths and in-memory original bytes. `_prepare_install_transaction` validates ownership before writing and snapshots exact config, Skill, encrypted-backup, and manifest states for rollback. `_install_managed_mcp`, `_install_managed_skill`, `_commit_ownership_manifest`, `_discard_superseded_backup`, `_rollback_install`, `_prepare_uninstall_transaction`, `_remove_managed_mcp`, `_remove_unchanged_skill_files`, and `_remove_recovery_and_manifest` each perform the single operation named and raise only `IntegrationError(code)` with a fixed allowlisted code.

`_discard_superseded_backup` runs only after the new ownership manifest commits and removes only the superseded backup path recorded by that transaction. Any discard failure raises `INTEGRATION_BACKUP_DISCARD_FAILED`; install then performs exact rollback of the prior config, Skill, backup, and manifest. If that rollback itself fails, return `INTEGRATION_ROLLBACK_FAILED` and retain recovery material.

Return only fixed codes such as `INTEGRATION_INSTALLED`, `INTEGRATION_REMOVED`, `INTEGRATION_NOT_PRESENT`, `CODEX_CONFIG_CONFLICT`, `SKILL_CONFLICT`, `INTEGRATION_BACKUP_DISCARD_FAILED`, `INTEGRATION_ROLLBACK_FAILED`, and `INTEGRATION_CLEANUP_REQUIRED`. No returned or logged value may contain a path, config byte, native error, environment value, or Skill content.

The internal executable modes are exact and mutually exclusive:

```text
--install-codex-integration=skill
--install-codex-integration=mcp
--install-codex-integration=skill,mcp
--remove-codex-integration
--purge-protected-state
```

Preserve the exact existing `--purge-protected-state` maintenance mode, fixed JSON output, and success/failure exit behavior. Dispatch the exact integration and STDIO modes before importing Qt. When a frozen packaged executable is named `AgentGuardianMcp.exe`, accept only exact arguments `['--stdio-mcp']`; when a frozen packaged executable is named `AgentGuardian.exe`, reject STDIO and retain only no-argument GUI plus exact maintenance/integration modes. Unfrozen source execution must retain `python -m agentguardian --stdio-mcp` for development and SDK tests. Reject mixed or unknown integration/STDIO mode combinations with exit `64`; no arguments on the GUI launcher must still start the GUI. Add focused dispatch tests for all of these paths. Map integration success codes to `0`, ordinary conflict to `2`, and rollback/cleanup failure to `3`.

Uninstall removes only the exact marked block after manifest/hash validation and reparses remaining TOML. Remove a managed Skill file only when its current SHA-256 matches the manifest; preserve modified and unknown files. Delete the encrypted backup only after successful MCP cleanup. Never restore the whole historical config during normal uninstall.

- [ ] **Step 5: Verify and commit Task 5**

Add `codex_integration.py` to `EXPECTED_REVIEWED_SOURCE_MODULES` in sorted order and change both exact count assertions in `tests/test_self_audit.py` from `23` to `24`. Update `source_policy.json`, then run:

```powershell
.analysis\venv-0.3\Scripts\python.exe -m pytest -q tests/test_codex_integration.py tests/test_mcp_server.py tests/test_self_audit.py -p no:cacheprovider
.analysis\venv-0.3\Scripts\python.exe -m pytest -q tests/test_app_smoke.py -k "maintenance_command or main_runs_maintenance_before_qapplication" -p no:cacheprovider
.analysis\venv-0.3\Scripts\python.exe -m compileall -q src tests
rtk git diff --check
rtk git add src/agentguardian/codex_integration.py src/agentguardian/__main__.py src/agentguardian/source_policy.json tests/test_codex_integration.py tests/test_self_audit.py
rtk git commit -m "Add transactional Codex integration"
```

Expected: all tests pass, including rollback and modified-file preservation.

### Task 6: Add The New Installer Identity And Native Lifecycle Gate

**Files:**
- Create: `release_profiles/integrations_preview.json`
- Create: `scripts/verify_integrations_preview_profile.py`
- Create: `tests/test_integrations_preview_profile.py`
- Create: `packaging/windows/AgentGuardianIntegrationsPreview.spec`
- Create: `packaging/windows/AgentGuardianIntegrationsPreview.iss`
- Create: `scripts/build_windows_integrations_preview_installer.py`
- Create: `scripts/verify_windows_integrations_preview.ps1`
- Create: `tests/test_windows_integrations_preview_installer.py`
- Modify: `.gitattributes`
- Modify: `scripts/build_windows_portable.py`
- Modify: `tests/test_windows_packaging.py`
- Modify: `tests/test_personal_release_profile.py`

- [ ] **Step 1: Write failing installer-contract tests**

Require the new script to have:

```python
DISPLAY_VERSION = "0.3.0-preview.1"
FILE_VERSION = "0.3.0.1"
APP_ID = "{A64DBF23-FE14-4E04-89AE-0924666A03DE}"
INSTALLER_NAME = "AgentGuardian-Setup-0.3.0-preview.1-x64.exe"
INSTALL_DIRECTORY = r"{localappdata}\Programs\AgentGuardian Integrations Preview"
GUI_LAUNCHER = "AgentGuardian.exe"
MCP_LAUNCHER = "AgentGuardianMcp.exe"
```

Assert distinct AppId/script/profile/install directory from 0.2, `PrivilegesRequired=lowest`, Windows 11 x64, the exact current-user directory above, no network/download/service/startup/scheduled-task/elevation directive, and two integration tasks with `Flags: unchecked`. Assert the portable build includes `skills/agentguardian/{SKILL.md,README.md,LICENSE}` from the canonical source and no Skill ZIP.

Inspect `packaging/windows/AgentGuardianIntegrationsPreview.spec` and the built inventory. Require one shared `Analysis`, one shared `PYZ`, and one `COLLECT` onedir payload containing exactly `AgentGuardian.exe` with `console=False` and `AgentGuardianMcp.exe` with `console=True`. Both launchers must use the same reviewed `agentguardian.__main__` source and runtime modules. The GUI launcher retains no-argument GUI and exact maintenance modes; the console helper accepts only exact arguments `['--stdio-mcp']` and rejects missing, mixed, or unknown arguments with exit `64` before Qt import.

Add lifecycle-script contract tests for: Skill-only, MCP-only, both, pre-existing config preservation, foreign conflicts, upgrade, modified Skill preservation, exact block removal, no report deletion, no network check, no elevation, bounded JSON evidence, and a real subprocess using installed `AgentGuardianMcp.exe --stdio-mcp` with redirected stdin/stdout pipes. An in-process server fixture or invocation of the windowed launcher does not satisfy this lifecycle test.

In `tests/test_integrations_preview_profile.py`, require canonical schema `1`, name/channel `integrations_preview`, versions `0.3.0a1` / `0.3.0-preview.1` / `0.3.0.1`, AppId `{A64DBF23-FE14-4E04-89AE-0924666A03DE}`, installer filename `AgentGuardian-Setup-0.3.0-preview.1-x64.exe`, exact install directory `{localappdata}\Programs\AgentGuardian Integrations Preview`, exact launcher inventory `AgentGuardian.exe` and `AgentGuardianMcp.exe` with their console modes, Skill `0.1.0`, Skill path `%USERPROFILE%\.agents\skills\agentguardian`, config/backup/manifest paths from the approved design, SDK `mcp==2.0.0`, transport `stdio`, and exactly the two approved tool names. Reject unknown keys, duplicate arrays, noncanonical JSON, wrong versions, a third launcher or tool, non-STDIO transport, default-selected integration tasks, `.codex\skills`, Provider SDK imports, and 0.2 evidence represented as current.

In `tests/test_personal_release_profile.py`, retain the exact frozen 0.2 verifier/profile assertions and add a build-dispatch test proving that selecting `personal_exe_private_beta` against the current `0.3.0a1` package/source identity fails closed before PyInstaller runs. Historical verification by `scripts/verify_personal_release_profile.py` must still pass unchanged.

- [ ] **Step 2: Verify RED**

```powershell
.analysis\venv-0.3\Scripts\python.exe -m pytest -q tests/test_integrations_preview_profile.py tests/test_windows_integrations_preview_installer.py tests/test_windows_packaging.py tests/test_personal_release_profile.py -p no:cacheprovider
```

Expected: failures because the preview profile verifier and installer files do not exist.

- [ ] **Step 3: Implement the separate profile verifier, LF contract, and profile/source identity guard**

Create the complete `integrations_preview.json` identity plus sorted exact arrays for active documents already present at this task, package inputs, both launcher names and console modes, the exact install directory, required source paths, forbidden Provider SDK imports, forbidden HTTP/listener/background/updater/telemetry/arbitrary-execution capabilities, supported operations, ownership paths, and installer task defaults. Keep status `INTEGRATIONS-PREVIEW-NOT-READY`.

In `verify_integrations_preview_profile.py`, reuse only `ProfileSnapshot`, `ProfileViolation`, and `canonical_json_bytes` from the historical verifier. Implement a separate bounded parser that:

1. Reads at most 256 KiB and requires canonical ASCII JSON with unique keys.
2. Requires the exact identity values and sorted unique bounded arrays.
3. Requires every named source/package/document path and rejects reparse traversal.
4. Parses every `src/agentguardian/*.py` AST under aggregate and node limits.
5. Rejects Provider SDKs, HTTP server startup, sockets/listeners, subprocess/arbitrary execution, updater, telemetry, and dynamic plugin loading outside reviewed internal dispatch.
6. Requires exactly two decorated tools, `server.run()` with no transport argument, no resource/prompt registration, and no Provider API call.
7. Parses the Skill frontmatter, shared PyInstaller spec, launcher inventory, and installer/config constants.
8. Verifies `pyproject.toml`, both hash locks, notices, source policy, and all three version identities.
9. Returns only `{"profile": "integrations_preview", "status": "pass"}`.

Add this exact tracked EOL rule without changing the frozen entries:

```gitattributes
release_profiles/integrations_preview.json text eol=lf
```

Extend the release-profile dispatch in `build_windows_portable.py` to load and verify the new profile with `scripts.verify_integrations_preview_profile`. Write `INTEGRATIONS-PREVIEW-PROFILE.json` for 0.3. Keep the historical verifier/profile files and `PERSONAL-RELEASE-PROFILE.json` format unchanged, but before any build require the selected profile's package/source identity to equal the current tree identity. A personal 0.2 artifact build from the current 0.3 source must fail with fixed code `RELEASE_PROFILE_SOURCE_IDENTITY_MISMATCH` before invoking PyInstaller.

- [ ] **Step 4: Add the reviewed shared-Analysis dual-launcher payload**

`AgentGuardianIntegrationsPreview.spec` is the only PyInstaller entry for the 0.3 profile. It must create one `Analysis` and `PYZ` from the same reviewed `agentguardian.__main__` and package graph, then create these two `EXE` launchers inside one `COLLECT` onedir payload:

```text
AgentGuardian.exe     console=False
AgentGuardianMcp.exe  console=True
```

Include the canonical Skill directory as `agentguardian_skill`, retain all existing bounded payload validation, and inventory both launcher names exactly. Do not build a second runtime tree, duplicate the audit core, or turn the GUI executable into a console build. Update the 0.3 `build_pyinstaller_command` to invoke the reviewed spec and add tests that both launchers share the same audited source-policy and dependency payload.

- [ ] **Step 5: Implement the new Inno Setup task flow**

The new `.iss` must use:

```ini
[Setup]
AppId={{A64DBF23-FE14-4E04-89AE-0924666A03DE}
AppName=AgentGuardian
AppVersion={#DisplayVersion}
VersionInfoVersion={#FileVersion}
DefaultDirName={localappdata}\Programs\AgentGuardian Integrations Preview
PrivilegesRequired=lowest
SetupArchitecture=x64
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.22000
OutputBaseFilename=AgentGuardian-Setup-{#DisplayVersion}-x64
ChangesAssociations=no
ChangesEnvironment=no
RestartApplications=no

[Tasks]
Name: "codexskill"; Description: "Install AgentGuardian Codex Skill"; Flags: unchecked
Name: "codexmcp"; Description: "Enable AgentGuardian local MCP"; Flags: unchecked
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked
```

In `PrepareToInstall`, display the exact selected categories and the fixed targets `{userprofile}\.agents\skills\agentguardian`, `{userprofile}\.codex\config.toml`, and `{localappdata}\AgentGuardian` before changing integration state. Build one exact helper argument from selected tasks and execute it once in `ssPostInstall`. A nonzero exit raises a fixed exception so installation aborts. Do not start, close, or restart Codex.

On uninstall, call `--remove-codex-integration` through the windowed GUI/maintenance launcher before program files are removed. Exit `3` aborts uninstall and retains recovery data. Preserve the exact existing optional `--purge-protected-state` maintenance mode and test; never delete user-exported reports. The distinct AppId and install directory must prevent the 0.3 uninstaller from addressing frozen 0.2 program files.

- [ ] **Step 6: Implement the bounded 0.3 builder and lifecycle evidence script**

`build_windows_integrations_preview_installer.py` must reuse the existing compiler digest, path, manifest, checksum, and Git-clean validation helpers; it must use only the new profile, script SHA-256, version, AppId, and output name. It must reject a 0.2 bundle or profile evidence.

`verify_windows_integrations_preview.ps1` must accept exact candidate SHA, installer path/hash, evidence path, and test mode. It must install silently into `{localappdata}\Programs\AgentGuardian Integrations Preview`, verify both exact launcher files, execute installed `AgentGuardianMcp.exe` with `--stdio-mcp` through an official Python SDK client over real redirected stdin/stdout pipes, verify integration files/config according to mode, install the same candidate again as an upgrade, uninstall, and record canonical bounded evidence. The script must restore its synthetic pre-existing Codex config fixture in `finally` and fail if unknown residue, frozen 0.2 file mutation, or a network connection attributable to the installer/helper is observed.

The evidence contains only schema, exact source SHA, artifact SHA-256, version, selected mode, fixed boolean gates, fixed exit codes, and residue names from an allowlist. It contains no user profile path, config content, Skill content, environment value, or native exception.

- [ ] **Step 7: Verify and commit Task 6**

```powershell
.analysis\venv-0.3\Scripts\python.exe -m pytest -q tests/test_integrations_preview_profile.py tests/test_windows_integrations_preview_installer.py tests/test_windows_packaging.py tests/test_windows_installer.py tests/test_personal_release_profile.py -p no:cacheprovider
.analysis\venv-0.3\Scripts\python.exe -m compileall -q scripts tests
rtk git diff --check
rtk git add .gitattributes release_profiles/integrations_preview.json scripts/verify_integrations_preview_profile.py tests/test_integrations_preview_profile.py packaging/windows/AgentGuardianIntegrationsPreview.spec packaging/windows/AgentGuardianIntegrationsPreview.iss scripts/build_windows_integrations_preview_installer.py scripts/verify_windows_integrations_preview.ps1 scripts/build_windows_portable.py tests/test_windows_integrations_preview_installer.py tests/test_windows_packaging.py tests/test_personal_release_profile.py
rtk git commit -m "Add integrations preview installer route"
```

Expected: new and frozen installer tests both pass; no 0.2 identity file changes.

## Phase 3: Independent 0.3 Governance And Evidence

### Task 7: Add The Exact-SHA CI Workflow, Status Ledger, And Active Docs

**Files:**
- Create: `.github/workflows/windows-integrations-preview.yml`
- Create: `docs/security/integrations-preview.md`
- Create: `docs/security/integrations-preview-status.json`
- Create: `tests/test_integrations_preview_workflow.py`
- Modify: `.gitattributes`
- Modify: `release_profiles/integrations_preview.json`
- Modify: `tests/test_personal_release_profile.py`
- Modify: `README.md`

- [ ] **Step 1: Write failing workflow and documentation contract tests**

Workflow tests require exact checkout SHA validation, pinned action SHAs, Python 3.12 hash installs, full tests, privacy gate, Skill build, profile verification, portable build, installer build, all three integration lifecycle modes, compileall, secret scan, clean-tree verification, and exact-SHA artifact metadata. They must reject `pull_request_target`, writable permissions, unpinned actions, secrets in command lines, marketplace upload, GitHub Release publication, deployment, or a production-ready status mutation.

Documentation tests require exactly eight canonical status gates, all `pending`; require the active 0.3 boundary and frozen 0.2 evidence distinction; and reject production-safe, high-sensitivity-ready, signed, marketplace-published, deployed, or current-GitHub-pass claims. Update `test_governing_and_historical_document_classes_are_explicit` in `tests/test_personal_release_profile.py` so `docs/security/integrations-preview.md` is asserted to be a separate active 0.3 document and is never placed in the historical 0.2 set. Retain every exact historical 0.2 classification and content assertion.

- [ ] **Step 2: Verify RED**

```powershell
.analysis\venv-0.3\Scripts\python.exe -m pytest -q tests/test_integrations_preview_workflow.py tests/test_personal_release_profile.py -p no:cacheprovider
```

Expected: collection fails because the workflow test target and active 0.3 documents do not exist.

- [ ] **Step 3: Create the exact-SHA workflow without publishing**

Use `windows-2025`, `permissions: contents: read`, checkout `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1`, and setup Python `actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97`. Pin the same Inno 7.0.2 asset, Authenticode subject, asset SHA-256, and `ISCC.exe` SHA-256 as the frozen workflow.

The workflow builds only from `EXPECTED_SOURCE_COMMIT`, verifies a clean checkout, installs both locks with `--require-hashes`, runs the local gates, builds the Skill and preview portable/installer, runs lifecycle modes `skill`, `mcp`, and `skill,mcp`, and archives workflow evidence only as a private Actions artifact if repository policy permits. It never creates a release or uploads to Agensi.

- [ ] **Step 4: Synchronize active documentation and an eight-gate status ledger**

`docs/security/integrations-preview.md` must state the three entry points, four operations, exact human-approval boundary, model-context disclosure, local Provider guidance/no default Provider API, installer ownership, Apache-2.0 Skill terms, unsigned warning, and unsupported high-sensitivity/regulated/production use.

`docs/security/integrations-preview-status.json` must be canonical and contain exactly these gates, all initially `pending` until evidence from Task 8 is bound to one SHA:

```text
local_verification
github_ci
windows_integrations_workflow
clean_machine_lifecycle
codex_desktop_stdio
codex_cli_stdio
license_and_marketplace_review
independent_security_review
```

README must identify 0.3 as the active development track, identify 0.2 as frozen historical exact-SHA evidence, and keep `INTEGRATIONS-PREVIEW-NOT-READY` plus `NO-GO` explicit.

Add the two new documentation paths to the profile's sorted active-document array and rerun canonicalization. Do not change status or carry any historical gate to pass.

Add this exact tracked EOL rule without changing the existing profile/evidence rules:

```gitattributes
docs/security/integrations-preview-status.json text eol=lf
```

- [ ] **Step 5: Verify and commit Task 7**

```powershell
.analysis\venv-0.3\Scripts\python.exe -m pytest -q tests/test_integrations_preview_workflow.py tests/test_integrations_preview_profile.py tests/test_personal_release_profile.py -p no:cacheprovider
.analysis\venv-0.3\Scripts\python.exe scripts/verify_integrations_preview_profile.py --project-root . --profile release_profiles/integrations_preview.json
.analysis\venv-0.3\Scripts\python.exe -m compileall -q src scripts tests
rtk git diff --check
rtk git add .gitattributes tests/test_integrations_preview_workflow.py tests/test_personal_release_profile.py release_profiles/integrations_preview.json .github/workflows/windows-integrations-preview.yml docs/security/integrations-preview.md docs/security/integrations-preview-status.json README.md
rtk git commit -m "Add integrations preview release governance"
```

Expected: both 0.3 and historical 0.2 profile tests pass; the new status remains not ready.

### Task 8: Run Full Local Gates, Build Local Artifacts, And Obtain Independent Reviews

**Files:**
- Modify only if a failing gate exposes an implementation defect: the directly responsible source/test/profile file.
- Create outside Git: `.analysis/integrations-preview-local-verification.json`
- Create outside Git: `.analysis/integrations-preview-independent-review.md`
- Do not modify the tracked status ledger in this task; this avoids creating a new, untested evidence commit after the verified SHA.

- [ ] **Step 1: Run the complete exact-lock local gate**

From a clean tree and the exact Python 3.12 lock environment, run:

```powershell
rtk git status --short --branch
.analysis\venv-0.3\Scripts\python.exe -m pytest -q -p no:cacheprovider
.analysis\venv-0.3\Scripts\python.exe scripts/run_personal_privacy_acceptance.py --evidence-path .analysis\integrations-preview-privacy.json
.analysis\venv-0.3\Scripts\python.exe scripts/check_brand_assets.py
.analysis\venv-0.3\Scripts\python.exe scripts/verify_integrations_preview_profile.py --project-root . --profile release_profiles/integrations_preview.json
.analysis\venv-0.3\Scripts\python.exe -m compileall -q src scripts tests
rtk git diff --check
```

Expected: every command returns zero. Record the exact passed/skipped counts; do not reuse the baseline count.

- [ ] **Step 2: Build two local deterministic Skill and portable artifacts**

Use the exact candidate SHA and commit UTC time. Build two independent Skill outputs and two preview portable outputs, compare ZIP hashes byte-for-byte, then build one local preview installer with the pinned Inno compiler. Run static candidate verification and the lifecycle script in every mode available on this host.

Expected: deterministic Skill and portable ZIP hashes match; installer candidate checks pass. A lifecycle gate that cannot run on this machine remains `NOT_RUN`, not `PASS`.

- [ ] **Step 3: Run two independent reviews**

Use `superpowers:requesting-code-review` with two fresh reviewers:

1. Spec-compliance reviewer: map every approved design requirement and all three disclosed compatibility corrections to code/tests/evidence.
2. Security/quality reviewer: inspect authorization consumption, prepare no-read behavior, lazy clipboard Qt boundary, result redaction/caps, console-helper-only installed STDIO command, real-pipe lifecycle, TOML transaction/DPAPI rollback, superseded-backup rollback, distinct installer ownership, dependency/SBOM/notices, and unsupported-data claims.

Resolve every Critical or Important finding with a focused failing test and local commit. Any review fix commit invalidates all earlier Task 8 verification, artifact, lifecycle, and review evidence: rerun Step 1, rerun the complete deterministic artifact and lifecycle Step 2, then rerun both independent reviewers against the resulting final HEAD. Repeat this sequence after every further fix commit. Record reviewer identities, reviewed SHA, findings, resolutions, and rerun evidence in `.analysis/integrations-preview-independent-review.md` without claiming reviewer independence beyond the actual separate review context.

- [ ] **Step 4: Write canonical out-of-tree local evidence only**

Write evidence only after Steps 1-3 all bind the same final clean HEAD. `.analysis/integrations-preview-local-verification.json` must bind that exact HEAD, Python version, lock hashes, test counts, focused gates, artifact hashes, and local lifecycle results. Every artifact manifest, lifecycle record, and review record must name that same SHA; a hash or review from an earlier commit cannot be carried forward. The evidence must not contain paths, secrets, environment values, user data, or remote-state claims.

Report `local_verification` and `independent_security_review` as current-session PASS only if their out-of-tree evidence names the same exact clean HEAD. Keep every tracked gate `pending`; GitHub, clean-machine, Codex Desktop, Codex CLI, license, marketplace, signing, and publication require separate evidence and authorization.

- [ ] **Step 5: Verify the candidate tree is unchanged and stop before remote actions**

```powershell
rtk git status --short --branch
rtk git log -1 --format="%H %s"
rtk git diff --exit-code
```

Expected: clean worktree at the exact reviewed/tested implementation SHA; `.analysis` remains ignored. Stop and request separate authorization before push, Draft PR updates, GitHub workflow dispatch, public release, marketplace upload, signing, deployment, or production-safety wording.

## External Acceptance After Task 8

These are required for delivery but are not authorized by plan approval alone:

1. With explicit GitHub authorization, push the exact locally reviewed SHA to `yangjing6213-dev/AgentGuardian`; verify normal CI and the Windows integrations workflow against that same SHA. Earlier runs do not count.
2. On clean Windows 11 x64 machines, run default install, Skill-only, MCP-only, combined install, upgrade, uninstall, modified-Skill preservation, config-conflict preservation, and residue checks. Bind signed evidence records to the exact installer hash and source SHA.
3. Using the installed candidate, invoke both tools through Codex CLI and the ChatGPT desktop Codex client. Verify that `prepare_audit` can run automatically, `run_prepared_audit` produces a host approval prompt, rejection performs no read/network action, and accepted synthetic operations return bounded redacted results.
4. Complete Apache-2.0, Qt, MCP SDK/transitive dependency, Inno Setup, CPython, Microsoft runtime, and marketplace buyer-term review. Confirm that an Agensi listing visibly preserves Apache-2.0 rights before any paid listing upload.
5. Obtain explicit publication authorization before a public binary, GitHub Release, marketplace listing, website download, signing operation, or deployment. Keep the unsigned/SmartScreen warning visible if the accepted traditional installer route remains unsigned.
6. Treat real highly sensitive or regulated data as a separate product program requiring a new approved threat model, legal/privacy review, abuse and operations controls, trusted signing, clean-machine evidence, and production acceptance. The 0.3 preview cannot pass that gate by adding wording or tests alone.

## Self-Review Checklist

- [ ] Every approved design section maps to a task and test above.
- [ ] The only approved-design deltas are the three disclosed pre-implementation compatibility corrections; none adds product scope.
- [ ] The Skill installs only to `%USERPROFILE%\.agents\skills\agentguardian`.
- [ ] One reviewed onedir payload contains windowed `AgentGuardian.exe` and console `AgentGuardianMcp.exe`; installed config and real-pipe lifecycle use only the latter for STDIO.
- [ ] 0.3 uses exactly `{localappdata}\Programs\AgentGuardian Integrations Preview`, and its AppId/uninstaller cannot overwrite or remove frozen 0.2 files.
- [ ] Exactly two MCP tools exist; no resource, prompt, shell, report export, listener, service, updater, telemetry, or Provider API path is introduced.
- [ ] Prepare performs syntax/shape validation only; run consumes authorization before access.
- [ ] File, browser, clipboard, and share operations use the existing authoritative audit functions.
- [ ] MCP outputs exclude raw values, full paths, report bodies, browser URLs, clipboard text, HTTP bodies, native errors, and environment values.
- [ ] Config and Skill changes are optional, owned, transactional, reversible, and bounded.
- [ ] Reviewed source counts progress exactly from 21 to 22, 23, and 24 after `mcp_service.py`, `mcp_server.py`, and `codex_integration.py`.
- [ ] The standalone Skill and installer consume the same three canonical source files.
- [ ] 0.2 source history and evidence remain historical and verifiable, are never counted as 0.3 evidence, and cannot be built as a personal 0.2 artifact from current 0.3 source.
- [ ] Task 8 verification, deterministic artifacts/lifecycle, both reviews, and evidence all bind the same final clean SHA after any fix commit.
- [ ] No unfinished markers, weakened assertions, wildcard staging, push, publish, deployment, or production-ready claim remain in the plan.
