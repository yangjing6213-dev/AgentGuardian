# AgentGuardian Finding Dispositions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add exact local cross-scan false-positive and accepted-risk dispositions with mandatory expiry, auditable dual scoring, and current-user DPAPI persistence while preserving scan-scoped exported fingerprints and the no-API boundary.

**Architecture:** Add one pure disposition module and one hidden local reference on `Finding`. Detection computes report and disposition HMACs from independent keys; the existing protected-state payload evolves to canonical schema v2 and remains the only write location. The application loads state read-only at startup, applies dispositions deterministically, and saves a candidate state before committing any UI change.

**Tech Stack:** Python 3.12+, standard-library dataclasses/HMAC/JSON/time handling, PySide6, Windows DPAPI, pytest, and the existing deterministic scoring/reporting/state-store APIs. No new dependency is added.

---

## File Map

- Create `src/agentguardian/dispositions.py`: record validation, stable local-reference construction, expiry evaluation, indexing, and reviewed-finding selection.
- Create `tests/test_dispositions.py`: pure disposition and scoring contract.
- Modify `src/agentguardian/domain.py`: hidden optional local reference and shared safe annotation validation.
- Modify `src/agentguardian/detectors.py`: compute the second HMAC without retaining its inputs.
- Modify `src/agentguardian/evidence_state.py`: schema-v2 key and disposition serialization plus schema-v1 read compatibility.
- Modify `src/agentguardian/state_store.py`: keep the existing single-file DPAPI/atomic boundary unchanged while accepting schema v2.
- Modify `src/agentguardian/reporting.py`: technical/reviewed scores and safe disposition metadata.
- Modify `src/agentguardian/app.py`: read-only startup load, dual-key scan context, transactionally persisted disposition controls, and expiry refresh.
- Modify focused tests under `tests/`: detector, evidence-state, store, reporting, scoring, app smoke, and self-audit coverage.
- Modify `README.md`, `docs/architecture.md`, the stage report, and Windows MVP roadmap after the implementation is verified.

## Task 1: Add the Pure Disposition Contract

**Files:**
- Create: `src/agentguardian/dispositions.py`
- Create: `tests/test_dispositions.py`
- Modify: `src/agentguardian/domain.py`
- Modify: `tests/test_domain.py`

- [x] **Step 1: Write failing model and reference tests**

Add tests that require a hidden 64-hex `Finding.disposition_ref`, exact status values, bounded safe metadata, canonical UTC seconds, a maximum 366-day lifetime, deterministic reference construction, and separation when the key, rule, path, or raw value changes.

```python
FIXED_NOW = datetime(2026, 8, 2, 9, 0, tzinfo=timezone.utc)
KEY = b"d" * 32


def test_disposition_reference_is_exact_and_hidden() -> None:
    reference = make_disposition_ref(
        KEY,
        rule_id="OPENAI_API_KEY",
        source=r"C:\Synthetic\config.env",
        raw_match="sk-proj-synthetic-value",
    )
    same = make_disposition_ref(
        KEY,
        rule_id="OPENAI_API_KEY",
        source=r"c:\synthetic\.\config.env",
        raw_match="sk-proj-synthetic-value",
    )
    moved = make_disposition_ref(
        KEY,
        rule_id="OPENAI_API_KEY",
        source=r"C:\Synthetic\moved.env",
        raw_match="sk-proj-synthetic-value",
    )

    assert reference == same
    assert reference != moved
    finding = Finding(
        "OPENAI_API_KEY",
        RiskDomain.CREDENTIALS,
        Severity.HIGH,
        "b" * 64,
        (Evidence("config.env", "c" * 64, "OpenAI API key detected"),),
        disposition_ref=reference,
    )
    assert reference not in repr(finding)


def test_disposition_record_requires_safe_finite_metadata() -> None:
    record = DispositionRecord(
        disposition_ref="a" * 64,
        rule_id="OPENAI_API_KEY",
        status=DispositionStatus.FALSE_POSITIVE,
        reason="Synthetic test fixture",
        reviewer="Local reviewer",
        created_at="2026-08-02T09:00:00Z",
        expires_at="2026-08-31T09:00:00Z",
    )

    assert record.status is DispositionStatus.FALSE_POSITIVE
    with pytest.raises(ValueError, match="DISPOSITION_INVALID"):
        replace(record, reason=r"C:\private\secret.txt")
    with pytest.raises(ValueError, match="DISPOSITION_INVALID"):
        replace(record, expires_at="2027-08-04T09:00:00Z")
```

- [x] **Step 2: Run the new tests and verify red**

Run: `rtk pytest -q -p no:cacheprovider tests/test_dispositions.py tests/test_domain.py`

Expected: collection or assertion failures because the disposition module, status, record, reference builder, and hidden finding field do not exist.

- [x] **Step 3: Implement the minimum pure model**

Add the optional field at the end of `Finding` so existing positional construction remains valid:

```python
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    domain: RiskDomain
    severity: Severity
    root_fingerprint: str
    evidence: tuple[Evidence, ...]
    disposition_ref: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        _require_tuple("evidence", self.evidence)
        if _SHA256_HEX.fullmatch(self.root_fingerprint) is None:
            raise ValueError("root_fingerprint must be a 64-character lowercase HMAC digest")
        if self.disposition_ref is not None and _SHA256_HEX.fullmatch(self.disposition_ref) is None:
            raise ValueError("disposition_ref must be a 64-character lowercase HMAC digest")
```

Implement these public disposition APIs without filesystem, UI, or network imports:

```python
_HEX = re.compile(r"[0-9a-f]{64}")
_RULE_ID = re.compile(r"[A-Z][A-Z0-9_]{0,79}")
_UTC_SECONDS = "%Y-%m-%dT%H:%M:%SZ"


def parse_utc(value: object) -> datetime:
    if type(value) is not str:
        raise ValueError("DISPOSITION_INVALID")
    try:
        return datetime.strptime(value, _UTC_SECONDS).replace(tzinfo=timezone.utc)
    except ValueError:
        raise ValueError("DISPOSITION_INVALID") from None


class DispositionStatus(str, Enum):
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


@dataclass(frozen=True, slots=True)
class DispositionRecord:
    disposition_ref: str = field(repr=False)
    rule_id: str
    status: DispositionStatus
    reason: str
    reviewer: str
    created_at: str
    expires_at: str

    def __post_init__(self) -> None:
        try:
            created = parse_utc(self.created_at)
            expires = parse_utc(self.expires_at)
            if (
                _HEX.fullmatch(self.disposition_ref) is None
                or _RULE_ID.fullmatch(self.rule_id) is None
                or not isinstance(self.status, DispositionStatus)
                or not created < expires
                or expires - created > timedelta(days=366)
            ):
                raise ValueError
            object.__setattr__(
                self, "reason", validate_safe_annotation("reason", self.reason, 240)
            )
            object.__setattr__(
                self,
                "reviewer",
                validate_safe_annotation("reviewer", self.reviewer, 80),
            )
        except (TypeError, ValueError):
            raise ValueError("DISPOSITION_INVALID") from None


@dataclass(frozen=True, slots=True)
class DispositionEvaluation:
    state: str
    record: DispositionRecord | None


def make_disposition_ref(
    key: bytes, *, rule_id: str, source: str, raw_match: str
) -> str:
    if (
        type(key) is not bytes
        or len(key) != 32
        or type(rule_id) is not str
        or _RULE_ID.fullmatch(rule_id) is None
        or type(source) is not str
        or not source
        or type(raw_match) is not str
        or not raw_match
    ):
        raise ValueError("DISPOSITION_INVALID")
    path = ntpath.normcase(ntpath.abspath(source))
    raw = unicodedata.normalize("NFKC", raw_match)
    parts = (
        rule_id.encode("utf-8"),
        path.encode("utf-8"),
        raw.encode("utf-8"),
    )
    message = b"".join(len(part).to_bytes(4, "big") + part for part in parts)
    return hmac.new(key, message, sha256).hexdigest()


def disposition_index(
    records: Iterable[DispositionRecord],
) -> dict[str, DispositionRecord]:
    index: dict[str, DispositionRecord] = {}
    for record in records:
        if not isinstance(record, DispositionRecord) or record.disposition_ref in index:
            raise ValueError("DISPOSITION_INVALID")
        index[record.disposition_ref] = record
    return index


def evaluate_disposition(
    finding: Finding,
    records: Mapping[str, DispositionRecord],
    *,
    now: datetime,
) -> DispositionEvaluation:
    record = records.get(finding.disposition_ref or "")
    if record is None or record.rule_id != finding.rule_id:
        return DispositionEvaluation("open", None)
    created = parse_utc(record.created_at)
    expires = parse_utc(record.expires_at)
    if now < created:
        return DispositionEvaluation("open", None)
    if now >= expires:
        return DispositionEvaluation("expired", record)
    return DispositionEvaluation(record.status.value, record)


def reviewed_findings(
    findings: Iterable[Finding],
    records: Mapping[str, DispositionRecord],
    *,
    now: datetime,
) -> tuple[Finding, ...]:
    return tuple(
        finding
        for finding in findings
        if evaluate_disposition(finding, records, now=now).state != "false_positive"
    )


def upsert_disposition(
    records: Iterable[DispositionRecord], record: DispositionRecord
) -> tuple[DispositionRecord, ...]:
    index = disposition_index(records)
    if not isinstance(record, DispositionRecord):
        raise ValueError("DISPOSITION_INVALID")
    index[record.disposition_ref] = record
    return tuple(sorted(index.values(), key=lambda item: item.disposition_ref))


def withdraw_disposition(
    records: Iterable[DispositionRecord], disposition_ref: str
) -> tuple[DispositionRecord, ...]:
    if _HEX.fullmatch(disposition_ref) is None:
        raise ValueError("DISPOSITION_INVALID")
    index = disposition_index(records)
    index.pop(disposition_ref, None)
    return tuple(sorted(index.values(), key=lambda item: item.disposition_ref))
```

Use one shared `validate_safe_annotation()` helper in `domain.py` for reason and reviewer validation:

```python
def validate_safe_annotation(name: str, value: object, max_length: int) -> str:
    if type(value) is not str or type(max_length) is not int or max_length < 1:
        raise ValueError(f"{name} contains unsafe content")
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > max_length
        or any(not character.isprintable() for character in normalized)
        or any(pattern.search(normalized) for pattern in _UNMASKED_SECRET_PATTERNS)
        or _URL.search(normalized)
        or _looks_like_path(normalized)
        or _looks_like_seed_phrase(normalized)
    ):
        raise ValueError(f"{name} contains unsafe content")
    return normalized
```

`parse_utc()` accepts only `YYYY-MM-DDTHH:MM:SSZ` and returns an aware UTC `datetime`. `evaluate_disposition()` rejects a naive or non-UTC `now` with `DISPOSITION_INVALID`.

Path matching follows Windows lexical rules through `ntpath.abspath`, `ntpath.normpath`, and `ntpath.normcase`. Do not Unicode-normalize the path; NFKC applies only to the raw match.

- [x] **Step 4: Add fixed-time evaluation, replacement, withdrawal, and score tests**

Require open, active false-positive, active accepted-risk, expired, future-created, rule mismatch, and reference mismatch behavior. Require upsert to replace only the same reference, withdrawal to leave every other sorted record unchanged, and malformed references to fail. Call the existing `score()` on all findings and on `reviewed_findings()`; assert accepted risks do not improve the reviewed score and expired false positives re-enter caps and deductions.

- [x] **Step 5: Run focused tests and commit**

Run: `rtk pytest -q -p no:cacheprovider tests/test_dispositions.py tests/test_domain.py tests/test_scoring.py`

Expected: all focused tests pass.

Commit: `Add expiring finding disposition model`

## Task 2: Compute Independent Local References During Detection

**Files:**
- Modify: `src/agentguardian/detectors.py`
- Modify: `tests/test_detectors.py`
- Modify: `tests/test_app_smoke.py`

- [x] **Step 1: Write failing dual-HMAC detector tests**

Require the scan fingerprint to change with `scan_key` while `disposition_ref` remains stable with the same matching key and exact source occurrence. Require a moved path, changed raw value, changed rule, or changed matching key to produce a different local reference.

```python
def test_detector_keeps_report_and_disposition_hmac_purposes_separate() -> None:
    arguments = {
        "text": "OPENAI_API_KEY=sk-proj-synthetic-value",
        "source": r"C:\Synthetic\config.env",
        "disposition_key": b"d" * 32,
    }
    first = detect_text(**arguments, scan_key=b"a" * 32)[0]
    second = detect_text(**arguments, scan_key=b"b" * 32)[0]

    assert first.root_fingerprint != second.root_fingerprint
    assert first.disposition_ref == second.disposition_ref
    assert first.disposition_ref not in repr(first)
```

- [x] **Step 2: Run the detector tests and verify red**

Run: `rtk pytest -q -p no:cacheprovider tests/test_detectors.py`

Expected: failures show that `disposition_key` is not accepted and findings do not carry a local reference.

- [x] **Step 3: Thread the matching key through all detector paths**

Add keyword-only `disposition_key: bytes | None = None` and a full `source_identity` path where needed to `detect_text`, `_detect_text`, `detect_file`, `detect_mcp_config`, and `_finding`. Preserve the display-only basename in `Evidence.source`.

```python
def _finding(
    rule_id: str,
    domain: RiskDomain,
    severity: Severity,
    raw_match: str,
    kind: str,
    source: str,
    scan_key: bytes,
    *,
    disposition_key: bytes | None,
    source_identity: str,
) -> Finding:
    fingerprint = hmac.new(
        scan_key,
        (rule_id + unicodedata.normalize("NFKC", raw_match)).encode("utf-8"),
        sha256,
    ).hexdigest()
    local_reference = (
        make_disposition_ref(
            disposition_key,
            rule_id=rule_id,
            source=source_identity,
            raw_match=raw_match,
        )
        if disposition_key is not None
        else None
    )
    return Finding(
        rule_id,
        domain,
        severity,
        fingerprint,
        (Evidence(source=source, fingerprint=fingerprint, masked=_mask(raw_match, kind)),),
        disposition_ref=local_reference,
    )
```

`detect_file()` passes the full `Path` only as `source_identity`; reports continue to receive `file_path.name`. The application must supply a 32-byte matching key for every production scan.

- [x] **Step 4: Verify privacy and complete detector integration**

Assert raw values, full paths, the matching key, and `disposition_ref` do not appear in evidence fields, exceptions, or `repr`. Cover MCP and custom-keyword findings as well as rule findings.

Run: `rtk pytest -q -p no:cacheprovider tests/test_detectors.py tests/test_app_smoke.py`

Expected: all focused tests pass with no API or network imports.

- [x] **Step 5: Commit**

Commit: `Add local disposition references to findings`

## Task 3: Evolve Protected State to Canonical Schema v2

**Files:**
- Modify: `src/agentguardian/evidence_state.py`
- Modify: `tests/test_evidence_state.py`
- Modify: `tests/test_state_store.py`
- Modify: `tests/test_windows_dpapi.py`

- [x] **Step 1: Write failing schema-v2 and legacy-v1 tests**

Require schema v2 to contain an exact 64-hex `disposition_hmac_key` and deterministically sorted disposition records. Add a literal canonical schema-v1 fixture using the old exact key set and require it to decode with `disposition_key is None` and no records. Require encoding a legacy snapshot to fail until the caller builds a v2 snapshot.

```python
def test_schema_v2_round_trip_keeps_key_hidden_from_repr() -> None:
    record = DispositionRecord(
        disposition_ref="a" * 64,
        rule_id="OPENAI_API_KEY",
        status=DispositionStatus.FALSE_POSITIVE,
        reason="Synthetic test fixture",
        reviewer="Local reviewer",
        created_at="2026-08-02T09:00:00Z",
        expires_at="2026-08-31T09:00:00Z",
    )
    snapshot = build_snapshot(
        _findings(),
        _score(),
        rule_version="1.1.0",
        captured_at=FIXED_NOW,
        disposition_key=b"d" * 32,
        dispositions=(record,),
    )

    encoded = encode_snapshot(snapshot)
    decoded = decode_snapshot(encoded)

    assert decoded == snapshot
    assert decoded.disposition_key == b"d" * 32
    assert (b"d" * 32).hex() not in repr(decoded)
```

- [x] **Step 2: Run evidence/store tests and verify red**

Run: `rtk pytest -q -p no:cacheprovider tests/test_evidence_state.py tests/test_state_store.py tests/test_windows_dpapi.py`

Expected: failures show schema version 2, key, records, and version-1 compatibility are missing.

- [x] **Step 3: Implement exact versioned decoding and v2-only encoding**

Extend `EvidenceSnapshot` with hidden key and records:

```python
@dataclass(frozen=True, slots=True)
class EvidenceSnapshot:
    schema_version: int
    captured_at: str
    product_version: str
    rule_version: str
    scan: ScanMetadata
    findings: tuple[FindingReference, ...]
    disposition_key: bytes | None = field(default=None, repr=False)
    dispositions: tuple[DispositionRecord, ...] = ()
```

`build_snapshot()` requires `disposition_key: bytes` and `dispositions: Iterable[DispositionRecord]`, validates exact length and count, and always returns schema 2. `decode_snapshot()` selects the exact allowed root keys by integer schema version; version 1 accepts only the historical keys, while version 2 additionally requires `disposition_hmac_key` and `dispositions`. Unknown versions, duplicate JSON keys, unknown fields, invalid ordering, malformed records, or an oversized payload return only `PROTECTED_STATE_INVALID`.

- [x] **Step 4: Prove the existing DPAPI and atomic boundary is unchanged**

Update state-store fixtures to build schema v2. Assert ciphertext excludes matching-key bytes, references, reasons, reviewer labels, source names, and raw markers. Keep the same `STATE_FILENAME`, application-integrity envelope, exclusive temporary file, `fsync`, and `os.replace` path.

Run: `rtk pytest -q -p no:cacheprovider tests/test_evidence_state.py tests/test_state_store.py tests/test_windows_dpapi.py`

Expected: all schema, synthetic protection, native Windows DPAPI, corruption, legacy, size, UNC, reparse, and replacement tests pass.

- [x] **Step 5: Commit**

Commit: `Persist dispositions in protected state v2`

## Task 4: Add Auditable Technical and Reviewed Reports

**Files:**
- Modify: `src/agentguardian/reporting.py`
- Modify: `tests/test_reporting.py`
- Modify: `tests/test_scoring.py`
- Modify: `tests/test_self_audit.py`

- [x] **Step 1: Write failing report and cap tests**

Require JSON to retain `score` as the technical score and add `reviewed_score`. Require every finding to have one safe disposition state; active records include metadata, expired records retain metadata, and open records contain only `{"status": "open"}`. Require accepted risk to retain deductions and cap reasons, while an active false positive can remove its deduction and cap only from the reviewed score.

```python
FIXED_NOW = datetime(2026, 8, 2, 9, 0, tzinfo=timezone.utc)
finding = Finding(
    "PUBLIC_ACTIVE_CREDENTIAL",
    RiskDomain.CREDENTIALS,
    Severity.HIGH,
    "a" * 64,
    (Evidence("config.env", "a" * 64, "Synthetic credential detected"),),
    disposition_ref="b" * 64,
)
record = DispositionRecord(
    disposition_ref="b" * 64,
    rule_id="PUBLIC_ACTIVE_CREDENTIAL",
    status=DispositionStatus.FALSE_POSITIVE,
    reason="Synthetic test fixture",
    reviewer="Local reviewer",
    created_at="2026-08-02T09:00:00Z",
    expires_at="2026-08-31T09:00:00Z",
)
records = (record,)
index = disposition_index(records)
technical_score = calculate_score((finding,), coverage=1.0)
reviewed_score = calculate_score(
    reviewed_findings((finding,), index, now=FIXED_NOW),
    coverage=1.0,
)
report = json.loads(
    render_json(
        technical_score,
        (finding,),
        rule_version="1.1.0",
        reviewed_score=reviewed_score,
        dispositions=records,
        evaluated_at=FIXED_NOW,
    )
)
assert report["score"]["total"] == 39
assert report["reviewed_score"]["total"] == 100
assert report["findings"][0]["disposition"] == {
    "status": "false_positive",
    "reason": "Synthetic test fixture",
    "reviewer": "Local reviewer",
    "created_at": "2026-08-02T09:00:00Z",
    "expires_at": "2026-08-31T09:00:00Z",
}
```

- [x] **Step 2: Run reporting tests and verify red**

Run: `rtk pytest -q -p no:cacheprovider tests/test_reporting.py tests/test_scoring.py`

Expected: renderers reject the new arguments or omit reviewed score and dispositions.

- [x] **Step 3: Extend renderers without exporting local identifiers**

Use this backward-compatible signature shape:

```python
def render_json(
    score: Score,
    findings: Iterable[Finding],
    *,
    rule_version: str,
    reviewed_score: Score | None = None,
    dispositions: Iterable[DispositionRecord] = (),
    evaluated_at: datetime | None = None,
) -> str:
    frozen_findings = tuple(findings)
    effective_score = reviewed_score if reviewed_score is not None else score
    index = disposition_index(dispositions)
    when = evaluated_at or datetime.now(timezone.utc)
    report = {
        "product": _PRODUCT,
        "version": __version__,
        "rule_version": rule_version,
        "score": _score_data(score),
        "reviewed_score": _score_data(effective_score),
        "findings": [
            _finding_data(finding, index, when)
            for finding in _sorted_findings(frozen_findings)
        ],
    }
    return json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False)
```

Move the existing score dictionary construction into `_score_data(score)`. Extend `_finding_data()` to add only the safe evaluation fields. `render_html()` receives the same keyword-only arguments and evaluates the same frozen input once. When no disposition inputs are provided, reviewed score equals technical score and every finding is open. Do not add `disposition_ref` or the key to any output or sort key.

- [x] **Step 4: Verify escaping, determinism, generators, and import policy**

Update the exact reporting import/call allowlist. Assert reason and reviewer HTML are escaped, input ordering does not alter output, one-shot finding generators still work, and synthetic raw paths/values/keys/references are absent from both formats.

Run: `rtk pytest -q -p no:cacheprovider tests/test_reporting.py tests/test_scoring.py tests/test_self_audit.py`

Expected: all focused tests pass and self-audit reports no network or unexpected write capability.

- [x] **Step 5: Commit**

Commit: `Report reviewed finding dispositions`

## Task 5: Load Disposition Context and Apply It During Audits

**Files:**
- Modify: `src/agentguardian/app.py`
- Modify: `tests/test_app_smoke.py`

- [x] **Step 1: Isolate app tests and write failing startup tests**

Add an autouse fixture that points `LOCALAPPDATA` at `tmp_path`, preventing tests from reading a real user state. Require startup behavior for valid v2, valid v1, missing, and invalid states, and assert none of them write a file.

```python
@pytest.fixture(autouse=True)
def isolated_local_app_data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))


def test_missing_state_creates_only_an_in_memory_matching_key(qapp, tmp_path: Path) -> None:
    window = create_window()

    assert len(window._disposition_key) == 32
    assert window._dispositions == ()
    assert not window._protected_state_invalid
    assert tuple(tmp_path.rglob("*")) == ()
```

- [x] **Step 2: Run app tests and verify red**

Run: `rtk pytest -q -p no:cacheprovider tests/test_app_smoke.py`

Expected: the window has no loaded disposition context and scans do not accept its key or records.

- [x] **Step 3: Add a read-only startup context and dual-score audit outcome**

Add a frozen internal context with a hidden key, records, and invalid-state flag. `_load_disposition_context()` maps `PROTECTED_STATE_UNAVAILABLE` to a fresh key, maps `PROTECTED_STATE_INVALID` to a fresh key plus `invalid=True`, and maps schema v1 to a fresh key plus no records. It never calls the save API.

Extend `_run_audit()` and `AuditWorker` with the matching key, records, and explicit evaluation time. Pass the key and full path to every detector, calculate the technical score from all findings, calculate the reviewed score from `reviewed_findings()`, and render both reports from the same fixed inputs.

```python
@dataclass(frozen=True, slots=True)
class AuditOutcome:
    findings: tuple[Finding, ...]
    score: Score
    reviewed_score: Score
    rule_version: str
    report_json: str
    report_html: str
    scanned_roots: tuple[Path, ...]
    evaluated_at: datetime
```

- [x] **Step 4: Prove cross-scan application and zero automatic writes**

Run two audits with different scan keys but the same matching key and path. Assert the second audit applies the saved disposition. Move the synthetic file and assert it reopens. Assert window creation, folder selection, scan start, scan completion, report refresh, and report export never call `save_protected_state`.

Run: `rtk pytest -q -p no:cacheprovider tests/test_app_smoke.py tests/test_detectors.py tests/test_reporting.py`

Expected: all focused tests pass.

- [x] **Step 5: Commit**

Commit: `Apply protected dispositions during audits`

## Task 6: Add Transactional Desktop Disposition Controls

**Files:**
- Modify: `src/agentguardian/app.py`
- Modify: `tests/test_app_smoke.py`
- Modify: `tests/test_self_audit.py`

- [x] **Step 1: Write failing control and transaction tests**

Require a stable five-column findings table with disposition status, explicit false-positive/accepted-risk/withdraw commands, mandatory validated form values, and disabled commands without a selected local-reference finding. Require the candidate protected state to save before any in-memory score, row, or report changes.

Add three failure-path tests:

1. user cancels the form, producing no write or UI change;
2. DPAPI/store save fails, preserving the previous state, scores, reports, and row status;
3. startup state was invalid and the user rejects replacement confirmation, producing no write.

- [x] **Step 2: Run UI tests and verify red**

Run: `rtk pytest -q -p no:cacheprovider tests/test_app_smoke.py`

Expected: disposition controls and transactional update behavior do not exist.

- [x] **Step 3: Implement explicit create, replace, and withdraw flows**

Use PySide6-native controls only: a `QComboBox` for status, `QLineEdit` fields for reason/reviewer, `QDateTimeEdit` for local expiry converted to canonical UTC seconds, and standard dialog buttons. Store one selected `Finding`, never raw detector input. Build the candidate tuple with pure helpers, then persist:

```python
candidate = upsert_disposition(self._dispositions, record)
snapshot = build_snapshot(
    self._audit_outcome.findings,
    self._audit_outcome.score,
    rule_version=self._audit_outcome.rule_version,
    captured_at=now,
    disposition_key=self._disposition_key,
    dispositions=candidate,
)
save_protected_state(snapshot)
self._commit_disposition_state(candidate, now=now)
```

Withdrawal follows the same save-before-commit sequence. If `_protected_state_invalid` is true, require `QMessageBox.Yes` before the save; successful replacement clears the flag. Fixed messages must not include paths, keys, references, native errors, or callback text.

- [x] **Step 4: Refresh expiry without writing state**

Use one single-shot `QTimer` for the nearest active expiry. Bound each interval to `min(remaining_ms, 86_400_000)` and reschedule after every timeout so a 366-day exception cannot overflow a Qt timer and clock changes are re-evaluated daily. On timeout, recalculate reviewed score, table statuses, and both reports from the immutable findings and existing records. Do not delete expired records and do not call the state store.

- [x] **Step 5: Verify layout, rollback, expiry, and write allowlist**

Assert controls do not overlap at the minimum window size, status text fits, selection state is stable, expiry refresh performs zero writes, and the exact self-audit write exception still permits only the existing `state_store.py` atomic path.

Run: `rtk pytest -q -p no:cacheprovider tests/test_app_smoke.py tests/test_self_audit.py tests/test_state_store.py`

Expected: all focused tests pass.

- [x] **Step 6: Commit**

Commit: `Add transactional finding dispositions`

## Task 7: Synchronize Local Evidence Before Batch 3 Acceptance

**Files:**
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/reports/alpha-0.1.0-stage-report.md`
- Modify: `docs/superpowers/plans/2026-08-02-agentguardian-windows-mvp-hardening.md`
- Modify: `docs/superpowers/plans/2026-08-02-agentguardian-finding-dispositions.md`
- Modify: `tests/test_self_audit.py`

- [x] **Step 1: Add failing documentation assertions**

Require current docs to state exact cross-scan matching, separate local and report HMAC purposes, mandatory finite expiry, accepted-risk scoring, schema-v1 read compatibility, corrupt-state replacement confirmation, no API calls, residual same-user/clock/path risks, and non-production status.

- [x] **Step 2: Update status documents after implementation evidence exists**

Describe only implemented behavior. Keep Batches 4-6 open. Do not claim production safety, stable matching after moves, cloud/team workflow, automatic remediation, or default OpenAI API access.

- [x] **Step 3: Run the complete local gate**

Run: `rtk pytest -q -p no:cacheprovider`

Run: `rtk proxy python scripts/check_brand_assets.py`

Run: `rtk proxy python -m compileall -q src`

Run: `rtk git diff --check`

Run with `PYTHONPATH=src`: `rtk proxy python -c "import json; from agentguardian.self_audit import collect_self_audit; print(json.dumps(collect_self_audit(), sort_keys=True))"`

Expected: zero failures, zero whitespace errors, `findings=[]`, and `network_capability=not_detected`. Record local skips separately from passes.

- [x] **Step 4: Run an independent read-only security review**

Review stable-reference privacy, canonical-message collision resistance, path normalization, key lifecycle, schema migration, expiry/clock handling, dual-score semantics, report leakage, transactional rollback, corrupt-state replacement, self-audit precision, synthetic-only tests, and no-network/no-LLM boundaries. Resolve every Critical or Important finding with a new failing test before submission.

Review result: `APPROVED / READY` at `ef7808975879bea153172c09e647e04d0bf48e9b`; Critical 0, Important 0, Minor 0. The earlier failed final-SHA runs `30759350802` and `30759352079` at `d719e0fb79eae9132fabc713e23f5256d0c1f70c` remain historical evidence in the stage report and do not count as remote acceptance.

- [x] **Step 5: Commit, push, and verify remote evidence**

The remotely accepted Batch 3 implementation/evidence baseline is `50b74e6cc50dd7a4681a26b3084e7f312c096c47`. [Push run `30762254791` / job `91534776936`](https://github.com/hqwzhu/AgentGuardian/actions/runs/30762254791/job/91534776936) and [PR run `30762256518` / job `91534781660`](https://github.com/hqwzhu/AgentGuardian/actions/runs/30762256518/job/91534781660) both succeeded with `687 passed`, all five named workflow steps passed, and annotations were 0/0. At evidence-capture time, Draft PR #1 was `OPEN / DRAFT` at that SHA; [PR link](https://github.com/hqwzhu/AgentGuardian/pull/1). Keep Batches 4-6 pending.

`a38910b340631b2e78c33c9d7595cf98aa2f52b9` is a docs/tests-only evidence-sync commit that changes no runtime or package source. It was not covered by the two cited CI runs for `50b74e6cc50dd7a4681a26b3084e7f312c096c47` and is not claimed as remotely verified.

Passing this plan completes only the documented Batch 3 acceptance. It does not complete the Windows MVP or establish production safety.

**Batch 3 acceptance status (2026-08-03):** Local gates and independent security review are complete; remote acceptance is evidenced at the implementation/evidence baseline `50b74e6cc50dd7a4681a26b3084e7f312c096c47`. 当前精确本地门禁、复审和远程验收记录在阶段报告；Batches 4-6 仍待完成。Batch 3 验收不表示 Windows MVP 完成或生产安全。
