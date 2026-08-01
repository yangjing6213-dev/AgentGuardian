# AgentGuardian Protected Evidence State Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an explicit, Windows-only DPAPI-protected evidence snapshot that never persists raw matches, scan keys, paths, source names, credentials, or endpoint values.

**Architecture:** Keep snapshot validation, DPAPI bytes protection, file persistence, and UI consent in separate modules. Build each boundary with synthetic TDD fixtures; do not connect persistence to audit execution until the core schema and Windows crypto behavior pass independently.

**Tech Stack:** Python 3.12 standard library, `ctypes`, Windows DPAPI, PySide6, pytest, and the existing `Finding`/`Score` domain model.

---

## Task 1: Freeze the Minimized Snapshot Schema

**Files:**
- Create: `src/agentguardian/evidence_state.py`
- Create: `tests/test_evidence_state.py`

- [x] **Step 1: Write failing schema tests**

Create synthetic `Finding` and `Score` values. Require `build_snapshot(...)` and `encode_snapshot(...)` to produce schema version 1 with UTC capture time, product/rule versions, coverage/confidence/incomplete/limits, rule IDs, masked summaries, and HMAC references. Assert serialized bytes do not contain source names, root paths, raw values, endpoint values, or a `scan_key` field.

- [x] **Step 2: Verify the red state**

Run: `python -B -m pytest -q -p no:cacheprovider tests/test_evidence_state.py`

Expected: collection fails because `agentguardian.evidence_state` does not exist.

- [x] **Step 3: Implement immutable snapshot types and canonical encoding**

Add frozen dataclasses for the snapshot, scan metadata, finding reference, and evidence reference. Convert iterables to tuples, sort findings/evidence deterministically, reuse the existing masked-evidence safety contract, and encode with `json.dumps(..., ensure_ascii=False, separators=(",", ":"), allow_nan=False)`.

- [x] **Step 4: Add strict decoding tests and implementation**

Require exact object keys, schema `1`, UTC `Z` timestamps, 64-character lowercase HMAC values, bounded counts, finite numeric values, and no unknown fields. Invalid or over-limit payloads must raise `EvidenceStateError("PROTECTED_STATE_INVALID")` without echoing input.

- [x] **Step 5: Run focused tests and commit**

Run: `python -B -m pytest -q -p no:cacheprovider tests/test_evidence_state.py tests/test_domain.py`

Expected: all focused tests pass.

Commit: `Add minimized evidence snapshot schema`

## Task 2: Add the Windows DPAPI Bytes Boundary

**Files:**
- Create: `src/agentguardian/windows_dpapi.py`
- Create: `tests/test_windows_dpapi.py`
- Modify: `src/agentguardian/self_audit.py`
- Modify: `tests/test_self_audit.py`

- [ ] **Step 1: Write failing DPAPI contract tests**

On Windows, require `protect_bytes(plaintext)` to return different bytes that do not contain plaintext and require `unprotect_bytes(ciphertext)` to recover it. A one-byte mutation must raise `DpapiError("PROTECTED_STATE_INVALID")`. A monkeypatched non-Windows platform must raise `DpapiError("DPAPI_UNAVAILABLE")`.

- [ ] **Step 2: Verify the red state**

Run: `python -B -m pytest -q -p no:cacheprovider tests/test_windows_dpapi.py`

Expected: collection fails because `agentguardian.windows_dpapi` does not exist.

- [ ] **Step 3: Implement the minimum DPAPI adapter**

Use current-user `CryptProtectData`/`CryptUnprotectData` with `CRYPTPROTECT_UI_FORBIDDEN`, a fixed `AgentGuardian protected evidence state` description, explicit ctypes signatures, and `LocalFree` in `finally`. Enforce non-empty input and the 1 MiB boundary before native calls. Return only fixed error codes.

- [ ] **Step 4: Lock the self-audit exception to the exact adapter**

Add AST tests proving the committed adapter is accepted while a copied module that adds another DLL name, native API, dynamic import, or ctypes reference yields `NATIVE_CAPABILITY` or `SOURCE_POLICY_VIOLATION`. Keep all existing arbitrary-ctypes tests unchanged.

- [ ] **Step 5: Run focused tests and commit**

Run: `python -B -m pytest -q -p no:cacheprovider tests/test_windows_dpapi.py tests/test_self_audit.py`

Expected: all focused tests pass and `static_capability_findings()` remains empty for the repository source.

Commit: `Add constrained Windows DPAPI adapter`

## Task 3: Persist One Protected State Atomically

**Files:**
- Create: `src/agentguardian/state_store.py`
- Create: `tests/test_state_store.py`

- [ ] **Step 1: Write failing store tests**

Require explicit save/load under a supplied temporary directory using injected protect/unprotect callables. Assert a successful replacement returns the decoded snapshot; no plaintext marker appears on disk; a corrupt, oversized, symlinked, or reparse target fails with a fixed error; and a failed replacement leaves the previous state readable.

- [ ] **Step 2: Verify the red state**

Run: `python -B -m pytest -q -p no:cacheprovider tests/test_state_store.py`

Expected: collection fails because `agentguardian.state_store` does not exist.

- [ ] **Step 3: Implement bounded protected storage**

Use `%LOCALAPPDATA%\AgentGuardian\evidence-state-v1.bin` as the default only when no explicit test directory is supplied. Create the app directory only during an explicit save, reject UNC/reparse/symlink paths, write an exclusive temporary file, flush and `fsync`, then `os.replace`. Never log or include paths in exceptions.

- [ ] **Step 4: Implement fail-closed loading**

Read at most 1 MiB plus one byte, reject missing/oversized/corrupt content with fixed errors, decrypt once, validate the complete snapshot, and return no partial object.

- [ ] **Step 5: Run focused tests and commit**

Run: `python -B -m pytest -q -p no:cacheprovider tests/test_state_store.py tests/test_evidence_state.py tests/test_windows_dpapi.py`

Expected: all focused tests pass.

Commit: `Persist protected evidence state atomically`

## Task 4: Add Explicit Desktop Consent

**Files:**
- Modify: `src/agentguardian/app.py`
- Modify: `tests/test_app_smoke.py`

- [ ] **Step 1: Write failing UI behavior tests**

Require no state-store call during application startup or `_run_audit`. After a completed audit, an explicit save control invokes the store once with the in-memory findings/score and current rule version. Fixed success/failure text must not include a path, native error, finding value, or endpoint.

- [ ] **Step 2: Verify the red state**

Run: `python -B -m pytest -q -p no:cacheprovider tests/test_app_smoke.py -k "protected_state"`

Expected: tests fail because the explicit save action is absent.

- [ ] **Step 3: Add the minimal explicit action**

Add one report-page save control that is disabled before a completed audit and enabled afterward. It writes only after the user activates it; do not add auto-save, startup load, background task, history browser, or cloud behavior.

- [ ] **Step 4: Run UI and boundary tests and commit**

Run: `python -B -m pytest -q -p no:cacheprovider tests/test_app_smoke.py tests/test_state_store.py tests/test_self_audit.py`

Expected: all focused tests pass.

Commit: `Add explicit protected state save action`

## Task 5: Synchronize Evidence and Close Batch 2

**Files:**
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/reports/alpha-0.1.0-stage-report.md`
- Modify: `docs/superpowers/plans/2026-08-02-agentguardian-windows-mvp-hardening.md`
- Modify: `tests/test_self_audit.py`

- [ ] **Step 1: Add documentation assertions**

Require docs to state current-user DPAPI scope, explicit save, excluded fields, fixed failure behavior, same-user compromise limitation, no API calls, and non-production status.

- [ ] **Step 2: Run the complete local gate**

Run: `python -B -m pytest -q -p no:cacheprovider`

Run: `python -B scripts/check_brand_assets.py`

Run: `python -B -m compileall -q src`

Run: `git diff --check`

Expected: zero failures and zero whitespace errors.

- [ ] **Step 3: Run independent read-only review**

Review schema minimization, native-memory cleanup, self-audit allowlist precision, path/reparse defenses, failure behavior, synthetic-only tests, and the no-network/no-LLM boundary. Resolve all Important findings before submission.

- [ ] **Step 4: Commit, push, and verify remote evidence**

Push `agent/founder-alpha`, wait for push and Draft PR workflows, inspect check-run annotations, and record exact final SHA/run IDs. Keep Batch 3-6 open and do not claim Windows MVP or production safety.
