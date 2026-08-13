# AgentGuardian Windows Portable Packaging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce and verify an unsigned, inspectable Windows portable package without changing AgentGuardian's local-only runtime boundary.

**Architecture:** A small standard-library build script constructs a fixed PyInstaller `onedir` command, validates the reviewed source set, generates canonical manifests, and creates a deterministic ZIP. PyInstaller and SBOM tooling live in a separate hash-locked build dependency file. Native installation, trusted signing, GitHub provenance, and release-candidate claims remain separately gated.

**Tech Stack:** Windows, Python 3.12, PyInstaller 6.16, PySide6, CycloneDX JSON, pytest, standard-library `hashlib`, `json`, `subprocess`, and `zipfile`.

---

### Task 1: Lock The Portable Build Contract

**Files:**
- Create: `tests/test_windows_packaging.py`
- Create: `scripts/build_windows_portable.py`
- Modify: `src/agentguardian/__main__.py`
- Modify: `src/agentguardian/source_policy.json`

- [x] **Step 1: Write failing tests for the fixed build command**

Require `--onedir`, `--windowed`, `--noupx`, a fixed name, all reviewed `.py` source copies, rules, policy, and the package path. Reject `--onefile`, `--uac-admin`, and any missing reviewed module.

- [x] **Step 2: Verify the red state**

Run: `py -3.12 -m pytest -q -p no:cacheprovider tests/test_windows_packaging.py`

Expected: collection fails because `scripts.build_windows_portable` does not exist.

- [x] **Step 3: Implement the minimal command builder**

Add pure functions that load and validate `source_policy.json`, compare its module names with `src/agentguardian/*.py`, and return the PyInstaller argument list. Use the existing package `__main__.py` as the only entry point, changing its import to absolute form so it can be analyzed as a script without adding an unaudited launcher.

- [x] **Step 4: Refresh the source policy and verify green**

Update only the canonical hash for `__main__.py`, then run the focused test and `tests/test_self_audit.py`.

### Task 2: Lock Build Dependencies

**Files:**
- Create: `requirements-build.lock`
- Modify: `tests/test_windows_packaging.py`

- [x] **Step 1: Write a failing lock contract test**

Require the build lock to include `requirements-dev.lock`, exact versions and SHA-256 hashes for PyInstaller and its direct Windows dependencies, and no index URL, editable install, VCS URL, or unhashed requirement.

- [x] **Step 2: Generate the Windows Python 3.12 lock evidence**

Download binary distributions for the exact selected versions into an ignored temporary directory, compute SHA-256, write the lock with exact pins, then prove `py -3.12 -m pip install --dry-run --require-hashes -r requirements-build.lock` succeeds.

- [x] **Step 3: Run the focused lock test**

Expected: all focused packaging tests pass without importing or invoking PyInstaller.

### Task 3: Generate Canonical Package Evidence

**Files:**
- Modify: `scripts/build_windows_portable.py`
- Modify: `tests/test_windows_packaging.py`

- [x] **Step 1: Write failing synthetic tests**

Require sorted relative paths, SHA-256 and size for every bundle file; reject absolute paths, `..`, symlinks/reparse points, duplicate case-insensitive paths, and generated absolute workspace paths. Require canonical JSON and byte-identical ZIPs from two synthetic trees with different file mtimes.

- [x] **Step 2: Verify the red state**

Run the exact new test nodes and confirm failures are caused by missing manifest and ZIP functions.

- [x] **Step 3: Implement manifest and ZIP generation**

Use `Path.rglob`, `hashlib.sha256`, `json.dumps(sort_keys=True, separators=(",", ":"))`, fixed ZIP timestamps, fixed permissions, and sorted POSIX paths. Keep the functions independent of PyInstaller so unit tests remain fast.

- [x] **Step 4: Verify green**

Run all `tests/test_windows_packaging.py` tests.

### Task 4: Add SBOM And License Evidence

**Files:**
- Modify: `requirements-build.lock`
- Modify: `scripts/build_windows_portable.py`
- Modify: `tests/test_windows_packaging.py`
- Create: `THIRD_PARTY_NOTICES.md`

- [x] **Step 1: Write failing component tests**

Require the SBOM to identify AgentGuardian, Python, PySide6, shiboken6, PyInstaller, and every installed component represented in the frozen package; require license identifiers or an explicit `NOASSERTION`; require Qt and PyInstaller notices and no absolute paths or secret-like values.

- [x] **Step 2: Add hash-locked CycloneDX tooling**

Pin the selected CycloneDX tool and all transitive dependencies with hashes in `requirements-build.lock`. Do not add them to `pyproject.toml` runtime dependencies.

- [ ] **Step 3: Generate and validate evidence**

Generate CycloneDX JSON from the isolated build environment, copy project and third-party notices, validate component coverage, then include them before creating the artifact manifest and ZIP.

### Task 5: Build And Rebuild On Windows Python 3.12

**Files:**
- Modify: `scripts/build_windows_portable.py`
- Modify: `tests/test_windows_packaging.py`
- Modify: `.gitignore` only if a new generated path is not already ignored

- [x] **Step 1: Create an isolated hash-locked build environment**

Create it under ignored `.analysis`, install `requirements-build.lock` with `--require-hashes`, and install AgentGuardian editable with `--no-build-isolation --no-deps` only for analysis.

- [ ] **Step 2: Build from a clean commit twice**

Run the build in two separate ignored directories with the same source commit and environment. No build output is committed.

- [ ] **Step 3: Verify the frozen package**

Check the executable, reviewed sources, rules, policy, licenses, SBOM, manifest, and hashes. Run package-source self-audit from the frozen layout and ensure it remains `findings=[]`, `local_only=true`, and `network_capability=not_detected`.

- [ ] **Step 4: Compare rebuilds**

Require identical relative file sets, file hashes, and ZIP hashes. A mismatch blocks Batch 5 layer 1 and is reported rather than waived.

### Task 6: Launch And Cleanup Smoke

**Files:**
- Create: `scripts/verify_windows_portable.ps1`
- Modify: `tests/test_windows_packaging.py`

- [ ] **Step 1: Add a verifier contract test**

Require isolated `APPDATA`, `LOCALAPPDATA`, `TEMP`, and `TMP`; launch only the copied package; detect immediate exit; terminate the bounded smoke process; remove the package and isolated state; and fail when any declared path remains.

- [ ] **Step 2: Run the verifier on one rebuilt artifact**

Record process startup, bounded liveness, termination, and zero declared residue. This is a local smoke, not clean-machine acceptance.

### Task 7: Synchronize Local Evidence

**Files:**
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/reports/alpha-0.1.0-stage-report.md`
- Modify: `docs/superpowers/plans/2026-08-02-agentguardian-windows-mvp-hardening.md`
- Modify: `tests/test_self_audit.py`

- [ ] **Step 1: Add failing documentation assertions**

Require documents to distinguish the accepted portable layer from pending trusted signing, native installation, fresh-runner acceptance, Batch 6, and production safety.

- [ ] **Step 2: Run local gates**

Run focused packaging/self-audit tests, the complete Python 3.12 and 3.14 suites, brand validation, compile, package-source self-audit, `git diff --check`, and the Ponytail/YAGNI review.

- [ ] **Step 3: Commit only verified local changes**

Stage an explicit file list and create an atomic local commit. Do not push, modify GitHub workflows, publish artifacts, mark the PR ready, merge, tag, release, or claim Windows MVP completion.

### Task 8: Fresh Runner, Provenance, Native Installer, And Signing

**Files:**
- Modify later with separate authorization: `.github/workflows/ci.yml` or a dedicated release workflow
- Create later after installer selection: native installer definition

- [ ] **Step 1: Obtain separate GitHub workflow-scope authorization**

Do not edit or push workflow files until the credential and workflow scope are explicitly approved.

- [ ] **Step 2: Add separate-runner artifact verification and provenance**

Build on one pinned Windows runner, verify on a fresh runner, attest the exact artifact digest, and retain logs bound to the commit.

- [ ] **Step 3: Obtain an approved trusted code-signing method**

Do not create, request, print, or commit certificate material. Select MSIX/MSI only after signing and user-install constraints are confirmed.

- [ ] **Step 4: Complete native install/uninstall acceptance**

Verify standard-user installation, signature and timestamp, launch, uninstall, declared-state retention policy, and residue on a clean Windows machine. Only then may Batch 5 be considered complete.
