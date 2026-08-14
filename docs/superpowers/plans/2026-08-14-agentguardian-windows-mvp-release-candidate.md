# AgentGuardian Windows MVP Release Candidate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a fail-closed Batch 6 evidence gate without changing AgentGuardian's local-only runtime boundary or prematurely claiming Windows MVP completion.

**Architecture:** A stable threat model names local controls and external blockers. Small scripts run selected negative security cases and fixed synthetic performance workloads. A final report binds every observation to an exact commit and remains `NO-GO` when any required evidence is missing or stale.

**Tech Stack:** Python 3.12 and 3.14, pytest, standard-library `subprocess`, `time`, `tracemalloc`, `json`, `tempfile`, and Markdown evidence.

---

### Task 1: Threat Model And Selected Negative Security Gate

**Files:**
- Create: `docs/security/windows-mvp-threat-model.md`
- Create: `scripts/run_windows_mvp_security_gate.py`
- Create: `tests/test_windows_mvp_security_gate.py`

- [x] **Step 1: Write the failing gate contract tests**

Require stable threat IDs, unique explicit pytest selectors that resolve to real test functions, a local bounded command, and an AG-T12 external-blocker row.

- [x] **Step 2: Verify the tests fail because the runner and model are absent**

Run: `python -B -m pytest -q -p no:cacheprovider tests/test_windows_mvp_security_gate.py`

Expected: collection fails because `scripts.run_windows_mvp_security_gate` does not exist.

- [x] **Step 3: Implement the minimal local runner and threat model**

Use a fixed tuple of threat IDs and pytest node IDs. Invoke the current interpreter with `subprocess.run`, no shell, no network, no dynamic selector input, and return pytest's exit code.

- [x] **Step 4: Run the contract and selected security gates**

Run: `python -B -m pytest -q -p no:cacheprovider tests/test_windows_mvp_security_gate.py`

Run: `python -B scripts/run_windows_mvp_security_gate.py`

Expected: both commands exit 0.

### Task 2: Fixed Synthetic Performance Gate

**Files:**
- Create: `scripts/measure_windows_mvp_performance.py`
- Create: `tests/test_windows_mvp_performance_gate.py`
- Modify: `docs/security/windows-mvp-threat-model.md`

- [x] **Step 1: Write failing tests for fixed workloads and canonical evidence**

Require immutable scan and report workloads, positive explicit budgets, canonical JSON with exact commit and interpreter identity, no real user paths, and nonzero exit when an observation exceeds its budget.

- [x] **Step 2: Measure the unmodified baseline before setting budgets**

Run each workload repeatedly on Python 3.12 and 3.14 from ignored temporary directories. Record median and worst observations. Set conservative budgets above observed noise; do not hide a functional failure by increasing a timeout.

- [x] **Step 3: Implement the minimal measurement command**

Use synthetic files, `time.perf_counter`, `tracemalloc`, and the existing public or package-local audit/report functions. Write evidence only to an explicit ignored output path and reject an existing destination.

- [x] **Step 4: Run focused tests and both performance gates**

Run the focused contract tests, then the command on Python 3.12 and 3.14. Expected: tests pass, both measurements remain within fixed budgets, and both evidence files identify the exact local commit.

### Task 3: Local Release-Candidate Evidence Report

**Files:**
- Create: `docs/reports/windows-mvp-release-candidate-report.md`
- Modify: `tests/test_self_audit.py`
- Modify: `README.md`
- Modify: `docs/reports/alpha-0.1.0-stage-report.md`
- Modify: `docs/superpowers/plans/2026-08-02-agentguardian-windows-mvp-hardening.md`

- [x] **Step 1: Write failing documentation assertions**

Require exact local implementation SHA, security and performance command results, dual-Python full-suite results, self-audit result, remote evidence status, independent-review status, AG-T12 status, and an explicit `NO-GO` decision whenever one is absent.

- [x] **Step 2: Run all local gates on one clean exact baseline**

Run selected security, performance, full dual-Python, self-audit, packaging, brand, compile, and diff checks without changing source between evidence runs.

Unified local evidence baseline `62de8ae81c27e146e3a2e8b831d85c41ac9f71d4` passed the selected security gate, both fixed performance gates, both supported Python full suites, two reproducible portable builds, two isolated launch/cleanup smokes, package-source self-audit, brand validation, compilation, and diff checks. This is local evidence only; later documentation synchronization is not automatically covered.

- [x] **Step 3: Write the evidence report and synchronize status documents**

Record only current observations. Historical CI remains historical. Keep Founder Alpha, Windows MVP incomplete, and non-production-safe language until every gate passes.

### Task 4: Independent Read-Only Review

**Files:**
- Modify after review: `docs/reports/windows-mvp-release-candidate-report.md`

- [ ] **Step 1: Commission a separate read-only review**

The reviewer inspects the exact diff, threat coverage, test selection, performance methodology, local evidence, residual risks, and release claims. The reviewer does not edit the implementation.

- [ ] **Step 2: Resolve all important findings locally**

Use a new failing regression test for each code defect, rerun affected gates, and preserve unresolved findings as blockers.

### Task 5: External Release Evidence

**Files:**
- Modify only after separate authorization: `.github/workflows/ci.yml` or a dedicated release workflow
- Create only after installer and signing approval: native installer definition
- Modify after evidence: `docs/reports/windows-mvp-release-candidate-report.md`

- [ ] **Step 1: Obtain `APPROVE_GITHUB_WORKFLOW_SCOPE_REFRESH`**

Do not edit or push workflow files before exact authorization.

- [ ] **Step 2: Verify exact-SHA remote CI and fresh-runner provenance**

Build and verify on separate pinned Windows runners, attest the exact artifact digest, and bind retained logs to the exact candidate SHA.

- [ ] **Step 3: Complete signing, licensing, native install, and uninstall evidence**

Use an approved trusted code-signing method and timestamp. Verify standard-user install, launch, uninstall, declared-state policy, residue, and redistribution rights on a clean Windows machine.

- [ ] **Step 4: Make the release-candidate decision**

Only an exact-SHA report with every local, independent, remote, and external gate passed may change `NO-GO` to Windows MVP release candidate. This decision still does not establish production safety.
