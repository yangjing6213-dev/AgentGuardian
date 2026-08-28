# AgentGuardian Windows MVP Release Candidate Gate Design

Status: approved Windows MVP roadmap continuation; Batch 6 implementation in progress.

## Goal

Create a fail-closed, reproducible evidence path for deciding whether AgentGuardian may be called a Windows MVP release candidate. The gate must keep local evidence, remote CI evidence, independent review, and externally supplied release evidence distinct. It must never convert a passing local test into a production-safety claim.

## Architecture

Batch 6 has four independent evidence layers:

1. A versioned threat model maps every in-scope threat to controls, selected negative tests, status, and residual risk.
2. A local security gate runs the selected negative pytest node IDs without changing runtime behavior or using the network.
3. A deterministic performance gate measures fixed synthetic scan and report workloads against explicit wall-clock, traced Python-memory, and output-size budgets. Performance evidence records interpreter, commit, workload, limits, and observations; it does not weaken functional limits. Portable artifact size and startup evidence remain in the packaging and clean-machine gates.
4. A release-candidate report aggregates exact local and remote evidence. Any absent, stale, mismatched, or externally blocked item produces `NO-GO`.

The product package under `src/agentguardian` remains unchanged unless a negative test exposes a concrete defect. Gate scripts live under `scripts`, security documentation under `docs/security`, and gate contract tests under `tests`.

## Security Gate Contract

Threat IDs `AG-T01` through `AG-T12` are stable. AG-T01 through AG-T11 have locally runnable controls. AG-T12 covers trusted build provenance, signing identity and timestamp, clean-machine native installation and uninstall, and redistribution rights; it cannot pass from local unit tests.

The local runner uses `subprocess.run` with an argument tuple, `shell=False` by default, the current Python interpreter, repository-root working directory, and explicit pytest node IDs. It does not discover arbitrary commands, accept user-controlled selectors, alter workflows, or upload results.

## Failure Behavior

- A missing or renamed selected test fails the gate contract test.
- A selected negative test failure returns pytest's nonzero exit code.
- A missing threat row or external blocker fails the documentation contract.
- Performance observations over budget fail the future performance command; a timeout increase is not an acceptable defect fix.
- Missing independent or external evidence leaves the release-candidate decision at `NO-GO`.

## Non-Goals

- No OpenAI API or third-party provider call.
- No GitHub workflow edit or push without separate workflow-scope authorization.
- No certificate creation, retrieval, display, or storage.
- No native installer selection before signing and installation constraints are confirmed.
- No claim that Founder Alpha, Batch 6, Windows MVP, or production safety is complete.

## Verification

The selected security gate, its contract tests, both supported Python full suites, self-audit, brand checks, compilation, and `git diff --check` must pass on the exact local source. A separate read-only reviewer must inspect the threat model, selected tests, performance evidence, release report, and diff. Current GitHub CI and external release gates must be verified against the exact candidate SHA.
