# AgentGuardian Windows MVP Release-Candidate Report

Status date: 2026-08-14

Release-candidate decision: `NO-GO`.

Windows MVP remains incomplete. Production safety is not established.

## Candidate Boundary

- Local gate implementation baseline: `f42a56d8cc20632e12ea6e21e8f64ffbf7be6cd8`.
- The implementation adds release-support scripts, tests, a threat model, and plans. It does not modify `src/agentguardian`.
- OpenAI Provider remains local detection and manual guidance only; the default product path makes no provider API call and performs no endpoint verification.
- The local remote-tracking reference was `9577a85fb107a7de506fd67ce48ce795bc707678` when this report was prepared. That local reference is not live GitHub verification and does not cover the candidate baseline.

## Current Local Evidence

| Gate | Current revalidation | Scope |
| --- | --- | --- |
| Security gate contract | `17 passed` | Threat IDs, test-node resolution, bounded local command, performance evidence contract, and documentation boundaries. |
| Selected negative security gate | `42 passed, 1 skipped` | AG-T01 through AG-T11 selected tests. The skip is preserved as a skip, not reported as a pass. |
| Python 3.14 full suite | `1315 passed, 8 skipped` | Current source and evidence-synchronization documentation. |
| Hash-locked Python 3.12 full suite | `1314 passed, 9 skipped` | Current source and evidence-synchronization documentation. The additional skip is the build-only CycloneDX integration. |
| Brand validation | Exit 0 | Existing brand-asset contract. |
| Source and script compilation | Exit 0 | `python -B -m compileall -q src scripts`. |
| Package-source self-audit | `findings=[]`, `local_only=true`, `network_capability=not_detected`, `ordinary_user_mode=true` | Source policy only; dependencies and binaries are not scanned. |

## Performance Evidence

Both files are ignored local artifacts under `.analysis` and bind the clean exact implementation SHA. They contain synthetic observations only and are not committed.

| Interpreter | Evidence SHA-256 | Worst scan | Worst report | Report bytes | Result |
| --- | --- | ---: | ---: | ---: | --- |
| CPython 3.14.0 | `6784865c45594b1b1f1d2c5694ae096a1763fd6549359a9c7bf45a86a6b0f1fa` | 3.558150 s / 11,684,018 traced bytes | 0.210084 s / 2,620,794 traced bytes | 468,300 | `passed=true` |
| CPython 3.12.2 | `7c78bd688670e1a39594e7ebba5761ad4298b79db60ee259e0048660ba25ab64` | 3.282711 s / 11,193,211 traced bytes | 0.383934 s / 3,867,210 traced bytes | 468,300 | `passed=true` |

The scan workload audits 1,000 synthetic harmless files three times with limits of 15.0 seconds and 48 MiB traced Python allocation per run. The report workload renders and parses 1,000 synthetic findings three times with limits of 3.0 seconds, 16 MiB traced Python allocation, and 1 MiB UTF-8 output per run.

This evidence does not cover the 10,000-file functional maximum, whole-process resident memory, slow disks, antivirus variance, native installer startup, a fresh runner, or a clean Windows machine.

## Pending Gates

- Independent read-only review: `PENDING`.
- Current exact-SHA GitHub CI: `PENDING`.
- Fresh-runner provenance: `PENDING`.
- Trusted code signing: `PENDING`.
- Native install and uninstall: `PENDING`.
- Clean Windows machine acceptance and residue review: `PENDING`.
- License and redistribution review: `PENDING`.

Workflow changes remain blocked until exact `APPROVE_GITHUB_WORKFLOW_SCOPE_REFRESH` authorization. No workflow was edited, no branch was pushed, no artifact was published, no certificate material was requested or handled, and no release or deployment was performed for this evidence.

## Decision

The local threat-model, selected security, and fixed performance increments are supported by current local evidence. Batch 5 external release controls and Batch 6 independent, remote, and external gates are absent. Therefore the release-candidate decision remains `NO-GO`.
