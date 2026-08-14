# AgentGuardian Windows MVP Release-Candidate Report

Status date: 2026-08-14

Release-candidate decision: `NO-GO`.

Windows MVP remains incomplete. Production safety is not established.

## Candidate Boundary

- Local gate implementation baseline: `f42a56d8cc20632e12ea6e21e8f64ffbf7be6cd8`.
- Unified local evidence baseline: `62de8ae81c27e146e3a2e8b831d85c41ac9f71d4`.
- The implementation adds release-support scripts, tests, a threat model, and plans. It does not modify `src/agentguardian`.
- Any later documentation/tests-only evidence synchronization commit is not automatically covered by the cited baseline results.
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
| Portable reproducibility | `208 files` and `92,869,602 bytes` in each bundle; Bundle diff count: `0`; both ZIPs were `36,032,907 bytes` with SHA-256 `48a05bab1cdd93b7ec3264b6e506a9df55fc004b82a7f4f262a3567aed5e97fb` | Two new build roots, one hash-locked Python 3.12.2/PyInstaller 6.16.0 environment, the same source SHA, and the same explicit canonical build time. PyInstaller work/spec intermediates are excluded. |
| Portable isolation smoke | Both copied bundles reported `process_startup=true`, `bounded_liveness=true`, `termination=forced_after_bounded_smoke`, and `declared_residue=false` | Four-second offscreen local smoke with isolated `APPDATA`, `LOCALAPPDATA`, `TEMP`, and `TMP`; not clean-machine acceptance. |
| Package-source self-audit | Both bundles returned `findings=[]`, `local_only=true`, `network_capability=not_detected`, `ordinary_user_mode=true` | Reviewed copied source policy only; dependencies and binaries are not scanned. |

## Performance Evidence

Both files are ignored local artifacts under `.analysis` and bind the clean exact implementation SHA. They contain synthetic observations only and are not committed.

| Interpreter | Evidence SHA-256 | Worst scan | Worst report | Report bytes | Result |
| --- | --- | ---: | ---: | ---: | --- |
| CPython 3.14.0 | `33831121efbc1f8cbf5771e0a03428784769c94677456eabe54ef003ceafbbb4` | 5.426514 s / 11,680,955 traced bytes | 0.241068 s / 2,620,866 traced bytes | 468,300 | `passed=true` |
| CPython 3.12.2 | `ed9bd8f801cc360e0a088ece36219f17ae17f098a92035a4a121e898e96abeda` | 3.433295 s / 11,196,811 traced bytes | 0.251267 s / 3,859,694 traced bytes | 468,300 | `passed=true` |

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

The local threat-model, selected security, fixed performance, reproducible portable build, isolated launch/cleanup, and package-source increments are supported by the unified local evidence baseline. Batch 5 external release controls and Batch 6 independent, remote, and external gates are absent. Therefore the release-candidate decision remains `NO-GO`.
