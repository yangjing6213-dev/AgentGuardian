# AgentGuardian Windows MVP Release-Candidate Report

Status date: 2026-08-15

Release-candidate decision: `NO-GO`.

Windows MVP remains incomplete. Production safety is not established.

## Candidate Boundary

- Local gate implementation and unified local evidence baseline: `392ff64f3bcb3f978874e668a97e5a3f013b762e`.
- The implementation adds release-support scripts, tests, a threat model, and plans. It does not modify `src/agentguardian`.
- The independent review of the previous evidence-sync HEAD found 7 Important and 2 Minor findings. The Important findings were locally remediated in this baseline; a fresh independent re-review remains pending.
- OpenAI Provider remains local detection and manual guidance only; the default product path makes no provider API call and performs no endpoint verification.
- The local remote-tracking reference was `9577a85fb107a7de506fd67ce48ce795bc707678` when this report was prepared. That local reference is not live GitHub verification and does not cover the candidate baseline.

## Current Local Evidence

| Gate | Current revalidation | Scope |
| --- | --- | --- |
| Security gate contract | `21 passed` | Threat IDs, test-node resolution, isolated pytest environment, timeout, explicit skip allowlist, performance evidence contract, and documentation boundaries. |
| Selected negative security gate | `47 passed, 1 skipped` | AG-T01 through AG-T11 selected tests. The only allowed skip is AG-T09 directory symlink unavailable; it is not reported as a full pass. |
| Python 3.14 full suite | `1321 passed, 8 skipped` | Current implementation and evidence-synchronization documentation. |
| Hash-locked Python 3.12 full suite | `1320 passed, 9 skipped` | Current implementation and evidence-synchronization documentation. The additional skip is the build-only CycloneDX integration. |
| Brand validation | Exit 0 | Existing brand-asset contract. |
| Source and script compilation | Exit 0 | `python -B -m compileall -q src scripts`. |
| Portable reproducibility | `208 files` and `92,870,198 bytes` in each bundle; Bundle diff count: `0`; both ZIPs were `36,033,202 bytes` with SHA-256 `d18d2cb0ced769b4878a75767a40149033fdf08ce968c04797a77b4f1590d368` | Two new build roots, one hash-locked Python 3.12.2/PyInstaller 6.16.0 environment, actual lock dependency versions recorded with lock SHA `75be59ee054a75d556cc89099f571d9826fa272aef656124fa75dc535731cdd5`, the same source SHA, and the same explicit canonical build time. PyInstaller work/spec intermediates are excluded. |
| Portable isolation smoke | Both copied bundles reported `process_startup=true`, `bounded_liveness=true`, `termination=forced_after_bounded_smoke`, `process_tree_terminated=true`, and `declared_residue=false` | Four-second offscreen local smoke with isolated `APPDATA`, `LOCALAPPDATA`, `TEMP`, `TMP`, `USERPROFILE`, and `PROGRAMDATA`; durable evidence binds source, bundle, ZIP, and verifier hashes. Evidence JSON SHA-256: L `84444754a34b60d91f7fef9b94c9f95a036768ec0be4dee101942fb841000b36`, M `ae5dd51e1cd4e0e7fb90ba3814f24573e1d2fa25a1dedf91e597c13f92022cf5`. This is not clean-machine acceptance. |
| Package-source self-audit | Both bundles returned `findings=[]`, `local_only=true`, `network_capability=not_detected`, `ordinary_user_mode=true` | Reviewed copied source policy only; dependencies and binaries are not scanned. |

## Performance Evidence

Both files are ignored local artifacts under `.analysis` and bind the clean exact implementation SHA. They contain synthetic observations only and are not committed.

| Interpreter | Evidence SHA-256 | Worst scan | Worst report | Report bytes | Result |
| --- | --- | ---: | ---: | ---: | --- |
| CPython 3.14.0 | `0c9a0ee0d8a853d7f955da199f44375bfbf751b64eab11a6b9d8486e5d7d2347` | 5.389549 s / 11,683,217 traced bytes | 0.307798 s / 2,689,051 traced bytes | 468,300 | `passed=true` |
| CPython 3.12.2 | `920cef81c155b2f660d491f86d703d0f8bd6b8f1fd387767bba8baded6e33e6e` | 7.285332 s / 11,194,609 traced bytes | 0.332064 s / 3,867,160 traced bytes | 468,300 | `passed=true` |

The scan workload audits 1,000 synthetic harmless files three times with limits of 15.0 seconds and 48 MiB traced Python allocation per run. The report workload renders and parses 1,000 synthetic findings three times with limits of 3.0 seconds, 16 MiB traced Python allocation, and 1 MiB UTF-8 output per run.

This evidence does not cover the 10,000-file functional maximum, whole-process resident memory, slow disks, antivirus variance, native installer startup, a fresh runner, or a clean Windows machine.

## Pending Gates

- Independent read-only review: `COMPLETED WITH 7 IMPORTANT FINDINGS` on the prior evidence-sync HEAD; local remediation is bound to the current baseline.
- Independent re-review: `PENDING`.
- Current exact-SHA GitHub CI: `PENDING`.
- Fresh-runner provenance: `PENDING`.
- Trusted code signing: `PENDING`.
- Native install and uninstall: `PENDING`.
- Clean Windows machine acceptance and residue review: `PENDING`.
- License and redistribution review: `PENDING`.

Workflow changes remain blocked until exact `APPROVE_GITHUB_WORKFLOW_SCOPE_REFRESH` authorization. No workflow was edited, no branch was pushed, no artifact was published, no certificate material was requested or handled, and no release or deployment was performed for this evidence.

## Decision

The local threat-model, selected security, fixed performance, reproducible portable build, isolated launch/cleanup, dependency-lock, and package-source increments are supported by the current local evidence baseline. The first independent review found 7 Important and 2 Minor findings; the Important items were remediated locally, but independent re-review is absent. Batch 5 external release controls and Batch 6 remote and external gates are absent. Therefore the release-candidate decision remains `NO-GO`.
