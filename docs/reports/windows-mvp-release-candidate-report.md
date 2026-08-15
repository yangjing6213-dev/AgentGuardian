# AgentGuardian Windows MVP Release-Candidate Report

Status date: 2026-08-15

Release-candidate decision: `NO-GO`.

Windows MVP remains incomplete. Production safety is not established.

## Candidate Boundary

- Local gate implementation and unified local evidence baseline: `90e6edad53bee48adca58d508d193fc855c1db7d`.
- The implementation adds release-support scripts, tests, a threat model, and plans. It does not modify `src/agentguardian`.
- The first independent review of the previous evidence-sync HEAD found 7 Important and 2 Minor findings. A second independent review of `305eeb4e1a143a245323a9b54d8fe27314a4e16c` found 2 further Important findings; both were remediated in `90e6eda`. A focused third independent re-review found no Critical or Important findings and one Minor; it did not execute tests independently.
- OpenAI Provider remains local detection and manual guidance only; the default product path makes no provider API call and performs no endpoint verification.
- The local remote-tracking reference was `9577a85fb107a7de506fd67ce48ce795bc707678` when this report was prepared. That local reference is not live GitHub verification and does not cover the candidate baseline.

## Current Follow-up Evidence

The current code-bearing hardening SHA is `253b77d1f46b63f1761fd8ac56c9fb6f49555d22`.
Its local full regression is `1404 passed, 11 skipped`; the Windows workflow
reported `1414 passed, 1 skipped`, and the synthetic high-sensitivity gate
reported `passed=true` with no raw markers in reports/findings, browser
temporary-copy removal, and workspace cleanup. The Windows AppContainer
integration proves loopback connection denial and transient profile cleanup;
the native MCP path also rejects an adapter without a locally trusted embedded
Authenticode signature.

The current documentation HEAD is `5a486118d45c27fe500b8dc5d903a9d5a3e741b7`.
Its push and Draft PR CI plus Windows package checks all completed
successfully. The Windows smoke evidence records install, same-identity
upgrade `0.1.0.0 -> 0.1.0.1`, termination, uninstall, and
`package_residue=false`. The package is explicitly `unsigned_ci_smoke` and
must not be treated as a trusted release artifact.

## Current Local Evidence

| Gate | Current revalidation | Scope |
| --- | --- | --- |
| Security gate contract | `22 passed` | Threat IDs, test-node resolution, isolated pytest environment, timeout, collection- and runtime-skip handling, performance evidence contract, and documentation boundaries. |
| Selected negative security gate | `47 passed, 1 skipped` | AG-T01 through AG-T11 selected tests. The only allowed skip is AG-T09 directory symlink unavailable; it is not reported as a full pass. |
| Python 3.14 full suite | `1322 passed, 8 skipped` | Current implementation and evidence-synchronization documentation. |
| Hash-locked Python 3.12 full suite | `1321 passed, 9 skipped` | Current implementation and evidence-synchronization documentation. The additional skip is the build-only CycloneDX integration. |
| Brand validation | Exit 0 | Existing brand-asset contract. |
| Source and script compilation | Exit 0 | `python -B -m compileall -q src scripts`. |
| Portable reproducibility | `208 files` and `92,870,198 bytes` in each bundle; Bundle diff count: `0`; both ZIPs were `36,033,202 bytes` with SHA-256 `4f7e9ffdd347fddf67ffb7544ab84e777ff7b93e2ed1bf546ed87e6e9517bad1` | Two new build roots, one hash-locked Python 3.12.2/PyInstaller 6.16.0 environment, actual lock dependency versions recorded with lock SHA `75be59ee054a75d556cc89099f571d9826fa272aef656124fa75dc535731cdd5`, source SHA `90e6eda`, and fixed build time `2026-08-15T00:00:00Z`. PyInstaller work/spec intermediates are excluded. |
| Portable isolation smoke | Both copied bundles reported `process_startup=true`, `bounded_liveness=true`, `termination=forced_after_bounded_smoke`, `process_tree_terminated=true`, and `declared_residue=false` | Four-second offscreen local smoke with isolated `APPDATA`, `LOCALAPPDATA`, `TEMP`, `TMP`, `USERPROFILE`, and `PROGRAMDATA`; the verifier enumerates the process tree before termination and confirms the captured process IDs are gone after taskkill. Durable evidence binds source, bundle, ZIP, and verifier hashes. Evidence JSON SHA-256: L `8ed7fe9a1e9fc43ee7fcf0c32cc4de3bceb9042695080d11c59451ae163cf034`, M `cd4317b9881aec914efe7090cf9d7324c4adf5803931ad4704e1776986a433c9`. This is not clean-machine acceptance. |
| Package-source self-audit | Both bundles returned `findings=[]`, `local_only=true`, `network_capability=not_detected`, `ordinary_user_mode=true` | Reviewed copied source policy only; dependencies and binaries are not scanned. |

## Performance Evidence

Both files are ignored local artifacts under `.analysis` and bind the clean exact implementation SHA. They contain synthetic observations only and are not committed.

| Interpreter | Evidence SHA-256 | Worst scan | Worst report | Report bytes | Result |
| --- | --- | ---: | ---: | ---: | --- |
| CPython 3.14.0 | `fe4689ae792246e6d48a51e5018b8125f64a3a2e2b3f83cf85c755bb9bc8cdd3` | 3.334307 s / 11,683,193 traced bytes | 0.210019 s / 2,694,251 traced bytes | 468,300 | `passed=true` |
| CPython 3.12.2 | `fa77cf277736912ccfe4d8c36635d557b6803bbeff95a5c116b1fe3e41d617fd` | 3.502715 s / 11,206,948 traced bytes | 0.256567 s / 3,867,352 traced bytes | 468,300 | `passed=true` |

The scan workload audits 1,000 synthetic harmless files three times with limits of 15.0 seconds and 48 MiB traced Python allocation per run. The report workload renders and parses 1,000 synthetic findings three times with limits of 3.0 seconds, 16 MiB traced Python allocation, and 1 MiB UTF-8 output per run.

This evidence does not cover the 10,000-file functional maximum, whole-process resident memory, slow disks, antivirus variance, native installer startup, a fresh runner, or a clean Windows machine.

## Pending Gates

- Independent read-only review: `COMPLETED WITH 7 IMPORTANT AND 2 MINOR FINDINGS` on the prior evidence-sync HEAD; those findings were remediated locally.
- Second independent re-review: `COMPLETED WITH 2 IMPORTANT AND 3 MINOR FINDINGS` on `305eeb4`; both Important findings were remediated in `90e6eda`.
- Third independent re-review: `COMPLETED WITH NO CRITICAL/IMPORTANT FINDINGS AND 1 MINOR`; the reviewer did not execute tests independently, so runtime confirmation remains the separately recorded local-gate evidence.
- Current exact-SHA GitHub CI: `VERIFIED` for documentation HEAD `5a48611`; the code-bearing parent `253b77d` has matching push/PR CI and Windows workflow success.
- GitHub-hosted Windows runner provenance: `VERIFIED AS CI EVIDENCE ONLY`; this does not replace an independent clean Windows machine.
- Trusted code signing: `PENDING`.
- Unsigned CI native install, upgrade, launch, termination and uninstall smoke: `VERIFIED`; trusted-package and independent acceptance remain pending.
- Clean Windows machine acceptance and residue review: `PENDING`.
- License and redistribution review: `PENDING`.

The trusted-signature workflow remains fail-closed and has not been run because
organization signing material is absent. No certificate material was requested
or handled, and no release or deployment was performed for this evidence.

## Decision

The local threat-model, selected security, fixed performance, reproducible portable build, isolated launch/cleanup, dependency-lock, and package-source increments are supported by the current local evidence baseline. The first independent review found 7 Important and 2 Minor findings; the second found 2 Important and 3 Minor findings; the focused third review found no Critical or Important findings and one Minor. All currently identified Important findings have local remediation. Batch 5 external release controls and Batch 6 remote and external gates are absent. Therefore the release-candidate decision remains `NO-GO`.
