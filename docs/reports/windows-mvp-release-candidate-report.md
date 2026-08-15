# AgentGuardian Windows MVP Release-Candidate Report

Status date: 2026-08-16

Release-candidate decision: `NO-GO`.

Windows MVP remains incomplete. Production safety is not established.

## Candidate Boundary

- Local gate implementation and unified local evidence baseline: historical `90e6edad53bee48adca58d508d193fc855c1db7d`.
- The current clean code-bearing hardening HEAD is `4d88e0b0123e7f4a6651fa43eb4afd652e4f152c`. It adds one shared streaming SHA-256 helper with an exact 64 MiB adapter limit across runtime launch, trusted staging, packaged acceptance, and final release verification. It retains runtime WinTrust handle binding, packaged MCP adapter staging, bounded direct artifact acquisition, staged-adapter locking through evidence and ZIP generation, trusted MSIX adapter acceptance, final release-evidence binding, and fail-closed signing-material cleanup. This report is a documentation-only follow-up to that SHA.
- The first independent review of the previous evidence-sync HEAD found 7 Important and 2 Minor findings. A second independent review of `305eeb4e1a143a245323a9b54d8fe27314a4e16c` found 2 further Important findings; both were remediated in `90e6eda`. A focused third independent re-review found no Critical or Important findings and one Minor; it did not execute tests independently.
- OpenAI Provider remains local detection and manual guidance only; the default product path makes no provider API call and performs no endpoint verification.
- The remote-tracking reference was `f4b3d5c5bfd9bd4f8f6733ac9dad491c7d2bb47e` when this report was prepared. Its exact-SHA push and Draft PR CI plus both Windows package checks succeeded, but it predates the current candidate baseline.

## Current Follow-up Evidence

Fresh local verification on clean code-bearing SHA
`4d88e0b0123e7f4a6651fa43eb4afd652e4f152c` recorded `1542 passed, 11 skipped`
for the full suite and `47 passed, 1 skipped` for
`scripts/run_windows_mvp_security_gate.py`. The command
`python -m compileall src scripts tests` exited 0 and `git diff --check` was
clean. Earlier independent review
reported the same full-suite count; the focused Task 2 run reported
`117 passed, 1 skipped`, but neither historical or focused result replaces the
fresh full-suite evidence above.

Task 1 implements packaged MCP adapter acceptance after a completed
same-identity trusted MSIX upgrade. Acceptance requires an exact source SHA,
fresh user state, strict installed package path and reparse checks, actual
installed adapter execution under AppContainer plus a Job Object, and bounded
evidence binding the adapter bytes, exact X.500 publisher subject, exact DER
certificate SHA-256, completed native sandbox metadata, and
`raw_response_retained=false`. Package cleanup requeries and retries uninstall
before the final source/signature/license/MCP evidence gate.

Task 2 requires all four external adapter inputs for trusted builds and rejects
them for unsigned builds. Under a source-file lock it verifies the exact SHA-256,
trusted Authenticode, publisher subject, and certificate pin, then stages only
`adapters/AgentGuardianMcpAdapter.exe` and `MCP-ADAPTER.json` before payload
manifests, checksums, and ZIP generation. The staged adapter is rehashed and held
without write/delete sharing through evidence and ZIP generation. The manual
workflow requires four non-secret repository variables and uses a direct HTTPS,
no-redirect, 64 MiB bounded streaming downloader with exact hash, random private
runner directory, Win32 final-handle path binding, and handle-bound failure
deletion. It scopes organization PFX/password material to
the required steps, verifies imported certificate/private-key and PFX cleanup
fail-closed, and sets a real 30-minute outer timeout.

The current bounded-hashing slice applies the downloader's 64 MiB artifact
boundary to runtime launch, source and staged build verification, packaged MCP
acceptance, and the final trusted-release evidence gate. Hashing is streaming;
exact-limit files are accepted, while `64 MiB + 1 byte` fails before launch,
copy, or evidence creation. A real sparse-file boundary test and a real Windows
`FileRenameInfoEx` POSIX replacement probe are included. Manifest and ZIP code
may still hold up to the bounded 64 MiB artifact in memory.

Task 1, Task 2, trusted-artifact acquisition, and bounded adapter hashing passed independent
specification or quality/security review with no remaining Critical or Important
issues. The focused runtime handle-binding review initially raised one Important
path-identity concern, then withdrew it after a real Windows test demonstrated
that parent-directory replacement fails while the final executable handle is
held and succeeds after release. Its final result was PASS with no Critical or
Important findings. The bounded-hashing review's two initial Important findings
were both resolved or withdrawn after final-release gate remediation and a real
Windows POSIX replacement probe; final re-review was PASS with no Critical or
Important findings. Predecessor `f4b3d5c5bfd9bd4f8f6733ac9dad491c7d2bb47e`
passed exact-SHA push and Draft PR CI plus both Windows package checks.
Historical successful CI remains evidence only for its exact historical SHA.

The earlier implementation HEAD was `a6a75c27e20d329a32f9e1ef2473f35b23deb198`.
Its local full regression is `1407 passed, 11 skipped`; push and Draft PR CI
plus both Windows package checks completed successfully. This HEAD adds the
offline desktop control-plane page and a strict `RequireFreshUserState` MSIX
verification mode. The latter requires trusted signing, an empty
`LOCALAPPDATA\AgentGuardian` state before install, and no user-state residue
after uninstall; it has not yet been executed on an independent clean Windows
machine.

The previous code-bearing HEAD was `bd4f5cc4a2957e222beacd7b7b24c8fbd98e7ddb`.
Its local full regression was `1424 passed, 11 skipped`; the enterprise service
then had an explicit development-only `127.0.0.1` adapter with serialized
SQLite access, fixed error responses, and no default startup. Its four exact-SHA
check-runs completed successfully. PR #1 remains open and Draft; this does not
change the release decision.

## Current Local Evidence

| Gate | Current revalidation | Scope |
| --- | --- | --- |
| Windows MVP security gate | `47 passed, 1 skipped` | Fresh run of `scripts/run_windows_mvp_security_gate.py` at `4d88e0b0123e7f4a6651fa43eb4afd652e4f152c`. The allowed skip is not reported as a pass. |
| Python 3.14 full suite | `1542 passed, 11 skipped` | Fresh full-suite run at the exact SHA above. |
| Source, script, and test compilation | Exit 0 | Fresh `python -m compileall -q src scripts tests`. |
| Latest completed exact-SHA GitHub CI | `VERIFIED` | At predecessor `f4b3d5c5bfd9bd4f8f6733ac9dad491c7d2bb47e`, push CI `31906131946`, push Windows `31906131948`, Draft PR CI `31906133527`, and Draft PR Windows `31906133509` all completed successfully. The Windows package remains unsigned CI smoke. |
| Brand validation | Historical exit 0 | Existing brand-asset contract; not rerun for this documentation sync. |
| Portable reproducibility | Historical: `208 files` and `92,870,198 bytes` in each bundle; Bundle diff count: `0`; both ZIPs were `36,033,202 bytes` with SHA-256 `4f7e9ffdd347fddf67ffb7544ab84e777ff7b93e2ed1bf546ed87e6e9517bad1` | Historical `90e6eda` evidence only. Two new build roots used a hash-locked Python 3.12.2/PyInstaller 6.16.0 environment, lock SHA `75be59ee054a75d556cc89099f571d9826fa272aef656124fa75dc535731cdd5`, and fixed build time `2026-08-15T00:00:00Z`. |
| Portable isolation smoke | Historical: both copied bundles reported `process_startup=true`, `bounded_liveness=true`, `termination=forced_after_bounded_smoke`, `process_tree_terminated=true`, and `declared_residue=false` | Historical local smoke with evidence JSON SHA-256 L `8ed7fe9a1e9fc43ee7fcf0c32cc4de3bceb9042695080d11c59451ae163cf034` and M `cd4317b9881aec914efe7090cf9d7324c4adf5803931ad4704e1776986a433c9`; not clean-machine acceptance or current-SHA runtime evidence. |
| Package-source self-audit | Historical: both bundles returned `findings=[]`, `local_only=true`, `network_capability=not_detected`, `ordinary_user_mode=true` | Reviewed copied source policy only; dependencies and binaries were not scanned. |

For traceability, the earlier Batch 6 evidence baseline remains recorded as
`1322 passed, 8 skipped` on Python 3.14 and `1321 passed, 9 skipped` on the
hash-locked Python 3.12 environment. The prior `ef571a1` result was
`1426 passed, 11 skipped`; neither historical count replaces the current
`4d88e0b` local result above.

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
- Task 1, Task 2, trusted-artifact acquisition, runtime WinTrust handle-binding, and bounded adapter hashing independent specification or quality/security review: `COMPLETED`; no Critical or Important issues remain. This does not provide external-material or trusted-release acceptance.
- Latest completed exact-SHA GitHub CI: `VERIFIED` for predecessor `f4b3d5c5bfd9bd4f8f6733ac9dad491c7d2bb47e`; push CI `31906131946`, push Windows `31906131948`, Draft PR CI `31906133527`, and Draft PR Windows `31906133509` all succeeded. Current local SHA `4d88e0b0123e7f4a6651fa43eb4afd652e4f152c` remains pending remote revalidation.
- Historical `e8013dc` label: Current exact-SHA GitHub CI: `VERIFIED`. It does not cover the current local SHA.
- Historical label: GitHub-hosted Windows runner provenance: `VERIFIED AS CI EVIDENCE ONLY`. It does not cover the current local SHA or replace an independent clean Windows machine.
- Trusted code signing: `PENDING`.
- Trusted-signature workflow final gate: `IMPLEMENTED AND FAIL-CLOSED`; it requires `trusted_release` bundle metadata, all four external adapter inputs, fresh-user-state and completed same-identity upgrade evidence, trusted signer evidence, packaged MCP acceptance, and complete SBOM/license evidence. It has not been dispatched or passed with a real organization adapter/certificate.
- Structured license-review evidence: `IMPLEMENTED`; the final gate binds an approved review record to the exact source SHA and SBOM SHA-256 and cross-checks every SBOM component. The committed worksheet is intentionally `pending`, so no legal/redistribution approval is claimed.
- Packaged MCP adapter build and acceptance: `IMPLEMENTED`; trusted builds stage only the fixed adapter and `MCP-ADAPTER.json`, while trusted MSIX acceptance executes the installed bytes under AppContainer plus a Job Object and binds bounded evidence to the source/signature/license/MCP gate. Real organization adapter/certificate execution remains pending.
- Release evidence path hardening: `IMPLEMENTED`; bundle, smoke evidence, and license-review inputs reject relative paths, symlinks, UNC paths, and reparse/junction components before reading.
- Unsigned CI native install, upgrade, launch, termination and uninstall smoke: `VERIFIED`; trusted-package and independent acceptance remain pending.
- Strict fresh-user-state verifier: `IMPLEMENTED`; independent clean Windows machine acceptance and residue review: `PENDING`.
- License and redistribution review: `PENDING`.
- Required repository variables, organization signing material, approved `windows-license-review.json`, real sanitized-sample human signoff, and independent clean-machine install/upgrade/run/uninstall evidence: `PENDING`.
- Remote enterprise console, device enrollment, and distribution: `UNIMPLEMENTED`.
- Residual Minor/defense-in-depth items: reparse validation and the final executable `CreateFileW` are not atomic, although traditional, parent-directory, and `FileRenameInfoEx` POSIX replacement attempts were blocked by the held file on current Windows/NTFS; multi-signature signer-index binding; evidence-output parent-path TOCTOU; and synchronous AppX operations bounded only by the outer workflow timeout.

The trusted-signature workflow remains fail-closed and has not been dispatched
or passed with a real organization adapter/certificate. No certificate material
was requested or handled, and no release or deployment was performed for this
documentation evidence.

## Decision

The packaged MCP release controls are implemented and fresh local tests pass,
but real external material and trusted runtime execution remain pending. Current
normal GitHub CI for the new local SHA is also pending revalidation. Required
signing, license, sanitized-sample, and independent clean-machine evidence is
absent; remote enterprise delivery remains unimplemented. Therefore the
release-candidate decision remains `NO-GO`. This report makes no production
safety, high-sensitive real-data readiness, or legal approval claim.
