# Personal v1 Independent-Machine Acceptance

The only active delivery and governance route is the unsigned `personal_exe_private_beta` track for known testers. Frozen candidate `8ad46e31486d05a2b4572ef8bd7442eb22a7b5b6` has current local-gate, GitHub CI, native unsigned-installer lifecycle, and independent-review evidence. It remains `PRIVATE-BETA-NOT-READY` because external license and Qt approval, this two-machine acceptance, and operations/security readiness are pending; formal public release remains `NO-GO`. An Actions artifact from the public repository is not an access-controlled private distribution channel; `private beta` is a maturity label, not a confidentiality claim.

## Machine requirements

Use two newly provisioned Windows 11 x64 machines with no development tools. Machine A must run 25H2. Machine B must run a supported 24H2 or 25H2 build. Both machines must use the same unsigned offline EXE whose installer SHA-256 is retained externally and bound to the frozen target candidate SHA.

Before testing, record only a machine ID hash plus Windows edition, version, and OS build. Evidence must never record username, never record full path, and never record user content. Use synthetic eligible data only.

## Acceptance sequence on both machines

1. Verify the installer SHA-256, installer identity and version, and the expected Unknown Publisher or SmartScreen result.
2. Complete install and launch as a standard user with no developer runtime.
3. Run an eligible scan over synthetic personal non-regulated configuration data; verify redacted JSON and HTML.
4. Trigger browser metadata audit; verify bounded counts and temporary-copy cleanup.
5. Trigger clipboard inspection once; verify redacted findings and no source-text retention.
6. Check explicit public URL share reachability; verify no local audit data is sent.
7. Exercise the fixed `OPENAI_BASE_URL_OVERRIDE` remediation and rollback; verify preview, confirmation, target recheck, backup, and conditional rollback.
8. Run report comparison using bounded synthetic reports.
9. Force a crash and restart; verify fail-closed state handling and inspect temporary residue.
10. Perform a same-identity upgrade from the approved predecessor to the frozen candidate.
11. Complete uninstall and residue inspection, including application data and temporary workspaces.

## Evidence and decision

For each step, record pass, fail, or blocked; UTC time; installer identity/version/hash summary; Windows warning result; target candidate SHA; and external evidence SHA-256. Do not record screenshots or logs containing usernames, full paths, clipboard text, browser data, report content, or credentials.

Both machines must pass the full sequence. Simulation, an installer with an unverified hash, one machine used twice, or a machine with build tools does not pass the `independent_machine` gate. Passing this gate would support known-tester private-beta maturity only; it would not authorize formal public release, high-sensitivity real data, or production-safety wording. OpenAI Provider remains limited to local adaptation, detection, and manual guidance, with no provider API call by default.
