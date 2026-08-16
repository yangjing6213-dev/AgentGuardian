# Personal v1 Independent-Machine Acceptance

## Machine requirements

Use two newly provisioned Windows 11 x64 machines with no development tools. Machine A must run 25H2. Machine B must run a supported 24H2 or 25H2 build. Both packages must originate from the private Store origin and bind to the frozen target candidate SHA.

Before testing, record only a machine ID hash plus Windows edition, version, and OS build. Evidence must never record username, never record full path, and never record user content. Use synthetic eligible data only.

## Acceptance sequence on both machines

1. Verify private Store origin, package identity, version, and signature.
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

For each step, record pass, fail, or blocked; UTC time; package identity/version/signature summary; target candidate SHA; and external evidence SHA-256. Do not record screenshots or logs containing usernames, full paths, clipboard text, browser data, report content, or credentials.

Both machines must pass the full sequence. Simulation, a development package, one machine used twice, or a machine with build tools does not pass the `independent_machine` gate.
