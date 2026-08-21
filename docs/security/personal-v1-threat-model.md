# Personal v1 Threat Model

## Scope

This model covers AgentGuardian Personal v1 `0.2.0-beta.1` on Windows 11 x64 in a personal non-regulated configuration. Private beta is `PRIVATE-BETA-NOT-READY`; formal release is `NO-GO`. It does not establish production safety.

Personal v1 permanently excludes MCP runtime integration. Enterprise features, a high-sensitivity mode, and dynamic MCP execution are permanent exclusions. The runtime has no telemetry, cloud console, automatic arbitrary remediation, or plugin execution. The runtime must not call OpenAI or another provider API by default.

## Protected assets

- User-selected configuration files and directory metadata.
- Clipboard text during one explicitly triggered in-memory read.
- Browser SQLite metadata while a bounded temporary copy exists.
- Redacted findings, reports, comparison summaries, and DPAPI-protected state.
- The allowlisted remediation target and its same-directory backup.

## Trust boundaries

1. User to local UI: scope and every optional action require explicit input.
2. Local UI to filesystem: reads are bounded to the selected scope; report writes use a user-selected destination.
3. Browser database to temporary workspace: approved SQLite files are copied read-only and cleaned after use.
4. Clipboard to detector: source text exists only for the one-time in-memory inspection.
5. Public URL to network verifier: only the explicitly supplied HTTP(S) URL crosses the network boundary.
6. Local state to Windows DPAPI: confidentiality is limited to the current Windows user context.

## Implemented controls

- Bounded read-only discovery and static detection.
- Redacted evidence and local HMAC-based references.
- Explainable scores, coverage, limits, and disposition guidance.
- Static detection of MCP shell, filesystem-write, and network capability combinations.
- Fixed `OPENAI_BASE_URL_OVERRIDE` preview, confirmation, target recheck, backup, replacement, and conditional rollback.
- Browser temporary-copy cleanup and clipboard non-retention.
- No default provider API call and no audit-data upload through share reachability.

## Residual threats and limits

- Malware in the same Windows user session can read local data and may defeat DPAPI confidentiality.
- Path checks and file replacement retain same-user race risk.
- Python cannot guarantee erasure of every immutable string or byte copy.
- Static rules can miss unknown formats or behavior and do not prove endpoint intent.
- Public URL reachability does not prove safe content, correct permissions, or search-index status.
- A clean local test does not prove installer integrity, external license approval, independent-machine behavior, or operations readiness. The private-beta installer is intentionally unsigned and may trigger Unknown Publisher or SmartScreen warnings.

## Unsupported data

Medical, financial, identity or biometric, legally privileged, customer data, state-secret, other regulated, and other high-sensitivity real data are unsupported. This declaration is not a content-classification guarantee; users must determine eligibility before scanning.
