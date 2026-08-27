# AgentGuardian Integrations Preview

This document is the active 0.3 boundary for the desktop GUI, standalone
Codex Skill, and local STDIO MCP entry points. All three use one local audit
core and require an explicit human decision before an operation reads local
content, reads the clipboard, copies a browser database, or performs public
share verification.

The supported boundary is personal non-regulated configuration only. Medical,
financial, identity, biometric, customer, legally privileged, regulated, and
other high-sensitivity real data are unsupported. This is a use restriction,
not a production safety claim. The product is currently
`INTEGRATIONS-PREVIEW-NOT-READY` and formal release is `NO-GO`.

The runtime must not call OpenAI or another Provider API by default. Provider
configuration is handled through local adaptation, static detection, and
manual guidance. The product has no telemetry, background listener, automatic
update, arbitrary execution, or dynamic MCP loading.

## Public preview staging boundary

The Windows 11 x64 preview staging path binds the output parent and temporary
directory handles, uses short-lived child-handle checks for identities and
digests, closes those child handles before the directory rename, and performs
one final content and source-state recheck before the no-replace atomic rename.
This bounds the release workflow without claiming to remove all kernel-level
TOCTOU behavior. A same-user process can still change content in the narrow
close-to-rename window; such changes are rejected when observed, and
unsupported handle or filesystem behavior fails closed with a fixed error.

## Operation and approval contract

The supported operations are exactly `files`, `browser`, `clipboard`, and
`public_share`. `prepare_audit` validates the operation and scope shape only;
it is configured for automatic approval and must not read content or use the
network. `run_prepared_audit` is configured for `prompt` approval, consumes the
one-time authorization, and is the only step that may perform the selected
bounded operation after the user chooses to continue.

Redacted tool arguments and results may enter the Codex model context. A
rejection, expiry, scope mismatch, or incomplete result stops the operation;
the Skill and local MCP entry point must not guess, repair, or silently retry.

The Windows installer is unsigned, current-user only, offline, and opt-in for
the Skill and MCP integration tasks. It never starts or restarts Codex. The
Skill source and runtime are Apache-2.0; a paid listing cannot remove rights
granted by that license. Reports remain outside installer ownership.

The checked-in lifecycle script is fail-closed and requires `-TestMode`; it
uses an isolated synthetic profile and rejects evidence paths inside user
ownership paths. Clean-machine lifecycle acceptance remains a separate pending
gate and must use a dedicated Windows account or machine, not a normal user's
profile.
