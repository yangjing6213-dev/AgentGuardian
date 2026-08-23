# AgentGuardian 0.3 Integrations Preview Design

**Date:** 2026-08-24
**Status:** Approved design
**Source baseline:** `7c8c7fb0ad9242fe9973a6f26b3ea84c12e352f4`
**Development branch:** `codex/0.3-integrations-preview`
**License:** Apache-2.0

## Relationship To The Frozen 0.2 Candidate

This design starts a separate `0.3 Integrations Preview`. It does not amend,
replace, or claim new evidence for the frozen `0.2.0-beta.1` candidate or its
private-beta reports. Historical local, GitHub CI, installer, and review
evidence remains evidence only for the exact source revision it names.

The `0.3` implementation receives a new release profile, build identity,
tests, reports, and acceptance evidence. No `0.2` gate is carried forward as a
passing `0.3` gate merely because the implementation shares source history.

## Context And Commercial Model

AgentGuardian currently exposes a Windows desktop GUI. Its file audit
orchestration is coupled to `app.py`, while browser metadata audit, one-time
clipboard audit, public-share verification, detectors, scoring, reporting, and
scope consent already exist as reusable local modules.

The selected product shape is one local audit core with three entry points:

1. Windows desktop GUI.
2. A standalone Codex Skill package.
3. An on-demand local STDIO MCP server that lets Codex invoke AgentGuardian.

All three entry points are open source under Apache-2.0. Revenue is expected
from convenient delivery, maintenance, rule work, integration, deployment,
training, and support rather than source-code secrecy or runtime license
enforcement. The project adds no closed Pro module, license key, account, or
telemetry system.

The standalone Skill may be listed as a paid product, but its listing must
display the Apache-2.0 license and must not promise exclusivity or prohibit
rights granted by that license. Paid marketplace publication remains blocked
until the marketplace confirms how its default buyer terms display and honor
the open-source license.

## Goals

- Reuse one local audit implementation across the GUI and MCP entry points.
- Preserve the existing desktop workflow while moving headless audit logic out
  of the GUI module.
- Give Codex two bounded local tools: prepare an audit and run the prepared
  audit.
- Give the GUI, Skill, and MCP paths access to the same four supported data
  classes under entry-point-appropriate interaction controls.
- Require a visible user decision before MCP reads content, reads the
  clipboard, copies a browser database, or performs public-share network I/O.
- Return only bounded, redacted results to Codex.
- Keep Provider handling local: detect configuration and provide manual
  guidance without calling OpenAI or another Provider API by default.
- Produce a standalone, reviewable Skill ZIP and an optional installer-based
  Codex integration.
- Make install, upgrade, rollback, and uninstall changes transactional and
  limited to AgentGuardian-owned files and configuration.
- Record exact-SHA test, package, lifecycle, and independent-review evidence.

## Non-Goals

- No HTTP MCP transport, listener, localhost service, background process,
  scheduled task, startup entry, or firewall rule.
- No cloud account, telemetry, remote rule fetch, automatic update, analytics,
  or central administration.
- No default OpenAI, Anthropic, or other Provider API call.
- No raw file, clipboard, browser, credential, or HTTP response content is
  returned to a model.
- No arbitrary command, script, plugin, executable, URL scheme, or MCP server
  execution is exposed by AgentGuardian.
- No automatic remediation or write access to audited user data.
- No production-safety, regulated-data, or high-sensitivity-data claim.
- No attempt to make the Skill self-contained by copying the audit engine or
  bundling a Windows executable into the Skill ZIP.
- No cross-agent compatibility claim until another host passes the same human
  approval and privacy acceptance tests.

## Architecture

The selected architecture is:

```text
                         +---------------------+
                         | Local Audit Modules |
                         +----------+----------+
                                    |
             +----------------------+----------------------+
             |                      |                      |
      +------v------+        +------v------+        +------v------+
      | Desktop GUI |        | STDIO MCP   |        | Codex Skill |
      | PySide6     |        | two tools   |<-------| workflow    |
      +-------------+        +-------------+        +-------------+
```

The implementation extracts `AuditOutcome` and the current `_run_audit`
orchestration from `app.py` into a headless audit-service module. The GUI calls
that service instead of owning a second implementation. Existing focused
modules remain authoritative for browser metadata, clipboard, public-share,
detection, scoring, reporting, remediation guidance, and protected state.

The MCP server uses the official MCP Python SDK and STDIO transport. The SDK
and its transitive dependencies must be version constrained, hash locked,
included in the SBOM, and covered by third-party notices. AgentGuardian does
not hand-roll MCP framing or JSON-RPC.

The installed executable uses one dispatch point:

- no special argument: start the desktop GUI;
- `--stdio-mcp`: start the MCP server before creating a GUI application;
- existing bounded maintenance arguments remain explicit and mutually
  exclusive.

There is no fourth user-facing CLI in this preview.

## Entry-Point Responsibilities

### Local Audit Modules

The local modules validate requests, enforce fixed limits, read supported data,
run detectors, calculate scores, render local reports, redact evidence, and
return fixed failure codes. They do not know whether the caller is the GUI or
MCP.

### Desktop GUI

The GUI owns native file pickers, visible consent dialogs, progress, local
report display, explicit export, and existing protected-state actions. It does
not duplicate detectors or scoring.

### STDIO MCP Server

The MCP server owns protocol validation, one pending authorization, bounded
structured responses, and translation between MCP arguments and existing local
audit functions. It exposes exactly these tools:

- `prepare_audit`
- `run_prepared_audit`

It exposes no resource, prompt, shell, write, report-export, configuration-edit,
or generic file-reading tool in this preview.

### Codex Skill

The Skill teaches Codex when AgentGuardian is appropriate, how to collect a
minimal scope, how to call `prepare_audit`, how to show the returned consent
summary, and when it may request `run_prepared_audit`. It must refuse to invent
approval, hide incomplete coverage, or restate a result as proof of safety.

The Skill contains no detector, secret pattern, HTTP client, installer, binary,
or duplicate audit logic. If the MCP tools are unavailable, it provides fixed
installation guidance and stops; it does not substitute shell commands or read
the target data itself.

## Capability Parity

"Same capability" means that every entry point can request the same supported
data operations and receive semantically equivalent outcomes. It does not mean
that GUI dialogs, MCP schemas, and Skill prose are identical.

The four supported operations are:

1. Bounded file and local AI/MCP configuration audit.
2. Fixed aggregate browser-database metadata audit.
3. One-time in-memory clipboard audit.
4. Bounded public HTTP(S) share reachability verification.

The same underlying function implements each operation for every caller.
Equivalent synthetic inputs must produce equivalent findings, scores, limits,
and redaction decisions. Presentation-only differences are allowed and tested.

## Two-Stage MCP Authorization

### Prepare

`prepare_audit` accepts a bounded request containing exactly one operation:
`files`, `browser`, `clipboard`, or `public_share`. A file operation may contain
multiple roots, but operation types cannot be combined under one authorization.
Every request contains the exact classification
`personal_non_regulated`; other or missing classifications are rejected. The
tool may validate request syntax, absolute path shape, root metadata, browser
kind, and public URL syntax. It must not:

- read supported file contents;
- copy or query a browser database;
- read the clipboard;
- resolve DNS or make a network request; or
- generate a final safety score.

It returns:

- a redacted scope summary;
- the requested data class;
- whether the request will perform public network I/O;
- fixed limits and unsupported-data language;
- a fixed statement that redacted MCP results may enter the Codex model
  context;
- an opaque authorization identifier; and
- an expiry time.

Only one pending authorization exists per STDIO process. Creating a new one
invalidates the previous one. The authorization is random, held only in
memory, bound to the normalized request, and expires after five minutes.

### Run

`run_prepared_audit` accepts the authorization identifier, exact redacted scope
digest, and exact user-visible consent summary returned by `prepare_audit`.
Including the summary in the run arguments makes it visible in the Codex tool
approval instead of presenting only an opaque token. The server validates all
three values and must reject:

- missing or unknown authorization;
- expiry;
- reuse;
- a changed scope digest;
- changed operation, paths, browser kind, data class, or URL;
- an unsupported data classification; and
- any request that exceeds a fixed limit.

The pending authorization is consumed before the first content read or network
operation. Success and failure both make it unusable. The core revalidates all
paths and inputs at execution time and fails closed if their security-relevant
shape changed.

### Human Approval Boundary

A model-provided `confirm=true` is not proof of human consent and is not used as
the security boundary. The installer writes Codex MCP configuration that:

- enables only the two AgentGuardian tools;
- allows `prepare_audit` without a content-read approval prompt; and
- sets `run_prepared_audit` to `approval_mode = "prompt"`.

Codex must obtain the user's host-level approval for the run tool. The Skill
also instructs Codex to display the prepare summary before requesting the run,
but Skill instructions are a usability control, not a security boundary.

This preview supports the AgentGuardian-managed Codex configuration only. A
host that ignores tool approval, or a user who replaces the managed approval
configuration, is outside the supported security boundary. The product must
state this limitation rather than claiming that an MCP token proves human
action by itself.

## Data-Class Contracts

### Files And Local AI/MCP Configuration

- Roots must be absolute, user-selected, unique, non-UNC, and below a drive
  root.
- Reparse points, symlinks, junction traversal, and unsupported file types are
  rejected or reported as incomplete coverage under existing policy.
- Existing fixed file, entry, byte, finding, and evidence limits remain
  authoritative.
- Static MCP configuration detection remains analysis of bounded local data;
  it never launches the configured MCP software.
- Provider configuration is observed locally and routed to manual guidance.

### Browser Database

- The request contains an explicit supported browser kind and absolute database
  path.
- Execution reuses the existing read-only temporary-copy implementation.
- Only fixed aggregate history and visit counts are returned.
- URL values, cookies, credentials, form data, page content, and arbitrary SQL
  are unsupported.
- Temporary copies and SQLite sidecars must be deleted before success is
  returned. Cleanup failure is a failed operation.

### Clipboard

- Prepare states that the clipboard value present at execution time will be
  read once.
- Run reads text once after host approval and scans it in memory.
- Raw clipboard text is neither persisted nor returned.
- Non-text, oversized, unreadable, or changed clipboard content fails closed or
  reports the existing bounded limitation.

### Public Share Verification

- Only user-provided public `http` and `https` URLs are eligible.
- Userinfo, query parameters, fragments, private addresses, loopback, link-local
  addresses, unsafe redirects, unsupported content types, oversized responses,
  and excessive redirects remain rejected.
- The request sends no scan files, findings, credentials, clipboard content,
  chat content, or Provider key.
- Only bounded reachability metadata is returned; the response body is
  discarded.
- This is the only supported network action and is never performed by default.

## Unsupported Data Boundary

The `0.3 Integrations Preview` retains the personal, non-regulated data
boundary. Every entry point presents the same boundary before data access. If
the user declares medical, financial, identity or biometric, legally
privileged, customer-dataset, national-secret, or equivalent real highly
sensitive data, the operation is cancelled.

This preview does not satisfy the user's longer-term production goal for real
highly sensitive data. That goal requires a separate approved design,
professional legal and privacy review, abuse and operations controls, trusted
signing, clean-machine evidence, and production acceptance. It is not implied
by successful preview tests.

## MCP Result Contract

MCP returns a canonical bounded object with only fields needed for action:

- schema and AgentGuardian version;
- operation status;
- technical and reviewed score where applicable;
- coverage state and explicit limits;
- rule identifier, severity, risk domain, masked evidence, and local opaque
  asset reference;
- fixed manual guidance;
- browser aggregate counts;
- public-share reachability metadata; and
- truncation and unsupported-use notices.

MCP never returns raw values, full evidence excerpts, clipboard text, browser
URLs, credentials, report HTML, response bodies, native exception text, or
complete sensitive paths. A prepare response is limited to 16 KiB. A run
response is limited to 64 KiB, 100 findings, and 200 evidence entries. A
truncated MCP response remains explicitly incomplete and may not be summarized
as safe.

The desktop may show or explicitly export the existing complete redacted local
report. MCP does not persist or export a report in this preview.

AgentGuardian itself makes no Provider API call. However, tool arguments and
redacted results handled by Codex may enter the model context under the user's
OpenAI product and workspace data controls. Marketing, privacy text, Skill
instructions, and consent summaries must state this distinction.

## Failure Handling

All trust-boundary failures use fixed machine-neutral codes. Tool results and
logs must not include caller paths, secret values, native errors, stack traces,
environment variables, or unbounded parser output.

- Prepare failure creates no pending authorization.
- A failed run consumes the pending authorization.
- Partial scanning returns incomplete coverage and explicit limits.
- Browser temporary-copy cleanup failure is a failure, not a warning.
- Public-share failures never fall back to a less restrictive HTTP client.
- MCP protocol failure terminates the STDIO process without starting another
  transport.
- The GUI remains usable if MCP configuration is absent or disabled.
- The Skill stops with setup guidance if the AgentGuardian tools are absent.

## Windows Installer

`0.3` uses a new release profile and installer build identity while retaining
the current-user, offline, no-elevation Inno Setup route. The installer contains
the complete GUI and MCP runtime. It adds two unchecked tasks:

- `Install AgentGuardian Codex Skill`
- `Enable AgentGuardian local MCP`

Before installation, the wizard displays the exact categories and target
locations it will modify. Neither task is selected by default. The installer
does not start Codex, close Codex, restart Codex, download a component, or make
a network request.

The MCP configuration points to the installed `AgentGuardian.exe --stdio-mcp`
command. A successful integration installation tells the user to restart the
relevant Codex client manually.

## Codex Configuration Transaction

The integration helper modifies only
`%USERPROFILE%\.codex\config.toml`. It uses a TOML parser for validation and a
uniquely delimited managed block for a formatting-preserving change. It does
not rewrite unrelated TOML tables or normalize the user's file.

The transaction is:

1. Validate the expected absolute Codex path and reject UNC or reparse paths.
2. Read the configuration under a fixed size limit, or record that it did not
   exist.
3. Parse it before modification.
4. Reject an existing non-AgentGuardian `mcp_servers.agentguardian` table or
   duplicate managed marker.
5. Encode whether the original existed together with its exact bytes in a
   non-empty bounded envelope, protect that envelope with current-user Windows
   DPAPI, and atomically store it as
   `%LOCALAPPDATA%\AgentGuardian\codex-config-backup-v1.bin`.
6. Append the fixed managed block to a temporary file.
7. Parse the complete candidate and verify the exact AgentGuardian table and
   approval modes.
8. Flush and atomically replace the configuration.
9. Store only the integration version and hashes in
   `%LOCALAPPDATA%\AgentGuardian\codex-integration-v1.json`.

No configuration content is logged or placed in the manifest. Any failure
before replacement leaves the original unchanged. Any failure after
replacement attempts exact rollback from the in-memory original; rollback
failure aborts installation with a fixed diagnostic and retains the encrypted
backup.

## Skill Installation And Independent Package

The canonical Skill source lives in one repository directory. Both the Windows
installer and standalone ZIP consume those same bytes.

The standalone ZIP contains only an allowlisted root directory with:

- `SKILL.md` with valid name and description frontmatter;
- `README.md` with runtime, privacy, compatibility, and setup requirements; and
- `LICENSE` containing Apache-2.0.

The package has an independent version and declares the compatible
AgentGuardian runtime range. A deterministic package script sorts entries,
normalizes timestamps, rejects links and unexpected files, checks for secrets
and dangerous executable content, and emits a SHA-256 digest. It does not
upload to Agensi or another marketplace.

Optional installer deployment targets
`%USERPROFILE%\.codex\skills\agentguardian`. A pre-existing same-name directory
without a matching AgentGuardian ownership manifest is not overwritten.
Managed files are recorded by relative path and SHA-256, never by content.

## Upgrade And Uninstall

An integration upgrade is allowed only when the installed ownership manifest,
managed markers, Skill file set, and current integration shape are valid. A
conflict stops the integration update without overwriting user data.

Normal uninstall:

- removes only the uniquely marked AgentGuardian MCP block and reparses the
  remaining TOML;
- never restores the entire historical config over later user changes;
- removes managed Skill files only when their current hashes match the
  ownership manifest;
- preserves modified or unknown Skill files and reports that manual review is
  required;
- removes the encrypted config backup after successful MCP cleanup; and
- retains the encrypted backup if MCP cleanup or rollback fails.

If managed-marker validation fails, uninstall does not guess at text ranges or
delete unrelated configuration. It reports the remaining integration and
leaves recovery material available. Existing user-selected audit reports remain
outside installer ownership.

## Release Profile And Evidence Separation

The new `integrations_preview` profile pins:

- product, Python package, and Windows file versions;
- the new installer script and identity;
- the Skill source and package allowlist;
- the MCP SDK and all runtime/build dependency locks;
- exactly two MCP tools and STDIO as the only transport;
- the Codex approval-mode contract;
- installer task defaults and ownership paths;
- forbidden Provider API, server, updater, telemetry, arbitrary-execution, and
  unsupported-data capabilities; and
- the active `0.3` documentation set.

The profile and reports must not mark any `0.2` test, CI run, installer
lifecycle, or review as current `0.3` evidence. `0.3` remains
`INTEGRATIONS-PREVIEW-NOT-READY` and formal `NO-GO` until every gate below
passes for one exact candidate SHA.

## Verification And Acceptance Gates

### Core Parity

- Existing GUI file-audit tests pass after the extraction.
- GUI and MCP adapters produce equivalent results for identical synthetic file,
  browser, clipboard, and share inputs.
- There is one detector and scoring path, verified by imports and behavior.

### Authorization

- Prepare performs no content read, clipboard access, database copy, DNS, or
  network request.
- Missing, refused, expired, reused, replaced, or mismatched authorization
  performs no content read or network request.
- Execution consumes authorization before access.
- The installed Codex config sets `run_prepared_audit` to `prompt` and enables
  no unapproved tool.

### Privacy

- Synthetic secrets, full paths, clipboard text, browser URLs, HTTP bodies,
  native errors, and environment values do not appear in MCP output, logs, or
  exceptions.
- Output and input limits fail closed.
- AgentGuardian makes no Provider API call and imports no Provider SDK.
- Public-share verification sends no local audit data or credentials.

### Skill Package

- Frontmatter and file allowlist are valid.
- ZIP bytes and checksum are deterministic for fixed inputs.
- Apache-2.0 and the runtime dependency are visible.
- No secret, executable, downloader, hidden file, link, or duplicate audit
  implementation is shipped.
- The Skill handles absent MCP tools and incomplete findings accurately.

### Installer Lifecycle

- Both integration tasks are unchecked by default.
- Each task works independently and together.
- Pre-existing config and Skill conflicts are preserved and reported.
- DPAPI backup, atomic write, rollback, upgrade, uninstall, modified-Skill
  preservation, and residue behavior pass on Windows 11 x64.
- Install and uninstall make no network request and require no elevation.
- Codex desktop and Codex CLI each complete a real STDIO invocation with the
  exact installed candidate.

### Regression And Release

- Focused tests, full tests, privacy acceptance, profile verification,
  compileall, secret scan, build, and `git diff --check` pass on a clean tree.
- Normal GitHub CI and the Windows integrations workflow pass for the exact
  candidate SHA; earlier runs do not count.
- A clean-machine install, use, upgrade, and uninstall acceptance run passes.
- An independent reviewer finds no unresolved Critical or Important issue.
- Marketplace upload, GitHub Release, public binary publication, deployment,
  and production-safety claims remain separately authorized actions.

## Explicit Limitations

- Tool approval is enforced by the supported Codex host configuration, not
  cryptographically attested by MCP itself.
- Local execution does not mean that redacted tool arguments and results remain
  outside the Codex model context.
- Static scanning cannot prove that an agent, MCP server, account, browser, or
  public share is safe.
- Browser audit returns aggregate metadata only.
- Clipboard audit observes only one moment in time.
- Public-share verification proves bounded reachability only, not access
  control, content safety, revocation, or search indexing.
- The unsigned preview installer may trigger Windows trust warnings.
- Passing preview tests does not establish suitability for real highly
  sensitive data or production deployment.

## Implementation Order

1. Extract and regression-test the headless audit service.
2. Implement and test the authorization state and redacted MCP result contract.
3. Add the official SDK STDIO server and executable dispatch.
4. Build and validate the standalone Skill package.
5. Add transactional Codex integration and installer lifecycle behavior.
6. Add the independent `0.3` release profile, CI evidence, documentation, and
   review gates.
