# AgentGuardian Windows Workflow and Report Hardening Design

**Status:** Design approved in conversation on 2026-08-03; written specification pending user review.

## Purpose

Windows MVP Batch 4 makes the existing desktop workflow more explicit and makes
incomplete results easier to interpret. It adds a bounded scope preview and
consent gate, explicit coverage states, local finding filters, and aggregate
comparison with a user-selected AgentGuardian JSON report.

This batch preserves the confirmed OpenAI Provider boundary: local discovery,
static detection, and manual guidance only. It does not import an OpenAI SDK,
make an API request, verify an endpoint remotely, revoke a credential, or modify
provider configuration.

## Goals

- Show the user what the selected scan can and cannot cover before it starts.
- Require explicit consent for the exact selected roots before each scan.
- Distinguish complete, limited, and no-supported-file outcomes in the UI and
  exported reports.
- Filter visible findings by severity, risk domain, and disposition state
  without changing audit evidence, scores, reports, or protected state.
- Compare current and baseline reports by safe aggregates only.
- Keep imported baseline data bounded, transient, local, and fail-closed.
- Preserve deterministic reports and the existing read-only/manual-remediation
  security model.

## Non-Goals

- Exact matching of individual findings across exported reports.
- Exporting `disposition_ref` or any other stable cross-scan finding identifier.
- Fuzzy matching after a path, rule, or matched value changes.
- Comparing HTML reports, arbitrary JSON, or reports from other products.
- Automatically discovering or loading a baseline report.
- Persisting the baseline path, baseline contents, or comparison result.
- Filtering or suppressing exported evidence.
- Automatic remediation, credential rotation, endpoint verification, network
  access, API calls, telemetry, or cloud synchronization.
- Replacing the Batch 5 packaging/provenance work or the Batch 6 release gates.

## Chosen Architecture

### 1. Pure Workflow Contracts

A focused workflow module owns immutable value objects and pure functions for:

- a scope preview;
- scan consent identity;
- coverage-state classification; and
- finding-filter criteria.

The Qt window renders these contracts and owns only transient interaction state.
The audit core remains responsible for discovery and detection. Report rendering
remains responsible for exported formats. Aggregate comparison is isolated in a
separate report-comparison module so untrusted baseline parsing does not become
part of scanning or disposition persistence.

The implementation must reuse existing `Finding`, `Score`, disposition, and
report contracts. It must not add a second scoring implementation or refactor
unrelated Batch 0-3 code.

### 2. Scope Preview and Consent

Selecting a folder creates a preview without traversing the folder. The preview
contains only:

- the number of selected roots;
- each root's short display name, never its full path;
- the supported suffix and exact-name selectors;
- the file, directory-entry, byte, finding, and evidence limits;
- fixed statements that UNC roots, Windows drive roots, and reparse paths are
  excluded or rejected; and
- fixed statements that the scan is local, read-only, and provides only manual
  guidance.

No known configuration root is silently added. The preview describes the roots
the user explicitly selected and the hard limits already enforced by the audit.

The scope page contains an unchecked consent checkbox tied to the immutable
current selected-root tuple and preview-contract version in memory. This binding
is not exported or persisted. The scan button is enabled only when:

1. at least one accepted root is selected;
2. no scan is running; and
3. consent is checked for the current scope identity.

The scan callback revalidates all three conditions instead of relying only on
the button's enabled state. Valid consent is consumed and reset before the
worker starts, so rerunning the same scope requires a new explicit check.
Selecting, clearing, or rejecting a different root revokes consent and
invalidates prior findings, reports, and comparisons. A completed scan does not
grant consent to a later scan.

### 3. Explicit Coverage States

Coverage classification is derived from the validated technical `Score` and
uses exactly three values:

- `complete`: `incomplete` is false;
- `no_supported_files`: `incomplete` is true and the canonical limit list
  contains `no_supported_files`; and
- `limited`: every other incomplete result.

The classifier rejects contradictory or malformed score data. In particular,
`complete` cannot carry a non-empty limit list, and `no_supported_files` must
have zero coverage. Existing discovery and scan limit codes remain the canonical
machine-readable reasons; the UI maps them to fixed, non-sensitive descriptions.
Only these existing canonical limit codes are valid:

- `byte_limit_reached`;
- `directory_excluded`;
- `directory_read_limited`;
- `entry_limit_reached`;
- `entry_read_limited`;
- `file_limit_reached`;
- `file_scan_limited`;
- `finding_limit_reached`;
- `mcp_config_scan_limited`;
- `no_supported_files`;
- `reparse_changed`;
- `reparse_excluded`; and
- `root_reparse_excluded`.

Unknown limit codes fail report validation rather than being echoed as arbitrary
user text.

The UI shows the state, percentage, and fixed reasons. Both incomplete states
must include the statement that the result cannot establish safety. A complete
scan may say only that the configured scope completed; it must not say the
system, account, provider, or endpoint is safe.

New reports declare `report_schema: 1` and include the explicit coverage state
alongside the existing score coverage, incomplete flag, and limit codes. JSON
and HTML render the same state and reasons deterministically. The technical and
reviewed scores continue to share coverage and limits.

### 4. Finding Filters

The findings page adds three exact option filters:

- severity: all or one existing `Severity` value;
- risk domain: all or one existing `RiskDomain` value; and
- disposition state: all, open, false positive, accepted risk, or expired.

Filters apply to findings, then render every evidence row belonging to each
matching finding. The page displays both the number of visible findings and the
total finding count; evidence-row count is not presented as finding count.

Filtering is a view operation only. It must not mutate or regenerate:

- `AuditOutcome.findings`;
- the technical or reviewed score;
- `report_json` or `report_html`;
- disposition records; or
- protected state.

Changing a filter clears a selection that is no longer visible and refreshes
manual guidance and disposition buttons. Expiry refreshes re-evaluate the
disposition filter at the same validated evaluation time used for disposition
status. Empty filter results show a fixed empty-state message without implying
that the unfiltered audit had no findings.

### 5. Aggregate JSON Report Comparison

The report page lets the user explicitly select one baseline `.json` report
after a current audit exists. HTML comparison is not supported.

The file boundary must:

- reject UNC paths and any path with a reparse component;
- require a regular file;
- reject a file larger than 2 MiB before parsing and bound the actual read to
  the same limit plus one sentinel byte;
- decode UTF-8 strictly;
- parse with the standard JSON parser; and
- normalize every failure to one fixed error code and one fixed UI message.

The parser accepts only exact built-in JSON types, bounded strings and lists,
`product == "AgentGuardian"`, and one of these schemas:

- the exact pre-Batch-4 Founder Alpha report shape, treated as legacy schema 0;
  or
- `report_schema == 1` from this batch.

Required and allowed keys are fixed for the top level, both score objects,
findings, evidence, deductions, and each disposition-state shape. Unknown keys
fail closed. Version and rule-version strings use the existing safe-annotation
rules with a 32-character maximum. Rule IDs must match
`[A-Z][A-Z0-9_]{0,63}`. Fingerprints, display names, masked evidence,
disposition annotations, and timestamps must pass the existing domain
validators even though comparison discards their item-level values.

Missing required fields, unknown schema versions, non-finite or boolean numeric
values, oversized collections, invalid enum values, unknown limit codes,
contradictory score data, more than 2,000 findings, or more than 2,000 total
evidence entries fail closed. The parser does not retain evidence sources,
masked evidence, fingerprints, disposition reasons, reviewers, timestamps, or
the selected full path after validation.

Both current and baseline reports are reduced to immutable aggregate summaries:

- technical score;
- reviewed score;
- coverage ratio and coverage state;
- total finding count;
- counts by rule ID;
- counts by severity;
- counts by disposition state; and
- canonical limit-code sets.

Counts are per finding object, never per evidence row. The current report is
parsed and summarized through the same schema-validation path as the baseline,
so comparison does not maintain a second interpretation of report fields.

The comparison contains baseline, current, and signed `current - baseline`
delta values for numeric aggregates. Added limits are `current - baseline`;
resolved limits are `baseline - current`. All category and limit output is
sorted deterministically. It may say that a category count increased or
decreased. It must not describe any individual finding as new, fixed,
unchanged, or matched.

The baseline display uses only the selected file's short name. The full path,
raw JSON, evidence, and fingerprints are not shown, logged, exported, saved to
DPAPI state, or retained after the comparison is cleared. A new root selection,
scan start, scan failure, or report invalidation clears the comparison. Report
export always exports the complete current audit and never embeds filters,
baseline data, or comparison results.

### 6. UI Integration

The existing three-page desktop structure remains unchanged.

- Scope page: add an unframed preview region and consent checkbox beneath the
  selected-root display.
- Findings page: add three compact combo filters and a stable result-count
  label above the table.
- Report page: add a baseline JSON selection command, a clear command, and an
  unframed aggregate comparison view below the existing report controls.

Controls must keep stable dimensions at the existing 960 by 640 minimum window
size. Familiar Qt standard icons are used where available, with tooltips for
unfamiliar icon-only commands. The implementation must not add nested cards,
marketing copy, oversized headings, decorative gradients, or a new landing
page.

## State and Data Flow

1. The user selects one local root.
2. The window validates the root, revokes old consent, invalidates old results,
   and builds a non-traversing preview.
3. The user reviews the preview and checks consent.
4. The scan callback revalidates and consumes consent, clears any comparison,
   and starts the existing read-only worker.
5. The worker produces the existing immutable audit outcome with explicit
   coverage classification added to report rendering.
6. The findings page derives its visible rows from the immutable outcome,
   current filters, dispositions, and one validated evaluation time.
7. The user may explicitly select one bounded local JSON baseline.
8. The baseline parser discards item-level evidence after producing an aggregate
   summary; the current report is summarized by the same contract.
9. The UI renders aggregate deltas. No comparison state enters report export or
   protected persistence.

## Failure Behavior

- Invalid or stale consent: do not start a worker; retain a fixed instruction
  to review and approve the current scope.
- Scope preview failure: clear roots, consent, results, and comparison; show a
  fixed scope error.
- Unknown or contradictory coverage data: fail report construction with the
  existing fixed `REPORT_INVALID` boundary.
- Filter evaluation failure: show no filtered rows and a fixed filter error;
  leave the immutable audit and report unchanged.
- Baseline read, decode, parse, or validation failure: clear baseline and
  comparison state and show `Unable to read the baseline report` without any
  exception or path text.
- Current-summary or comparison failure: clear comparison only; do not clear or
  rewrite the current audit report.
- Every Qt callback contains unexpected exceptions at a fixed user-safe boundary.

## Security and Privacy Properties

- Scope preview never traverses the selected directory and never displays a full
  path.
- Consent is explicit, scope-bound, transient, and revalidated at execution.
- Filters cannot hide findings from exports, scores, or protected state.
- Comparison is aggregate-only and cannot link individual findings across
  exported reports.
- Baseline import is a bounded, explicit, user-selected local read. It adds no
  ambient directory scan and no automatic file access.
- Imported item-level evidence is discarded after aggregation and never copied
  into UI, reports, exceptions, logs, or persistence.
- The only permitted writes remain explicit report export and explicit protected
  state operations already present before Batch 4.
- No network, OpenAI API, LLM, telemetry, updater, shell, clipboard, browser
  database, dynamic plugin, or automatic-remediation capability is added.

Residual limitations remain explicit: DPAPI cannot defend against code already
controlling the same Windows user; host-clock, path-alias, reparse race, and
immutable-Python-object limits remain; report validation does not prove report
authenticity; aggregate comparison can merge distinct findings in the same
category; dependencies and binaries remain outside the static source audit.

## Compatibility

- Existing Batch 0-3 audit, disposition, and protected-state schemas remain
  unchanged.
- New report schema 1 is additive to the existing report fields.
- Baseline comparison accepts only the exact legacy Founder Alpha shape and
  schema 1. It does not guess future schemas.
- Old reports remain immutable; no migration or rewrite occurs.
- Existing report exports remain complete and unfiltered.

## Acceptance Criteria

1. Selecting a synthetic local root displays only its short name and fixed scan
   boundaries; no traversal occurs before consent.
2. The scan button and callback both reject missing or stale consent; every scan
   consumes consent before its worker starts.
3. Changing or rejecting a root revokes consent and clears prior audit and
   comparison state.
4. Complete, limited, and no-supported-file outcomes render distinct fixed UI,
   JSON, and HTML states without any safety claim.
5. Severity, domain, and disposition filters show correct finding counts and do
   not change scores, reports, dispositions, or protected state.
6. Expired dispositions update the disposition filter using the same validated
   evaluation time as scoring and report rendering.
7. A valid synthetic legacy or schema-1 JSON baseline produces deterministic
   aggregate deltas and sorted added/resolved limits.
8. Comparison output contains no source, evidence, fingerprint, reason,
   reviewer, timestamp, full path, `disposition_ref`, or individual finding
   lifecycle claim.
9. UNC, reparse, non-regular, oversized, malformed, hostile, contradictory, and
   unsupported-schema baselines fail closed with one fixed message.
10. New scan lifecycle transitions clear comparison state but preserve the
    existing audit failure and report-export guarantees.
11. The full synthetic test suite, brand validation, source compilation,
    whitespace check, package-source self-audit, independent security review,
    and both final-SHA GitHub workflows pass before Batch 4 acceptance.
12. Passing Batch 4 does not complete Batches 5-6, the Windows MVP, or a
    production-safety review.
