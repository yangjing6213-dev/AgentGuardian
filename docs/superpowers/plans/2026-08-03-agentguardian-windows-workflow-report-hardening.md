# AgentGuardian Windows Workflow and Report Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete Windows MVP Batch 4 with explicit per-scan scope consent, clear coverage states, view-only finding filters, and bounded aggregate JSON report comparison.

**Architecture:** Add one pure workflow-contract module and one isolated report-comparison module. Keep scanning, scoring, dispositions, protected state, and report export authoritative and immutable; the Qt window owns only transient consent, filters, and baseline-comparison state. Preserve local-only operation, manual remediation, report privacy, and zero default OpenAI API access.

**Tech Stack:** Python 3.12+, standard library, PySide6, pytest, Windows GitHub Actions, existing AgentGuardian domain/report/disposition contracts.

---

## Approved Specification

Implement exactly:

- `docs/superpowers/specs/2026-08-03-agentguardian-windows-workflow-report-hardening-design.md`

Do not add exact cross-report finding matching, exported stable identifiers,
comparison persistence, automatic remediation, network access, OpenAI SDK/API
calls, or Batch 5/6 features.

## File Map

- Create `src/agentguardian/workflow.py`: immutable scope, consent, coverage, and
  finding-filter contracts.
- Create `tests/test_workflow.py`: pure workflow-contract tests.
- Modify `src/agentguardian/reporting.py`: report schema 1 and explicit coverage
  state in deterministic JSON/HTML.
- Modify `tests/test_reporting.py`: schema, consistency, escaping, and
  deterministic coverage tests.
- Create `src/agentguardian/report_comparison.py`: strict report parser,
  aggregate summary/delta contracts, and bounded baseline file read.
- Create `tests/test_report_comparison.py`: legacy/schema-1, adversarial,
  privacy, aggregate, and file-boundary tests.
- Modify `src/agentguardian/app.py`: scope preview/consent, coverage UI,
  filters, and transient comparison UI.
- Modify `tests/test_app_smoke.py`: consent lifecycle, filter isolation,
  comparison lifecycle, fixed errors, and minimum-size layout tests.
- Modify `src/agentguardian/source_policy.json`: exact final package source
  manifest after all source edits are reviewed.
- Modify `tests/test_self_audit.py`: Batch 4 documentation/capability assertions.
- Modify `README.md`, `docs/architecture.md`,
  `docs/reports/alpha-0.1.0-stage-report.md`, and
  `docs/superpowers/plans/2026-08-02-agentguardian-windows-mvp-hardening.md`:
  verified Batch 4 behavior, evidence, and remaining limits.

## Execution Rules

- Execute tasks sequentially in the existing `agent/founder-alpha` worktree.
- Use a fresh implementation subagent per task.
- After each implementation commit, run a read-only specification review, then
  a separate code-quality review. Resolve every finding and repeat the relevant
  review before moving on.
- Every production behavior change follows RED, GREEN, REFACTOR. Record the
  failing test and expected reason before implementation.
- Tasks 1-8 intentionally run focused tests while package source is changing.
  The exact source-policy manifest is updated once in Task 9; until then, a
  source-policy mismatch is expected and must not be presented as a passing full
  gate.
- Update this plan's checkboxes only after the corresponding command or review
  actually passes.
- Keep all test data synthetic. Never inspect real keys, chats, browser stores,
  endpoint contents, or unrelated user files.
- Do not merge, deploy, mark the PR ready, or claim Windows MVP/production
  safety.

## Task 1: Add Pure Scope, Consent, and Coverage Contracts

**Files:**
- Create: `src/agentguardian/workflow.py`
- Create: `tests/test_workflow.py`

- [x] **Step 1: Write failing scope-preview tests**

Cover a synthetic, nonexistent local root and prove preview construction does
not call `stat`, `resolve`, `scandir`, or directory iteration. Require:

```python
preview = build_scope_preview(
    (Path(r"C:\Synthetic\selected-root"),),
    selectors=(".env", ".json"),
    max_files=10_000,
    max_entries=50_000,
    max_bytes=512 * 1024 * 1024,
    max_findings=2_000,
    max_evidence=4_000,
)

assert preview.root_names == ("selected-root",)
assert r"C:\Synthetic" not in repr(preview)
assert preview.read_only is True
assert preview.manual_guidance_only is True
```

Also reject an empty root tuple, duplicate roots, mutable selector inputs,
non-positive limits, Windows drive roots, UNC roots, and unsafe short names.

- [x] **Step 2: Run the preview tests and verify RED**

Run: `rtk pytest -q -p no:cacheprovider tests/test_workflow.py -k scope_preview`

Expected: import or symbol failure because `workflow.py` does not exist.

- [x] **Step 3: Implement the minimal immutable preview contract**

Add exact frozen/slotted dataclasses and pure constructors. Keep root paths in
private `repr=False` fields only where consent matching requires them. Display
data contains short names and fixed contract values only. Do not traverse the
filesystem.

- [x] **Step 4: Write failing consent-binding tests**

Require an in-memory consent value to match only the exact normalized root tuple
and preview-contract version. Test changed order, changed root, changed version,
subclasses, and forged mutable fields. No consent value may reveal a full path
through `repr`.

- [x] **Step 5: Run consent tests and verify RED**

Run: `rtk pytest -q -p no:cacheprovider tests/test_workflow.py -k consent`

Expected: missing consent contract or matcher.

- [x] **Step 6: Implement minimum consent binding**

Use host Windows lexical normalization for the private root identity. Do not
persist, export, hash into reports, or add a new key.

- [x] **Step 7: Write failing coverage-state tests**

Require `complete`, `limited`, and `no_supported_files`. Require the exact
canonical limit-code allowlist from the design. Reject:

- non-`Score` objects and subclasses;
- unknown or duplicate limit codes;
- complete scores with limits or coverage below 1;
- incomplete scores with no reason and full coverage; and
- `no_supported_files` with nonzero coverage or additional reasons.

- [x] **Step 8: Run coverage tests and verify RED**

Run: `rtk pytest -q -p no:cacheprovider tests/test_workflow.py -k coverage`

Expected: missing classifier or validation behavior.

- [x] **Step 9: Implement the coverage classifier and fixed labels**

Return an enum plus fixed Chinese UI labels/reason descriptions. Never echo an
unvalidated limit string.

- [x] **Step 10: Run Task 1 tests and commit**

Run: `rtk pytest -q -p no:cacheprovider tests/test_workflow.py`

Run: `rtk git diff --check`

Expected: all Task 1 tests pass and no whitespace errors.

Commit: `Add workflow consent contracts`

## Task 2: Add Report Schema 1 and Explicit Coverage Output

**Files:**
- Modify: `src/agentguardian/reporting.py`
- Modify: `tests/test_reporting.py`

- [x] **Step 1: Write failing JSON schema tests**

Require top-level `report_schema == 1` and require both score objects to contain
the same exact `coverage_state`. Replace historical arbitrary synthetic limit
strings in report fixtures with canonical codes.

```python
payload = json.loads(render_json(score, findings, rule_version="rules-1"))
assert payload["report_schema"] == 1
assert payload["score"]["coverage_state"] == "limited"
assert payload["reviewed_score"]["coverage_state"] == "limited"
```

Add complete and no-supported-file cases and retain deterministic JSON equality.

- [x] **Step 2: Run JSON tests and verify RED**

Run: `rtk pytest -q -p no:cacheprovider tests/test_reporting.py -k 'schema or coverage'`

Expected: missing schema and coverage-state fields.

- [x] **Step 3: Implement schema 1 through the workflow classifier**

Call the single Task 1 classifier from `_validated_score_data`. Do not duplicate
coverage rules in `reporting.py`.

- [x] **Step 4: Write failing score-consistency and HTML tests**

Require technical and reviewed scores to share coverage, confidence,
incomplete, limits, and coverage state. Require deterministic HTML labels for
all three states and fixed safe reason descriptions. Contradictory pairs must
raise `ValueError("REPORT_INVALID")`.

- [x] **Step 5: Run the new tests and verify RED**

Run: `rtk pytest -q -p no:cacheprovider tests/test_reporting.py -k 'consistency or html'`

Expected: mismatched scores are accepted or HTML omits the explicit state.

- [x] **Step 6: Implement consistency validation and HTML output**

Preserve escaping, ordering, report item bounds, disposition privacy, and the
existing technical/reviewed totals.

- [x] **Step 7: Run reporting regression tests and commit**

Run: `rtk pytest -q -p no:cacheprovider tests/test_reporting.py tests/test_scoring.py`

Run: `rtk git diff --check`

Expected: all focused tests pass.

Commit: `Expose explicit report coverage states`

## Task 3: Add Pure View-Only Finding Filters

**Files:**
- Modify: `src/agentguardian/workflow.py`
- Modify: `tests/test_workflow.py`

- [x] **Step 1: Write failing filter tests**

Create synthetic findings spanning all severities, domains, multiple evidence
rows, and open/false-positive/accepted-risk/expired states. Require exact
severity, domain, and disposition filters, including combinations.

```python
visible = filter_findings(
    findings,
    dispositions,
    FindingFilters(
        severity=Severity.HIGH,
        domain=RiskDomain.CREDENTIALS,
        disposition_state="open",
    ),
    now=EVALUATED_AT,
)
```

Assert counts are per finding, original tuple order is preserved, inputs are not
mutated, and evidence count does not become finding count.

- [x] **Step 2: Run filters and verify RED**

Run: `rtk pytest -q -p no:cacheprovider tests/test_workflow.py -k filter`

Expected: missing filter contract/function.

- [x] **Step 3: Implement minimal filter predicates**

Reuse `disposition_index` and `evaluate_disposition`. Validate one exact UTC
evaluation time. Reject invalid enum/string criteria and hostile iterables at a
bounded fixed error boundary.

- [x] **Step 4: Add expiry and privacy regression tests**

Prove the same finding moves from false-positive to expired under a later time,
and prove no `disposition_ref`, reason, reviewer, raw match, or full path enters
filter labels or representations.

- [x] **Step 5: Run Task 3 tests and commit**

Run: `rtk pytest -q -p no:cacheprovider tests/test_workflow.py tests/test_dispositions.py`

Run: `rtk git diff --check`

Commit: `Add view-only finding filters`

## Task 4: Parse and Compare Strict Aggregate Reports

**Files:**
- Create: `src/agentguardian/report_comparison.py`
- Create: `tests/test_report_comparison.py`

- [x] **Step 1: Write failing schema-1 summary tests**

Build reports with the real renderer. Require immutable `ReportSummary` fields
for technical score, reviewed score, coverage ratio/state, finding count, and
sorted counts by rule, severity, disposition state, and canonical limits.

- [x] **Step 2: Run summary tests and verify RED**

Run: `rtk pytest -q -p no:cacheprovider tests/test_report_comparison.py -k schema_1`

Expected: module import failure.

- [x] **Step 3: Implement a strict schema-1 parser**

Use `json.loads` with explicit rejection of `NaN`, `Infinity`, and
`-Infinity`. Require exact built-in types and exact key sets. Reuse existing
domain validation for enum values, fingerprints, display names, masked evidence,
annotations, and timestamps. Enforce 2,000 findings and 4,000 total evidence.
Discard item-level values after aggregation.

- [x] **Step 4: Write failing legacy-schema tests**

Create an exact legacy report by removing `report_schema` and score
`coverage_state` from a valid rendered payload. Require derived coverage state
and the same aggregate summary. Reject partial legacy/new hybrids and unknown
schema versions.

- [x] **Step 5: Implement only exact legacy compatibility**

Do not infer or guess future schemas. Unknown and extra keys fail closed.

- [x] **Step 6: Write failing aggregate-delta tests**

Require signed `current - baseline` score/count/coverage deltas, sorted category
deltas, added limits as `current - baseline`, and resolved limits as
`baseline - current`. Assert comparison objects contain none of:

- evidence source or masked text;
- fingerprints or `disposition_ref`;
- reason, reviewer, or timestamps; or
- individual `new`, `fixed`, `matched`, or `unchanged` claims.

- [x] **Step 7: Implement immutable deterministic comparison**

Use tuples of sorted key/count pairs. Do not retain parsed payloads.

- [x] **Step 8: Add hostile and bounded-input tests**

Parametrize missing/extra keys, booleans as numbers, non-finite values, invalid
domains/severities/statuses, unsafe strings, malformed fingerprints, duplicate
or unknown limits, contradictory scores, 2,001 findings, and 4,001 evidence
entries. Every failure must normalize to `REPORT_COMPARISON_INVALID` without
including attacker text.

- [x] **Step 9: Run Task 4 tests and commit**

Run: `rtk pytest -q -p no:cacheprovider tests/test_report_comparison.py tests/test_reporting.py`

Run: `rtk git diff --check`

Commit: `Add aggregate report comparison`

Review follow-up: recompute both scores from validated ephemeral findings,
validate forged summary limits before sorting or set operations, classify
summary coverage through the canonical contract, and validate masked text
through the existing `Evidence` domain contract.

## Task 5: Add the Bounded Baseline File Boundary

**Files:**
- Modify: `src/agentguardian/report_comparison.py`
- Modify: `tests/test_report_comparison.py`

- [x] **Step 1: Write failing local-file boundary tests**

Require a user-supplied `.json` path, regular file, strict UTF-8, and maximum
2 MiB. Reject before parsing:

- UNC paths;
- non-JSON suffixes;
- directories and devices;
- a symlink/reparse point at any existing path component;
- files larger than 2 MiB; and
- a file that grows beyond the limit during the bounded read.

Use synthetic temporary paths only. Windows junction tests may skip when the
test process cannot create a junction.

- [x] **Step 2: Run file tests and verify RED**

Run: `rtk pytest -q -p no:cacheprovider tests/test_report_comparison.py -k file`

Expected: missing file loader or unsafe paths are accepted.

- [x] **Step 3: Implement the bounded loader**

Read at most `2 MiB + 1` bytes, reject a sentinel byte, decode UTF-8 strictly,
and pass text to the one Task 4 parser. Recheck regular/reparse state around the
read and normalize all errors to the fixed comparison error. Document the
remaining same-user path replacement race.

- [x] **Step 4: Add privacy and cleanup tests**

Use a secret marker and full path marker in a malformed report. Assert neither
appears in the exception, summary, comparison, or `repr`.

- [x] **Step 5: Run Task 5 tests and commit**

Run: `rtk pytest -q -p no:cacheprovider tests/test_report_comparison.py`

Run: `rtk git diff --check`

Commit: `Bound baseline report imports`

## Task 6: Integrate Scope Consent and Coverage into the Desktop Workflow

**Files:**
- Modify: `src/agentguardian/app.py`
- Modify: `tests/test_app_smoke.py`

- [x] **Step 1: Write failing scope UI tests**

Update `test_folder_selection_shows_only_short_name` and add focused tests that
require:

- a stable preview of selectors, numeric caps, exclusions, local/read-only
  mode, and manual guidance;
- no full selected path in visible text, tooltips, or widget representations;
- an unchecked consent checkbox after root selection;
- a disabled scan button until consent; and
- root change/rejection clearing consent, old audit, and comparison state.

- [x] **Step 2: Run scope UI tests and verify RED**

Run: `rtk pytest -q -p no:cacheprovider tests/test_app_smoke.py -k 'folder_selection or scope_preview or consent'`

Expected: scan remains enabled without consent and preview widgets are absent.

- [x] **Step 3: Implement the minimum scope UI**

Add `QCheckBox`, fixed preview labels, and private transient consent. Use the
Task 1 contract. Keep the existing three-page layout and minimum window size.

- [x] **Step 4: Write failing callback and lifecycle tests**

Call `_start_scan()` directly with missing, stale, and forged consent and assert
no thread/worker/discovery/randomness starts. Require valid consent to be reset
before the worker starts. Update the three existing click-to-scan tests to check
consent explicitly. A completed scan must require new consent before rerun.

- [x] **Step 5: Implement callback revalidation and consent consumption**

Do not trust only Qt enabled state. Keep fixed safe status messages.

- [x] **Step 6: Write failing coverage UI tests**

Require distinct complete, limited, and no-supported-file labels, percentages,
fixed reason descriptions, and the exact incomplete disclaimer. Unknown or
contradictory state must fail at the fixed report/audit boundary.

- [x] **Step 7: Implement coverage UI through the Task 1 classifier**

Do not create a second coverage calculation. Never say a complete configured
scope proves provider, account, endpoint, or system safety.

- [x] **Step 8: Run Task 6 tests and commit**

Run: `rtk pytest -q -p no:cacheprovider tests/test_app_smoke.py -k 'scope or consent or coverage or supported_files or threaded_worker'`

Run: `rtk git diff --check`

Commit: `Require explicit scan scope consent`

## Task 7: Integrate Finding Filters Without Mutating Evidence

**Files:**
- Modify: `src/agentguardian/app.py`
- Modify: `tests/test_app_smoke.py`

- [x] **Step 1: Write failing filter-control tests**

Require three compact combo boxes with exact all/value options and a stable
`visible findings / total findings` label. At 960 by 640, controls, table,
disposition actions, and guidance must not overlap or resize when options change.

- [x] **Step 2: Run control tests and verify RED**

Run: `rtk pytest -q -p no:cacheprovider tests/test_app_smoke.py -k filter_control`

Expected: controls do not exist.

- [x] **Step 3: Implement controls backed by pure filters**

Derive visible findings from `AuditOutcome.findings`; render all evidence rows
for each visible finding. Keep a row-to-finding map only for visible rows.

- [x] **Step 4: Write failing isolation tests**

Capture immutable outcome, scores, reports, dispositions, and protected-state
save calls. Change every filter and assert only table rows, count label,
selection, guidance, and action enabled states change. An empty filtered view
must not say the audit found no risks.

- [x] **Step 5: Write failing disposition-expiry tests**

With a disposition-only filter active, advance the validated evaluation time
through expiry and require the row to move to the expired filter. Reuse the same
time used for reviewed score/report refresh.

- [x] **Step 6: Implement filter refresh and selection clearing**

Integrate with scan completion, disposition create/replace/withdraw, expiry
timer, report invalidation, and scan failure. Contain unexpected filter errors
without altering the authoritative outcome or report.

- [x] **Step 7: Run Task 7 tests and commit**

Run: `rtk pytest -q -p no:cacheprovider tests/test_workflow.py tests/test_app_smoke.py -k 'filter or disposition or expiry'`

Run: `rtk git diff --check`

Commit: `Add view-only finding filters to UI`

## Task 8: Integrate Transient Aggregate Comparison into the Report Page

**Files:**
- Modify: `src/agentguardian/app.py`
- Modify: `tests/test_app_smoke.py`

- [x] **Step 1: Write failing comparison UI tests**

Require a baseline JSON selection command, clear command, short-name label, and
aggregate comparison view. Selection is disabled before a current audit.
Selecting a valid synthetic baseline must show baseline/current/delta for scores,
coverage, finding count, category counts, and added/resolved limits.

- [x] **Step 2: Run comparison UI tests and verify RED**

Run: `rtk pytest -q -p no:cacheprovider tests/test_app_smoke.py -k comparison`

Expected: comparison controls do not exist.

- [x] **Step 3: Implement transient comparison state**

Use `QFileDialog.getOpenFileName` with JSON filter, `load_report_summary()` for
the baseline, and `summarize_report_json()` for the current report. Store only
the short baseline name and aggregate objects. Render deterministic text/table
without item-level data.

- [x] **Step 4: Write failing fixed-error and privacy tests**

Inject invalid, oversized, and secret-bearing baseline files. Require one fixed
Chinese error message and cleared comparison state. Assert full path, raw JSON,
evidence, fingerprints, reason, reviewer, and timestamps never enter visible
widgets, reports, protected state, or exceptions.

- [x] **Step 5: Write failing reset/export-isolation tests**

Require root selection, scan start, scan failure, and `_invalidate_report()` to
clear comparison. Filter changes must not clear it. Export content must remain
byte-for-byte equal before and after comparison.

- [x] **Step 6: Implement reset and fixed callback boundaries**

Comparison failures clear comparison only, never the valid current audit.
Unexpected Qt callback exceptions do not escape.

- [x] **Step 7: Add minimum-size layout checks**

At 960 by 640, report controls and comparison output must not overlap. Use Qt
standard icons where available and tooltips for unfamiliar commands.

- [x] **Step 8: Run Task 8 tests and commit**

Run: `rtk pytest -q -p no:cacheprovider tests/test_report_comparison.py tests/test_app_smoke.py -k 'comparison or export or report_page'`

Run: `rtk git diff --check`

Commit: `Add transient aggregate report comparison UI`

## Task 9: Close Local Security, Documentation, and Package Evidence

**Files:**
- Modify: `tests/test_self_audit.py`
- Modify: `src/agentguardian/source_policy.json`
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/reports/alpha-0.1.0-stage-report.md`
- Modify: `docs/superpowers/plans/2026-08-02-agentguardian-windows-mvp-hardening.md`
- Modify: `docs/superpowers/plans/2026-08-03-agentguardian-windows-workflow-report-hardening.md`

- [x] **Step 1: Add failing documentation and capability assertions**

Require current docs to state:

- per-scan scope-bound consent;
- the three coverage states and incomplete disclaimer;
- filters are UI-only and exports remain complete;
- comparison is bounded, aggregate-only, transient, and JSON-only;
- legacy/schema-1 compatibility and no report authenticity claim;
- no exact finding matching or exported stable identifier;
- baseline read adds no ambient scan, network, API, or write capability;
- same-user/path-race/clock/aggregate-collision/dependency/binary limits; and
- Batches 5-6, Windows MVP, and production safety remain open.

- [x] **Step 2: Run documentation assertions and verify RED**

Run: `rtk pytest -q -p no:cacheprovider tests/test_self_audit.py -k batch_4`

Expected: missing current status documentation.

- [x] **Step 3: Update only verified behavior in docs**

Record local implementation evidence only. Do not claim remote CI or Batch 4
acceptance before the final SHA workflows complete.

- [x] **Step 4: Regenerate the exact reviewed-source manifest**

Update canonical source SHA-256 values for every package `.py` module, including
the two new modules. Do not weaken exact module-set checks or sign/attest claims.

- [x] **Step 5: Run focused source-policy and wheel tests**

Run: `rtk pytest -q -p no:cacheprovider tests/test_self_audit.py tests/test_packaging.py`

Expected: source manifest matches exactly; wheel contains the policy and rules;
offline extraction probe passes.

- [x] **Step 6: Run the complete local gate on Python 3.14**

Run: `rtk pytest -q -p no:cacheprovider`

Run: `rtk proxy python scripts/check_brand_assets.py`

Run: `rtk proxy python -m compileall -q src`

Run: `rtk git diff --check`

Run with `PYTHONPATH=src`:

`rtk proxy python -c "import json; from agentguardian.self_audit import collect_self_audit; print(json.dumps(collect_self_audit(), sort_keys=True))"`

Expected: zero failures, no whitespace errors, `findings=[]`, `local_only=true`,
and `network_capability=not_detected`. Record skips separately.

- [x] **Step 7: Run the complete local gate on Python 3.12**

Use the available locked local test environment without mixing incompatible
binary packages. Run the full suite and source compilation. Record any local
environment limitation separately; do not convert it into code success.

- [x] **Step 8: Commit local Batch 4 evidence**

Commit: `Document Batch 4 local verification`

Task 9 checkbox evidence was captured on 2026-08-03 for
`991bf81bb520e7f2ec12f331fbbe714f03212507`. Assertion-only commits through `9d87f972df6c5021482cf6dfc01b0ecf8ced86c9`
passed the focused `tests/test_self_audit.py tests/test_packaging.py` gate with
`143 passed` on 2026-08-13. No runtime or package source changed in those
assertion-only commits. That result does not cover a later docs/tests
synchronization commit; Task 10 must rerun both complete Python gates at the
current reviewed HEAD.

## Task 10: Independent Review and Final-SHA Remote Evidence

**Files:**
- Modify only if review findings require TDD fixes or final evidence wording.

- [ ] **Step 1: Run independent read-only specification review**

Review every design goal/non-goal and acceptance criterion against the complete
diff. Resolve every gap with a failing test first. If a fix changes package
source, regenerate the exact source-policy manifest before re-running gates.

- [ ] **Step 2: Run independent read-only security and quality review**

Cover consent bypass, full-path leakage, filter/report divergence, expiry-time
consistency, report parser confusion, JSON non-finite values, collection bounds,
symlink/reparse races, baseline lifecycle, exception leakage, deterministic
output, source-policy integrity, synthetic-only fixtures, and no-network/no-API
boundaries. Resolve every Critical, Important, and Minor finding and re-review
to zero open findings. Regenerate the source-policy manifest after any reviewed
package-source fix.

- [ ] **Step 3: Re-run the complete local gate at the reviewed HEAD**

Repeat both Python versions, brand validation, compilation, diff check, package
test, and package-source self-audit. Do not reuse pre-fix results.

- [ ] **Step 4: Commit any synchronized review evidence**

Keep the commit docs/tests-only when runtime code did not change. Distinguish the
reviewed implementation SHA from later evidence-only commits.

- [ ] **Step 5: Push and verify both final-HEAD workflows**

Push `agent/founder-alpha`. Wait for both push and Draft PR workflows for the
exact final HEAD. Record:

- final local and remote SHA equality;
- exact run and job IDs;
- Windows pass/skip/fail counts;
- each named workflow step conclusion; and
- check-run annotation counts.

- [ ] **Step 6: Synchronize Batch 4 acceptance without evidence loops**

Record the remotely accepted implementation/evidence baseline in the stage
report. If a later docs-only evidence commit is needed, state exactly which runs
cover which SHA, then verify that final docs-only HEAD separately in the handoff.

- [ ] **Step 7: Final boundary check**

Confirm Draft PR #1 remains open/draft. Do not merge, deploy, mark ready, or say
Windows MVP/production safety is complete. Keep Batches 5-6 pending.

## Plan Completion Gate

This plan is complete only when Tasks 1-10 and both review stages pass and the
final pushed HEAD has successful push and Draft PR CI evidence. Passing Batch 4
proves only the documented Windows workflow/report-hardening gate. It does not
complete packaging provenance, the Windows MVP release candidate, or production
safety.
