# AgentGuardian Finding Dispositions and Expiring Exceptions Design

**Status:** Approved for implementation planning on 2026-08-02.

## Purpose

Windows MVP Batch 3 adds local, auditable `false_positive` and `accepted_risk` dispositions. A disposition must survive an application restart and match the same occurrence on a later scan without persisting or exporting the raw match or full path. Expired, invalid, missing, or unmatched dispositions fail closed and leave the finding open.

This batch preserves the confirmed OpenAI Provider boundary: local discovery, static detection, and manual guidance only. It does not import an OpenAI SDK, make an API request, verify an endpoint remotely, revoke a credential, or modify provider configuration.

## Goals

- Match a disposition across scans only when the rule, normalized source location, and normalized raw match are unchanged.
- Keep exported report fingerprints scan-scoped and unlinkable across scans.
- Persist the separate local matching key and disposition records only inside the existing current-user DPAPI state.
- Require an explicit user action, reason, reviewer, creation time, and finite expiry for every disposition.
- Reopen expired or unmatched findings automatically.
- Preserve an unadjusted technical score and expose a separately reviewed score.
- Keep accepted risks in the reviewed score; exclude only active false positives.
- Keep reports deterministic, escaped, and auditable without exporting the local matching reference.

## Non-Goals

- Rule-wide suppression or organization-wide policy.
- Cloud synchronization, team approval workflows, remote identity, or API calls.
- Permanent exceptions.
- Automatic remediation or credential rotation.
- Fuzzy matching after a file move, rename, rule change, or content change.
- A complete disposition event ledger. The protected state retains the latest record for each local matching reference; previously exported reports remain immutable audit evidence.
- Finding filtering and report comparison, which remain Batch 4 work.

## Chosen Architecture

### Two Independent HMAC Purposes

The existing scan key remains random for every scan. It continues to produce the `root_fingerprint` and evidence fingerprints shown in the UI and exported reports.

Batch 3 adds a second 32-byte random matching key. It produces a local-only `disposition_ref` from a length-delimited canonical message containing:

1. the rule ID;
2. the normalized absolute source path used for that scan; and
3. the NFKC-normalized raw match.

The local matching key and `disposition_ref` never appear in JSON, HTML, status text, logs, exceptions, or object representations. The full source path and raw match are inputs only and are not retained by the disposition model.

The path is normalized with the host Windows path rules before hashing. A renamed or moved file, changed raw match, changed rule ID, or changed matching key produces a different reference and therefore reopens the finding. Identical matches under the same rule in the same file share one disposition; the same value in another file remains independent.

### Matching-Key Lifecycle

At startup the application attempts a read-only load of the existing protected state:

- A valid current state supplies its matching key and latest dispositions.
- A valid legacy Batch 2 state supplies no dispositions; a fresh in-memory matching key is generated.
- A missing state produces a fresh in-memory matching key and no dispositions.
- A corrupt, undecryptable, oversized, or incompatible state produces no active dispositions and a fixed `PROTECTED_STATE_INVALID` condition.

Missing or legacy state is not written automatically. The fresh key is persisted only when the user explicitly saves encrypted state or creates, changes, or withdraws a disposition. A corrupt state is never overwritten silently; the first attempted disposition or protected-state save requires explicit replacement confirmation.

### Protected-State Evolution

The existing DPAPI file remains the single controlled user-data-write location. Its payload advances to schema version 2 and contains:

- the existing minimized evidence snapshot;
- a 32-byte local disposition HMAC key encoded as fixed lowercase hexadecimal; and
- a bounded, deterministically ordered tuple of disposition records.

The decoder accepts canonical schema version 1 as a legacy input and maps it to an empty disposition set with no matching key. Encoding always writes canonical version 2. Migration happens only during a later explicit save; startup never rewrites the file.

All existing 1 MiB state size, count, duplicate-key, canonical-order, application-integrity, DPAPI, UNC, reparse, temporary-file, `fsync`, and atomic-replacement constraints remain in force. A schema, key, disposition, integrity, or decryption failure rejects the entire state with `PROTECTED_STATE_INVALID`.

## Disposition Model

Each latest disposition record contains exactly:

- `disposition_ref`: 64 lowercase hexadecimal characters;
- `rule_id`: the rule that generated the reference;
- `status`: `false_positive` or `accepted_risk`;
- `reason`: trimmed printable text, 1 to 240 characters;
- `reviewer`: a trimmed printable label, 1 to 80 characters;
- `created_at`: canonical UTC seconds;
- `expires_at`: canonical UTC seconds later than `created_at` and no more than 366 days later.

Reason and reviewer text use the same secret, URL, path, seed-phrase, and control-character rejection boundary as other exported user-visible values. No record may contain unknown fields. Records are unique by `disposition_ref`, ordered by that reference, and capped by the existing finding limit. A record whose `rule_id` differs from the current finding does not match even if its reference is present.

Withdrawal removes the current record only after the updated protected state is saved successfully. Expired records remain in protected state and reports as expired audit context, but they do not change scoring or the open status. Reapplying a disposition replaces the latest record for that reference with a new creation and expiry time.

## Evaluation and Scoring

Disposition evaluation receives an explicit UTC `now`; production supplies the current UTC time and tests use a fixed value.

A record is active only when all of the following are true:

- its `disposition_ref` equals the current finding's local reference;
- its `rule_id` equals the finding's rule ID; and
- `created_at <= now < expires_at`.

All other findings are open. Evaluation never falls back to rule-only, source-name-only, masked-text, or scan-fingerprint matching.

Every audit calculates two scores from the same coverage, confidence, and limits:

- **Technical score:** all detected findings, regardless of disposition.
- **Reviewed score:** all open findings plus active `accepted_risk` findings; active `false_positive` findings are excluded.

An accepted risk therefore remains a technical deduction and cannot raise the reviewed score. Expired false positives immediately re-enter the reviewed score. Both scores retain their own cap reason and domain deductions.

## Reports

JSON retains the existing `score` object as the unadjusted technical score for compatibility and adds `reviewed_score`. Each finding adds a `disposition` object with one of these report states:

- `open`, with no reviewer metadata;
- `false_positive` or `accepted_risk`, with reason, reviewer, creation, and expiry;
- `expired`, with the last status and its metadata.

HTML presents the same information with escaped text. Reports continue to include only scan-scoped finding fingerprints. They never include `disposition_ref`, the matching key, a full path, a raw match, a DPAPI path, or native error details.

Report ordering remains deterministic. A disposition update regenerates both report formats from the same immutable findings, current disposition set, and evaluation time before the state is committed to the UI.

## Desktop Interaction

The findings table gains a compact disposition-status column without filtering or hiding rows. Selecting a row enables explicit commands to:

- mark it as a false positive;
- accept the risk;
- withdraw the current disposition.

Creating or replacing a disposition uses a modal form with a status selector, reason input, reviewer input, and date control. Expiry is mandatory and cannot exceed 366 days. The save command is disabled until all fields validate. Withdrawal requires confirmation.

The operation is transactional:

1. build and validate a candidate record set;
2. build the updated schema-v2 protected state;
3. save it through the existing DPAPI atomic store;
4. only after save succeeds, update in-memory dispositions, scores, table state, and reports.

If encryption or persistence fails, the current UI and reports remain unchanged and show only a fixed safe failure message. A disposition action is the explicit authorization for that write; scans and report exports still do not save automatically.

## Failure Behavior

- Missing disposition: finding is open.
- Expired disposition: finding is open and reported as expired.
- Rule or local-reference mismatch: finding is open.
- Invalid metadata or timestamp: reject the whole protected state.
- Missing legacy matching key: generate a fresh in-memory key; no legacy finding is silently matched.
- Corrupt protected state: no disposition is active, do not silently overwrite, and expose only `PROTECTED_STATE_INVALID`.
- State-save failure: retain the prior in-memory state, score, report, and on-disk ciphertext.
- Clock before `created_at`: disposition is inactive and the finding is open.

## Security Boundaries and Limitations

- DPAPI binds the state to the current Windows user and machine but does not defend against software already controlling that user session.
- The stable local reference intentionally permits local cross-scan correlation inside the protected state. It is never exported.
- Matching depends on the host clock and canonical path. Clock rollback, file moves, or path aliases can reopen findings; they never silently broaden an exception.
- The existing path-check-to-`os.replace` same-user race and lack of handle-level directory binding remain documented limitations.
- Python cannot guarantee erasure of every immutable bytes or string copy holding a key, path, or raw match.
- Static self-audit remains a bounded source-policy check, not semantic proof over dependencies or binaries.
- No API, telemetry, updater, shell, clipboard, browser database, or automatic remediation capability is added.

## Verification Contract

Implementation follows TDD and uses synthetic values only. Acceptance requires:

- reference determinism for the same rule/path/value and separation for any changed component;
- proof that local references and matching keys never enter JSON, HTML, UI text, exceptions, or `repr`;
- exact active, accepted-risk, false-positive, expired, future-created, mismatch, and withdrawal behavior at fixed times;
- technical and reviewed score tests, including cap behavior;
- schema-v1 read compatibility, schema-v2 canonical round trip, limits, unknown fields, duplicate keys, malformed timestamps, malformed metadata, and key validation;
- native Windows DPAPI and atomic replacement round trips;
- corrupt-state failure closing and explicit replacement confirmation;
- UI tests proving dispositions write only after explicit action and rollback fully on save failure;
- deterministic JSON/HTML report tests with safe escaping;
- self-audit confirmation of no network, LLM, telemetry, updater, shell, clipboard, or unexpected write capability;
- complete local tests, brand validation, source compilation, whitespace checks, independent read-only review, and successful push plus Draft PR Windows CI.

Passing Batch 3 does not complete Batches 4-6 and does not establish production safety.
