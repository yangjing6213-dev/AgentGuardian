# Windows MVP Threat Model

Status: Batch 6 local security gate in progress. This document does not establish a release candidate and does not establish production safety.

## Scope

The target is AgentGuardian 0.1.0 Founder Alpha running as a standard Windows user. The runtime may discover explicitly approved local configuration roots, read supported local files, produce redacted in-memory findings, save a new report only at a user-selected destination outside scanned roots, and store minimized evidence state protected by Windows DPAPI.

The runtime must not call OpenAI or another provider API, verify a remote endpoint, open a network client, execute commands, read browser databases or the clipboard, load dynamic plugins, elevate privileges, update itself, or perform remediation. Tests use synthetic data only.

## Trust Boundaries

1. User-selected scan roots and known local configuration roots are untrusted filesystem input.
2. File contents, report files, rule data, persisted evidence state, and artifact metadata are untrusted structured input.
3. The current standard-user process and Windows DPAPI user boundary are trusted only against other users; an active attacker controlling the same user account remains outside the protection claim.
4. PyPI packages, GitHub Actions, build runners, signing services, installers, and redistribution rights are release supply-chain boundaries and need evidence separate from local tests.

## Checklist

`verified-local` means the selected local negative tests pass at the cited source baseline. `partial-local` means a local control is tested while a documented residual risk remains. `blocked-external` means local code cannot provide the required evidence.

| Threat ID | Scenario | Control and selected verification | Status | Residual or external evidence |
| --- | --- | --- | --- | --- |
| AG-T01 | A stale or forged consent value starts a scan after the scope changes. | Consent is bound to normalized roots and selectors, revalidated, consumed before worker construction, and revoked on scope change. `tests/test_app_smoke.py::test_start_scan_rejects_missing_stale_or_forged_consent_before_side_effects` | verified-local | UI automation does not prove user understanding. |
| AG-T02 | A drive root, UNC path, device path, or ambiguous Windows path expands the scan beyond the intended scope. | Root validation rejects broad or non-local roots before discovery. `tests/test_app_smoke.py::test_unc_paths_are_rejected_before_filesystem_access` `tests/test_discovery.py::test_discovery_rejects_windows_roots_before_filesystem_access` | verified-local | Mapped network drives are not reliably identified. |
| AG-T03 | A symlink, junction, reparse point, or path replacement redirects reads. | Discovery and report loading recheck file identity and reparse state and fail closed. `tests/test_discovery.py::test_discovery_discards_batch_when_reparse_appears_after_scandir` `tests/test_report_comparison.py::test_report_file_replacement_race_fails_closed` | partial-local | No handle sandbox exists against an active same-user replacement race. |
| AG-T04 | Large trees, files, findings, evidence, or hostile iterators exhaust time or memory. | File, entry, byte, finding, evidence, state, and report budgets stop bounded work and mark coverage incomplete. `tests/test_app_smoke.py::test_audit_evidence_cap_rejects_partial_finding_batch` `tests/test_app_smoke.py::test_total_byte_limit_stops_before_over_budget_file` `tests/test_report_comparison.py::test_hostile_2001_findings_fail_before_item_validation` `tests/test_report_comparison.py::test_hostile_4001_evidence_fail_before_item_validation` | verified-local | Fixed synthetic performance implementation exists; clean-SHA evidence remains pending. |
| AG-T05 | A detected credential, full path, disposition reference, or private callback error leaks to reports. | Detection fingerprints and masks evidence before rendering; renderers reject unsafe values. `tests/test_reporting.py::test_real_detection_scoring_reporting_chain_keeps_raw_data_private` | verified-local | A local user can still read the original files they already control. |
| AG-T06 | A hostile baseline report forges scores, duplicate keys, dispositions, limits, or counts. | The parser enforces exact schemas and recomputes technical and reviewed scores. `tests/test_report_comparison.py::test_hostile_duplicate_json_keys_fail_closed` `tests/test_report_comparison.py::test_score_recomputation_rejects_independent_contradictions` | verified-local | Parsing validates structure and consistency, not report authenticity. |
| AG-T07 | Persisted state is tampered with, replayed, malformed, or used to forge dispositions. | DPAPI, an internal digest envelope, exact schema validation, and deep startup revalidation fail closed. `tests/test_windows_dpapi.py::test_dpapi_tamper_fails_closed_without_echoing_data` `tests/test_app_smoke.py::test_startup_rejects_forged_snapshot_invariants_without_writing` | verified-local | Same-user control, host clock manipulation, and backup replay remain residual risks. |
| AG-T08 | Runtime or packaging drift introduces network, API, LLM, shell, clipboard, telemetry, updater, or unreviewed source capability. | Source policy hashes the exact package module set; static negative probes and frozen-layout checks reject known network capability. `tests/test_self_audit.py::test_current_package_has_no_prohibited_static_capabilities` `tests/test_self_audit.py::test_static_scan_detects_network_import_families_and_aliases` `tests/test_windows_packaging.py::test_frozen_layout_rejects_network_components` | verified-local | Static inspection does not prove third-party binaries have no capability. |
| AG-T09 | Report export overwrites a file, writes inside a scanned root, or follows a redirected parent. | Export uses exclusive creation and repeated resolved-parent checks outside captured scan roots. `tests/test_app_smoke.py::test_export_new_report_is_exclusive_and_outside_scanned_roots` `tests/test_app_smoke.py::test_export_rejects_resolved_parent_symlink_into_scanned_root` | partial-local | An active same-user reparse replacement race remains documented. |
| AG-T10 | A forged, expired, mismatched, or overlong finding disposition suppresses technical risk. | Hidden HMAC references bind rule, normalized path, and raw match; expiry is mandatory and reviewed score is separate. `tests/test_dispositions.py::test_disposition_reference_is_deterministic_normalized_and_hidden` `tests/test_dispositions.py::test_evaluate_disposition_covers_open_active_expired_and_future_states` | verified-local | Host clock manipulation can affect expiry evaluation. |
| AG-T11 | A dirty or mismatched source tree produces an untraceable or modified portable artifact. | The build requires a clean exact HEAD and creates canonical manifests, hashes, SBOM data, and deterministic ZIP output while rejecting reparse points. `tests/test_windows_packaging.py::test_artifact_manifest_rejects_reparse_points` `tests/test_windows_packaging.py::test_git_build_context_requires_clean_exact_head` | verified-local | The current portable artifact is unsigned and locally built. |
| AG-T12 | A release artifact is substituted, built on an untrusted runner, signed by an unapproved identity, installed with unexpected privilege, or distributed without resolved rights. | Local manifests and hashes provide inspection evidence only. | blocked-external | Requires `APPROVE_GITHUB_WORKFLOW_SCOPE_REFRESH`, fresh-runner provenance, trusted code signing, a clean Windows machine, native install and uninstall evidence, and license and redistribution review. |

## Local Gate

Run `python -B scripts/run_windows_mvp_security_gate.py`. The script invokes only the selected existing pytest node IDs for AG-T01 through AG-T11, uses the current interpreter, disables pytest cache writes, and performs no network or provider API call.

Passing this selected gate is necessary local evidence only. The full test suites, performance gate, independent read-only review, current GitHub CI, AG-T12 external evidence, and a release-candidate report remain separate gates.

## Performance Gate

Run `python -B scripts/measure_windows_mvp_performance.py --source-sha <full-sha> --measured-at <canonical-utc-seconds> --output .analysis/<new-file>.json` from a clean exact source SHA. The output path must be new and inside the ignored `.analysis` directory.

The fixed workloads and local budgets are:

- scan 1,000 synthetic files three times: no more than 15.0 seconds and 48 MiB peak traced Python allocation per run;
- render and parse a report containing 1,000 synthetic findings three times: no more than 3.0 seconds, 16 MiB peak traced Python allocation, and 1 MiB UTF-8 output per run.

The command records all samples, worst observations, budgets, interpreter version, explicit measurement time, and exact source SHA in canonical JSON. Any malformed observation or exceeded budget fails closed.

This representative local workload does not cover the 10,000-file functional maximum, native installer startup, whole-process resident memory, antivirus variance, slow disks, or a fresh Windows runner. Existing functional caps, portable launch smoke, fresh-runner performance, and clean-machine acceptance remain separate evidence.
