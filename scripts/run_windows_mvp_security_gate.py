from __future__ import annotations

import subprocess
import sys
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYTEST_TIMEOUT_SECONDS = 120
ALLOWED_SKIPS = {
    (
        "tests/test_app_smoke.py::test_export_rejects_resolved_parent_symlink_into_scanned_root",
        "directory symlink unavailable",
    )
}

SECURITY_CASES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "AG-T01",
        (
            "tests/test_app_smoke.py::test_start_scan_rejects_missing_stale_or_forged_consent_before_side_effects",
            "tests/test_app_smoke.py::test_start_scan_consumes_valid_consent_before_worker_construction",
        ),
    ),
    (
        "AG-T02",
        (
            "tests/test_app_smoke.py::test_unc_paths_are_rejected_before_filesystem_access",
            "tests/test_discovery.py::test_discovery_rejects_windows_roots_before_filesystem_access",
            "tests/test_workflow.py::test_scope_root_anchor_rejects_unqualified_windows_roots",
        ),
    ),
    (
        "AG-T03",
        (
            "tests/test_discovery.py::test_discovery_discards_batch_when_reparse_appears_after_scandir",
            "tests/test_report_comparison.py::test_report_file_replacement_race_fails_closed",
        ),
    ),
    (
        "AG-T04",
        (
            "tests/test_app_smoke.py::test_audit_evidence_cap_rejects_partial_finding_batch",
            "tests/test_app_smoke.py::test_total_byte_limit_stops_before_over_budget_file",
            "tests/test_report_comparison.py::test_hostile_2001_findings_fail_before_item_validation",
            "tests/test_report_comparison.py::test_hostile_4001_evidence_fail_before_item_validation",
        ),
    ),
    (
        "AG-T05",
        (
            "tests/test_reporting.py::test_real_detection_scoring_reporting_chain_keeps_raw_data_private",
        ),
    ),
    (
        "AG-T06",
        (
            "tests/test_report_comparison.py::test_hostile_duplicate_json_keys_fail_closed",
            "tests/test_report_comparison.py::test_score_recomputation_rejects_independent_contradictions",
        ),
    ),
    (
        "AG-T07",
        (
            "tests/test_windows_dpapi.py::test_dpapi_tamper_fails_closed_without_echoing_data",
            "tests/test_app_smoke.py::test_startup_rejects_forged_snapshot_invariants_without_writing",
        ),
    ),
    (
        "AG-T08",
        (
            "tests/test_self_audit.py::test_current_package_has_no_prohibited_static_capabilities",
            "tests/test_self_audit.py::test_static_scan_detects_network_import_families_and_aliases",
            "tests/test_windows_packaging.py::test_frozen_layout_rejects_network_components",
        ),
    ),
    (
        "AG-T09",
        (
            "tests/test_app_smoke.py::test_export_new_report_is_exclusive_and_outside_scanned_roots",
            "tests/test_app_smoke.py::test_export_rejects_resolved_parent_symlink_into_scanned_root",
        ),
    ),
    (
        "AG-T10",
        (
            "tests/test_dispositions.py::test_disposition_reference_is_deterministic_normalized_and_hidden",
            "tests/test_dispositions.py::test_evaluate_disposition_covers_open_active_expired_and_future_states",
        ),
    ),
    (
        "AG-T11",
        (
            "tests/test_windows_packaging.py::test_artifact_manifest_rejects_reparse_points",
            "tests/test_windows_packaging.py::test_git_build_context_requires_clean_exact_head",
        ),
    ),
)


def build_pytest_command(python_executable: str = sys.executable) -> tuple[str, ...]:
    selectors = tuple(
        selector
        for _threat_id, threat_selectors in SECURITY_CASES
        for selector in threat_selectors
    )
    return (
        python_executable,
        "-B",
        "-m",
        "pytest",
        "-q",
        "-p",
        "no:cacheprovider",
        "-p",
        "scripts.security_gate_pytest_plugin",
        *selectors,
    )


def main() -> int:
    environment = os.environ.copy()
    environment.pop("PYTEST_ADDOPTS", None)
    environment.pop("PYTEST_PLUGINS", None)
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    try:
        completed = subprocess.run(
            build_pytest_command(),
            cwd=ROOT,
            check=False,
            env=environment,
            timeout=PYTEST_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        print(
            f"security gate timed out after {PYTEST_TIMEOUT_SECONDS} seconds",
            file=sys.stderr,
        )
        return 124
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
