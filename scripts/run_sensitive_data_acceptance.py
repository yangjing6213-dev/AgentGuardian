"""Run the synthetic or user-supplied sanitized-data acceptance gate."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentguardian.app import (  # noqa: E402
    _run_audit,
    _scope_preview_for,
    export_new_report,
)
from agentguardian.browser_audit import BrowserKind, audit_browser_database  # noqa: E402
from agentguardian.clipboard_audit import audit_clipboard_once  # noqa: E402
from agentguardian.discovery import _has_reparse_component  # noqa: E402
from agentguardian.sensitive_mode import SensitiveModePolicy  # noqa: E402


_RAW_MARKER = "sk-proj-SYNTHETIC_AGENTGUARDIAN_MARKER_20260815"


def _validated_sample_root(value: str | Path) -> Path:
    root = Path(value)
    if (
        not root.is_absolute()
        or not root.is_dir()
        or root.is_symlink()
        or os.fspath(root).startswith(("\\\\", "//"))
        or _has_reparse_component(root)
    ):
        raise ValueError("sample root must be an absolute local directory")
    return root


def run_acceptance(
    evidence_path: str | Path,
    *,
    sample_root: str | Path | None = None,
) -> dict[str, object]:
    destination = Path(evidence_path).resolve()
    if not destination.is_absolute() or not destination.parent.is_dir():
        raise ValueError("evidence path must have an existing parent directory")
    validated_sample_root = (
        None if sample_root is None else _validated_sample_root(sample_root)
    )

    policy = SensitiveModePolicy.enabled_policy()
    export_confirmation_enforced = False
    report_checks: dict[str, bool]
    clipboard_checks: dict[str, bool]
    browser_checks: dict[str, bool]
    workspace_path: Path

    with tempfile.TemporaryDirectory(
        dir=destination.parent,
        prefix="agentguardian-sensitive-acceptance-",
    ) as workspace:
        workspace_path = Path(workspace)
        if validated_sample_root is None:
            scan_root = workspace_path / "scan"
            scan_root.mkdir()
            (scan_root / "credentials.env").write_text(
                f"OPENAI_API_KEY={_RAW_MARKER}\n",
                encoding="utf-8",
            )
            roots = (scan_root,)
            sample_source_kind = "synthetic"
        else:
            roots = (validated_sample_root,)
            sample_source_kind = "user_sanitized_sample"
        outcome = _run_audit(
            roots,
            scope_preview=_scope_preview_for(roots),
            disposition_key=b"s" * 32,
        )
        report_json = outcome.report_json
        report_html = outcome.report_html

        report_path = workspace_path / "report.json"
        try:
            export_new_report(
                report_path,
                report_json,
                roots,
                sensitive_mode=policy,
                export_confirmed=False,
            )
        except PermissionError as error:
            if error.args != ("SENSITIVE_EXPORT_CONFIRMATION_REQUIRED",):
                raise
            export_confirmation_enforced = True
        export_new_report(
            report_path,
            report_json,
            roots,
            sensitive_mode=policy,
            export_confirmed=True,
        )
        exported_report = report_path.read_text(encoding="utf-8")
        report_checks = {
            "raw_marker_in_json": _RAW_MARKER in report_json,
            "raw_marker_in_html": _RAW_MARKER in report_html,
            "raw_marker_in_export": _RAW_MARKER in exported_report,
            "export_confirmation_enforced": export_confirmation_enforced,
        }
        if validated_sample_root is not None:
            sample_path = os.fspath(validated_sample_root)
            report_checks.update(
                {
                    "sample_path_in_json": sample_path in report_json,
                    "sample_path_in_html": sample_path in report_html,
                    "sample_path_in_export": sample_path in exported_report,
                }
            )

        clipboard = audit_clipboard_once(
            lambda: _RAW_MARKER,
            scan_key=b"c" * 32,
        )
        clipboard_checks = {
            "scanned": clipboard.scanned,
            "raw_data_retained": clipboard.raw_data_retained,
            "raw_marker_in_findings": any(
                _RAW_MARKER in repr(finding) for finding in clipboard.findings
            ),
        }

        browser_path = workspace_path / "History"
        connection = sqlite3.connect(browser_path)
        try:
            connection.executescript(
                """
                CREATE TABLE urls (id INTEGER, url TEXT);
                CREATE TABLE visits (id INTEGER, url INTEGER);
                INSERT INTO urls VALUES (1, 'https://example.test/marker');
                INSERT INTO visits VALUES (1, 1);
                """
            )
        finally:
            connection.close()
        browser = audit_browser_database(browser_path, BrowserKind.CHROME)
        browser_checks = {
            "temporary_copy_removed": browser.temporary_copy_removed,
            "raw_data_retained": browser.raw_data_retained,
        }

    workspace_cleanup = not workspace_path.exists()
    expected_report_checks = {
        "raw_marker_in_json": False,
        "raw_marker_in_html": False,
        "raw_marker_in_export": False,
        "export_confirmation_enforced": True,
    }
    if validated_sample_root is not None:
        expected_report_checks.update(
            {
                "sample_path_in_json": False,
                "sample_path_in_html": False,
                "sample_path_in_export": False,
            }
        )
    result: dict[str, object] = {
        "schema_version": 1,
        "passed": (
            policy.enabled
            and not policy.api_access
            and not policy.raw_persistence
            and report_checks == expected_report_checks
            and clipboard_checks == {
                "scanned": True,
                "raw_data_retained": False,
                "raw_marker_in_findings": False,
            }
            and browser_checks == {
                "temporary_copy_removed": True,
                "raw_data_retained": False,
            }
            and workspace_cleanup
        ),
        "high_sensitivity": {
            "enabled": policy.enabled,
            "api_access": policy.api_access,
            "raw_persistence": policy.raw_persistence,
            "share_verification_blocked": policy.enabled,
            "export_confirmation_required": policy.export_requires_confirmation,
        },
        "report": report_checks,
        "sample": {
            "source_kind": sample_source_kind,
            "finding_count": len(outcome.findings),
            "coverage": outcome.score.coverage,
            "incomplete": outcome.score.incomplete,
        },
        "clipboard": clipboard_checks,
        "browser": browser_checks,
        "workspace_cleanup": workspace_cleanup,
    }
    destination.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    if not result["passed"]:
        raise RuntimeError("SENSITIVE_DATA_ACCEPTANCE_FAILED")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-path", type=Path, required=True)
    parser.add_argument("--sample-root", type=Path)
    args = parser.parse_args()
    result = run_acceptance(args.evidence_path, sample_root=args.sample_root)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
