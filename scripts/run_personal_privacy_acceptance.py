"""Run the personal privacy acceptance gate with sanitized local data."""

from __future__ import annotations

import argparse
import json
import os
import socket
import sqlite3
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch


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


_RAW_MARKER = "".join(("sk", "-", "proj", "-", "PERSONAL_PRIVACY_CANARY"))


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


@contextmanager
def _deny_network_requests(events: list[str]):
    def blocked(name: str):
        def record(*args: object, **kwargs: object) -> None:
            events.append(name)
            raise RuntimeError("PERSONAL_PRIVACY_ACCEPTANCE_FAILED")

        return record

    with (
        patch.object(socket, "getaddrinfo", blocked("getaddrinfo")),
        patch.object(socket, "create_connection", blocked("create_connection")),
        patch.object(socket.socket, "connect", blocked("connect")),
        patch.object(socket.socket, "connect_ex", blocked("connect_ex")),
    ):
        yield


def run_acceptance(
    evidence_path: str | Path,
    *,
    sample_root: str | Path | None = None,
) -> dict[str, object]:
    destination = Path(evidence_path).resolve()
    if not destination.parent.is_dir():
        raise ValueError("evidence path must have an existing parent directory")
    supplied_root = (
        None if sample_root is None else _validated_sample_root(sample_root)
    )
    network_events: list[str] = []
    workspace_path: Path

    with _deny_network_requests(network_events):
        with tempfile.TemporaryDirectory(
            dir=destination.parent,
            prefix="agentguardian-personal-privacy-",
        ) as workspace:
            workspace_path = Path(workspace)
            if supplied_root is None:
                scan_root = workspace_path / "scan"
                scan_root.mkdir()
                (scan_root / "credentials.env").write_text(
                    f"OPENAI_API_KEY={_RAW_MARKER}\n",
                    encoding="utf-8",
                )
                source_kind = "generated_synthetic"
            else:
                scan_root = supplied_root
                source_kind = "supplied_sanitized_sample"
            roots = (scan_root,)
            outcome = _run_audit(
                roots,
                scope_preview=_scope_preview_for(roots),
                disposition_key=b"p" * 32,
            )
            report_json = outcome.report_json
            report_html = outcome.report_html
            report_path = workspace_path / "report.json"
            export_new_report(report_path, report_json, roots)
            exported_report = report_path.read_text(encoding="utf-8")
            sample_path = os.fspath(scan_root)
            report_checks = {
                "json_redacted": _RAW_MARKER not in report_json,
                "html_redacted": _RAW_MARKER not in report_html,
                "export_redacted": _RAW_MARKER not in exported_report,
                "sample_path_absent_from_json": sample_path not in report_json,
                "sample_path_absent_from_html": sample_path not in report_html,
                "sample_path_absent_from_export": sample_path not in exported_report,
            }

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
                    f"""
                    CREATE TABLE urls (id INTEGER, url TEXT);
                    CREATE TABLE visits (id INTEGER, url INTEGER);
                    INSERT INTO urls VALUES (1, 'https://example.test/{_RAW_MARKER}');
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
            raw_markers_absent = (
                report_checks["json_redacted"]
                and report_checks["html_redacted"]
                and report_checks["export_redacted"]
                and not clipboard_checks["raw_marker_in_findings"]
            )

    workspace_cleanup = not workspace_path.exists()
    claims = {
        "redacted_reports": all(
            report_checks[field]
            for field in ("json_redacted", "html_redacted", "export_redacted")
        ),
        "clipboard_raw_retained": clipboard_checks["raw_data_retained"],
        "browser_snapshot_cleaned": (
            browser_checks["temporary_copy_removed"]
            and not browser_checks["raw_data_retained"]
        ),
        "temporary_workspace_cleaned": workspace_cleanup,
        "raw_markers_absent": raw_markers_absent,
        "default_api_call": bool(network_events),
    }
    passed = (
        all(report_checks.values())
        and outcome.findings != ()
        and clipboard_checks
        == {
            "scanned": True,
            "raw_data_retained": False,
            "raw_marker_in_findings": False,
        }
        and browser_checks
        == {
            "temporary_copy_removed": True,
            "raw_data_retained": False,
        }
        and claims
        == {
            "redacted_reports": True,
            "clipboard_raw_retained": False,
            "browser_snapshot_cleaned": True,
            "temporary_workspace_cleaned": True,
            "raw_markers_absent": True,
            "default_api_call": False,
        }
    )
    result: dict[str, object] = {
        "schema": 1,
        "profile": "personal_privacy_acceptance",
        "passed": passed,
        "claims": claims,
        "report": report_checks,
        "sample": {
            "source_kind": source_kind,
            "finding_count": len(outcome.findings),
            "coverage": outcome.score.coverage,
            "incomplete": outcome.score.incomplete,
        },
        "clipboard": clipboard_checks,
        "browser": browser_checks,
        "workspace_cleanup": workspace_cleanup,
    }
    evidence = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if _RAW_MARKER in evidence or os.fspath(scan_root) in evidence:
        raise RuntimeError("PERSONAL_PRIVACY_ACCEPTANCE_FAILED")
    destination.write_text(evidence, encoding="utf-8", newline="\n")
    if result["passed"] is not True:
        raise RuntimeError("PERSONAL_PRIVACY_ACCEPTANCE_FAILED")
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
