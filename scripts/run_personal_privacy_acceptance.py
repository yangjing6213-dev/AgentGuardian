"""Run the personal privacy acceptance gate with sanitized local data."""

from __future__ import annotations

import argparse
import html
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
from contextlib import ExitStack, contextmanager
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


def _text_omits_path(text: str, path: Path) -> bool:
    folded = text.casefold()
    native = os.fspath(path)
    values = {
        native,
        path.as_posix(),
        native.replace("/", "\\"),
        native.replace("\\", "/"),
    }
    return all(value.casefold() not in folded for value in values)


def _structured_value_omits_path(value: object, path: Path) -> bool:
    if isinstance(value, str):
        return _text_omits_path(value, path)
    if isinstance(value, list):
        return all(_structured_value_omits_path(item, path) for item in value)
    if isinstance(value, dict):
        return all(
            _structured_value_omits_path(key, path)
            and _structured_value_omits_path(item, path)
            for key, item in value.items()
        )
    return True


def _json_omits_path(document: str, path: Path) -> bool:
    try:
        value = json.loads(document)
    except (json.JSONDecodeError, RecursionError):
        return False
    return _structured_value_omits_path(value, path)


def _html_omits_path(document: str, path: Path) -> bool:
    return _text_omits_path(html.unescape(document), path)


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


class _ObservedAcceptanceAttempt(Exception):
    pass


def _observation_targets() -> tuple[tuple[object, str, str, str], ...]:
    targets = [
        (socket, "getaddrinfo", "dns", "socket.getaddrinfo"),
        (socket, "create_connection", "tcp", "socket.create_connection"),
        (socket.socket, "connect", "tcp", "socket.socket.connect"),
        (socket.socket, "connect_ex", "tcp", "socket.socket.connect_ex"),
        (socket.socket, "sendto", "udp", "socket.socket.sendto"),
    ]
    if hasattr(socket.socket, "sendmsg"):
        targets.append(
            (socket.socket, "sendmsg", "udp", "socket.socket.sendmsg")
        )
    targets.append((subprocess, "Popen", "subprocess", "subprocess.Popen"))
    return tuple(targets)


class _BoundedObservation:
    def __init__(self) -> None:
        self.categories: list[str] = []
        self.workspace_path: Path | None = None
        self.sample_path: Path | None = None

    @property
    def attempted(self) -> bool:
        return bool(self.categories)

    def block(self, category: str) -> None:
        if category not in self.categories:
            self.categories.append(category)
        raise _ObservedAcceptanceAttempt

    def evidence(self) -> dict[str, object]:
        return {
            "intercepted_call_sites": [
                identifier for *_, identifier in _observation_targets()
            ],
            "limitations": {
                "pre_bound_aliases": "not_observed",
                "socket_apis_outside_listed_call_sites": "not_observed",
                "native_extensions": "not_observed",
                "direct_os_calls": "not_observed",
                "concurrent_threads": "unsupported",
            },
            "default_api_call_within_declared_boundary": self.attempted,
            "attempt_categories": sorted(self.categories),
        }


@contextmanager
def _deny_network_requests(observation: _BoundedObservation):
    def blocked(category: str):
        def record(*args: object, **kwargs: object) -> None:
            observation.block(category)

        return record

    with ExitStack() as stack:
        for owner, name, category, _identifier in _observation_targets():
            stack.enter_context(patch.object(owner, name, blocked(category)))
        yield


def _run_acceptance_observed(
    evidence_path: str | Path,
    *,
    sample_root: str | Path | None = None,
    observation: _BoundedObservation,
) -> dict[str, object]:
    destination = Path(evidence_path).resolve()
    if not destination.parent.is_dir():
        raise ValueError("evidence path must have an existing parent directory")
    supplied_root = (
        None if sample_root is None else _validated_sample_root(sample_root)
    )
    workspace_path: Path

    with _deny_network_requests(observation):
        with tempfile.TemporaryDirectory(
            dir=destination.parent,
            prefix="agentguardian-personal-privacy-",
        ) as workspace:
            workspace_path = Path(workspace)
            observation.workspace_path = workspace_path
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
            observation.sample_path = scan_root
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
            report_checks = {
                "json_redacted": _RAW_MARKER not in report_json,
                "html_redacted": _RAW_MARKER not in report_html,
                "export_redacted": _RAW_MARKER not in exported_report,
                "sample_path_absent_from_json": _json_omits_path(
                    report_json, scan_root
                ),
                "sample_path_absent_from_html": _html_omits_path(
                    report_html, scan_root
                ),
                "sample_path_absent_from_export": _json_omits_path(
                    exported_report, scan_root
                ),
                "workspace_path_absent_from_json": _json_omits_path(
                    report_json, workspace_path
                ),
                "workspace_path_absent_from_html": _html_omits_path(
                    report_html, workspace_path
                ),
                "workspace_path_absent_from_export": (
                    _json_omits_path(exported_report, workspace_path)
                ),
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
            raw_markers_absent_from_outputs = (
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
        "raw_markers_absent": raw_markers_absent_from_outputs,
        "default_api_call": observation.attempted,
    }
    result: dict[str, object] = {
        "schema": 1,
        "profile": "personal_privacy_acceptance",
        "passed": False,
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
        "network_observation": observation.evidence(),
        "workspace_cleanup": workspace_cleanup,
    }
    evidence_probe = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    evidence_checks = {
        "raw_marker_absent_from_evidence": _RAW_MARKER not in evidence_probe,
        "sample_path_absent_from_evidence": _json_omits_path(
            evidence_probe, scan_root
        ),
        "workspace_path_absent_from_evidence": _json_omits_path(
            evidence_probe, workspace_path
        ),
    }
    report_checks.update(evidence_checks)
    claims["raw_markers_absent"] = (
        raw_markers_absent_from_outputs
        and all(evidence_checks.values())
    )
    result["passed"] = (
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
    evidence = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    final_evidence_checks = {
        "raw_marker_absent_from_evidence": _RAW_MARKER not in evidence,
        "sample_path_absent_from_evidence": _json_omits_path(evidence, scan_root),
        "workspace_path_absent_from_evidence": _json_omits_path(
            evidence, workspace_path
        ),
    }
    if final_evidence_checks != evidence_checks or not all(
        final_evidence_checks.values()
    ):
        raise RuntimeError("PERSONAL_PRIVACY_ACCEPTANCE_FAILED")
    destination.write_text(evidence, encoding="utf-8", newline="\n")
    if result["passed"] is not True:
        raise RuntimeError("PERSONAL_PRIVACY_ACCEPTANCE_FAILED")
    return result


def _observed_attempt_failure(
    observation: _BoundedObservation,
) -> tuple[dict[str, object], str]:
    workspace_cleanup = (
        observation.workspace_path is None
        or not observation.workspace_path.exists()
    )
    report_checks = {
        "json_redacted": False,
        "html_redacted": False,
        "export_redacted": False,
        "sample_path_absent_from_json": False,
        "sample_path_absent_from_html": False,
        "sample_path_absent_from_export": False,
        "workspace_path_absent_from_json": False,
        "workspace_path_absent_from_html": False,
        "workspace_path_absent_from_export": False,
    }
    result: dict[str, object] = {
        "schema": 1,
        "profile": "personal_privacy_acceptance",
        "passed": False,
        "claims": {
            "redacted_reports": False,
            "clipboard_raw_retained": None,
            "browser_snapshot_cleaned": False,
            "temporary_workspace_cleaned": workspace_cleanup,
            "raw_markers_absent": False,
            "default_api_call": observation.attempted,
        },
        "report": report_checks,
        "sample": {
            "source_kind": "not_completed",
            "finding_count": 0,
            "coverage": 0.0,
            "incomplete": True,
        },
        "clipboard": {
            "scanned": False,
            "raw_data_retained": None,
            "raw_marker_in_findings": False,
        },
        "browser": {
            "temporary_copy_removed": False,
            "raw_data_retained": None,
        },
        "network_observation": observation.evidence(),
        "workspace_cleanup": workspace_cleanup,
    }
    evidence_probe = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    evidence_checks = {
        "raw_marker_absent_from_evidence": _RAW_MARKER not in evidence_probe,
        "sample_path_absent_from_evidence": (
            observation.sample_path is None
            or _json_omits_path(evidence_probe, observation.sample_path)
        ),
        "workspace_path_absent_from_evidence": (
            observation.workspace_path is None
            or _json_omits_path(evidence_probe, observation.workspace_path)
        ),
    }
    report_checks.update(evidence_checks)
    evidence = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    final_checks = {
        "raw_marker_absent_from_evidence": _RAW_MARKER not in evidence,
        "sample_path_absent_from_evidence": (
            observation.sample_path is None
            or _json_omits_path(evidence, observation.sample_path)
        ),
        "workspace_path_absent_from_evidence": (
            observation.workspace_path is None
            or _json_omits_path(evidence, observation.workspace_path)
        ),
    }
    if final_checks != evidence_checks or not all(final_checks.values()):
        raise RuntimeError("PERSONAL_PRIVACY_ACCEPTANCE_FAILED")
    return result, evidence


def run_acceptance(
    evidence_path: str | Path,
    *,
    sample_root: str | Path | None = None,
) -> dict[str, object]:
    observation = _BoundedObservation()
    try:
        return _run_acceptance_observed(
            evidence_path,
            sample_root=sample_root,
            observation=observation,
        )
    except _ObservedAcceptanceAttempt:
        destination = Path(evidence_path).resolve()
        result, evidence = _observed_attempt_failure(observation)
        destination.write_text(evidence, encoding="utf-8", newline="\n")
        raise RuntimeError("PERSONAL_PRIVACY_ACCEPTANCE_FAILED") from None


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
