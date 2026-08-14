from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gc
import json
import math
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
import tracemalloc
from typing import Callable, TypeVar


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentguardian import app  # noqa: E402
from agentguardian.domain import Evidence, Finding, RiskDomain, Severity  # noqa: E402
from agentguardian.report_comparison import parse_report_summary  # noqa: E402
from agentguardian.reporting import render_json  # noqa: E402
from agentguardian.scoring import score  # noqa: E402


RUNS = 3
SCAN_FILE_COUNT = 1_000
REPORT_FINDING_COUNT = 1_000
WORKLOAD_BUDGETS: dict[str, dict[str, int | float]] = {
    "report_1000_findings": {
        "max_output_bytes": 1 * 1024 * 1024,
        "max_peak_bytes": 16 * 1024 * 1024,
        "max_seconds": 3.0,
    },
    "scan_1000_files": {
        "max_peak_bytes": 48 * 1024 * 1024,
        "max_seconds": 15.0,
    },
}
_EVALUATED_AT = datetime(2026, 8, 14, tzinfo=timezone.utc)
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
_T = TypeVar("_T")


def validate_git_context(head: str, status: str, source_sha: str) -> None:
    if len(source_sha) != 40 or any(
        character not in "0123456789abcdef" for character in source_sha
    ):
        raise ValueError("source SHA must be a full lowercase SHA-1")
    if head != source_sha:
        raise ValueError("source SHA does not match HEAD")
    if status.strip():
        raise ValueError("worktree must be clean")


def validate_measured_at(value: str) -> str:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        raise ValueError("measurement time must be canonical UTC seconds") from None
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ValueError("measurement time must be canonical UTC seconds")
    return value


def evaluate_observations(observations: object) -> dict[str, object]:
    if type(observations) is not dict or set(observations) != set(WORKLOAD_BUDGETS):
        raise ValueError("invalid workload set")

    workload_results: dict[str, object] = {}
    all_passed = True
    for name in sorted(WORKLOAD_BUDGETS):
        budget = WORKLOAD_BUDGETS[name]
        samples = observations[name]
        if type(samples) is not tuple or len(samples) != RUNS:
            raise ValueError("invalid sample count")
        requires_output_size = "max_output_bytes" in budget
        expected_fields = {"seconds", "peak_bytes"}
        if requires_output_size:
            expected_fields.add("output_bytes")

        normalized_samples: list[dict[str, int | float]] = []
        for sample in samples:
            if type(sample) is not dict or set(sample) != expected_fields:
                raise ValueError("invalid observation")
            seconds = sample["seconds"]
            peak_bytes = sample["peak_bytes"]
            if (
                type(seconds) not in {int, float}
                or not math.isfinite(seconds)
                or seconds < 0
                or type(peak_bytes) is not int
                or peak_bytes < 0
            ):
                raise ValueError("invalid observation")
            normalized: dict[str, int | float] = {
                "peak_bytes": peak_bytes,
                "seconds": round(float(seconds), 6),
            }
            if requires_output_size:
                output_bytes = sample["output_bytes"]
                if type(output_bytes) is not int or output_bytes < 0:
                    raise ValueError("invalid observation")
                normalized["output_bytes"] = output_bytes
            normalized_samples.append(normalized)

        max_seconds = max(float(sample["seconds"]) for sample in samples)
        max_peak_bytes = max(int(sample["peak_bytes"]) for sample in samples)
        passed = (
            max_seconds <= float(budget["max_seconds"])
            and max_peak_bytes <= int(budget["max_peak_bytes"])
        )
        observed: dict[str, int | float] = {
            "max_peak_bytes": max_peak_bytes,
            "max_seconds": round(max_seconds, 6),
        }
        if requires_output_size:
            max_output_bytes = max(int(sample["output_bytes"]) for sample in samples)
            observed["max_output_bytes"] = max_output_bytes
            passed = passed and max_output_bytes <= int(budget["max_output_bytes"])

        workload_results[name] = {
            "budget": dict(budget),
            "observed": observed,
            "passed": passed,
            "samples": normalized_samples,
        }
        all_passed = all_passed and passed

    return {"passed": all_passed, "workloads": workload_results}


def build_evidence(
    *,
    source_sha: str,
    measured_at: str,
    observations: object,
    python_implementation: str,
    python_version: str,
) -> dict[str, object]:
    validate_git_context(source_sha, "", source_sha)
    validate_measured_at(measured_at)
    if python_implementation != "CPython" or _VERSION.fullmatch(python_version) is None:
        raise ValueError("unsupported Python identity")
    evaluated = evaluate_observations(observations)
    return {
        "measured_at": measured_at,
        "passed": evaluated["passed"],
        "phase": "windows_mvp_batch_6",
        "product": "AgentGuardian",
        "python": {
            "implementation": python_implementation,
            "version": python_version,
        },
        "schema_version": 1,
        "source_sha": source_sha,
        "workloads": evaluated["workloads"],
    }


def write_evidence(path: Path, evidence: dict[str, object]) -> None:
    rendered = json.dumps(
        evidence,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    with open(path, "x", encoding="utf-8", newline="\n") as stream:
        stream.write(rendered)
        stream.write("\n")


def _measure(operation: Callable[[], _T]) -> tuple[_T, dict[str, int | float]]:
    gc.collect()
    tracemalloc.start()
    started = time.perf_counter()
    try:
        result = operation()
        elapsed = time.perf_counter() - started
        _current, peak_bytes = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return result, {"peak_bytes": peak_bytes, "seconds": elapsed}


def _create_scan_fixture(root: Path) -> None:
    for index in range(SCAN_FILE_COUNT):
        (root / f"file-{index:04d}.txt").write_text(
            "synthetic harmless content\n",
            encoding="utf-8",
        )


def _scan_samples(root: Path) -> tuple[dict[str, int | float], ...]:
    roots = (Path(os.path.abspath(root)),)
    preview = app._scope_preview_for(roots)
    samples: list[dict[str, int | float]] = []
    for _ in range(RUNS):
        outcome, observation = _measure(
            lambda: app._run_audit(
                roots,
                scope_preview=preview,
                disposition_key=b"d" * 32,
                evaluated_at=_EVALUATED_AT,
            )
        )
        if outcome.findings or outcome.score.incomplete:
            raise RuntimeError("synthetic scan workload did not complete cleanly")
        samples.append(observation)
    return tuple(samples)


def _report_fixture() -> tuple[tuple[Finding, ...], object]:
    findings = tuple(
        Finding(
            rule_id="TEST_RULE",
            domain=RiskDomain.CREDENTIALS,
            severity=Severity.HIGH,
            root_fingerprint=f"{index:064x}",
            evidence=(
                Evidence(
                    source=f"file-{index}.txt",
                    fingerprint=f"{index + REPORT_FINDING_COUNT:064x}",
                    masked="masked",
                ),
            ),
        )
        for index in range(REPORT_FINDING_COUNT)
    )
    return findings, score(findings, coverage=1.0)


def _report_samples() -> tuple[dict[str, int | float], ...]:
    findings, audit_score = _report_fixture()
    samples: list[dict[str, int | float]] = []
    for _ in range(RUNS):
        def render_and_parse() -> str:
            rendered = render_json(
                audit_score,
                findings,
                rule_version="1.1.0",
                reviewed_score=audit_score,
                evaluated_at=_EVALUATED_AT,
            )
            summary = parse_report_summary(rendered)
            if summary.finding_count != REPORT_FINDING_COUNT:
                raise RuntimeError("synthetic report workload count changed")
            return rendered

        rendered, observation = _measure(render_and_parse)
        observation["output_bytes"] = len(rendered.encode("utf-8"))
        samples.append(observation)
    return tuple(samples)


def run_workloads() -> dict[str, tuple[dict[str, int | float], ...]]:
    with TemporaryDirectory(prefix="agentguardian-performance-") as raw_root:
        scan_root = Path(raw_root)
        _create_scan_fixture(scan_root)
        scan = _scan_samples(scan_root)
    return {
        "report_1000_findings": _report_samples(),
        "scan_1000_files": scan,
    }


def _git(*arguments: str) -> str:
    completed = subprocess.run(
        ("git", *arguments),
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _validated_output_path(value: str) -> Path:
    output = Path(value).resolve()
    analysis_root = (ROOT / ".analysis").resolve()
    try:
        output.relative_to(analysis_root)
    except ValueError:
        raise ValueError("output must be inside the ignored .analysis directory") from None
    if output.suffix.lower() != ".json":
        raise ValueError("output must be a JSON file")
    if output.exists():
        raise FileExistsError("output already exists")
    if not output.parent.is_dir():
        raise FileNotFoundError("output parent does not exist")
    return output


def main(argv: tuple[str, ...] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--measured-at", required=True)
    parser.add_argument("--output", required=True)
    arguments = parser.parse_args(argv)

    output = _validated_output_path(arguments.output)
    head = _git("rev-parse", "HEAD")
    status = _git("status", "--porcelain=v1", "--untracked-files=all")
    validate_git_context(head, status, arguments.source_sha)
    validate_measured_at(arguments.measured_at)

    evidence = build_evidence(
        source_sha=arguments.source_sha,
        measured_at=arguments.measured_at,
        observations=run_workloads(),
        python_implementation=platform.python_implementation(),
        python_version=platform.python_version(),
    )
    write_evidence(output, evidence)
    return 0 if evidence["passed"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
