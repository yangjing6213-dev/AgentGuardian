import json
from pathlib import Path

import pytest

import scripts.measure_windows_mvp_performance as performance_gate


ROOT = Path(__file__).resolve().parents[1]
THREAT_MODEL = ROOT / "docs" / "security" / "windows-mvp-threat-model.md"


def _samples(
    *,
    seconds: float,
    peak_bytes: int,
    output_bytes: int | None = None,
) -> tuple[dict[str, int | float], ...]:
    sample: dict[str, int | float] = {
        "seconds": seconds,
        "peak_bytes": peak_bytes,
    }
    if output_bytes is not None:
        sample["output_bytes"] = output_bytes
    return tuple(dict(sample) for _ in range(performance_gate.RUNS))


def test_performance_workloads_and_budgets_are_fixed_and_bounded() -> None:
    assert performance_gate.RUNS == 3
    assert performance_gate.SCAN_FILE_COUNT == 1_000
    assert performance_gate.REPORT_FINDING_COUNT == 1_000
    assert performance_gate.WORKLOAD_BUDGETS == {
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


def test_observation_evaluation_fails_closed_on_time_memory_or_size() -> None:
    passing = {
        "scan_1000_files": _samples(seconds=1.0, peak_bytes=1024),
        "report_1000_findings": _samples(
            seconds=1.0,
            peak_bytes=1024,
            output_bytes=4096,
        ),
    }
    result = performance_gate.evaluate_observations(passing)

    assert result["passed"] is True
    assert result["workloads"]["scan_1000_files"]["passed"] is True

    for workload, field, value in (
        ("scan_1000_files", "seconds", 15.000001),
        ("scan_1000_files", "peak_bytes", 48 * 1024 * 1024 + 1),
        ("report_1000_findings", "seconds", 3.000001),
        ("report_1000_findings", "peak_bytes", 16 * 1024 * 1024 + 1),
        ("report_1000_findings", "output_bytes", 1 * 1024 * 1024 + 1),
    ):
        failing = {
            name: tuple(dict(sample) for sample in samples)
            for name, samples in passing.items()
        }
        failing[workload][0][field] = value
        evaluated = performance_gate.evaluate_observations(failing)
        assert evaluated["passed"] is False
        assert evaluated["workloads"][workload]["passed"] is False


@pytest.mark.parametrize(
    ("observations", "message"),
    (
        ({}, "workload set"),
        (
            {
                "scan_1000_files": _samples(seconds=1.0, peak_bytes=1024)[:-1],
                "report_1000_findings": _samples(
                    seconds=1.0, peak_bytes=1024, output_bytes=4096
                ),
            },
            "sample count",
        ),
        (
            {
                "scan_1000_files": _samples(seconds=-1.0, peak_bytes=1024),
                "report_1000_findings": _samples(
                    seconds=1.0, peak_bytes=1024, output_bytes=4096
                ),
            },
            "invalid observation",
        ),
    ),
)
def test_observation_evaluation_rejects_malformed_evidence(
    observations: object,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        performance_gate.evaluate_observations(observations)


def test_performance_evidence_is_canonical_and_contains_no_machine_path(
    tmp_path: Path,
) -> None:
    observations = {
        "scan_1000_files": _samples(seconds=1.25, peak_bytes=2048),
        "report_1000_findings": _samples(
            seconds=0.5,
            peak_bytes=4096,
            output_bytes=8192,
        ),
    }
    output = tmp_path / "performance.json"
    evidence = performance_gate.build_evidence(
        source_sha="a" * 40,
        measured_at="2026-08-14T10:00:00Z",
        observations=observations,
        python_implementation="CPython",
        python_version="3.12.2",
    )

    performance_gate.write_evidence(output, evidence)
    rendered = output.read_text(encoding="utf-8")

    assert rendered.endswith("\n")
    assert json.loads(rendered) == evidence
    assert str(tmp_path) not in rendered
    assert evidence["schema_version"] == 1
    assert evidence["source_sha"] == "a" * 40
    assert evidence["measured_at"] == "2026-08-14T10:00:00Z"
    assert evidence["passed"] is True
    with pytest.raises(FileExistsError):
        performance_gate.write_evidence(output, evidence)


@pytest.mark.parametrize(
    ("head", "status", "source_sha", "message"),
    (
        ("a" * 40, "", "short", "full lowercase"),
        ("a" * 40, "", "b" * 40, "does not match"),
        ("a" * 40, " M README.md", "a" * 40, "clean"),
    ),
)
def test_performance_context_requires_clean_exact_head(
    head: str,
    status: str,
    source_sha: str,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        performance_gate.validate_git_context(head, status, source_sha)

    performance_gate.validate_git_context("a" * 40, "", "a" * 40)


@pytest.mark.parametrize(
    "value",
    (
        "2026-08-14T10:00:00+00:00",
        "2026-08-14T10:00:00.1Z",
        "2026-08-14T10:00:00z",
        "not-a-time",
    ),
)
def test_measurement_time_requires_canonical_utc_seconds(value: str) -> None:
    with pytest.raises(ValueError, match="canonical UTC seconds"):
        performance_gate.validate_measured_at(value)

    assert (
        performance_gate.validate_measured_at("2026-08-14T10:00:00Z")
        == "2026-08-14T10:00:00Z"
    )


def test_threat_model_records_performance_scope_budgets_and_limits() -> None:
    text = THREAT_MODEL.read_text(encoding="utf-8")

    for required in (
        "python -B scripts/measure_windows_mvp_performance.py",
        "1,000 synthetic files",
        "15.0 seconds",
        "48 MiB",
        "1,000 synthetic findings",
        "3.0 seconds",
        "16 MiB",
        "1 MiB",
        "clean exact source SHA",
        "does not cover the 10,000-file functional maximum",
    ):
        assert required in text
