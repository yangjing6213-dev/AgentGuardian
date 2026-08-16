import importlib.util
import json
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "run_personal_privacy_acceptance.py"
RAW_MARKER = "".join(("sk", "-", "proj", "-", "PERSONAL_PRIVACY_CANARY"))
TOP_LEVEL_FIELDS = (
    "schema",
    "profile",
    "passed",
    "claims",
    "report",
    "sample",
    "clipboard",
    "browser",
    "workspace_cleanup",
)
CLAIM_FIELDS = (
    "redacted_reports",
    "clipboard_raw_retained",
    "browser_snapshot_cleaned",
    "temporary_workspace_cleaned",
    "raw_markers_absent",
    "default_api_call",
)


def _load_acceptance_module():
    assert SCRIPT_PATH.is_file(), "personal privacy acceptance script is missing"
    spec = importlib.util.spec_from_file_location(
        "run_personal_privacy_acceptance", SCRIPT_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _all_fields(value: object) -> tuple[str, ...]:
    fields: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            fields.append(str(key))
            fields.extend(_all_fields(item))
    elif isinstance(value, (list, tuple)):
        for item in value:
            fields.extend(_all_fields(item))
    elif isinstance(value, str):
        fields.append(value)
    return tuple(fields)


def _assert_no_retired_product_fields(result: dict[str, object]) -> None:
    serialized_fields = "\n".join(_all_fields(result)).lower()
    forbidden = (
        "high" + "_sensitivity",
        "sensitive" + "_mode",
        "readiness",
        "enabled" + "_policy",
    )
    assert not any(term in serialized_fields for term in forbidden)


def test_personal_privacy_acceptance_writes_exact_redacted_evidence(
    tmp_path: Path,
) -> None:
    module = _load_acceptance_module()
    evidence_path = tmp_path / "personal-privacy-acceptance.json"

    result = module.run_acceptance(evidence_path)

    assert tuple(result) == TOP_LEVEL_FIELDS
    assert result["schema"] == 1
    assert result["profile"] == "personal_privacy_acceptance"
    assert result["passed"] is True
    assert tuple(result["claims"]) == CLAIM_FIELDS
    assert result["claims"] == {
        "redacted_reports": True,
        "clipboard_raw_retained": False,
        "browser_snapshot_cleaned": True,
        "temporary_workspace_cleaned": True,
        "raw_markers_absent": True,
        "default_api_call": False,
    }
    assert result["report"] == {
        "json_redacted": True,
        "html_redacted": True,
        "export_redacted": True,
        "sample_path_absent_from_json": True,
        "sample_path_absent_from_html": True,
        "sample_path_absent_from_export": True,
    }
    assert result["clipboard"] == {
        "scanned": True,
        "raw_data_retained": False,
        "raw_marker_in_findings": False,
    }
    assert result["browser"] == {
        "temporary_copy_removed": True,
        "raw_data_retained": False,
    }
    assert result["workspace_cleanup"] is True
    evidence = evidence_path.read_text(encoding="utf-8")
    assert json.loads(evidence) == result
    assert RAW_MARKER not in evidence
    assert str(tmp_path) not in evidence
    assert Path.home().name.lower() not in evidence.lower()
    _assert_no_retired_product_fields(result)


def test_personal_privacy_acceptance_uses_supplied_sanitized_sample(
    tmp_path: Path,
) -> None:
    module = _load_acceptance_module()
    sample_root = (tmp_path / "sanitized-sample").resolve()
    sample_root.mkdir()
    (sample_root / "config.env").write_text(
        f"OPENAI_API_KEY={RAW_MARKER}\n",
        encoding="utf-8",
    )
    evidence_path = tmp_path / "supplied-sample-acceptance.json"

    result = module.run_acceptance(evidence_path, sample_root=sample_root)

    assert result["passed"] is True
    assert result["sample"]["source_kind"] == "supplied_sanitized_sample"
    assert result["sample"]["finding_count"] >= 1
    assert all(result["report"].values())
    evidence = evidence_path.read_text(encoding="utf-8")
    assert RAW_MARKER not in evidence
    assert str(sample_root) not in evidence
    assert str(tmp_path) not in evidence


@pytest.mark.parametrize("sample_kind", ("relative", "missing", "file"))
def test_personal_privacy_acceptance_rejects_hostile_sample_roots(
    tmp_path: Path, sample_kind: str
) -> None:
    module = _load_acceptance_module()
    evidence_path = tmp_path / "rejected.json"
    if sample_kind == "relative":
        sample_root = Path("relative-sample")
    elif sample_kind == "missing":
        sample_root = (tmp_path / "missing").resolve()
    else:
        sample_root = (tmp_path / "sample.txt").resolve()
        sample_root.write_text("sanitized", encoding="utf-8")

    with pytest.raises(
        ValueError, match="^sample root must be an absolute local directory$"
    ):
        module.run_acceptance(evidence_path, sample_root=sample_root)

    assert not evidence_path.exists()


def test_personal_privacy_acceptance_rejects_reparse_sample_root(
    tmp_path: Path,
) -> None:
    module = _load_acceptance_module()
    target = (tmp_path / "target").resolve()
    target.mkdir()
    link = (tmp_path / "linked-sample").resolve()
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"directory symlink unavailable: {error.__class__.__name__}")

    with pytest.raises(
        ValueError, match="^sample root must be an absolute local directory$"
    ):
        module.run_acceptance(tmp_path / "rejected.json", sample_root=link)


def test_personal_privacy_claims_are_computed_from_observed_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_acceptance_module()
    evidence_path = tmp_path / "failed-acceptance.json"
    monkeypatch.setattr(
        module,
        "audit_clipboard_once",
        lambda *args, **kwargs: SimpleNamespace(
            scanned=True,
            raw_data_retained=True,
            findings=(),
        ),
    )

    with pytest.raises(RuntimeError, match="^PERSONAL_PRIVACY_ACCEPTANCE_FAILED$"):
        module.run_acceptance(evidence_path)

    result = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert result["passed"] is False
    assert result["clipboard"]["raw_data_retained"] is True
    assert result["claims"]["clipboard_raw_retained"] is True


def test_default_api_claim_tracks_bounded_network_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_acceptance_module()
    evidence_path = tmp_path / "network-attempt.json"

    @contextmanager
    def observed_attempt(events):
        events.append("synthetic-network-attempt")
        yield

    monkeypatch.setattr(module, "_deny_network_requests", observed_attempt)

    with pytest.raises(RuntimeError, match="^PERSONAL_PRIVACY_ACCEPTANCE_FAILED$"):
        module.run_acceptance(evidence_path)

    result = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert result["passed"] is False
    assert result["claims"]["default_api_call"] is True
