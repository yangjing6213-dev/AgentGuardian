from pathlib import Path

from scripts.run_sensitive_data_acceptance import run_acceptance


def test_sensitive_data_acceptance_writes_only_redacted_evidence(
    tmp_path: Path,
) -> None:
    evidence_path = tmp_path / "sensitive-data-acceptance.json"

    result = run_acceptance(evidence_path)

    assert result["passed"] is True
    assert result["high_sensitivity"] == {
        "enabled": True,
        "api_access": False,
        "raw_persistence": False,
        "share_verification_blocked": True,
        "export_confirmation_required": True,
    }
    assert result["report"] == {
        "raw_marker_in_json": False,
        "raw_marker_in_html": False,
        "raw_marker_in_export": False,
        "export_confirmation_enforced": True,
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
    assert "sk-proj-" not in evidence_path.read_text(encoding="utf-8")
