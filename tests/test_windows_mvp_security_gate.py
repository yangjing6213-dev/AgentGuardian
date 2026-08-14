import ast
from pathlib import Path

import scripts.run_windows_mvp_security_gate as security_gate


ROOT = Path(__file__).resolve().parents[1]
THREAT_MODEL = ROOT / "docs" / "security" / "windows-mvp-threat-model.md"


def _test_functions(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    }


def test_local_security_cases_cover_each_locally_testable_threat_once() -> None:
    expected_ids = tuple(f"AG-T{number:02d}" for number in range(1, 12))
    case_ids = tuple(threat_id for threat_id, _selectors in security_gate.SECURITY_CASES)
    selectors = tuple(
        selector
        for _threat_id, threat_selectors in security_gate.SECURITY_CASES
        for selector in threat_selectors
    )

    assert case_ids == expected_ids
    assert len(selectors) == len(set(selectors))
    assert selectors

    for selector in selectors:
        relative_path, separator, test_name = selector.partition("::")
        assert separator == "::"
        assert relative_path.startswith("tests/")
        assert test_name.startswith("test_")
        test_path = ROOT / relative_path
        assert test_path.is_file()
        assert test_name in _test_functions(test_path)


def test_security_gate_command_is_local_bounded_and_plugin_stable() -> None:
    command = security_gate.build_pytest_command("python-test")
    selectors = tuple(
        selector
        for _threat_id, threat_selectors in security_gate.SECURITY_CASES
        for selector in threat_selectors
    )

    assert command == (
        "python-test",
        "-B",
        "-m",
        "pytest",
        "-q",
        "-p",
        "no:cacheprovider",
        *selectors,
    )
    assert not any(value.startswith(("http://", "https://")) for value in command)


def test_threat_model_tracks_local_controls_and_external_release_blockers() -> None:
    text = THREAT_MODEL.read_text(encoding="utf-8")

    for number in range(1, 13):
        assert text.count(f"| AG-T{number:02d} |") == 1
    for threat_id, selectors in security_gate.SECURITY_CASES:
        assert threat_id in text
        for selector in selectors:
            assert f"`{selector}`" in text

    assert "AG-T12" in text
    assert "blocked-external" in text
    assert "APPROVE_GITHUB_WORKFLOW_SCOPE_REFRESH" in text
    assert "trusted code signing" in text
    assert "clean Windows machine" in text
    assert "native install and uninstall" in text
    assert "license and redistribution review" in text
    assert "does not establish a release candidate" in text
    assert "does not establish production safety" in text
