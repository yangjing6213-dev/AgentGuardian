import ast
from pathlib import Path
import subprocess

import scripts.run_windows_mvp_security_gate as security_gate
import scripts.security_gate_pytest_plugin as security_plugin


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
        "-p",
        "scripts.security_gate_pytest_plugin",
        *selectors,
    )
    assert not any(value.startswith(("http://", "https://")) for value in command)


def test_security_gate_sanitizes_pytest_environment_and_sets_timeout(
    monkeypatch,
) -> None:
    monkeypatch.setenv("PYTEST_ADDOPTS", "--collect-only")
    monkeypatch.setenv("PYTEST_PLUGINS", "untrusted_plugin")
    observed: dict[str, object] = {}

    def fake_run(command, *, cwd, check, env, timeout):
        observed.update(
            command=command,
            cwd=cwd,
            check=check,
            env=env,
            timeout=timeout,
        )
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(security_gate.subprocess, "run", fake_run)

    assert security_gate.main() == 0
    environment = observed["env"]
    assert isinstance(environment, dict)
    assert environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
    assert "PYTEST_ADDOPTS" not in environment
    assert "PYTEST_PLUGINS" not in environment
    assert observed["timeout"] == security_gate.PYTEST_TIMEOUT_SECONDS


def test_security_gate_allows_only_the_declared_environment_skip() -> None:
    assert security_gate.ALLOWED_SKIPS == {
        (
            "tests/test_app_smoke.py::test_export_rejects_resolved_parent_symlink_into_scanned_root",
            "directory symlink unavailable",
        )
    }


def test_security_gate_plugin_fails_unexpected_skips(monkeypatch) -> None:
    monkeypatch.setattr(
        security_plugin,
        "_skips",
        [("tests/test_app_smoke.py::test_unexpected", "Skipped: not declared")],
    )

    class Session:
        exitstatus = 0

    session = Session()
    security_plugin.pytest_sessionfinish(session, 0)

    assert session.exitstatus == 1


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
    for threat_id in ("AG-T04", "AG-T06", "AG-T07"):
        row = next(line for line in text.splitlines() if f"| {threat_id} |" in line)
        assert "| partial-local |" in row
