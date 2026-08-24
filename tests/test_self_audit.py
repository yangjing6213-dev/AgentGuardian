import ast
import builtins
import hashlib
import io
import json
import re
import socket
import subprocess
import sys
import tokenize
import tomllib
from pathlib import Path

import pytest

from agentguardian import __version__, self_audit
from agentguardian.self_audit import collect_self_audit, static_capability_findings

PROJECT_ROOT = Path(__file__).parents[1]
PACKAGE_ROOT = PROJECT_ROOT / "src" / "agentguardian"
SOURCE_POLICY_PATH = PACKAGE_ROOT / "source_policy.json"
EXPECTED_REVIEWED_SOURCE_MODULES = (
    "__init__.py",
    "__main__.py",
    "app.py",
    "audit_service.py",
    "browser_audit.py",
    "clipboard_audit.py",
    "detectors.py",
    "discovery.py",
    "dispositions.py",
    "domain.py",
    "evidence_state.py",
    "guidance.py",
    "remediation.py",
    "report_comparison.py",
    "reporting.py",
    "scoring.py",
    "self_audit.py",
    "share_verification.py",
    "state_store.py",
    "windows_dpapi.py",
    "workflow.py",
)
_APPROVED_TASK_2_EXAMPLE = """import json
from datetime import datetime, timezone

from agentguardian.reporting import render_json
from agentguardian.scoring import score

findings = ()
technical_score = score(
    findings,
    coverage=0.75,
    limits=("file_scan_limited",),
)
payload = json.loads(
    render_json(
        technical_score,
        findings,
        rule_version="rules-1",
        evaluated_at=datetime(2026, 8, 3, 12, tzinfo=timezone.utc),
    )
)
assert payload["report_schema"] == 1
assert payload["evaluated_at"] == "2026-08-03T12:00:00Z"
assert payload["score"]["coverage_state"] == "limited"
assert payload["reviewed_score"]["coverage_state"] == "limited"
"""
_APPROVED_TASK_2_AST = ast.dump(
    ast.parse(_APPROVED_TASK_2_EXAMPLE),
    include_attributes=False,
)
def _task_2_example_source(workflow_plan: str) -> str:
    match = re.search(
        r"## Task 2:.*?```python\n(.*?)```",
        workflow_plan,
        flags=re.DOTALL,
    )
    assert match is not None
    return match.group(1)


def _current_task_2_example_source() -> str:
    path = (
        PROJECT_ROOT
        / "docs"
        / "superpowers"
        / "plans"
        / "2026-08-03-agentguardian-windows-workflow-report-hardening.md"
    )
    return _task_2_example_source(path.read_text(encoding="utf-8"))


def _validate_task_2_example(source: str) -> None:
    filename = "<task-2-report-example>"
    tree = ast.parse(source, filename=filename)
    if ast.dump(tree, include_attributes=False) != _APPROVED_TASK_2_AST:
        raise AssertionError("Task 2 example is not approved")


class _Task2SideEffectProbe:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, *args: object, **kwargs: object) -> None:
        self.calls += 1
        raise RuntimeError("TASK_2_SIDE_EFFECT")

    def __setitem__(self, key: object, value: object) -> None:
        self.calls += 1
        raise RuntimeError("TASK_2_SIDE_EFFECT")


def _canonical_source_digest(path: Path) -> str:
    normalized = path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    encoding, _ = tokenize.detect_encoding(io.BytesIO(normalized).readline)
    return hashlib.sha256(normalized.decode(encoding).encode("utf-8")).hexdigest()


def _copy_reviewed_package(tmp_path: Path) -> Path:
    package = tmp_path / "agentguardian"
    package.mkdir()
    for source in sorted(PACKAGE_ROOT.rglob("*.py")):
        target = package / source.relative_to(PACKAGE_ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
    (package / SOURCE_POLICY_PATH.name).write_bytes(SOURCE_POLICY_PATH.read_bytes())
    return package


def _write_manifest(path: Path, modules: dict[str, str]) -> None:
    path.write_text(
        json.dumps(
            {"schema": 1, "modules": modules},
            ensure_ascii=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )


def test_collect_self_audit_is_transparent_and_keeps_environment_private(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_name = "AGENTGUARDIAN_SYNTHETIC_SECRET"
    secret_value = "synthetic-secret-must-not-leak"
    monkeypatch.setenv(secret_name, secret_value)
    monkeypatch.setattr(
        socket,
        "socket",
        lambda *args, **kwargs: pytest.fail("self-audit attempted network access"),
    )
    monkeypatch.setattr(self_audit, "_ordinary_user_mode", lambda: True)

    audit = collect_self_audit()
    serialized = json.dumps(audit)

    assert audit == {
        "version": __version__,
        "python_version": (
            f"{sys.version_info.major}."
            f"{sys.version_info.minor}."
            f"{sys.version_info.micro}"
        ),
        "rules_sha256": hashlib.sha256(
            (PROJECT_ROOT / "rules" / "default.json").read_bytes()
        ).hexdigest(),
        "local_only": False,
        "network_capability": "detected",
        "ordinary_user_mode": True,
        "alpha_status": "Founder Alpha",
        "findings": [
            "DATABASE_CAPABILITY",
            "NETWORK_MODULE_IMPORT",
            "USER_DATA_WRITE",
        ],
        "scope": {
            "capabilities": "package_source_policy",
            "semantic_analysis": "not_performed",
            "dependencies": "not_scanned",
            "binaries": "not_scanned",
            "mapped_network_drives": "not_reliably_detected",
        },
    }
    assert secret_name not in serialized
    assert secret_value not in serialized
    assert "executable_path" not in audit
    assert sys.executable not in serialized


def test_current_package_reports_its_constrained_network_adapter() -> None:
    assert static_capability_findings() == (
        "DATABASE_CAPABILITY",
        "NETWORK_MODULE_IMPORT",
        "USER_DATA_WRITE",
    )


def test_source_policy_manifest_exactly_matches_current_package() -> None:
    assert SOURCE_POLICY_PATH.is_file()
    policy = json.loads(SOURCE_POLICY_PATH.read_text(encoding="utf-8"))
    modules = policy["modules"]
    package_names = tuple(
        path.relative_to(PACKAGE_ROOT).as_posix()
        for path in sorted(PACKAGE_ROOT.rglob("*.py"))
    )

    assert list(policy) == ["schema", "modules"]
    assert policy["schema"] == 1
    assert len(EXPECTED_REVIEWED_SOURCE_MODULES) == 21
    assert package_names == EXPECTED_REVIEWED_SOURCE_MODULES
    assert tuple(modules) == EXPECTED_REVIEWED_SOURCE_MODULES
    assert len(modules) == 21
    assert modules == {
        name: _canonical_source_digest(PACKAGE_ROOT / name)
        for name in EXPECTED_REVIEWED_SOURCE_MODULES
    }


def test_source_policy_contract_rejects_an_accepted_seventeenth_module(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = _copy_reviewed_package(tmp_path)
    (package / "unexpected.py").write_text("value = 1\n", encoding="utf-8")
    modules = {
        path.relative_to(package).as_posix(): _canonical_source_digest(path)
        for path in sorted(package.rglob("*.py"))
    }
    manifest = tmp_path / "source-policy.json"
    _write_manifest(manifest, modules)
    monkeypatch.setattr(sys.modules[__name__], "PACKAGE_ROOT", package)
    monkeypatch.setattr(sys.modules[__name__], "SOURCE_POLICY_PATH", manifest)

    with pytest.raises(AssertionError):
        test_source_policy_manifest_exactly_matches_current_package()


def test_personal_runtime_package_has_no_process_or_dynamic_execution_calls() -> None:
    forbidden_imports = {"importlib", "runpy", "subprocess"}
    forbidden_calls = {
        "__import__",
        "_winapi.CreateProcess",
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
        "compile",
        "eval",
        "exec",
        "multiprocessing.Process",
        "os.popen",
        "os.startfile",
        "os.system",
        "runpy.run_module",
        "runpy.run_path",
    }
    forbidden_prefixes = ("os.exec", "os.spawn", "subprocess.")
    violations: list[str] = []

    def dotted_name(node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            owner = dotted_name(node.value)
            return f"{owner}.{node.attr}" if owner else None
        return None

    for module in sorted(PACKAGE_ROOT.glob("*.py")):
        tree = ast.parse(module.read_bytes(), filename=str(module))
        aliases: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for item in node.names:
                    root = item.name.split(".", 1)[0]
                    aliases[item.asname or root] = item.name
                    if root in forbidden_imports:
                        violations.append(f"{module.name}:import:{item.name}")
            elif isinstance(node, ast.ImportFrom) and node.module:
                root = node.module.split(".", 1)[0]
                if root in forbidden_imports:
                    violations.append(f"{module.name}:import:{node.module}")
                for item in node.names:
                    aliases[item.asname or item.name] = f"{node.module}.{item.name}"

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = dotted_name(node.func)
            if not name:
                continue
            root, separator, suffix = name.partition(".")
            resolved = aliases.get(root, root)
            if separator:
                resolved = f"{resolved}.{suffix}"
            if resolved in forbidden_calls or resolved.startswith(forbidden_prefixes):
                violations.append(f"{module.name}:call:{resolved}")

    assert violations == []


@pytest.mark.parametrize(
    "module_name",
    EXPECTED_REVIEWED_SOURCE_MODULES,
)
def test_source_policy_rejects_source_change_in_every_reviewed_module(
    tmp_path: Path, module_name: str
) -> None:
    package = _copy_reviewed_package(tmp_path)
    module = package / module_name
    module.write_text(
        module.read_text(encoding="utf-8") + "\nreview_marker = 1\n",
        encoding="utf-8",
    )

    assert "SOURCE_POLICY_VIOLATION" in static_capability_findings(package)


def test_source_policy_rejects_unparseable_reviewed_module(tmp_path: Path) -> None:
    package = _copy_reviewed_package(tmp_path)
    (package / "guidance.py").write_text("def broken(:\n", encoding="utf-8")

    assert static_capability_findings(package) == (
        "SOURCE_POLICY_VIOLATION",
        "SOURCE_SCAN_ERROR",
    )


@pytest.mark.parametrize(
    ("encoding", "marker"),
    (("utf-7", "\u20ac"), ("latin-1", "\xe9")),
)
def test_source_policy_uses_pep263_decoded_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    encoding: str,
    marker: str,
) -> None:
    package = _copy_reviewed_package(tmp_path)
    module = package / "guidance.py"
    source = module.read_text(encoding="utf-8")
    module.write_bytes(
        (f"# coding: {encoding}\n{source}\nreview_marker = {marker!r}\n").encode(
            encoding
        )
    )
    ast.parse(module.read_bytes(), filename=str(module))

    policy = json.loads(SOURCE_POLICY_PATH.read_text(encoding="utf-8"))
    policy["modules"] = {
        path.relative_to(package).as_posix(): _canonical_source_digest(path)
        for path in sorted(package.rglob("*.py"))
    }
    updated_manifest = tmp_path / f"{encoding}-source-policy.json"
    _write_manifest(updated_manifest, policy["modules"])
    monkeypatch.setattr(self_audit, "SOURCE_POLICY_PATH", updated_manifest)

    assert static_capability_findings(package) == ()


def test_canonical_source_digest_normalizes_newlines_but_attests_text() -> None:
    source = b"# coding: latin-1\nvalue = 'caf\xe9'\n"
    crlf_source = source.replace(b"\n", b"\r\n")
    changed_cookie = source.replace(b"latin-1", b"iso-8859-1")
    changed_comment = source + b"# reviewed\n"
    changed_source = source.replace(b"caf\xe9", b"cafe")

    assert self_audit._canonical_source_sha256(source) == (
        self_audit._canonical_source_sha256(crlf_source)
    )
    assert self_audit._canonical_source_sha256(source) != (
        self_audit._canonical_source_sha256(changed_cookie)
    )
    assert self_audit._canonical_source_sha256(source) != (
        self_audit._canonical_source_sha256(changed_comment)
    )
    assert self_audit._canonical_source_sha256(source) != (
        self_audit._canonical_source_sha256(changed_source)
    )


def test_canonical_source_digest_handles_latin1_bare_cr() -> None:
    source = b"\n# coding: latin-1\nvalue = 'caf\xe9'\n"
    crlf_source = source.replace(b"\n", b"\r\n")
    cr_source = source.replace(b"\n", b"\r")

    for runtime_source in (source, crlf_source, cr_source):
        ast.parse(runtime_source, filename="latin1_newlines.py")

    assert {
        self_audit._canonical_source_sha256(runtime_source)
        for runtime_source in (source, crlf_source, cr_source)
    } == {self_audit._canonical_source_sha256(source)}


def test_utf7_runtime_injection_is_scanned_from_raw_bytes(tmp_path: Path) -> None:
    package = tmp_path / "synthetic"
    package.mkdir()
    source = b"# coding: utf-7\nvalue = 1+AAo-import socket\n"
    module = package / "injected.py"
    module.write_bytes(source)

    tree = ast.parse(source, filename=str(module))
    assert any(isinstance(node, ast.Import) for node in ast.walk(tree))
    assert static_capability_findings(package) == ("NETWORK_MODULE_IMPORT",)


def test_canonical_source_manifest_matches_python_312_and_314() -> None:
    script = """
import json
import pathlib
import sys

source_root = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(source_root))
from agentguardian.self_audit import _canonical_source_sha256

package_root = source_root / "agentguardian"
print(json.dumps({
    path.relative_to(package_root).as_posix(): _canonical_source_sha256(path.read_bytes())
    for path in sorted(package_root.rglob("*.py"))
}, sort_keys=True))
"""
    policy = json.loads(SOURCE_POLICY_PATH.read_text(encoding="utf-8"))
    manifests: list[dict[str, str]] = []
    unavailable: list[str] = []
    for version in ("3.12", "3.14"):
        probe = subprocess.run(
            ["py", f"-{version}", "-c", "pass"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if probe.returncode:
            unavailable.append(version)
            continue
        result = subprocess.run(
            ["py", f"-{version}", "-c", script, str(PROJECT_ROOT / "src")],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        manifest = json.loads(result.stdout)
        assert manifest == policy["modules"]
        manifests.append(manifest)

    if unavailable:
        pytest.skip(f"Python launchers unavailable: {', '.join(unavailable)}")

    assert manifests[0] == manifests[1]


@pytest.mark.parametrize(
    "source",
    (b"# coding: no-such-encoding\nvalue = 1\n", b"def broken(:\n"),
)
def test_source_policy_reports_fixed_finding_for_invalid_encoding_or_syntax(
    tmp_path: Path, source: bytes
) -> None:
    package = _copy_reviewed_package(tmp_path)
    (package / "guidance.py").write_bytes(source)

    assert static_capability_findings(package) == (
        "SOURCE_POLICY_VIOLATION",
        "SOURCE_SCAN_ERROR",
    )


def test_reviewed_module_mismatch_does_not_run_unknown_module_heuristic(
    tmp_path: Path,
) -> None:
    package = _copy_reviewed_package(tmp_path)
    module = package / "guidance.py"
    module.write_text(
        module.read_text(encoding="utf-8") + "\nimport socket\n",
        encoding="utf-8",
    )

    assert static_capability_findings(package) == ("SOURCE_POLICY_VIOLATION",)


@pytest.mark.parametrize("change", ("missing", "extra"))
def test_source_policy_requires_exact_reviewed_module_set(
    tmp_path: Path, change: str
) -> None:
    package = _copy_reviewed_package(tmp_path)
    if change == "missing":
        (package / "guidance.py").unlink()
    else:
        (package / "extra.py").write_text("value = 1\n", encoding="utf-8")

    assert "SOURCE_POLICY_VIOLATION" in static_capability_findings(package)


def test_source_policy_rejects_replacing_all_reviewed_modules(
    tmp_path: Path,
) -> None:
    package = _copy_reviewed_package(tmp_path)
    for module in package.glob("*.py"):
        module.unlink()
    (package / "synthetic.py").write_text("value = 1\n", encoding="utf-8")

    assert "SOURCE_POLICY_VIOLATION" in static_capability_findings(package)


@pytest.mark.parametrize(
    ("relative_path", "injection"),
    (
        ("app.py", "member = 'replace'\ngetattr(target, member)\n"),
        ("app.py", "getattr(target, 're' + 'place')\n"),
        ("app.py", "import sys\ngetattr(sys, 'modules')\n"),
        ("app.py", "target.replace('a', 'b')\n"),
        ("app.py", "from pathlib import Path\nPath('a').copy('b')\n"),
        (
            "state_store.py",
            "writer, marker = open, object()\nwriter('x', 'w')\n",
        ),
        ("state_store.py", "import os\nos.fsync(1)\n"),
        (
            "state_store.py",
            "import os\ngetattr(os, 'replace')('a', 'b')\n",
        ),
    ),
)
def test_reviewed_source_injections_are_manifest_violations(
    tmp_path: Path, relative_path: str, injection: str
) -> None:
    package = _copy_reviewed_package(tmp_path)
    module = package / relative_path
    module.write_text(
        module.read_text(encoding="utf-8") + "\n" + injection,
        encoding="utf-8",
    )

    assert static_capability_findings(package) == ("SOURCE_POLICY_VIOLATION",)


def test_source_policy_manifest_update_is_required_after_source_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = _copy_reviewed_package(tmp_path)
    module = package / "guidance.py"
    module.write_text(
        module.read_text(encoding="utf-8") + "\nreview_marker = 1\n",
        encoding="utf-8",
    )
    assert "SOURCE_POLICY_VIOLATION" in static_capability_findings(package)

    policy = json.loads(SOURCE_POLICY_PATH.read_text(encoding="utf-8"))
    policy["modules"]["guidance.py"] = _canonical_source_digest(module)
    updated_manifest = tmp_path / "updated-source-policy.json"
    _write_manifest(updated_manifest, policy["modules"])
    monkeypatch.setattr(
        self_audit, "SOURCE_POLICY_PATH", updated_manifest, raising=False
    )

    assert static_capability_findings(package) == ()


@pytest.mark.parametrize(
    "payload",
    (
        b"{",
        b'{"schema":1,"modules":{},"extra":true}',
        b'{"modules":{},"schema":1}',
        b'{"schema":true,"modules":{}}',
        b'{"schema":1,"modules":{"Bad.py":"' + b"0" * 64 + b'"}}',
        b'{"schema":1,"modules":{"b.py":"'
        + b"0" * 64
        + b'","a.py":"'
        + b"0" * 64
        + b'"}}',
        b'{"schema":1,"modules":{"a.py":"' + b"A" * 64 + b'"}}',
    ),
)
def test_source_policy_rejects_malformed_or_noncanonical_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
) -> None:
    package = tmp_path / "agentguardian"
    package.mkdir()
    (package / "synthetic.py").write_text("value = 1\n", encoding="utf-8")
    manifest = tmp_path / "source_policy.json"
    manifest.write_bytes(payload)
    monkeypatch.setattr(self_audit, "SOURCE_POLICY_PATH", manifest, raising=False)

    assert static_capability_findings(package) == (
        "SOURCE_POLICY_MANIFEST_INVALID",
        "SOURCE_SCAN_ERROR",
    )


@pytest.mark.parametrize("manifest_state", ("missing", "oversize"))
def test_source_policy_rejects_missing_or_oversize_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    manifest_state: str,
) -> None:
    package = tmp_path / "agentguardian"
    package.mkdir()
    (package / "synthetic.py").write_text("value = 1\n", encoding="utf-8")
    manifest = tmp_path / "source_policy.json"
    if manifest_state == "oversize":
        manifest.write_bytes(b" " * 65_537)
    monkeypatch.setattr(self_audit, "SOURCE_POLICY_PATH", manifest, raising=False)

    assert static_capability_findings(package) == (
        "SOURCE_POLICY_MANIFEST_INVALID",
        "SOURCE_SCAN_ERROR",
    )


def test_source_policy_manifest_is_configured_as_package_data() -> None:
    project = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text("utf-8"))

    assert project["tool"]["setuptools"]["package-data"]["agentguardian"] == [
        "rules/*.json",
        "source_policy.json",
    ]


@pytest.mark.parametrize(
    ("findings", "network_capability", "local_only"),
    (
        ((), "not_detected", True),
        (("NETWORK_MODULE_IMPORT",), "detected", False),
        (("NETWORK_CAPABILITY",), "detected", False),
        (("DYNAMIC_EXECUTION",), "unverified", False),
        (("NATIVE_CAPABILITY",), "unverified", False),
        (("SOURCE_POLICY_MANIFEST_INVALID",), "unverified", False),
        (("SOURCE_POLICY_VIOLATION",), "unverified", False),
        (("SOURCE_SCAN_ERROR",), "unverified", False),
    ),
)
def test_collect_self_audit_derives_trust_fields_from_findings(
    monkeypatch: pytest.MonkeyPatch,
    findings: tuple[str, ...],
    network_capability: str,
    local_only: bool,
) -> None:
    monkeypatch.setattr(self_audit, "static_capability_findings", lambda: findings)
    monkeypatch.setattr(self_audit, "_ordinary_user_mode", lambda: True)

    audit = collect_self_audit()

    assert audit["network_capability"] == network_capability
    assert audit["local_only"] is local_only
    assert audit["findings"] == list(findings)


def test_collect_self_audit_reports_elevated_process_as_not_ordinary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(self_audit, "static_capability_findings", lambda: ())
    monkeypatch.setattr(self_audit, "_ordinary_user_mode", lambda: False)

    assert collect_self_audit()["ordinary_user_mode"] is False


def test_ordinary_user_mode_uses_windows_admin_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Shell32:
        @staticmethod
        def IsUserAnAdmin() -> int:
            return 1

    class Windll:
        shell32 = Shell32()

    monkeypatch.setattr(self_audit.sys, "platform", "win32")
    monkeypatch.setattr(self_audit.ctypes, "windll", Windll(), raising=False)

    assert self_audit._ordinary_user_mode() is False


def test_ordinary_user_mode_fails_closed_off_windows_or_on_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(self_audit.sys, "platform", "linux")
    assert self_audit._ordinary_user_mode() is False

    class BrokenShell32:
        @staticmethod
        def IsUserAnAdmin() -> int:
            raise OSError("synthetic failure")

    class Windll:
        shell32 = BrokenShell32()

    monkeypatch.setattr(self_audit.sys, "platform", "win32")
    monkeypatch.setattr(self_audit.ctypes, "windll", Windll(), raising=False)
    assert self_audit._ordinary_user_mode() is False


def test_collect_self_audit_uses_fixed_rule_read_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    missing = tmp_path / "private" / "rules.json"
    monkeypatch.setattr(self_audit, "DEFAULT_RULES_PATH", missing)
    monkeypatch.setattr(self_audit, "_ordinary_user_mode", lambda: True)

    with pytest.raises(RuntimeError) as error:
        collect_self_audit()

    assert str(error.value) == "SELF_AUDIT_READ_ERROR"
    assert str(missing) not in str(error.value)


@pytest.mark.parametrize(
    ("source", "expected"),
    (
        ("import socket\n", "NETWORK_MODULE_IMPORT"),
        ("import subprocess\n", "SHELL_EXECUTION"),
        ("eval('40 + 2')\n", "DYNAMIC_EXECUTION"),
        ("open('private.txt', 'w')\n", "USER_DATA_WRITE"),
        ("import sentry_sdk\n", "TELEMETRY_CAPABILITY"),
        ("import pip\n", "UPDATER_CAPABILITY"),
        ("import openai\n", "LLM_CAPABILITY"),
        ("import ctypes\n", "NATIVE_CAPABILITY"),
        ("import runpy\n", "DYNAMIC_EXECUTION"),
        ("import importlib\n", "DYNAMIC_EXECUTION"),
        ("import webbrowser\n", "NETWORK_MODULE_IMPORT"),
        ("import webbrowser\n", "EXTERNAL_CAPABILITY"),
        ("import pyperclip\n", "CLIPBOARD_CAPABILITY"),
        ("import pyperclip\n", "USER_DATA_WRITE"),
        ("import win32clipboard\n", "CLIPBOARD_CAPABILITY"),
        ("import win32clipboard\n", "USER_DATA_WRITE"),
        (
            "import asyncio\nasyncio.create_subprocess_exec('cmd')\n",
            "NETWORK_CAPABILITY",
        ),
        (
            "import asyncio\nasyncio.create_subprocess_shell('cmd')\n",
            "NETWORK_CAPABILITY",
        ),
        ("import os\nos.startfile('file.txt')\n", "SHELL_EXECUTION"),
    ),
)
def test_static_scan_returns_only_fixed_codes(
    tmp_path: Path, source: str, expected: str
) -> None:
    package = tmp_path / "agentguardian"
    package.mkdir()
    module = package / "synthetic.py"
    module.write_text(source, encoding="utf-8")

    findings = static_capability_findings(package)
    serialized = json.dumps(findings)

    assert expected in findings
    assert str(module) not in serialized
    assert source.strip() not in serialized


def test_static_scan_detects_network_import_families_and_aliases(
    tmp_path: Path,
) -> None:
    package = tmp_path / "agentguardian"
    package.mkdir()
    module = package / "synthetic.py"
    sources = (
        "import urllib3\n",
        "import urllib3 as transport\n",
        "from urllib3 import PoolManager as Client\n",
        "import xmlrpc.client\n",
        "import xmlrpc.client as rpc\n",
        "from xmlrpc import client as rpc\n",
        "from xmlrpc.client import ServerProxy as Proxy\n",
        "import imaplib\n",
        "import imaplib as mail\n",
        "from imaplib import IMAP4_SSL as Client\n",
        "import PySide6.QtNetwork\n",
        "import PySide6.QtWebSockets as sockets\n",
        "import PySide6.QtWebEngineWidgets as web\n",
        "from PySide6 import QtNetwork as network\n",
        "from PySide6 import QtWebSockets\n",
        "from PySide6 import QtWebEngineWidgets as web\n",
        "from PySide6.QtWebEngineWidgets import QWebEngineView as View\n",
    )

    for source in sources:
        module.write_text(source, encoding="utf-8")
        assert static_capability_findings(package) == (
            "NETWORK_MODULE_IMPORT",
        ), source


def test_static_scan_fails_closed_for_unknown_absolute_but_allows_relative_imports(
    tmp_path: Path,
) -> None:
    package = tmp_path / "agentguardian"
    package.mkdir()
    module = package / "synthetic.py"
    for source in (
        "import future_transport\n",
        "import future_transport as transport\n",
        "from future_transport import Client as Transport\n",
    ):
        module.write_text(source, encoding="utf-8")
        assert static_capability_findings(package) == (
            "SOURCE_POLICY_VIOLATION",
        ), source

    module.write_text(
        "from . import local_helper\nfrom .local_helper import value\n",
        encoding="utf-8",
    )
    assert static_capability_findings(package) == ()


def test_static_scan_allows_exact_integer_zero_getattr_default(tmp_path: Path) -> None:
    package = tmp_path / "agentguardian"
    package.mkdir()
    (package / "synthetic.py").write_text(
        "import stat\ngetattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0)\n",
        encoding="utf-8",
    )

    assert static_capability_findings(package) == ()


@pytest.mark.parametrize("default", ("False", "0.0", "0j"))
def test_static_scan_rejects_non_integer_zero_getattr_defaults(
    tmp_path: Path, default: str
) -> None:
    package = tmp_path / "agentguardian"
    package.mkdir()
    (package / "synthetic.py").write_text(
        "import stat\n"
        f"getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', {default})\n",
        encoding="utf-8",
    )

    assert static_capability_findings(package) == ("SOURCE_POLICY_VIOLATION",)


@pytest.mark.parametrize(
    ("source", "expected"),
    (
        (
            "import asyncio\nasyncio.open_connection('host', 443)\n",
            ("NETWORK_CAPABILITY",),
        ),
        (
            "import os as operating_system\noperating_system.system('cmd')\n",
            ("SOURCE_POLICY_VIOLATION",),
        ),
        (
            "from os import system as run_command\nrun_command('cmd')\n",
            ("SHELL_EXECUTION", "SOURCE_POLICY_VIOLATION"),
        ),
        (
            "import shutil as files\nfiles.copyfile('source', 'target')\n",
            ("USER_DATA_WRITE",),
        ),
        (
            "from shutil import copyfile as duplicate\nduplicate('source', 'target')\n",
            ("USER_DATA_WRITE",),
        ),
        (
            "import tkinter as tk\nroot = tk.Tk()\nroot.clipboard_get()\n",
            ("CLIPBOARD_CAPABILITY",),
        ),
        (
            "import builtins as runtime\nruntime.__import__('socket')\n",
            ("DYNAMIC_EXECUTION",),
        ),
        (
            "from builtins import __import__ as load\nload('socket')\n",
            ("DYNAMIC_EXECUTION",),
        ),
    ),
)
def test_static_scan_resolves_import_and_call_provenance(
    tmp_path: Path, source: str, expected: tuple[str, ...]
) -> None:
    package = tmp_path / "agentguardian"
    package.mkdir()
    (package / "synthetic.py").write_text(source, encoding="utf-8")

    assert static_capability_findings(package) == expected


@pytest.mark.parametrize(
    ("source", "expected"),
    (
        ("import asyncio\n", ("NETWORK_CAPABILITY",)),
        ("import shutil\n", ("USER_DATA_WRITE",)),
        ("import tkinter\n", ("CLIPBOARD_CAPABILITY",)),
        ("import builtins\n", ("DYNAMIC_EXECUTION",)),
        ("import os as operating_system\n", ("SOURCE_POLICY_VIOLATION",)),
        ("import pathlib as paths\n", ("SOURCE_POLICY_VIOLATION",)),
        ("from os import system\n", ("SHELL_EXECUTION",)),
    ),
)
def test_static_scan_reports_conservative_import_capabilities(
    tmp_path: Path, source: str, expected: tuple[str, ...]
) -> None:
    package = tmp_path / "agentguardian"
    package.mkdir()
    (package / "synthetic.py").write_text(source, encoding="utf-8")

    assert static_capability_findings(package) == expected


@pytest.mark.parametrize(
    ("source", "expected"),
    (
        (
            "from pathlib import Path\nPath('report').write_text('data')\n",
            ("USER_DATA_WRITE",),
        ),
        (
            "import builtins\nbuiltins.open('report', 'w')\n",
            ("DYNAMIC_EXECUTION", "USER_DATA_WRITE"),
        ),
        (
            "import tkinter\ntkinter.Tk().clipboard_append('data')\n",
            ("CLIPBOARD_CAPABILITY", "USER_DATA_WRITE"),
        ),
    ),
)
def test_static_scan_reports_direct_write_capabilities(
    tmp_path: Path, source: str, expected: tuple[str, ...]
) -> None:
    package = tmp_path / "agentguardian"
    package.mkdir()
    (package / "synthetic.py").write_text(source, encoding="utf-8")

    assert static_capability_findings(package) == expected


def test_static_scan_detects_path_moves(tmp_path: Path) -> None:
    package = tmp_path / "agentguardian"
    package.mkdir()
    module = package / "synthetic.py"
    sources = (
        "from pathlib import Path\nPath('a').rename('b')\n",
        "from pathlib import Path\nPath('a').replace('b')\n",
    )

    for source in sources:
        module.write_text(source, encoding="utf-8")
        assert "USER_DATA_WRITE" in static_capability_findings(package), source


@pytest.mark.parametrize(
    ("source", "expected"),
    (
        (
            "writer, marker = open, object()\nwriter('report', 'w')\n",
            ("USER_DATA_WRITE",),
        ),
        (
            "import os\n"
            "writer, marker = os.replace, object()\n"
            "writer('temporary', 'target')\n",
            ("USER_DATA_WRITE",),
        ),
        (
            "__builtins__['open']('report', 'w')\n",
            (
                "DYNAMIC_EXECUTION",
                "SOURCE_POLICY_VIOLATION",
                "USER_DATA_WRITE",
            ),
        ),
    ),
)
def test_static_scan_reports_write_capability_references(
    tmp_path: Path, source: str, expected: tuple[str, ...]
) -> None:
    package = tmp_path / "agentguardian"
    package.mkdir()
    (package / "synthetic.py").write_text(source, encoding="utf-8")

    assert static_capability_findings(package) == expected


@pytest.mark.parametrize(
    "source",
    (
        "loader = __import__ if True else object()\nloader('socket')\n",
        "def load(loader=__import__):\n    return loader('socket')\n",
        "from builtins import __import__ as loader\nloader('socket')\n",
    ),
)
def test_static_scan_reports_dynamic_import_capability_references(
    tmp_path: Path, source: str
) -> None:
    package = tmp_path / "agentguardian"
    package.mkdir()
    (package / "synthetic.py").write_text(source, encoding="utf-8")

    assert static_capability_findings(package) == ("DYNAMIC_EXECUTION",)


def test_static_scan_reports_unapproved_stream_write_reference(tmp_path: Path) -> None:
    package = tmp_path / "agentguardian"
    package.mkdir()
    (package / "synthetic.py").write_text(
        "def emit(stream):\n    stream.write('data')\n",
        encoding="utf-8",
    )

    assert static_capability_findings(package) == ("USER_DATA_WRITE",)


def test_static_scan_allows_safe_direct_pathlib_import(tmp_path: Path) -> None:
    package = tmp_path / "agentguardian"
    package.mkdir()
    (package / "synthetic.py").write_text(
        "import pathlib\npathlib.PurePath('x')\n",
        encoding="utf-8",
    )

    assert static_capability_findings(package) == ()


def test_static_scan_rejects_top_level_exclusive_open_in_app(tmp_path: Path) -> None:
    package = tmp_path / "agentguardian"
    package.mkdir()
    (package / "app.py").write_text(
        "with open('report.json', 'x', encoding='utf-8') as stream:\n"
        "    stream.write('{}')\n",
        encoding="utf-8",
    )

    assert static_capability_findings(package) == (
        "SOURCE_POLICY_VIOLATION",
    )


def test_real_app_export_contract_is_the_only_allowed_write() -> None:
    findings = static_capability_findings(PROJECT_ROOT / "src" / "agentguardian")

    assert "USER_DATA_WRITE" not in findings


def test_static_scan_recurses_into_nested_package(tmp_path: Path) -> None:
    package = tmp_path / "agentguardian"
    nested = package / "nested"
    nested.mkdir(parents=True)
    (nested / "capability.py").write_text("import socket\n", encoding="utf-8")

    assert static_capability_findings(package) == ("NETWORK_MODULE_IMPORT",)


def test_nested_self_audit_does_not_receive_admin_probe_exception(
    tmp_path: Path,
) -> None:
    package = tmp_path / "agentguardian"
    nested = package / "nested"
    nested.mkdir(parents=True)
    (nested / "self_audit.py").write_text(
        "import ctypes\nctypes.windll.shell32.IsUserAnAdmin()\n",
        encoding="utf-8",
    )

    assert static_capability_findings(package) == ("NATIVE_CAPABILITY",)


def test_nested_app_does_not_receive_report_export_exception(tmp_path: Path) -> None:
    package = tmp_path / "agentguardian"
    nested = package / "nested"
    nested.mkdir(parents=True)
    (nested / "app.py").write_text(
        "with open('report.json', 'x', encoding='utf-8') as stream:\n"
        "    stream.write('{}')\n",
        encoding="utf-8",
    )

    assert static_capability_findings(package) == ("USER_DATA_WRITE",)


def test_static_scan_allows_only_constrained_protected_state_write(
    tmp_path: Path,
) -> None:
    package = _copy_reviewed_package(tmp_path)
    module = package / "state_store.py"
    source = module.read_text(encoding="utf-8")

    assert static_capability_findings(package) == ()

    mutations = (
        source + '\nopen("extra.bin", "wb")\n',
        source + '\nos.replace("extra.tmp", "extra.bin")\n',
        source + '\nPath("extra.bin").open("wb").write(b"unsafe")\n',
        source + '\nPath("extra").mkdir()\n',
    )
    for mutated in mutations:
        module.write_text(mutated, encoding="utf-8")
        assert static_capability_findings(package) == ("SOURCE_POLICY_VIOLATION",)


def test_nested_state_store_does_not_receive_write_exception(tmp_path: Path) -> None:
    package = tmp_path / "agentguardian" / "nested"
    package.mkdir(parents=True)
    (package / "state_store.py").write_text(
        'open("extra.bin", "wb")\n',
        encoding="utf-8",
    )

    assert static_capability_findings(package.parent) == ("USER_DATA_WRITE",)


def test_static_scan_reports_fixed_error_without_source_details(tmp_path: Path) -> None:
    package = tmp_path / "agentguardian"
    package.mkdir()
    marker = "synthetic-secret-source-marker"
    module = package / "broken.py"
    module.write_text(f"value = '{marker}\n", encoding="utf-8")

    findings = static_capability_findings(package)
    serialized = json.dumps(findings)

    assert findings == ("SOURCE_SCAN_ERROR",)
    assert marker not in serialized
    assert str(module) not in serialized


def test_windows_ci_runs_required_local_checks_without_uploads() -> None:
    workflow = (PROJECT_ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    lowered = workflow.lower()
    action_refs = re.findall(
        r"^\s*-\s+uses:\s+([^@\s]+)@([^\s#]+)", workflow, flags=re.MULTILINE
    )

    for required in (
        "windows-latest",
        "id: testable_tree",
        '"ready=$($ready.ToString().ToLowerInvariant())"',
        '"refs/heads/main"',
        '"refs/heads/agent/design-baseline"',
        "if: steps.testable_tree.outputs.ready == 'true'",
        "python-version: '3.12'",
        "python -m pip install --require-hashes -r requirements-dev.lock",
        "python -m pip install --no-build-isolation --no-deps -e .",
        "rtk pytest",
        "python -m pytest",
        "scripts/check_brand_assets.py",
        "python -m compileall -q src",
        "git diff --exit-code",
        "git status --porcelain --untracked-files=all",
        "if ($status)",
        "contents: read",
    ):
        assert required in workflow
    assert action_refs == [
        ("actions/checkout", "3d3c42e5aac5ba805825da76410c181273ba90b1"),
        ("actions/setup-python", "5fda3b95a4ea91299a34e894583c3862153e4b97"),
    ]
    for _, reference in action_refs:
        assert re.fullmatch(r"[0-9a-f]{40}", reference)
    assert "upload-artifact" not in lowered
    assert "telemetry" not in lowered
    assert 'pip install -e ".[dev]"' not in workflow
    assert workflow.count("if: steps.testable_tree.outputs.ready == 'true'") == 6


def test_python_dependencies_are_hash_locked_for_windows_ci() -> None:
    lock = (PROJECT_ROOT / "requirements-dev.lock").read_text(encoding="utf-8")
    requirement_lines = [
        line
        for line in lock.splitlines()
        if line and not line.startswith("#") and not line.startswith(" ")
    ]

    assert "Generated for Windows Python 3.12 CI" in lock
    assert requirement_lines
    for line in requirement_lines:
        assert re.fullmatch(
            r"[A-Za-z0-9_.-]+==[A-Za-z0-9_.!+-]+ --hash=sha256:[0-9a-f]{64}",
            line,
        )


def test_design_status_tracks_windows_mvp_hardening() -> None:
    spec = (
        PROJECT_ROOT / "docs" / "superpowers" / "specs"
        / "2026-08-01-agentguardian-design.md"
    ).read_text(encoding="utf-8")

    assert "Founder Alpha 已达内部 GO" in spec
    assert "下一阶段：Windows MVP 硬化" in spec
    assert "OpenAI Provider：本地适配、检测和人工指引优先，不默认调用 API" in spec


def test_docs_track_openai_local_provider_hardening_batch() -> None:
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    report = (
        PROJECT_ROOT / "docs" / "reports" / "alpha-0.1.0-stage-report.md"
    ).read_text(encoding="utf-8")
    spec = (
        PROJECT_ROOT / "docs" / "superpowers" / "specs"
        / "2026-08-01-agentguardian-design.md"
    ).read_text(encoding="utf-8")

    assert "OpenAI Provider local adaptation, detection, and manual guidance only" in readme
    assert "The runtime must not call OpenAI or another provider API by default." in readme
    assert "端点覆盖发现只表示配置需要人工复核" in report
    assert "不证明端点属于恶意第三方" in report
    assert "Windows MVP 硬化批次 1" in spec


def test_readme_does_not_claim_self_audit_exposes_interpreter_path() -> None:
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")

    assert "运行解释器路径" not in readme
    assert "Python 版本" in readme


def test_docs_track_protected_evidence_state_boundaries() -> None:
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    architecture = (PROJECT_ROOT / "docs" / "architecture.md").read_text(
        encoding="utf-8"
    )
    report = (
        PROJECT_ROOT / "docs" / "reports" / "alpha-0.1.0-stage-report.md"
    ).read_text(encoding="utf-8")
    combined = "\n".join((readme, architecture, report))

    for required in (
        "当前 Windows 用户范围 DPAPI",
        "只有用户点击“保存加密状态”才会写入",
        "不保存原始匹配、扫描密钥、完整路径或证据来源文件名",
        "PROTECTED_STATE_INVALID",
        "不能抵御已经控制同一 Windows 用户会话的程序",
        "固定规则摘要",
        "SHA-256 完整性封装",
        "竞态窗口",
        "不发起 API 调用",
        "do not establish production safety",
    ):
        assert required in combined


@pytest.mark.parametrize(
    ("target", "attribute", "mutation"),
    (
        (
            builtins,
            "open",
            'open("agentguardian-task-2-probe.txt", "w").write("changed")',
        ),
        (socket, "socket", "import socket\nsocket.socket()"),
        (
            subprocess,
            "run",
            'import subprocess\nsubprocess.run(("echo", "changed"))',
        ),
        (builtins, "print", 'print("unexpected call")'),
    ),
    ids=("file-write", "socket", "subprocess", "arbitrary-call"),
)
def test_task_2_example_rejects_side_effects_before_execution(
    monkeypatch: pytest.MonkeyPatch,
    target: object,
    attribute: str,
    mutation: str,
) -> None:
    probe = _Task2SideEffectProbe()
    monkeypatch.setattr(target, attribute, probe)
    mutated = f"{mutation}\n{_current_task_2_example_source()}"

    try:
        with pytest.raises(AssertionError):
            _validate_task_2_example(mutated)
    finally:
        monkeypatch.undo()

    assert probe.calls == 0


def test_task_2_example_rejects_environment_mutation_before_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe = _Task2SideEffectProbe()
    monkeypatch.setattr(sys.modules["os"], "environ", probe)
    mutated = (
        'import os\nos.environ["AGENTGUARDIAN_TASK_2_PROBE"] = "changed"\n'
        f"{_current_task_2_example_source()}"
    )

    try:
        with pytest.raises(AssertionError):
            _validate_task_2_example(mutated)
    finally:
        monkeypatch.undo()

    assert probe.calls == 0


def test_batch_4_remote_evidence_is_bound_to_exact_sha_and_limits() -> None:
    plans = PROJECT_ROOT / "docs" / "superpowers" / "plans"
    current_status_files = {
        "stage report": (
            PROJECT_ROOT / "docs" / "reports" / "alpha-0.1.0-stage-report.md"
        ),
        "Windows MVP hardening plan": (
            plans / "2026-08-02-agentguardian-windows-mvp-hardening.md"
        ),
    }
    implementation_sha = "a79995a7a6a950050d5628324f94a6b8a07e6308"

    for document, path in current_status_files.items():
        text = path.read_text(encoding="utf-8")
        for required in (
            implementation_sha,
            "Batch 5 便携开发包层已完成本地验证",
            "Windows MVP 尚未完成",
            "未形成生产安全结论",
        ):
            assert required in text, f"{document} missing remote evidence: {required}"

    detailed_evidence = (
        current_status_files["stage report"].read_text(encoding="utf-8")
        + (
            plans / "2026-08-03-agentguardian-windows-workflow-report-hardening.md"
        ).read_text(encoding="utf-8")
    )
    for required in (
        "31714716636",
        "94496371022",
        "31714721274",
        "94496388008",
        "1277 passed",
        "annotations：0/0",
        "Install、Full test suite、Brand validator、Compile source、Verify clean tree 均通过",
        "Draft PR #1 保持 `OPEN / DRAFT`",
    ):
        assert required in detailed_evidence


def test_docs_track_batch_5_portable_layer_and_remaining_gates() -> None:
    current_status_files = (
        PROJECT_ROOT / "docs" / "reports" / "alpha-0.1.0-stage-report.md",
        PROJECT_ROOT
        / "docs"
        / "superpowers"
        / "plans"
        / "2026-08-02-agentguardian-windows-mvp-hardening.md",
    )
    required = (
        "Batch 5 便携开发包层已完成本地验证",
        "10e65322cd590f2028fb5946fff7125afd2e101d",
        "216936f89d9a8b8352e3a58ce8c2602dbb26e7d450ddfcb0959d289e0755ef7b",
        "PyInstaller Bootloader",
        "未签名开发产物",
        "可信代码签名",
        "原生安装",
        "干净机器验收",
        "卸载残留检查",
        "当前本地提交尚未获得 GitHub CI 验证",
        "Batch 6 仍待完成",
        "Windows MVP 尚未完成",
        "未形成生产安全结论",
    )

    for path in current_status_files:
        text = path.read_text(encoding="utf-8")
        for marker in required:
            assert marker in text, f"{path.name} missing Batch 5 status: {marker}"


def test_docs_track_batch_6_local_gates_without_premature_release_claim() -> None:
    plans = PROJECT_ROOT / "docs" / "superpowers" / "plans"
    status_files = (
        PROJECT_ROOT / "docs" / "reports" / "alpha-0.1.0-stage-report.md",
        plans / "2026-08-02-agentguardian-windows-mvp-hardening.md",
    )
    implementation_sha = "90e6edad53bee48adca58d508d193fc855c1db7d"
    evidence_sha = "90e6edad53bee48adca58d508d193fc855c1db7d"

    for path in status_files:
        text = path.read_text(encoding="utf-8")
        for required in (
            "Batch 6 local gate",
            implementation_sha,
            evidence_sha,
            "Release-candidate decision: `NO-GO`",
            "Windows MVP remains incomplete",
            "Production safety is not established",
            "Important findings",
        ):
            assert required in text, f"{path.name} missing Batch 6 status: {required}"

    report = (
        PROJECT_ROOT
        / "docs"
        / "reports"
        / "windows-mvp-release-candidate-report.md"
    ).read_text(encoding="utf-8")
    for required in (
        implementation_sha,
        evidence_sha,
        "47 passed, 1 skipped",
            "1322 passed, 8 skipped",
            "1321 passed, 9 skipped",
            "fe4689ae792246e6d48a51e5018b8125f64a3a2e2b3f83cf85c755bb9bc8cdd3",
            "fa77cf277736912ccfe4d8c36635d557b6803bbeff95a5c116b1fe3e41d617fd",
            "4f7e9ffdd347fddf67ffb7544ab84e777ff7b93e2ed1bf546ed87e6e9517bad1",
            "8ed7fe9a1e9fc43ee7fcf0c32cc4de3bceb9042695080d11c59451ae163cf034",
            "cd4317b9881aec914efe7090cf9d7324c4adf5803931ad4704e1776986a433c9",
        "208 files",
        "92,870,198 bytes",
        "Bundle diff count: `0`",
        "declared_residue=false",
        "process_tree_terminated=true",
            "Independent read-only review: `COMPLETED WITH 7 IMPORTANT AND 2 MINOR FINDINGS`",
            "Second independent re-review: `COMPLETED WITH 2 IMPORTANT AND 3 MINOR FINDINGS`",
            "Third independent re-review: `COMPLETED WITH NO CRITICAL/IMPORTANT FINDINGS AND 1 MINOR`",
            "Current exact-SHA GitHub CI: `VERIFIED`",
            "GitHub-hosted Windows runner provenance: `VERIFIED AS CI EVIDENCE ONLY`",
            "Trusted code signing: `PENDING`",
            "Unsigned CI native install, upgrade, launch, termination and uninstall smoke: `VERIFIED`",
            "License and redistribution review: `PENDING`",
            "OpenAI Provider remains local detection and manual guidance only",
        "Release-candidate decision: `NO-GO`",
        "Production safety is not established",
    ):
        assert required in report, f"release-candidate report missing: {required}"

    candidate_plan = (
        plans
        / "2026-08-14-agentguardian-windows-mvp-release-candidate.md"
    ).read_text(encoding="utf-8")
    assert (
        "- [x] **Step 2: Run all local gates on one clean exact baseline**"
        in candidate_plan
    )
    assert "- [x] **Step 1: Commission a separate read-only review**" in candidate_plan
    assert "- [x] **Step 2: Resolve all important findings locally**" in candidate_plan


def test_retired_release_report_is_historical_before_any_old_claims() -> None:
    report = (
        PROJECT_ROOT
        / "docs"
        / "reports"
        / "windows-mvp-release-candidate-report.md"
    ).read_text(encoding="utf-8")
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    status = "## Historical Snapshot Status"
    normalized_report = " ".join(report.split())

    assert report.index(status) < report.index("Release-candidate decision")
    assert report.index(status) < report.index("Task 1 implements packaged MCP")
    for required in (
        "Covered runtime SHA: `6ccb5232f6eb3955890f89f7a1000df338db8e8a`",
        "Snapshot date: `2026-08-16`",
        "not current product or release evidence",
        "dynamic adapter, PFX, and enterprise material described below is retired",
        "Personal v1 supports static MCP configuration detection only",
    ):
        assert required in normalized_report

    assert "older Windows MVP reports are historical planning or evidence snapshots" in readme
    assert "[Windows MVP release-candidate 报告]" not in readme


def test_readme_describes_current_release_verifier_without_checksum_claim() -> None:
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")

    assert "SBOM/notices/checksums" not in readme
    assert "traditional unsigned offline EXE installer" in readme
    assert "No installer candidate has passed the required gates" in readme
