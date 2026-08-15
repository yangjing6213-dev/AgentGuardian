import ast
import builtins
import dataclasses
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

from agentguardian import __version__, domain, self_audit
from agentguardian.self_audit import collect_self_audit, static_capability_findings

PROJECT_ROOT = Path(__file__).parents[1]
PACKAGE_ROOT = PROJECT_ROOT / "src" / "agentguardian"
SOURCE_POLICY_PATH = PACKAGE_ROOT / "source_policy.json"
EXPECTED_REVIEWED_SOURCE_MODULES = (
    "__init__.py",
    "__main__.py",
    "app.py",
    "browser_audit.py",
    "clipboard_audit.py",
    "detectors.py",
    "discovery.py",
    "dispositions.py",
    "domain.py",
    "enterprise_control_plane.py",
    "enterprise_policy.py",
    "enterprise_service.py",
    "enterprise_signing.py",
    "evidence_state.py",
    "guidance.py",
    "mcp_sandbox.py",
    "remediation.py",
    "report_comparison.py",
    "reporting.py",
    "scoring.py",
    "self_audit.py",
    "sensitive_mode.py",
    "share_verification.py",
    "state_store.py",
    "windows_appcontainer.py",
    "windows_code_signing.py",
    "windows_dpapi.py",
    "windows_job_object.py",
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
_APPROVED_TASK_2_IMPORTS = frozenset(
    {
        "json",
        "datetime",
        "agentguardian.reporting",
        "agentguardian.scoring",
    }
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


def _approved_task_2_import(
    name: str,
    globals: dict[str, object] | None = None,
    locals: dict[str, object] | None = None,
    fromlist: tuple[str, ...] = (),
    level: int = 0,
) -> object:
    assert level == 0 and name in _APPROVED_TASK_2_IMPORTS
    return builtins.__import__(name, globals, locals, fromlist, level)


def _execute_task_2_example(source: str) -> dict[str, object]:
    filename = "<task-2-report-example>"
    tree = ast.parse(source, filename=filename)
    if ast.dump(tree, include_attributes=False) != _APPROVED_TASK_2_AST:
        raise AssertionError("Task 2 example is not approved")
    namespace: dict[str, object] = {
        "__builtins__": {"__import__": _approved_task_2_import}
    }
    exec(compile(tree, filename, "exec"), namespace)
    return namespace


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
            "NATIVE_CAPABILITY",
            "NETWORK_MODULE_IMPORT",
            "SHELL_EXECUTION",
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
        "NATIVE_CAPABILITY",
        "NETWORK_MODULE_IMPORT",
        "SHELL_EXECUTION",
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
    assert len(EXPECTED_REVIEWED_SOURCE_MODULES) == 29
    assert package_names == EXPECTED_REVIEWED_SOURCE_MODULES
    assert tuple(modules) == EXPECTED_REVIEWED_SOURCE_MODULES
    assert len(modules) == 29
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

    assert "Windows MVP 硬化实施计划" in readme
    assert "OpenAI Provider 本地适配批次" in readme
    assert "不发起 API 调用或联网验证端点" in readme
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
        "不代表 Windows MVP 完成或生产安全",
    ):
        assert required in combined


def test_docs_track_batch_3_finding_disposition_boundaries() -> None:
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    architecture = (PROJECT_ROOT / "docs" / "architecture.md").read_text(
        encoding="utf-8"
    )
    report = (
        PROJECT_ROOT / "docs" / "reports" / "alpha-0.1.0-stage-report.md"
    ).read_text(encoding="utf-8")
    hardening_plan = (
        PROJECT_ROOT / "docs" / "superpowers" / "plans"
        / "2026-08-02-agentguardian-windows-mvp-hardening.md"
    ).read_text(encoding="utf-8")
    disposition_plan = (
        PROJECT_ROOT / "docs" / "superpowers" / "plans"
        / "2026-08-02-agentguardian-finding-dispositions.md"
    ).read_text(encoding="utf-8")
    inventory_match = re.search(
        r"<!-- domain-field-inventory -->\s*```json\s*(\{.*?\})\s*```",
        architecture,
        flags=re.DOTALL,
    )
    assert inventory_match is not None
    documented_fields = json.loads(inventory_match.group(1))
    domain_types = (
        domain.Asset,
        domain.Evidence,
        domain.Finding,
        domain.Score,
        domain.RemediationPlan,
        domain.VerificationResult,
    )
    actual_fields = {
        contract.__name__: [item.name for item in dataclasses.fields(contract)]
        for contract in domain_types
    }
    assert documented_fields == actual_fields

    status = "Batch 3 本地实现、自动门禁、独立安全复审和最终 SHA 远程验收已完成。"
    pending = "Batches 4-6 仍待完成"
    premature = (
        "只关闭 Batch 3",
        "Completed locally",
        "## Completed Batch: Finding Dispositions",
        "Local closure status",
        "Close Batch 3",
    )

    for required in (
        "规则 ID、按 Windows 词法规则规范化的源路径，以及 NFKC 规范化的原始匹配",
        "本地处置 HMAC 密钥与每次扫描随机生成的报告 HMAC 密钥彼此独立",
        "报告 HMAC 仍限定于单次扫描",
        "处置有效期必须有限且不超过 366 天",
        "有效误报只从复核分排除；接受风险仍计入复核分；技术分不受处置影响",
        "schema v1 只读兼容，只有显式保存才迁移到 schema v2",
        "损坏、不可解密或无效的受保护状态必须先获得明确确认，才允许替换",
        "不发起 API 调用，也不默认访问 OpenAI API",
        status,
        pending,
        "非生产",
    ):
        assert required in readme

    for required in (
        "## 当前 Founder Alpha 已实现数据流",
        "## 未来目标（未实现）",
        "## 后续可信性要求（未实现门禁）",
        "当前实现不包含隔离扫描插件、限权修复代理、独立复审器、签名更新器或外部解释服务",
        "`disposition_ref` 是 `repr=False` 的本地处置引用，不进入导出报告",
        "`RemediationPlan` 当前没有 `title` 字段",
        "`RemediationPlan` 只承载人工指引",
        "`mode` 固定为 `manual`",
        "`VerificationResult.status` 固定为 `not_performed`",
        "不表示通过/失败复审记录",
        "动态 MCP 的网络拒绝、签名适配器、完整执行放行、企业服务端身份/策略分发和独立复审字段仍是未来能力",
        "Findings --> Guidance",
        "规则 ID、按 Windows 词法规则规范化的源路径，以及 NFKC 规范化的原始匹配",
        "本地处置 HMAC 密钥与每次扫描随机生成的报告 HMAC 密钥彼此独立",
        "DPAPI 不能抵御已经控制同一 Windows 用户会话的程序",
        "主机时钟、路径别名或文件移动可能重新打开发现，但不会扩大处置范围",
        "路径检查与 `os.replace` 之间仍有同用户竞态窗口",
        "Python 不能保证清除所有不可变 bytes 或字符串副本",
        "静态自审计只覆盖已复核源码清单和有界启发式，不扫描依赖或二进制",
        "`source_policy.json`",
        "canonical source SHA-256",
        "PEP 263 编码声明",
        "原始 ASCII newline bytes",
        "CRLF 和 CR 确定性规范化为 LF",
        "注释和编码 cookie",
        "`src/agentguardian/rules/default.json`",
        "byte-identical",
        "wheel `RECORD`",
        "URL-safe base64 SHA-256",
        "记录的字节大小",
        "`setuptools.build_meta.build_wheel`",
        "`zipfile` 直接解压",
        "有限启发式仅对清单外的合成未知模块运行",
        "不是 Python 表达式解释器",
        "清单未签名",
        "同一用户控制",
        "Batch 5",
        status,
        pending,
        "非生产",
    ):
        assert required in architecture
    for forbidden_node in (
        "Runner[隔离扫描插件",
        "Broker[限权修复代理",
        "Verify[独立复审器",
        "Update[签名规则与版本更新]",
        "Optional[用户选择的脱敏解释",
        "Report --> Guidance",
    ):
        assert forbidden_node not in architecture

    for required in (
        "报告日期：2026-08-01",
        "更新日期：2026-08-03",
        "第 8 节为已被第 9 至 10 节取代的历史交接记录",
        "Batch 2 历史远程证据",
        "Batch 3 当前本地证据",
        "`py -3.12 -m pytest -q`：`681 passed, 6 skipped`",
        "`py -3.14 -m pytest -q -p no:cacheprovider`：`681 passed, 6 skipped`",
        "`d719e0fb79eae9132fabc713e23f5256d0c1f70c`",
        "`30759350802`",
        "`30759352079`",
        "Python 3.12 与本地 Python 3.14 的 `ast.dump` 输出不同",
        "`build` 不在哈希锁定的 CI 开发依赖中",
        "Batch 3 远程验收的实现与证据基线 SHA：`50b74e6cc50dd7a4681a26b3084e7f312c096c47`",
        "push run `30762254791` / job `91534776936`：`SUCCESS`",
        "PR run `30762256518` / job `91534781660`：`SUCCESS`",
        "https://github.com/hqwzhu/AgentGuardian/actions/runs/30762254791/job/91534776936",
        "https://github.com/hqwzhu/AgentGuardian/actions/runs/30762256518/job/91534781660",
        "Windows Full test suite：`687 passed`",
        "Install、Full test suite、Brand validator、Compile source、Verify clean tree 均通过",
        "annotations：0/0",
        "证据采集时，Draft PR #1 在该 SHA 上为 `OPEN / DRAFT`",
        "`a38910b340631b2e78c33c9d7595cf98aa2f52b9` 是仅修改文档与文档断言测试的证据同步提交",
        "不更改运行时或包源码",
        "未被上述两次针对 `50b74e6cc50dd7a4681a26b3084e7f312c096c47` 的 CI 运行覆盖",
        "不声明 `a38910b340631b2e78c33c9d7595cf98aa2f52b9` 已远程验证",
        "https://github.com/hqwzhu/AgentGuardian/pull/1",
        "复审对象 SHA：`ef7808975879bea153172c09e647e04d0bf48e9b`",
        "结论：`APPROVED / READY`",
        "Critical：0；Important：0；Minor：0",
        "`findings=[]`、`local_only=true`、`network_capability=not_detected`",
        "`source_policy.json`",
        "canonical source SHA-256",
        "PEP 263 编码声明",
        "原始 ASCII newline bytes",
        "CRLF 和 CR 确定性规范化为 LF",
        "有限启发式仅对清单外的合成未知模块运行",
        "不是 Python 表达式解释器",
        "wheel `RECORD` 包含 `agentguardian/source_policy.json`",
        "`agentguardian/rules/default.json`",
        "URL-safe base64 SHA-256",
        "记录的字节大小",
        "`setuptools.build_meta.build_wheel`",
        "`zipfile` 直接解压",
        "不调用打包或安装前端",
        "清单未签名",
        "Batch 5",
        "该验收不构成生产安全结论",
        status,
        pending,
        "非生产",
    ):
        assert required in report
    assert "下一批为 DPAPI 保护的本地证据状态，目前尚未实现" not in report
    assert "最终验收 SHA：" not in report

    for required in (
        "## Batch 3 Local Implementation and Gate Status",
        "Remotely accepted Batch 3 implementation/evidence baseline: `50b74e6cc50dd7a4681a26b3084e7f312c096c47`",
        "At evidence-capture time, Draft PR #1 was `OPEN / DRAFT` at that SHA",
        "`a38910b340631b2e78c33c9d7595cf98aa2f52b9` is a docs/tests-only evidence-sync commit",
        "changes no runtime or package source",
        "was not covered by the two cited CI runs for `50b74e6cc50dd7a4681a26b3084e7f312c096c47`",
        "is not claimed as remotely verified",
        status,
        pending,
        "非生产",
    ):
        assert required in hardening_plan
    assert "Accepted at final SHA" not in hardening_plan
    assert "Batch 3 accepted at final SHA" not in hardening_plan

    for required in (
        "Path matching follows Windows lexical rules through",
        "Do not Unicode-normalize the path; NFKC applies only to the raw match",
        "The remotely accepted Batch 3 implementation/evidence baseline is `50b74e6cc50dd7a4681a26b3084e7f312c096c47`",
        "At evidence-capture time, Draft PR #1 was `OPEN / DRAFT` at that SHA",
        "`a38910b340631b2e78c33c9d7595cf98aa2f52b9` is a docs/tests-only evidence-sync commit",
        "changes no runtime or package source",
        "was not covered by the two cited CI runs for `50b74e6cc50dd7a4681a26b3084e7f312c096c47`",
        "is not claimed as remotely verified",
        "https://github.com/hqwzhu/AgentGuardian/actions/runs/30762254791/job/91534776936",
        "https://github.com/hqwzhu/AgentGuardian/actions/runs/30762256518/job/91534781660",
        pending,
        "production safety",
    ):
        assert required in disposition_plan
    assert "Final remote acceptance complete at" not in disposition_plan
    assert "remains open and draft at the accepted SHA" not in disposition_plan

    tasks_one_to_six, task_seven = disposition_plan.split(
        "## Task 7: Synchronize Local Evidence Before Batch 3 Acceptance",
        1,
    )
    assert tasks_one_to_six.count("- [x] **Step") == 31
    assert "- [ ] **Step" not in tasks_one_to_six
    for completed_step in (
        "Step 1: Add failing documentation assertions",
        "Step 2: Update status documents after implementation evidence exists",
        "Step 3: Run the complete local gate",
        "Step 4: Run an independent read-only security review",
        "Step 5: Commit, push, and verify remote evidence",
    ):
        assert f"- [x] **{completed_step}**" in task_seven
    assert "- [ ] **Step" not in task_seven
    assert "remotely accepted Batch 3 implementation/evidence baseline" in task_seven

    for forbidden in premature:
        assert forbidden not in readme, f"README contains premature status: {forbidden}"
        assert forbidden not in architecture, (
            f"architecture contains premature status: {forbidden}"
        )
        assert forbidden not in report, (
            f"stage report contains premature status: {forbidden}"
        )
        assert forbidden not in hardening_plan, (
            f"hardening plan contains premature status: {forbidden}"
        )
        assert forbidden not in disposition_plan, (
            f"disposition plan contains premature status: {forbidden}"
        )


_PREMATURE_BATCH_4_STATUS_PATTERNS = (
    r"GitHub CI.{0,16}(?:已通过|已验证|已重新验证|成功)",
    r"Batch 4.{0,16}(?:已完成|已验收|已接受|\baccepted\b|\bcompleted?\b)",
    r"Windows MVP.{0,16}(?:已完成|已就绪|\bready\b|\bcompleted?\b)",
    r"(?:已通过|已达到).{0,8}生产安全|"
    r"生产安全.{0,8}(?:已通过|已验证|验证通过|已完成|已就绪|verified|ready)",
)


def _assert_current_batch_4_status(
    document: str,
    status: str,
    required_phrases: tuple[str, ...],
) -> None:
    for required in required_phrases:
        assert required in status, f"{document} missing Batch 4 status: {required}"
    normalized_status = " ".join(status.split())
    for pattern in _PREMATURE_BATCH_4_STATUS_PATTERNS:
        match = re.search(pattern, normalized_status, re.IGNORECASE)
        assert match is None, (
            f"{document} contains premature Batch 4 status: {match.group(0)}"
        )


def test_batch_4_status_guard_allows_incomplete_but_rejects_complete() -> None:
    _assert_current_batch_4_status(
        "synthetic",
        "Windows MVP remains incomplete",
        (),
    )
    with pytest.raises(AssertionError, match="premature Batch 4 status"):
        _assert_current_batch_4_status(
            "synthetic",
            "Windows MVP complete",
            (),
        )


def _extract_unique_current_section(
    document: str,
    text: str,
    start: str,
    end: str | None = None,
) -> str:
    start_count = text.count(start)
    assert start_count != 0, f"{document} missing section start: {start}"
    assert start_count == 1, f"{document} duplicate section start: {start}"
    start_index = text.index(start) + len(start)
    if end is None:
        return text[start_index:]

    end_count = text.count(end)
    assert end_count != 0, f"{document} missing section end: {end}"
    assert end_count == 1, f"{document} duplicate section end: {end}"
    end_index = text.index(end)
    assert start_index < end_index, f"{document} invalid section order"
    return text[start_index:end_index]


_MACHINE_SPECIFIC_ABSOLUTE_PATH = re.compile(
    r"(?i)(?:\b[A-Z]:[\\/]|\\\\[^\\/\s]+[\\/][^\\/\s]+)"
)


def _assert_no_machine_specific_paths(document: str, text: str) -> None:
    match = _MACHINE_SPECIFIC_ABSOLUTE_PATH.search(text)
    assert match is None, f"{document} contains machine-specific path"


@pytest.mark.parametrize(
    "path",
    (
        r"C:\Users\Synthetic\Python\python.exe",
        r"\\server\share\Users\Synthetic\python.exe",
    ),
    ids=("drive-qualified", "unc"),
)
def test_publishable_status_path_contract_rejects_machine_paths(path: str) -> None:
    with pytest.raises(AssertionError, match="contains machine-specific path"):
        _assert_no_machine_specific_paths("synthetic current status", path)


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
            _execute_task_2_example(mutated)
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
            _execute_task_2_example(mutated)
    finally:
        monkeypatch.undo()

    assert probe.calls == 0


def test_docs_track_batch_4_workflow_and_report_boundaries() -> None:
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    architecture = (PROJECT_ROOT / "docs" / "architecture.md").read_text(
        encoding="utf-8"
    )
    report = (
        PROJECT_ROOT / "docs" / "reports" / "alpha-0.1.0-stage-report.md"
    ).read_text(encoding="utf-8")
    plans = PROJECT_ROOT / "docs" / "superpowers" / "plans"
    hardening_plan = (
        plans / "2026-08-02-agentguardian-windows-mvp-hardening.md"
    ).read_text(encoding="utf-8")
    workflow_plan = (
        plans / "2026-08-03-agentguardian-windows-workflow-report-hardening.md"
    ).read_text(encoding="utf-8")
    workflow_design = (
        PROJECT_ROOT
        / "docs"
        / "superpowers"
        / "specs"
        / "2026-08-03-agentguardian-windows-workflow-report-hardening-design.md"
    ).read_text(encoding="utf-8")
    sample = _task_2_example_source(workflow_plan)
    namespace = _execute_task_2_example(sample)
    assert set(namespace) == {
        "__builtins__",
        "datetime",
        "findings",
        "json",
        "payload",
        "render_json",
        "score",
        "technical_score",
        "timezone",
    }
    assert type(namespace["__builtins__"]) is dict
    assert set(namespace["__builtins__"]) == {"__import__"}
    payload = namespace["payload"]
    expected_score = {
        "total": 100,
        "deductions": [
            {"domain": risk_domain.value, "amount": 0}
            for risk_domain in domain.RiskDomain
        ],
        "cap_reason": None,
        "coverage": 0.75,
        "confidence": 1.0,
        "incomplete": True,
        "limits": ["file_scan_limited"],
        "coverage_state": "limited",
    }

    assert type(payload) is dict
    assert payload == {
        "product": "AgentGuardian",
        "version": __version__,
        "report_schema": 1,
        "evaluated_at": "2026-08-03T12:00:00Z",
        "rule_version": "rules-1",
        "score": expected_score,
        "reviewed_score": expected_score,
        "findings": [],
    }

    readme_status = _extract_unique_current_section(
        "README",
        readme,
        "**工作流与报告硬化 Batch 4 当前状态。**",
        "## 开发与验证",
    )
    architecture_status = _extract_unique_current_section(
        "architecture",
        architecture,
        "## Windows MVP Batch 4 工作流与报告硬化",
        "## 后续可信性要求",
    )
    report_status = _extract_unique_current_section(
        "stage report",
        report,
        "## 11. Windows MVP 硬化 Batch 4：工作流与报告硬化",
    )
    hardening_status = _extract_unique_current_section(
        "Windows MVP hardening plan",
        hardening_plan,
        "## Batch 4 Local Implementation Status",
        "## Completed Batch: OpenAI Local Provider Hardening",
    )
    task_9 = _extract_unique_current_section(
        "Task 9 plan",
        workflow_plan,
        "## Task 9: Close Local Security, Documentation, and Package Evidence",
        "## Task 10: Independent Review and Final-SHA Remote Evidence",
    )
    task_10 = _extract_unique_current_section(
        "Task 10 plan",
        workflow_plan,
        "## Task 10: Independent Review and Final-SHA Remote Evidence",
        "## Plan Completion Gate",
    )

    incomplete_boundary = (
        "`a79995a7a6a950050d5628324f94a6b8a07e6308`",
        "Windows MVP 尚未完成",
        "未形成生产安全结论",
    )
    statuses = {
        "README": readme_status,
        "architecture": architecture_status,
        "stage report": report_status,
        "Windows MVP hardening plan": hardening_status,
    }
    for document, status in {
        **statuses,
        "Task 9 plan": task_9,
        "Task 10 plan": task_10,
    }.items():
        _assert_no_machine_specific_paths(document, status)
    owned_details = {
        "README": (
            "Task 10 的本地独立复审和双 Python 完整门禁已绑定",
            "`d1c3e9caa856812d0bdd3221b0c6a7083da937ff`",
            "Critical、Important、Minor 均为 0",
            "`1264 passed, 8 skipped, 0 failed`",
            "`152 passed`",
            "后续文档/测试证据同步提交必须单独验证",
            "每次扫描都需要与当前范围绑定的明确同意",
            "`complete`、`limited` 和 `no_supported_files`",
            "不完整结果不能用于确认安全",
            "筛选仅影响界面可见行，导出仍包含完整当前审计",
            "仅支持 JSON",
            "2 MiB",
            "聚合比较结果只在内存中瞬态保留",
            "2026-08-03 的 Task 9 证据提交",
            "`991bf81bb520e7f2ec12f331fbbe714f03212507`",
            "绑定该提交的历史证据",
            "规范 UTC 秒级 `evaluated_at`",
            "最多 2,000 个 findings、4,000 条 evidence 和 2 MiB UTF-8",
            "旧 schema 1 和 legacy schema 0 仅在所有处置均为 `open`",
            "tooltip 仅含完整 basename",
        ),
        "architecture": (
            "缺少 `evaluated_at` 的精确旧 schema 1 和 legacy schema 0",
            "不证明报告来源、内容真实性",
            "不匹配单个 finding",
            "不导出稳定的跨扫描 finding 标识符",
            "不会增加环境目录扫描、网络、API 调用或写入能力",
            "同一用户控制",
            "路径竞态",
            "主机时钟",
            "聚合碰撞",
            "依赖和二进制",
            "2026-08-03",
            "`991bf81bb520e7f2ec12f331fbbe714f03212507`",
            "绑定该 SHA 的历史证据",
            "`d1c3e9caa856812d0bdd3221b0c6a7083da937ff`",
            "独立规格复审和独立安全/质量复审均为零发现",
            "`1264 passed, 8 skipped, 0 failed`",
            "哈希锁定依赖临时隔离",
            "该实现基线之后的文档/测试证据同步提交不由上述运行自动覆盖",
            "最多 2,000 个 findings、4,000 条 evidence 和 2 MiB UTF-8",
            "生成器用同一个已验证时点计算处置状态、复核分并序列化",
            "任何不可验证的非 `open` 处置失败关闭",
            "tooltip 仅保留 basename，不包含目录",
        ),
        "stage report": (
            "OpenAI Provider 仍仅做本地适配、检测与人工指引",
            "不默认调用 API",
            "Python 3.14",
            "Python 3.12",
            "1174 passed, 8 skipped, 0 failed",
            "2026-08-03",
            "`991bf81bb520e7f2ec12f331fbbe714f03212507`",
            "`132 passed`",
            "全部 16 个包内 `.py` 模块",
            "findings=[]",
            "local_only=true",
            "network_capability=not_detected",
            "symlink 创建权限",
            "junction 已测试",
            "2026-08-13",
            "`d1c3e9caa856812d0bdd3221b0c6a7083da937ff`",
            "独立规格复审和独立安全/质量复审",
            "Critical：0；Important：0；Minor：0",
            "`1264 passed, 8 skipped, 0 failed`",
            "`152 passed`",
            "哈希锁定依赖临时隔离",
            "不把该 SHA 之后的文档/测试证据同步提交声明为被这些本地结果覆盖",
            "当前 Task 10 修复树",
            "最多 2,000 个 findings、4,000 条 evidence 和 2 MiB UTF-8",
            "push run `31714716636` / job `94496371022`",
            "Draft PR run `31714721274` / job `94496388008`",
            "annotations：0/0",
        ),
        "Windows MVP hardening plan": (
            "Task 1-8 已在本地实现",
            "2026-08-03",
            "`991bf81bb520e7f2ec12f331fbbe714f03212507`",
            "2026-08-13",
            "`d1c3e9caa856812d0bdd3221b0c6a7083da937ff`",
            "独立规格复审和独立安全/质量复审均为零发现",
            "`1264 passed, 8 skipped, 0 failed`",
            "哈希锁定依赖临时隔离",
            "push run `31714716636`",
            "Draft PR run `31714721274`",
            "规范 UTC 秒级 `evaluated_at`",
            "旧 schema 1 与 legacy schema 0 仅兼容全 `open` 报告",
            "长 basename 省略显示且 tooltip 不含目录",
        ),
    }
    for document, status in statuses.items():
        _assert_current_batch_4_status(
            document, status, incomplete_boundary + owned_details[document]
        )
    _assert_current_batch_4_status("Task 9 plan", task_9, ())
    _assert_current_batch_4_status("Task 10 plan", task_10, ())
    assert "Batches 5-6, Windows MVP, and production safety remain open" in task_9
    assert "Keep Batches 5-6 pending" in task_10

    assert "不默认访问 OpenAI API" in readme
    assert "不默认访问 OpenAI API" in architecture
    assert "不默认调用 API" in report_status
    assert "free of default API calls" in hardening_plan
    assert "zero default OpenAI API access" in workflow_plan
    for document, text, required in (
        (
            "README",
            readme,
            (
                "`evaluated_at` 是无默认值的 keyword-only 必填参数",
                "精确复算技术分和复核分",
            ),
        ),
        (
            "architecture",
            architecture,
            (
                "`evaluated_at` 是无默认值的 keyword-only 必填参数",
                "精确复算技术分和复核分",
            ),
        ),
        (
            "stage report",
            report,
            (
                "`evaluated_at` 是无默认值的 keyword-only 必填参数",
                "精确复算技术分和复核分",
            ),
        ),
        (
            "Windows MVP hardening plan",
            hardening_plan,
            (
                "required keyword-only `evaluated_at`",
                "recompute the technical and reviewed scores exactly",
            ),
        ),
        (
            "workflow plan",
            workflow_plan,
            (
                "required keyword-only `evaluated_at`",
                "recompute the technical and reviewed scores exactly",
            ),
        ),
        (
            "workflow design",
            workflow_design,
            (
                "required keyword-only `evaluated_at`",
                "recompute the technical and reviewed scores exactly",
            ),
        ),
    ):
        for phrase in required:
            assert phrase in text, f"{document} missing report contract: {phrase}"
    assert (
        "Task 1-8 implementation is local; Task 9 historical evidence is bound to "
        "`991bf81bb520e7f2ec12f331fbbe714f03212507`"
    ) in hardening_plan
    normalized_task_9 = " ".join(task_9.split())
    for required in (
        "Task 9 checkbox evidence was captured on 2026-08-03 for",
        "`991bf81bb520e7f2ec12f331fbbe714f03212507`",
        "Assertion-only commits through `9d87f972df6c5021482cf6dfc01b0ecf8ced86c9`",
        "`143 passed` on 2026-08-13",
        "No runtime or package source changed",
        "does not cover a later docs/tests synchronization commit",
        "Task 10 must rerun both complete Python gates at the current reviewed HEAD",
    ):
        assert required in normalized_task_9

    assert re.findall(r"- \[x\] \*\*Step (\d):", task_9) == list("12345678")
    assert "- [ ] **Step" not in task_9
    assert re.findall(r"- \[x\] \*\*Step (\d):", task_10) == list("123456")
    assert re.findall(r"- \[ \] \*\*Step (\d):", task_10) == list("7")
    normalized_task_10 = " ".join(task_10.split())
    for required in (
        "`https://github.com/yangjing6213-dev/AgentGuardian.git`",
        "target repository is absent before creation",
        "`origin` must match that exact URL",
        "upstream must be `origin/agent/founder-alpha`",
        "Never push to the retired `hqwzhu/AgentGuardian` remote",
        "push run `31714716636` / job `94496371022`",
        "Draft PR run `31714721274` / job `94496388008`",
        "check-run annotations were 0/0",
    ):
        assert required in normalized_task_10

    assert "Task 9 的完整本地门禁" not in readme_status
    assert "尚待本节提交" not in report_status


def test_batch_4_remote_evidence_is_bound_to_exact_sha_and_limits() -> None:
    plans = PROJECT_ROOT / "docs" / "superpowers" / "plans"
    current_status_files = {
        "README": PROJECT_ROOT / "README.md",
        "architecture": PROJECT_ROOT / "docs" / "architecture.md",
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
        PROJECT_ROOT / "README.md",
        PROJECT_ROOT / "docs" / "architecture.md",
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


def _replace_document_text(
    monkeypatch: pytest.MonkeyPatch,
    relative_path: str,
    current: str,
    replacement: str,
) -> None:
    original_read_text = Path.read_text
    target = PROJECT_ROOT / relative_path

    def replaced(path: Path, *args: object, **kwargs: object) -> str:
        text = original_read_text(path, *args, **kwargs)
        if path == target:
            assert current in text
            return text.replace(current, replacement, 1)
        return text

    monkeypatch.setattr(Path, "read_text", replaced)


@pytest.mark.parametrize(
    ("relative_path", "marker", "document"),
    (
        ("README.md", "2026-08-03 的 Task 9 证据提交", "README"),
        (
            "docs/architecture.md",
            "缺少 `evaluated_at` 的精确旧 schema 1 和 legacy schema 0",
            "architecture",
        ),
        (
            "docs/reports/alpha-0.1.0-stage-report.md",
            "全部 16 个包内 `.py` 模块",
            "stage report",
        ),
        (
            "docs/superpowers/plans/2026-08-02-agentguardian-windows-mvp-hardening.md",
            "push run `31714716636` 和 Draft PR run `31714721274`",
            "Windows MVP hardening plan",
        ),
    ),
)
def test_batch_4_doc_contract_rejects_cross_document_masking(
    monkeypatch: pytest.MonkeyPatch,
    relative_path: str,
    marker: str,
    document: str,
) -> None:
    _replace_document_text(monkeypatch, relative_path, marker, "")
    with pytest.raises(
        AssertionError,
        match=rf"{re.escape(document)} missing Batch 4 status",
    ):
        test_docs_track_batch_4_workflow_and_report_boundaries()


@pytest.mark.parametrize(
    "claim",
    (
        "GitHub CI 已通过",
        "Batch 4 已验收",
        "Windows MVP 已就绪",
        "已通过生产安全验证",
    ),
)
def test_batch_4_doc_contract_rejects_alternate_premature_claims(
    monkeypatch: pytest.MonkeyPatch,
    claim: str,
) -> None:
    current = "远程实现与证据基线 `a79995a7a6a950050d5628324f94a6b8a07e6308`"
    _replace_document_text(monkeypatch, "README.md", current, f"{current}。{claim}")
    with pytest.raises(
        AssertionError,
        match="README contains premature Batch 4 status",
    ):
        test_docs_track_batch_4_workflow_and_report_boundaries()


def test_batch_4_doc_contract_rejects_premature_claim_in_task_10(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = (
        "docs/superpowers/plans/"
        "2026-08-03-agentguardian-windows-workflow-report-hardening.md"
    )
    heading = "## Task 10: Independent Review and Final-SHA Remote Evidence"
    _replace_document_text(
        monkeypatch,
        plan,
        heading,
        f"{heading}\n\nGitHub CI 已通过",
    )
    with pytest.raises(
        AssertionError,
        match="Task 10 plan contains premature Batch 4 status",
    ):
        test_docs_track_batch_4_workflow_and_report_boundaries()


def test_batch_4_doc_contract_rejects_multiline_premature_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = "远程实现与证据基线 `a79995a7a6a950050d5628324f94a6b8a07e6308`"
    _replace_document_text(
        monkeypatch,
        "README.md",
        current,
        f"{current}。GitHub CI\n已通过",
    )
    with pytest.raises(
        AssertionError,
        match="README contains premature Batch 4 status",
    ):
        test_docs_track_batch_4_workflow_and_report_boundaries()


def test_batch_4_doc_contract_rejects_duplicate_current_section(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    heading = "**工作流与报告硬化 Batch 4 当前状态。**"
    end = "## 开发与验证"
    _replace_document_text(
        monkeypatch,
        "README.md",
        end,
        f"{end}\n\n{heading}\n\nGitHub CI 已通过",
    )
    with pytest.raises(AssertionError, match="README duplicate section start"):
        test_docs_track_batch_4_workflow_and_report_boundaries()


def test_batch_4_doc_contract_reports_missing_current_section(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    heading = "## Windows MVP Batch 4 工作流与报告硬化"
    _replace_document_text(monkeypatch, "docs/architecture.md", heading, "")
    with pytest.raises(AssertionError, match="architecture missing section start"):
        test_docs_track_batch_4_workflow_and_report_boundaries()


def test_docs_track_batch_6_local_gates_without_premature_release_claim() -> None:
    plans = PROJECT_ROOT / "docs" / "superpowers" / "plans"
    status_files = (
        PROJECT_ROOT / "README.md",
        PROJECT_ROOT / "docs" / "architecture.md",
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
