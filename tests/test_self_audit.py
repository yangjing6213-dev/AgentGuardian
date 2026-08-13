import ast
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
    "detectors.py",
    "discovery.py",
    "dispositions.py",
    "domain.py",
    "evidence_state.py",
    "guidance.py",
    "report_comparison.py",
    "reporting.py",
    "scoring.py",
    "self_audit.py",
    "state_store.py",
    "windows_dpapi.py",
    "workflow.py",
)


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
        "executable_path": sys.executable,
        "rules_sha256": hashlib.sha256(
            (PROJECT_ROOT / "rules" / "default.json").read_bytes()
        ).hexdigest(),
        "local_only": True,
        "network_capability": "not_detected",
        "ordinary_user_mode": True,
        "alpha_status": "Founder Alpha",
        "findings": [],
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


def test_current_package_has_no_prohibited_static_capabilities() -> None:
    assert static_capability_findings() == ()


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
    assert len(EXPECTED_REVIEWED_SOURCE_MODULES) == 16
    assert package_names == EXPECTED_REVIEWED_SOURCE_MODULES
    assert tuple(modules) == EXPECTED_REVIEWED_SOURCE_MODULES
    assert len(modules) == 16
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
        "路径、权限范围、动作 ID、前置条件、预览、批准、回滚和通过/失败复审字段均为未来未实现设想",
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
    assert "Draft PR #1 保持 `OPEN / DRAFT`" not in report

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
    r"Batch 4.{0,16}(?:已完成|已验收|已接受|accepted|completed?)",
    r"Windows MVP.{0,16}(?:已完成|已就绪|ready|completed?)",
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
    for pattern in _PREMATURE_BATCH_4_STATUS_PATTERNS:
        match = re.search(pattern, status, re.IGNORECASE)
        assert match is None, (
            f"{document} contains premature Batch 4 status: {match.group(0)}"
        )


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

    readme_status = readme.split(
        "**工作流与报告硬化 Batch 4 当前状态。**", 1
    )[1].split("## 开发与验证", 1)[0]
    architecture_status = architecture.split(
        "## Windows MVP Batch 4 工作流与报告硬化", 1
    )[1].split("## 后续可信性要求", 1)[0]
    report_status = report.split(
        "## 11. Windows MVP 硬化 Batch 4：工作流与报告硬化", 1
    )[1]
    hardening_status = hardening_plan.split(
        "## Batch 4 Local Implementation Status", 1
    )[1].split("## Completed Batch: OpenAI Local Provider Hardening", 1)[0]
    task_9 = workflow_plan.split(
        "## Task 9: Close Local Security, Documentation, and Package Evidence", 1
    )[1]
    task_9, task_10 = task_9.split(
        "## Task 10: Independent Review and Final-SHA Remote Evidence", 1
    )
    task_10 = task_10.split("## Plan Completion Gate", 1)[0]

    incomplete_boundary = (
        "当前 Batch 4 GitHub CI 尚未重新验证",
        "Batches 5-6 仍待完成",
        "Windows MVP 尚未完成",
        "未形成生产安全结论",
    )
    statuses = {
        "README": readme_status,
        "architecture": architecture_status,
        "stage report": report_status,
        "Windows MVP hardening plan": hardening_status,
    }
    owned_details = {
        "README": (
            "Task 9 完整本地门禁已重新通过",
            "Task 10 的独立复审和最终 SHA 远程验收尚未完成",
            "每次扫描都需要与当前范围绑定的明确同意",
            "`complete`、`limited` 和 `no_supported_files`",
            "不完整结果不能用于确认安全",
            "筛选仅影响界面可见行，导出仍包含完整当前审计",
            "仅支持 JSON",
            "2 MiB",
            "聚合比较结果只在内存中瞬态保留",
        ),
        "architecture": (
            "只接受精确的 legacy schema 0 和 report schema 1",
            "校验不证明报告真实性",
            "不匹配单个 finding",
            "不导出稳定的跨扫描 finding 标识符",
            "不会增加环境目录扫描、网络、API 调用或写入能力",
            "同一用户控制",
            "路径竞态",
            "主机时钟",
            "聚合碰撞",
            "依赖和二进制",
        ),
        "stage report": (
            "OpenAI Provider 仍仅做本地适配、检测与人工指引",
            "不默认调用 API",
            "Python 3.14",
            "Python 3.12",
            "1174 passed, 8 skipped, 0 failed",
            "全部 16 个包内 `.py` 模块",
            "findings=[]",
            "local_only=true",
            "network_capability=not_detected",
            "symlink 创建权限",
            "junction 已测试",
            "Task 10 的独立规格、安全和质量复审",
        ),
        "Windows MVP hardening plan": (
            "Task 1-8 已在本地实现",
            "Task 10 的独立复审和最终 SHA 远程证据未执行",
        ),
    }
    for document, status in statuses.items():
        _assert_current_batch_4_status(
            document, status, incomplete_boundary + owned_details[document]
        )

    assert "不默认访问 OpenAI API" in readme
    assert "不默认访问 OpenAI API" in architecture
    assert "不默认调用 API" in report_status
    assert "free of default API calls" in hardening_plan
    assert "zero default OpenAI API access" in workflow_plan
    assert (
        "Task 1-9 local implementation and evidence recorded. Task 10 independent "
        "review and final-SHA remote evidence remain pending."
    ) in hardening_plan

    assert re.findall(r"- \[x\] \*\*Step (\d):", task_9) == list("12345678")
    assert "- [ ] **Step" not in task_9
    assert re.findall(r"- \[ \] \*\*Step (\d):", task_10) == list("1234567")
    assert "- [x] **Step" not in task_10

    assert "Task 9 的完整本地门禁" not in readme_status
    assert "尚待本节提交" not in report_status


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
        ("README.md", "Task 9 完整本地门禁已重新通过", "README"),
        (
            "docs/architecture.md",
            "只接受精确的 legacy schema 0 和 report schema 1",
            "architecture",
        ),
        (
            "docs/reports/alpha-0.1.0-stage-report.md",
            "全部 16 个包内 `.py` 模块",
            "stage report",
        ),
        (
            "docs/superpowers/plans/2026-08-02-agentguardian-windows-mvp-hardening.md",
            "Task 10 的独立复审和最终 SHA 远程证据未执行",
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
    with pytest.raises(AssertionError, match=re.escape(document)):
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
    current = "当前 Batch 4 GitHub CI 尚未重新验证"
    _replace_document_text(monkeypatch, "README.md", current, f"{current}。{claim}")
    with pytest.raises(AssertionError, match="README"):
        test_docs_track_batch_4_workflow_and_report_boundaries()
