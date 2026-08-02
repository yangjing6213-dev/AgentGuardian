import hashlib
import json
import re
import socket
import sys
from pathlib import Path

import pytest

from agentguardian import __version__, self_audit
from agentguardian.self_audit import collect_self_audit, static_capability_findings

PROJECT_ROOT = Path(__file__).parents[1]


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


@pytest.mark.parametrize(
    ("findings", "network_capability", "local_only"),
    (
        ((), "not_detected", True),
        (("NETWORK_MODULE_IMPORT",), "detected", False),
        (("NETWORK_CAPABILITY",), "detected", False),
        (("DYNAMIC_EXECUTION",), "unverified", False),
        (("NATIVE_CAPABILITY",), "unverified", False),
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


def test_static_scan_marks_ambiguous_write_api_as_policy_violation(
    tmp_path: Path,
) -> None:
    package = tmp_path / "agentguardian"
    package.mkdir()
    (package / "synthetic.py").write_text(
        "class Status:\n"
        "    def system(self):\n"
        "        return 'memory only'\n"
        "class Label:\n"
        "    def write_text(self):\n"
        "        return 'memory only'\n"
        "Status().system()\n"
        "Label().write_text()\n",
        encoding="utf-8",
    )

    assert static_capability_findings(package) == ("SOURCE_POLICY_VIOLATION",)


def test_dangerous_attribute_alias_stays_reported_after_rebinding(
    tmp_path: Path,
) -> None:
    package = tmp_path / "agentguardian"
    package.mkdir()
    (package / "synthetic.py").write_text(
        "import os\n"
        "run = os.system\n"
        "run = lambda value: value\n"
        "run('cmd')\n",
        encoding="utf-8",
    )

    assert static_capability_findings(package) == ("SHELL_EXECUTION",)


def test_function_parameter_shadows_outer_import(tmp_path: Path) -> None:
    package = tmp_path / "agentguardian"
    package.mkdir()
    (package / "synthetic.py").write_text(
        "import os\n"
        "def use(os):\n"
        "    return os.system()\n",
        encoding="utf-8",
    )

    assert static_capability_findings(package) == ("SOURCE_POLICY_VIOLATION",)


def test_function_default_uses_outer_import_before_parameter_binding(
    tmp_path: Path,
) -> None:
    package = tmp_path / "agentguardian"
    package.mkdir()
    (package / "synthetic.py").write_text(
        "import os\n"
        "def use(os=os.system('cmd')):\n"
        "    return os\n",
        encoding="utf-8",
    )

    assert static_capability_findings(package) == ("SOURCE_POLICY_VIOLATION",)


def test_class_body_uses_outer_import_before_rebinding(tmp_path: Path) -> None:
    package = tmp_path / "agentguardian"
    package.mkdir()
    (package / "synthetic.py").write_text(
        "import os\n"
        "class Status:\n"
        "    before = os.system('cmd')\n"
        "    os = object()\n",
        encoding="utf-8",
    )

    assert static_capability_findings(package) == ("SOURCE_POLICY_VIOLATION",)


@pytest.mark.parametrize(
    "source",
    (
        "import os\nalias = os\nalias.system('cmd')\n",
        "load = __import__\nload('socket')\n",
        "from pathlib import Path\ntarget = Path('report')\ntarget.write_text('data')\n",
        "import pathlib\npathlib.Path('report').write_text('data')\n",
        "import os.path as osp\nosp.join('a', 'b')\n",
        "import os\nclass Memory:\n    def system(self): return 'memory'\nos = Memory()\nos.system()\n",
        "import os\ndef outer():\n    os.system('cmd')\n    def inner():\n        os = object()\n",
    ),
)
def test_source_policy_fails_closed_for_ambiguous_capability_code(
    tmp_path: Path, source: str
) -> None:
    package = tmp_path / "agentguardian"
    package.mkdir()
    (package / "synthetic.py").write_text(source, encoding="utf-8")

    assert static_capability_findings(package)


@pytest.mark.parametrize(
    "source",
    (
        "import os\nalias: object = os\nalias.system('cmd')\n",
        "load: object = __import__\nload('socket')\n",
        "import os\nif alias := os:\n    alias.system('cmd')\n",
        "import os\nalias, marker = os, object()\n",
    ),
)
def test_source_policy_covers_direct_alias_assignment_forms(
    tmp_path: Path, source: str
) -> None:
    package = tmp_path / "agentguardian"
    package.mkdir()
    (package / "synthetic.py").write_text(source, encoding="utf-8")

    assert static_capability_findings(package)


def test_static_scan_rejects_top_level_exclusive_open_in_app(tmp_path: Path) -> None:
    package = tmp_path / "agentguardian"
    package.mkdir()
    (package / "app.py").write_text(
        "with open('report.json', 'x', encoding='utf-8') as stream:\n"
        "    stream.write('{}')\n",
        encoding="utf-8",
    )

    assert static_capability_findings(package) == ("USER_DATA_WRITE",)


def test_real_app_export_contract_is_the_only_allowed_write() -> None:
    findings = static_capability_findings(PROJECT_ROOT / "src" / "agentguardian")

    assert "USER_DATA_WRITE" not in findings


def test_static_scan_recurses_into_nested_package(tmp_path: Path) -> None:
    package = tmp_path / "agentguardian"
    nested = package / "nested"
    nested.mkdir(parents=True)
    (nested / "capability.py").write_text("import socket\n", encoding="utf-8")

    assert static_capability_findings(package) == ("NETWORK_MODULE_IMPORT",)


def test_static_scan_allows_only_exact_self_audit_admin_probe(tmp_path: Path) -> None:
    package = tmp_path / "agentguardian"
    package.mkdir()
    module = package / "self_audit.py"
    module.write_text(
        "import ctypes\nctypes.windll.shell32.IsUserAnAdmin()\n",
        encoding="utf-8",
    )

    assert static_capability_findings(package) == ()

    module.write_text(
        "import ctypes\n"
        "native = ctypes\n"
        "ctypes.windll.shell32.IsUserAnAdmin()\n",
        encoding="utf-8",
    )
    assert static_capability_findings(package) == ("NATIVE_CAPABILITY",)

    module.write_text(
        "import ctypes\n"
        "native = ctypes.windll\n"
        "ctypes.windll.shell32.IsUserAnAdmin()\n",
        encoding="utf-8",
    )
    assert static_capability_findings(package) == ("NATIVE_CAPABILITY",)

    module.write_text(
        "import ctypes\n"
        "ctypes.windll.shell32.IsUserAnAdmin()\n"
        "ctypes.windll.shell32.IsUserAnAdmin()\n",
        encoding="utf-8",
    )
    assert static_capability_findings(package) == ("NATIVE_CAPABILITY",)

    module.write_text(
        "import ctypes\nctypes.CDLL('synthetic-library')\n",
        encoding="utf-8",
    )
    assert static_capability_findings(package) == ("NATIVE_CAPABILITY",)

    module.write_text("import ctypes\n", encoding="utf-8")
    assert static_capability_findings(package) == ("NATIVE_CAPABILITY",)


def test_static_scan_allows_only_constrained_windows_dpapi_adapter(
    tmp_path: Path,
) -> None:
    package = tmp_path / "agentguardian"
    package.mkdir()
    module = package / "windows_dpapi.py"
    source = (
        PROJECT_ROOT / "src" / "agentguardian" / "windows_dpapi.py"
    ).read_text(encoding="utf-8")

    module.write_text(source, encoding="utf-8")
    assert static_capability_findings(package) == ()

    mutations = (
        source.replace('"Crypt32.dll"', '"User32.dll"', 1),
        source + '\ncrypt32.CreateFileW\n',
        source + '\nnative = crypt32\nnative.CreateFileW()\n',
        source + '\nidentity = lambda value: value\nidentity(crypt32).CreateFileW()\n',
        source + '\n_libraries()[0].CreateFileW()\n',
        source + '\nloader = _libraries\nloader()[0].CreateFileW()\n',
        source + '\nnative = getattr(crypt32, "CreateFileW")\nnative()\n',
        source + '\ncrypt32["CreateFileW"]()\n',
        source + '\nctypes.WinDLL("User32.dll").CreateFileW()\n',
        source + '\nctypes.CDLL("User32.dll")\n',
        source + '\n__import__("ctypes")\n',
        source + "\nnative = ctypes\n",
    )
    for mutated in mutations:
        module.write_text(mutated, encoding="utf-8")
        assert static_capability_findings(package)


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
    package = tmp_path / "agentguardian"
    package.mkdir()
    module = package / "state_store.py"
    source = (PROJECT_ROOT / "src" / "agentguardian" / "state_store.py").read_text(
        encoding="utf-8"
    )

    module.write_text(source, encoding="utf-8")
    assert static_capability_findings(package) == ()

    mutations = (
        source + '\nopen("extra.bin", "wb")\n',
        source + '\nos.replace("extra.tmp", "extra.bin")\n',
        source + '\nreplace = os.replace\nreplace("extra.tmp", "extra.bin")\n',
        source + '\ngetattr(os, "replace")("extra.tmp", "extra.bin")\n',
        source + '\nos.__dict__["replace"]("extra.tmp", "extra.bin")\n',
        source + '\nvars(os)["replace"]("extra.tmp", "extra.bin")\n',
        source + '\ngetattr(os, "__dict__")["replace"]("extra.tmp", "extra.bin")\n',
        source + '\nlookup = vars\nlookup(os)["replace"]("extra.tmp", "extra.bin")\n',
        source + '\nlookup = getattr\nlookup(os, "replace")("extra.tmp", "extra.bin")\n',
        source + '\nPath("extra.bin").open("wb").write(b"unsafe")\n',
        source + '\ngetattr(Path("extra.bin"), "open")("wb").write(b"unsafe")\n',
        source + '\nos.open("extra.bin", 1)\n',
        source + '\nPath("extra").mkdir()\n',
        source + '\nPath("extra").unlink()\n',
    )
    for mutated in mutations:
        module.write_text(mutated, encoding="utf-8")
        assert static_capability_findings(package) == ("USER_DATA_WRITE",)


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
    status = "Batch 3 本地实现和门禁已完成；验收仍待最终 SHA 的远程验证。"
    pending = "Batches 4-6 仍待完成"
    premature = (
        "Batch 3 已完成。",
        "Batch 3 已完成；",
        "Batch 3 已完成本地实现",
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
        "`RemediationPlan` 和 `VerificationResult` 仅保留为数据契约",
        "Findings --> Guidance",
        "规则 ID、按 Windows 词法规则规范化的源路径，以及 NFKC 规范化的原始匹配",
        "本地处置 HMAC 密钥与每次扫描随机生成的报告 HMAC 密钥彼此独立",
        "DPAPI 不能抵御已经控制同一 Windows 用户会话的程序",
        "主机时钟、路径别名或文件移动可能重新打开发现，但不会扩大处置范围",
        "路径检查与 `os.replace` 之间仍有同用户竞态窗口",
        "Python 不能保证清除所有不可变 bytes 或字符串副本",
        "静态自审计只覆盖有界源码策略，不是对依赖或二进制的语义证明",
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
        "更新日期：2026-08-02",
        "第 8 节为已被第 9 至 10 节取代的历史交接记录",
        "Batch 2 历史远程证据",
        "Batch 3 当前本地证据",
        "`632 passed, 6 skipped`，0 failed",
        "`findings=[]`、`local_only=true`、`network_capability=not_detected`",
        "未经控制者验证，不声明当前或最终远程 CI",
        status,
        pending,
        "非生产",
    ):
        assert required in report
    assert "下一批为 DPAPI 保护的本地证据状态，目前尚未实现" not in report

    for required in (
        "## Batch 3 Local Implementation and Gate Status",
        "Acceptance pending final-SHA remote verification",
        status,
        pending,
        "非生产",
    ):
        assert required in hardening_plan

    for required in (
        "Path matching follows Windows lexical rules through",
        "Do not Unicode-normalize the path; NFKC applies only to the raw match",
        "Acceptance pending final-SHA remote verification",
        status,
        pending,
        "production safety",
    ):
        assert required in disposition_plan

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
