from __future__ import annotations

import importlib
import json
import os
from pathlib import Path, PureWindowsPath
import shutil
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "release_profiles" / "personal_store_release.json"


def _verifier():
    try:
        return importlib.import_module("scripts.verify_personal_release_profile")
    except ModuleNotFoundError:
        pytest.fail("personal release profile verifier is missing")


def _profile() -> dict[str, object]:
    if not PROFILE_PATH.is_file():
        pytest.fail("personal release profile is missing")
    return json.loads(PROFILE_PATH.read_text(encoding="ascii"))


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


def _copy_fixture(tmp_path: Path) -> Path:
    root = tmp_path / "repository"
    for relative in ("src/agentguardian", ".github/workflows", "docs/security"):
        shutil.copytree(ROOT / relative, root / relative)
    for relative in (
        "README.md",
        "docs/architecture.md",
        "scripts/build_windows_portable.py",
        "scripts/run_personal_privacy_acceptance.py",
        "scripts/verify_windows_release_candidate.py",
        "release_profiles/personal_store_release.json",
    ):
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    return root


def _write_profile(root: Path, profile: dict[str, object]) -> Path:
    path = root / "release_profiles" / "personal_store_release.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_canonical(profile))
    return path


def _verify_profile(verifier, root: Path) -> dict[str, str]:
    snapshot = verifier.load_profile_snapshot(
        root, "release_profiles/personal_store_release.json"
    )
    return verifier.verify_profile(root, snapshot)


def test_repository_matches_canonical_personal_store_release_profile() -> None:
    verifier = _verifier()
    profile = _profile()

    assert "forbidden_runtime_names" in profile
    assert "forbidden_runtime_members" in profile
    assert "forbidden_runtime_member_prefixes" in profile
    assert "forbidden_runtime_references" not in profile
    assert PROFILE_PATH.read_bytes() == _canonical(profile)
    assert _verify_profile(verifier, ROOT) == {
        "profile": "personal_store_release",
        "status": "pass",
    }


def test_profile_is_git_bound_to_lf_line_endings() -> None:
    result = subprocess.run(
        (
            "git",
            "check-attr",
            "eol",
            "--",
            "release_profiles/personal_store_release.json",
        ),
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    assert result.stdout.strip().endswith(": eol: lf")


@pytest.mark.parametrize(
    "mutation,code",
    (
        (lambda value: value.update({"unknown": []}), "PROFILE_SCHEMA_INVALID"),
        (
            lambda value: value["required_source_paths"].reverse(),
            "PROFILE_ARRAY_INVALID",
        ),
    ),
)
def test_profile_rejects_unknown_or_unsorted_values(
    tmp_path: Path, mutation, code: str
) -> None:
    verifier = _verifier()
    profile = _profile()
    mutation(profile)
    path = _write_profile(tmp_path, profile)

    with pytest.raises(verifier.ProfileViolation, match=f"^{code}$"):
        verifier.load_profile_snapshot(tmp_path, path)


def test_profile_rejects_duplicate_keys_and_oversized_json(tmp_path: Path) -> None:
    verifier = _verifier()
    path = tmp_path / "profile.json"
    path.write_bytes(b'{"schema":1,"schema":1}\n')
    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_JSON_INVALID$"):
        verifier.load_profile_snapshot(tmp_path, path)

    path.write_bytes(b" " * (64 * 1024 + 1))
    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_JSON_TOO_LARGE$"):
        verifier.load_profile_snapshot(tmp_path, path)


def test_profile_rejects_crlf_canonical_json(tmp_path: Path) -> None:
    verifier = _verifier()
    path = tmp_path / "profile.json"
    path.write_bytes(PROFILE_PATH.read_bytes().replace(b"\n", b"\r\n"))

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_JSON_INVALID$"):
        verifier.load_profile_snapshot(tmp_path, path)


@pytest.mark.parametrize("field,value", (("schema", 2), ("name", "personal_release")))
def test_profile_requires_exact_schema_and_name(
    tmp_path: Path, field: str, value: object
) -> None:
    verifier = _verifier()
    profile = _profile()
    profile[field] = value

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_SCHEMA_INVALID$"):
        verifier.load_profile_snapshot(tmp_path, _write_profile(tmp_path, profile))


@pytest.mark.parametrize(
    "value",
    (
        "/absolute/*.py",
        "C:/absolute/*.py",
        "file:/absolute/*.py",
        "../escape.py",
        "src/../escape.py",
        "src/./bad.py",
        "src//bad.py",
        "src/bad.py/",
        "src/carrier:stream/bad.py",
        "src\\bad.py",
    ),
)
def test_profile_rejects_unsafe_globs(tmp_path: Path, value: str) -> None:
    verifier = _verifier()
    profile = _profile()
    profile["forbidden_source_globs"] = sorted(
        [*profile["forbidden_source_globs"], value]
    )
    path = _write_profile(tmp_path, profile)

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_PATH_INVALID$"):
        verifier.load_profile_snapshot(tmp_path, path)


@pytest.mark.parametrize(
    "value",
    ("", ".", "..", "../profile.json", "release_profiles/../profile.json", "release_profiles\\profile.json"),
)
def test_profile_snapshot_rejects_unsafe_relative_actual_paths(
    tmp_path: Path, value: str
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_PATH_INVALID$") as caught:
        verifier.load_profile_snapshot(root, value)

    assert str(caught.value) == "PROFILE_PATH_INVALID"
    assert str(root) not in str(caught.value)


@pytest.mark.skipif(os.name != "nt", reason="Windows native Path regression")
def test_profile_snapshot_accepts_native_relative_path_object(tmp_path: Path) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)

    snapshot = verifier.load_profile_snapshot(
        root, Path("release_profiles") / "personal_store_release.json"
    )

    assert snapshot.profile["name"] == "personal_store_release"


@pytest.mark.skipif(os.name != "nt", reason="Windows native Path regression")
@pytest.mark.parametrize(
    "value",
    (
        Path(),
        Path("..") / "profile.json",
        Path("release_profiles") / "carrier:profile",
        Path("C:profile.json"),
    ),
)
def test_profile_snapshot_rejects_unsafe_native_relative_path_objects(
    tmp_path: Path, value: Path
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_PATH_INVALID$"):
        verifier.load_profile_snapshot(root, value)


def test_profile_path_rejects_windows_rooted_relative_before_filesystem_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = _verifier()

    class SimulatedWindowsPath(PureWindowsPath):
        def absolute(self):
            return self

    probes: list[PureWindowsPath] = []

    def reject_probe(path: PureWindowsPath) -> bool:
        probes.append(path)
        pytest.fail("rooted-relative profile path reached filesystem inspection")

    monkeypatch.setattr(verifier, "Path", SimulatedWindowsPath)
    monkeypatch.setattr(verifier, "_has_reparse_component", reject_probe)

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_PATH_INVALID$") as caught:
        verifier._resolved_profile_path(
            SimulatedWindowsPath("C:/project"),
            SimulatedWindowsPath(r"\Windows\win.ini"),
        )

    assert str(caught.value) == "PROFILE_PATH_INVALID"
    assert probes == []


def test_profile_snapshot_rejects_symlink_escape_before_resolution(tmp_path: Path) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    shutil.copyfile(PROFILE_PATH, outside / "profile.json")
    link = root / "release_profiles" / "linked"
    try:
        os.symlink(outside, link, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_REPARSE_POINT$") as caught:
        verifier.load_profile_snapshot(root, "release_profiles/linked/profile.json")

    assert str(caught.value) == "PROFILE_REPARSE_POINT"
    assert str(outside) not in str(caught.value)


def test_profile_snapshot_rejects_reparse_escape_deterministically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    linked = root / "release_profiles" / "linked"
    linked.mkdir()
    shutil.copyfile(PROFILE_PATH, linked / "profile.json")
    original = verifier._is_reparse_point
    monkeypatch.setattr(
        verifier,
        "_is_reparse_point",
        lambda path: path == linked or original(path),
    )

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_REPARSE_POINT$") as caught:
        verifier.load_profile_snapshot(root, "release_profiles/linked/profile.json")

    assert str(caught.value) == "PROFILE_REPARSE_POINT"
    assert str(linked) not in str(caught.value)


@pytest.mark.parametrize("absolute", (False, True))
def test_profile_snapshot_rejects_ntfs_ads_path_when_supported(
    tmp_path: Path, absolute: bool
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    carrier = root / "release_profiles" / "carrier"
    carrier.write_bytes(b"carrier")
    ads = Path(str(carrier) + ":profile")
    try:
        ads.write_bytes(PROFILE_PATH.read_bytes())
    except OSError:
        pytest.skip("NTFS alternate data streams are unavailable")

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_PATH_INVALID$") as caught:
        verifier.load_profile_snapshot(
            root, ads if absolute else "release_profiles/carrier:profile"
        )

    assert str(caught.value) == "PROFILE_PATH_INVALID"
    assert str(carrier) not in str(caught.value)


def test_profile_rejects_case_colliding_globs(tmp_path: Path) -> None:
    verifier = _verifier()
    profile = _profile()
    original = profile["forbidden_source_globs"][0]
    profile["forbidden_source_globs"] = sorted(
        [*profile["forbidden_source_globs"], original.upper()]
    )

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_ARRAY_INVALID$"):
        verifier.load_profile_snapshot(tmp_path, _write_profile(tmp_path, profile))


@pytest.mark.parametrize(
    "relative",
    (
        "requirements-enterprise.lock",
        "src/agentguardian/enterprise_policy.py",
        "src/agentguardian/sensitive_mode.py",
        "src/agentguardian/mcp_sandbox.py",
        "src/agentguardian/windows_appcontainer.py",
        "src/agentguardian/windows_code_signing.py",
        "src/agentguardian/windows_job_object.py",
        "scripts/download_trusted_mcp_adapter.py",
        "scripts/run_windows_mcp_adapter_acceptance.py",
        ".github/workflows/windows-mvp-signed.yml",
    ),
)
def test_profile_rejects_each_forbidden_source_class_case_insensitively(
    tmp_path: Path, relative: str
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    path = root / relative.upper()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("forbidden", encoding="utf-8")

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_SOURCE_FORBIDDEN$"):
        _verify_profile(verifier, root)


def test_double_star_forbidden_source_glob_matches_nested_path(tmp_path: Path) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    profile = _profile()
    profile["forbidden_source_globs"] = sorted(
        [*profile["forbidden_source_globs"], "**/blocked.py"]
    )
    _write_profile(root, profile)
    blocked = root / "unlisted" / "nested" / "blocked.py"
    blocked.parent.mkdir(parents=True)
    blocked.write_text("blocked", encoding="utf-8")

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_SOURCE_FORBIDDEN$"):
        snapshot = verifier.load_profile_snapshot(
            root, "release_profiles/personal_store_release.json"
        )
        verifier.verify_profile(root, snapshot)


@pytest.mark.parametrize("noise", ("build", "dist", "__pycache__"))
def test_double_star_glob_scans_nested_operational_noise_names(
    tmp_path: Path, noise: str
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    profile = _profile()
    profile["forbidden_source_globs"] = sorted(
        [*profile["forbidden_source_globs"], "**/blocked.py"]
    )
    _write_profile(root, profile)
    blocked = root / "nested" / noise / "blocked.py"
    blocked.parent.mkdir(parents=True)
    blocked.write_text("blocked", encoding="utf-8")

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_SOURCE_FORBIDDEN$"):
        _verify_profile(verifier, root)


def test_root_operational_noise_remains_excluded(tmp_path: Path) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    profile = _profile()
    profile["forbidden_source_globs"] = sorted(
        [*profile["forbidden_source_globs"], "**/blocked.py"]
    )
    _write_profile(root, profile)
    for noise in ("build", "dist", "__pycache__", ".pytest_cache"):
        blocked = root / noise / "blocked.py"
        blocked.parent.mkdir(parents=True)
        blocked.write_text("root noise", encoding="utf-8")

    assert _verify_profile(verifier, root)["status"] == "pass"


def test_project_traversal_rejects_case_colliding_entries_when_supported(
    tmp_path: Path,
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    directory = root / "collision"
    directory.mkdir()
    upper = directory / "Entry.txt"
    lower = directory / "entry.txt"
    upper.write_text("upper", encoding="utf-8")
    lower.write_text("lower", encoding="utf-8")
    if len(tuple(directory.iterdir())) != 2:
        pytest.skip("case-distinct filenames are unavailable")

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_PROJECT_INVALID$"):
        _verify_profile(verifier, root)


@pytest.mark.parametrize(
    "relative",
    (
        "adapters/tool.exe",
        "_internal/ADAPTERS/tool.exe",
        "_internal/McpAdapter-x64.exe",
        "_internal/agentguardian/ENTERPRISE_POLICY.PYC",
        "_internal/agentguardian/sensitive_mode.py",
        "scripts/RUN_WINDOWS_MCP_ADAPTER_ACCEPTANCE.PY",
    ),
)
def test_payload_rejects_retired_names_under_any_prefix(
    tmp_path: Path, relative: str
) -> None:
    verifier = _verifier()
    bundle = tmp_path / "bundle"
    path = bundle / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"synthetic")

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_PAYLOAD_FORBIDDEN$"):
        verifier.verify_payload(bundle, verifier.load_profile_snapshot(ROOT, PROFILE_PATH))


def test_payload_rejects_enumerated_colon_component(tmp_path: Path) -> None:
    verifier = _verifier()
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    colon_entry = bundle / "nested" / "carrier:stream"
    colon_entry.parent.mkdir()
    colon_entry.write_bytes(b"synthetic")
    if not any(path.name == "carrier:stream" for path in colon_entry.parent.iterdir()):
        pytest.skip("colon entry is not enumerable on this filesystem")

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_PAYLOAD_INVALID$") as caught:
        verifier.verify_payload(
            bundle, verifier.load_profile_snapshot(ROOT, PROFILE_PATH)
        )

    assert str(caught.value) == "PROFILE_PAYLOAD_INVALID"
    assert str(bundle) not in str(caught.value)


def test_payload_rejects_symlink_or_reparse_entry_when_supported(tmp_path: Path) -> None:
    verifier = _verifier()
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    target = tmp_path / "target"
    target.write_bytes(b"target")
    try:
        os.symlink(target, bundle / "linked")
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_REPARSE_POINT$"):
        verifier.verify_payload(bundle, verifier.load_profile_snapshot(ROOT, PROFILE_PATH))


def test_payload_rejects_reparse_entry_deterministically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier = _verifier()
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    residue = bundle / "residue"
    residue.write_bytes(b"synthetic")
    original = verifier._is_reparse_point
    monkeypatch.setattr(
        verifier,
        "_is_reparse_point",
        lambda path: path == residue or original(path),
    )

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_REPARSE_POINT$"):
        verifier.verify_payload(bundle, verifier.load_profile_snapshot(ROOT, PROFILE_PATH))


@pytest.mark.parametrize(
    "source,code",
    (
        ("import subprocess\n", "PROFILE_RUNTIME_IMPORT_FORBIDDEN"),
        ("from importlib import import_module\n", "PROFILE_RUNTIME_IMPORT_FORBIDDEN"),
        ("import openai\n", "PROFILE_RUNTIME_IMPORT_FORBIDDEN"),
        ("import anthropic\n", "PROFILE_RUNTIME_IMPORT_FORBIDDEN"),
        ("import sentry_sdk\n", "PROFILE_RUNTIME_IMPORT_FORBIDDEN"),
        ("import builtins as b\nrunner = b.compile\n", "PROFILE_RUNTIME_IMPORT_FORBIDDEN"),
        ("from builtins import eval as runner\n", "PROFILE_RUNTIME_IMPORT_FORBIDDEN"),
        ("from os import system as runner\n", "PROFILE_RUNTIME_REFERENCE_FORBIDDEN"),
        (
            "from PySide6.QtCore import QProcess as process\n",
            "PROFILE_RUNTIME_REFERENCE_FORBIDDEN",
        ),
        ("exec('pass')\n", "PROFILE_RUNTIME_REFERENCE_FORBIDDEN"),
        (
            "import os\nos.system('command')\n",
            "PROFILE_RUNTIME_REFERENCE_FORBIDDEN",
        ),
        (
            "from .mcp_sandbox import run_mcp_sandbox\n",
            "PROFILE_RUNTIME_SYMBOL_FORBIDDEN",
        ),
        ("SensitiveModePolicy()\n", "PROFILE_RUNTIME_SYMBOL_FORBIDDEN"),
        ("def _enterprise_page():\n    pass\n", "PROFILE_RUNTIME_SYMBOL_FORBIDDEN"),
    ),
)
def test_runtime_ast_rejects_removed_dynamic_llm_telemetry_and_process_code(
    tmp_path: Path, source: str, code: str
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    (root / "src/agentguardian/hostile.py").write_text(source, encoding="utf-8")

    with pytest.raises(verifier.ProfileViolation, match=f"^{code}$"):
        _verify_profile(verifier, root)


@pytest.mark.parametrize(
    "source",
    (
        "from os import *\nsystem('command')\n",
        "from os import *\nexecv('tool', ('tool',))\n",
        "from multiprocessing import *\nProcess()\n",
        "from asyncio import *\ncreate_subprocess_exec('tool')\n",
        "from benign_module import *\nvalue = harmless\n",
    ),
)
def test_runtime_ast_rejects_all_wildcard_imports_before_name_analysis(
    tmp_path: Path, source: str
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    (root / "src/agentguardian/hostile.py").write_text(source, encoding="utf-8")

    with pytest.raises(
        verifier.ProfileViolation, match="^PROFILE_RUNTIME_WILDCARD_IMPORT_FORBIDDEN$"
    ) as caught:
        _verify_profile(verifier, root)

    assert str(caught.value) == "PROFILE_RUNTIME_WILDCARD_IMPORT_FORBIDDEN"
    assert str(root) not in str(caught.value)
    assert source.strip() not in str(caught.value)


def test_runtime_ast_allows_explicit_allowed_imports(tmp_path: Path) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    (root / "src/agentguardian/allowed_imports.py").write_text(
        "from pathlib import Path\n"
        "from sqlite3 import connect\n"
        "path = Path('.')\n"
        "connection = connect(':memory:')\n",
        encoding="utf-8",
    )

    assert _verify_profile(verifier, root) == {
        "profile": "personal_store_release",
        "status": "pass",
    }


@pytest.mark.parametrize(
    "source",
    (
        "import PySide6.QtCore\nPySide6.QtCore.QProcess.startDetached('tool')\n",
        "import PySide6.QtCore as qc\nqc.QProcess.start('tool')\n",
        "import PySide6.QtCore as qc\nmodule = qc\nproc = module.QProcess\n",
        "from PySide6.QtCore import QProcess\nrunner = QProcess.startDetached\nrunner('tool')\n",
        "import PySide6.QtCore\nproc = PySide6.QtCore.QProcess\nproc.start('tool')\n",
        "import PySide6.QtCore as qc\nfirst = qc.QProcess\nsecond = first\nsecond.start('tool')\n",
        "import PySide6.QtCore as qc\nfirst = qc.QProcess\nsecond = first\nfirst = second\nsecond.start('tool')\n",
        "import os\nmodule = os\nrunner = module.system\n",
        "import multiprocessing\nrunner = multiprocessing.Process\n",
        "runner = getattr(module, 'system')\n",
        "runner = getattr(module, 'QProcess')\n",
        "runner = getattr(module, 'popen')\n",
        "runner = getattr(module, 'execv')\n",
        "runner = eval\n",
    ),
)
def test_runtime_ast_rejects_qualified_and_aliased_forbidden_references(
    tmp_path: Path, source: str
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    (root / "src/agentguardian/hostile.py").write_text(source, encoding="utf-8")

    with pytest.raises(
        verifier.ProfileViolation, match="^PROFILE_RUNTIME_REFERENCE_FORBIDDEN$"
    ) as caught:
        _verify_profile(verifier, root)

    assert str(caught.value) == "PROFILE_RUNTIME_REFERENCE_FORBIDDEN"
    assert str(root) not in str(caught.value)
    assert source.strip() not in str(caught.value)


def test_runtime_ast_rejects_subprocess_import_before_reference_scan(
    tmp_path: Path,
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    source = "import subprocess\nrunner = subprocess.run\nrunner(('tool',))\n"
    (root / "src/agentguardian/hostile.py").write_text(source, encoding="utf-8")

    with pytest.raises(
        verifier.ProfileViolation, match="^PROFILE_RUNTIME_IMPORT_FORBIDDEN$"
    ) as caught:
        _verify_profile(verifier, root)

    assert str(caught.value) == "PROFILE_RUNTIME_IMPORT_FORBIDDEN"


def test_runtime_ast_preserves_benign_aliases_and_noncalled_literals(
    tmp_path: Path,
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    (root / "src/agentguardian/benign_alias.py").write_text(
        "import sqlite3 as database\n"
        "connect = database.connect\n"
        "open_database = connect\n"
        "open_database(':memory:')\n"
        "left = right\nright = left\n"
        "import os\npath_value = os.fspath('.')\n"
        "safe_one = getattr(object(), 'st_file_attributes', 0)\n"
        "safe_two = getattr(object(), 'FILE_ATTRIBUTE_REPARSE_POINT', 0)\n"
        "class Library:\n"
        "    def compile(self): return None\n"
        "    def eval(self): return None\n"
        "    def exec(self): return None\n"
        "    def start(self): return None\n"
        "library = Library()\n"
        "library.compile(); library.eval(); library.exec(); library.start()\n"
        "DETECTOR_NAMES = ('subprocess.run', 'builtins.exec', 'QProcess.start')\n",
        encoding="utf-8",
    )

    assert _verify_profile(verifier, root)["status"] == "pass"


def test_runtime_ast_allows_benign_same_names_without_forbidden_rhs(
    tmp_path: Path,
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    (root / "src/agentguardian/benign_alias.py").write_text(
        "def first():\n"
        "    runner = len\n"
        "    return runner(())\n"
        "def benign_call():\n"
        "    runner = print\n"
        "    runner('ok')\n",
        encoding="utf-8",
    )

    assert _verify_profile(verifier, root)["status"] == "pass"


def test_runtime_ast_rejects_forbidden_reference_without_call(
    tmp_path: Path,
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    (root / "src/agentguardian/hostile.py").write_text(
        "import PySide6.QtCore as qc\n"
        "def forbidden_reference():\n"
        "    runner = qc.QProcess.start\n"
        "    return runner\n",
        encoding="utf-8",
    )

    with pytest.raises(
        verifier.ProfileViolation, match="^PROFILE_RUNTIME_REFERENCE_FORBIDDEN$"
    ):
        _verify_profile(verifier, root)


def test_runtime_ast_rejects_reference_even_when_later_shadowed(tmp_path: Path) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    source = root / "src/agentguardian/alias_order.py"
    source.write_text(
        "import PySide6.QtCore as qc\n"
        "runner = qc.QProcess.start\n"
        "runner = print\n"
        "runner('ok')\n",
        encoding="utf-8",
    )
    with pytest.raises(
        verifier.ProfileViolation, match="^PROFILE_RUNTIME_REFERENCE_FORBIDDEN$"
    ):
        _verify_profile(verifier, root)

    source.write_text(
        "runner = print\n"
        "runner = len\n"
        "runner(())\n",
        encoding="utf-8",
    )
    assert _verify_profile(verifier, root)["status"] == "pass"


def test_runtime_ast_allows_nested_benign_names_and_parameter_shadowing(
    tmp_path: Path,
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    (root / "src/agentguardian/benign_nested.py").write_text(
        "runner = print\n"
        "def outer():\n"
        "    runner = len\n"
        "    def inner(runner):\n"
        "        runner('ok')\n"
        "    inner(print)\n"
        "    safe_lambda = lambda runner: runner('ok')\n"
        "    safe_lambda(print)\n"
        "outer()\n",
        encoding="utf-8",
    )

    assert _verify_profile(verifier, root)["status"] == "pass"


def test_runtime_ast_scans_forbidden_reference_in_branch(tmp_path: Path) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    (root / "src/agentguardian/hostile.py").write_text(
        "import PySide6.QtCore as qc\n"
        "runner = print\n"
        "if condition:\n"
        "    runner = qc.QProcess.start\n"
        "else:\n"
        "    runner = print\n"
        "runner('tool')\n",
        encoding="utf-8",
    )

    with pytest.raises(
        verifier.ProfileViolation, match="^PROFILE_RUNTIME_REFERENCE_FORBIDDEN$"
    ):
        _verify_profile(verifier, root)


@pytest.mark.parametrize(
    "source",
    (
        "import os\nfor callback in (os.system,):\n    pass\n",
        "import os\ncallbacks = [os.system for _ in range(1)]\n",
        "import os\ndef run(callback=os.system):\n    return callback\n",
        "import os\nregister(os.system)\n",
        "from functools import partial\nimport os\ncallback = partial(os.system, 'tool')\n",
        "import os\ntry:\n    callback = os.system\nexcept Exception:\n    pass\n",
        "import os\nif (callback := os.system):\n    pass\n",
        "import os\ndef callback():\n    return os.system\n",
    ),
)
def test_runtime_ast_rejects_forbidden_reference_in_every_expression_context(
    tmp_path: Path, source: str
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    (root / "src/agentguardian/hostile.py").write_text(source, encoding="utf-8")

    with pytest.raises(
        verifier.ProfileViolation, match="^PROFILE_RUNTIME_REFERENCE_FORBIDDEN$"
    ) as caught:
        _verify_profile(verifier, root)

    assert str(caught.value) == "PROFILE_RUNTIME_REFERENCE_FORBIDDEN"
    assert str(root) not in str(caught.value)
    assert source.strip() not in str(caught.value)


@pytest.mark.parametrize("statement", ("pass\n", "0\n"))
def test_runtime_ast_node_limit_fails_closed_quickly_with_fixed_code(
    tmp_path: Path, statement: str
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    source = statement * 20_000
    (root / "src/agentguardian/hostile.py").write_text(source, encoding="utf-8")

    started = time.monotonic()
    with pytest.raises(
        verifier.ProfileViolation, match="^PROFILE_RUNTIME_ANALYSIS_LIMIT$"
    ) as caught:
        _verify_profile(verifier, root)
    elapsed = time.monotonic() - started

    assert str(caught.value) == "PROFILE_RUNTIME_ANALYSIS_LIMIT"
    assert str(root) not in str(caught.value)
    assert source.strip() not in str(caught.value)
    assert elapsed < 10.0


def test_runtime_source_byte_limit_fails_with_fixed_code(tmp_path: Path) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    source = root / "src/agentguardian/hostile.py"
    source.write_bytes(b"#" * (256 * 1024 + 1))

    with pytest.raises(
        verifier.ProfileViolation, match="^PROFILE_RUNTIME_ANALYSIS_LIMIT$"
    ):
        _verify_profile(verifier, root)


def test_runtime_parser_resource_failure_is_bounded_and_redacted(tmp_path: Path) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    source = "value = " + "+".join("1" for _ in range(12_000)) + "\n"
    assert len(source.encode("utf-8")) < verifier.MAX_RUNTIME_SOURCE_BYTES
    (root / "src/agentguardian/hostile.py").write_text(source, encoding="utf-8")

    with pytest.raises(
        verifier.ProfileViolation, match="^PROFILE_RUNTIME_ANALYSIS_LIMIT$"
    ) as caught:
        _verify_profile(verifier, root)

    assert str(caught.value) == "PROFILE_RUNTIME_ANALYSIS_LIMIT"
    assert str(root) not in str(caught.value)


@pytest.mark.parametrize(
    "failure", (RecursionError, MemoryError, OverflowError, SystemError)
)
def test_runtime_parser_resource_exceptions_use_fixed_limit_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: type[BaseException],
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)

    def fail_parse(_source: bytes):
        raise failure()

    monkeypatch.setattr(verifier, "ast", SimpleNamespace(parse=fail_parse))
    with pytest.raises(
        verifier.ProfileViolation, match="^PROFILE_RUNTIME_ANALYSIS_LIMIT$"
    ) as caught:
        _verify_profile(verifier, root)

    assert str(caught.value) == "PROFILE_RUNTIME_ANALYSIS_LIMIT"
    assert str(root) not in str(caught.value)


def test_network_import_set_rejects_undeclared_and_missing_modules(tmp_path: Path) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    (root / "src/agentguardian/hostile.py").write_text(
        "from requests import get\n", encoding="utf-8"
    )
    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_NETWORK_SET_INVALID$"):
        _verify_profile(verifier, root)

    (root / "src/agentguardian/hostile.py").unlink()
    (root / "src/agentguardian/share_verification.py").write_text(
        "def verify_public_share():\n    return None\n", encoding="utf-8"
    )
    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_NETWORK_SET_INVALID$"):
        _verify_profile(verifier, root)


def test_self_audit_detector_literals_do_not_false_positive(tmp_path: Path) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    (root / "src/agentguardian/self_audit.py").write_text(
        'DETECTOR_LITERALS = ("subprocess", "exec", "McpSandboxPolicy", "openai")\n',
        encoding="utf-8",
    )

    assert _verify_profile(verifier, root)["status"] == "pass"


def test_runtime_ast_retains_ctypes_sqlite_and_file_write_capabilities(
    tmp_path: Path,
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    (root / "src/agentguardian/retained.py").write_text(
        "import ctypes\nimport sqlite3\nfrom pathlib import Path\n"
        "sqlite3.connect(':memory:')\nPath('local').write_text('value')\n"
        "ctypes.c_void_p()\n",
        encoding="utf-8",
    )

    (root / "src/agentguardian/rebound_aliases.py").write_text(
        "def ctypes_value():\n"
        "    import ctypes as library\n"
        "    return library.c_void_p()\n"
        "def sqlite_value():\n"
        "    import sqlite3 as library\n"
        "    return library.connect(':memory:')\n",
        encoding="utf-8",
    )

    assert _verify_profile(verifier, root)["status"] == "pass"


def test_workflow_allows_normal_build_commands_but_rejects_retired_contracts(
    tmp_path: Path,
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    workflow = root / ".github/workflows/ordinary.yml"
    workflow.write_text(
        "on: workflow_dispatch\njobs:\n  build:\n    steps:\n      - run: python scripts/build_windows_portable.py\n",
        encoding="utf-8",
    )
    assert _verify_profile(verifier, root)["status"] == "pass"

    workflow.write_text("env:\n  AGENTGUARDIAN_SIGNING_PFX: retired\n", encoding="utf-8")
    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_WORKFLOW_FORBIDDEN$"):
        _verify_profile(verifier, root)


def test_workflow_scans_yaml_suffix_case_insensitively(tmp_path: Path) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    workflow = root / ".github/workflows/ordinary.YaMl"
    workflow.write_text(
        "on: workflow_dispatch\njobs:\n  build:\n    steps:\n"
        "      - run: python scripts/build_windows_portable.py\n",
        encoding="utf-8",
    )
    assert _verify_profile(verifier, root)["status"] == "pass"

    workflow.write_text(
        "env:\n  AGENTGUARDIAN_SIGNING_PFX: retired\n", encoding="utf-8"
    )
    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_WORKFLOW_FORBIDDEN$"):
        _verify_profile(verifier, root)


def test_workflow_read_limit_fails_closed_without_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    workflow = root / ".github/workflows/oversized.yaml"
    workflow.write_text("#" * 64, encoding="utf-8")
    monkeypatch.setattr(verifier, "_MAX_WORKFLOW_FILE_BYTES", 32)

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_WORKFLOW_INVALID$") as caught:
        _verify_profile(verifier, root)

    assert str(caught.value) == "PROFILE_WORKFLOW_INVALID"
    assert str(workflow) not in str(caught.value)


@pytest.mark.parametrize(
    "constant,code",
    (
        ("_MAX_DOCUMENT_FILE_BYTES", "PROFILE_DOCUMENT_INVALID"),
        ("_MAX_DOCUMENT_AGGREGATE_BYTES", "PROFILE_DOCUMENT_INVALID"),
    ),
)
def test_document_read_limits_fail_closed_without_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    constant: str,
    code: str,
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    monkeypatch.setattr(verifier, constant, 32)

    with pytest.raises(verifier.ProfileViolation, match=f"^{code}$") as caught:
        _verify_profile(verifier, root)

    assert str(caught.value) == code
    assert str(root) not in str(caught.value)


@pytest.mark.parametrize(
    "constant,value",
    (("_MAX_TRAVERSAL_ENTRIES", 2), ("_MAX_TRAVERSAL_DEPTH", 1)),
)
def test_project_traversal_limits_fail_closed_without_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    constant: str,
    value: int,
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    deep = root / "unlisted/a/b/c/value.txt"
    deep.parent.mkdir(parents=True)
    deep.write_text("value", encoding="utf-8")
    monkeypatch.setattr(verifier, constant, value)

    with pytest.raises(
        verifier.ProfileViolation, match="^PROFILE_PROJECT_TRAVERSAL_LIMIT$"
    ) as caught:
        _verify_profile(verifier, root)

    assert str(caught.value) == "PROFILE_PROJECT_TRAVERSAL_LIMIT"
    assert str(deep) not in str(caught.value)


def test_payload_traversal_limit_fails_closed_without_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier = _verifier()
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "one").write_text("one", encoding="utf-8")
    (bundle / "two").write_text("two", encoding="utf-8")
    monkeypatch.setattr(verifier, "_MAX_TRAVERSAL_ENTRIES", 1)

    with pytest.raises(
        verifier.ProfileViolation, match="^PROFILE_PAYLOAD_TRAVERSAL_LIMIT$"
    ) as caught:
        verifier.verify_payload(
            bundle, verifier.load_profile_snapshot(ROOT, PROFILE_PATH)
        )

    assert str(caught.value) == "PROFILE_PAYLOAD_TRAVERSAL_LIMIT"
    assert str(bundle) not in str(caught.value)


def test_static_detector_source_remains_required(tmp_path: Path) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    (root / "src/agentguardian/detectors.py").unlink()

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_REQUIRED_SOURCE_MISSING$"):
        _verify_profile(verifier, root)


def test_active_docs_reject_positive_promises_but_allow_negative_boundaries(
    tmp_path: Path,
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    readme = root / "README.md"
    readme.write_text(
        readme.read_text(encoding="utf-8")
        + "\nHigh-sensitivity mode is not supported.\n",
        encoding="utf-8",
    )
    assert _verify_profile(verifier, root)["status"] == "pass"

    readme.write_text(
        readme.read_text(encoding="utf-8")
        + "\nenterprise control plane is implemented\n",
        encoding="utf-8",
    )
    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_DOCUMENT_FORBIDDEN$"):
        _verify_profile(verifier, root)


@pytest.mark.parametrize(
    "stale_claim",
    (
        "Offline enterprise policy enforcement is implemented",
        "The desktop now exposes a local-only control-plane page",
        "A network-neutral enterprise service boundary now enforces",
        "A local transactional enterprise control-plane core is now implemented",
        "High-sensitivity mode disables the share-verification UI",
    ),
)
def test_active_readme_rejects_each_retired_implementation_claim(
    tmp_path: Path, stale_claim: str
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    readme = root / "README.md"
    readme.write_text(
        readme.read_text(encoding="utf-8") + "\n" + stale_claim + "\n",
        encoding="utf-8",
    )

    with pytest.raises(
        verifier.ProfileViolation, match="^PROFILE_DOCUMENT_FORBIDDEN$"
    ):
        _verify_profile(verifier, root)


@pytest.mark.parametrize(
    "relative,stale_claim",
    (
        (
            "docs/architecture.md",
            "`enterprise_policy.py` provides offline policy admission",
        ),
        (
            "docs/architecture.md",
            "`enterprise_policy.py` 提供离线策略准入",
        ),
        (
            "docs/security/windows-mvp-threat-model.md",
            "`enterprise_policy.py` rejects duplicate/unknown fields",
        ),
        (
            "docs/security/windows-mvp-threat-model.md",
            "Optional `enterprise_signing.py` verifies an Ed25519 envelope",
        ),
    ),
)
def test_active_architecture_and_threat_model_reject_retired_controls(
    tmp_path: Path, relative: str, stale_claim: str
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    document = root / relative
    document.write_text(
        document.read_text(encoding="utf-8") + "\n" + stale_claim + "\n",
        encoding="utf-8",
    )

    with pytest.raises(
        verifier.ProfileViolation, match="^PROFILE_DOCUMENT_FORBIDDEN$"
    ):
        _verify_profile(verifier, root)


def test_historical_report_and_superpowers_docs_are_excluded(tmp_path: Path) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    for relative in ("docs/reports/history.md", "docs/superpowers/history.md"):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "Offline enterprise policy enforcement is implemented\n",
            encoding="utf-8",
        )

    assert _verify_profile(verifier, root)["status"] == "pass"


def test_cli_emits_bounded_canonical_json_without_private_paths(tmp_path: Path) -> None:
    script = ROOT / "scripts" / "verify_personal_release_profile.py"
    passed = subprocess.run(
        [sys.executable, str(script), "--project-root", str(ROOT), "--profile", str(PROFILE_PATH)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert passed.returncode == 0, passed.stderr
    assert passed.stdout == '{"profile":"personal_store_release","status":"pass"}\n'
    assert passed.stderr == ""

    relative = subprocess.run(
        [
            sys.executable,
            str(script),
            "--project-root",
            str(ROOT),
            "--profile",
            "release_profiles/personal_store_release.json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert relative.returncode == 0, relative.stderr
    assert relative.stdout == '{"profile":"personal_store_release","status":"pass"}\n'
    assert relative.stderr == ""

    root = _copy_fixture(tmp_path)
    forbidden = root / "src/agentguardian/mcp_sandbox.py"
    forbidden.write_text("forbidden", encoding="utf-8")
    failed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--project-root",
            str(root),
            "--profile",
            str(root / "release_profiles/personal_store_release.json"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    combined = failed.stdout + failed.stderr
    assert failed.returncode != 0
    assert "PROFILE_SOURCE_FORBIDDEN" in combined
    assert str(root) not in combined
