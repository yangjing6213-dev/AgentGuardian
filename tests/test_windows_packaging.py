import hashlib
import json
import inspect
import os
from pathlib import Path
import re
import subprocess
import sys
from types import SimpleNamespace
import zipfile
from datetime import datetime, timezone

import pytest

from scripts.verify_personal_release_profile import (
    ProfileViolation,
    profile_snapshot_from_bytes,
)
from scripts.build_windows_portable import (
    artifact_manifest,
    build_portable,
    build_pyinstaller_command,
    build_integrations_preview_pyinstaller_command,
    canonical_json_bytes,
    cyclonedx_bom_bytes,
    deterministic_zip,
    filter_qt_gui_binaries,
    portable_component_specs,
    reviewed_source_paths,
    runtime_library_versions,
    _locked_versions,
    validate_build_dependency_snapshot,
    validate_relative_paths,
    write_portable_evidence,
    validate_frozen_layout,
    validate_git_build_context,
    validate_build_time,
    _pe_version,
)


PROJECT_ROOT = Path(__file__).parents[1]
PACKAGE_ROOT = PROJECT_ROOT / "src" / "agentguardian"
BUILD_PACKAGES = {
    "altgraph": "0.17.4",
    "annotated-types": "0.8.0",
    "anyio": "4.14.2",
    "attrs": "26.1.0",
    "boolean-py": "5.0",
    "cffi": "2.1.1",
    "click": "8.4.2",
    "colorama": "0.4.6",
    "cryptography": "50.0.0",
    "cyclonedx-python-lib": "11.12.0",
    "defusedxml": "0.7.1",
    "h11": "0.16.0",
    "httpcore2": "2.12.0",
    "httpx2": "2.12.0",
    "idna": "3.19",
    "jsonschema": "4.26.0",
    "jsonschema-specifications": "2025.9.1",
    "mcp": "2.0.0",
    "mcp-types": "2.0.0",
    "opentelemetry-api": "1.44.0",
    "license-expression": "30.4.4",
    "packaging": "26.2",
    "packageurl-python": "0.17.6",
    "pefile": "2023.2.7",
    "py-serializable": "2.1.0",
    "pycparser": "3.0",
    "pydantic": "2.13.4",
    "pydantic-core": "2.46.4",
    "pyinstaller": "6.16.0",
    "pyinstaller-hooks-contrib": "2025.9",
    "pyjwt": "2.13.0",
    "pyside6": "6.11.1",
    "pyside6-addons": "6.11.1",
    "pyside6-essentials": "6.11.1",
    "python-multipart": "0.0.32",
    "pywin32": "312",
    "pywin32-ctypes": "0.2.3",
    "referencing": "0.37.0",
    "rpds-py": "2026.6.3",
    "setuptools": "81.0.0",
    "shiboken6": "6.11.1",
    "sortedcontainers": "2.4.0",
    "sse-starlette": "3.4.8",
    "starlette": "1.6.0",
    "truststore": "0.10.4",
    "typing-extensions": "4.16.0",
    "typing-inspection": "0.4.4",
    "uvicorn": "0.52.4",
}

RUNTIME_PACKAGES = {
    "annotated-types",
    "anyio",
    "attrs",
    "cffi",
    "click",
    "colorama",
    "cryptography",
    "h11",
    "httpcore2",
    "httpx2",
    "idna",
    "jsonschema",
    "jsonschema-specifications",
    "mcp",
    "mcp-types",
    "opentelemetry-api",
    "pydantic",
    "pydantic-core",
    "pycparser",
    "pyjwt",
    "pyside6",
    "pyside6-addons",
    "pyside6-essentials",
    "python-multipart",
    "pywin32",
    "referencing",
    "rpds-py",
    "shiboken6",
    "sse-starlette",
    "starlette",
    "truststore",
    "typing-extensions",
    "typing-inspection",
    "uvicorn",
}
def _prepare_portable_build(
    monkeypatch: pytest.MonkeyPatch,
    *,
    commit: str,
    events: list[str],
) -> None:
    import scripts.build_windows_portable as build_module

    snapshot = profile_snapshot_from_bytes(
        (
            PROJECT_ROOT / "release_profiles/personal_exe_private_beta.json"
        ).read_bytes()
    )

    def record_snapshot(name: str):
        def record(*args) -> None:
            assert args[-1] is snapshot
            events.append(name)

        return record

    monkeypatch.setattr(build_module.sys, "platform", "win32")
    monkeypatch.setattr(build_module.sys, "version_info", (3, 12))
    monkeypatch.setattr(
        build_module,
        "_git",
        lambda _root, *arguments: commit if arguments == ("rev-parse", "HEAD") else "",
    )
    monkeypatch.setattr(build_module, "_require_current_source_identity", lambda *args: None)
    monkeypatch.setattr(build_module, "validate_build_dependency_snapshot", lambda: {})
    monkeypatch.setattr(build_module, "build_pyinstaller_command", lambda *args: ("fake",))
    monkeypatch.setattr(
        build_module.subprocess,
        "run",
        lambda *args, **kwargs: events.append("pyinstaller"),
    )
    monkeypatch.setattr(
        build_module,
        "load_profile_snapshot",
        lambda *args: snapshot,
        raising=False,
    )
    monkeypatch.setattr(
        build_module,
        "verify_profile",
        record_snapshot("source_profile"),
        raising=False,
    )
    monkeypatch.setattr(
        build_module,
        "verify_payload",
        record_snapshot("payload_profile"),
        raising=False,
    )
    monkeypatch.setattr(
        build_module,
        "require_profile_snapshot_unchanged",
        record_snapshot("snapshot_unchanged"),
        raising=False,
    )
    monkeypatch.setattr(
        build_module,
        "validate_frozen_layout",
        lambda *args: events.append("layout"),
    )
    monkeypatch.setattr(build_module, "runtime_library_versions", lambda: ("3.12.2", "3.0.13"))
    monkeypatch.setattr(build_module, "_pe_version", lambda path: "14.0.0.0")
    monkeypatch.setattr(build_module, "portable_component_specs", lambda **kwargs: ())
    monkeypatch.setattr(
        build_module,
        "write_portable_evidence",
        lambda *args, **kwargs: events.append("evidence"),
    )
    monkeypatch.setattr(
        build_module,
        "_write_personal_profile_evidence",
        record_snapshot("profile_evidence"),
        raising=False,
    )
    monkeypatch.setattr(
        build_module, "deterministic_zip", lambda *args: events.append("zip")
    )


def test_personal_portable_builder_has_no_dynamic_mcp_inputs() -> None:
    signature = inspect.signature(build_portable)

    assert tuple(signature.parameters) == (
        "project_root",
        "output_root",
        "source_commit",
        "built_at",
        "artifact_status",
        "release_profile",
    )


def test_portable_builder_rejects_retired_store_artifact_status(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import scripts.build_windows_portable as build_module

    monkeypatch.setattr(build_module.sys, "platform", "win32")
    monkeypatch.setattr(build_module.sys, "version_info", (3, 12))

    with pytest.raises(ValueError, match="artifact status is invalid"):
        build_module.build_portable(
            tmp_path,
            tmp_path / "output",
            source_commit="a" * 40,
            built_at="2026-08-21T00:00:00Z",
            artifact_status="store_submission_candidate",
        )
def test_portable_build_verifies_source_then_payload_and_records_profile_digest(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import scripts.build_windows_portable as build_module

    events: list[str] = []
    _prepare_portable_build(monkeypatch, commit="a" * 40, events=events)
    output = tmp_path / "output"
    record_source_profile = build_module.verify_profile

    def verify_before_output(*args) -> None:
        assert not output.exists()
        record_source_profile(*args)

    monkeypatch.setattr(build_module, "verify_profile", verify_before_output)

    build_module.build_portable(
        tmp_path,
        output,
        source_commit="a" * 40,
        built_at="2026-08-14T00:00:00Z",
    )

    assert events.index("source_profile") < events.index("pyinstaller")
    assert (
        events.index("layout")
        < events.index("payload_profile")
        < events.index("evidence")
    )
    assert events.index("snapshot_unchanged") < events.index("profile_evidence")
    assert events.index("snapshot_unchanged") < events.index("evidence")
    assert events.index("snapshot_unchanged") < events.index("zip")


def test_integrations_preview_portable_uses_profile_filename(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import scripts.build_windows_portable as build_module
    import scripts.verify_integrations_preview_profile as preview_verifier

    commit = "a" * 40
    snapshot = preview_verifier.load_profile_snapshot(
        PROJECT_ROOT, PROJECT_ROOT / "release_profiles/integrations_preview.json"
    )
    destinations: list[Path] = []

    monkeypatch.setattr(build_module.sys, "platform", "win32")
    monkeypatch.setattr(build_module.sys, "version_info", (3, 12))
    monkeypatch.setattr(build_module, "_git", lambda _root, *args: commit if args == ("rev-parse", "HEAD") else "")
    monkeypatch.setattr(build_module, "load_integrations_preview_profile_snapshot", lambda *args: snapshot)
    monkeypatch.setattr(build_module, "_require_current_source_identity", lambda *args: None)
    monkeypatch.setattr(build_module, "validate_build_dependency_snapshot", lambda: {})
    monkeypatch.setattr(build_module, "build_integrations_preview_pyinstaller_command", lambda *args: ("fake",))
    monkeypatch.setattr(build_module.subprocess, "run", lambda *args, **kwargs: None)
    monkeypatch.setattr(build_module, "_materialize_integrations_preview_skill", lambda *args: None)
    monkeypatch.setattr(build_module, "validate_integrations_preview_layout", lambda *args: None)
    monkeypatch.setattr(build_module, "_write_integrations_preview_profile_evidence", lambda *args: None)
    monkeypatch.setattr(preview_verifier, "verify_profile", lambda *args: None)
    monkeypatch.setattr(preview_verifier, "verify_payload", lambda *args: None)
    monkeypatch.setattr(preview_verifier, "verify_profile_evidence", lambda *args: None)
    monkeypatch.setattr(build_module, "runtime_library_versions", lambda: ("3.12.2", "3.0.13"))
    monkeypatch.setattr(build_module, "_pe_version", lambda path: "14.0.0.0")
    monkeypatch.setattr(build_module, "portable_component_specs", lambda **kwargs: ())
    monkeypatch.setattr(build_module, "write_portable_evidence", lambda *args, **kwargs: None)
    monkeypatch.setattr(build_module, "require_profile_snapshot_unchanged", lambda *args: None)
    monkeypatch.setattr(
        build_module,
        "deterministic_zip",
        lambda _bundle, destination: destinations.append(destination) or destination,
    )

    build_module.build_portable(
        tmp_path,
        tmp_path / "output",
        source_commit=commit,
        built_at="2026-08-25T00:00:00Z",
        release_profile="integrations_preview",
    )

    assert destinations == [tmp_path / "output" / snapshot.profile["portable_filename"]]


def test_private_beta_portable_keeps_sha_suffixed_filename(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import scripts.build_windows_portable as build_module

    commit = "b" * 40
    destinations: list[Path] = []
    _prepare_portable_build(monkeypatch, commit=commit, events=[])
    monkeypatch.setattr(
        build_module,
        "deterministic_zip",
        lambda _bundle, destination: destinations.append(destination) or destination,
    )

    build_module.build_portable(
        tmp_path,
        tmp_path / "output",
        source_commit=commit,
        built_at="2026-08-25T00:00:00Z",
    )

    assert destinations == [
        tmp_path / "output" / f"AgentGuardian-0.2.0-beta.1-windows-x64-{commit[:12]}.zip"
    ]


def test_personal_profile_evidence_is_canonical_and_digest_bound(tmp_path: Path) -> None:
    import scripts.build_windows_portable as build_module

    bundle = tmp_path / "bundle"
    bundle.mkdir()
    profile_path = (
        PROJECT_ROOT / "release_profiles/personal_exe_private_beta.json"
    )
    snapshot = profile_snapshot_from_bytes(profile_path.read_bytes())
    build_module._write_personal_profile_evidence(bundle, snapshot)

    evidence_path = bundle / "PERSONAL-RELEASE-PROFILE.json"
    evidence = json.loads(evidence_path.read_bytes())
    assert evidence == {
        "profile": "personal_exe_private_beta",
        "profile_sha256": snapshot.sha256,
        "schema": 2,
        "status": "pass",
    }
    assert evidence_path.read_bytes() == canonical_json_bytes(evidence)


def test_portable_build_rejects_profile_mutation_before_evidence_and_zip(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import scripts.build_windows_portable as build_module
    from scripts.verify_personal_release_profile import require_profile_snapshot_unchanged

    project = tmp_path / "project"
    profile_path = project / "release_profiles/personal_exe_private_beta.json"
    profile_path.parent.mkdir(parents=True)
    profile_path.write_bytes(
        (
            PROJECT_ROOT / "release_profiles/personal_exe_private_beta.json"
        ).read_bytes()
    )
    events: list[str] = []
    _prepare_portable_build(monkeypatch, commit="a" * 40, events=events)

    def mutate_profile(*args, **kwargs) -> None:
        events.append("pyinstaller")
        profile_path.write_bytes(profile_path.read_bytes() + b" ")

    monkeypatch.setattr(build_module.subprocess, "run", mutate_profile)
    monkeypatch.setattr(
        build_module,
        "require_profile_snapshot_unchanged",
        require_profile_snapshot_unchanged,
    )
    output = tmp_path / "output"

    with pytest.raises(ProfileViolation, match="^PROFILE_SNAPSHOT_CHANGED$"):
        build_module.build_portable(
            project,
            output,
            source_commit="a" * 40,
            built_at="2026-08-14T00:00:00Z",
        )

    assert "profile_evidence" not in events
    assert "evidence" not in events
    assert not tuple(output.glob("*.zip"))


def test_portable_builder_cli_loads_project_package_without_pythonpath() -> None:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)

    result = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "scripts" / "build_windows_portable.py"), "--help"],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def test_reviewed_source_paths_exactly_match_package_policy() -> None:
    policy = json.loads(
        (PACKAGE_ROOT / "source_policy.json").read_text(encoding="utf-8")
    )

    paths = reviewed_source_paths(PROJECT_ROOT)

    assert tuple(path.name for path in paths) == tuple(sorted(policy["modules"]))
    assert set(paths) == set(PACKAGE_ROOT.glob("*.py"))


def test_reviewed_source_paths_reject_missing_policy_module(tmp_path: Path) -> None:
    package_root = tmp_path / "src" / "agentguardian"
    package_root.mkdir(parents=True)
    (package_root / "source_policy.json").write_text(
        json.dumps({"schema": 1, "modules": {"missing.py": "0" * 64}}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="reviewed source set"):
        reviewed_source_paths(tmp_path)


def test_pyinstaller_command_is_inspectable_non_elevated_onedir(
    tmp_path: Path,
) -> None:
    output_root = tmp_path / "output"

    command = build_pyinstaller_command(
        PROJECT_ROOT,
        output_root,
        python_executable="python.exe",
    )

    assert command[:3] == ("python.exe", "-m", "PyInstaller")
    for required in (
        "--clean",
        "--noconfirm",
        "--onedir",
        "--windowed",
        "--noupx",
        "--name",
        "AgentGuardian",
        "--paths",
        str((PROJECT_ROOT / "src").resolve()),
        "--additional-hooks-dir",
        str((PROJECT_ROOT / "scripts" / "pyinstaller_hooks").resolve()),
        str((PACKAGE_ROOT / "__main__.py").resolve()),
    ):
        assert required in command
    for forbidden in ("--onefile", "--uac-admin", "--uac-uiaccess"):
        assert forbidden not in command
    excluded_modules = {
        command[index + 1]
        for index, value in enumerate(command[:-1])
        if value == "--exclude-module"
    }
    assert excluded_modules == {"PySide6.QtNetwork"}

    data_specs = {
        command[index + 1]
        for index, value in enumerate(command[:-1])
        if value == "--add-data"
    }
    expected_sources = {
        f"{(PACKAGE_ROOT / name).resolve()}:agentguardian"
        for name in (
            path.name for path in reviewed_source_paths(PROJECT_ROOT)
        )
    }
    assert expected_sources <= data_specs
    assert f"{(PACKAGE_ROOT / 'source_policy.json').resolve()}:agentguardian" in data_specs
    assert (
        f"{(PROJECT_ROOT / 'rules' / 'default.json').resolve()}:agentguardian/rules"
        in data_specs
    )

    assert command[command.index("--distpath") + 1] == str(output_root / "dist")
    assert command[command.index("--workpath") + 1] == str(output_root / "work")
    assert command[command.index("--specpath") + 1] == str(output_root / "spec")


def test_integrations_preview_command_uses_one_reviewed_spec_and_two_launchers(
    tmp_path: Path,
) -> None:
    command = build_integrations_preview_pyinstaller_command(
        PROJECT_ROOT,
        tmp_path / "output",
        python_executable="python.exe",
    )

    assert command[:5] == ("python.exe", "-m", "PyInstaller", "--clean", "--noconfirm")
    assert command[-1].endswith("packaging\\windows\\AgentGuardianIntegrationsPreview.spec")
    assert "--windowed" not in command
    assert "--specpath" not in command
    assert "AgentGuardianIntegrationsPreview.spec" in command[-1]

    spec = (
        PROJECT_ROOT / "packaging/windows/AgentGuardianIntegrationsPreview.spec"
    ).read_text(encoding="utf-8")
    assert "Path(SPECPATH)" in spec
    assert "Path(__file__)" not in spec
    assert '"agentguardian_skill"' not in spec


def test_integrations_preview_skill_is_materialized_from_fixed_allowlist(
    tmp_path: Path,
) -> None:
    import scripts.build_windows_portable as build_module

    source = tmp_path / "skills" / "agentguardian"
    source.mkdir(parents=True)
    for name in ("LICENSE", "README.md", "SKILL.md"):
        (source / name).write_text(name, encoding="ascii")
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    build_module._materialize_integrations_preview_skill(tmp_path, bundle)

    skill = bundle / "agentguardian_skill"
    assert {path.name for path in skill.iterdir()} == {
        "LICENSE",
        "README.md",
        "SKILL.md",
    }
    assert (skill / "SKILL.md").read_text(encoding="ascii") == "SKILL.md"


def test_qt_gui_hook_filters_only_unused_network_dependency_chain() -> None:
    binaries = [
        ("C:/Qt/plugins/platforms/qwindows.dll", "PySide6/plugins/platforms"),
        ("C:/Qt/plugins/imageformats/qjpeg.dll", "PySide6/plugins/imageformats"),
        ("C:/Qt/plugins/imageformats/qpdf.dll", "PySide6/plugins/imageformats"),
        (
            "C:/Qt/plugins/platforminputcontexts/qtvirtualkeyboardplugin.dll",
            "PySide6/plugins/platforminputcontexts",
        ),
        ("C:/Qt/plugins/generic/qtuiotouchplugin.dll", "PySide6/plugins/generic"),
    ]

    assert filter_qt_gui_binaries(binaries) == (
        binaries[0],
        binaries[1],
    )


def test_build_dependencies_are_exactly_hash_locked() -> None:
    lock_text = (PROJECT_ROOT / "requirements-build.lock").read_text(encoding="utf-8")
    lines = lock_text.splitlines()

    assert not any(
        line.strip().startswith(("-r ", "--requirement ")) for line in lines
    )
    assert not any(
        forbidden in lock_text.casefold()
        for forbidden in ("--index-url", "--extra-index-url", "git+", "-e ", "file:")
    )
    requirements: dict[str, tuple[str, set[str]]] = {}
    current: str | None = None
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\"):
            line = line[:-1].rstrip()
        if line.startswith("--hash="):
            assert current is not None, line
            assert re.fullmatch(r"--hash=sha256:[0-9a-f]{64}", line), line
            requirements[current][1].add(line.removeprefix("--hash=sha256:"))
            continue
        match = re.fullmatch(r"([a-z0-9-]+)==([^ ]+)", line)
        assert match is not None, line
        name, version = match.groups()
        assert name not in requirements
        requirements[name] = (version, set())
        current = name

    assert requirements
    assert all(digests for _, digests in requirements.values())

    assert {name: version for name, (version, _) in requirements.items()} == (
        BUILD_PACKAGES
    )


def test_build_lock_parser_accepts_indented_hash_continuations(
    tmp_path: Path,
) -> None:
    lock = tmp_path / "requirements.lock"
    lock.write_text(
        "demo-package==1.2.3 " + chr(92) + "\n"
        "    --hash=sha256:" + "a" * 64 + " " + chr(92) + "\n"
        "    --hash=sha256:" + "b" * 64 + "\n",
        encoding="ascii",
    )

    assert _locked_versions(lock) == {"demo-package": "1.2.3"}


def test_build_dependency_snapshot_rejects_installed_version_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_version(name: str) -> str:
        return "0.0.0" if name == "pyinstaller" else BUILD_PACKAGES[name]

    monkeypatch.setattr(
        "scripts.build_windows_portable.metadata.version",
        fake_version,
    )

    with pytest.raises(ValueError, match="pyinstaller"):
        validate_build_dependency_snapshot()


def test_artifact_manifest_is_canonical_and_hashes_sorted_files(
    tmp_path: Path,
) -> None:
    bundle = tmp_path / "bundle"
    (bundle / "nested").mkdir(parents=True)
    (bundle / "z.txt").write_bytes(b"last")
    (bundle / "nested" / "a.bin").write_bytes(b"first")

    manifest = artifact_manifest(bundle, forbidden_texts=(str(PROJECT_ROOT),))

    assert manifest == {
        "schema": 1,
        "algorithm": "sha256",
        "files": [
            {
                "path": "nested/a.bin",
                "sha256": (
                    "a7937b64b8caa58f03721bb6bacf5c78"
                    "cb235febe0e70b1b84cd99541461a08e"
                ),
                "size": 5,
            },
            {
                "path": "z.txt",
                "sha256": (
                    "3547cb112ac4489af2310c0626cdba6f"
                    "3097a2ad5a3b42ddd3b59c76c7a079a3"
                ),
                "size": 4,
            },
        ],
    }
    encoded = canonical_json_bytes(manifest)
    assert encoded.endswith(b"\n")
    assert b" " not in encoded
    assert json.loads(encoded) == manifest


def test_relative_paths_reject_case_insensitive_duplicates_and_traversal() -> None:
    with pytest.raises(ValueError, match="duplicate artifact path"):
        validate_relative_paths(("Rules/default.json", "rules/DEFAULT.json"))
    with pytest.raises(ValueError, match="unsafe artifact path"):
        validate_relative_paths(("../outside.txt",))
    with pytest.raises(ValueError, match="unsafe artifact path"):
        validate_relative_paths(("C:/outside.txt",))


def test_artifact_manifest_rejects_reparse_points(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    suspect = bundle / "suspect.txt"
    suspect.write_text("data", encoding="utf-8")
    original = Path.is_symlink
    monkeypatch.setattr(
        Path,
        "is_symlink",
        lambda path: path == suspect or original(path),
    )

    with pytest.raises(ValueError, match="reparse point"):
        artifact_manifest(bundle)


def test_artifact_manifest_rejects_workspace_path_in_evidence_text(
    tmp_path: Path,
) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "build-metadata.json").write_text(
        json.dumps({"workspace": str(PROJECT_ROOT)}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="forbidden build path"):
        artifact_manifest(bundle, forbidden_texts=(str(PROJECT_ROOT),))


def test_deterministic_zip_ignores_source_mtime(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    for root, timestamp in ((first, 1_600_000_000), (second, 1_700_000_000)):
        (root / "nested").mkdir(parents=True)
        for relative, content in (("a.txt", b"alpha"), ("nested/b.bin", b"beta")):
            path = root / relative
            path.write_bytes(content)
            os.utime(path, (timestamp, timestamp))

    first_zip = deterministic_zip(first, tmp_path / "first.zip")
    second_zip = deterministic_zip(second, tmp_path / "second.zip")

    assert first_zip.read_bytes() == second_zip.read_bytes()
    with zipfile.ZipFile(first_zip) as archive:
        assert archive.namelist() == ["a.txt", "nested/b.bin"]
        assert all(info.date_time == (1980, 1, 1, 0, 0, 0) for info in archive.infolist())


def test_portable_component_specs_separate_runtime_and_build_tools() -> None:
    specs = portable_component_specs(
        python_version="3.12.2",
        openssl_version="3.0.13",
        vc_runtime_version="14.38.33126.1",
        ucrt_version="10.0.19041.1",
    )
    by_name = {spec["name"]: spec for spec in specs}

    assert set(by_name) == {
        "AgentGuardian",
        "CPython",
        "OpenSSL",
        "PyInstaller",
        "PyInstaller Bootloader",
        "PySide6",
        "PySide6_Addons",
        "PySide6_Essentials",
        "shiboken6",
        "Microsoft Visual C++ Runtime",
        "Microsoft Universal C Runtime",
    } | {
        {
            "pyside6": "PySide6",
            "pyside6-addons": "PySide6_Addons",
            "pyside6-essentials": "PySide6_Essentials",
        }.get(name, name)
        for name in RUNTIME_PACKAGES
    }
    assert by_name["AgentGuardian"]["role"] == "runtime"
    assert by_name["AgentGuardian"]["version"] == "0.2.0-beta.1"
    assert by_name["AgentGuardian"]["license"] == "Apache-2.0"
    assert by_name["CPython"]["version"] == "3.12.2"
    assert by_name["OpenSSL"]["version"] == "3.0.13"
    assert by_name["Microsoft Visual C++ Runtime"]["license"] == "NOASSERTION"
    assert by_name["Microsoft Universal C Runtime"]["license"] == "NOASSERTION"
    assert by_name["PyInstaller"]["role"] == "build-time"
    assert by_name["PyInstaller Bootloader"]["role"] == "runtime"
    assert by_name["PyInstaller Bootloader"]["license"] == (
        "GPL-2.0-or-later WITH Bootloader-exception"
    )
    for name in ("PySide6", "PySide6_Addons", "PySide6_Essentials", "shiboken6"):
        assert by_name[name]["role"] == "runtime"
        assert by_name[name]["license"] == (
            "LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only"
        )


def test_third_party_notices_keep_qt_and_signing_limits_explicit() -> None:
    notices = (PROJECT_ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")

    for required in (
        "PySide6 6.11.1",
        "LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only",
        "Qt commercial license has not been verified",
        "PyInstaller 6.16.0",
        "Bootloader-exception",
        "Microsoft Visual C++ Runtime",
        "NOASSERTION",
        "unsigned development artifact",
    ):
        assert required in notices
    for name in RUNTIME_PACKAGES:
        assert f"`{name}`" in notices
    assert "registers and starts only STDIO" in notices


def test_cyclonedx_tracks_embedded_bootloader_as_runtime_dependency() -> None:
    pytest.importorskip("cyclonedx")
    specs = portable_component_specs(
        python_version="3.12.2",
        openssl_version="3.0.13",
        vc_runtime_version="14.38.33126.1",
        ucrt_version="10.0.19041.1",
    )
    bom = json.loads(
        cyclonedx_bom_bytes(
            specs,
            build_id="a" * 40,
            built_at=datetime(2026, 8, 14, tzinfo=timezone.utc),
        )
    )
    by_name = {component["name"]: component for component in bom["components"]}
    dependencies = {dependency["ref"]: dependency for dependency in bom["dependencies"]}
    root_ref = bom["metadata"]["component"]["bom-ref"]
    bootloader_ref = by_name["PyInstaller Bootloader"]["bom-ref"]
    tool_ref = by_name["PyInstaller"]["bom-ref"]

    assert by_name["PyInstaller Bootloader"]["scope"] == "required"
    assert by_name["PyInstaller"]["scope"] == "excluded"
    assert bootloader_ref in dependencies[root_ref]["dependsOn"]
    assert tool_ref not in dependencies[root_ref]["dependsOn"]
    normalized_names = {
        name.casefold().replace("_", "-") for name in by_name
    }
    assert RUNTIME_PACKAGES <= normalized_names
    normalized_by_name = {
        name.casefold().replace("_", "-"): component
        for name, component in by_name.items()
    }
    assert all(
        normalized_by_name[name]["scope"] == "required"
        for name in RUNTIME_PACKAGES
    )


def test_portable_evidence_is_canonical_and_excludes_its_own_checksums(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "AgentGuardian.exe").write_bytes(b"synthetic executable")
    monkeypatch.setattr(
        "scripts.build_windows_portable.cyclonedx_bom_bytes",
        lambda *args, **kwargs: b'{"bomFormat":"CycloneDX","specVersion":"1.6"}\n',
    )
    components = portable_component_specs(
        python_version="3.12.2",
        openssl_version="3.0.13",
        vc_runtime_version="14.38.33126.1",
        ucrt_version="10.0.19041.1",
    )

    write_portable_evidence(
        bundle,
        project_root=PROJECT_ROOT,
        component_specs=components,
        source_commit="a" * 40,
        built_at="2026-08-14T00:00:00Z",
        build_dependencies={
            "lock_sha256": "c" * 64,
            "versions": BUILD_PACKAGES,
        },
        forbidden_texts=(str(PROJECT_ROOT),),
    )

    metadata = json.loads((bundle / "BUILD-METADATA.json").read_bytes())
    assert metadata == {
        "artifact_status": "unsigned_development_only",
        "build_mode": "pyinstaller_onedir",
        "build_dependencies": {
            "lock_sha256": "c" * 64,
            "versions": BUILD_PACKAGES,
        },
        "built_at": "2026-08-14T00:00:00Z",
        "source_commit": "a" * 40,
    }
    manifest = json.loads((bundle / "PAYLOAD-MANIFEST.json").read_bytes())
    manifest_paths = {entry["path"] for entry in manifest["files"]}
    assert "PAYLOAD-MANIFEST.json" not in manifest_paths
    assert "SHA256SUMS" not in manifest_paths
    assert {
        "AgentGuardian.cdx.json",
        "AgentGuardian.exe",
        "BUILD-METADATA.json",
        "LICENSE",
        "THIRD_PARTY_NOTICES.md",
    } <= manifest_paths
    checksum_paths = {
        line.split(" *", 1)[1]
        for line in (bundle / "SHA256SUMS").read_text(encoding="ascii").splitlines()
    }
    assert "PAYLOAD-MANIFEST.json" in checksum_paths
    assert "SHA256SUMS" not in checksum_paths


def test_portable_evidence_rejects_retired_release_artifact_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "AgentGuardian.exe").write_bytes(b"synthetic executable")
    monkeypatch.setattr(
        "scripts.build_windows_portable.cyclonedx_bom_bytes",
        lambda *args, **kwargs: b'{"bomFormat":"CycloneDX","specVersion":"1.6"}\n',
    )
    with pytest.raises(ValueError, match="artifact status is invalid"):
        write_portable_evidence(
            bundle,
            project_root=PROJECT_ROOT,
            component_specs=portable_component_specs(
                python_version="3.12.2",
                openssl_version="3.0.13",
                vc_runtime_version="14.38.33126.1",
                ucrt_version="10.0.19041.1",
            ),
            source_commit="a" * 40,
            built_at="2026-08-14T00:00:00Z",
            build_dependencies={"lock_sha256": "c" * 64, "versions": BUILD_PACKAGES},
            forbidden_texts=(str(PROJECT_ROOT),),
            artifact_status="trusted_release",
        )


def test_frozen_layout_requires_reviewed_sources_and_no_qt_network_modules(
    tmp_path: Path,
) -> None:
    bundle = tmp_path / "AgentGuardian"
    package = bundle / "_internal" / "agentguardian"
    (package / "rules").mkdir(parents=True)
    (bundle / "AgentGuardian.exe").write_bytes(b"MZ synthetic")
    for path in reviewed_source_paths(PROJECT_ROOT):
        (package / path.name).write_bytes(path.read_bytes())
    (package / "source_policy.json").write_bytes(
        (PACKAGE_ROOT / "source_policy.json").read_bytes()
    )
    (package / "rules" / "default.json").write_bytes(
        (PROJECT_ROOT / "rules" / "default.json").read_bytes()
    )

    validate_frozen_layout(bundle, PROJECT_ROOT)

    (bundle / "_internal" / "_socket.pyd").write_bytes(b"synthetic stdlib socket")
    validate_frozen_layout(bundle, PROJECT_ROOT)

    (package / "app.py").unlink()
    with pytest.raises(ValueError, match="reviewed source layout"):
        validate_frozen_layout(bundle, PROJECT_ROOT)


@pytest.mark.parametrize(
    "relative",
    (
        "_internal/PySide6/QtNetwork.pyd",
        "_internal/PySide6/Qt6Network.dll",
        "_internal/PySide6/plugins/tls/qopensslbackend.dll",
        "_internal/PySide6/plugins/networkinformation/qnetworklistmanager.dll",
    ),
)
def test_frozen_layout_rejects_network_components(
    tmp_path: Path,
    relative: str,
) -> None:
    bundle = tmp_path / "AgentGuardian"
    package = bundle / "_internal" / "agentguardian"
    (package / "rules").mkdir(parents=True)
    (bundle / "AgentGuardian.exe").write_bytes(b"MZ synthetic")
    for path in reviewed_source_paths(PROJECT_ROOT):
        (package / path.name).write_bytes(path.read_bytes())
    (package / "source_policy.json").write_bytes(
        (PACKAGE_ROOT / "source_policy.json").read_bytes()
    )
    (package / "rules" / "default.json").write_bytes(
        (PROJECT_ROOT / "rules" / "default.json").read_bytes()
    )
    forbidden = bundle / relative
    forbidden.parent.mkdir(parents=True, exist_ok=True)
    forbidden.write_bytes(b"synthetic")

    with pytest.raises(ValueError, match="network-capable component"):
        validate_frozen_layout(bundle, PROJECT_ROOT)


def test_git_build_context_requires_clean_exact_head() -> None:
    commit = "a" * 40

    validate_git_build_context(commit, "", commit)

    with pytest.raises(ValueError, match="full lowercase"):
        validate_git_build_context(commit, "", "abc")
    with pytest.raises(ValueError, match="does not match HEAD"):
        validate_git_build_context(commit, "", "b" * 40)
    with pytest.raises(ValueError, match="worktree must be clean"):
        validate_git_build_context(commit, " M README.md", commit)


def test_portable_build_rechecks_git_context_after_pyinstaller(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import scripts.build_windows_portable as build_module

    commit = "a" * 40
    git_calls: list[tuple[str, ...]] = []

    def fake_git(_project_root: Path, *arguments: str) -> str:
        git_calls.append(arguments)
        return commit if arguments == ("rev-parse", "HEAD") else ""

    monkeypatch.setattr(build_module.sys, "platform", "win32")
    monkeypatch.setattr(build_module.sys, "version_info", (3, 12))
    monkeypatch.setattr(build_module, "_git", fake_git)
    monkeypatch.setattr(build_module, "_require_current_source_identity", lambda *args: None)
    monkeypatch.setattr(build_module, "validate_build_dependency_snapshot", lambda: {})
    snapshot = profile_snapshot_from_bytes(
        (
            PROJECT_ROOT / "release_profiles/personal_exe_private_beta.json"
        ).read_bytes()
    )
    monkeypatch.setattr(build_module, "load_profile_snapshot", lambda *args: snapshot)
    monkeypatch.setattr(build_module, "verify_profile", lambda *args: None)
    monkeypatch.setattr(build_module, "verify_payload", lambda *args: None)
    monkeypatch.setattr(
        build_module, "require_profile_snapshot_unchanged", lambda *args: None
    )
    monkeypatch.setattr(build_module, "build_pyinstaller_command", lambda *args: ("fake",))
    monkeypatch.setattr(build_module.subprocess, "run", lambda *args, **kwargs: None)
    monkeypatch.setattr(build_module, "validate_frozen_layout", lambda *args: None)
    monkeypatch.setattr(build_module, "runtime_library_versions", lambda: ("3.12.2", "3.0.13"))
    monkeypatch.setattr(build_module, "_pe_version", lambda path: "14.0.0.0")
    monkeypatch.setattr(build_module, "portable_component_specs", lambda **kwargs: ())
    monkeypatch.setattr(build_module, "write_portable_evidence", lambda *args, **kwargs: None)
    monkeypatch.setattr(build_module, "_write_personal_profile_evidence", lambda *args: None)
    monkeypatch.setattr(build_module, "deterministic_zip", lambda *args: None)

    build_module.build_portable(
        tmp_path,
        tmp_path / "output",
        source_commit=commit,
        built_at="2026-08-14T00:00:00Z",
    )

    assert git_calls == [
        ("rev-parse", "HEAD"),
        ("status", "--porcelain=v1", "--untracked-files=all"),
        ("rev-parse", "HEAD"),
        ("status", "--porcelain=v1", "--untracked-files=all"),
    ]


def test_build_time_requires_canonical_utc_seconds() -> None:
    assert validate_build_time("2026-08-14T00:00:00Z") == datetime(
        2026,
        8,
        14,
        tzinfo=timezone.utc,
    )
    for invalid in (
        "2026-08-14",
        "2026-08-14T00:00:00+00:00",
        "2026-08-14T00:00:00.000000Z",
    ):
        with pytest.raises(ValueError, match="canonical UTC"):
            validate_build_time(invalid)


def test_pe_version_parses_version_resources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixed = SimpleNamespace(
        FileVersionMS=(3 << 16) | 12,
        FileVersionLS=(2 << 16),
    )

    def fake_pe(path: str, *, fast_load: bool) -> object:
        assert path == "runtime.dll"
        assert fast_load is False
        return SimpleNamespace(VS_FIXEDFILEINFO=[fixed])

    monkeypatch.setitem(sys.modules, "pefile", SimpleNamespace(PE=fake_pe))

    assert _pe_version(Path("runtime.dll")) == "3.12.2.0"


def test_runtime_library_versions_use_semantic_versions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("platform.python_version", lambda: "3.12.2")
    monkeypatch.setattr("ssl.OPENSSL_VERSION", "OpenSSL 3.0.13 30 Jan 2024")

    assert runtime_library_versions() == ("3.12.2", "3.0.13")


def test_windows_portable_verifier_enforces_isolated_smoke_and_cleanup() -> None:
    script = PROJECT_ROOT / "scripts" / "verify_windows_portable.ps1"
    text = script.read_text(encoding="utf-8")

    for required in (
        "$BundleRoot",
        "$TestRoot",
        "$ZipPath",
        "$EvidencePath",
        '"APPDATA"',
        '"LOCALAPPDATA"',
        '"TEMP"',
        '"TMP"',
        '"USERPROFILE"',
        '"PROGRAMDATA"',
        '"QT_QPA_PLATFORM"',
        "Copy-Item",
        "Start-Process",
        ".HasExited",
        "Stop-Process",
        "taskkill.exe",
        '"/T"',
        "Get-CimInstance -ClassName Win32_Process",
        "Confirm-ProcessTreeStopped",
        "process_tree_terminated",
        "verifier_script_sha256",
        "source_commit",
        "Get-FileHash",
        "ConvertTo-Json -Compress",
        "Remove-Item",
        "declared_residue",
    ):
        assert required in text

    assert "Invoke-WebRequest" not in text
    assert "Invoke-RestMethod" not in text
    assert "foreach ($name in $originalEnvironment.Keys)" in text
    assert text.count("finally {") >= 3
