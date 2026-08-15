"""Build-contract helpers for the unsigned Windows portable package."""

from __future__ import annotations

import argparse
from contextlib import nullcontext
from datetime import datetime, timezone
from importlib import metadata
import json
import hashlib
import os
import platform
from pathlib import Path
from pathlib import PurePosixPath
import shutil
import stat
import subprocess
import sys
import ssl
from uuid import UUID, uuid5
import zipfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentguardian import windows_code_signing  # noqa: E402
from agentguardian.file_integrity import (  # noqa: E402
    FileSizeLimitExceeded,
    bounded_file_sha256,
)


_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
_UNUSED_QT_GUI_PLUGINS = {
    "qpdf.dll",
    "qtuiotouchplugin.dll",
    "qtvirtualkeyboardplugin.dll",
}
_SBOM_NAMESPACE = UUID("f2b2b988-15ce-5e1c-a6cb-08c2db8e6e7a")
_FORBIDDEN_NETWORK_COMPONENTS = {
    "_socket.pyd",
    "qnetworklistmanager.dll",
    "qopensslbackend.dll",
    "qschannelbackend.dll",
    "qt6network.dll",
    "qtnetwork.pyd",
}
_MCP_ADAPTER_NAME = "AgentGuardianMcpAdapter.exe"
_MCP_ADAPTER_RELATIVE_PATH = f"adapters/{_MCP_ADAPTER_NAME}"


def reviewed_source_paths(project_root: Path) -> tuple[Path, ...]:
    package_root = project_root / "src" / "agentguardian"
    policy_path = package_root / "source_policy.json"
    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        reviewed_names = tuple(sorted(policy["modules"]))
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError):
        raise ValueError("invalid source policy") from None

    reviewed = tuple(package_root / name for name in reviewed_names)
    package_sources = set(package_root.glob("*.py"))
    if any(not path.is_file() for path in reviewed) or set(reviewed) != package_sources:
        raise ValueError("reviewed source set does not match package")
    return reviewed


def build_pyinstaller_command(
    project_root: Path,
    output_root: Path,
    *,
    python_executable: str = sys.executable,
) -> tuple[str, ...]:
    project_root = project_root.resolve()
    package_root = project_root / "src" / "agentguardian"
    data_specs = [
        *(f"{path.resolve()}:agentguardian" for path in reviewed_source_paths(project_root)),
        f"{(package_root / 'source_policy.json').resolve()}:agentguardian",
        f"{(project_root / 'rules' / 'default.json').resolve()}:agentguardian/rules",
    ]
    command = [
        python_executable,
        "-m",
        "PyInstaller",
        "--clean",
        "--noconfirm",
        "--onedir",
        "--windowed",
        "--noupx",
        "--exclude-module",
        "PySide6.QtNetwork",
        "--exclude-module",
        "socket",
        "--exclude-module",
        "ssl",
        "--name",
        "AgentGuardian",
        "--paths",
        str((project_root / "src").resolve()),
        "--additional-hooks-dir",
        str((project_root / "scripts" / "pyinstaller_hooks").resolve()),
        "--distpath",
        str(output_root / "dist"),
        "--workpath",
        str(output_root / "work"),
        "--specpath",
        str(output_root / "spec"),
    ]
    for data_spec in data_specs:
        command.extend(("--add-data", data_spec))
    command.append(str((package_root / "__main__.py").resolve()))
    return tuple(command)


def filter_qt_gui_binaries(
    binaries: list[tuple[str, str]],
) -> tuple[tuple[str, str], ...]:
    return tuple(
        binary
        for binary in binaries
        if Path(binary[0]).name.casefold() not in _UNUSED_QT_GUI_PLUGINS
    )


def portable_component_specs(
    *,
    python_version: str,
    openssl_version: str,
    vc_runtime_version: str,
    ucrt_version: str,
) -> tuple[dict[str, str], ...]:
    versions = _locked_versions(Path(__file__).parents[1] / "requirements-build.lock")
    qt_license = "LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only"
    return (
        _component("AgentGuardian", "0.1.0", "Apache-2.0", "runtime", "application"),
        _component("CPython", python_version, "Python-2.0", "runtime"),
        _component("OpenSSL", openssl_version, "Apache-2.0", "runtime"),
        _component("Microsoft Universal C Runtime", ucrt_version, "NOASSERTION", "runtime"),
        _component("Microsoft Visual C++ Runtime", vc_runtime_version, "NOASSERTION", "runtime"),
        _component("PyInstaller", versions["pyinstaller"], "GPL-2.0-or-later WITH Bootloader-exception", "build-time"),
        _component("PyInstaller Bootloader", versions["pyinstaller"], "GPL-2.0-or-later WITH Bootloader-exception", "runtime"),
        _component("PySide6", versions["pyside6"], qt_license, "runtime"),
        _component("PySide6_Addons", versions["pyside6-addons"], qt_license, "runtime"),
        _component("PySide6_Essentials", versions["pyside6-essentials"], qt_license, "runtime"),
        _component("shiboken6", versions["shiboken6"], qt_license, "runtime"),
    )


def cyclonedx_bom_bytes(
    component_specs: tuple[dict[str, str], ...],
    *,
    build_id: str,
    built_at: object,
) -> bytes:
    from cyclonedx.model import Property
    from cyclonedx.model.bom_ref import BomRef
    from cyclonedx.model.bom import Bom, BomMetaData
    from cyclonedx.model.component import Component, ComponentScope, ComponentType
    from cyclonedx.model.dependency import Dependency
    from cyclonedx.model.license import DisjunctiveLicense, LicenseExpression
    from cyclonedx.output import OutputFormat, SchemaVersion, make_outputter

    if not build_id or not hasattr(built_at, "tzinfo") or built_at.tzinfo is None:
        raise ValueError("build identity and timezone-aware timestamp are required")
    components = []
    for spec in component_specs:
        license_value = (
            DisjunctiveLicense(name="NOASSERTION")
            if spec["license"] == "NOASSERTION"
            else LicenseExpression(spec["license"])
        )
        components.append(
            Component(
                name=spec["name"],
                version=spec["version"],
                bom_ref=f"pkg:generic/{_reference_name(spec['name'])}@{spec['version']}",
                type=ComponentType.APPLICATION if spec["type"] == "application" else ComponentType.LIBRARY,
                scope=(
                    ComponentScope.REQUIRED
                    if spec["role"] == "runtime"
                    else ComponentScope.EXCLUDED
                ),
                licenses=(license_value,),
                properties=(
                    Property(name="agentguardian:component:role", value=spec["role"]),
                ),
            )
        )
    application = next(component for component in components if component.name == "AgentGuardian")
    runtime_dependencies = tuple(
        Dependency(BomRef(str(component.bom_ref)))
        for component in components
        if component is not application
        and next(spec for spec in component_specs if spec["name"] == component.name)["role"] == "runtime"
    )
    dependencies = (
        Dependency(BomRef(str(application.bom_ref)), dependencies=runtime_dependencies),
        *runtime_dependencies,
        *(
            Dependency(BomRef(str(component.bom_ref)))
            for component in components
            if component is not application
            and next(spec for spec in component_specs if spec["name"] == component.name)["role"] != "runtime"
        ),
    )
    bom = Bom(
        components=(component for component in components if component is not application),
        dependencies=dependencies,
        serial_number=uuid5(_SBOM_NAMESPACE, build_id),
        metadata=BomMetaData(component=application, timestamp=built_at),
        properties=(Property(name="agentguardian:build:id", value=build_id),),
    )
    outputter = make_outputter(bom, OutputFormat.JSON, SchemaVersion.V1_6)
    return canonical_json_bytes(json.loads(outputter.output_as_string(indent=None)))


def write_portable_evidence(
    bundle_root: Path,
    *,
    project_root: Path,
    component_specs: tuple[dict[str, str], ...],
    source_commit: str,
    built_at: str,
    build_dependencies: dict[str, object],
    forbidden_texts: tuple[str, ...],
    artifact_status: str = "unsigned_development_only",
) -> None:
    if len(source_commit) != 40 or any(character not in "0123456789abcdef" for character in source_commit):
        raise ValueError("source commit must be a full lowercase SHA-1")
    if not built_at.endswith("Z"):
        raise ValueError("build time must be canonical UTC")
    if artifact_status not in {"unsigned_development_only", "trusted_release"}:
        raise ValueError("artifact status is invalid")
    shutil.copyfile(project_root / "LICENSE", bundle_root / "LICENSE")
    shutil.copyfile(
        project_root / "THIRD_PARTY_NOTICES.md",
        bundle_root / "THIRD_PARTY_NOTICES.md",
    )
    from datetime import datetime

    parsed_time = datetime.fromisoformat(built_at.replace("Z", "+00:00"))
    (bundle_root / "AgentGuardian.cdx.json").write_bytes(
        cyclonedx_bom_bytes(
            component_specs,
            build_id=source_commit,
            built_at=parsed_time,
        )
    )
    metadata = {
        "artifact_status": artifact_status,
        "build_mode": "pyinstaller_onedir",
        "build_dependencies": build_dependencies,
        "built_at": built_at,
        "source_commit": source_commit,
    }
    (bundle_root / "BUILD-METADATA.json").write_bytes(canonical_json_bytes(metadata))
    payload_manifest = artifact_manifest(
        bundle_root,
        forbidden_texts=forbidden_texts,
    )
    (bundle_root / "PAYLOAD-MANIFEST.json").write_bytes(
        canonical_json_bytes(payload_manifest)
    )
    checksum_manifest = artifact_manifest(
        bundle_root,
        forbidden_texts=forbidden_texts,
    )
    checksums = "".join(
        f"{entry['sha256']} *{entry['path']}\n"
        for entry in checksum_manifest["files"]
    ).encode("ascii")
    (bundle_root / "SHA256SUMS").write_bytes(checksums)


def validate_frozen_layout(bundle_root: Path, project_root: Path) -> None:
    executable = bundle_root / "AgentGuardian.exe"
    package = bundle_root / "_internal" / "agentguardian"
    if not executable.is_file() or not package.is_dir():
        raise ValueError("frozen executable or package layout is missing")
    expected_sources = reviewed_source_paths(project_root)
    frozen_sources = tuple(sorted(package.glob("*.py"), key=lambda path: path.name))
    if tuple(path.name for path in frozen_sources) != tuple(
        path.name for path in expected_sources
    ):
        raise ValueError("reviewed source layout does not match")
    for source, frozen in zip(expected_sources, frozen_sources, strict=True):
        if source.read_bytes() != frozen.read_bytes():
            raise ValueError("reviewed source layout does not match")
    required_resources = (
        (
            project_root / "src" / "agentguardian" / "source_policy.json",
            package / "source_policy.json",
        ),
        (
            project_root / "rules" / "default.json",
            package / "rules" / "default.json",
        ),
    )
    if any(
        not frozen.is_file() or source.read_bytes() != frozen.read_bytes()
        for source, frozen in required_resources
    ):
        raise ValueError("frozen policy or rules do not match")
    forbidden = sorted(
        path.relative_to(bundle_root).as_posix()
        for path in bundle_root.rglob("*")
        if path.is_file() and path.name.casefold() in _FORBIDDEN_NETWORK_COMPONENTS
    )
    if forbidden:
        raise ValueError(f"frozen layout contains network-capable component: {forbidden[0]}")


def validate_git_build_context(head: str, status: str, source_commit: str) -> None:
    if len(source_commit) != 40 or any(
        character not in "0123456789abcdef" for character in source_commit
    ):
        raise ValueError("source commit must be a full lowercase SHA-1")
    if head != source_commit:
        raise ValueError("source commit does not match HEAD")
    if status.strip():
        raise ValueError("worktree must be clean")


def validate_build_time(value: str) -> datetime:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        raise ValueError("build time must be canonical UTC seconds") from None
    return parsed


def stage_trusted_mcp_adapter(
    bundle_root: Path,
    adapter_path: Path,
    *,
    expected_sha256: str,
    expected_publisher_subject: str,
    expected_certificate_sha256: str,
) -> Path:
    adapter = Path(adapter_path)
    if (
        not adapter.is_absolute()
        or _is_unc(adapter)
        or adapter.name != _MCP_ADAPTER_NAME
        or any(part in {".", ".."} for part in adapter.parts)
        or _has_reparse_component(adapter)
    ):
        raise ValueError("MCP adapter path is invalid or contains a reparse point")
    try:
        mode = adapter.stat(follow_symlinks=False).st_mode
    except OSError:
        raise ValueError("MCP adapter must be a regular file") from None
    if not stat.S_ISREG(mode):
        raise ValueError("MCP adapter must be a regular file")
    _validate_lower_sha256(expected_sha256, "MCP adapter SHA-256 is invalid")
    _validate_lower_sha256(
        expected_certificate_sha256,
        "MCP adapter certificate SHA-256 is invalid",
    )
    if type(expected_publisher_subject) is not str:
        raise ValueError("MCP adapter publisher subject is invalid")
    publisher_key, separator, publisher_value = expected_publisher_subject.partition("=")
    if (
        not expected_publisher_subject
        or expected_publisher_subject != expected_publisher_subject.strip()
        or len(expected_publisher_subject) > 512
        or "\x00" in expected_publisher_subject
        or not separator
        or not publisher_key.strip()
        or not publisher_value.strip()
    ):
        raise ValueError("MCP adapter publisher subject is invalid")
    if not bundle_root.is_dir() or _is_reparse_point(bundle_root):
        raise ValueError("MCP adapter bundle root is invalid")

    destination = bundle_root / "adapters" / _MCP_ADAPTER_NAME
    metadata_path = bundle_root / "MCP-ADAPTER.json"
    if destination.exists() or metadata_path.exists():
        raise ValueError("MCP adapter staging destination already exists")
    adapters_root_created = not destination.parent.exists()
    destination.parent.mkdir(parents=False, exist_ok=True)
    if _is_reparse_point(destination.parent):
        raise ValueError("MCP adapter staging path contains a reparse point")
    try:
        with windows_code_signing.hold_executable_for_launch(adapter):
            if _bounded_adapter_sha256(adapter) != expected_sha256:
                raise ValueError("MCP adapter SHA-256 does not match")
            if not windows_code_signing.verify_authenticode_publisher(
                adapter,
                (expected_publisher_subject,),
                allowed_certificate_sha256=(expected_certificate_sha256,),
            ):
                raise ValueError("MCP adapter trusted Authenticode identity is invalid")
            with adapter.open("rb") as source, destination.open("xb") as target:
                shutil.copyfileobj(source, target, length=1024 * 1024)
            if _bounded_adapter_sha256(destination) != expected_sha256:
                raise ValueError("MCP adapter identity changed during staging")
        metadata = {
            "schema": 1,
            "path": _MCP_ADAPTER_RELATIVE_PATH,
            "name": _MCP_ADAPTER_NAME,
            "sha256": expected_sha256,
            "publisher_subject": expected_publisher_subject,
            "certificate_sha256": expected_certificate_sha256,
        }
        metadata_path.write_bytes(canonical_json_bytes(metadata))
    except Exception:
        destination.unlink(missing_ok=True)
        metadata_path.unlink(missing_ok=True)
        if adapters_root_created:
            destination.parent.rmdir()
        raise
    return destination


def build_portable(
    project_root: Path,
    output_root: Path,
    *,
    source_commit: str,
    built_at: str,
    artifact_status: str = "unsigned_development_only",
    mcp_adapter_path: Path | None = None,
    mcp_adapter_sha256: str | None = None,
    mcp_adapter_publisher: str | None = None,
    mcp_adapter_certificate_sha256: str | None = None,
) -> Path:
    if sys.platform != "win32" or sys.version_info[:2] != (3, 12):
        raise RuntimeError("portable builds require Windows Python 3.12")
    adapter_inputs = (
        mcp_adapter_path,
        mcp_adapter_sha256,
        mcp_adapter_publisher,
        mcp_adapter_certificate_sha256,
    )
    if artifact_status == "trusted_release" and not all(
        value is not None for value in adapter_inputs
    ):
        raise ValueError("trusted release requires all four MCP adapter inputs")
    if artifact_status == "unsigned_development_only" and any(
        value is not None for value in adapter_inputs
    ):
        raise ValueError("unsigned build cannot stage MCP adapter inputs")
    if artifact_status not in {"unsigned_development_only", "trusted_release"}:
        raise ValueError("artifact status is invalid")
    project_root = project_root.resolve()
    output_root = output_root.resolve()
    head = _git(project_root, "rev-parse", "HEAD")
    status = _git(project_root, "status", "--porcelain=v1", "--untracked-files=all")
    validate_git_build_context(head, status, source_commit)
    build_time = validate_build_time(built_at)
    build_dependencies = validate_build_dependency_snapshot()
    if output_root.exists():
        raise ValueError("output root already exists")
    output_root.mkdir(parents=True)
    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONHASHSEED": "0",
            "PYINSTALLER_CONFIG_DIR": str(output_root / "pyinstaller-cache"),
            "SOURCE_DATE_EPOCH": str(int(build_time.timestamp())),
        }
    )
    subprocess.run(
        build_pyinstaller_command(project_root, output_root),
        cwd=project_root,
        env=environment,
        check=True,
    )
    final_head = _git(project_root, "rev-parse", "HEAD")
    final_status = _git(
        project_root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    )
    validate_git_build_context(final_head, final_status, source_commit)
    bundle_root = output_root / "dist" / "AgentGuardian"
    validate_frozen_layout(bundle_root, project_root)
    internal = bundle_root / "_internal"
    python_version, openssl_version = runtime_library_versions()
    components = portable_component_specs(
        python_version=python_version,
        openssl_version=openssl_version,
        vc_runtime_version=_pe_version(internal / "VCRUNTIME140.dll"),
        ucrt_version=_pe_version(internal / "ucrtbase.dll"),
    )
    staged_adapter = None
    if artifact_status == "trusted_release":
        staged_adapter = stage_trusted_mcp_adapter(
            bundle_root,
            mcp_adapter_path,
            expected_sha256=mcp_adapter_sha256,
            expected_publisher_subject=mcp_adapter_publisher,
            expected_certificate_sha256=mcp_adapter_certificate_sha256,
        )
    adapter_guard = (
        windows_code_signing.hold_executable_for_launch(staged_adapter)
        if staged_adapter is not None
        else nullcontext()
    )
    with adapter_guard:
        if (
            staged_adapter is not None
            and _bounded_adapter_sha256(staged_adapter) != mcp_adapter_sha256
        ):
            raise ValueError("staged MCP adapter identity changed before packaging")
        write_portable_evidence(
            bundle_root,
            project_root=project_root,
            component_specs=components,
            source_commit=source_commit,
            built_at=built_at,
            build_dependencies=build_dependencies,
            forbidden_texts=(str(project_root), str(output_root)),
            artifact_status=artifact_status,
        )
        deterministic_zip(
            bundle_root,
            output_root / f"AgentGuardian-0.1.0-windows-x64-{source_commit[:12]}.zip",
        )
    return bundle_root


def _git(project_root: Path, *arguments: str) -> str:
    return subprocess.run(
        ("git", *arguments),
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def runtime_library_versions() -> tuple[str, str]:
    openssl_version = ssl.OPENSSL_VERSION.split()[1]
    return platform.python_version(), openssl_version


def _pe_version(path: Path) -> str:
    import pefile

    pe = pefile.PE(str(path), fast_load=False)
    fixed = pe.VS_FIXEDFILEINFO[0]
    return ".".join(
        str(value)
        for value in (
            fixed.FileVersionMS >> 16,
            fixed.FileVersionMS & 0xFFFF,
            fixed.FileVersionLS >> 16,
            fixed.FileVersionLS & 0xFFFF,
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build an AgentGuardian Windows portable artifact."
    )
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--built-at", required=True)
    parser.add_argument(
        "--artifact-status",
        choices=("unsigned_development_only", "trusted_release"),
        default="unsigned_development_only",
    )
    parser.add_argument("--mcp-adapter-path", type=Path)
    parser.add_argument("--mcp-adapter-sha256")
    parser.add_argument("--mcp-adapter-publisher")
    parser.add_argument("--mcp-adapter-certificate-sha256")
    arguments = parser.parse_args()
    build_portable(
        Path(__file__).parents[1],
        arguments.output_root,
        source_commit=arguments.source_commit,
        built_at=arguments.built_at,
        artifact_status=arguments.artifact_status,
        mcp_adapter_path=arguments.mcp_adapter_path,
        mcp_adapter_sha256=arguments.mcp_adapter_sha256,
        mcp_adapter_publisher=arguments.mcp_adapter_publisher,
        mcp_adapter_certificate_sha256=arguments.mcp_adapter_certificate_sha256,
    )
    return 0


def _component(
    name: str,
    version: str,
    license_expression: str,
    role: str,
    component_type: str = "library",
) -> dict[str, str]:
    return {
        "name": name,
        "version": version,
        "license": license_expression,
        "role": role,
        "type": component_type,
    }


def _reference_name(name: str) -> str:
    return "-".join(name.casefold().replace("+", "plus").replace("_", "-").split())


def _locked_versions(lock_path: Path) -> dict[str, str]:
    versions: dict[str, str] = {}
    for line in lock_path.read_text(encoding="utf-8").splitlines():
        requirement, separator, _ = line.partition(" --hash=sha256:")
        name, pinned, version = requirement.partition("==")
        if not separator or pinned != "==" or not name or not version:
            raise ValueError("invalid build lock")
        versions[name] = version
    return versions


def validate_build_dependency_snapshot(
    lock_path: Path | None = None,
) -> dict[str, object]:
    resolved_lock = lock_path or Path(__file__).parents[1] / "requirements-build.lock"
    lock_bytes = resolved_lock.read_bytes()
    locked = _locked_versions(resolved_lock)
    installed: dict[str, str] = {}
    for name in sorted(locked):
        try:
            installed[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            raise ValueError(f"build dependency is not installed: {name}") from None
    if installed != locked:
        mismatches = [
            name
            for name in sorted(locked)
            if installed.get(name) != locked[name]
        ]
        raise ValueError(f"build dependency version drift: {mismatches[0]}")
    return {
        "lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
        "versions": installed,
    }


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


def validate_relative_paths(paths: tuple[str, ...]) -> tuple[str, ...]:
    seen: set[str] = set()
    for value in paths:
        path = PurePosixPath(value)
        unsafe = (
            not value
            or "\\" in value
            or path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.parts)
            or ":" in path.parts[0]
        )
        if unsafe:
            raise ValueError(f"unsafe artifact path: {value}")
        folded = value.casefold()
        if folded in seen:
            raise ValueError(f"duplicate artifact path: {value}")
        seen.add(folded)
    return paths


def artifact_manifest(
    bundle_root: Path,
    *,
    forbidden_texts: tuple[str, ...] = (),
) -> dict[str, object]:
    files = _bundle_files(bundle_root)
    relative_paths = tuple(path.relative_to(bundle_root).as_posix() for path in files)
    validate_relative_paths(relative_paths)
    forbidden_bytes = tuple(
        variant.encode("utf-8")
        for value in forbidden_texts
        if value
        for variant in {
            value,
            value.replace("\\", "\\\\"),
            value.replace("\\", "/"),
            json.dumps(value, ensure_ascii=True)[1:-1],
            json.dumps(value.replace("\\", "/"), ensure_ascii=True)[1:-1],
        }
    )
    entries = []
    for path, relative in zip(files, relative_paths, strict=True):
        content = path.read_bytes()
        if any(value in content for value in forbidden_bytes):
            raise ValueError(f"forbidden build path in artifact: {relative}")
        entries.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
        )
    return {"schema": 1, "algorithm": "sha256", "files": entries}


def deterministic_zip(bundle_root: Path, destination: Path) -> Path:
    files = _bundle_files(bundle_root)
    relative_paths = tuple(path.relative_to(bundle_root).as_posix() for path in files)
    validate_relative_paths(relative_paths)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(
        destination,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for path, relative in zip(files, relative_paths, strict=True):
            info = zipfile.ZipInfo(relative, date_time=_ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, path.read_bytes(), compresslevel=9)
    return destination


def _bundle_files(bundle_root: Path) -> tuple[Path, ...]:
    if not bundle_root.is_dir() or _is_reparse_point(bundle_root):
        raise ValueError("bundle root is missing or a reparse point")
    paths = sorted(bundle_root.rglob("*"), key=lambda path: path.relative_to(bundle_root).as_posix())
    for path in paths:
        if _is_reparse_point(path):
            raise ValueError(f"artifact contains reparse point: {path.name}")
    return tuple(path for path in paths if path.is_file())


def _is_reparse_point(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        attributes = getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0)
    except OSError:
        raise ValueError(f"unable to inspect artifact path: {path.name}") from None
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _has_reparse_component(path: Path) -> bool:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if _is_reparse_point(current):
            return True
    return False


def _is_unc(path: Path) -> bool:
    return path.anchor.startswith("\\\\") or os.fspath(path).startswith(("\\\\", "//"))


def _validate_lower_sha256(value: object, message: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(message)


def _bounded_adapter_sha256(path: Path) -> str:
    try:
        return bounded_file_sha256(path)
    except FileSizeLimitExceeded:
        raise ValueError("MCP adapter exceeds 64 MiB limit") from None


if __name__ == "__main__":
    raise SystemExit(main())
