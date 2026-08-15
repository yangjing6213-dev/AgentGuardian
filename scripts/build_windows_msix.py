"""Build-contract helpers for the Windows MSIX package."""

from __future__ import annotations

import argparse
import re
from pathlib import Path
import shutil
import subprocess
from xml.sax.saxutils import escape


_IDENTITY_NAME = re.compile(r"^[A-Za-z0-9.-]{3,50}$")
_VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)\.(\d+)$")
_CERTIFICATE_THUMBPRINT = re.compile(r"^[0-9A-Fa-f]{40}$")
_LOGO_SOURCE = "assets/brand/agentguardian-mark-512.png"
_TIMESTAMP_URL = "http://timestamp.digicert.com"


def msix_manifest_bytes(
    *,
    identity_name: str,
    publisher: str,
    version: str,
    display_name: str = "AgentGuardian",
    executable: str = "AgentGuardian.exe",
) -> bytes:
    _validate_manifest_values(identity_name, publisher, version)
    if not display_name or any(ord(character) < 32 for character in display_name):
        raise ValueError("display name must be printable")
    if Path(executable).name != executable or not executable.casefold().endswith(".exe"):
        raise ValueError("executable must be a package-root exe")
    attributes = {
        "identity": identity_name,
        "publisher": publisher,
        "version": version,
        "display_name": display_name,
        "executable": executable,
    }
    escaped = {key: escape(value, {'"': "&quot;"}) for key, value in attributes.items()}
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"\n'
        '         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"\n'
        '         IgnorableNamespaces="uap">\n'
        f'  <Identity Name="{escaped["identity"]}" Publisher="{escaped["publisher"]}" '
        f'Version="{escaped["version"]}" />\n'
        '  <Properties>\n'
        f'    <DisplayName>{escaped["display_name"]}</DisplayName>\n'
        '    <PublisherDisplayName>AgentGuardian</PublisherDisplayName>\n'
        '    <Description>Local-first AI agent data security audit.</Description>\n'
        '    <Logo>Assets/StoreLogo.png</Logo>\n'
        '  </Properties>\n'
        '  <Resources><Resource Language="zh-CN" /></Resources>\n'
        '  <Dependencies />\n'
        '  <Applications>\n'
        f'    <Application Id="AgentGuardian" Executable="{escaped["executable"]}" '
        'EntryPoint="Windows.FullTrustApplication">\n'
        '      <uap:VisualElements AppListEntry="default" '
        f'DisplayName="{escaped["display_name"]}" '
        'Description="Local-first AI agent data security audit." '
        'BackgroundColor="#0F1215" '
        'Square44x44Logo="Assets/Square44x44Logo.png" '
        'Square150x150Logo="Assets/Square150x150Logo.png" />\n'
        '    </Application>\n'
        '  </Applications>\n'
        '</Package>\n'
    ).encode("utf-8")


def build_msix_stage(
    bundle_root: Path,
    stage_root: Path,
    *,
    project_root: Path,
    identity_name: str,
    publisher: str,
    version: str,
) -> Path:
    bundle = bundle_root.resolve()
    stage = stage_root.resolve()
    if not bundle.is_dir() or not (bundle / "AgentGuardian.exe").is_file():
        raise ValueError("portable bundle is missing AgentGuardian.exe")
    if stage.exists():
        raise ValueError("output stage already exists")
    if stage == bundle or bundle in stage.parents:
        raise ValueError("output stage must not be inside the portable bundle")
    logo = (project_root / _LOGO_SOURCE).resolve()
    if not logo.is_file() or logo.is_symlink():
        raise ValueError("MSIX logo asset is missing or unsafe")

    stage.mkdir(parents=True)
    try:
        for source in sorted(bundle.rglob("*"), key=lambda path: path.as_posix().casefold()):
            if source.is_symlink():
                raise ValueError("portable bundle contains a reparse or symlink")
            relative = source.relative_to(bundle)
            destination = stage / relative
            if source.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
            elif source.is_file():
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
            else:
                raise ValueError("portable bundle contains a non-file entry")

        assets = stage / "Assets"
        assets.mkdir()
        for name in ("Square44x44Logo.png", "Square150x150Logo.png", "StoreLogo.png"):
            shutil.copyfile(logo, assets / name)
        (stage / "AppxManifest.xml").write_bytes(
            msix_manifest_bytes(
                identity_name=identity_name,
                publisher=publisher,
                version=version,
            )
        )
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise
    return stage


def makeappx_pack_command(
    makeappx_executable: str, stage_root: Path, package_path: Path
) -> tuple[str, ...]:
    if package_path.exists():
        raise ValueError("MSIX output already exists")
    return (
        makeappx_executable,
        "pack",
        "/d",
        str(stage_root),
        "/p",
        str(package_path),
    )


def signtool_sign_by_thumbprint_command(
    signtool_executable: str,
    package_path: Path,
    certificate_thumbprint: str,
) -> tuple[str, ...]:
    if not _CERTIFICATE_THUMBPRINT.fullmatch(certificate_thumbprint):
        raise ValueError("certificate thumbprint must be 40 hexadecimal characters")
    return (
        signtool_executable,
        "sign",
        "/fd",
        "SHA256",
        "/sha1",
        certificate_thumbprint,
        "/tr",
        _TIMESTAMP_URL,
        "/td",
        "SHA256",
        str(package_path),
    )


def signtool_verify_command(
    signtool_executable: str, package_path: Path
) -> tuple[str, ...]:
    return (signtool_executable, "verify", "/pa", "/all", str(package_path))


def _validate_manifest_values(identity_name: str, publisher: str, version: str) -> None:
    if not _IDENTITY_NAME.fullmatch(identity_name):
        raise ValueError("identity name is not MSIX-safe")
    if not publisher or any(ord(character) < 32 for character in publisher):
        raise ValueError("publisher must be printable")
    match = _VERSION.fullmatch(version)
    if not match or any(int(part) > 65535 for part in match.groups()):
        raise ValueError("version must contain four 16-bit numeric components")


def main() -> int:
    parser = argparse.ArgumentParser(description="Stage a Windows MSIX package.")
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--stage-root", type=Path, required=True)
    parser.add_argument("--project-root", type=Path, default=Path(__file__).parents[1])
    parser.add_argument("--identity-name", required=True)
    parser.add_argument("--publisher", required=True)
    parser.add_argument("--version", default="0.1.0.0")
    args = parser.parse_args()
    build_msix_stage(
        args.bundle_root,
        args.stage_root,
        project_root=args.project_root,
        identity_name=args.identity_name,
        publisher=args.publisher,
        version=args.version,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
